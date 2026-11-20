// SPDX-License-Identifier: AGPL-3.0-only

// Package config is scrim's settings registry and loader.
//
// Every package declares its settings once, as package-level typed keys:
//
//	var Timeout = config.Register(config.Spec[time.Duration]{
//		Key:         "approvals.timeout",
//		Default:     2 * time.Minute,
//		Description: "How long an approval waits for a decision before it is denied.",
//		Flag:        true,
//	})
//
// and reads them from an effective [Config]:
//
//	d := Timeout.Get(cfg)
//
// The key is the single name of the setting everywhere (design D10): the
// environment variable is derived as SCRIM_ plus the key upper-cased with
// dots and dashes as underscores, and the flag as the key with dots as
// dashes. A [Config] is built by [Load] from layers in precedence order
// (default, profile, file, environment, flag); each value remembers its
// [Source] for `scrim config show --effective`.
package config

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Type is the set of Go types a setting can hold.
type Type interface {
	string | bool | int | float64 | time.Duration | []string | map[string]string | SecretRef
}

// SecretRef is the reference form of a secret-valued setting: `env:NAME`,
// `file:/path`, a systemd credential name, a store reference such as
// `bao://kv/scrim#token`, or (discouraged, warned about) a literal. The
// string itself is safe to show; the value it resolves to is not, and is only
// ever held as a secret.Value.
type SecretRef string

// Kind names the type of a setting in the schema and in documentation.
type Kind string

// Setting kinds.
const (
	KindString    Kind = "string"
	KindBool      Kind = "bool"
	KindInt       Kind = "int"
	KindFloat     Kind = "float"
	KindDuration  Kind = "duration"
	KindList      Kind = "list"
	KindMap       Kind = "map"
	KindSecretRef Kind = "secret-ref"
)

// Spec declares one setting. Key, Description and Default are required.
type Spec[T Type] struct {
	// Key is the canonical dotted key, lower-case words separated by dots,
	// words may contain dashes: `proxy.no-proxy`.
	Key string
	// Default is the built-in value. A weakening setting's default must be
	// the safe value.
	Default T
	// Description is one or two sentences for generated documentation.
	Description string
	// Flag exposes the setting as a command-line flag named by FlagName.
	Flag bool
	// Enum, for string settings, lists the accepted values.
	Enum []string
	// Weakening marks a setting that weakens a security invariant. It is
	// named for what it weakens, logged at start-up while active and listed
	// in `scrim status`.
	Weakening bool
	// RestartRequired marks a setting a hot reload cannot change.
	RestartRequired bool
	// Validate, if set, checks a parsed value beyond its type.
	Validate func(T) error
	// RequireReference, for secret-ref settings, rejects a literal value:
	// the setting must be given as env:, file:, cred: or a store reference.
	RequireReference bool
	// Profiles sets the value a built-in profile (see [Profiles]) gives the
	// setting. A profile sits above the default and below every other source.
	Profiles map[string]T
}

// Setting is the type-erased view of a registered setting, used by the
// loader, schema generator and documentation.
type Setting struct {
	Key             string
	Kind            Kind
	Default         any
	Description     string
	Flag            bool
	Enum            []string
	Weakening       bool
	SecretRef       bool
	RestartRequired bool
	// RequireReference rejects a literal for a secret-ref setting.
	RequireReference bool
	// Profiles maps a profile name to the value it gives the setting.
	Profiles map[string]any

	validate func(any) error
}

// EnvVar is the environment variable for the setting.
func (s *Setting) EnvVar() string { return EnvVar(s.Key) }

// FlagName is the flag name for the setting, without leading dashes.
func (s *Setting) FlagName() string { return FlagName(s.Key) }

// EnvVar derives the environment variable name for key.
func EnvVar(key string) string {
	return "SCRIM_" + strings.NewReplacer(".", "_", "-", "_").Replace(strings.ToUpper(key))
}

// FlagName derives the flag name for key.
func FlagName(key string) string { return strings.ReplaceAll(key, ".", "-") }

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*(\.[a-z][a-z0-9]*(-[a-z0-9]+)*)*$`)

// Registry holds every declared setting.
type Registry struct {
	mu       sync.RWMutex
	settings map[string]*Setting
	envs     map[string]string
	flags    map[string]string
	checks   []namedCheck
	// collections are named-instance sections, see [RegisterCollection].
	collections map[string]*CollectionSpec
}

// NewRegistry returns an empty registry. Most code uses [Default].
func NewRegistry() *Registry {
	return &Registry{
		settings: map[string]*Setting{},
		envs:     map[string]string{},
		flags:    map[string]string{},
	}
}

// Default is the process-wide registry that [Register] adds to.
var Default = NewRegistry()

// Key is a typed handle to a registered setting.
type Key[T Type] struct{ s *Setting }

// Name returns the canonical key.
func (k Key[T]) Name() string { return k.s.Key }

// Setting returns the registered setting.
func (k Key[T]) Setting() *Setting { return k.s }

// Get returns the effective value of the setting in c. It panics if c was
// built from a registry that does not hold the key, which is a wiring bug.
func (k Key[T]) Get(c *Config) T {
	e, ok := c.values[k.s.Key]
	if !ok {
		panic("config: " + k.s.Key + " is not in this Config's registry")
	}
	return clone(e.Value).(T)
}

// Register declares a setting in [Default]. It panics on an invalid or
// duplicate declaration, so mistakes surface at start-up and in every test.
func Register[T Type](spec Spec[T]) Key[T] { return MustRegisterIn(Default, spec) }

// MustRegisterIn is [RegisterIn] that panics on error.
func MustRegisterIn[T Type](r *Registry, spec Spec[T]) Key[T] {
	k, err := RegisterIn(r, spec)
	if err != nil {
		panic(err)
	}
	return k
}

// RegisterIn declares a setting in r.
func RegisterIn[T Type](r *Registry, spec Spec[T]) (Key[T], error) {
	s := &Setting{
		Key:             spec.Key,
		Kind:            kindOf[T](),
		Default:         clone(any(spec.Default)),
		Description:     strings.TrimSpace(spec.Description),
		Flag:            spec.Flag,
		Enum:            slices.Clone(spec.Enum),
		Weakening:       spec.Weakening,
		RestartRequired: spec.RestartRequired,
	}
	s.SecretRef = s.Kind == KindSecretRef
	s.RequireReference = spec.RequireReference
	if len(spec.Profiles) > 0 {
		s.Profiles = make(map[string]any, len(spec.Profiles))
		for name, v := range spec.Profiles {
			s.Profiles[name] = clone(any(v))
		}
	}
	if v := spec.Validate; v != nil {
		s.validate = func(a any) error { return v(a.(T)) }
	}
	if err := r.add(s); err != nil {
		return Key[T]{}, err
	}
	return Key[T]{s: s}, nil
}

func (r *Registry) add(s *Setting) error {
	if !keyPattern.MatchString(s.Key) {
		return fmt.Errorf("config: invalid key %q: use lower-case dotted words", s.Key)
	}
	if s.Description == "" {
		return fmt.Errorf("config: setting %s has no description", s.Key)
	}
	if len(s.Enum) > 0 && s.Kind != KindString {
		return fmt.Errorf("config: setting %s: enum is only valid for string settings", s.Key)
	}
	if s.Weakening && s.Kind == KindBool && s.Default.(bool) {
		return fmt.Errorf("config: weakening setting %s must default to false", s.Key)
	}
	if err := s.check(s.Default); err != nil {
		return fmt.Errorf("config: default of %s: %w", s.Key, err)
	}
	if s.RequireReference && s.Kind != KindSecretRef {
		return fmt.Errorf("config: setting %s: RequireReference is only valid for secret-ref settings", s.Key)
	}
	if s.Kind == KindSecretRef && refKind(s.Default.(SecretRef)) == RefLiteral {
		return fmt.Errorf("config: setting %s: a secret-ref default must be empty or a reference", s.Key)
	}
	for _, name := range slices.Sorted(maps.Keys(s.Profiles)) {
		if !slices.Contains(Profiles, name) {
			return fmt.Errorf("config: setting %s: unknown profile %q (profiles: %s)", s.Key, name, strings.Join(Profiles, ", "))
		}
		if err := s.check(s.Profiles[name]); err != nil {
			return fmt.Errorf("config: profile %s value of %s: %w", name, s.Key, err)
		}
		if s.Weakening && !equalValues(s.Profiles[name], s.Default) {
			return fmt.Errorf("config: weakening setting %s cannot be changed by profile %s", s.Key, name)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.settings[s.Key]; dup {
		return fmt.Errorf("config: setting %s registered twice", s.Key)
	}
	for k := range r.settings {
		if strings.HasPrefix(k, s.Key+".") || strings.HasPrefix(s.Key, k+".") {
			return fmt.Errorf("config: setting %s conflicts with %s: a key cannot be both a value and a section", s.Key, k)
		}
	}
	if col := r.collisionWithCollection(s.Key); col != "" {
		return fmt.Errorf("config: setting %s conflicts with collection %s", s.Key, col)
	}
	if other, dup := r.envs[s.EnvVar()]; dup {
		return fmt.Errorf("config: settings %s and %s map to the same variable %s", s.Key, other, s.EnvVar())
	}
	if other, dup := r.flags[s.FlagName()]; dup {
		return fmt.Errorf("config: settings %s and %s map to the same flag --%s", s.Key, other, s.FlagName())
	}
	r.settings[s.Key] = s
	r.envs[s.EnvVar()] = s.Key
	r.flags[s.FlagName()] = s.Key
	return nil
}

// check validates a parsed value against the setting's enum and validator.
func (s *Setting) check(v any) error {
	if len(s.Enum) > 0 {
		if str := v.(string); !slices.Contains(s.Enum, str) {
			return fmt.Errorf("%q is not one of %s", str, strings.Join(s.Enum, ", "))
		}
	}
	if s.validate != nil {
		return s.validate(v)
	}
	return nil
}

// Lookup returns the setting for key.
func (r *Registry) Lookup(key string) (*Setting, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.settings[key]
	return s, ok
}

// LookupEnv returns the setting whose environment variable is name.
func (r *Registry) LookupEnv(name string) (*Setting, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.envs[name]
	if !ok {
		return nil, false
	}
	return r.settings[k], true
}

// Settings returns every setting sorted by key.
func (r *Registry) Settings() []*Setting {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Setting, 0, len(r.settings))
	for _, s := range r.settings {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Closest returns the registered key nearest to key by edit distance, for
// "did you mean" messages. It returns "" when nothing is reasonably close.
func (r *Registry) Closest(key string) string {
	best, bestD := "", len(key)/2+2
	for _, s := range r.Settings() {
		if d := distance(key, s.Key); d < bestD {
			best, bestD = s.Key, d
		}
	}
	return best
}

func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func kindOf[T Type]() Kind {
	var zero T
	switch any(zero).(type) {
	case string:
		return KindString
	case bool:
		return KindBool
	case int:
		return KindInt
	case float64:
		return KindFloat
	case time.Duration:
		return KindDuration
	case []string:
		return KindList
	case map[string]string:
		return KindMap
	case SecretRef:
		return KindSecretRef
	}
	panic("unreachable")
}

// clone copies list and map values so callers cannot mutate shared state.
func clone(v any) any {
	switch t := v.(type) {
	case []string:
		if t == nil {
			return []string{}
		}
		return slices.Clone(t)
	case map[string]string:
		out := make(map[string]string, len(t))
		for k, x := range t {
			out[k] = x
		}
		return out
	}
	return v
}

// ErrUnknownKey is wrapped by errors about keys no setting declares.
var ErrUnknownKey = errors.New("unknown setting")
