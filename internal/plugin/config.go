// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	pb "github.com/heliopsy/scrim/pkg/plugin/pluginv1"
)

// Fields every plugin instance accepts, in the `stores` collection (with
// kind: plugin) and in `notify.plugins`.
const (
	FieldCommand      = "command"
	FieldArgs         = "args"
	FieldEnv          = "env"
	FieldOptions      = "options"
	FieldSHA256       = "sha256"
	FieldTimeout      = "timeout"
	FieldStartTimeout = "start-timeout"
)

// Defaults.
const (
	DefaultTimeout      = 10 * time.Second
	DefaultStartTimeout = 5 * time.Second
	defaultBackoff      = time.Second
	maxBackoff          = 30 * time.Second
)

// DefaultPath is the PATH a plugin starts with unless env sets one.
const DefaultPath = "/usr/local/bin:/usr/bin:/bin"

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Config is how one plugin instance is started.
type Config struct {
	// Instance is the configured instance name.
	Instance string
	// Kind is what the plugin must provide.
	Kind pb.Kind
	// Command is the absolute path of the plugin binary.
	Command string
	// Args are its arguments after argv[0].
	Args []string
	// Env is its whole environment besides SCRIM_PLUGIN_*, PATH defaulting
	// to [DefaultPath]. Never a credential: those are secret fields.
	Env map[string]string
	// SHA256, if set, pins the binary's digest.
	SHA256 string
	// Options is the plugin's own `options` object, passed as JSON.
	Options map[string]any
	// Secrets maps each credential field set on the instance to its
	// reference. The values are resolved at every start and sent only in
	// Configure.
	Secrets map[string]string
	// StartTimeout bounds the start, handshake and Configure; CallTimeout
	// bounds each call. A call that runs over stops the plugin.
	StartTimeout time.Duration
	CallTimeout  time.Duration
	// Backoff is the first restart delay after a crash, doubling to 30s;
	// default 1s.
	Backoff time.Duration
}

// ParseConfig reads a plugin instance's fields. secretFields are the
// collection's credential fields; extra are other fields the caller reads
// itself, returned in rest. Any other field is an error. Errors name fields,
// never values.
func ParseConfig(instance string, kind pb.Kind, fields map[string]any, secretFields, extra []string) (Config, map[string]any, error) {
	c := Config{Instance: instance, Kind: kind, StartTimeout: DefaultStartTimeout, CallTimeout: DefaultTimeout,
		Options: map[string]any{}, Secrets: map[string]string{}, Env: map[string]string{}}
	rest := map[string]any{}
	var errs []error
	bad := func(field, want string) { errs = append(errs, fmt.Errorf("%s must be %s", field, want)) }
	for _, k := range slices.Sorted(maps.Keys(fields)) {
		v := fields[k]
		switch {
		case k == FieldCommand:
			s, ok := v.(string)
			if !ok {
				bad(k, "an absolute path")
			}
			c.Command = s
		case k == FieldArgs:
			list, ok := stringList(v)
			if !ok {
				bad(k, "a list of strings")
			}
			c.Args = list
		case k == FieldSHA256:
			s, ok := v.(string)
			if !ok {
				bad(k, "a hex sha256 digest")
			}
			c.SHA256 = s
		case k == FieldTimeout || k == FieldStartTimeout:
			d, ok := duration(v)
			if !ok || d <= 0 {
				bad(k, "a positive duration such as 10s")
				continue
			}
			if k == FieldTimeout {
				c.CallTimeout = d
			} else {
				c.StartTimeout = d
			}
		case k == FieldEnv || strings.HasPrefix(k, FieldEnv+"."):
			if err := setEnv(c.Env, strings.TrimPrefix(strings.TrimPrefix(k, FieldEnv), "."), v); err != nil {
				errs = append(errs, err)
			}
		case k == FieldOptions || strings.HasPrefix(k, FieldOptions+"."):
			if err := setOption(c.Options, strings.TrimPrefix(strings.TrimPrefix(k, FieldOptions), "."), v); err != nil {
				errs = append(errs, err)
			}
		case slices.Contains(secretFields, k):
			s, ok := v.(string)
			if !ok {
				s = fmt.Sprint(v)
			}
			if s != "" {
				c.Secrets[k] = s
			}
		case slices.Contains(extra, k):
			rest[k] = v
		default:
			errs = append(errs, fmt.Errorf("unknown field %s (plugin options go under %s)", k, FieldOptions))
		}
	}
	if c.Command == "" {
		errs = append(errs, fmt.Errorf("%s is required", FieldCommand))
	}
	if _, err := json.Marshal(c.Options); err != nil {
		errs = append(errs, fmt.Errorf("%s cannot be encoded as JSON", FieldOptions))
	}
	return c, rest, errors.Join(errs...)
}

func setEnv(env map[string]string, sub string, v any) error {
	if sub == "" {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be a map of variable names to strings", FieldEnv)
		}
		for k, x := range m {
			if err := setEnv(env, k, x); err != nil {
				return err
			}
		}
		return nil
	}
	if !envNamePattern.MatchString(sub) || strings.HasPrefix(sub, "SCRIM_PLUGIN_") {
		return fmt.Errorf("%s.%s is not a variable name a plugin may be given", FieldEnv, sub)
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("%s.%s must be a string", FieldEnv, sub)
	}
	env[sub] = s
	return nil
}

// setOption puts v at the dotted path sub of opts, so `options.a.b` from the
// environment and a nested `options: {a: {b: ...}}` from a file agree.
func setOption(opts map[string]any, sub string, v any) error {
	if sub == "" {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be a map", FieldOptions)
		}
		for k, x := range m {
			if err := setOption(opts, k, x); err != nil {
				return err
			}
		}
		return nil
	}
	head, tail, nested := strings.Cut(sub, ".")
	if !nested {
		if m, ok := v.(map[string]any); ok {
			child, _ := opts[head].(map[string]any)
			if child == nil {
				child = map[string]any{}
				opts[head] = child
			}
			return setOption(child, "", m)
		}
		if _, dup := opts[head]; dup {
			return fmt.Errorf("%s.%s is set twice", FieldOptions, sub)
		}
		opts[head] = v
		return nil
	}
	child, ok := opts[head].(map[string]any)
	if !ok {
		if _, dup := opts[head]; dup {
			return fmt.Errorf("%s.%s is set twice", FieldOptions, head)
		}
		child = map[string]any{}
		opts[head] = child
	}
	return setOption(child, tail, v)
}

func stringList(v any) ([]string, bool) {
	switch x := v.(type) {
	case []string:
		return slices.Clone(x), true
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	case string:
		// From the environment: comma-separated.
		var out []string
		for _, p := range strings.Split(x, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out, true
	}
	return nil, false
}

func duration(v any) (time.Duration, bool) {
	switch x := v.(type) {
	case time.Duration:
		return x, true
	case string:
		d, err := time.ParseDuration(x)
		return d, err == nil
	}
	return 0, false
}

// environ is the plugin's whole environment.
func (c Config) environ() []string {
	env := map[string]string{"PATH": DefaultPath}
	maps.Copy(env, c.Env)
	env["SCRIM_PLUGIN_FD"] = "3"
	env["SCRIM_PLUGIN_PROTOCOL"] = fmt.Sprint(Protocol)
	env["SCRIM_PLUGIN_INSTANCE"] = c.Instance
	out := make([]string, 0, len(env))
	for _, k := range slices.Sorted(maps.Keys(env)) {
		out = append(out, k+"="+env[k])
	}
	return out
}

// OptionsJSON encodes the plugin's options.
func OptionsJSON(opts map[string]any) ([]byte, error) {
	if opts == nil {
		opts = map[string]any{}
	}
	b, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be encoded as JSON", FieldOptions)
	}
	return b, nil
}
