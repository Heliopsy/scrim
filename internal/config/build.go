// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/heliopsy/scrim/internal/secret"
)

// Profiles are the built-in deployment profiles, in documentation order.
// A setting gives a profile its own value with [Spec.Profiles].
var Profiles = []string{"local", "k8s", "ci"}

// Settings of the configuration system itself. They are registered in
// [Default] and, for other registries, by [RegisterBuiltins].
var (
	// ProfileKey selects the built-in profile.
	ProfileKey Key[string]
	// StrictKey makes unknown keys in a config file an error.
	StrictKey Key[bool]
	// WatchKey reloads the configuration when a config file changes.
	WatchKey Key[bool]
)

func init() {
	ProfileKey, StrictKey, WatchKey = RegisterBuiltins(Default)
}

// RegisterBuiltins registers the configuration system's own settings
// (`profile`, `config.strict`, `config.watch`) in r and returns their keys.
// [Default] has them already; tests building their own registry call this
// when they need them.
func RegisterBuiltins(r *Registry) (profile Key[string], strict, watch Key[bool]) {
	profile = MustRegisterIn(r, Spec[string]{
		Key:     "profile",
		Default: "local",
		Enum:    slices.Clone(Profiles),
		Flag:    true,
		Description: "Built-in preset of defaults for a deployment shape: `local` for a laptop or VM, " +
			"`k8s` for Kubernetes, `ci` for throwaway runs. Any value a profile sets can be overridden.",
	})
	strict = MustRegisterIn(r, Spec[bool]{
		Key:     "config.strict",
		Default: true,
		Description: "Reject config files containing keys scrim does not know. When false, unknown keys " +
			"are reported as warnings instead.",
	})
	watch = MustRegisterIn(r, Spec[bool]{
		Key:     "config.watch",
		Default: true,
		Description: "Reload the configuration when a config file or an included file changes. " +
			"SIGHUP always triggers a reload.",
	})
	return profile, strict, watch
}

// Options says where [Build] reads configuration from.
type Options struct {
	// Registry holds the settings; nil means [Default].
	Registry *Registry
	// ConfigPaths are explicit config files (--config, repeatable). When
	// empty, SCRIM_CONFIG and then the search path are used.
	ConfigPaths []string
	// Environ is the environment as from os.Environ; nil means os.Environ().
	Environ []string
	// Flags is the parsed flag set bound with [Registry.BindFlags]; nil
	// means no flags.
	Flags *pflag.FlagSet
	// Stores resolves store references. When nil, store references are
	// checked for syntax only and reported by [Config.Unresolved].
	Stores StoreResolver
	// SystemDir overrides /etc/scrim, for tests.
	SystemDir string
	// Context bounds store reference resolution; nil means Background.
	Context context.Context
}

// Warning is something worth telling the operator that does not make the
// configuration invalid: a literal secret, an unknown key under
// `config.strict: false`. Messages never contain secret values.
type Warning struct {
	Key     string `json:"key,omitempty"`
	Source  Source `json:"source"`
	Message string `json:"message"`
}

func (w Warning) String() string {
	p := Problem{Key: w.Key, Source: w.Source, Err: errors.New(w.Message)}
	return p.Error()
}

// meta is what a built Config knows beyond its values.
type meta struct {
	files     []string
	watchDirs []string
	profile   string
	warnings  []Warning
	secrets   map[string]secret.Value
	deferred  []string
	version   uint64
	pending   []string
	// collections holds the instances of every collection by key.
	collections map[string]colState
	// resolver resolves references with the environment Build saw.
	resolver refResolver
	// stateHome and home are XDG_STATE_HOME and HOME as Build saw them.
	stateHome, home string
}

// Build reads the whole configuration: built-in defaults, the selected
// profile, the config files with their includes, the environment and the
// flags, in that order of precedence (flag wins). Secret references other
// than store references are resolved, and store references too when
// opts.Stores is set. Every problem is reported in one error (see
// [Problems]); no partial Config is returned.
func Build(opts Options) (*Config, error) {
	r := opts.Registry
	if r == nil {
		r = Default
	}
	environ := opts.Environ
	if environ == nil {
		environ = os.Environ()
	}
	env := environMap(environ)
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}

	var errs []error
	disc, err := Discover(opts.ConfigPaths, env, opts.SystemDir)
	if err != nil {
		errs = append(errs, err)
	}
	files, err := LoadFiles(r, disc.Paths)
	if err != nil {
		errs = append(errs, err)
	}
	envLayer := EnvLayer(environ)
	var flagLayer Layer = LayerFunc(func(*Registry) ([]Raw, error) { return nil, nil })
	if opts.Flags != nil {
		flagLayer = FlagLayer(opts.Flags)
	}
	envRaws, _ := envLayer.Values(r)
	flagRaws, _ := flagLayer.Values(r)

	// Strictness and the profile decide how the other layers apply, so they
	// are read first from the layers above the profile.
	strict := true
	if s, ok := r.Lookup("config.strict"); ok {
		if v, ok := topValue(s, files.Raws, envRaws, flagRaws); ok {
			strict = v.(bool)
		}
	}
	var warnings []Warning
	for _, u := range files.Unknown {
		if strict {
			errs = append(errs, u)
		} else {
			warnings = append(warnings, Warning{Key: u.Key, Source: u.Source, Message: u.Err.Error()})
		}
	}
	profile := ""
	if s, ok := r.Lookup("profile"); ok {
		profile = s.Default.(string)
		if v, ok := topValue(s, files.Raws, envRaws, flagRaws); ok {
			profile = v.(string)
		}
	}

	c, err := Load(r, profileLayer(profile), files.Layer(), staticLayer(envRaws), staticLayer(flagRaws))
	if err != nil {
		errs = append(errs, err)
	}
	states := map[string]colState{}
	for _, col := range r.Collections() {
		states[col.Key] = colState{}
	}
	for _, cr := range files.colRaws {
		states[cr.col.Key].apply(cr)
	}
	colWarns, colErrs := applyCollectionEnv(r, states, environ)
	warnings = append(warnings, colWarns...)
	errs = append(errs, colErrs...)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	c.files = files.Files
	c.watchDirs = files.WatchDirs
	c.stateHome, c.home = env["XDG_STATE_HOME"], env["HOME"]
	c.profile = profile
	c.warnings = warnings
	c.collections = states
	if err := errors.Join(c.checkCollections()...); err != nil {
		return nil, err
	}

	c.resolver = refResolver{env: env, stores: opts.Stores}
	if err := c.resolveSecrets(ctx, c.resolver); err != nil {
		c.wipe()
		return nil, err
	}
	if err := r.runChecks(c); err != nil {
		c.wipe()
		return nil, err
	}
	return c, nil
}

func staticLayer(raws []Raw) Layer {
	return LayerFunc(func(*Registry) ([]Raw, error) { return raws, nil })
}

// topValue returns the highest-precedence valid value for s among the
// layers, flags first. An invalid value is skipped here; [Load] reports it.
func topValue(s *Setting, layers ...[]Raw) (any, bool) {
	for i := len(layers) - 1; i >= 0; i-- {
		raws := layers[i]
		for j := len(raws) - 1; j >= 0; j-- {
			if raws[j].Key != s.Key {
				continue
			}
			if v, err := Parse(s, raws[j].Value); err == nil {
				return v, true
			}
		}
	}
	return nil, false
}

// profileLayer supplies the values the named profile gives each setting.
func profileLayer(name string) Layer {
	return LayerFunc(func(r *Registry) ([]Raw, error) {
		var out []Raw
		for _, s := range r.Settings() {
			if v, ok := s.Profiles[name]; ok {
				out = append(out, Raw{Key: s.Key, Value: clone(v), Source: Source{Kind: SourceProfile, Name: name}, Merge: true})
			}
		}
		return out, nil
	})
}

// resolveSecrets resolves every secret-ref setting, collecting every
// problem. Literals are warned about, or rejected where a reference is
// required.
func (c *Config) resolveSecrets(ctx context.Context, rr refResolver) error {
	c.secrets = map[string]secret.Value{}
	var errs []error
	for _, f := range c.secretFields() {
		switch f.ref.Kind() {
		case RefNone:
			continue
		case RefLiteral:
			if f.require {
				errs = append(errs, &Problem{Key: f.key, Source: f.source, Err: errors.New("a literal secret is not accepted here; use env:, file:, cred: or a store reference")})
				continue
			}
			c.warnings = append(c.warnings, Warning{Key: f.key, Source: f.source, Message: "holds a literal secret; use env:, file:, cred: or a store reference instead"})
		case RefEnv, RefFile, RefCredential, RefStore:
		}
		v, err := rr.resolve(ctx, f.ref)
		switch {
		case errors.Is(err, ErrUnresolved):
			c.deferred = append(c.deferred, f.key)
		case err != nil:
			errs = append(errs, &Problem{Key: f.key, Source: f.source, Err: err})
		default:
			c.secrets[f.key] = v
		}
	}
	return errors.Join(errs...)
}

// secretFields lists every secret-ref setting and collection secret field,
// sorted by key.
func (c *Config) secretFields() []secretField {
	var out []secretField
	for _, e := range c.Entries() {
		if e.Setting.Kind == KindSecretRef {
			out = append(out, secretField{key: e.Setting.Key, ref: e.Value.(SecretRef), source: e.Source,
				require: e.Setting.RequireReference, restart: e.Setting.RestartRequired})
		}
	}
	out = append(out, c.collectionSecrets()...)
	slices.SortFunc(out, func(a, b secretField) int { return strings.Compare(a.key, b.key) })
	return out
}

// ResolveRef resolves any secret reference with the environment the Config
// was built from and its store resolver, for references that live outside
// settings (catalog entries, store adapter options). Errors name the
// reference form only.
func (c *Config) ResolveRef(ctx context.Context, ref SecretRef) (secret.Value, error) {
	if ref.Kind() == RefNone {
		return secret.Value{}, errors.New("empty secret reference")
	}
	return c.resolver.resolve(ctx, ref)
}

// Getenv returns a variable of the environment the Config was built from
// (Options.Environ, or the process environment), for settings whose default
// comes from a standard variable outside the SCRIM_ namespace, such as the
// upstream proxy from HTTPS_PROXY. Empty when unset.
func (c *Config) Getenv(name string) string { return c.resolver.env[name] }

// SecretAt returns the resolved value of a secret field by its full key:
// a secret-ref setting (`stores.token`) or a collection secret field
// (`stores.bao-prod.token`).
func (c *Config) SecretAt(key string) (secret.Value, bool) {
	v, ok := c.secrets[key]
	return v, ok
}

// String keeps fmt from printing a Config's internals, which include the
// environment it was built from.
func (c *Config) String() string {
	return fmt.Sprintf("config.Config(version %d, %d settings)", c.version, len(c.values))
}

// GoString implements fmt.GoStringer like [Config.String].
func (c *Config) GoString() string { return c.String() }

// wipe clears every resolved secret of a Config that is being discarded.
func (c *Config) wipe() {
	for _, v := range c.secrets {
		v.Wipe()
	}
}

// Secret returns the resolved value of a secret-ref setting. ok is false
// when the setting is empty or holds a store reference not resolved yet
// (see [Config.Unresolved]).
func (c *Config) Secret(k Key[SecretRef]) (v secret.Value, ok bool) {
	v, ok = c.secrets[k.Name()]
	return v, ok
}

// EachSecret calls fn with the full key and the resolved value of every
// secret field that holds one, sorted by key: secret-ref settings and
// collection secret fields, whatever kind of reference they were read
// through. fn must not retain or wipe v; the Config owns it.
func (c *Config) EachSecret(fn func(key string, v secret.Value)) {
	keys := make([]string, 0, len(c.secrets))
	for k := range c.secrets {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if v := c.secrets[k]; !v.IsZero() {
			fn(k, v)
		}
	}
}

// Unresolved lists the secret-ref settings holding store references that
// were not resolved because no [StoreResolver] was given.
func (c *Config) Unresolved() []string { return slices.Clone(c.deferred) }

// ResolveStores returns a copy of c with its unresolved store references
// resolved by sr: those of the settings named by keys, or all of them when
// keys is empty. The others stay unresolved. c itself is not changed. Every
// failure is reported.
func (c *Config) ResolveStores(ctx context.Context, sr StoreResolver, keys ...string) (*Config, error) {
	n := c.clone()
	n.secrets = make(map[string]secret.Value, len(c.secrets)+len(c.deferred))
	for k, v := range c.secrets {
		n.secrets[k] = v
	}
	n.deferred = nil
	var errs []error
	fields := map[string]secretField{}
	for _, f := range c.secretFields() {
		fields[f.key] = f
	}
	n.resolver.stores = sr
	for _, key := range c.deferred {
		if len(keys) > 0 && !slices.Contains(keys, key) {
			n.deferred = append(n.deferred, key)
			continue
		}
		f := fields[key]
		v, err := n.resolver.resolve(ctx, f.ref)
		if err != nil {
			errs = append(errs, &Problem{Key: key, Source: f.source, Err: err})
			continue
		}
		n.secrets[key] = v
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return n, nil
}

func (c *Config) clone() *Config {
	n := &Config{reg: c.reg, values: make(map[string]Entry, len(c.values)), meta: c.meta}
	for k, e := range c.values {
		n.values[k] = e
	}
	n.collections = make(map[string]colState, len(c.collections))
	for k, st := range c.collections {
		cp := make(colState, len(st))
		for name, inst := range st {
			cp[name] = inst.clone()
		}
		n.collections[k] = cp
	}
	return n
}

// Files lists every config file read, in the order applied.
func (c *Config) Files() []string { return slices.Clone(c.files) }

// Profile returns the profile in effect.
func (c *Config) Profile() string { return c.profile }

// Warnings returns the warnings found while building the Config.
func (c *Config) Warnings() []Warning { return slices.Clone(c.warnings) }

// Version is the configuration version: 0 for a Config not published by a
// [Manager], then 1 for the first and one more for every applied reload.
func (c *Config) Version() uint64 { return c.version }

// PendingRestart lists restart-only settings whose configured value differs
// from the running one. They keep the running value until scrim restarts.
func (c *Config) PendingRestart() []string { return slices.Clone(c.pending) }

// Check is a cross-setting validation run by [Build] after every value is
// parsed. It returns every problem it finds; messages must not contain
// secret values.
type Check func(c *Config) []error

// AddCheck registers a validation over the whole Config, for rules that
// span several settings. A failing check rejects the Config, at start-up and
// on reload alike.
func (r *Registry) AddCheck(name string, check Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks = append(r.checks, namedCheck{name: name, fn: check})
}

type namedCheck struct {
	name string
	fn   Check
}

func (r *Registry) runChecks(c *Config) error {
	r.mu.RLock()
	checks := slices.Clone(r.checks)
	r.mu.RUnlock()
	var errs []error
	for _, ch := range checks {
		for _, err := range ch.fn(c) {
			var p *Problem
			if !errors.As(err, &p) {
				err = &Problem{Err: fmt.Errorf("%s: %w", ch.name, err)}
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// StateDir is scrim's directory for local state, $XDG_STATE_HOME/scrim
// (~/.local/state/scrim), from the environment the Config was built from,
// so a test or a service with its own environment never touches the user's.
func (c *Config) StateDir() (string, error) {
	if c.stateHome != "" && filepath.IsAbs(c.stateHome) {
		return filepath.Join(c.stateHome, "scrim"), nil
	}
	home := c.home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("config: no XDG_STATE_HOME and no home directory: %w", err)
		}
		home = h
	}
	return filepath.Join(home, ".local", "state", "scrim"), nil
}
