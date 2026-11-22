// SPDX-License-Identifier: AGPL-3.0-only

// Package env is the env store adapter: secrets read from scrim's own
// process environment, addressed as `env://NAME`.
//
// The source is read-only. It declares read and list only: the environment
// of a running process does not change from outside, so there is nothing to
// watch, and a write or watch is refused with stores.ErrUnsupported ("env
// source is read-only") before anything happens.
//
// Each variable is a secret with one field, "value". The `prefix` option
// limits the source to variables whose names start with it, and `allow`
// narrows it further to exact names or glob patterns; everything else is
// invisible and reads as not found, so a configuration mistake cannot expose
// scrim's whole environment by reference.
//
// Limitation: the Go runtime hands environment variables out as strings,
// which are immutable and cannot be wiped. The copy in the returned
// secret.Value is wiped as usual, but the process environment itself keeps
// the value for the life of the process. Prefer the file source, or a real
// store, for anything long-lived.
package env

import (
	"context"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/options"
)

// Kind is the adapter kind this package registers.
const Kind = "env"

// Field is the name of the only field an env secret has.
const Field = "value"

const readOnly = "env source is read-only"

func init() {
	stores.Register(Kind, func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		cfg, err := ParseOptions(inst.Name, inst.Options)
		if err != nil {
			return nil, err
		}
		return New(inst.Name, cfg), nil
	})
}

// Config is the env source's configuration.
type Config struct {
	// Prefix limits the source to variables whose names start with it
	// (option `prefix`).
	Prefix string
	// Allow, when non-empty, limits the source to variables matching one of
	// these exact names or path.Match glob patterns (option `allow`).
	Allow []string
}

// ParseOptions decodes and validates instance options strictly.
func ParseOptions(store string, raw map[string]any) (Config, error) {
	d := options.New(store, raw)
	cfg := Config{Prefix: d.String("prefix", ""), Allow: d.Strings("allow")}
	for _, p := range cfg.Allow {
		if _, err := path.Match(p, ""); err != nil {
			d.Errorf("option allow: malformed pattern %q", p)
		}
	}
	return cfg, d.Finish()
}

// Environment is where the adapter reads variables. The default is the
// process environment; tests inject their own.
type Environment interface {
	LookupEnv(name string) (string, bool)
	Environ() []string
}

type processEnv struct{}

func (processEnv) LookupEnv(name string) (string, bool) { return os.LookupEnv(name) }
func (processEnv) Environ() []string                    { return os.Environ() }

// Option tunes an Adapter.
type Option func(*Adapter)

// WithEnvironment replaces the process environment as the source.
func WithEnvironment(e Environment) Option { return func(a *Adapter) { a.env = e } }

// Adapter is the env source.
type Adapter struct {
	name string
	cfg  Config
	env  Environment
}

// New returns an env source named name.
func New(name string, cfg Config, opts ...Option) *Adapter {
	a := &Adapter{name: name, cfg: cfg, env: processEnv{}}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.name }

// Capabilities implements stores.Adapter: read, list and glob listing.
func (a *Adapter) Capabilities() stores.Capabilities {
	return stores.CapRead | stores.CapList | stores.CapGlob
}

func (a *Adapter) visible(name string) bool {
	if name == "" || !strings.HasPrefix(name, a.cfg.Prefix) {
		return false
	}
	if len(a.cfg.Allow) == 0 {
		return true
	}
	for _, p := range a.cfg.Allow {
		if p == name {
			return true
		}
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

func (a *Adapter) err(op stores.Op, ref stores.Ref, kind error, detail string) error {
	e := stores.NewError(a.name, op, ref, kind, nil)
	e.Detail = detail
	return e
}

// Read implements stores.Adapter.
func (a *Adapter) Read(_ context.Context, ref stores.Ref) (stores.Secret, error) {
	if ref.Selectors != "" {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, "the env source has no version selectors")
	}
	if strings.ContainsAny(ref.Path, "=\x00") {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrInvalidRef, "not a variable name")
	}
	if ref.Field != "" && ref.Field != Field {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, `env secrets have one field, "value"`)
	}
	if !a.visible(ref.Path) {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "")
	}
	v, ok := a.env.LookupEnv(ref.Path)
	if !ok {
		return stores.Secret{}, a.err(stores.OpRead, ref, stores.ErrNotFound, "")
	}
	return stores.Secret{
		Meta:   stores.Metadata{Ref: ref.Secret(), Fields: []string{Field}, Labels: a.labels(ref.Path)},
		Fields: map[string]secret.Value{Field: secret.FromString(v)},
	}, nil
}

// List implements stores.Adapter. The prefix is matched by path segments
// like every store (`env://APP` lists APP and APP/...); a prefix ending in
// `*` is a glob (stores.CapGlob) and matches names by plain string prefix
// instead, so `env://SCRIM_*` lists every visible variable starting with
// SCRIM_. Only a trailing `*` is special; the prefix and allow options still
// decide what is visible.
func (a *Adapter) List(_ context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	match := func(name string) bool {
		p := prefix.Path
		if s, ok := strings.CutSuffix(p, "*"); ok {
			return strings.HasPrefix(name, s)
		}
		return name == p || strings.HasPrefix(name, strings.TrimSuffix(p, "/")+"/")
	}
	var names []string
	for _, kv := range a.env.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if ok && a.visible(name) && match(name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	out := make([]stores.Metadata, 0, len(names))
	for _, n := range names {
		out = append(out, stores.Metadata{Ref: stores.Ref{Scheme: prefix.Scheme, Path: n}, Fields: []string{Field}, Labels: a.labels(n)})
	}
	return out, nil
}

// labels are an env secret's native labels: env.variable, the variable
// name, and env.prefix, the configured prefix when there is one.
func (a *Adapter) labels(name string) map[string]string {
	l := map[string]string{}
	stores.SetNative(l, Kind, "variable", name)
	stores.SetNative(l, Kind, "prefix", a.cfg.Prefix)
	return l
}

// Watch implements stores.Adapter: always refused.
func (a *Adapter) Watch(_ context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	return nil, a.err(stores.OpWatch, prefix, stores.ErrUnsupported, readOnly)
}

// Write implements stores.Adapter: always refused, before anything is
// touched. The caller's values are left as they are.
func (a *Adapter) Write(_ context.Context, ref stores.Ref, _ map[string]secret.Value, _ stores.WriteOptions) (stores.Metadata, error) {
	return stores.Metadata{}, a.err(stores.OpWrite, ref.Secret(), stores.ErrUnsupported, readOnly)
}

// Health implements stores.Adapter. The environment is always there.
func (a *Adapter) Health(context.Context) error { return nil }

// Close implements stores.Adapter.
func (a *Adapter) Close() error { return nil }
