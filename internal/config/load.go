// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/pflag"
)

// SourceKind is the precedence level a value came from.
type SourceKind string

// Source kinds, lowest precedence first.
const (
	SourceDefault SourceKind = "default"
	SourceProfile SourceKind = "profile"
	SourceFile    SourceKind = "file"
	SourceEnv     SourceKind = "env"
	SourceFlag    SourceKind = "flag"
)

// Source says where an effective value came from.
type Source struct {
	Kind SourceKind
	// Name is the profile name, file path, environment variable or flag,
	// empty for defaults.
	Name string
}

func (s Source) String() string {
	if s.Name == "" {
		return string(s.Kind)
	}
	return string(s.Kind) + ":" + s.Name
}

// Raw is one value a layer supplies before parsing. Value is a string for
// environment and flag layers (in the environment encoding) or a decoded
// YAML value (string, bool, number, []any, map[string]any) for file layers.
type Raw struct {
	Key    string
	Value  any
	Source Source
}

// Layer supplies values from one source. Layers are applied in the order
// given to [Load]; a later layer overrides an earlier one, so pass them
// lowest precedence first: profile, files, environment, flags.
type Layer interface {
	Values(r *Registry) ([]Raw, error)
}

// LayerFunc adapts a function to [Layer].
type LayerFunc func(r *Registry) ([]Raw, error)

// Values implements [Layer].
func (f LayerFunc) Values(r *Registry) ([]Raw, error) { return f(r) }

// Entry is one setting's effective value with its provenance.
type Entry struct {
	Setting *Setting
	Value   any
	Source  Source
}

// Config is an immutable set of effective values for every setting of a
// registry. Read it through typed [Key] handles.
type Config struct {
	reg    *Registry
	values map[string]Entry
}

// Registry returns the registry the config was built from.
func (c *Config) Registry() *Registry { return c.reg }

// Entry returns the effective entry for key.
func (c *Config) Entry(key string) (Entry, bool) {
	e, ok := c.values[key]
	return e, ok
}

// Entries returns every entry sorted by key.
func (c *Config) Entries() []Entry {
	out := make([]Entry, 0, len(c.values))
	for _, e := range c.values {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Setting.Key < out[j].Setting.Key })
	return out
}

// Weakened returns the weakening settings that are not at their safe
// default, for the start-up warning and `scrim status`.
func (c *Config) Weakened() []Entry {
	var out []Entry
	for _, e := range c.Entries() {
		if e.Setting.Weakening && e.Source.Kind != SourceDefault && fmt.Sprint(e.Value) != fmt.Sprint(e.Setting.Default) {
			out = append(out, e)
		}
	}
	return out
}

// Load builds a Config from r's defaults and the given layers. Every problem
// is reported, joined into one error, and no partial Config is returned.
func Load(r *Registry, layers ...Layer) (*Config, error) {
	c := &Config{reg: r, values: map[string]Entry{}}
	for _, s := range r.Settings() {
		c.values[s.Key] = Entry{Setting: s, Value: clone(s.Default), Source: Source{Kind: SourceDefault}}
	}
	var errs []error
	for _, l := range layers {
		raws, err := l.Values(r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, raw := range raws {
			s, ok := r.Lookup(raw.Key)
			if !ok {
				err := fmt.Errorf("%s: %w %q", raw.Source, ErrUnknownKey, raw.Key)
				if near := r.Closest(raw.Key); near != "" {
					err = fmt.Errorf("%w (did you mean %q?)", err, near)
				}
				errs = append(errs, err)
				continue
			}
			v, err := Parse(s, raw.Value)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %s: %w", raw.Source, s.Key, err))
				continue
			}
			c.values[s.Key] = Entry{Setting: s, Value: v, Source: raw.Source}
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// MustLoadDefaults returns a Config with every setting at its default. It is
// meant for tests.
func MustLoadDefaults(r *Registry) *Config {
	c, err := Load(r)
	if err != nil {
		panic(err)
	}
	return c
}

// EnvLayer reads SCRIM_* variables from environ (as returned by os.Environ).
// Variables that name no setting are ignored, since some SCRIM_ variables
// are not settings (SCRIM_CONFIG, SCRIM_DP_FD).
func EnvLayer(environ []string) Layer {
	return LayerFunc(func(r *Registry) ([]Raw, error) {
		var out []Raw
		for _, kv := range environ {
			name, val, ok := strings.Cut(kv, "=")
			if !ok || !strings.HasPrefix(name, "SCRIM_") {
				continue
			}
			if s, ok := r.LookupEnv(name); ok {
				out = append(out, Raw{Key: s.Key, Value: val, Source: Source{Kind: SourceEnv, Name: name}})
			}
		}
		return out, nil
	})
}

// BindFlags adds a flag to fs for every setting declared with Flag. Values
// are read back by [FlagLayer]; defaults are not applied through the flag
// set, so an unset flag never overrides another source.
func (r *Registry) BindFlags(fs *pflag.FlagSet) {
	for _, s := range r.Settings() {
		if !s.Flag || fs.Lookup(s.FlagName()) != nil {
			continue
		}
		usage := s.Description
		if s.Kind == KindBool {
			fs.Bool(s.FlagName(), s.Default.(bool), usage)
			continue
		}
		fs.String(s.FlagName(), FormatValue(s.Default), usage)
	}
}

// FlagLayer reads the flags bound by [Registry.BindFlags] that were set on
// the command line.
func FlagLayer(fs *pflag.FlagSet) Layer {
	return LayerFunc(func(r *Registry) ([]Raw, error) {
		var out []Raw
		for _, s := range r.Settings() {
			if !s.Flag {
				continue
			}
			f := fs.Lookup(s.FlagName())
			if f == nil || !f.Changed {
				continue
			}
			out = append(out, Raw{Key: s.Key, Value: f.Value.String(), Source: Source{Kind: SourceFlag, Name: "--" + f.Name}})
		}
		return out, nil
	})
}

// Parse converts a raw value to the setting's Go type and checks it.
//
// Strings use the environment encoding: booleans as strconv.ParseBool,
// durations as time.ParseDuration, lists as a JSON array or comma-separated
// items (a literal comma written as `\,`), maps as a JSON object or
// comma-separated `key=value` pairs.
func Parse(s *Setting, raw any) (any, error) {
	v, err := parse(s.Kind, raw)
	if err != nil {
		return nil, err
	}
	if err := s.check(v); err != nil {
		return nil, err
	}
	return v, nil
}

func parse(kind Kind, raw any) (any, error) {
	if str, ok := raw.(string); ok {
		return parseString(kind, str)
	}
	switch kind {
	case KindBool:
		if b, ok := raw.(bool); ok {
			return b, nil
		}
	case KindInt:
		switch n := raw.(type) {
		case int:
			return n, nil
		case int64:
			if n >= math.MinInt && n <= math.MaxInt {
				return int(n), nil
			}
		case uint64:
			if n <= math.MaxInt {
				return int(n), nil
			}
		case float64:
			if n == math.Trunc(n) && n >= math.MinInt && n <= math.MaxInt {
				return int(n), nil
			}
		}
	case KindFloat:
		switch n := raw.(type) {
		case float64:
			return n, nil
		case int:
			return float64(n), nil
		case int64:
			return float64(n), nil
		}
	case KindList:
		if items, ok := raw.([]any); ok {
			out := make([]string, 0, len(items))
			for _, it := range items {
				str, ok := it.(string)
				if !ok {
					return nil, fmt.Errorf("list items must be strings, got %T", it)
				}
				out = append(out, str)
			}
			return out, nil
		}
		if items, ok := raw.([]string); ok {
			return clone(items), nil
		}
	case KindMap:
		if m, ok := raw.(map[string]any); ok {
			out := make(map[string]string, len(m))
			for k, it := range m {
				str, ok := it.(string)
				if !ok {
					return nil, fmt.Errorf("map values must be strings, got %T for %q", it, k)
				}
				out[k] = str
			}
			return out, nil
		}
		if m, ok := raw.(map[string]string); ok {
			return clone(m), nil
		}
	case KindString, KindDuration, KindSecretRef:
		// Only strings are accepted, handled above.
	}
	return nil, fmt.Errorf("expected %s, got %T", kind, raw)
}

func parseString(kind Kind, s string) (any, error) {
	switch kind {
	case KindString:
		return s, nil
	case KindSecretRef:
		return SecretRef(s), nil
	case KindBool:
		return strconv.ParseBool(s)
	case KindInt:
		return strconv.Atoi(s)
	case KindFloat:
		return strconv.ParseFloat(s, 64)
	case KindDuration:
		return time.ParseDuration(s)
	case KindList:
		if strings.HasPrefix(strings.TrimSpace(s), "[") {
			var out []string
			if err := json.Unmarshal([]byte(s), &out); err != nil {
				return nil, fmt.Errorf("invalid JSON list: %w", err)
			}
			return out, nil
		}
		return splitEscaped(s, ','), nil
	case KindMap:
		if strings.HasPrefix(strings.TrimSpace(s), "{") {
			var out map[string]string
			if err := json.Unmarshal([]byte(s), &out); err != nil {
				return nil, fmt.Errorf("invalid JSON object: %w", err)
			}
			return out, nil
		}
		out := map[string]string{}
		for _, pair := range splitEscaped(s, ',') {
			k, v, ok := strings.Cut(pair, "=")
			if !ok || k == "" {
				return nil, fmt.Errorf("map entry %q is not key=value", pair)
			}
			out[k] = v
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported kind %s", kind)
}

// splitEscaped splits s on sep, honouring a backslash before sep or before
// another backslash. An empty s yields an empty list.
func splitEscaped(s string, sep byte) []string {
	out := []string{}
	if s == "" {
		return out
	}
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && (s[i+1] == sep || s[i+1] == '\\'):
			cur.WriteByte(s[i+1])
			i++
		case s[i] == sep:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(out, cur.String())
}

// FormatValue renders a value in the environment encoding, so that
// Parse(FormatValue(v)) round-trips. Lists and maps use JSON.
func FormatValue(v any) string {
	switch t := v.(type) {
	case []string, map[string]string:
		b, _ := json.Marshal(t)
		return string(b)
	case time.Duration:
		return t.String()
	}
	return fmt.Sprint(v)
}

// Holder publishes the current Config and notifies subscribers when a
// reload swaps in a new one. A reload builds a complete Config first and
// swaps it in one step, so readers never see a partial apply.
type Holder struct {
	cur  atomic.Pointer[Config]
	mu   sync.Mutex
	next int
	subs map[int]func(old, cur *Config)
}

// NewHolder returns a Holder serving c.
func NewHolder(c *Config) *Holder {
	h := &Holder{subs: map[int]func(old, cur *Config){}}
	h.cur.Store(c)
	return h
}

// Current returns the Config in effect.
func (h *Holder) Current() *Config { return h.cur.Load() }

// Swap installs c and calls every subscriber with the old and new Config.
func (h *Holder) Swap(c *Config) {
	h.mu.Lock()
	defer h.mu.Unlock()
	old := h.cur.Swap(c)
	for _, id := range sortedKeys(h.subs) {
		h.subs[id](old, c)
	}
}

// Subscribe registers fn to run after every Swap and returns a function that
// removes it. fn runs with the Holder's lock held and must not call Swap.
func (h *Holder) Subscribe(fn func(old, cur *Config)) (cancel func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.next
	h.next++
	h.subs[id] = fn
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.subs, id)
	}
}

func sortedKeys(m map[int]func(old, cur *Config)) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
