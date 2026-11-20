// SPDX-License-Identifier: AGPL-3.0-only

// Package options decodes a store instance's adapter options
// (stores.Instance.Options) strictly.
//
// Options arrive as a map that may be nested ({"watch": {"interval": "5s"}}),
// dotted ({"watch.interval": "5s"}) or a mix, and values may be typed (from a
// YAML file) or strings (from SCRIM_* environment variables and flags). A
// [Decoder] flattens the map to dotted keys, converts each value on request,
// and [Decoder.Finish] reports every key nobody asked for, naming the
// closest known key, so a typo fails start-up instead of being ignored.
package options

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// Decoder reads options for one store instance.
type Decoder struct {
	store string
	vals  map[string]any
	known []string
	errs  []error
}

// New flattens raw. store names the instance in errors.
func New(store string, raw map[string]any) *Decoder {
	d := &Decoder{store: store, vals: map[string]any{}}
	d.flatten("", raw)
	return d
}

func (d *Decoder) flatten(prefix string, m map[string]any) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if sub, ok := v.(map[string]any); ok {
			d.flatten(key, sub)
			continue
		}
		if _, dup := d.vals[key]; dup {
			d.errs = append(d.errs, fmt.Errorf("store %s: option %s set twice", d.store, key))
			continue
		}
		d.vals[key] = v
	}
}

func (d *Decoder) take(key string) (any, bool) {
	d.known = append(d.known, key)
	v, ok := d.vals[key]
	return v, ok
}

func (d *Decoder) fail(key, want string) {
	// The value is not quoted: an option may hold a credential pasted in
	// the wrong place.
	d.errs = append(d.errs, fmt.Errorf("store %s: option %s must be %s", d.store, key, want))
}

// String returns a string option, or def when unset.
func (d *Decoder) String(key, def string) string {
	v, ok := d.take(key)
	if !ok {
		return def
	}
	switch s := v.(type) {
	case string:
		return s
	case config.SecretRef:
		return string(s)
	}
	d.fail(key, "a string")
	return def
}

// SecretRef returns a secret-valued option in reference form (`env:NAME`,
// `file:/path`, a store reference or a literal), or "" when unset. The
// value is resolved later through stores.Instance.Resolve.
func (d *Decoder) SecretRef(key string) config.SecretRef {
	return config.SecretRef(d.String(key, ""))
}

// SecretRef returns a secret-valued option in reference form (`env:NAME`,
// `file:/path`, a store reference or a literal), or "" when unset. Both
// config.SecretRef and plain strings are accepted. The value is not
// resolved here.
func (d *Decoder) SecretRef(key string) config.SecretRef {
	v, ok := d.take(key)
	if !ok {
		return ""
	}
	switch x := v.(type) {
	case config.SecretRef:
		return x
	case string:
		return config.SecretRef(x)
	}
	d.fail(key, "a secret reference")
	return ""
}

// Bool returns a boolean option, or def when unset.
func (d *Decoder) Bool(key string, def bool) bool {
	v, ok := d.take(key)
	if !ok {
		return def
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		b, err := strconv.ParseBool(x)
		if err == nil {
			return b
		}
	}
	d.fail(key, "true or false")
	return def
}

// Int returns an integer option, or def when unset.
func (d *Decoder) Int(key string, def int64) int64 {
	v, ok := d.take(key)
	if !ok {
		return def
	}
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case float64:
		if x == float64(int64(x)) {
			return int64(x)
		}
	case string:
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return n
		}
	}
	d.fail(key, "an integer")
	return def
}

// Size returns a byte size option: an integer or a string such as "512KiB",
// "1MiB", "2MB". def applies when unset.
func (d *Decoder) Size(key string, def int64) int64 {
	v, ok := d.take(key)
	if !ok {
		return def
	}
	if s, isStr := v.(string); isStr {
		if n, err := ParseSize(s); err == nil {
			return n
		}
		d.fail(key, "a size such as 1048576 or 1MiB")
		return def
	}
	d.known = d.known[:len(d.known)-1]
	return d.Int(key, def)
}

// Duration returns a duration option ("10s", "1m30s"), or def when unset.
func (d *Decoder) Duration(key string, def time.Duration) time.Duration {
	v, ok := d.take(key)
	if !ok {
		return def
	}
	switch x := v.(type) {
	case time.Duration:
		return x
	case string:
		if t, err := time.ParseDuration(x); err == nil {
			return t
		}
	}
	d.fail(key, "a duration such as 10s")
	return def
}

// Strings returns a list option. A string is split on commas, as an
// environment variable would carry it.
func (d *Decoder) Strings(key string) []string {
	v, ok := d.take(key)
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case []string:
		return slices.Clone(x)
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				d.fail(key, "a list of strings")
				return nil
			}
			out = append(out, s)
		}
		return out
	case string:
		var out []string
		for _, p := range strings.Split(x, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	d.fail(key, "a list of strings")
	return nil
}

// Errorf records a validation error for the instance.
func (d *Decoder) Errorf(format string, args ...any) {
	d.errs = append(d.errs, fmt.Errorf("store %s: "+format, append([]any{d.store}, args...)...))
}

// Finish returns every conversion error and every unknown key, each naming
// the closest known key.
func (d *Decoder) Finish() error {
	keys := make([]string, 0, len(d.vals))
	for k := range d.vals {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if slices.Contains(d.known, k) {
			continue
		}
		msg := fmt.Sprintf("store %s: unknown option %s", d.store, k)
		if c := closest(k, d.known); c != "" {
			msg += fmt.Sprintf(" (did you mean %s?)", c)
		}
		d.errs = append(d.errs, errors.New(msg))
	}
	return errors.Join(d.errs...)
}

// ParseSize parses "1048576", "512KiB", "1MiB", "1GiB", "10KB", "2MB".
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"B", 1}}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("invalid size")
	}
	return n * mult, nil
}

func closest(k string, known []string) string {
	best, bestD := "", len(k)/2+2
	for _, c := range known {
		if dd := distance(k, c); dd < bestD {
			best, bestD = c, dd
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
