// SPDX-License-Identifier: AGPL-3.0-only

package stores

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Ref addresses one secret, or one field of it, in one store instance:
//
//	<scheme>://<path>[?<selector>=<value>&...][#<field>]
//
// for example `bao://kv/agents/github#token` or
// `aws-sm://agents/github?stage=AWSPREVIOUS`. The scheme names a configured
// store instance (its name or an alias), not an adapter kind, so two Vault
// clusters can be `vault-eu://` and `vault-us://`. A Ref is metadata and is
// safe to log.
type Ref struct {
	// Scheme is the store instance alias, lower case.
	Scheme string
	// Path is the store-specific path, never empty, without leading or
	// trailing slashes.
	Path string
	// Field selects one field of a multi-field secret; empty means the
	// whole secret.
	Field string
	// Selectors holds store-specific version selectors (`version`,
	// `stage`) in canonical query form: keys sorted, each once. It is a
	// string so that Ref stays comparable and usable as a map key; read it
	// with [Ref.Selector].
	Selectors string
}

var schemePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// ParseRef parses a reference. Errors wrap [ErrInvalidRef] and quote only
// the scheme or the part that failed, never a value: a reference is not a
// value, but a user may paste one by mistake.
func ParseRef(s string) (Ref, error) {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return Ref{}, fmt.Errorf("%w: missing <scheme>://", ErrInvalidRef)
	}
	if !schemePattern.MatchString(scheme) {
		return Ref{}, fmt.Errorf("%w: scheme must be lower-case words joined by dashes", ErrInvalidRef)
	}
	r := Ref{Scheme: scheme}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		r.Field, rest = rest[i+1:], rest[:i]
		if r.Field == "" {
			return Ref{}, fmt.Errorf("%w: empty field after #", ErrInvalidRef)
		}
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		q, err := url.ParseQuery(rest[i+1:])
		if err != nil {
			return Ref{}, fmt.Errorf("%w: malformed selectors", ErrInvalidRef)
		}
		rest = rest[:i]
		for k, v := range q {
			if k == "" || len(v) != 1 || v[0] == "" {
				return Ref{}, fmt.Errorf("%w: selector %q must appear once with a value", ErrInvalidRef, k)
			}
		}
		r.Selectors = q.Encode() // sorted by key
	}
	r.Path = strings.Trim(rest, "/")
	if r.Path == "" {
		return Ref{}, fmt.Errorf("%w: empty path", ErrInvalidRef)
	}
	if strings.Contains(r.Path, "//") {
		return Ref{}, fmt.Errorf("%w: empty path segment", ErrInvalidRef)
	}
	return r, nil
}

// MustParseRef is [ParseRef] that panics, for tests and constants.
func MustParseRef(s string) Ref {
	r, err := ParseRef(s)
	if err != nil {
		panic(err)
	}
	return r
}

// String renders the reference in canonical form: selectors sorted, path
// without surrounding slashes. ParseRef(r.String()) == r.
func (r Ref) String() string {
	var b strings.Builder
	b.WriteString(r.Scheme)
	b.WriteString("://")
	b.WriteString(r.Path)
	if r.Selectors != "" {
		b.WriteByte('?')
		b.WriteString(r.Selectors)
	}
	if r.Field != "" {
		b.WriteByte('#')
		b.WriteString(r.Field)
	}
	return b.String()
}

// Selector returns the value of one selector, or "".
func (r Ref) Selector(name string) string {
	q, _ := url.ParseQuery(r.Selectors)
	return q.Get(name)
}

// Secret returns r without its field selector: the whole secret.
func (r Ref) Secret() Ref {
	r.Field = ""
	return r
}

// WithField returns r selecting field.
func (r Ref) WithField(field string) Ref {
	r.Field = field
	return r
}

// IsZero reports whether r is the zero Ref.
func (r Ref) IsZero() bool { return r.Scheme == "" && r.Path == "" }

// MarshalText implements encoding.TextMarshaler.
func (r Ref) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (r *Ref) UnmarshalText(b []byte) error {
	p, err := ParseRef(string(b))
	if err != nil {
		return err
	}
	*r = p
	return nil
}
