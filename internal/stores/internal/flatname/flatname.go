// SPDX-License-Identifier: AGPL-3.0-only

// Package flatname maps scrim's hierarchical reference paths onto stores
// whose secret names are flat (Google Secret Manager, Azure Key Vault).
//
// A path's segments are joined with a separator ("--" by default) to form
// the store name: `agents/github` is the secret `agents--github`. The
// mapping is reversible as long as no segment contains the separator or
// starts or ends with a character the separator is made of, so a write
// whose path cannot round-trip is refused instead of landing under a name
// that would list as another path.
package flatname

import (
	"errors"
	"strings"
)

// Mapper joins and splits paths with one separator over one alphabet.
type Mapper struct {
	// Sep is the separator, for example "--".
	Sep string
	// Valid reports whether a byte may appear in a store name.
	Valid func(c byte) bool
	// MaxLen is the longest store name, 0 for no limit.
	MaxLen int
}

// Name returns the store name of path, or an error naming what is wrong
// (never the path itself, which the caller's error already names).
func (m Mapper) Name(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty path")
	}
	segs := strings.Split(path, "/")
	for _, s := range segs {
		if err := m.segment(s); err != nil {
			return "", err
		}
	}
	name := strings.Join(segs, m.Sep)
	if m.MaxLen > 0 && len(name) > m.MaxLen {
		return "", errors.New("name too long for the store")
	}
	return name, nil
}

func (m Mapper) segment(s string) error {
	if s == "" {
		return errors.New("empty path segment")
	}
	for i := 0; i < len(s); i++ {
		if !m.Valid(s[i]) {
			return errors.New("path segments may hold only characters the store allows in a secret name")
		}
	}
	if strings.Contains(s, m.Sep) {
		return errors.New("a path segment contains the path separator " + m.Sep)
	}
	// A segment starting or ending with a separator character would merge
	// with the separator ("a-" + "--" + "b" reads back as "a/-b").
	if strings.ContainsRune(m.Sep, rune(s[0])) || strings.ContainsRune(m.Sep, rune(s[len(s)-1])) {
		return errors.New("a path segment starts or ends with a character of the path separator " + m.Sep)
	}
	return nil
}

// Path returns the reference path of a store name: separators become '/'.
// A name that does not map back to itself (a leading, trailing or tripled
// separator, a character the store would not allow) has no path and is
// reported with ok false; listings skip it.
func (m Mapper) Path(name string) (string, bool) {
	segs := strings.Split(name, m.Sep)
	for _, s := range segs {
		if m.segment(s) != nil {
			return "", false
		}
	}
	return strings.Join(segs, "/"), true
}

// Prefix is a listing prefix: a path that selects itself and everything
// under it, or a glob ending in `*` that selects every path starting with
// the text before it. A trailing `/*` is the folder form.
type Prefix struct {
	path string
	glob bool
}

// ParsePrefix parses a listing prefix path.
func ParsePrefix(p string) Prefix {
	p = strings.TrimSuffix(p, "/*")
	if rest, ok := strings.CutSuffix(p, "*"); ok {
		return Prefix{path: rest, glob: true}
	}
	return Prefix{path: strings.Trim(p, "/")}
}

// Glob reports whether the prefix is a glob.
func (p Prefix) Glob() bool { return p.glob }

// Match reports whether path is selected.
func (p Prefix) Match(path string) bool {
	if p.glob {
		return strings.HasPrefix(path, p.path)
	}
	return p.path == "" || path == p.path || strings.HasPrefix(path, p.path+"/")
}
