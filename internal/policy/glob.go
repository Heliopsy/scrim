// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"fmt"
)

// Glob patterns are used by the `glob` rule function and by the data-plane
// snapshot. The syntax is deliberately small so the control plane and the
// data plane implement it identically:
//
//	*    any run of characters except '/'
//	**   any run of characters including '/'
//	?    exactly one character except '/'
//	\x   the literal character x
//
// Every other character matches itself. Matching is on Unicode code points
// and anchored at both ends. There are no character classes or alternation;
// use several rules or `||` instead.

type globTok struct {
	kind byte // 'l' literal, '?' one, '*' star, 'S' double star
	r    rune
}

// compileGlob parses a pattern into tokens.
func compileGlob(p string) ([]globTok, error) {
	rs := []rune(p)
	toks := make([]globTok, 0, len(rs))
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\\':
			if i+1 >= len(rs) {
				return nil, errors.New("glob: trailing backslash")
			}
			i++
			toks = append(toks, globTok{kind: 'l', r: rs[i]})
		case '?':
			toks = append(toks, globTok{kind: '?'})
		case '*':
			if i+1 < len(rs) && rs[i+1] == '*' {
				i++
				for i+1 < len(rs) && rs[i+1] == '*' {
					i++
				}
				toks = append(toks, globTok{kind: 'S'})
			} else {
				toks = append(toks, globTok{kind: '*'})
			}
		default:
			toks = append(toks, globTok{kind: 'l', r: rs[i]})
		}
	}
	return toks, nil
}

// ValidateGlob reports whether p is a valid glob pattern.
func ValidateGlob(p string) error {
	_, err := compileGlob(p)
	return err
}

// Glob reports whether s matches pattern p. An invalid pattern matches
// nothing.
func Glob(p, s string) bool {
	toks, err := compileGlob(p)
	if err != nil {
		return false
	}
	return globMatch(toks, []rune(s))
}

// globMatch is a dynamic programme over (token, position): cur[j] is true
// when the tokens consumed so far match s[:j]. It runs in O(len(toks) *
// len(s)) with no backtracking, so hostile inputs cannot blow it up.
func globMatch(toks []globTok, s []rune) bool {
	n := len(s)
	cur := make([]bool, n+1)
	next := make([]bool, n+1)
	cur[0] = true
	for _, t := range toks {
		clear(next)
		switch t.kind {
		case 'l':
			for j := 0; j < n; j++ {
				if cur[j] && s[j] == t.r {
					next[j+1] = true
				}
			}
		case '?':
			for j := 0; j < n; j++ {
				if cur[j] && s[j] != '/' {
					next[j+1] = true
				}
			}
		case '*':
			for j := 0; j <= n; j++ {
				// Zero characters, or one more non-separator.
				next[j] = cur[j] || (j > 0 && next[j-1] && s[j-1] != '/')
			}
		case 'S':
			for j := 0; j <= n; j++ {
				next[j] = cur[j] || (j > 0 && next[j-1])
			}
		default:
			panic(fmt.Sprintf("glob: unknown token %q", t.kind))
		}
		cur, next = next, cur
	}
	return cur[n]
}
