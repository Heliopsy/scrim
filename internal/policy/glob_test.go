// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"regexp"
	"strings"
	"testing"
)

func TestGlob(t *testing.T) {
	tests := []struct {
		p, s string
		want bool
	}{
		{"", "", true},
		{"", "a", false},
		{"abc", "abc", true},
		{"abc", "abcd", false},
		{"bao://kv/prod/*", "bao://kv/prod/db", true},
		{"bao://kv/prod/*", "bao://kv/prod/a/b", false},
		{"bao://kv/prod/*", "bao://kv/prod/", true},
		{"bao://kv/prod/**", "bao://kv/prod/a/b", true},
		{"bao://kv/**/db", "bao://kv/prod/eu/db", true},
		{"bao://kv/**/db", "bao://kv/db", false},
		{"bao://kv/**db", "bao://kv/db", true},
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "github.com", false},
		{"*.github.com", "a.b.github.com", true},
		{"*.github.com", "evilgithub.com", false},
		{"?", "a", true},
		{"?", "/", false},
		{"?", "é", true},
		{"a?c", "abc", true},
		{`a\*c`, "a*c", true},
		{`a\*c`, "abc", false},
		{`\\`, `\`, true},
		{"***", "a/b", true},
		{"*", "", true},
		{"*a*b*", "xxaxxbxx", true},
		{"*a*b*", "xxbxxaxx", false},
	}
	for _, tt := range tests {
		if got := Glob(tt.p, tt.s); got != tt.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", tt.p, tt.s, got, tt.want)
		}
	}
	if Glob(`a\`, "a") {
		t.Error("invalid pattern matched")
	}
	if ValidateGlob(`a\`) == nil {
		t.Error("trailing backslash accepted")
	}
}

// globRegexp is an independent oracle for the glob semantics.
func globRegexp(p string) (*regexp.Regexp, bool) {
	var b strings.Builder
	b.WriteString(`^`)
	rs := []rune(p)
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\\':
			if i+1 >= len(rs) {
				return nil, false
			}
			i++
			b.WriteString(regexp.QuoteMeta(string(rs[i])))
		case '?':
			b.WriteString(`[^/]`)
		case '*':
			if i+1 < len(rs) && rs[i+1] == '*' {
				for i+1 < len(rs) && rs[i+1] == '*' {
					i++
				}
				b.WriteString(`(?s:.*)`)
			} else {
				b.WriteString(`[^/]*`)
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(rs[i])))
		}
	}
	b.WriteString(`$`)
	return regexp.MustCompile(b.String()), true
}

func FuzzGlob(f *testing.F) {
	for _, s := range []struct{ p, s string }{
		{"bao://kv/*/x", "bao://kv/a/x"}, {"**", "a/b"}, {"a?*\\*", "ab*"}, {"*.*.com", "a.b.com"},
	} {
		f.Add(s.p, s.s)
	}
	f.Fuzz(func(t *testing.T, p, s string) {
		if len(p) > 64 || len(s) > 256 {
			return
		}
		re, ok := globRegexp(p)
		if !ok {
			if ValidateGlob(p) == nil {
				t.Fatalf("pattern %q accepted, oracle rejects", p)
			}
			return
		}
		if !strings.ContainsRune(s, '�') && !strings.ContainsRune(p, '�') {
			if got, want := Glob(p, s), re.MatchString(s); got != want {
				t.Fatalf("Glob(%q, %q) = %v, oracle %v", p, s, got, want)
			}
		}
	})
}
