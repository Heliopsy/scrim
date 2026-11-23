// SPDX-License-Identifier: AGPL-3.0-only

package flatname

import "testing"

func dashes() Mapper {
	return Mapper{Sep: "--", MaxLen: 20, Valid: func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
	}}
}

func TestRoundTrip(t *testing.T) {
	m := dashes()
	for path, name := range map[string]string{"a": "a", "a/b": "a--b", "my-app/db-1/x": "my-app--db-1--x"} {
		got, err := m.Name(path)
		if err != nil || got != name {
			t.Errorf("Name(%q) = %q, %v; want %q", path, got, err, name)
		}
		back, ok := m.Path(name)
		if !ok || back != path {
			t.Errorf("Path(%q) = %q, %v; want %q", name, back, ok, path)
		}
	}
}

func TestRefused(t *testing.T) {
	m := dashes()
	for _, p := range []string{"", "a//b", "a-/b", "a/-b", "a--b/c", "A", "a.b", "abcdefghij/abcdefghij"} {
		if n, err := m.Name(p); err == nil {
			t.Errorf("Name(%q) = %q, want an error", p, n)
		}
	}
	for _, n := range []string{"a---b", "--a", "a--", "a----b", "A"} {
		if p, ok := m.Path(n); ok {
			t.Errorf("Path(%q) = %q, want no path", n, p)
		}
	}
}

func TestPrefix(t *testing.T) {
	for _, tc := range []struct {
		prefix, path string
		want         bool
	}{
		{"list", "list", true},
		{"list", "list/a", true},
		{"list", "listx", false},
		{"list", "list-other/x", false},
		{"list/*", "list/a", true},
		{"list/*", "listx", false},
		{"app-*", "app-1", true},
		{"app-*", "app/x", false},
		{"*", "anything/here", true},
		{"", "x", true},
	} {
		if got := ParsePrefix(tc.prefix).Match(tc.path); got != tc.want {
			t.Errorf("%q matches %q = %v, want %v", tc.prefix, tc.path, got, tc.want)
		}
	}
	if !ParsePrefix("a*").Glob() || ParsePrefix("a/*").Glob() {
		t.Errorf("glob detection")
	}
}
