// SPDX-License-Identifier: AGPL-3.0-only

package fsview

import "testing"

// On Windows auto falls back to no view and home is refused: a mirror that
// only moves HOME would claim cover Windows tools do not give.
func TestResolveWindows(t *testing.T) {
	for _, c := range []struct {
		req      string
		mode     string
		fallback bool
		err      bool
	}{
		{"", ModeOff, false, false},
		{ModeOff, ModeOff, false, false},
		{ModeAuto, ModeOff, true, false},
		{ModeHome, "", false, true},
		{ModeNamespace, "", false, true},
	} {
		mode, fb, err := Resolve(c.req, Availability{Reason: "no user or mount namespaces"})
		if mode != c.mode || (fb != "") != c.fallback || (err != nil) != c.err {
			t.Errorf("Resolve(%q) = %q, %q, %v", c.req, mode, fb, err)
		}
	}
}
