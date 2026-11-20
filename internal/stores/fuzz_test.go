// SPDX-License-Identifier: AGPL-3.0-only

package stores_test

import (
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
)

// FuzzParseRef checks that parsing never panics, that a parsed reference
// round-trips through String, and that errors never echo the input.
func FuzzParseRef(f *testing.F) {
	for _, s := range []string{"bao://kv/a#token", "aws-sm://a/b?stage=X&version=2", "x://", "inf://p/e/K#f#g", "%%", "a://b?=c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := stores.ParseRef(s)
		if err != nil {
			if len(s) > 12 && strings.Contains(err.Error(), s) {
				t.Fatalf("error echoes the input: %v", err)
			}
			return
		}
		back, err := stores.ParseRef(r.String())
		if err != nil || back != r {
			t.Fatalf("%q -> %q -> %+v, %v", s, r.String(), back, err)
		}
	})
}
