// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"encoding/base64"
	"testing"

	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// A text document the proxy redacted is forwarded as base64 again; its
// placeholder counts, so the row is redacted rather than repaired.
func TestBase64Match(t *testing.T) {
	ph := fp.DefaultPlaceholderPattern
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for body, want := range map[string]bool{
		`{"file_data":"data:text/plain;base64,` + enc("TOKEN=⟦scrim:api-key:3f2a⟧\n") + `"}`: true,
		`{"data":"` + enc("PASSWORD=⟦scrim:db:91c0⟧ and more text") + `"}`:                   true,
		`{"file_data":"data:text/plain;base64,` + enc("TOKEN=nothing to see here\n") + `"}`:  false,
		`{"text":"no base64 here at all, only words"}`:                                       false,
	} {
		if got := base64Match(ph, []byte(body)); got != want {
			t.Errorf("base64Match(%s) = %v, want %v", body, got, want)
		}
	}
}
