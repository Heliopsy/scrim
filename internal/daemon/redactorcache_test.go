// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"testing"
)

// TestRedactorCacheSettingReachesTheSnapshot: redaction.redactor-cache is on by default and its off
// value reaches the data plane as redactor_cache_off.
func TestRedactorCacheSettingReachesTheSnapshot(t *testing.T) {
	for _, c := range []struct {
		body string
		off  bool
	}{
		{"", false},
		{"redaction:\n  redactor-cache: true\n", false},
		{"redaction:\n  redactor-cache: false\n", true},
	} {
		s, err := detectorSnapshot(t, c.body).Build(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := s.GetRedaction().GetRedactorCacheOff(); got != c.off {
			t.Errorf("%q: redactor_cache_off = %v, want %v", c.body, got, c.off)
		}
	}
}
