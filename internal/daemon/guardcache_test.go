// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"testing"
)

// TestGuardCacheSettingReachesTheSnapshot: redaction.guard-cache is on by default and its off
// value reaches the data plane as guard_cache_off.
func TestGuardCacheSettingReachesTheSnapshot(t *testing.T) {
	for _, c := range []struct {
		body string
		off  bool
	}{
		{"", false},
		{"redaction:\n  guard-cache: true\n", false},
		{"redaction:\n  guard-cache: false\n", true},
	} {
		s, err := detectorSnapshot(t, c.body).Build(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := s.GetRedaction().GetGuardCacheOff(); got != c.off {
			t.Errorf("%q: guard_cache_off = %v, want %v", c.body, got, c.off)
		}
	}
}
