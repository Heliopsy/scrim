// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"context"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
)

// atVersion is a store whose schema is at a fixed version.
type atVersion struct {
	state.Store
	v int
}

func (a atVersion) SchemaVersion(context.Context) (int, error) { return a.v, nil }

// A store opened without migrating it reports its schema against the
// version this binary expects.
func TestStateOfExpectedSchema(t *testing.T) {
	for _, tc := range []struct {
		name    string
		v       int
		healthy bool
		detail  string
	}{
		{"current", 3, true, ""},
		{"empty", 0, true, "not created yet"},
		{"behind", 2, true, "schema version 2 is behind version 3"},
		{"ahead", 4, false, "schema version 4 is ahead of version 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := StateOf{Store: atVersion{memstate.New(), tc.v}, Expected: 3}.StateStatus(t.Context())
			if got.Healthy != tc.healthy || got.SchemaVersion != tc.v ||
				(tc.detail == "") != (got.Detail == "") || !strings.Contains(got.Detail, tc.detail) {
				t.Errorf("state = %+v", got)
			}
		})
	}
}
