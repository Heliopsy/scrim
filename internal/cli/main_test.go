// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"os"
	"testing"

	"github.com/heliopsy/scrim/internal/fsview"
	"github.com/heliopsy/scrim/internal/testing/pgtest"
	"github.com/heliopsy/scrim/internal/testing/testhome"
)

// TestMain keeps every test away from the user's own HOME and XDG
// directories: the local profile keeps state, keys and sockets there. A
// start as the filesystem view helper runs the helper instead. A
// PostgreSQL container started by pgtest is removed at the end.
func TestMain(m *testing.M) {
	fsview.Main()
	code := testhome.Run(m)
	pgtest.Stop()
	os.Exit(code)
}
