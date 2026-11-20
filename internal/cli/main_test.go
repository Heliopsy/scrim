// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"os"
	"testing"
)

// TestMain points HOME and the XDG directories at a temporary directory, so
// no test reads or writes the user's configuration, state database, keys or
// sockets (the local profile defaults to SQLite under XDG_STATE_HOME).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "scrim-test-home-")
	if err != nil {
		panic(err)
	}
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME"} {
		if err := os.Setenv(k, dir); err != nil {
			panic(err)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
