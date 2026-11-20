// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"os"
	"testing"

	"github.com/heliopsy/scrim/internal/testing/testhome"
)

// TestMain keeps every test away from the user's own HOME and XDG
// directories: the local profile keeps state, keys and sockets there.
func TestMain(m *testing.M) { os.Exit(testhome.Run(m)) }
