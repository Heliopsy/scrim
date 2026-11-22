// SPDX-License-Identifier: AGPL-3.0-only

package profiles

import (
	"os"
	"testing"

	"github.com/heliopsy/scrim/internal/credhelper"
)

// TestMain lets the test binary stand in for scrim when a profile check runs
// a credential helper (Check runs helpers as os.Executable).
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "credential-helper" {
		os.Exit(credhelper.Main(os.Args[2:], os.Environ(), os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}
