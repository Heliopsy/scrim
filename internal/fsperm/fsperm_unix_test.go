// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package fsperm

import (
	"os"
	"testing"
)

func openUp(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}
