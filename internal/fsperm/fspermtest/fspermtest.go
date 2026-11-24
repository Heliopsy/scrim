// SPDX-License-Identifier: AGPL-3.0-only

// Package fspermtest opens files up to other accounts, for tests that check
// scrim refuses them. It works on every platform: mode bits on Unix, an ACE
// for Everyone on Windows.
package fspermtest

import (
	"os"
	"testing"

	"github.com/heliopsy/scrim/internal/fsperm"
)

// Open makes path readable by every account (group- and world-readable on
// Unix, an allow ACE for Everyone on Windows) and fails the test otherwise.
func Open(t testing.TB, path string) {
	t.Helper()
	if err := open(path); err != nil {
		t.Fatalf("opening up %s: %v", path, err)
	}
}

// Private fails the test when path is reachable by accounts other than its
// owner, as [fsperm.Loose] decides. Tests use it on Windows, where the mode
// bits Go reports say nothing about access.
func Private(t testing.TB, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if loose, detail, err := fsperm.Loose(path, fi); err != nil || loose {
		t.Errorf("%s is reachable by other accounts: %s %v", path, detail, err)
	}
}
