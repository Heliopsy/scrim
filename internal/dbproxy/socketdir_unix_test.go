// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package dbproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultSocketDirWithoutXDGRuntimeDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", tmp)
	want := filepath.Join(tmp, fmt.Sprintf("scrim-%d", os.Getuid()), "db", "pg")
	if got := DefaultSocketDir("pg"); got != want {
		t.Fatalf("DefaultSocketDir = %s, want %s", got, want)
	}
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if got := DefaultSocketDir("pg"); got != "/run/user/1000/scrim/db/pg" {
		t.Fatalf("DefaultSocketDir = %s", got)
	}
}
