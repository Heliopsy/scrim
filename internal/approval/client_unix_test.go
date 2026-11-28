// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package approval

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Without $XDG_RUNTIME_DIR the admin socket goes in this user's directory
// under the temporary directory, never in a directory every user shares.
func TestDefaultAdminSocketWithoutXDGRuntimeDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", tmp)
	want := filepath.Join(tmp, fmt.Sprintf("scrim-%d", os.Getuid()), "admin.sock")
	if got := DefaultAdminSocket(); got != want {
		t.Fatalf("DefaultAdminSocket() = %s, want %s", got, want)
	}
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if got := DefaultAdminSocket(); got != "/run/user/1000/scrim/admin.sock" {
		t.Fatalf("DefaultAdminSocket() = %s", got)
	}
}

// A client refuses an admin socket in a runtime directory another user
// could have planted.
func TestClientRefusesALooseRuntimeDir(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	dir := filepath.Join(xdg, "scrim")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient("")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListApprovals(t.Context(), "", "")
	if err == nil || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("ListApprovals = %v, want a refusal naming %s", err, dir)
	}
}
