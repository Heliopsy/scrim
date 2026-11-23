// SPDX-License-Identifier: AGPL-3.0-only

package plugin_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hostplugin "github.com/heliopsy/scrim/internal/plugin"
)

func private(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func exe(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, "plugin")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckBinary(t *testing.T) {
	good := exe(t, private(t), 0o755)
	sum := sha256.Sum256([]byte("#!/bin/sh\n"))
	if got, err := hostplugin.CheckBinary(good, ""); err != nil || got != good {
		t.Fatalf("good binary: %q %v", got, err)
	}
	if _, err := hostplugin.CheckBinary(good, "sha256:"+hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("matching digest: %v", err)
	}

	loose := private(t)
	if err := os.Chmod(loose, 0o775); err != nil {
		t.Fatal(err)
	}
	inLoose := exe(t, loose, 0o755)

	linkDir := private(t)
	link := filepath.Join(linkDir, "link")
	if err := os.Symlink(inLoose, link); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, path, sum, want string
	}{
		{"relative", "plugin", "", "not an absolute path"},
		{"missing", filepath.Join(private(t), "nope"), "", "no such file"},
		{"directory", private(t), "", "not a regular file"},
		{"not executable", exe(t, private(t), 0o644), "", "not executable"},
		{"world-writable", exe(t, private(t), 0o757), "", "writable by every user"},
		{"group-writable directory", inLoose, "", "writable by its group"},
		{"symlink into a group-writable directory", link, "", "writable by its group"},
		{"digest mismatch", good, strings.Repeat("ab", 32), "sha256 is"},
		{"malformed digest", good, "abc", "64 hex digits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hostplugin.CheckBinary(tc.path, tc.sum)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
