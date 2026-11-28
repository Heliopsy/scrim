// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package run

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionDirWithoutXDGRuntimeDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	d, err := sessionDir("", "", "s1")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, fmt.Sprintf("scrim-%d", os.Getuid()), "run")
	if filepath.Dir(d) != want {
		t.Fatalf("sessionDir = %s, want a directory in %s", d, want)
	}
}

// A per-user directory someone else pre-created (here: one others can
// write) is refused rather than used for the session's files.
func TestSessionDirRefusesALooseRuntimeDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	top := filepath.Join(tmp, fmt.Sprintf("scrim-%d", os.Getuid()))
	if err := os.Mkdir(top, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(top, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionDir("", "", "s1"); err == nil || !strings.Contains(err.Error(), top) {
		t.Fatalf("sessionDir = %v, want a refusal naming %s", err, top)
	}
	xdg := t.TempDir()
	if err := os.Mkdir(filepath.Join(xdg, "scrim"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(xdg, "scrim"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionDir("", xdg, "s1"); err == nil || !strings.Contains(err.Error(), filepath.Join(xdg, "scrim")) {
		t.Fatalf("sessionDir = %v, want a refusal", err)
	}
}
