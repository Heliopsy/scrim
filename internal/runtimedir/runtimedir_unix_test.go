// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package runtimedir

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirWithoutXDGRuntimeDirCarriesTheUID(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", tmp)
	want := filepath.Join(tmp, fmt.Sprintf("scrim-%d", os.Getuid()))
	if got := Dir(); got != want {
		t.Fatalf("Dir() = %s, want %s", got, want)
	}
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if got := Dir(); got != "/run/user/1000/scrim" {
		t.Fatalf("Dir() = %s, want /run/user/1000/scrim", got)
	}
}

func TestMkdirCreatesAPrivateDirectory(t *testing.T) {
	top := filepath.Join(t.TempDir(), "scrim")
	t.Setenv("XDG_RUNTIME_DIR", filepath.Dir(top))
	dir := filepath.Join(top, "db", "pg")
	if err := Mkdir(dir); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{top, dir} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: mode %04o, want 0700", d, fi.Mode().Perm())
		}
	}
	if err := CheckSocket(filepath.Join(dir, "s.sock")); err != nil {
		t.Fatal(err)
	}
}

func TestMkdirRefusesALooseDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o1777} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			xdg := t.TempDir()
			t.Setenv("XDG_RUNTIME_DIR", xdg)
			top := filepath.Join(xdg, "scrim")
			if err := os.Mkdir(top, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(top, mode); err != nil {
				t.Fatal(err)
			}
			sub := filepath.Join(top, "db")
			err := Mkdir(sub)
			if err == nil || !strings.Contains(err.Error(), top) || !strings.Contains(err.Error(), "writable by group or others") {
				t.Fatalf("Mkdir = %v, want a refusal naming %s", err, top)
			}
			if _, err := os.Stat(sub); !os.IsNotExist(err) {
				t.Fatalf("Mkdir created %s inside a refused directory", sub)
			}
			if err := CheckSocket(filepath.Join(top, "admin.sock")); err == nil {
				t.Fatal("CheckSocket accepted a socket in a loose directory")
			}
		})
	}
}

func TestMkdirRefusesALooseSubdirectory(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	sub := filepath.Join(xdg, "scrim", "db")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := Mkdir(filepath.Join(sub, "pg")); err == nil || !strings.Contains(err.Error(), sub) {
		t.Fatalf("Mkdir = %v, want a refusal naming %s", err, sub)
	}
	if err := CheckSocket(filepath.Join(sub, "pg.sock")); err == nil {
		t.Fatal("CheckSocket accepted a socket in a loose subdirectory")
	}
}

func TestMkdirRefusesADirectoryOwnedBySomeoneElse(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	top := filepath.Join(xdg, "scrim")
	if err := os.Mkdir(top, 0o700); err != nil {
		t.Fatal(err)
	}
	// The directory belongs to this process's user; pretend to be another.
	real := os.Getuid()
	getuid = func() int { return real + 1 }
	t.Cleanup(func() { getuid = os.Getuid })
	err := Mkdir(top)
	if err == nil || !strings.Contains(err.Error(), top) || !strings.Contains(err.Error(), "not this user") {
		t.Fatalf("Mkdir = %v, want a refusal naming the owner", err)
	}
	if err := CheckSocket(filepath.Join(top, "admin.sock")); err == nil {
		t.Fatal("CheckSocket accepted a socket in a directory owned by someone else")
	}
}

func TestMkdirRefusesASymlink(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(xdg, "scrim")); err != nil {
		t.Fatal(err)
	}
	if err := Mkdir(filepath.Join(xdg, "scrim")); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Mkdir = %v, want a refusal of the symbolic link", err)
	}
}

func TestOutsideTheRuntimeDirIsNotChecked(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	// A configured path elsewhere (api.socket, /run/scrim for the system
	// service) keeps its own rules.
	other := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(other, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := CheckSocket(filepath.Join(other, "api.sock")); err != nil {
		t.Fatal(err)
	}
	if err := Mkdir(other); err != nil {
		t.Fatal(err)
	}
	// A missing runtime directory is not an error for a client.
	if err := CheckSocket(filepath.Join(xdg, "scrim", "admin.sock")); err != nil {
		t.Fatal(err)
	}
}
