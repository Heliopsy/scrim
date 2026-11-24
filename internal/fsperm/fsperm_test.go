// SPDX-License-Identifier: AGPL-3.0-only

package fsperm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMkdirPrivateIsNotLoose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "private")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loose, detail, err := Loose(dir, fi); err != nil || loose {
		t.Fatalf("Loose = %v, %q, %v; want a private directory", loose, detail, err)
	}
	if err := Owned(dir, fi); err != nil {
		t.Fatal(err)
	}
	// A file created inside inherits the directory's access.
	f := filepath.Join(dir, "key")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ffi, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if loose, detail, err := Loose(f, ffi); err != nil || loose {
		t.Fatalf("file: Loose = %v, %q, %v; want private", loose, detail, err)
	}
}

func TestLooseDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	openUp(t, dir)
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	loose, detail, err := Loose(dir, fi)
	if err != nil || !loose || detail == "" {
		t.Fatalf("Loose = %v, %q, %v; want loose with a reason", loose, detail, err)
	}
	t.Logf("loose: %s; fix: %s", detail, FixHint(dir, true))
}
