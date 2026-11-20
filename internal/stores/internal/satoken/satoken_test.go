// SPDX-License-Identifier: AGPL-3.0-only

package satoken

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	jwt := "eyJ." + hex.EncodeToString(b)
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("\n "+jwt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	_ = v.Expose(func(b []byte) error { got = string(b); return nil })
	v.Wipe()
	if got != jwt {
		t.Fatal("token not trimmed to its content")
	}
	// Rotation: the next read sees the new content.
	if err := os.WriteFile(path, []byte("rotated"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, _ = Read(path)
	_ = v.Expose(func(b []byte) error { got = string(b); return nil })
	v.Wipe()
	if got != "rotated" {
		t.Fatal("rotated token not read")
	}

	if err := os.WriteFile(path, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty file: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := Read(missing); err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing file: %v", err)
	}
}
