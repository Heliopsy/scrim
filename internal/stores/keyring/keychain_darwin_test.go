// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package keyring

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// TestKeychain runs the conformance suite against a throwaway keychain
// file created under t.TempDir(), never the login keychain. It changes the
// user's keychain search list while it runs, so it only runs when
// SCRIM_TEST_KEYCHAIN=1 (the macOS CI job).
func TestKeychain(t *testing.T) {
	if os.Getenv("SCRIM_TEST_KEYCHAIN") != "1" {
		t.Skip("set SCRIM_TEST_KEYCHAIN=1 to run against a throwaway keychain")
	}
	security := func(t storetest.TB, args ...string) {
		t.Helper()
		if out, err := exec.Command("/usr/bin/security", args...).CombinedOutput(); err != nil {
			t.Fatalf("security %s: %v: %s", args[0], err, out)
		}
	}
	path := filepath.Join(t.TempDir(), "scrim-keyring-test.keychain-db")
	pw := gen(t)
	security(t, "create-keychain", "-p", pw, path)
	t.Cleanup(func() { _ = exec.Command("/usr/bin/security", "delete-keychain", path).Run() })
	security(t, "unlock-keychain", "-p", pw, path)
	security(t, "set-keychain-settings", path) // no automatic lock

	newAdapter := func(t storetest.TB) *Adapter {
		cfg, err := ParseOptions("kc", map[string]any{"services": "scrim-conformance", "keychain": path, "timeout": "5s"}, BackendKeychain)
		if err != nil {
			t.Fatalf("options: %v", err)
		}
		a, err := New("kc", cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return a
	}
	split := func(ref stores.Ref) (string, string) {
		s, a, _ := strings.Cut(ref.Path, "/")
		return s, a
	}
	storetest.Run(t, func(t storetest.TB) storetest.Harness {
		return storetest.Harness{
			Adapter:     newAdapter(t),
			SingleField: Field,
			Seed: func(t storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
				s, a := split(ref)
				_ = fields[Field].Expose(func(b []byte) error {
					// Test values only: the value is on this command line.
					security(t, "add-generic-password", "-U", "-s", s, "-a", a, "-w", string(b), "-T", "/usr/bin/security", path)
					return nil
				})
			},
			Delete: func(t storetest.TB, ref stores.Ref) {
				s, a := split(ref)
				security(t, "delete-generic-password", "-s", s, "-a", a, path)
			},
		}
	})

	t.Run("Labels", func(t *testing.T) {
		v := gen(t)
		security(t, "add-generic-password", "-U", "-s", "scrim-conformance", "-a", "labelled", "-l", "Deploy key", "-w", v, "-T", "/usr/bin/security", path)
		a := newAdapter(t)
		m, err := a.ReadMetadata(t.Context(), stores.MustParseRef("kc://scrim-conformance/labelled"))
		if err != nil {
			t.Fatal(err)
		}
		if m.Labels["keyring.backend"] != BackendKeychain || m.Labels["keyring.label"] != "Deploy key" || m.Labels["keyring.keychain"] != path {
			t.Errorf("labels %v", m.Labels)
		}
	})

	t.Run("Locked", func(t *testing.T) {
		security(t, "add-generic-password", "-U", "-s", "scrim-conformance", "-a", "locked", "-w", gen(t), "-T", "/usr/bin/security", path)
		security(t, "lock-keychain", path)
		defer security(t, "unlock-keychain", "-p", pw, path)
		a := newAdapter(t)
		_, err := a.Read(t.Context(), stores.MustParseRef("kc://scrim-conformance/locked"))
		if !errors.Is(err, stores.ErrLocked) {
			t.Errorf("Read of a locked keychain: %v, want ErrLocked", err)
		}
	})
}
