// SPDX-License-Identifier: AGPL-3.0-only

package placeholder

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// The pinned vector from specs/redaction "Placeholder fields".
func TestDerivePinned(t *testing.T) {
	k := Key{Version: 1, Key: secret.FromString("0123456789abcdef0123456789abcdef")}
	got, err := Derive(k, "db-password", secret.FromString("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "⟦scrim:db-password:0120a7d732ee4c8da2⟧"; got != want {
		t.Fatalf("Derive = %s, want %s", got, want)
	}
}

func TestDeriveRefusesBadInput(t *testing.T) {
	v := secret.FromString("value-generated-in-test")
	if _, err := Derive(Key{Version: 0, Key: secret.FromString(strings.Repeat("k", 32))}, "a", v); err == nil {
		t.Fatal("version 0 accepted")
	}
	if _, err := Derive(Key{Version: 1, Key: secret.FromString("short")}, "a", v); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := Derive(Key{Version: 1, Key: secret.FromString(strings.Repeat("k", 32))}, "-bad", v); err == nil {
		t.Fatal("bad slug accepted")
	}
}

func TestSlugMatchesDataPlane(t *testing.T) {
	for in, want := range map[string]string{
		"env://ACME_KEY":               "env-acme-key",
		"bao://kv/agents/github#token": "bao-kv-agents-github-token",
		"github":                       "github",
		"--":                           "ref",
		"":                             "ref",
		"Ä-x":                          "x",
		strings.Repeat("ab-", 30):      strings.TrimRight(strings.Repeat("ab-", 16), "-"),
	} {
		got := Slug(in)
		if got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
		if !ValidSlug(got) {
			t.Errorf("Slug(%q) = %q is not valid", in, got)
		}
	}
}

const header = "apiVersion: " + config.APIVersion + "\nkind: Config\n"

func build(t *testing.T, yaml string, env ...string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Build(config.Options{Registry: config.Default, ConfigPaths: []string{p}, Environ: env})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadGeneratesOnceAndPersists(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := build(t, header+"redaction:\n  placeholder-key-dir: "+dir+"\n")

	r1, err := Load(context.Background(), cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Wipe()
	r2, err := Load(context.Background(), cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Wipe()
	if len(r1.Keys) != 1 || r1.Current().Version != 1 || !r1.Current().Key.Equal(r2.Current().Key) {
		t.Fatal("second load did not return the persisted key")
	}
	fi, err := os.Stat(filepath.Join(dir, "placeholder-01.key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	_ = r1.Current().Key.Expose(func(b []byte) error {
		if bytes.Contains(logs.Bytes(), []byte(hex.EncodeToString(b))) || bytes.Contains(logs.Bytes(), b) {
			t.Fatal("key material in the log")
		}
		return nil
	})
	if !strings.Contains(logs.String(), "generated a placeholder key") {
		t.Fatalf("log = %s", logs.String())
	}
}

func TestLoadRefusesOpenPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "placeholder-01.key"), []byte(strings.Repeat("ab", 32)), 0o644); err != nil { //nolint:gosec // the test needs a readable file
		t.Fatal(err)
	}
	cfg := build(t, header+"redaction:\n  placeholder-key-dir: "+dir+"\n")
	if _, err := Load(context.Background(), cfg, nil); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("Load = %v", err)
	}
}

func TestLoadFromConfigByReference(t *testing.T) {
	k1, k2 := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(k1)
	_, _ = rand.Read(k2)
	cfg := build(t, header+`redaction:
  placeholder-keys:
    old: {version: 1, key: env:PK_OLD}
    new: {version: 2, key: env:PK_NEW}
`, "PK_OLD="+hex.EncodeToString(k1), "PK_NEW="+hex.EncodeToString(k2))
	r, err := Load(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Wipe()
	if len(r.Keys) != 2 || r.Current().Version != 2 || r.Keys[1].Version != 1 {
		t.Fatalf("versions = %+v", r.Keys)
	}
	if strings.Contains(r.Source, hex.EncodeToString(k1)) || !strings.Contains(r.Source, "redaction.placeholder-keys.new.key") {
		t.Fatalf("source = %q", r.Source)
	}
}

func TestLoadFromConfigRejectsDuplicateVersion(t *testing.T) {
	cfg := build(t, header+`redaction:
  placeholder-keys:
    a: {version: 1, key: env:PK_A}
    b: {version: 1, key: env:PK_B}
`, "PK_A="+strings.Repeat("a", 32), "PK_B="+strings.Repeat("b", 32))
	if _, err := Load(context.Background(), cfg, nil); err == nil || !strings.Contains(err.Error(), "both have version 1") {
		t.Fatalf("Load = %v", err)
	}
}
