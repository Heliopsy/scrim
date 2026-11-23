// SPDX-License-Identifier: AGPL-3.0-only

package sops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	_ "github.com/heliopsy/scrim/internal/stores/file"
	"github.com/heliopsy/scrim/internal/stores/refresh"
	"github.com/heliopsy/scrim/internal/stores/storeconfig"
)

// TestLoadsThroughConfiguration configures a sops store the way an operator
// does, with the identity as a file: reference, and checks the redaction
// set holds every value of the redact target plus the age key itself.
func TestLoadsThroughConfiguration(t *testing.T) {
	id := identity(t)
	dir, root := t.TempDir(), t.TempDir()
	keyFile := filepath.Join(dir, "test-only-age-key.txt")
	if err := os.WriteFile(keyFile, []byte("# test-only throwaway key\n"+id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, want := nested(t)
	put(t, root, "prod/app.yaml", encryptFile(t, FormatYAML, doc, encOptions{recipients: []*age.X25519Recipient{id.Recipient()}}))
	cfgFile := filepath.Join(dir, "scrim.yaml")
	if err := os.WriteFile(cfgFile, []byte("apiVersion: scrim.dev/v1\nkind: Config\nstores:\n  team:\n    kind: sops\n"+
		"    root: "+root+"\n    age-identity: file:"+keyFile+"\n    redact: [\"team://prod/*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Build(config.Options{ConfigPaths: []string{cfgFile}, SystemDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	// age-identity is a credential field of the collection: resolved and
	// held as a secret, masked in config show.
	if v, ok := cfg.SecretAt("stores.team.age-identity"); !ok || !strings.Contains(plain(v), id.String()) {
		t.Error("age-identity is not resolved as a secret field")
	}
	o, err := storeconfig.Open(t.Context(), cfg, stores.DefaultRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	r := o.Refreshers[0]
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	var creds []string
	r.EachValue(func(src refresh.Source, v secret.Value) {
		if src.Ref.IsZero() {
			creds = append(creds, plain(v))
			return
		}
		got[src.Ref.Field] = plain(v)
	})
	equalFields(t, "redaction set", got, want)
	if len(creds) != 1 || creds[0] != id.String() {
		t.Errorf("the age key is not in the redaction set (%d credentials)", len(creds))
	}
}

// TestIdentityFromAnotherStore: a credential field may be a reference into
// another configured store. The age key lives in a file store; the sops
// store reads it from there when it decrypts, and holds it for redaction.
func TestIdentityFromAnotherStore(t *testing.T) {
	id := identity(t)
	dir, root, keys := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(keys, "age"), []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, want := nested(t)
	put(t, root, "prod/app.yaml", encryptFile(t, FormatYAML, doc, encOptions{recipients: []*age.X25519Recipient{id.Recipient()}}))
	cfgFile := filepath.Join(dir, "scrim.yaml")
	if err := os.WriteFile(cfgFile, []byte("apiVersion: scrim.dev/v1\nkind: Config\nstores:\n  keys:\n    kind: file\n    root: "+keys+"\n"+
		"  team:\n    kind: sops\n    root: "+root+"\n    age-identity: keys://age\n    redact: [\"team://prod/*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Build(config.Options{ConfigPaths: []string{cfgFile}, SystemDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	o, err := storeconfig.Open(t.Context(), cfg, stores.DefaultRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	var r *refresh.Refresher
	for _, x := range o.Refreshers {
		if x.Store() == "team" {
			r = x
		}
	}
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	var creds []string
	r.EachValue(func(src refresh.Source, v secret.Value) {
		if src.Ref.IsZero() {
			creds = append(creds, plain(v))
			return
		}
		got[src.Ref.Field] = plain(v)
	})
	equalFields(t, "redaction set", got, want)
	if len(creds) != 1 || strings.TrimSpace(creds[0]) != id.String() {
		t.Errorf("the age key from the other store is not in the redaction set (%d credentials)", len(creds))
	}
}
