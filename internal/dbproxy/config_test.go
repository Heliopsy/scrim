// SPDX-License-Identifier: AGPL-3.0-only

package dbproxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/secret"
)

func buildConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "scrim.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: "+config.APIVersion+"\nkind: Config\n"+yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Build(config.Options{ConfigPaths: []string{p}, Environ: []string{}, SystemDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func exposed(t *testing.T, v secret.Value) string {
	t.Helper()
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

// TestStoreReferencePasswordResolvesAtLogin: a password given as a store
// reference is read through the store resolver at every login, so a rotated
// value is used by the next one; other references still come from the
// configuration; neither value reaches an error.
func TestStoreReferencePasswordResolvesAtLogin(t *testing.T) {
	filePW := leak.Generate(leak.KindDBPassword)
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte(filePW.Value()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := buildConfig(t, `databases:
  app:
    kind: postgres
    address: db.internal:5432
    user: app
    password: bao://kv/db/app#password
    tls: insecure-plaintext
  other:
    kind: mysql
    address: db.internal:3306
    user: other
    password: file:`+pwFile+`
    tls: insecure-plaintext
`)
	if got := cfg.Unresolved(); !slices.Equal(got, []string{"databases.app.password"}) {
		t.Fatalf("unresolved %v", got)
	}
	if got := StoreRefs(cfg); !slices.Equal(got, []string{"bao://kv/db/app#password"}) {
		t.Fatalf("store refs %v", got)
	}

	current := leak.Generate(leak.KindDBPassword)
	var asked []config.SecretRef
	resolve := func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
		asked = append(asked, ref)
		return secret.FromString(current.Value()), nil
	}
	specs, err := Specs(cfg, func() *config.Config { return cfg }, resolve)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*Database{}
	for _, s := range specs {
		byName[s.DB.Name] = s.DB
	}

	v, err := byName["app"].Password(t.Context())
	if err != nil {
		t.Fatalf("store reference: %v", err)
	}
	if exposed(t, v) != current.Value() {
		t.Fatal("store reference resolved to the wrong value")
	}
	v.Wipe()
	first := current
	current = leak.Generate(leak.KindDBPassword)
	v, err = byName["app"].Password(t.Context())
	if err != nil || exposed(t, v) != current.Value() {
		t.Fatalf("rotated value not used by the next login: %v", err)
	}
	v.Wipe()
	if len(asked) != 2 || asked[0] != "bao://kv/db/app#password" {
		t.Fatalf("resolver asked %v", asked)
	}

	v, err = byName["other"].Password(t.Context())
	if err != nil || exposed(t, v) != filePW.Value() {
		t.Fatalf("file reference: %v", err)
	}
	v.Wipe()
	if len(asked) != 2 {
		t.Fatal("a file reference went to the store resolver")
	}

	checker := leak.NewChecker([]leak.Seed{filePW, first, current})
	failing := func(context.Context, config.SecretRef) (secret.Value, error) {
		return secret.Value{}, errors.New("store bao: kv/db/app: locked")
	}
	empty := func(context.Context, config.SecretRef) (secret.Value, error) { return secret.Value{}, nil }
	for name, r := range map[string]StoreResolver{"none": nil, "failing": failing, "empty": empty} {
		specs, err := Specs(cfg, func() *config.Config { return cfg }, r)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range specs {
			if s.DB.Name != "app" {
				continue
			}
			_, err := s.DB.Password(t.Context())
			if err == nil || !strings.Contains(err.Error(), "databases.app.password") {
				t.Fatalf("%s: want an error naming the setting, got %v", name, err)
			}
			if fs := checker.CheckText(1, err.Error()); len(fs) > 0 {
				t.Fatalf("%s: error leaked: %+v", name, fs)
			}
		}
	}
}
