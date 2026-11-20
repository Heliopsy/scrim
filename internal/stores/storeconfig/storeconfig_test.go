// SPDX-License-Identifier: AGPL-3.0-only

package storeconfig_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/stores"
	_ "github.com/heliopsy/scrim/internal/stores/memstore"
	"github.com/heliopsy/scrim/internal/stores/openbao"
	"github.com/heliopsy/scrim/internal/stores/storeconfig"
)

func build(t *testing.T, yaml string, environ ...string) (*config.Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "scrim.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: scrim.dev/v1\nkind: Config\n"+yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Build(config.Options{ConfigPaths: []string{p}, Environ: environ, SystemDir: dir})
}

const good = `
stores:
  bao:
    kind: openbao
    aliases: [bao-prod]
    address: http://127.0.0.1:1
    auth: {method: approle}
    role-id: env:BAO_ROLE
    secret-id: env:BAO_SECRET
    write-only-paths: [kv/inbox]
    redact: ["bao://kv/agents/*"]
    refresh: {interval: 1m, staleness: 30m}
  mem:
    kind: memory
`

func TestOpenBuildsAdaptersAndRefreshers(t *testing.T) {
	cfg, err := build(t, good, "BAO_ROLE=role-abcdef", "BAO_SECRET=sid-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	o, err := storeconfig.Open(t.Context(), cfg, stores.DefaultRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if len(o.Refreshers) != 2 {
		t.Fatalf("%d refreshers", len(o.Refreshers))
	}
	a, err := o.Set.Lookup(stores.MustParseRef("bao-prod://kv/x"))
	if err != nil || a.Name() != "bao" {
		t.Fatalf("alias lookup: %v", err)
	}
	// The adapter resolves its credentials from the collection's secret
	// fields; the refresher's status names the store.
	if st := o.Refreshers[0].Status(); st.Store != "bao" {
		t.Fatalf("status %+v", st)
	}
	if _, ok := a.(*openbao.Adapter); !ok {
		t.Fatalf("adapter %T", a)
	}
}

func TestValidationNamesTheProblem(t *testing.T) {
	cases := map[string]string{
		"unknown kind":   "stores:\n  x:\n    kind: nosuch\n",
		"adapter typo":   "stores:\n  bao:\n    kind: openbao\n    adress: http://x\n    token: env:T\n",
		"refresh typo":   "stores:\n  bao:\n    kind: openbao\n    address: http://x\n    token: env:T\n    refresh: {intervall: 1m}\n",
		"foreign target": "stores:\n  bao:\n    kind: openbao\n    address: http://x\n    token: env:T\n    redact: [\"inf://p/e/*\"]\n",
		"missing kind":   "stores:\n  bao:\n    address: http://x\n",
	}
	want := map[string]string{
		"unknown kind": "unknown store kind", "adapter typo": "did you mean address",
		"refresh typo": "did you mean refresh.interval", "foreign target": "names another store",
		"missing kind": "is required",
	}
	for name, yaml := range cases {
		_, err := build(t, yaml, "T=tok-0123456789")
		if err == nil || !strings.Contains(err.Error(), want[name]) {
			t.Errorf("%s: got %v, want %q", name, err, want[name])
		}
	}
}

func TestCredentialsAreMaskedAndResolved(t *testing.T) {
	const secretID = "sid-must-not-leak-0123456789"
	cfg, err := build(t, good, "BAO_ROLE=role-abcdef", "BAO_SECRET="+secretID)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := cfg.SecretAt("stores.bao.secret-id")
	if !ok {
		t.Fatal("secret-id not resolved as a secret field")
	}
	_ = v.Expose(func(b []byte) error {
		if string(b) != secretID {
			t.Error("wrong value")
		}
		return nil
	})
	for _, inst := range storeconfig.Collection.Get(cfg) {
		if strings.Contains(inst.String("secret-id"), secretID) {
			t.Fatal("instance fields hold the resolved value")
		}
	}
}
