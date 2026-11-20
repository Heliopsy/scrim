// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// seeded is a value that must never appear in any output.
const seeded = "s3cr3t-SEEDED-value-0xC0FFEE"

func expose(t *testing.T, v secret.Value) string {
	t.Helper()
	var out string
	if err := v.Expose(func(b []byte) error { out = string(b); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSecretReferences(t *testing.T) {
	w := newWorld(t)
	tokenFile := w.file("secrets/bao-token", seeded+"\n")
	credDir := filepath.Join(w.dir, "creds")
	w.file("creds/ca-key", seeded+"-ca")
	w.setenv("INF_SECRET="+seeded+"-inf", "CREDENTIALS_DIRECTORY="+credDir)
	p := w.file("c.yaml", header+fmt.Sprintf(`
stores:
  openbao:
    token: file:%s
  infisical:
    client-secret: env:INF_SECRET
interception.ca-key: cred:ca-key
`, tokenFile))
	c := w.build(p)
	for key, want := range map[config.Key[config.SecretRef]]string{
		w.token: seeded, w.infSec: seeded + "-inf", w.caKey: seeded + "-ca",
	} {
		v, ok := c.Secret(key)
		if !ok {
			t.Fatalf("%s not resolved", key.Name())
		}
		if got := expose(t, v); got != want {
			t.Errorf("%s resolved to the wrong value (length %d, want %d)", key.Name(), len(got), len(want))
		}
	}
	if len(c.Warnings()) != 0 {
		t.Fatalf("references should not warn: %v", c.Warnings())
	}
}

func TestUnresolvableReference(t *testing.T) {
	cases := map[string]struct{ ref, want string }{
		"missing file":    {"file:/run/secrets/bao-token", "file:/run/secrets/bao-token: no such file or directory"},
		"relative file":   {"file:bao-token", "path must be absolute"},
		"unset env":       {"env:NOPE", "environment variable NOPE is not set"},
		"bad env name":    {"env:1X", "not a valid environment variable name"},
		"no creds dir":    {"cred:token", "$CREDENTIALS_DIRECTORY is not set"},
		"bad cred name":   {"cred:../x", "not a valid credential name"},
		"empty store ref": {"bao://", "store path is empty"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			p := w.file("c.yaml", header+"stores.openbao.token: "+tc.ref+"\n")
			err := w.buildErr(p)
			mustContain(t, err.Error(), "stores.openbao.token", tc.want)
		})
	}
	t.Run("empty value", func(t *testing.T) {
		w := newWorld(t)
		f := w.file("empty", "\n")
		w.setenv("EMPTY=")
		p := w.file("c.yaml", header+"stores.openbao.token: file:"+f+"\nstores.infisical.client-secret: env:EMPTY\n")
		err := w.buildErr(p)
		mustContain(t, err.Error(), "stores.openbao.token", "stores.infisical.client-secret", "resolves to an empty value")
	})
}

func TestLiteralSecrets(t *testing.T) {
	t.Run("warned where allowed", func(t *testing.T) {
		w := newWorld(t)
		p := w.file("c.yaml", header+"stores.infisical.client-secret: "+seeded+"\n")
		c := w.build(p)
		warns := c.Warnings()
		if len(warns) != 1 || warns[0].Key != "stores.infisical.client-secret" {
			t.Fatalf("warnings = %v", warns)
		}
		var logs bytes.Buffer
		config.LogWarnings(slog.New(slog.NewTextHandler(&logs, nil)), c)
		mustContain(t, logs.String(), "stores.infisical.client-secret", "literal secret")
		assertNoSeed(t, "warning", warns[0].String(), logs.String())
	})
	t.Run("rejected where a reference is required", func(t *testing.T) {
		w := newWorld(t)
		p := w.file("c.yaml", header+"stores.openbao.token: "+seeded+"\n")
		err := w.buildErr(p)
		mustContain(t, err.Error(), "stores.openbao.token", "literal secret is not accepted")
		assertNoSeed(t, "error", err.Error())
	})
	t.Run("rejected from the environment too", func(t *testing.T) {
		w := newWorld(t)
		w.setenv("SCRIM_STORES_OPENBAO_TOKEN=" + seeded)
		err := w.buildErr()
		mustContain(t, err.Error(), "env:SCRIM_STORES_OPENBAO_TOKEN")
		assertNoSeed(t, "error", err.Error())
	})
}

func TestStoreReferences(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+"stores.openbao.token: bao://kv/scrim#token\n")
	c := w.build(p)
	if _, ok := c.Secret(w.token); ok {
		t.Fatal("store reference resolved without a resolver")
	}
	if got := c.Unresolved(); len(got) != 1 || got[0] != "stores.openbao.token" {
		t.Fatalf("unresolved = %v", got)
	}
	var asked []string
	sr := config.StoreResolverFunc(func(_ context.Context, ref string) (secret.Value, error) {
		asked = append(asked, ref)
		return secret.FromString(seeded), nil
	})
	r, err := c.ResolveStores(context.Background(), sr)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := r.Secret(w.token); !ok || expose(t, v) != seeded || len(asked) != 1 || asked[0] != "bao://kv/scrim#token" {
		t.Fatalf("resolution: ok=%v asked=%v", ok, asked)
	}
	if _, ok := c.Secret(w.token); ok {
		t.Fatal("ResolveStores changed the original Config")
	}

	failing := config.StoreResolverFunc(func(context.Context, string) (secret.Value, error) {
		return secret.Value{}, errors.New("store sealed")
	})
	opts := w.opts(p)
	opts.Stores = failing
	_, err = config.Build(opts)
	mustContain(t, fmt.Sprint(err), "stores.openbao.token", "bao://kv/scrim#token", "store sealed")
}

func TestReferenceDisplay(t *testing.T) {
	cases := map[config.SecretRef]string{
		"":                                 "",
		"env:X":                            "env:X",
		"file:/run/x":                      "file:/run/x",
		"cred:tok":                         "cred:tok",
		"bao://kv/a#b":                     "bao://kv/a#b",
		"postgres://u:" + seeded + "@db/x": "postgres://***@db/x",
		seeded:                             "<literal>",
	}
	for ref, want := range cases {
		if got := ref.Display(); got != want {
			t.Errorf("Display(%s) = %q, want %q", ref.Kind(), got, want)
		}
		for _, out := range []string{fmt.Sprint(ref), fmt.Sprintf("%s|%v|%q", ref, ref, ref)} {
			assertNoSeed(t, "formatted reference", out)
		}
		b, _ := json.Marshal(ref)
		assertNoSeed(t, "JSON reference", string(b))
	}
	if got := config.SecretRef("bao-prod://kv/x").Scheme(); got != "bao-prod" {
		t.Errorf("scheme = %q", got)
	}
}

func assertNoSeed(t *testing.T, what string, outs ...string) {
	t.Helper()
	for _, out := range outs {
		if strings.Contains(out, seeded) || strings.Contains(out, "0xC0FFEE") {
			t.Fatalf("%s contains the secret value", what)
		}
	}
}
