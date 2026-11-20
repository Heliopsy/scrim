// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/status"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/vwtest"
)

// fileResolver resolves file: references, as the configuration resolver
// does, and fails everything else.
func fileResolver(_ context.Context, ref config.SecretRef) (secret.Value, error) {
	p, ok := strings.CutPrefix(string(ref), "file:")
	if !ok {
		return secret.Value{}, fmt.Errorf("unsupported reference %s", ref)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return secret.Value{}, err
	}
	return secret.Adopt(b), nil
}

type env struct {
	t       *testing.T
	server  *vwtest.Server
	account *vwtest.Account
	dir     string
	unlock  string
	secret  string
}

func newEnv(t *testing.T, srv *vwtest.Server, kdf bwcrypto.KDFParams) *env {
	t.Helper()
	acc := srv.Register(t, kdf)
	dir := t.TempDir()
	return &env{
		t: t, server: srv, account: acc, dir: dir,
		unlock: "file:" + vwtest.WriteSecretFile(t, dir, acc.Password),
		secret: "file:" + vwtest.WriteSecretFile(t, dir, acc.ClientSecret),
	}
}

func (e *env) adapter(t storetest.TB, base string, mod func(*vaultwarden.Options)) *vaultwarden.Adapter {
	t.Helper()
	u, _ := url.Parse(base)
	o := vaultwarden.Options{
		URL:          u,
		ClientID:     e.account.ClientID,
		ClientSecret: config.SecretRef(e.secret),
		Unlock:       config.SecretRef(e.unlock),
		PollInterval: 300 * time.Millisecond,
		Timeout:      5 * time.Second,
	}
	if mod != nil {
		mod(&o)
	}
	a, err := vaultwarden.New("vw", o, fileResolver)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return a
}

func expose(t testing.TB, v secret.Value) string {
	t.Helper()
	var s string
	if err := v.Expose(func(b []byte) error { s = string(b); return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVaultwarden(t *testing.T) {
	srv := vwtest.Start(t)

	t.Run("ConformancePBKDF2", func(t *testing.T) {
		e := newEnv(t, srv, bwcrypto.KDFParams{Type: bwcrypto.KDFPBKDF2, Iterations: 600_000})
		proxy := vwtest.NewProxy(t, strings.TrimPrefix(srv.URL, "http://"))
		storetest.Run(t, func(t storetest.TB) storetest.Harness {
			return storetest.Harness{
				Adapter:      e.adapter(t, proxy.URL, nil),
				WatchTimeout: 10 * time.Second,
				Outage: func(storetest.TB) func() {
					proxy.SetDown(true)
					return func() { proxy.SetDown(false) }
				},
			}
		})
	})

	t.Run("ConformanceArgon2id", func(t *testing.T) {
		e := newEnv(t, srv, bwcrypto.DefaultArgon2id())
		storetest.Run(t, func(t storetest.TB) storetest.Harness {
			return storetest.Harness{Adapter: e.adapter(t, srv.URL, nil)}
		})
	})

	t.Run("ConformancePasswordLogin", func(t *testing.T) {
		e := newEnv(t, srv, bwcrypto.DefaultPBKDF2())
		storetest.Run(t, func(t storetest.TB) storetest.Harness {
			return storetest.Harness{Adapter: e.adapter(t, srv.URL, func(o *vaultwarden.Options) {
				o.ClientID, o.ClientSecret, o.Email = "", "", e.account.Email
			})}
		})
	})

	t.Run("ItemsWrittenByAClient", func(t *testing.T) {
		e := newEnv(t, srv, bwcrypto.DefaultPBKDF2())
		acc := e.account
		token := secret.FromString("tok_" + vwtest.RandHex(t, 16))
		pw := secret.FromString("pw_" + vwtest.RandHex(t, 16))
		user := secret.FromString("user_" + vwtest.RandHex(t, 4))
		notes := secret.FromString("note_" + vwtest.RandHex(t, 8))
		acc.CreateItem(t, vwtest.Item{
			Folder: "Agents", Name: "GitHub", Username: user, Password: pw, Notes: notes,
			Fields: map[string]secret.Value{"token": token},
			Labels: map[string]string{"scrim.hosts": "api.github.com", "scrim.placeholder": "SCRIM_GITHUB_TOKEN"},
		})
		keyed := secret.FromString("keyed_" + vwtest.RandHex(t, 16))
		acc.CreateItem(t, vwtest.Item{Folder: "Agents", Name: "Keyed", Password: keyed, ItemKey: true})
		note := secret.FromString("sn_" + vwtest.RandHex(t, 16))
		acc.CreateItem(t, vwtest.Item{Name: "Loose", SecureNote: true, Notes: note})

		a := e.adapter(t, srv.URL, nil)
		defer func() { _ = a.Close() }()
		ctx := vwtest.Ctx(t, 30*time.Second)

		// The spec scenario: vw://Agents/GitHub#token reads the custom field.
		s, err := a.Read(ctx, stores.MustParseRef("vw://Agents/GitHub#token"))
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := s.Field("token"); !v.Equal(token) {
			t.Fatal("custom field token has the wrong value")
		}
		if s.Meta.Labels["scrim.hosts"] != "api.github.com" || s.Meta.Labels["scrim.placeholder"] != "SCRIM_GITHUB_TOKEN" {
			t.Fatalf("labels: %v", s.Meta.Labels)
		}
		s.Wipe()

		all, err := a.Read(ctx, stores.MustParseRef("vw://Agents/GitHub"))
		if err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]secret.Value{"username": user, "password": pw, "notes": notes, "token": token} {
			if v, ok := all.Field(name); !ok || !v.Equal(want) {
				t.Errorf("field %s missing or wrong", name)
			}
		}
		if _, ok := all.Field("scrim.hosts"); ok {
			t.Error("a label was returned as a value")
		}
		all.Wipe()

		k, err := a.Read(ctx, stores.MustParseRef("vw://Agents/Keyed#password"))
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := k.Field("password"); !v.Equal(keyed) {
			t.Fatal("item with a per-item key decrypted wrongly")
		}
		n, err := a.Read(ctx, stores.MustParseRef("vw://Loose#notes"))
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := n.Field("notes"); !v.Equal(note) {
			t.Fatal("secure note decrypted wrongly")
		}

		// Rotating the password through scrim keeps the username, and a
		// Bitwarden client sees the new value.
		rotated := secret.FromString("rot_" + vwtest.RandHex(t, 16))
		if _, err := a.Write(ctx, stores.MustParseRef("vw://Agents/Keyed"), map[string]secret.Value{"password": rotated}, stores.WriteOptions{}); err != nil {
			t.Fatal(err)
		}
		ids := acc.ItemIDs(t, "Keyed", nil)
		if len(ids) != 1 {
			t.Fatalf("Keyed items: %d", len(ids))
		}
		if !acc.DecryptItemField(t, ids[0], "password", nil).Equal(rotated) {
			t.Fatal("client does not see the rotated password")
		}
		if _, err := a.Write(ctx, stores.MustParseRef("vw://Agents/GitHub"), map[string]secret.Value{"password": rotated}, stores.WriteOptions{
			Labels: map[string]string{"hosts": "api.github.com,uploads.github.com"},
		}); err != nil {
			t.Fatal(err)
		}
		after, err := a.Read(ctx, stores.MustParseRef("vw://Agents/GitHub"))
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := after.Field("username"); !v.Equal(user) {
			t.Error("rotation lost the username")
		}
		if after.Meta.Labels["scrim.hosts"] != "api.github.com,uploads.github.com" {
			t.Errorf("label not updated: %v", after.Meta.Labels)
		}
		after.Wipe()

		advice, err := a.Advice(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(advice) == 0 || !strings.Contains(advice[0], "dedicated agent account") {
			t.Fatalf("no dedicated-account advice: %v", advice)
		}
	})

	t.Run("Organisation", func(t *testing.T) {
		e := newEnv(t, srv, bwcrypto.DefaultPBKDF2())
		org := e.account.CreateOrg(t, "Acme", "Agents")
		val := secret.FromString("org_" + vwtest.RandHex(t, 16))
		e.account.CreateItem(t, vwtest.Item{Org: org, Name: "Deploy", Password: val, ItemKey: true})
		a := e.adapter(t, srv.URL, nil)
		defer func() { _ = a.Close() }()
		ctx := vwtest.Ctx(t, 30*time.Second)
		s, err := a.Read(ctx, stores.MustParseRef("vw://Agents/Deploy?org=Acme#password"))
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := s.Field("password"); !v.Equal(val) {
			t.Fatal("organisation item decrypted wrongly")
		}
		// Unqualified path works too when it is unambiguous.
		if _, err := a.Read(ctx, stores.MustParseRef("vw://Agents/Deploy#password")); err != nil {
			t.Fatal(err)
		}
		// A personal item at the same path makes the unqualified path
		// ambiguous, and ?org= resolves it.
		e.account.CreateItem(t, vwtest.Item{Folder: "Agents", Name: "Deploy", Password: secret.FromString("p_" + vwtest.RandHex(t, 8))})
		if _, err := a.Read(ctx, stores.MustParseRef("vw://Agents/Deploy")); !errors.Is(err, stores.ErrInvalidRef) {
			t.Fatalf("ambiguous path: %v", err)
		}
		if _, err := a.Read(ctx, stores.MustParseRef("vw://Agents/Deploy?org=Acme")); err != nil {
			t.Fatal(err)
		}

		written := secret.FromString("w_" + vwtest.RandHex(t, 16))
		if _, err := a.Write(ctx, stores.MustParseRef("vw://Agents/Captured?org=Acme"), map[string]secret.Value{"token": written}, stores.WriteOptions{CreateOnly: true}); err != nil {
			t.Fatal(err)
		}
		ids := e.account.ItemIDs(t, "Captured", org)
		if len(ids) != 1 {
			t.Fatalf("captured items in org: %d", len(ids))
		}
		if !e.account.DecryptItemField(t, ids[0], "token", org).Equal(written) {
			t.Fatal("client does not see the value written into the organisation")
		}
		_, err = a.Write(ctx, stores.MustParseRef("vw://Missing/X?org=Acme"), map[string]secret.Value{"token": written}, stores.WriteOptions{})
		if !errors.Is(err, stores.ErrNotFound) {
			t.Fatalf("write to a missing collection: %v", err)
		}
	})

	t.Run("Scope", func(t *testing.T) {
		e := newEnv(t, srv, bwcrypto.DefaultPBKDF2())
		e.account.CreateItem(t, vwtest.Item{Folder: "Agents", Name: "In", Password: secret.FromString("in_" + vwtest.RandHex(t, 8))})
		e.account.CreateItem(t, vwtest.Item{Folder: "Personal", Name: "Bank", Password: secret.FromString("out_" + vwtest.RandHex(t, 8))})
		a := e.adapter(t, srv.URL, func(o *vaultwarden.Options) { o.Scope = []string{"Agents"} })
		defer func() { _ = a.Close() }()
		ctx := vwtest.Ctx(t, 30*time.Second)
		if _, err := a.Read(ctx, stores.MustParseRef("vw://Agents/In")); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Read(ctx, stores.MustParseRef("vw://Personal/Bank")); !errors.Is(err, stores.ErrNotFound) {
			t.Fatalf("out of scope read: %v", err)
		}
		if _, err := a.Write(ctx, stores.MustParseRef("vw://Personal/New"), map[string]secret.Value{"password": secret.FromString("x")}, stores.WriteOptions{}); !errors.Is(err, stores.ErrPermission) {
			t.Fatalf("out of scope write: %v", err)
		}
		advice, err := a.Advice(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(advice) == 0 || !strings.Contains(advice[0], "1 items outside the configured scope") {
			t.Fatalf("advice: %v", advice)
		}
		d := status.Diagnose(ctx, 10*time.Second, a.DoctorChecks()...)
		if d.Warned != 1 || d.Failed != 0 || !strings.Contains(d.Findings[0].Message, "dedicated agent account") {
			t.Fatalf("doctor: %+v", d)
		}
	})

	t.Run("Locked", func(t *testing.T) {
		e := newEnv(t, srv, bwcrypto.DefaultPBKDF2())
		ctx := vwtest.Ctx(t, 30*time.Second)
		empty := filepath.Join(e.dir, "empty")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		for name, unlock := range map[string]string{
			"missing": "file:" + filepath.Join(e.dir, "nope"),
			"empty":   "file:" + empty,
			"wrong":   "file:" + vwtest.WriteSecretFile(t, e.dir, secret.FromString("wrong-"+vwtest.RandHex(t, 8))),
		} {
			a := e.adapter(t, srv.URL, func(o *vaultwarden.Options) { o.Unlock = config.SecretRef(unlock) })
			err := a.Health(ctx)
			if !errors.Is(err, stores.ErrLocked) {
				t.Errorf("%s unlock key: Health = %v, want ErrLocked", name, err)
			}
			if _, err := a.Read(ctx, stores.MustParseRef("vw://Agents/X")); !errors.Is(err, stores.ErrLocked) {
				t.Errorf("%s unlock key: Read = %v, want ErrLocked", name, err)
			}
			if d := status.Diagnose(ctx, 10*time.Second, a.DoctorChecks()...); d.Failed != 1 {
				t.Errorf("%s unlock key: doctor did not fail: %+v", name, d)
			}
			_ = a.Close()
		}
		// A group-readable unlock file is refused.
		loose := vwtest.WriteSecretFile(t, e.dir, e.account.Password)
		if err := os.Chmod(loose, 0o640); err != nil {
			t.Fatal(err)
		}
		a := e.adapter(t, srv.URL, func(o *vaultwarden.Options) { o.Unlock = config.SecretRef("file:" + loose) })
		if err := a.Health(ctx); !errors.Is(err, stores.ErrLocked) || !strings.Contains(err.Error(), "readable by group or others") {
			t.Errorf("group-readable unlock file: %v", err)
		}
		_ = a.Close()
	})

	t.Run("WrongAPIKey", func(t *testing.T) {
		e := newEnv(t, srv, bwcrypto.DefaultPBKDF2())
		bad := "file:" + vwtest.WriteSecretFile(t, e.dir, secret.FromString(vwtest.RandHex(t, 15)))
		a := e.adapter(t, srv.URL, func(o *vaultwarden.Options) { o.ClientSecret = config.SecretRef(bad) })
		defer func() { _ = a.Close() }()
		if err := a.Health(vwtest.Ctx(t, 30*time.Second)); !errors.Is(err, stores.ErrPermission) {
			t.Fatalf("wrong client secret: %v", err)
		}
	})
}
