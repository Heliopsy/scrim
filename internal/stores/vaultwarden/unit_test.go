// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

func TestDecodeOptions(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			OptURL: "https://vault.example.com", OptClientID: "user.x",
			OptClientSecret: "file:/run/secrets/vw-client", OptUnlock: "keyring:scrim/vw",
		}
	}
	o, err := decodeOptions("vw", base())
	if err != nil {
		t.Fatal(err)
	}
	if o.PollInterval == 0 || o.URL.Host != "vault.example.com" {
		t.Fatalf("defaults not applied: %+v", o)
	}
	m := base()
	m[OptScope] = []any{"/Agents/", "Shared/CI"}
	m[OptPollInterval] = "5s"
	o, err = decodeOptions("vw", m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(o.Scope, ",") != "Agents,Shared/CI" {
		t.Fatalf("scope: %v", o.Scope)
	}

	bad := map[string]func(map[string]any){
		"literal unlock":         func(m map[string]any) { m[OptUnlock] = "hunter2 correct horse" },
		"literal: unlock":        func(m map[string]any) { m[OptUnlock] = "literal:abc" },
		"literal client secret":  func(m map[string]any) { m[OptClientSecret] = "s3cr3t" },
		"missing unlock":         func(m map[string]any) { delete(m, OptUnlock) },
		"missing url":            func(m map[string]any) { delete(m, OptURL) },
		"url with credentials":   func(m map[string]any) { m[OptURL] = "https://u:p@vault.example.com" },
		"plain http remote":      func(m map[string]any) { m[OptURL] = "http://vault.example.com" },
		"client id alone":        func(m map[string]any) { delete(m, OptClientSecret) },
		"no login method":        func(m map[string]any) { delete(m, OptClientSecret); delete(m, OptClientID) },
		"unknown option":         func(m map[string]any) { m["pasword"] = "x" },
		"empty scope":            func(m map[string]any) { m[OptScope] = []any{"/"} },
		"negative poll interval": func(m map[string]any) { m[OptPollInterval] = "-1s" },
	}
	for name, mod := range bad {
		m := base()
		mod(m)
		_, err := decodeOptions("vw", m)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: error echoes the literal: %v", name, err)
		}
	}
	m = base()
	m[OptURL] = "http://127.0.0.1:8080"
	if _, err := decodeOptions("vw", m); err != nil {
		t.Errorf("loopback http refused: %v", err)
	}
	m[OptURL] = "http://vault.internal"
	m[OptAllowInsecureHTTP] = true
	if _, err := decodeOptions("vw", m); err != nil {
		t.Errorf("allow-insecure-http ignored: %v", err)
	}
	m = base()
	delete(m, OptClientID)
	delete(m, OptClientSecret)
	m[OptEmail] = "agent@example.com"
	if _, err := decodeOptions("vw", m); err != nil {
		t.Errorf("password login refused: %v", err)
	}
}

func TestDeviceIDStable(t *testing.T) {
	o, err := decodeOptions("vw", map[string]any{OptURL: "https://v.example.com", OptEmail: "a@example.com", OptUnlock: "file:/x"})
	if err != nil {
		t.Fatal(err)
	}
	a, b := o.deviceID("vw"), o.deviceID("vw")
	if a != b || len(a) != 36 || a == o.deviceID("other") {
		t.Fatalf("device id not stable per instance: %s %s", a, b)
	}
}

// fixture builds an index from a synthetic sync encrypted with real keys.
type fixture struct {
	keys *keyring
	sync *syncResponse
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	uk, err := bwcrypto.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{keys: &keyring{user: uk, orgs: map[string]bwcrypto.SymmetricKey{}}, sync: &syncResponse{Profile: profileJSON{ID: "u1", Email: "a@example.com"}}}
}

func (f *fixture) enc(t *testing.T, k bwcrypto.SymmetricKey, s string) *string {
	t.Helper()
	e, err := k.EncryptMetadata(s)
	if err != nil {
		t.Fatal(err)
	}
	out := e.String()
	return &out
}

func (f *fixture) folder(t *testing.T, id, name string) {
	f.sync.Folders = append(f.sync.Folders, folderJSON{ID: id, Name: *f.enc(t, f.keys.user, name)})
}

func (f *fixture) login(t *testing.T, id, folder, name string, fields map[string]string) {
	k := f.keys.user
	c := cipherJSON{ID: id, Type: cipherLogin, Name: *f.enc(t, k, name), Login: &loginJSON{}, RevisionDate: "2026-11-20T00:00:00Z"}
	if folder != "" {
		c.FolderID = &folder
	}
	for n, v := range fields {
		switch n {
		case FieldPassword:
			c.Login.Password = f.enc(t, k, v)
		case FieldUsername:
			c.Login.Username = f.enc(t, k, v)
		default:
			typ := fieldHidden
			if strings.HasPrefix(n, LabelPrefix) {
				typ = fieldText
			}
			c.Fields = append(c.Fields, fieldJSON{Type: typ, Name: f.enc(t, k, n), Value: f.enc(t, k, v)})
		}
	}
	f.sync.Ciphers = append(f.sync.Ciphers, c)
}

func TestVaultIndex(t *testing.T) {
	f := newFixture(t)
	f.folder(t, "f1", "Agents")
	f.folder(t, "f2", "Personal")
	f.login(t, "c1", "f1", "GitHub", map[string]string{"password": "pw-value", "token": "tok-value", "scrim.hosts": "api.github.com", "password ": "x"}) //nolint:gocritic // the trailing space is the case under test
	f.login(t, "c2", "f1", "Dup", map[string]string{"password": "a"})
	f.login(t, "c3", "f1", "Dup", map[string]string{"password": "b"})
	f.login(t, "c4", "f2", "Bank", map[string]string{"password": "c"})
	f.login(t, "c5", "", "Loose", map[string]string{"password": "d"})
	f.login(t, "c6", "f1", "Shadow", map[string]string{"password": "real", "username": "u"})
	// A custom field named like a built-in is shadowed on login items.
	f.sync.Ciphers[len(f.sync.Ciphers)-1].Fields = append(f.sync.Ciphers[len(f.sync.Ciphers)-1].Fields,
		fieldJSON{Type: fieldHidden, Name: f.enc(t, f.keys.user, "password"), Value: f.enc(t, f.keys.user, "custom")})
	deleted := "2026-01-01T00:00:00Z"
	f.login(t, "c7", "f1", "Trashed", map[string]string{"password": "e"})
	f.sync.Ciphers[len(f.sync.Ciphers)-1].DeletedDate = &deleted
	// Garbage metadata: skipped and reported by id only.
	f.sync.Ciphers = append(f.sync.Ciphers, cipherJSON{ID: "bad", Type: cipherLogin, Name: "2.AAAA|AAAA|AAAA"})

	v := buildVault(f.sync, f.keys, 1, []string{"Agents", "Loose"})
	if len(v.warnings) != 1 || !strings.Contains(v.warnings[0], "item bad") {
		t.Fatalf("warnings: %v", v.warnings)
	}
	it, _, err := v.lookup("Agents/GitHub", "")
	if err != nil || it == nil {
		t.Fatalf("lookup: %v %v", it, err)
	}
	if it.labels["scrim.hosts"] != "api.github.com" {
		t.Fatalf("labels: %v", it.labels)
	}
	if strings.Join(it.fields, ",") != "password,password ,token" {
		t.Fatalf("fields: %v", it.fields)
	}
	val, ok, err := it.decryptField(f.keys, "token")
	if err != nil || !ok || !val.Equal(secret.FromString("tok-value")) {
		t.Fatal("token field")
	}
	if _, ok, _ := it.decryptField(f.keys, "scrim.hosts"); ok {
		t.Fatal("a label decrypted as a value")
	}
	if _, _, err := v.lookup("Agents/Dup", ""); !errors.Is(err, errAmbiguous) {
		t.Fatalf("duplicate: %v", err)
	}
	if it, _, _ := v.lookup("Personal/Bank", ""); it != nil {
		t.Fatal("out-of-scope item found")
	}
	if it, _, _ := v.lookup("Loose", ""); it == nil {
		t.Fatal("item without a folder not found by name")
	}
	if it, _, _ := v.lookup("Agents/Trashed", ""); it != nil {
		t.Fatal("trashed item found")
	}
	sh, _, _ := v.lookup("Agents/Shadow", "")
	pw, _, _ := sh.decryptField(f.keys, "password")
	if !pw.Equal(secret.FromString("real")) {
		t.Fatal("custom field shadowed the built-in password")
	}
}

func TestReadLockedWithoutNetwork(t *testing.T) {
	o, err := decodeOptions("vw", map[string]any{OptURL: "http://127.0.0.1:1", OptEmail: "a@example.com", OptUnlock: "file:/nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := New("vw", o, func(context.Context, config.SecretRef) (secret.Value, error) {
		return secret.Value{}, errors.New("unreachable")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	// Port 1 refuses: prelogin fails as unavailable before any unlock.
	_, err = a.Read(t.Context(), stores.MustParseRef("vw://Agents/X"))
	if !errors.Is(err, stores.ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	if _, err := a.Read(t.Context(), stores.MustParseRef("vw://Agents/X?version=2")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Fatalf("unknown selector: %v", err)
	}
	if _, err := a.Write(t.Context(), stores.MustParseRef("vw://Agents/X"), map[string]secret.Value{"scrim.hosts": secret.FromString("x")}, stores.WriteOptions{}); !errors.Is(err, stores.ErrInvalidRef) {
		t.Fatalf("label as field: %v", err)
	}
}

func TestServerMessageSanitised(t *testing.T) {
	msg := serverMessage([]byte(`{"message":"bad\nthing` + strings.Repeat("x", 400) + `"}`))
	if strings.ContainsAny(msg, "\n") || len(msg) > 210 {
		t.Fatalf("message not sanitised: %q", msg)
	}
	if serverMessage([]byte("<html>")) != "" {
		t.Fatal("non-JSON body produced a message")
	}
}
