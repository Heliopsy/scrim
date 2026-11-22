// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"strconv"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

func TestLabelKey(t *testing.T) {
	for in, want := range map[string]string{
		"Environment":     "environment",
		"Owner Team":      "owner_team",
		"vaultwarden.org": "vaultwarden.org",
		"..a..B c..":      "a.b_c",
		"db_main-2":       "db_main-2",
		"Café":            "caf_",
		"":                "",
	} {
		if got := stores.LabelKey(in); got != want {
			t.Errorf("stores.LabelKey(%q) = %q, want %q", in, got, want)
		}
	}
	for _, a := range multiAttrs {
		if !stores.IsMulti(Kind, a) {
			t.Errorf("%s.%s is not declared multi-valued", Kind, a)
		}
	}
	for _, a := range []string{"folder", "org", "name"} {
		if stores.IsMulti(Kind, a) {
			t.Errorf("%s.%s is declared multi-valued", Kind, a)
		}
	}
	if got := strings.Join(ancestors("Agents/CI Jobs/x"), "|"); got != "Agents|Agents/CI Jobs|Agents/CI Jobs/x" {
		t.Errorf("ancestors: %q", got)
	}
	if got := strings.Join(ancestors("Prod"), "|"); got != "Prod" {
		t.Errorf("ancestors: %q", got)
	}
}

// labelFixture is a vault with a nested personal folder and an organisation
// with three collections.
type labelFixture struct {
	*fixture
	org bwcrypto.SymmetricKey
}

func newLabelFixture(t *testing.T) *labelFixture {
	t.Helper()
	f := &labelFixture{fixture: newFixture(t)}
	ok, err := bwcrypto.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	f.org = ok
	f.keys.orgs["o1"] = ok
	admin := 1
	f.sync.Profile.Organizations = []orgJSON{{ID: "o1", Name: "Acme", Type: &admin}}
	f.folder(t, "f1", "Agents/CI")
	yes := true
	f.sync.Collections = []collectionJSON{
		{ID: "k1", OrganizationID: "o1", Name: *f.enc(t, ok, "Prod"), ReadOnly: true},
		{ID: "k2", OrganizationID: "o1", Name: *f.enc(t, ok, "Shared/Team A"), HidePasswords: true, Manage: &yes},
		{ID: "k3", OrganizationID: "o1", Name: *f.enc(t, ok, "Other")},
	}
	return f
}

func (f *labelFixture) field(t *testing.T, k bwcrypto.SymmetricKey, typ int, name, value string) fieldJSON {
	return fieldJSON{Type: typ, Name: f.enc(t, k, name), Value: f.enc(t, k, value)}
}

func TestNativeLabels(t *testing.T) {
	f := newLabelFixture(t)
	const (
		hiddenValue = "hidden-secret-4f1c"
		password    = "pw-value-9a2e"
		username    = "user-value-77d1"
		totp        = "JBSWY3DPEHPK3PXP"
	)
	uk := f.keys.user
	// Personal login in the nested folder Agents/CI, trying to forge native
	// labels through text custom fields and a scrim.* label.
	f.sync.Ciphers = append(f.sync.Ciphers, cipherJSON{
		ID: "c1", Type: cipherLogin, Name: *f.enc(t, uk, "Deploy"), FolderID: ptr("f1"),
		Login:        &loginJSON{Password: f.enc(t, uk, password)},
		RevisionDate: "2026-11-20T10:00:00Z", CreationDate: "2026-11-01T09:00:00Z",
		Fields: []fieldJSON{
			f.field(t, uk, fieldText, "vaultwarden.org", "Evil"),
			f.field(t, uk, fieldText, "vaultwarden.owner", "org"),
			f.field(t, uk, fieldText, "Environment", "staging"),
			f.field(t, uk, fieldText, "environment", "second wins not"),
			f.field(t, uk, fieldHidden, "token", hiddenValue),
			f.field(t, uk, fieldText, "scrim.hosts", "api.example.test"),
			f.field(t, uk, fieldBoolean, "rotated", "true"),
		},
	})
	// Organisation login with its own item key in two collections, with
	// URIs, TOTP, an attachment and every flag set.
	ik, err := bwcrypto.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := f.org.Encrypt(ik.Value())
	if err != nil {
		t.Fatal(err)
	}
	ws := wrapped.String()
	regex := uriMatchRegex
	uris := `[{"uri":"` + *f.enc(t, ik, "https://user:"+password+"@API.GitHub.com:8443/path?token="+hiddenValue) + `"},` +
		`{"uri":"` + *f.enc(t, ik, "gitlab.com/group") + `","match":null},` +
		`{"uri":"` + *f.enc(t, ik, `^https://secret\.internal/`) + `","match":` + itoa(regex) + `}]`
	yes, no := true, false
	f.sync.Ciphers = append(f.sync.Ciphers, cipherJSON{
		ID: "c2", Type: cipherLogin, Name: *f.enc(t, ik, "DB"), OrganizationID: ptr("o1"), Key: &ws,
		CollectionIDs: []string{"k1", "k2", "missing"}, Favorite: true, Reprompt: 1,
		Edit: &no, ViewPassword: &yes,
		Login: &loginJSON{
			Username: f.enc(t, ik, username), Password: f.enc(t, ik, password), Totp: f.enc(t, ik, totp),
			URIs: []byte(uris), PasswordRevisionDate: ptr("2026-10-01T00:00:00Z"),
		},
		Attachments: []byte(`[{"id":"a1","fileName":"x"}]`),
		Fields:      []fieldJSON{f.field(t, ik, fieldText, "vaultwarden.org", "Evil")},
	})
	// SSH key item in no folder.
	f.sync.Ciphers = append(f.sync.Ciphers, cipherJSON{ID: "c3", Type: cipherSSHKey, Name: *f.enc(t, uk, "Key"), SSHKey: []byte(`{}`)})

	v := buildVault(f.sync, f.keys, 1, nil, true)
	if len(v.warnings) != 0 {
		t.Fatalf("warnings: %v", v.warnings)
	}
	get := func(path, org string) map[string]string {
		t.Helper()
		it, _, err := v.lookup(path, org)
		if err != nil || it == nil {
			t.Fatalf("lookup %s: %v %v", path, it, err)
		}
		return it.all
	}
	want := func(l map[string]string, kv map[string]string, absent ...string) {
		t.Helper()
		for k, val := range kv {
			if got, ok := l[k]; !ok || got != val {
				t.Errorf("%s = %q (present %v), want %q", k, got, ok, val)
			}
		}
		for _, k := range absent {
			if _, ok := l[k]; ok {
				t.Errorf("%s present, want absent", k)
			}
		}
	}
	noValues := func(l map[string]string) {
		t.Helper()
		for k, val := range l {
			for _, s := range []string{hiddenValue, password, username, totp, "secret.internal"} {
				if strings.Contains(k, s) || strings.Contains(val, s) {
					t.Errorf("label %s=%q carries a value", k, val)
				}
			}
		}
	}

	p := get("Agents/CI/Deploy", "")
	want(p, map[string]string{
		"vaultwarden.owner":                  "personal",
		"vaultwarden.type":                   "login",
		"vaultwarden.name":                   "Deploy",
		"vaultwarden.id":                     "c1",
		"vaultwarden.folder":                 "Agents/CI",
		"vaultwarden.folder-id":              "f1",
		"vaultwarden.folder.Agents":          "true",
		"vaultwarden.folder.Agents/CI":       "true",
		"vaultwarden.has-password":           "true",
		"vaultwarden.has-username":           "false",
		"vaultwarden.has-totp":               "false",
		"vaultwarden.has-passkey":            "false",
		"vaultwarden.has-notes":              "false",
		"vaultwarden.has-attachments":        "false",
		"vaultwarden.item-key":               "false",
		"vaultwarden.favorite":               "false",
		"vaultwarden.reprompt":               "false",
		"vaultwarden.revision-date":          "2026-11-20T10:00:00Z",
		"vaultwarden.creation-date":          "2026-11-01T09:00:00Z",
		"vaultwarden.meta.vaultwarden.org":   "Evil",
		"vaultwarden.meta.vaultwarden.owner": "org",
		"vaultwarden.meta.environment":       "staging",
		"scrim.hosts":                        "api.example.test",
	}, "vaultwarden.org", "vaultwarden.org.id", "vaultwarden.collection", "vaultwarden.meta.token",
		"vaultwarden.meta.rotated", "vaultwarden.meta.scrim.hosts", "vaultwarden.edit", "vaultwarden.uri-host")
	noValues(p)

	o := get("Prod/DB", "Acme")
	if get("Shared/Team A/DB", "o1")["vaultwarden.id"] != "c2" {
		t.Fatal("the item is not found through its second collection")
	}
	want(o, map[string]string{
		"vaultwarden.owner":                                   "org",
		"vaultwarden.org":                                     "Acme",
		"vaultwarden.org.id":                                  "o1",
		"vaultwarden.org.role":                                "admin",
		"vaultwarden.collection":                              "Prod,Shared/Team A",
		"vaultwarden.collection.Prod":                         "true",
		"vaultwarden.collection.Shared":                       "true",
		"vaultwarden.collection.Shared/Team A":                "true",
		"vaultwarden.collection-id":                           "k1,k2",
		"vaultwarden.collection-id.k1":                        "true",
		"vaultwarden.collection-id.k2":                        "true",
		"vaultwarden.collection-read-only":                    "Prod",
		"vaultwarden.collection-read-only.Prod":               "true",
		"vaultwarden.collection-hide-passwords":               "Shared/Team A",
		"vaultwarden.collection-hide-passwords.Shared":        "true",
		"vaultwarden.collection-hide-passwords.Shared/Team A": "true",
		"vaultwarden.collection-manage.Shared/Team A":         "true",
		"vaultwarden.favorite":                                "true",
		"vaultwarden.reprompt":                                "true",
		"vaultwarden.item-key":                                "true",
		"vaultwarden.edit":                                    "false",
		"vaultwarden.view-password":                           "true",
		"vaultwarden.has-username":                            "true",
		"vaultwarden.has-totp":                                "true",
		"vaultwarden.has-attachments":                         "true",
		"vaultwarden.password-revision-date":                  "2026-10-01T00:00:00Z",
		"vaultwarden.uri-host":                                "api.github.com,gitlab.com",
		"vaultwarden.uri-host.api.github.com":                 "true",
		"vaultwarden.uri-host.gitlab.com":                     "true",
		"vaultwarden.meta.vaultwarden.org":                    "Evil",
	}, "vaultwarden.folder", "vaultwarden.collection.Other", "vaultwarden.collection-id.k3",
		"vaultwarden.collection-id.missing", "vaultwarden.collection-read-only.Shared")
	noValues(o)

	k := get("Key", "")
	want(k, map[string]string{"vaultwarden.type": "ssh-key", "vaultwarden.owner": "personal"},
		"vaultwarden.has-password", "vaultwarden.folder", "vaultwarden.collection")

	// meta-labels: false drops vaultwarden.meta.* and nothing else.
	off := buildVault(f.sync, f.keys, 1, nil, false)
	it, _, _ := off.lookup("Agents/CI/Deploy", "")
	for key := range it.all {
		if strings.HasPrefix(key, metaPrefix) {
			t.Errorf("meta label %s with meta labels off", key)
		}
	}
	if it.all["scrim.hosts"] == "" || it.all["vaultwarden.folder.Agents"] != "true" {
		t.Errorf("meta labels off dropped other labels: %v", it.all)
	}
}

func TestMergeNativeOverrides(t *testing.T) {
	user := map[string]string{
		"vaultwarden.org":             "Evil",
		"vaultwarden.collection.Prod": "true",
		"vaultwarden.meta.env":        "dev",
		"scrim.hosts":                 "h",
	}
	n := nativeLabels{}
	n.set("org", "Acme")
	got := mergeNative(user, n)
	if got["vaultwarden.org"] != "Acme" {
		t.Errorf("native org overridden: %q", got["vaultwarden.org"])
	}
	if _, ok := got["vaultwarden.collection.Prod"]; ok {
		t.Error("a user-supplied native presence key survived")
	}
	if got["vaultwarden.meta.env"] != "dev" || got["scrim.hosts"] != "h" {
		t.Errorf("user labels dropped: %v", got)
	}
}

func TestWriteLabels(t *testing.T) {
	f := newLabelFixture(t)
	uk := f.keys.user
	f.sync.Ciphers = append(f.sync.Ciphers, cipherJSON{
		ID: "c1", Type: cipherLogin, Name: *f.enc(t, uk, "Deploy"), FolderID: ptr("f1"), Login: &loginJSON{},
	})
	a := &Adapter{v: buildVault(f.sync, f.keys, 1, nil, true)}
	ref := func(s string) stores.Ref { return stores.MustParseRef(s) }

	// An existing item: its own labels.
	if got := a.WriteLabels(ref("vw://Agents/CI/Deploy#password")); got["vaultwarden.id"] != "c1" || got["vaultwarden.folder.Agents"] != "true" {
		t.Errorf("existing item: %v", got)
	}
	// A new personal item lands in the folder named by the prefix.
	got := a.WriteLabels(ref("vw://Agents/CI/New"))
	for k, v := range map[string]string{
		"vaultwarden.owner": "personal", "vaultwarden.folder": "Agents/CI", "vaultwarden.folder-id": "f1",
		"vaultwarden.folder.Agents": "true", "vaultwarden.folder.Agents/CI": "true",
		"vaultwarden.name": "New", "vaultwarden.type": "login",
	} {
		if got[k] != v {
			t.Errorf("new personal item: %s = %q, want %q", k, got[k], v)
		}
	}
	// A new organisation item lands in the collection named by the prefix.
	got = a.WriteLabels(ref("vw://Prod/New?org=Acme"))
	for k, v := range map[string]string{
		"vaultwarden.owner": "org", "vaultwarden.org": "Acme", "vaultwarden.org.id": "o1",
		"vaultwarden.org.role": "admin", "vaultwarden.collection": "Prod", "vaultwarden.collection.Prod": "true",
		"vaultwarden.collection-id.k1": "true", "vaultwarden.collection-read-only.Prod": "true",
	} {
		if got[k] != v {
			t.Errorf("new org item: %s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["vaultwarden.folder"]; ok {
		t.Error("an organisation item got a folder")
	}
	// Before the first sync, the reference alone decides.
	cold := &Adapter{}
	got = cold.WriteLabels(ref("vw://Prod/DB/New?org=Acme"))
	if got["vaultwarden.org"] != "Acme" || got["vaultwarden.collection.Prod/DB"] != "true" || got["vaultwarden.collection.Prod"] != "true" {
		t.Errorf("cold org write: %v", got)
	}
	got = cold.WriteLabels(ref("vw://X/New?org=6F9619FF-8B86-D011-B42D-00C04FC964FF"))
	if got["vaultwarden.org.id"] != "6f9619ff-8b86-d011-b42d-00c04fc964ff" || got["vaultwarden.org"] != "" {
		t.Errorf("cold org id write: %v", got)
	}
}

func ptr(s string) *string { return &s }

func itoa(n int) string { return strconv.Itoa(n) }

// TestMetaGuard checks the second guard on vaultwarden.meta.*: a text field
// whose value equals or contains a secret value of any item in the store is
// never reported, even with meta labels on.
func TestMetaGuard(t *testing.T) {
	f := newLabelFixture(t)
	uk := f.keys.user
	const (
		token = "tok-3b9f0c2a77e1"
		pw    = "pw-c41d8e0f9a"
		seed  = "JBSWY3DPEHPK3PXP"
	)
	f.sync.Ciphers = append(f.sync.Ciphers, cipherJSON{
		ID: "c1", Type: cipherLogin, Name: *f.enc(t, uk, "Source"), FolderID: ptr("f1"),
		Login:  &loginJSON{Password: f.enc(t, uk, pw)},
		Notes:  f.enc(t, uk, "rotate monthly"),
		Fields: []fieldJSON{f.field(t, uk, fieldHidden, "token", token), f.field(t, uk, fieldText, "env", "prod")},
	}, cipherJSON{
		ID: "c2", Type: cipherLogin, Name: *f.enc(t, uk, "Leaky"), FolderID: ptr("f1"),
		Login: &loginJSON{Totp: f.enc(t, uk, seed)},
		Fields: []fieldJSON{
			f.field(t, uk, fieldText, "contains", "export TOKEN="+token+" # ci"),
			f.field(t, uk, fieldText, "equals", pw),
			f.field(t, uk, fieldText, "own-totp", seed),
			f.field(t, uk, fieldText, "notes-copy", "rotate monthly"),
			f.field(t, uk, fieldText, "env", "prod"),
		},
	})
	v := buildVault(f.sync, f.keys, 1, nil, true)
	it, _, err := v.lookup("Agents/CI/Leaky", "")
	if err != nil || it == nil {
		t.Fatalf("lookup: %v", err)
	}
	for _, k := range []string{"contains", "equals", "own-totp", "notes-copy"} {
		if _, ok := it.all[metaPrefix+k]; ok {
			t.Errorf("%s%s present: a meta label carries a secret value", metaPrefix, k)
		}
	}
	if it.all[metaPrefix+"env"] != "prod" {
		t.Errorf("a text field without a secret value was dropped: %v", it.all)
	}
	// Off by default: no meta labels at all.
	off := buildVault(f.sync, f.keys, 1, nil, false)
	src, _, _ := off.lookup("Agents/CI/Source", "")
	if _, ok := src.all[metaPrefix+"env"]; ok {
		t.Error("meta label with meta labels off")
	}
}

// TestMetaGuardScope checks that the guard never decrypts items outside the
// configured scope: an out-of-scope item whose hidden value cannot decrypt
// would otherwise make the guard drop every meta label, and one repeating
// an in-scope text value would suppress it.
func TestMetaGuardScope(t *testing.T) {
	f := newLabelFixture(t)
	uk := f.keys.user
	f.folder(t, "f2", "Personal")
	f.sync.Ciphers = append(f.sync.Ciphers, cipherJSON{
		ID: "in", Type: cipherLogin, Name: *f.enc(t, uk, "In"), FolderID: ptr("f1"), Login: &loginJSON{},
		Fields: []fieldJSON{f.field(t, uk, fieldText, "env", "prod-eu-1")},
	}, cipherJSON{
		ID: "out", Type: cipherLogin, Name: *f.enc(t, uk, "Bank"), FolderID: ptr("f2"), Login: &loginJSON{},
		Fields: []fieldJSON{
			// A value that cannot decrypt: decrypting it would fail the guard.
			{Type: fieldHidden, Name: f.enc(t, uk, "broken"), Value: ptr("2.AAAA|AAAA|AAAA")},
			f.field(t, uk, fieldHidden, "same", "prod-eu-1"),
			f.field(t, uk, fieldText, "outside", "visible"),
		},
	})
	v := buildVault(f.sync, f.keys, 1, []string{"Agents"}, true)
	in, _, _ := v.lookup("Agents/CI/In", "")
	if in == nil || in.all[metaPrefix+"env"] != "prod-eu-1" {
		t.Error("an out-of-scope item was decrypted by the meta guard")
	}
	for _, it := range v.items {
		if it.raw.ID == "out" && len(it.meta) > 0 {
			t.Error("text fields of an out-of-scope item were decrypted")
		}
	}
	// Without a scope the whole account is in scope, so the broken value
	// makes the guard drop every meta label.
	all := buildVault(f.sync, f.keys, 1, nil, true)
	in, _, _ = all.lookup("Agents/CI/In", "")
	if _, ok := in.all[metaPrefix+"env"]; ok {
		t.Error("guard did not cover the whole account without a scope")
	}
}
