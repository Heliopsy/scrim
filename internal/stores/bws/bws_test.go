// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if x != "" && strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// errText is everything an error can print.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v %+v %#v", err, err, err)
}

func ref(path string) stores.Ref { return stores.Ref{Scheme: "bws", Path: path} }

func read(t *testing.T, a *Adapter, r stores.Ref) string {
	t.Helper()
	s, err := a.Read(t.Context(), r)
	if err != nil {
		t.Fatalf("Read %s: %v", r, err)
	}
	defer s.Wipe()
	if len(s.Fields) != 1 {
		t.Fatalf("Read %s: %d fields", r, len(s.Fields))
	}
	for _, v := range s.Fields {
		return plainOf(t, v)
	}
	return ""
}

func TestReadsOfficialFixtures(t *testing.T) {
	f := newFake(t)
	f.seedOfficial()
	a := newAdapter(t, f, nil)
	c := officialCipher
	if got := read(t, a, ref("Production Environment/TUX")); got != c.plainTux {
		t.Errorf("TUX = %q", got)
	}
	if got := read(t, a, ref("Development Environment/synced-secret").WithField(FieldValue)); got != c.plainSyncedV {
		t.Errorf("synced-secret = %q", got)
	}
	if got := read(t, a, ref("Production Environment/FERRIS").WithField(FieldNote)); got != c.plainTEST {
		t.Errorf("FERRIS note = %q", got)
	}
	ms, err := a.List(t.Context(), ref("Production Environment"))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, m := range ms {
		paths = append(paths, m.Ref.Path)
		if m.Labels["bws.project"] != c.plainProd || m.Labels["bws.org"] != officialOrg {
			t.Errorf("labels of %s: %v", m.Ref, m.Labels)
		}
	}
	if !slices.Equal(paths, []string{"Production Environment/FERRIS", "Production Environment/TUX"}) {
		t.Errorf("listed %v", paths)
	}
}

func TestDeviceTypeHeader(t *testing.T) {
	f := newFake(t)
	f.addProject("p", true)
	a := newAdapter(t, f, nil)
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, d := range f.deviceTypes {
		if d != deviceTypeSDK {
			t.Errorf("request with Device-Type %q, want %s like the SDK", d, deviceTypeSDK)
		}
	}
}

// TestRequestsCarryOnlyCiphertext checks that a value and a note written
// through scrim never reach the server in plaintext.
func TestRequestsCarryOnlyCiphertext(t *testing.T) {
	f := newFake(t)
	f.addProject("app", true)
	a := newAdapter(t, f, nil)
	val, note := "val_"+newUUID(), "note_"+newUUID()
	fields := map[string]secret.Value{FieldValue: secret.FromString(val), FieldNote: secret.FromString(note)}
	if _, err := a.Write(t.Context(), ref("app/API_TOKEN"), fields, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	second := "val2_" + newUUID()
	m2, err := a.Write(t.Context(), ref("app/API_TOKEN"), map[string]secret.Value{FieldValue: secret.FromString(second)}, stores.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m2.Labels["bws.project"] != "app" {
		t.Errorf("update metadata lost the project (the server answers without it): %v", m2.Labels)
	}
	for _, p := range []string{val, note, second, "API_TOKEN"} {
		if f.sawPlain(p) {
			t.Errorf("a request carried %q in plaintext", p)
		}
	}
	if f.sawPlain(officialSecret) && !strings.Contains(strings.Join(f.requests, "\n"), "client_secret="+officialSecret) {
		t.Errorf("client secret sent outside the login form")
	}
	// The update kept the note and the project.
	if got := read(t, a, ref("app/API_TOKEN").WithField(FieldNote)); got != note {
		t.Errorf("note after a value-only update = %q", got)
	}
	if got := read(t, a, ref("app/API_TOKEN")); got != second {
		t.Errorf("value after update = %q", got)
	}
}

func TestAmbiguousKeys(t *testing.T) {
	f := newFake(t)
	pid := f.addProject("app", true)
	v1, v2 := "one_"+newUUID(), "two_"+newUUID()
	id1 := f.put(pid, "DUP", secret.FromString(v1))
	id2 := f.addSecretCipher(pid, f.enc("DUP"), f.enc(v2), f.enc(""))
	f.put(pid, "UNIQUE", secret.FromString("u_"+newUUID()))
	a := newAdapter(t, f, nil)

	_, err := a.Read(t.Context(), ref("app/DUP"))
	if !errors.Is(err, stores.ErrInvalidRef) || !strings.Contains(err.Error(), id1) || !strings.Contains(err.Error(), id2) {
		t.Errorf("Read of a shared key: %v, want ErrInvalidRef naming both IDs", err)
	}
	if containsAny(errText(err), v1, v2) {
		t.Errorf("ambiguity error carries a value")
	}
	if got := read(t, a, ref(id2)); got != v2 {
		t.Errorf("Read by ID = %q", got)
	}
	_, err = a.Write(t.Context(), ref("app/DUP"), map[string]secret.Value{FieldValue: secret.FromString("x")}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("Write to a shared key: %v, want ErrInvalidRef", err)
	}
	ms, err := a.List(t.Context(), ref("app"))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, m := range ms {
		paths = append(paths, m.Ref.Path)
	}
	want := []string{id1, id2, "app/UNIQUE"}
	slices.Sort(want)
	if !slices.Equal(paths, want) {
		t.Errorf("List = %v, want shared keys by ID: %v", paths, want)
	}
}

func TestAmbiguousProjects(t *testing.T) {
	f := newFake(t)
	p1 := f.addProject("same", true)
	p2 := f.addProject("same", true)
	f.put(p1, "K", secret.FromString("a_"+newUUID()))
	v := "b_" + newUUID()
	f.put(p2, "K", secret.FromString(v))
	a := newAdapter(t, f, nil)
	_, err := a.Read(t.Context(), ref("same/K"))
	if !errors.Is(err, stores.ErrInvalidRef) || !strings.Contains(err.Error(), p1) || !strings.Contains(err.Error(), p2) {
		t.Errorf("Read through a shared project name: %v", err)
	}
	if got := read(t, a, ref(p2+"/K")); got != v {
		t.Errorf("Read by project ID = %q", got)
	}
	ms, err := a.List(t.Context(), ref(strings.ToUpper(p2)))
	if err != nil || len(ms) != 1 || ms[0].Ref.Path != strings.ToUpper(p2)+"/K" {
		t.Errorf("List by project ID: %v %v", ms, err)
	}
}

// TestMetadataWithoutValues checks ReadMetadata and List never fetch a
// secret (GET /secrets/{id} is the only call that returns a value) and label
// as Read does.
func TestMetadataWithoutValues(t *testing.T) {
	f := newFake(t)
	pid := f.addProject("payments", true)
	v := "v_" + newUUID()
	id := f.put(pid, "db/PASSWORD", secret.FromString(v))
	a := newAdapter(t, f, nil)
	m, err := a.ReadMetadata(t.Context(), ref("payments/db/PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.List(t.Context(), ref("payments/db")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadMetadata(t.Context(), ref(id)); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.requests {
		if strings.HasPrefix(r, "GET /api/secrets/") {
			t.Errorf("metadata lookup fetched a secret: %s", strings.Fields(r)[1])
		}
	}
	s, err := a.Read(t.Context(), ref("payments/db/PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wipe()
	if !maps.Equal(m.Labels, s.Meta.Labels) || m.Version != s.Meta.Version {
		t.Errorf("metadata labels %v / %s differ from read %v / %s", m.Labels, m.Version, s.Meta.Labels, s.Meta.Version)
	}
	want := map[string]string{
		"bws.org": officialOrg, "bws.id": id, "bws.key": "db/PASSWORD",
		"bws.project": "payments", "bws.project.payments": "true",
		"bws.project-id": pid, "bws.project-id." + pid: "true",
	}
	for k, v := range want {
		if m.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, m.Labels[k], v)
		}
	}
	for _, k := range []string{"bws.created", "bws.updated"} {
		if m.Labels[k] == "" {
			t.Errorf("label %s missing", k)
		}
	}
	_, err = a.ReadMetadata(t.Context(), ref("payments/absent"))
	if !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("ReadMetadata of a missing secret: %v", err)
	}
}

// TestLabelsHoldNoValueOrNote seeds a note and a value and checks neither
// appears in any label.
func TestLabelsHoldNoValueOrNote(t *testing.T) {
	f := newFake(t)
	f.addProject("app", true)
	a := newAdapter(t, f, nil)
	v, n := "value_"+newUUID(), "note_"+newUUID()
	m, err := a.Write(t.Context(), ref("app/K"), map[string]secret.Value{FieldValue: secret.FromString(v), FieldNote: secret.FromString(n)}, stores.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.Read(t.Context(), ref("app/K"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wipe()
	for _, l := range []map[string]string{m.Labels, s.Meta.Labels} {
		for k, val := range l {
			if containsAny(k+"="+val, v, n) {
				t.Errorf("label %s carries the value or note", k)
			}
		}
	}
	if _, ok := s.Fields[FieldNote]; ok {
		t.Errorf("a whole-secret read returned the note")
	}
	if m.Labels["bws.project"] != "app" {
		t.Errorf("write metadata labels %v", m.Labels)
	}
}

func TestWriteLabels(t *testing.T) {
	a := newAdapter(t, newFake(t), nil)
	got := a.WriteLabels(ref("payments/db/NEW"))
	want := map[string]string{"bws.project": "payments", "bws.project.payments": "true", "bws.key": "db/NEW"}
	if !maps.Equal(got, want) {
		t.Errorf("WriteLabels = %v, want %v", got, want)
	}
	id := newUUID()
	if got := a.WriteLabels(ref(strings.ToUpper(id) + "/K")); got["bws.project-id"] != id {
		t.Errorf("WriteLabels by project ID = %v", got)
	}
	if got := a.WriteLabels(ref(id)); got["bws.id"] != id || len(got) != 1 {
		t.Errorf("WriteLabels by secret ID = %v", got)
	}
}

func TestWriteRules(t *testing.T) {
	f := newFake(t)
	f.addProject("app", true)
	a := newAdapter(t, f, nil)
	ctx := t.Context()
	val := func() map[string]secret.Value {
		return map[string]secret.Value{FieldValue: secret.FromString("v_" + newUUID())}
	}
	cases := []struct {
		name   string
		ref    stores.Ref
		fields map[string]secret.Value
		kind   error
	}{
		{"unknown project", ref("nope/K"), val(), stores.ErrNotFound},
		{"unknown secret ID", ref(newUUID()), val(), stores.ErrNotFound},
		{"bare name", ref("K"), val(), stores.ErrInvalidRef},
		{"other field", ref("app/K"), map[string]secret.Value{"password": secret.FromString("x")}, stores.ErrInvalidRef},
		{"empty value", ref("app/K"), map[string]secret.Value{FieldValue: secret.FromString("")}, stores.ErrUnsupported},
		{"invalid UTF-8", ref("app/K"), map[string]secret.Value{FieldValue: secret.New([]byte{0xff, 0xfe})}, stores.ErrUnsupported},
		{"too long", ref("app/K"), map[string]secret.Value{FieldValue: secret.FromString(strings.Repeat("x", maxValueLen+1))}, stores.ErrUnsupported},
		{"too long encrypted", ref("app/K"), map[string]secret.Value{FieldValue: secret.FromString(strings.Repeat("é", maxValueLen))}, stores.ErrUnsupported},
		{"key with trailing space", ref("app/K "), val(), stores.ErrInvalidRef},
		{"selector", stores.Ref{Scheme: "bws", Path: "app/K", Selectors: "version=1"}, val(), stores.ErrInvalidRef},
	}
	for _, c := range cases {
		_, err := a.Write(ctx, c.ref, c.fields, stores.WriteOptions{})
		if !errors.Is(err, c.kind) {
			t.Errorf("%s: %v, want %v", c.name, err, c.kind)
		}
	}
	if len(f.secrets) != 0 {
		t.Errorf("a refused write stored %d secrets", len(f.secrets))
	}
}

func TestReadRules(t *testing.T) {
	f := newFake(t)
	pid := f.addProject("app", true)
	f.put(pid, "K", secret.FromString("v_"+newUUID()))
	a := newAdapter(t, f, nil)
	for _, c := range []struct {
		r    stores.Ref
		kind error
	}{
		{ref("app/K").WithField("password"), stores.ErrNotFound},
		{ref("app"), stores.ErrInvalidRef},
		{stores.Ref{Scheme: "bws", Path: "app/K", Selectors: "version=2"}, stores.ErrInvalidRef},
	} {
		if _, err := a.Read(t.Context(), c.r); !errors.Is(err, c.kind) {
			t.Errorf("Read %s: %v, want %v", c.r, err, c.kind)
		}
	}
}

// TestTamperedCiphertext changes one byte of a stored value's MAC: the read
// fails and returns nothing.
func TestTamperedCiphertext(t *testing.T) {
	f := newFake(t)
	pid := f.addProject("app", true)
	id := f.put(pid, "K", secret.FromString("v_"+newUUID()))
	f.mu.Lock()
	s := f.secrets[id]
	b := []byte(s.value)
	i := len(b) - 3
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	s.value = string(b)
	f.mu.Unlock()
	a := newAdapter(t, f, nil)
	got, err := a.Read(t.Context(), ref("app/K"))
	if err == nil {
		got.Wipe()
		t.Fatal("a tampered value was read")
	}
	if !errors.Is(err, stores.ErrUnavailable) || len(got.Fields) != 0 {
		t.Errorf("tampered read: %v", err)
	}
}

func TestLoginRefused(t *testing.T) {
	f := newFake(t)
	wrong := "0." + officialTokenID + ".WrongSecret" + newUUID()[:8] + ":X8vbvA0bduihIDe/qrzIQQ=="
	a, err := New(t.Context(), stores.Instance{Name: "bws", Kind: Kind, Options: map[string]any{"server-url": f.srv.URL, "token": "env:T"}, Resolve: resolver(wrong)})
	if err != nil {
		t.Fatal(err)
	}
	err = a.Health(t.Context())
	if !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Health with a revoked token: %v, want ErrPermission", err)
	}
	if containsAny(errText(err), "WrongSecret", "X8vbvA0bduihIDe") {
		t.Errorf("login error quotes the token: %v", err)
	}
	b, err := New(t.Context(), stores.Instance{Name: "bws", Kind: Kind, Options: map[string]any{"server-url": f.srv.URL, "token": "env:T"}, Resolve: resolver("garbage-" + officialSecret)})
	if err != nil {
		t.Fatal(err)
	}
	err = b.Health(t.Context())
	if !errors.Is(err, stores.ErrPermission) || containsAny(errText(err), officialSecret) {
		t.Errorf("Health with a malformed token: %v", err)
	}
}

func TestLoginAgain(t *testing.T) {
	f := newFake(t)
	pid := f.addProject("app", true)
	v := "v_" + newUUID()
	f.put(pid, "K", secret.FromString(v))
	a := newAdapter(t, f, nil)
	read(t, a, ref("app/K"))
	f.revokeBearers()
	if got := read(t, a, ref("app/K")); got != v {
		t.Errorf("value after a refused bearer = %q", got)
	}
	if f.logins != 2 {
		t.Errorf("%d logins, want 2 (one after the 401)", f.logins)
	}
	// A token past its expiry is renewed before it is used.
	f.expiresIn = 60
	b := newAdapter(t, f, nil)
	read(t, b, ref("app/K"))
	read(t, b, ref("app/K"))
	if f.logins != 3 {
		t.Errorf("%d logins, want 3 (the token is reused while valid)", f.logins)
	}
	later := time.Now().Add(time.Minute)
	b.c.mu.Lock()
	b.c.now = func() time.Time { return later }
	b.c.mu.Unlock()
	read(t, b, ref("app/K"))
	if f.logins != 4 {
		t.Errorf("%d logins, want 4 (an expired token is renewed)", f.logins)
	}
}

func TestCredentials(t *testing.T) {
	f := newFake(t)
	f.addProject("p", true)
	a := newAdapter(t, f, nil)
	if len(a.Credentials()) != 0 {
		t.Errorf("credentials before the first login")
	}
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	creds := a.Credentials()
	var got []string
	for _, c := range creds {
		got = append(got, plainOf(t, c))
		c.Wipe()
	}
	for _, want := range []string{officialToken, officialSecret, "X8vbvA0bduihIDe/qrzIQQ=="} {
		if !slices.Contains(got, want) {
			t.Errorf("credentials miss a part of the access token")
		}
	}
	if len(got) != 4 || !strings.HasPrefix(got[3], "eyJ") {
		t.Errorf("credentials miss the bearer token (%d entries)", len(got))
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if len(a.Credentials()) != 0 {
		t.Errorf("credentials after close")
	}
}

func TestGlobList(t *testing.T) {
	f := newFake(t)
	pid := f.addProject("app", true)
	for _, k := range []string{"APP_ONE", "APP_TWO", "OTHER", "APP/nested"} {
		f.put(pid, k, secret.FromString("v_"+newUUID()))
	}
	a := newAdapter(t, f, nil)
	for prefix, want := range map[string][]string{
		"app/APP_*": {"app/APP_ONE", "app/APP_TWO"},
		"app/APP":   {"app/APP/nested"},
		"app/*":     {"app/APP/nested", "app/APP_ONE", "app/APP_TWO", "app/OTHER"},
		"nothing":   nil,
	} {
		ms, err := a.List(t.Context(), ref(prefix))
		if err != nil {
			t.Fatalf("List %s: %v", prefix, err)
		}
		var got []string
		for _, m := range ms {
			got = append(got, m.Ref.Path)
		}
		if !slices.Equal(got, want) {
			t.Errorf("List %s = %v, want %v", prefix, got, want)
		}
	}
	if _, err := a.List(t.Context(), ref("ap*")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("glob in the project: %v", err)
	}
}

func TestOptions(t *testing.T) {
	cases := []struct {
		name string
		opts map[string]any
		api  string
		id   string
		bad  string
	}{
		{"defaults", map[string]any{"token": "env:T"}, defaultAPIURL, defaultIdentityURL, ""},
		{"eu", map[string]any{"token": "env:T", "api-url": "https://api.bitwarden.eu", "identity-url": "https://identity.bitwarden.eu/"}, "https://api.bitwarden.eu", "https://identity.bitwarden.eu", ""},
		{"self-hosted", map[string]any{"token": "env:T", "server-url": "https://vault.example.test/"}, "https://vault.example.test/api", "https://vault.example.test/identity", ""},
		{"no token", map[string]any{}, "", "", "token is required"},
		{"both", map[string]any{"token": "env:T", "server-url": "https://a", "api-url": "https://b"}, "", "", "cannot be combined"},
		{"bad url", map[string]any{"token": "env:T", "api-url": "ftp://x"}, "", "", "http or https"},
		{"typo", map[string]any{"token": "env:T", "server-ulr": "https://x"}, "", "", "server-ulr"},
	}
	for _, c := range cases {
		a, err := New(t.Context(), stores.Instance{Name: "bws", Kind: Kind, Options: c.opts, Resolve: resolver("x")})
		if c.bad != "" {
			if err == nil || !strings.Contains(err.Error(), c.bad) {
				t.Errorf("%s: %v, want an error about %q", c.name, err, c.bad)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		s := a.(*Adapter).s
		if s.api.String() != c.api || s.identity.String() != c.id {
			t.Errorf("%s: api %s identity %s", c.name, s.api, s.identity)
		}
	}
}

func TestRegistered(t *testing.T) {
	if !slices.Contains(stores.DefaultRegistry.Kinds(), Kind) {
		t.Fatal("bws not registered")
	}
	if !stores.IsMulti(Kind, "project") {
		t.Error("bws.project not declared multi-valued")
	}
}
