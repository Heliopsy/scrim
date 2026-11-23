// SPDX-License-Identifier: AGPL-3.0-only

package onepassword

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// The conformance suite and these tests run against the in-process fake in
// fake_test.go, which follows the Connect OpenAPI document and the item
// shapes in testdata. No 1Password account or Connect server is involved;
// docs/stores/onepassword.md lists what the fake cannot vouch for.

func instance(addr string, tokens map[string]string, extra map[string]any) stores.Instance {
	opts := map[string]any{"address": addr, "token": config.SecretRef("env:OP_CONNECT_TOKEN")}
	maps.Copy(opts, extra)
	return stores.Instance{
		Name: "op", Kind: Kind, Options: opts,
		Resolve: func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
			v, ok := tokens[string(ref)]
			if !ok {
				return secret.Value{}, fmt.Errorf("reference %s does not resolve", ref)
			}
			return secret.FromString(v), nil
		},
	}
}

func newAdapter(t testing.TB, f *fake, extra map[string]any) *Adapter {
	t.Helper()
	a, err := New(t.Context(), instance(f.srv.URL, map[string]string{"env:OP_CONNECT_TOKEN": f.token}, extra))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a.(*Adapter)
}

func plain(t testing.TB, v secret.Value) string {
	t.Helper()
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

func ref(s string) stores.Ref { return stores.MustParseRef("op://" + s) }

// noLeak fails if any rendering of x contains one of the values.
func noLeak(t *testing.T, what string, x any, vals ...string) {
	t.Helper()
	texts := []string{fmt.Sprintf("%v", x), fmt.Sprintf("%+v", x), fmt.Sprintf("%#v", x)}
	if err, ok := x.(error); ok && err != nil {
		for e := err; e != nil; e = errors.Unwrap(e) {
			texts = append(texts, e.Error())
		}
		var se *stores.Error
		if errors.As(err, &se) && se.Cause != nil {
			texts = append(texts, fmt.Sprintf("%+v", se.Cause))
		}
	}
	for _, s := range texts {
		for _, v := range vals {
			if v != "" && strings.Contains(s, v) {
				t.Errorf("%s contains a value", what)
				return
			}
		}
	}
}

func TestConformanceFake(t *testing.T) {
	f := newFake(t)
	v := f.addVault("Conformance")
	ro := f.addVault("Readonly")
	ro.ReadOnly = true
	storetest.Run(t, func(tb storetest.TB) storetest.Harness {
		a := newAdapter(tb.(testing.TB), f, map[string]any{"watch.interval": "50ms", "watch.max-backoff": "200ms"})
		return storetest.Harness{
			Adapter: a,
			Prefix:  "Conformance/run-" + randHex(4),
			Delete: func(_ storetest.TB, r stores.Ref) {
				loc, _ := splitSecret(r.Path)
				f.removeTitled(v, loc.item)
			},
			Outage: func(storetest.TB) func() {
				f.setDown(true)
				return func() { f.setDown(false) }
			},
			Reject:       func(storetest.TB) stores.Ref { return ref("Readonly/refused-" + randHex(4)) },
			WatchTimeout: 5 * time.Second,
		}
	})
}

// fixture loads testdata/item-login.json with every {{name}} replaced by a
// value generated for this run, and returns the values by name.
func fixture(t *testing.T) (map[string]any, map[string]string) {
	t.Helper()
	b, err := os.ReadFile("testdata/item-login.json")
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]string{}
	s := string(b)
	for _, n := range []string{"username", "password", "notes", "region", "api-token", "backup-token", "otp-uri", "totp"} {
		vals[n] = n + "-" + randHex(8)
		s = strings.ReplaceAll(s, "{{"+n+"}}", vals[n])
	}
	var it map[string]any
	if err := json.Unmarshal([]byte(s), &it); err != nil {
		t.Fatal(err)
	}
	return it, vals
}

// seedFixture creates vault Prod (with the fixture's vault ID) holding the
// fixture item.
func seedFixture(t *testing.T, f *fake) (*fakeVault, map[string]string) {
	t.Helper()
	it, vals := fixture(t)
	f.mu.Lock()
	v := &fakeVault{ID: "ionaiwtdvgclrixbt6ztpqcxnq", Name: "Prod", Type: "USER_CREATED", items: map[string]map[string]any{}}
	f.vaults[v.ID] = v
	f.mu.Unlock()
	f.put(v, it)
	return v, vals
}

func allValues(vals map[string]string) []string { return slices.Collect(maps.Values(vals)) }

func TestRegistered(t *testing.T) {
	f := newFake(t)
	a, err := stores.DefaultRegistry.Open(t.Context(), instance(f.srv.URL, map[string]string{"env:OP_CONNECT_TOKEN": f.token}, nil))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = a.Close() }()
	if got := a.Capabilities().String(); got != "read,list,watch,write,glob" {
		t.Errorf("capabilities = %s", got)
	}
	if n := len(f.requestLog()); n != 0 {
		t.Errorf("the factory contacted the store (%d requests)", n)
	}
	if c := a.(stores.CredentialHolder).Credentials(); len(c) != 0 {
		t.Errorf("the factory resolved the token")
	}
}

func TestOptions(t *testing.T) {
	tokens := map[string]string{"env:OP_CONNECT_TOKEN": "x"}
	for name, tc := range map[string]struct {
		addr  string
		extra map[string]any
		want  string
	}{
		"no address":     {"", nil, "address is required"},
		"bad address":    {"ftp://connect", nil, "http or https URL"},
		"bad category":   {"http://connect:8080", map[string]any{"write.category": "custom"}, "unsupported category"},
		"unknown option": {"http://connect:8080", map[string]any{"vault": "Prod"}, "unknown option vault"},
		"bad interval":   {"http://connect:8080", map[string]any{"watch.interval": "-1s"}, "must be positive"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(t.Context(), instance(tc.addr, tokens, tc.extra))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !errors.Is(err, stores.ErrInvalidRef) {
				t.Errorf("New: %v, want an error about %q", err, tc.want)
			}
		})
	}
	inst := instance("http://connect:8080", tokens, nil)
	delete(inst.Options, "token")
	if _, err := New(t.Context(), inst); err == nil || !strings.Contains(err.Error(), "token is required") {
		t.Errorf("New without token: %v", err)
	}
	a, err := New(t.Context(), instance("http://connect:8080", tokens, map[string]any{"write.category": "login"}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := a.(*Adapter).s.category; got != "LOGIN" {
		t.Errorf("category = %s", got)
	}
}

func TestReadFixture(t *testing.T) {
	f := newFake(t)
	_, vals := seedFixture(t, f)
	a := newAdapter(t, f, nil)
	s, err := a.Read(t.Context(), ref("Prod/GitHub/deploy"))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	defer s.Wipe()
	want := map[string]string{
		"username":              vals["username"],
		"password":              vals["password"],
		"notesPlain":            vals["notes"],
		"region":                vals["region"],
		"API/token":             vals["api-token"],
		"Backup/token":          vals["backup-token"],
		"API/one-time password": vals["otp-uri"],
	}
	if got := slices.Sorted(maps.Keys(s.Fields)); !slices.Equal(got, slices.Sorted(maps.Keys(want))) {
		t.Errorf("fields = %v, want %v", got, slices.Sorted(maps.Keys(want)))
	}
	for k, w := range want {
		if v, ok := s.Field(k); !ok || plain(t, v) != w {
			t.Errorf("field %s: wrong value", k)
		}
	}
	if !slices.Equal(s.Meta.Fields, slices.Sorted(maps.Keys(want))) {
		t.Errorf("Meta.Fields = %v", s.Meta.Fields)
	}
	if s.Meta.Version != "3" {
		t.Errorf("version = %q", s.Meta.Version)
	}
	wantLabels := map[string]string{
		"onepassword.vault":                   "Prod",
		"onepassword.vault-id":                "ionaiwtdvgclrixbt6ztpqcxnq",
		"onepassword.vault-type":              "USER_CREATED",
		"onepassword.item":                    "GitHub/deploy",
		"onepassword.item-id":                 "p7eflcy7f5mk7vg6zrzf5rjjyu",
		"onepassword.category":                "LOGIN",
		"onepassword.favorite":                "true",
		"onepassword.version":                 "3",
		"onepassword.last-edited-by":          "DOEU2NHY4FDGFG4ZVLKSLE5ORM",
		"onepassword.created":                 "2024-01-04T16:37:15.402Z",
		"onepassword.updated":                 "2024-05-21T09:12:44.118Z",
		"onepassword.tag":                     "ci,team/payments",
		"onepassword.tag.ci":                  "true",
		"onepassword.tag.team":                "true",
		"onepassword.tag.team/payments":       "true",
		"onepassword.url-host":                "api.github.com,github.com",
		"onepassword.url-host.github.com":     "true",
		"onepassword.url-host.api.github.com": "true",
	}
	if !maps.Equal(s.Meta.Labels, wantLabels) {
		t.Errorf("labels:\n got %v\nwant %v", s.Meta.Labels, wantLabels)
	}
	// The TOTP code Connect derives is never a field, and no value is a
	// label or appears in metadata.
	noLeak(t, "metadata", s.Meta, allValues(vals)...)
	for k, v := range s.Fields {
		if plain(t, v) == vals["totp"] {
			t.Errorf("field %s holds the TOTP code", k)
		}
	}
}

func TestFieldSelection(t *testing.T) {
	f := newFake(t)
	_, vals := seedFixture(t, f)
	a := newAdapter(t, f, nil)
	for sel, want := range map[string]string{
		"password":                          vals["password"],
		"region":                            vals["region"],
		"add more/region":                   vals["region"],
		"API/token":                         vals["api-token"],
		"a3dq5oqxsnkbtbs4scb5xijtdm/token":  vals["api-token"],
		"Backup/qkxzmqn7eexfbjfv4xn2fssppe": vals["backup-token"],
		"qkxzmqn7eexfbjfv4xn2fssppe":        vals["backup-token"],
		"API/one-time password":             vals["otp-uri"],
		"notesPlain":                        vals["notes"],
	} {
		s, err := a.Read(t.Context(), ref("Prod/GitHub/deploy").WithField(sel))
		if err != nil {
			t.Errorf("Read #%s: %v", sel, err)
			continue
		}
		if v, ok := s.Field(sel); !ok || plain(t, v) != want || len(s.Fields) != 1 {
			t.Errorf("Read #%s: wrong field", sel)
		}
		s.Wipe()
	}
	for sel, kind := range map[string]error{
		"token":      stores.ErrInvalidRef, // in API and Backup
		"nope":       stores.ErrNotFound,
		"API/nope":   stores.ErrNotFound,
		"API/unused": stores.ErrNotFound, // a field without a value
	} {
		_, err := a.Read(t.Context(), ref("Prod/GitHub/deploy").WithField(sel))
		if !errors.Is(err, kind) {
			t.Errorf("Read #%s: %v, want %v", sel, err, kind)
		}
		noLeak(t, "field error", err, allValues(vals)...)
	}
}

func TestDuplicateFieldNames(t *testing.T) {
	f := newFake(t)
	v := f.addVault("Dev")
	one, two := "one-"+randHex(6), "two-"+randHex(6)
	f.put(v, map[string]any{"title": "db", "category": "DATABASE", "version": 1,
		"fields": []any{
			map[string]any{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaa", "type": "CONCEALED", "label": "key", "value": one},
			map[string]any{"id": "bbbbbbbbbbbbbbbbbbbbbbbbbb", "type": "CONCEALED", "label": "key", "value": two},
		}})
	a := newAdapter(t, f, nil)
	s, err := a.Read(t.Context(), ref("Dev/db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wipe()
	if got := slices.Sorted(maps.Keys(s.Fields)); !slices.Equal(got, []string{"aaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbb"}) {
		t.Errorf("fields = %v, want both keyed by ID", got)
	}
	if _, err := a.Read(t.Context(), ref("Dev/db#key")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("ambiguous field: %v", err)
	}
}

func TestMetadataWithoutValues(t *testing.T) {
	f := newFake(t)
	_, vals := seedFixture(t, f)
	a := newAdapter(t, f, nil)
	s, err := a.Read(t.Context(), ref("Prod/GitHub/deploy"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	before := f.gets()
	m, err := a.ReadMetadata(t.Context(), ref("Prod/GitHub/deploy#password"))
	if err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}
	if !maps.Equal(m.Labels, s.Meta.Labels) || m.Version != s.Meta.Version || m.Ref.Field != "" {
		t.Errorf("ReadMetadata = %+v, want the labels and version Read reports", m)
	}
	ls, err := a.List(t.Context(), ref("Prod"))
	if err != nil || len(ls) != 1 {
		t.Fatalf("List: %v %v", ls, err)
	}
	if !maps.Equal(ls[0].Labels, s.Meta.Labels) || ls[0].Ref.Path != "Prod/GitHub/deploy" {
		t.Errorf("List = %+v, want the labels Read reports", ls[0])
	}
	// By item ID too, which the listing resolves.
	if _, err := a.ReadMetadata(t.Context(), ref("Prod/p7eflcy7f5mk7vg6zrzf5rjjyu")); err != nil {
		t.Errorf("ReadMetadata by ID: %v", err)
	}
	if got := f.gets(); got != before {
		t.Errorf("metadata lookups fetched %d full items, which hold values", got-before)
	}
	noLeak(t, "metadata", m, allValues(vals)...)
	if _, err := a.ReadMetadata(t.Context(), ref("Prod/absent")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("ReadMetadata of a missing item: %v", err)
	}
	f.setDown(true)
	if _, err := a.ReadMetadata(t.Context(), ref("Prod/GitHub/deploy")); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("ReadMetadata during an outage: %v", err)
	}
}

func TestAddressByID(t *testing.T) {
	f := newFake(t)
	_, vals := seedFixture(t, f)
	a := newAdapter(t, f, nil)
	s, err := a.Read(t.Context(), ref("ionaiwtdvgclrixbt6ztpqcxnq/p7eflcy7f5mk7vg6zrzf5rjjyu#password"))
	if err != nil {
		t.Fatalf("Read by IDs: %v", err)
	}
	if v, _ := s.Field("password"); plain(t, v) != vals["password"] {
		t.Errorf("wrong value")
	}
	if s.Meta.Labels["onepassword.vault"] != "Prod" {
		t.Errorf("vault label = %q", s.Meta.Labels["onepassword.vault"])
	}
	s.Wipe()
	if _, err := a.Read(t.Context(), ref("Prod/zzzzzzzzzzzzzzzzzzzzzzzzzz")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("unknown item ID: %v", err)
	}
	if _, err := a.Read(t.Context(), ref("Nope/x")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("unknown vault: %v", err)
	}
}

func TestAmbiguousAndOddTitles(t *testing.T) {
	f := newFake(t)
	v := f.addVault("Dev")
	id1 := f.put(v, map[string]any{"title": "twin", "category": "PASSWORD", "version": 1})
	id2 := f.put(v, map[string]any{"title": "twin", "category": "PASSWORD", "version": 1})
	id3 := f.put(v, map[string]any{"title": "odd#title", "category": "PASSWORD", "version": 1})
	f.put(v, map[string]any{"title": "plain", "category": "PASSWORD", "version": 1})
	a := newAdapter(t, f, nil)
	if _, err := a.Read(t.Context(), ref("Dev/twin")); !errors.Is(err, stores.ErrInvalidRef) || !strings.Contains(err.Error(), "use the item ID") {
		t.Errorf("Read of a shared title: %v", err)
	}
	ls, err := a.List(t.Context(), ref("Dev"))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, m := range ls {
		paths = append(paths, m.Ref.Path)
		if _, err := stores.ParseRef(m.Ref.String()); err != nil {
			t.Errorf("List returned an unparseable reference %s", m.Ref)
		}
	}
	slices.Sort(paths)
	want := []string{"Dev/" + id1, "Dev/" + id2, "Dev/" + id3, "Dev/plain"}
	slices.Sort(want)
	if !slices.Equal(paths, want) {
		t.Errorf("List = %v, want %v", paths, want)
	}
}

func TestListGlob(t *testing.T) {
	f := newFake(t)
	v := f.addVault("Dev")
	for _, title := range []string{"app/a", "app/b/c", "app-x", "apple", "other"} {
		f.put(v, map[string]any{"title": title, "category": "PASSWORD", "version": 1})
	}
	a := newAdapter(t, f, nil)
	for prefix, want := range map[string][]string{
		"Dev":       {"Dev/app-x", "Dev/app/a", "Dev/app/b/c", "Dev/apple", "Dev/other"},
		"Dev/*":     {"Dev/app-x", "Dev/app/a", "Dev/app/b/c", "Dev/apple", "Dev/other"},
		"Dev/app":   {"Dev/app/a", "Dev/app/b/c"},
		"Dev/app/*": {"Dev/app/a", "Dev/app/b/c"},
		"Dev/app*":  {"Dev/app-x", "Dev/app/a", "Dev/app/b/c", "Dev/apple"},
	} {
		ls, err := a.List(t.Context(), ref(prefix))
		if err != nil {
			t.Fatalf("List %s: %v", prefix, err)
		}
		var got []string
		for _, m := range ls {
			got = append(got, m.Ref.Path)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("List %s = %v, want %v", prefix, got, want)
		}
	}
}

func TestWriteKeepsTheRestOfTheItem(t *testing.T) {
	f := newFake(t)
	v, vals := seedFixture(t, f)
	a := newAdapter(t, f, nil)
	pw, extra := "rotated-"+randHex(8), "extra-"+randHex(8)
	m, err := a.Write(t.Context(), ref("Prod/GitHub/deploy"), map[string]secret.Value{
		"password":  secret.FromString(pw),
		"API/token": secret.FromString(pw + "-api"),
		"Extra/key": secret.FromString(extra),
	}, stores.WriteOptions{})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if m.Version != "4" {
		t.Errorf("version after write = %q, want 4", m.Version)
	}
	noLeak(t, "write metadata", m, pw, extra)
	s, err := a.Read(t.Context(), ref("Prod/GitHub/deploy"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wipe()
	for k, want := range map[string]string{
		"password": pw, "API/token": pw + "-api", "Extra/key": extra,
		"username": vals["username"], "Backup/token": vals["backup-token"], "notesPlain": vals["notes"],
	} {
		if got, ok := s.Field(k); !ok || plain(t, got) != want {
			t.Errorf("after write, field %s is wrong", k)
		}
	}
	f.mu.Lock()
	it := v.items["p7eflcy7f5mk7vg6zrzf5rjjyu"]
	files, _ := it["files"].([]any)
	tags, _ := it["tags"].([]any)
	var pwType string
	for _, x := range it["fields"].([]any) {
		fm := x.(map[string]any)
		if fm["id"] == "password" {
			pwType, _ = fm["purpose"].(string)
		}
	}
	f.mu.Unlock()
	if len(files) != 1 || len(tags) != 2 || pwType != "PASSWORD" {
		t.Errorf("write dropped files (%d), tags (%d) or the password purpose (%q)", len(files), len(tags), pwType)
	}
	_, err = a.Write(t.Context(), ref("Prod/GitHub/deploy"), map[string]secret.Value{"token": secret.FromString(pw)}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("write to an ambiguous field: %v", err)
	}
}

func TestWriteNewItem(t *testing.T) {
	f := newFake(t)
	v := f.addVault("Dev")
	a := newAdapter(t, f, map[string]any{"write.category": "PASSWORD"})
	val := "new-" + randHex(8)
	m, err := a.Write(t.Context(), ref("Dev/svc/api"), map[string]secret.Value{"creds/key": secret.FromString(val)}, stores.WriteOptions{CreateOnly: true})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if m.Labels["onepassword.category"] != "PASSWORD" || !slices.Equal(m.Fields, []string{"creds/key"}) {
		t.Errorf("metadata = %+v", m)
	}
	f.mu.Lock()
	var it map[string]any
	for _, x := range v.items {
		it = x
	}
	f.mu.Unlock()
	if it["title"] != "svc/api" || it["category"] != "PASSWORD" {
		t.Errorf("created %v", it)
	}
	fm := it["fields"].([]any)[0].(map[string]any)
	if fm["type"] != "CONCEALED" || fm["label"] != "key" {
		t.Errorf("field = %v", fm)
	}
	if _, err := a.Write(t.Context(), ref("Nope/x"), map[string]secret.Value{"k": secret.FromString(val)}, stores.WriteOptions{}); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("write into a missing vault: %v", err)
	}
}

func TestWriteRefusals(t *testing.T) {
	f := newFake(t)
	f.addVault("Dev")
	a := newAdapter(t, f, nil)
	val := secret.FromString("v-" + randHex(8))
	cases := map[string]struct {
		r      stores.Ref
		fields map[string]secret.Value
		opts   stores.WriteOptions
		kind   error
	}{
		"labels":       {ref("Dev/x"), map[string]secret.Value{"k": val}, stores.WriteOptions{Labels: map[string]string{"scrim.hosts": "a"}}, stores.ErrUnsupported},
		"invalid utf8": {ref("Dev/x"), map[string]secret.Value{"k": secret.New([]byte{0xff, 0xfe})}, stores.WriteOptions{}, stores.ErrUnsupported},
		"no fields":    {ref("Dev/x"), nil, stores.WriteOptions{}, stores.ErrInvalidRef},
		"bad name":     {ref("Dev/x"), map[string]secret.Value{"a/b/c": val}, stores.WriteOptions{}, stores.ErrInvalidRef},
		"no item":      {ref("Dev"), map[string]secret.Value{"k": val}, stores.WriteOptions{}, stores.ErrInvalidRef},
		"selector":     {stores.Ref{Scheme: "op", Path: "Dev/x", Selectors: "version=1"}, map[string]secret.Value{"k": val}, stores.WriteOptions{}, stores.ErrInvalidRef},
	}
	for name, tc := range cases {
		_, err := a.Write(t.Context(), tc.r, tc.fields, tc.opts)
		if !errors.Is(err, tc.kind) {
			t.Errorf("%s: %v, want %v", name, err, tc.kind)
		}
	}
	if n := slices.IndexFunc(f.requestLog(), func(s string) bool { return strings.HasPrefix(s, "POST") || strings.HasPrefix(s, "PUT") }); n >= 0 {
		t.Errorf("a refused write reached Connect")
	}
	if val.Wiped() {
		t.Errorf("a refused write wiped the caller's value")
	}
}

func TestStoreEchoWithheld(t *testing.T) {
	f := newFake(t)
	f.addVault("Dev")
	a := newAdapter(t, f, nil)
	val := "echo-" + randHex(8)
	f.mu.Lock()
	f.echo = true
	f.mu.Unlock()
	_, err := a.Write(t.Context(), ref("Dev/x"), map[string]secret.Value{"k": secret.FromString(val)}, stores.WriteOptions{})
	if err == nil {
		t.Fatal("write succeeded against an echoing server")
	}
	noLeak(t, "write error", err, val)
	if !strings.Contains(err.Error(), "withheld") {
		t.Errorf("error %q does not say the message was withheld", err)
	}
}

func TestTokenHandling(t *testing.T) {
	f := newFake(t)
	f.addVault("Dev")
	tokens := map[string]string{"env:OP_CONNECT_TOKEN": "wrong-" + randHex(8)}
	ad, err := New(t.Context(), instance(f.srv.URL, tokens, nil))
	if err != nil {
		t.Fatal(err)
	}
	a := ad.(*Adapter)
	defer func() { _ = a.Close() }()
	err = a.Health(t.Context())
	if !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Health with a wrong token: %v", err)
	}
	noLeak(t, "token error", err, tokens["env:OP_CONNECT_TOKEN"], f.token)
	// A rotated token is picked up after the next 401.
	tokens["env:OP_CONNECT_TOKEN"] = f.token
	if err := a.Health(t.Context()); err != nil {
		t.Errorf("Health after the token was fixed: %v", err)
	}
	creds := a.Credentials()
	if len(creds) != 1 || plain(t, creds[0]) != f.token {
		t.Errorf("Credentials does not report the token")
	}
	for _, c := range creds {
		c.Wipe()
	}
	if err := a.Close(); err != nil || len(a.Credentials()) != 0 {
		t.Errorf("Close kept the token")
	}
}

func TestVaultScope(t *testing.T) {
	f := newFake(t)
	h := f.addVault("Hidden")
	h.Hidden = true
	a := newAdapter(t, f, nil)
	if _, err := a.Read(t.Context(), ref(h.ID+"/x")); !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Read in a vault outside the token's scope: %v", err)
	}
	if _, err := a.Read(t.Context(), ref("Hidden/x")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("Read by name of a vault outside the scope: %v", err)
	}
}

func TestSelectorsRefused(t *testing.T) {
	f := newFake(t)
	seedFixture(t, f)
	a := newAdapter(t, f, nil)
	r := ref("Prod/GitHub/deploy")
	r.Selectors = "version=2"
	if _, err := a.Read(t.Context(), r); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("Read with a version selector: %v", err)
	}
	if len(f.requestLog()) != 0 {
		t.Errorf("a refused selector reached Connect")
	}
}

func TestWriteLabels(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	got := a.WriteLabels(ref("Prod/svc/api#key"))
	for k, v := range map[string]string{"onepassword.vault": "Prod", "onepassword.item": "svc/api", "onepassword.category": "API_CREDENTIAL"} {
		if got[k] != v {
			t.Errorf("WriteLabels[%s] = %q, want %q", k, got[k], v)
		}
	}
	if len(f.requestLog()) != 0 {
		t.Errorf("WriteLabels contacted Connect")
	}
	// Once the vault is known, its ID is reported too.
	seedFixture(t, f)
	if _, err := a.ReadMetadata(t.Context(), ref("Prod/GitHub/deploy")); err != nil {
		t.Fatal(err)
	}
	if got := a.WriteLabels(ref("Prod/new")); got["onepassword.vault-id"] != "ionaiwtdvgclrixbt6ztpqcxnq" {
		t.Errorf("WriteLabels after a lookup = %v", got)
	}
}

func TestWatchStartsDuringOutage(t *testing.T) {
	f := newFake(t)
	v := f.addVault("Dev")
	a := newAdapter(t, f, map[string]any{"watch.interval": "20ms", "watch.max-backoff": "50ms"})
	f.setDown(true)
	ch, err := a.Watch(t.Context(), ref("Dev"))
	if err != nil {
		t.Fatalf("Watch during an outage: %v", err)
	}
	f.put(v, map[string]any{"title": "late", "category": "PASSWORD", "version": 1})
	f.setDown(false)
	select {
	case c := <-ch:
		if c.Ref.Path != "Dev/late" || c.Kind != stores.Changed {
			t.Errorf("change = %+v", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no change after the store came back")
	}
}
