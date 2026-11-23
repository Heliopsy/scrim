// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// fakeKV serves one secret, prod/eu/db under mount kv-prod, with its full
// metadata and mount information. Setting deny refuses metadata/ and sys/.
type fakeKV struct {
	t         *testing.T
	value     string
	custom    map[string]string
	deny      bool
	deletion  string
	sysCalls  atomic.Int32
	metaCalls atomic.Int32
	dataCalls atomic.Int32
	// metaStatus, when set, is the status of every metadata/ GET.
	metaStatus int
	logins     atomic.Int32
}

func (f *fakeKV) meta() map[string]any {
	return map[string]any{
		"created_time": "2026-01-01T00:00:00Z", "updated_time": "2026-03-01T00:00:00Z",
		"current_version": 3, "oldest_version": 1, "max_versions": 5, "cas_required": true,
		"delete_version_after": "720h0m0s", "custom_metadata": f.custom,
		"versions": map[string]any{
			"1": map[string]any{"created_time": "2026-01-01T00:00:00Z", "deletion_time": "", "destroyed": true},
			"2": map[string]any{"created_time": "2026-02-01T00:00:00Z", "deletion_time": "2026-02-02T00:00:00Z", "destroyed": false},
			"3": map[string]any{"created_time": "2026-03-01T00:00:00Z", "deletion_time": f.deletion, "destroyed": false},
		},
	}
}

func (f *fakeKV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	denied := func() {
		writeJSON(w, 403, map[string]any{"errors": []string{"1 error occurred:\n\t* permission denied\n\n"}})
	}
	switch {
	case p == "/v1/auth/approle/login":
		f.logins.Add(1)
		writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": "tok-login", "lease_duration": 3600, "renewable": true}})
	case strings.HasPrefix(p, "/v1/sys/"):
		f.sysCalls.Add(1)
		if f.deny || p != "/v1/sys/internal/ui/mounts/kv-prod" {
			denied()
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"type": "kv", "path": "kv-prod/", "description": "Production, team Payments", "accessor": "kv_1234",
			"local": false, "seal_wrap": true, "options": map[string]string{"version": "2"},
			"config": map[string]any{"default_lease_ttl": 0, "listing_visibility": "hidden", "audit_non_hmac_request_keys": []string{"a", "b"}},
		}})
	case p == "/v1/kv-prod/data/prod/eu/db":
		f.dataCalls.Add(1)
		if r.Method == http.MethodPost {
			writeJSON(w, 200, map[string]any{"data": map[string]any{"version": 4, "created_time": "2026-04-01T00:00:00Z"}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"data": map[string]any{"password": f.value},
			"metadata": map[string]any{"version": 3, "created_time": "2026-03-01T00:00:00Z", "custom_metadata": f.custom,
				"deletion_time": f.deletion, "destroyed": false},
		}})
	case p == "/v1/kv-prod/metadata/prod/eu/db":
		f.metaCalls.Add(1)
		if f.deny && r.Method == http.MethodGet {
			denied()
			return
		}
		if f.metaStatus != 0 && r.Method == http.MethodGet {
			writeJSON(w, f.metaStatus, map[string]any{"errors": []string{"boom"}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": f.meta()})
	case r.Method == "LIST" && p == "/v1/kv-prod/detailed-metadata/prod/":
		writeJSON(w, 200, map[string]any{"data": map[string]any{"keys": []string{"eu/"}}})
	case r.Method == "LIST" && p == "/v1/kv-prod/detailed-metadata/prod/eu/":
		writeJSON(w, 200, map[string]any{"data": map[string]any{"keys": []string{"db"}, "key_info": map[string]any{"db": f.meta()}}})
	default:
		f.t.Errorf("unexpected %s %s", r.Method, p)
		w.WriteHeader(http.StatusNotFound)
	}
}

func newFakeKV(t *testing.T) (*fakeKV, *httptest.Server) {
	t.Helper()
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	f := &fakeKV{t: t, value: "v-" + hex.EncodeToString(b), custom: map[string]string{
		"scrim.hosts": "api.example.test", "team": "payments", "Cost Center": "42",
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// wantLabels checks every key in want, where "" means the key must be absent.
func wantLabels(t *testing.T, where string, got, want map[string]string) {
	t.Helper()
	for k, v := range want {
		g, ok := got[k]
		switch {
		case v == "" && ok:
			t.Errorf("%s: label %s = %q, want it absent", where, k, g)
		case v != "" && g != v:
			t.Errorf("%s: label %s = %q, want %q", where, k, g, v)
		}
	}
}

// fullLabels is what a token that may read everything sees for prod/eu/db.
var fullLabels = map[string]string{
	"openbao.mount": "kv-prod", "openbao.engine": "kv-v2",
	"openbao.namespace": "team-a/eu", "openbao.namespaces": "team-a,team-a/eu",
	"openbao.namespaces.team-a": "true", "openbao.namespaces.team-a/eu": "true",
	"openbao.path": "prod/eu/db", "openbao.name": "db", "openbao.folder": "prod/eu",
	"openbao.ancestors": "prod,prod/eu", "openbao.ancestors.prod": "true", "openbao.ancestors.prod/eu": "true",
	"openbao.ancestors.prod/eu/db": "", "openbao.segments": "prod,eu,db", "openbao.segments.eu": "true",
	"openbao.mount_type": "kv", "openbao.mount_version": "2", "openbao.mount_option.version": "2",
	"openbao.mount_description": "Production, team Payments", "openbao.mount_accessor": "kv_1234",
	"openbao.mount_local": "false", "openbao.mount_seal_wrap": "true",
	"openbao.mount_config.default_lease_ttl": "0", "openbao.mount_config.listing_visibility": "hidden",
	"openbao.mount_config.audit_non_hmac_request_keys": "a,b",
	"openbao.version": "3", "openbao.current_version": "3", "openbao.oldest_version": "1",
	"openbao.max_versions": "5", "openbao.cas_required": "true", "openbao.delete_version_after": "720h0m0s",
	"openbao.created_time": "2026-01-01T00:00:00Z", "openbao.updated_time": "2026-03-01T00:00:00Z",
	"openbao.version_created_time": "2026-03-01T00:00:00Z", "openbao.destroyed": "false",
	"openbao.deletion_time": "", "openbao.versions": "3", "openbao.deleted_versions": "1",
	"openbao.destroyed_versions": "1",
	"openbao.meta.team":          "payments", "openbao.meta.scrim.hosts": "api.example.test",
	"openbao.meta.cost_center": "42", "scrim.hosts": "api.example.test", "team": "payments",
}

func TestNativeLabelsOnReadAndList(t *testing.T) {
	_, srv := newFakeKV(t)
	a := newTest(t, srv, map[string]any{"namespace": "team-a/eu"}, nil)
	s, err := a.Read(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	wantLabels(t, "Read", s.Meta.Labels, fullLabels)
	if s.Meta.CreatedAt.Month() != time.January {
		t.Errorf("CreatedAt %s, want the secret's creation from its metadata", s.Meta.CreatedAt)
	}
	ms, err := a.List(t.Context(), stores.MustParseRef("bao://kv-prod/prod"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("list %+v", ms)
	}
	wantLabels(t, "List", ms[0].Labels, fullLabels)
}

func TestCustomMetadataCannotForgeNativeLabels(t *testing.T) {
	f, srv := newFakeKV(t)
	f.custom = map[string]string{
		"openbao.mount": "kv-dev", "OpenBao.Path": "dev/x", "openbao.meta.team": "forged",
		"openbao.ancestors.dev": "true", "team": "payments", "TEAM": "shouty", "store.name": "forged",
	}
	a := newTest(t, srv, nil, nil)
	s, err := a.Read(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	ms, err := a.List(t.Context(), stores.MustParseRef("bao://kv-prod/prod"))
	if err != nil {
		t.Fatal(err)
	}
	for where, got := range map[string]map[string]string{"Read": s.Meta.Labels, "List": ms[0].Labels} {
		wantLabels(t, where, got, map[string]string{
			"openbao.mount": "kv-prod", "openbao.path": "prod/eu/db", "OpenBao.Path": "",
			"openbao.ancestors.dev": "", "store.name": "", "openbao.meta.store.name": "forged",
			// TEAM sorts before team; the first key that folds to a name wins.
			"openbao.meta.team":          "shouty",
			"openbao.meta.openbao.mount": "kv-dev", "openbao.meta.openbao.meta.team": "forged",
			"openbao.meta.openbao.ancestors.dev": "true", "team": "payments", "TEAM": "shouty",
		})
	}
}

func TestForbiddenLabelLookupsDegrade(t *testing.T) {
	f, srv := newFakeKV(t)
	f.deny = true
	a := newTest(t, srv, map[string]any{"auth.method": "approle", "token": nil, "role-id": "test:r", "secret-id": "test:s"},
		map[string]string{"test:r": "r", "test:s": "s"})
	for range 2 {
		s, err := a.Read(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db"))
		if err != nil {
			t.Fatalf("read failed because an optional lookup was refused: %v", err)
		}
		if v, ok := s.Field("password"); !ok || v.IsZero() {
			t.Error("value missing")
		}
		s.Wipe()
		wantLabels(t, "Read", s.Meta.Labels, map[string]string{
			"openbao.mount": "kv-prod", "openbao.engine": "kv-v2", "openbao.path": "prod/eu/db",
			"openbao.ancestors.prod": "true", "openbao.version": "3", "openbao.destroyed": "false",
			"openbao.version_created_time": "2026-03-01T00:00:00Z", "openbao.meta.team": "payments",
			"scrim.hosts":             "api.example.test",
			"openbao.current_version": "", "openbao.max_versions": "", "openbao.mount_type": "",
			"openbao.mount_description": "",
		})
	}
	if n := f.logins.Load(); n != 1 {
		t.Errorf("logged in %d times; a refused label lookup must not force a new login", n)
	}
	// Both sys/ endpoints are tried once, then the refusal is cached.
	if n := f.sysCalls.Load(); n != 2 {
		t.Errorf("mount lookups = %d, want 2 (cached after the first read)", n)
	}
}

func TestLabelLookupsCanBeTurnedOff(t *testing.T) {
	f, srv := newFakeKV(t)
	a := newTest(t, srv, map[string]any{"labels": map[string]any{"lookups": false}}, nil)
	s, err := a.Read(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	if f.sysCalls.Load() != 0 || f.metaCalls.Load() != 0 {
		t.Errorf("lookups made: sys %d, metadata %d", f.sysCalls.Load(), f.metaCalls.Load())
	}
	wantLabels(t, "Read", s.Meta.Labels, map[string]string{"openbao.mount": "kv-prod", "openbao.ancestors.prod/eu": "true", "openbao.current_version": ""})
}

func TestNoValueInLabels(t *testing.T) {
	f, srv := newFakeKV(t)
	a := newTest(t, srv, nil, nil)
	check := func(where string, l map[string]string) {
		t.Helper()
		if len(l) == 0 {
			t.Fatalf("%s: no labels", where)
		}
		for k, v := range l {
			if strings.Contains(k, f.value) || strings.Contains(v, f.value) {
				t.Errorf("%s: label %q carries the value", where, k)
			}
		}
	}
	s, err := a.Read(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	check("Read", s.Meta.Labels)
	ms, err := a.List(t.Context(), stores.MustParseRef("bao://kv-prod/prod"))
	if err != nil {
		t.Fatal(err)
	}
	check("List", ms[0].Labels)
	m, err := a.Write(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db"),
		map[string]secret.Value{"password": secret.FromString(f.value)}, stores.WriteOptions{Labels: map[string]string{"team": "payments"}})
	if err != nil {
		t.Fatal(err)
	}
	check("Write", m.Labels)
	wantLabels(t, "Write", m.Labels, map[string]string{
		"openbao.version": "4", "openbao.version_created_time": "2026-04-01T00:00:00Z", "openbao.meta.team": "payments",
		"openbao.mount_type": "kv", "openbao.ancestors.prod/eu": "true",
	})
	check("WriteLabels", a.WriteLabels(stores.MustParseRef("bao://kv-prod/prod/eu/db")))
}

func TestWriteLabelsMakesNoRequest(t *testing.T) {
	f, srv := newFakeKV(t)
	a := newTest(t, srv, map[string]any{"mounts": "teams/kv"}, nil)
	l := a.WriteLabels(stores.MustParseRef("bao://teams/kv/prod/new#token"))
	wantLabels(t, "WriteLabels", l, map[string]string{
		"openbao.mount": "teams/kv", "openbao.path": "prod/new", "openbao.ancestors": "prod",
		"openbao.ancestors.prod": "true", "openbao.engine": "kv-v2", "openbao.version": "",
	})
	if f.sysCalls.Load() != 0 {
		t.Error("WriteLabels contacted the store")
	}
}

func TestScheduledDeletionIsStillReadable(t *testing.T) {
	f, srv := newFakeKV(t)
	a := newTest(t, srv, nil, nil)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	a.c.Now = func() time.Time { return now }
	f.deletion = now.Add(time.Hour).Format(time.RFC3339)
	s, err := a.Read(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db"))
	if err != nil {
		t.Fatalf("version with a deletion time still to come: %v", err)
	}
	s.Wipe()
	wantLabels(t, "Read", s.Meta.Labels, map[string]string{"openbao.deletion_time": f.deletion})
	if ms, err := a.List(t.Context(), stores.MustParseRef("bao://kv-prod/prod")); err != nil || len(ms) != 1 {
		t.Errorf("list with a scheduled deletion: %v %v", ms, err)
	}
	f.deletion = now.Add(-time.Hour).Format(time.RFC3339)
	if _, err := a.Read(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("version deleted an hour ago: %v", err)
	}
	if ms, err := a.List(t.Context(), stores.MustParseRef("bao://kv-prod/prod")); err != nil || len(ms) != 0 {
		t.Errorf("list with a past deletion: %v %v", ms, err)
	}
}

func TestMountInfoIsCached(t *testing.T) {
	f, srv := newFakeKV(t)
	a := newTest(t, srv, nil, nil)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	a.c.Now = func() time.Time { return now }
	for range 3 {
		s, err := a.Read(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db"))
		if err != nil {
			t.Fatal(err)
		}
		s.Wipe()
	}
	if n := f.sysCalls.Load(); n != 1 {
		t.Errorf("mount looked up %d times, want once", n)
	}
	now = now.Add(mountTTL)
	s, _ := a.Read(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db"))
	s.Wipe()
	if n := f.sysCalls.Load(); n != 2 {
		t.Errorf("mount looked up %d times after the TTL, want twice", n)
	}
}

func TestLabelKeyAndLists(t *testing.T) {
	for in, want := range map[string]string{
		"Team": "team", "cost center": "cost_center", "a/b.c-d_e": "a_b.c-d_e", "Zürich": "z_rich",
		"x:y=z": "x_y_z", "..a..b.": "a.b", "...": "",
	} {
		if got := stores.LabelKey(in); got != want {
			t.Errorf("stores.LabelKey(%q) = %q, want %q", in, got, want)
		}
	}
	l := map[string]string{}
	setNative(l, "ancestors", ancestors("a/B/c")...)
	want := map[string]string{"openbao.ancestors": "a,a/B", "openbao.ancestors.a": "true", "openbao.ancestors.a/B": "true"}
	if fmt.Sprint(l) != fmt.Sprint(want) {
		t.Errorf("list labels %v, want %v", l, want)
	}
	l = map[string]string{}
	setNative(l, "ancestors", ancestors("top")...)
	if len(l) != 0 {
		t.Errorf("a top-level secret has no ancestors, got %v", l)
	}
	l = map[string]string{}
	setNative(l, "mount", "kv")
	setNative(l, "meta.team", "forged")
	if fmt.Sprint(l) != fmt.Sprint(map[string]string{"openbao.mount": "kv"}) {
		t.Errorf("single-valued labels %v", l)
	}
}

// TestReadMetadataMatchesRead: ReadMetadata reports what Read would, labels
// included, without asking for the data, with and without label lookups.
func TestReadMetadataMatchesRead(t *testing.T) {
	for _, opts := range []map[string]any{{"namespace": "team-a/eu"}, {"labels.lookups": false}} {
		f, srv := newFakeKV(t)
		a := newTest(t, srv, opts, nil)
		ref := stores.MustParseRef("bao://kv-prod/prod/eu/db#password")
		s, err := a.Read(t.Context(), ref.Secret())
		if err != nil {
			t.Fatal(err)
		}
		s.Wipe()
		f.dataCalls.Store(0)
		m, err := a.ReadMetadata(t.Context(), ref)
		if err != nil {
			t.Fatalf("ReadMetadata %v: %v", opts, err)
		}
		if n := f.dataCalls.Load(); n != 0 {
			t.Errorf("ReadMetadata %v asked for the data %d times", opts, n)
		}
		if fmt.Sprint(m.Labels) != fmt.Sprint(s.Meta.Labels) {
			t.Errorf("ReadMetadata %v labels\n%v\nwant Read's\n%v", opts, m.Labels, s.Meta.Labels)
		}
		if m.Ref != ref.Secret() || m.Version != s.Meta.Version || !m.CreatedAt.Equal(s.Meta.CreatedAt) || !m.UpdatedAt.Equal(s.Meta.UpdatedAt) {
			t.Errorf("ReadMetadata %v = %+v, want Read's %+v", opts, m, s.Meta)
		}
		for k, v := range m.Labels {
			if strings.Contains(k, f.value) || strings.Contains(v, f.value) {
				t.Errorf("label %q carries the value", k)
			}
		}
	}
}

// TestReadMetadataFailsLikeRead: every case Read refuses or misses,
// ReadMetadata refuses or misses the same way; a refused metadata read
// falls back to Read with its values wiped.
func TestReadMetadataFailsLikeRead(t *testing.T) {
	f, srv := newFakeKV(t)
	a := newTest(t, srv, map[string]any{"write-only-paths": []any{"kv-prod/inbox"}}, nil)
	ctx := t.Context()
	for ref, kind := range map[string]error{
		"bao://kv-prod/inbox/x":                stores.ErrPermission,
		"bao://kv-prod":                        stores.ErrInvalidRef,
		"bao://kv-prod/prod/eu/db?color=blue":  stores.ErrInvalidRef,
		"bao://kv-prod/prod/eu/db?version=abc": stores.ErrInvalidRef,
	} {
		r := stores.MustParseRef(ref)
		_, rerr := a.Read(ctx, r)
		_, merr := a.ReadMetadata(ctx, r)
		if !errors.Is(rerr, kind) || !errors.Is(merr, kind) {
			t.Errorf("%s: Read %v, ReadMetadata %v, want %v", ref, rerr, merr, kind)
		}
	}
	// The fake serves the data of version 3 whatever is asked; OpenBao
	// answers these with 404 (covered live in TestReadMetadataLive).
	for _, v := range []string{"1", "2", "9"} { // destroyed, deleted, not yet
		if _, err := a.ReadMetadata(ctx, stores.MustParseRef("bao://kv-prod/prod/eu/db?version="+v)); !errors.Is(err, stores.ErrNotFound) {
			t.Errorf("version %s: %v, want not found", v, err)
		}
	}
	if _, err := a.ReadMetadata(ctx, stores.MustParseRef("bao://kv-prod/prod/eu/db?version=3")); err != nil {
		t.Errorf("current version by selector: %v", err)
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	a.c.Now = func() time.Time { return now }
	f.deletion = now.Add(-time.Hour).Format(time.RFC3339)
	if _, err := a.ReadMetadata(ctx, stores.MustParseRef("bao://kv-prod/prod/eu/db")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("current version deleted: %v", err)
	}
	f.deletion = now.Add(time.Hour).Format(time.RFC3339)
	if _, err := a.ReadMetadata(ctx, stores.MustParseRef("bao://kv-prod/prod/eu/db")); err != nil {
		t.Errorf("scheduled deletion: %v", err)
	}
	f.deletion = ""

	// A store failure is returned, never papered over with a Read.
	f.metaStatus = http.StatusInternalServerError
	f.dataCalls.Store(0)
	if _, err := a.ReadMetadata(ctx, stores.MustParseRef("bao://kv-prod/prod/eu/db")); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("metadata 500: %v, want unavailable", err)
	}
	if f.dataCalls.Load() != 0 {
		t.Error("a failed metadata read fell back to reading the data")
	}
	f.metaStatus = 0

	// A policy without read on metadata/ gets what Read gives it.
	f.deny = true
	s, err := a.Read(ctx, stores.MustParseRef("bao://kv-prod/prod/eu/db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	m, err := a.ReadMetadata(ctx, stores.MustParseRef("bao://kv-prod/prod/eu/db"))
	if err != nil {
		t.Fatalf("ReadMetadata with metadata refused: %v", err)
	}
	if fmt.Sprint(m.Labels) != fmt.Sprint(s.Meta.Labels) {
		t.Errorf("fallback labels %v, want Read's %v", m.Labels, s.Meta.Labels)
	}
}

// TestSetMetadataUsesReadMetadata: stores.Set.Metadata goes through
// ReadMetadata, so the value is never fetched.
func TestSetMetadataUsesReadMetadata(t *testing.T) {
	f, srv := newFakeKV(t)
	a := newTest(t, srv, nil, nil)
	set := stores.NewSet()
	if err := set.Add(a); err != nil {
		t.Fatal(err)
	}
	m, exists, err := set.Metadata(t.Context(), stores.MustParseRef("bao://kv-prod/prod/eu/db#password"))
	if err != nil || !exists {
		t.Fatalf("Metadata: %v %v", exists, err)
	}
	if f.dataCalls.Load() != 0 {
		t.Error("Set.Metadata read the value")
	}
	wantLabels(t, "Set.Metadata", m.Labels, map[string]string{"openbao.mount": "kv-prod", "openbao.current_version": "3", "team": "payments"})
}
