// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// escapeKV serves KV v2 secrets by their decoded path, as OpenBao does, and
// records every request URI as sent on the wire.
type escapeKV struct {
	t       *testing.T
	value   string
	secrets map[string]bool // decoded path under kv/, e.g. "git hub/tok"
	mu      sync.Mutex
	uris    []string
}

func (f *escapeKV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.uris = append(f.uris, r.Method+" "+r.RequestURI)
	f.mu.Unlock()
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/v1/sys/"):
		writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
	case strings.HasPrefix(p, "/v1/kv/data/"):
		name := strings.TrimPrefix(p, "/v1/kv/data/")
		if r.Method == http.MethodPost {
			writeJSON(w, 200, map[string]any{"data": map[string]any{"version": 1, "created_time": "2026-04-01T00:00:00Z"}})
			return
		}
		if !f.secrets[name] {
			writeJSON(w, 404, map[string]any{"errors": []string{}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"data":     map[string]any{"token": f.value},
			"metadata": map[string]any{"version": 1, "created_time": "2026-03-01T00:00:00Z", "deletion_time": "", "destroyed": false},
		}})
	case strings.HasPrefix(p, "/v1/kv/metadata/"):
		if !f.secrets[strings.TrimPrefix(p, "/v1/kv/metadata/")] {
			writeJSON(w, 404, map[string]any{"errors": []string{}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"created_time": "2026-03-01T00:00:00Z", "updated_time": "2026-03-01T00:00:00Z", "current_version": 1,
			"versions": map[string]any{"1": map[string]any{"created_time": "2026-03-01T00:00:00Z", "deletion_time": "", "destroyed": false}},
		}})
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.RequestURI)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *escapeKV) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.uris
	f.uris = nil
	return out
}

func newEscapeKV(t *testing.T, names ...string) (*escapeKV, *Adapter, *bytes.Buffer) {
	t.Helper()
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	f := &escapeKV{t: t, value: "v-" + hex.EncodeToString(b), secrets: map[string]bool{}}
	for _, n := range names {
		f.secrets[n] = true
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	a := newTest(t, srv, map[string]any{"labels.lookups": false}, nil)
	var logs bytes.Buffer
	a.c.Log = slog.New(slog.NewTextHandler(&logs, nil))
	return f, a, &logs
}

// TestPathEscapedOnce: a path with characters that need escaping reaches
// OpenBao escaped once, on every kind of request.
func TestPathEscapedOnce(t *testing.T) {
	f, a, _ := newEscapeKV(t, "git hub/to%ken")
	ref := stores.Ref{Scheme: "bao", Path: "kv/git hub/to%ken"}
	ctx := t.Context()

	s, err := a.Read(ctx, ref)
	if err != nil {
		t.Fatalf("Read: %v (requests %v)", err, f.take())
	}
	s.Wipe()
	if got, want := f.take(), []string{"GET /v1/kv/data/git%20hub/to%25ken"}; !equal(got, want) {
		t.Errorf("Read sent %v, want %v", got, want)
	}

	if _, err := a.ReadMetadata(ctx, ref); err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}
	if got, want := f.take(), []string{"GET /v1/kv/metadata/git%20hub/to%25ken"}; !equal(got, want) {
		t.Errorf("ReadMetadata sent %v, want %v", got, want)
	}

	if _, err := a.Write(ctx, ref, map[string]secret.Value{"token": secret.FromString(f.value)}, stores.WriteOptions{}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := f.take(), []string{"POST /v1/kv/data/git%20hub/to%25ken"}; !equal(got, want) {
		t.Errorf("Write sent %v, want %v", got, want)
	}
}

// TestLegacyDoubleEscapedName: a secret stored under the name earlier
// releases produced ("git%20hub", OpenBao's decoding of "git%2520hub") is
// still found when the correct name does not exist, with one warning that
// names the paths and no value.
func TestLegacyDoubleEscapedName(t *testing.T) {
	f, a, logs := newEscapeKV(t, "git%20hub/tok")
	ref := stores.Ref{Scheme: "bao", Path: "kv/git hub/tok"}
	ctx := t.Context()
	for range 2 {
		s, err := a.Read(ctx, ref)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if v, ok := s.Field("token"); !ok || v.IsZero() {
			t.Fatal("value missing")
		}
		if s.Meta.Labels["openbao.path"] != "git hub/tok" {
			t.Errorf("openbao.path = %q, want the reference's path", s.Meta.Labels["openbao.path"])
		}
		s.Wipe()
	}
	if got, want := f.take(), []string{
		"GET /v1/kv/data/git%20hub/tok", "GET /v1/kv/data/git%2520hub/tok",
		"GET /v1/kv/data/git%20hub/tok", "GET /v1/kv/data/git%2520hub/tok",
	}; !equal(got, want) {
		t.Errorf("sent %v, want %v", got, want)
	}
	m, err := a.ReadMetadata(ctx, ref)
	if err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}
	if m.Version != "1" {
		t.Errorf("ReadMetadata version %q", m.Version)
	}
	if got, want := f.take(), []string{"GET /v1/kv/metadata/git%20hub/tok", "GET /v1/kv/metadata/git%2520hub/tok"}; !equal(got, want) {
		t.Errorf("ReadMetadata sent %v, want %v", got, want)
	}
	out := logs.String()
	if n := strings.Count(out, "level=WARN"); n != 1 {
		t.Errorf("got %d warnings, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "git%20hub/tok") || strings.Contains(out, f.value) {
		t.Errorf("warning does not name the legacy path or carries the value:\n%s", out)
	}

	// Once the secret exists under its correct name, that one is used.
	f.secrets["git hub/tok"] = true
	s, err := a.Read(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	if got, want := f.take(), []string{"GET /v1/kv/data/git%20hub/tok"}; !equal(got, want) {
		t.Errorf("sent %v, want %v", got, want)
	}
}

// TestNoLegacyLookupWithoutEscapes: a path that needs no escaping was never
// affected, so a miss is a plain miss.
func TestNoLegacyLookupWithoutEscapes(t *testing.T) {
	f, a, _ := newEscapeKV(t)
	_, err := a.Read(t.Context(), stores.Ref{Scheme: "bao", Path: "kv/github/tok"})
	if !errors.Is(err, stores.ErrNotFound) {
		t.Fatalf("Read: %v, want not found", err)
	}
	if got := f.take(); len(got) != 1 {
		t.Errorf("sent %v, want one request", got)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
