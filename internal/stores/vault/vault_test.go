// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fake is a Vault with a KV v2 mount at secret/, a KV v1 mount at kv1/, a
// database engine at database/, JWT auth and the lease endpoints.
type fake struct {
	mu sync.Mutex
	// namespaces records the X-Vault-Namespace of each request by path.
	namespaces map[string][]string
	jwts       []string
	custom     map[string]string
	renewals   []float64
	revoked    []string
	leaseTTL   int
	renewable  bool
	renewFail  int
	sys        atomic.Int32
	issued     int
}

func newFake() *fake {
	return &fake{namespaces: map[string][]string{}, leaseTTL: 1, renewable: true}
}

func (f *fake) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	f.namespaces[p] = append(f.namespaces[p], r.Header.Get("X-Vault-Namespace"))
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch {
	case p == "auth/jwt/login":
		jwt, _ := body["jwt"].(string)
		f.jwts = append(f.jwts, jwt)
		if body["role"] != "scrim" {
			writeJSON(w, 400, map[string]any{"errors": []string{"role not found; jwt " + jwt}})
			return
		}
		writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": "hvs.jwt", "lease_duration": 3600, "renewable": true}})
	case strings.HasPrefix(p, "sys/internal/ui/mounts/"):
		f.sys.Add(1)
		rest := strings.TrimPrefix(p, "sys/internal/ui/mounts/")
		switch {
		case strings.HasPrefix(rest, "secret"):
			writeJSON(w, 200, map[string]any{"data": map[string]any{"path": "secret/", "type": "kv", "options": map[string]string{"version": "2"}}})
		case strings.HasPrefix(rest, "kv1"):
			writeJSON(w, 200, map[string]any{"data": map[string]any{"path": "kv1/", "type": "kv", "options": map[string]string{"version": "1"}}})
		case strings.HasPrefix(rest, "database"):
			writeJSON(w, 200, map[string]any{"data": map[string]any{"path": "database/", "type": "database"}})
		default:
			writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
		}
	case p == "secret/data/app/db":
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"data":     map[string]any{"password": "pw-value"},
			"metadata": map[string]any{"version": 3, "created_time": "2026-01-01T00:00:00Z", "custom_metadata": f.custom},
		}})
	case p == "secret/metadata/app/db":
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"current_version": 3, "custom_metadata": f.custom,
			"versions": map[string]any{"3": map[string]any{"created_time": "2026-01-01T00:00:00Z"}},
		}})
	case p == "kv1/app/db":
		writeJSON(w, 200, map[string]any{"data": map[string]any{"password": "pw-value"}})
	case p == "database/creds/ro":
		f.issued++
		writeJSON(w, 200, map[string]any{
			"lease_id": fmt.Sprintf("database/creds/ro/%d", f.issued), "lease_duration": f.leaseTTL, "renewable": f.renewable,
			"data": map[string]any{"username": "v-ro-1", "password": "db-secret-pw"},
		})
	case p == "sys/leases/renew":
		inc, _ := body["increment"].(float64)
		f.renewals = append(f.renewals, inc)
		if f.renewFail != 0 {
			writeJSON(w, f.renewFail, map[string]any{"errors": []string{"lease not found"}})
			return
		}
		writeJSON(w, 200, map[string]any{"lease_id": body["lease_id"], "lease_duration": int(inc), "renewable": true})
	case p == "sys/leases/revoke":
		id, _ := body["lease_id"].(string)
		f.revoked = append(f.revoked, id)
		w.WriteHeader(204)
	case p == "auth/token/lookup-self", p == "sys/health":
		writeJSON(w, 200, map[string]any{"data": map[string]any{}})
	default:
		writeJSON(w, 404, map[string]any{"errors": []string{}})
	}
}

func (f *fake) snapshot() (renewals []float64, revoked []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]float64(nil), f.renewals...), append([]string(nil), f.revoked...)
}

func newTest(t *testing.T, f *fake, extra map[string]any) *Adapter {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	opts := map[string]any{"address": srv.URL, "token": "test:token", "leases.check-interval": "50ms"}
	for k, v := range extra {
		if v == nil {
			delete(opts, k)
			continue
		}
		opts[k] = v
	}
	a, err := New(stores.Instance{
		Name: "vault", Kind: Kind, Options: opts,
		Resolve: func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
			if ref == "test:token" {
				return secret.FromString("hvs.root"), nil
			}
			return secret.Value{}, errors.New("no such reference")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func TestOptions(t *testing.T) {
	for _, c := range []struct {
		opts map[string]any
		want []string
	}{
		{map[string]any{"address": "http://v:8200", "auth.method": "jwt"}, []string{"auth.jwt.role is required", "exactly one of auth.jwt.token-file and jwt"}},
		{map[string]any{"address": "http://v:8200", "auth.method": "jwt", "auth.jwt.role": "r", "jwt": "env:J", "auth.jwt.token-file": "/t", "token": "env:T"}, []string{"exactly one of", "token is not used with auth.method jwt"}},
		{map[string]any{"address": "http://v:8200", "auth.method": "ldap"}, []string{"must be token, approle, kubernetes or jwt"}},
		{map[string]any{"address": "http://v:8200", "token": "env:T", "leases.check-interval": "0s", "leases.increment": "-1s"}, []string{"leases.check-interval must be positive", "leases.increment must not be negative"}},
		{map[string]any{"address": "http://v:8200", "token": "env:T", "kv-v1-mount": "x"}, []string{"did you mean kv-v1-mounts"}},
	} {
		_, err := ParseOptions(c.opts)
		for _, w := range c.want {
			if err == nil || !strings.Contains(err.Error(), w) {
				t.Errorf("%v: error %v, want %q", c.opts, err, w)
			}
		}
	}
	o, err := ParseOptions(map[string]any{"address": "http://v:8200/", "auth": map[string]any{"method": "jwt", "jwt": map[string]any{"role": "ci", "token-file": "/run/jwt"}}})
	if err != nil {
		t.Fatal(err)
	}
	if o.JWTMount != "jwt" || o.JWTRole != "ci" || !o.MountDetect || !o.RevokeOnClose || o.LeaseCheck != defaultLeaseCheck {
		t.Errorf("defaults: %+v", o)
	}
}

// TestNamespaceHeader: every request carries the configured namespace, and
// logins the auth namespace when one is set (an auth method mounted in a
// parent namespace).
func TestNamespaceHeader(t *testing.T) {
	f := newFake()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "jwt")
	if err := os.WriteFile(tokenFile, []byte("eyJ.first.jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newTest(t, f, map[string]any{
		"token": nil, "namespace": "team-a/eu/", "auth.namespace": "team-a",
		"auth.method": "jwt", "auth.jwt.role": "scrim", "auth.jwt.token-file": tokenFile,
	})
	s, err := a.Read(t.Context(), stores.MustParseRef("vault://secret/app/db#password"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.namespaces["auth/jwt/login"]; len(got) != 1 || got[0] != "team-a" {
		t.Errorf("login namespace %v, want team-a", got)
	}
	if got := f.namespaces["secret/data/app/db"]; len(got) != 1 || got[0] != "team-a/eu" {
		t.Errorf("read namespace %v, want team-a/eu", got)
	}
	if len(f.jwts) != 1 || f.jwts[0] != "eyJ.first.jwt" {
		t.Errorf("JWT sent %q", f.jwts)
	}
	if s.Meta.Labels["vault.namespace"] != "team-a/eu" || s.Meta.Labels["vault.namespaces.team-a"] != "true" {
		t.Errorf("labels %v", s.Meta.Labels)
	}
}

// TestJWTReadAtEveryLogin: the JWT file is read again for each login, and
// a refused login that quotes the JWT does not pass it on.
func TestJWTReadAtEveryLogin(t *testing.T) {
	f := newFake()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "jwt")
	_ = os.WriteFile(tokenFile, []byte("eyJ.one"), 0o600)
	a := newTest(t, f, map[string]any{"token": nil, "auth.method": "jwt", "auth.jwt.role": "scrim", "auth.jwt.token-file": tokenFile})
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	a.c.DropToken(a.c.TokenCopy())
	_ = os.WriteFile(tokenFile, []byte("eyJ.two"), 0o600)
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	jwts := append([]string(nil), f.jwts...)
	f.mu.Unlock()
	if strings.Join(jwts, " ") != "eyJ.one eyJ.two" {
		t.Errorf("JWTs sent %q, want the rotated one on the second login", jwts)
	}

	bad := newTest(t, f, map[string]any{"token": nil, "auth.method": "jwt", "auth.jwt.role": "other", "auth.jwt.token-file": tokenFile})
	err := bad.Health(t.Context())
	if !errors.Is(err, stores.ErrPermission) || strings.Contains(err.Error(), "eyJ.two") {
		t.Errorf("refused login: %v", err)
	}
}

func TestLocateAndLabels(t *testing.T) {
	f := newFake()
	f.custom = map[string]string{"vault.engine": "forged", "team": "payments", "scrim.hosts": "db.example.test"}
	a := newTest(t, f, nil)
	ctx := t.Context()
	s, err := a.Read(ctx, stores.MustParseRef("vault://secret/app/db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	l := s.Meta.Labels
	if l["vault.engine"] != "kv-v2" || l["vault.meta.vault.engine"] != "forged" || l["vault.meta.team"] != "payments" ||
		l["scrim.hosts"] != "db.example.test" || l["vault.version"] != "3" || l["vault.path"] != "app/db" {
		t.Errorf("KV v2 labels %v", l)
	}
	s, err = a.Read(ctx, stores.MustParseRef("vault://kv1/app/db#password"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	if s.Meta.Labels["vault.engine"] != "kv-v1" || s.Meta.Version != "" {
		t.Errorf("KV v1: %v %q", s.Meta.Labels, s.Meta.Version)
	}
	for _, l := range []map[string]string{l, s.Meta.Labels} {
		for k, v := range l {
			if strings.Contains(v, "pw-value") || strings.Contains(k, "pw-value") {
				t.Errorf("label %s holds the value", k)
			}
		}
	}
	if _, err := a.Read(ctx, stores.MustParseRef("vault://database/creds/ro")); !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("Read of a dynamic path: %v", err)
	}
	// Detection is cached per mount: three reads above, one lookup each
	// mount.
	if n := f.sys.Load(); n != 3 {
		t.Errorf("%d mount lookups, want 3", n)
	}
	before := f.sys.Load()
	wl := a.WriteLabels(stores.MustParseRef("vault://kv1/new/item#v"))
	if wl["vault.engine"] != "kv-v1" || wl["vault.mount"] != "kv1" || f.sys.Load() != before {
		t.Errorf("WriteLabels %v (lookups %d -> %d)", wl, before, f.sys.Load())
	}
}

// TestConfiguredMountsWithoutDetection: with detection off the options
// decide: kv-v1-mounts, dynamic-paths, and KV v2 for the rest.
func TestConfiguredMountsWithoutDetection(t *testing.T) {
	f := newFake()
	a := newTest(t, f, map[string]any{"mounts.detect": false, "labels.lookups": false, "kv-v1-mounts": []any{"kv1"}, "dynamic-paths": []any{"database/creds"}})
	ctx := t.Context()
	for ref, want := range map[string]engine{"secret/app/db": kv2, "kv1/app/db": kv1, "database/creds/ro": dynamic} {
		if got := a.locate(ctx, stores.Ref{}, ref); got.engine != want {
			t.Errorf("%s: engine %s, want %s", ref, got.engine, want)
		}
	}
	if f.sys.Load() != 0 {
		t.Error("looked a mount up with detection and label lookups off")
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// holder is a lease holder the test switches.
type holder struct {
	mu     sync.Mutex
	until  time.Time
	active bool
	err    error
}

func (h *holder) set(until time.Time, active bool, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.until, h.active, h.err = until, active, err
}

func (h *holder) lease(id string) stores.LeaseHolder {
	return stores.LeaseHolder{ID: id, Active: func(context.Context) (time.Time, bool, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.until, h.active, h.err
	}}
}

// TestLeaseLifecycle: renewed while the holder is active, never by more
// than the holder has left, kept without renewal past the last known end
// while the holder cannot answer, and revoked once it ends.
func TestLeaseLifecycle(t *testing.T) {
	f := newFake()
	f.leaseTTL = 1
	a := newTest(t, f, map[string]any{"leases.increment": "1h"})
	h := &holder{}
	h.set(time.Now().Add(10*time.Minute), true, nil)
	ref := stores.MustParseRef("vault://database/creds/ro")
	s, info, err := a.Issue(t.Context(), ref, h.lease("grant:1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != "database/creds/ro/1" || info.Holder != "grant:1" || !info.Renewable {
		t.Errorf("lease %+v", info)
	}
	if s.Meta.Labels["vault.engine"] != "database" || s.Meta.Labels["vault.dynamic"] != "true" || s.Meta.Labels["vault.lease_duration"] != "1" {
		t.Errorf("labels %v", s.Meta.Labels)
	}
	for k, v := range s.Meta.Labels {
		if strings.Contains(v, "db-secret-pw") {
			t.Errorf("label %s holds the password", k)
		}
	}
	s.Wipe()
	waitUntil(t, "a renewal", func() bool { r, _ := f.snapshot(); return len(r) > 0 })
	// The increment asked for is capped at what the holder has left (ten
	// minutes), not the hour configured.
	if r, _ := f.snapshot(); r[0] > 600 || r[0] < 590 {
		t.Errorf("increment %v, want at most the holder's ten minutes", r[0])
	}
	if len(a.Leases()) != 1 {
		t.Fatalf("leases %v", a.Leases())
	}

	// The holder cannot answer: nothing is revoked.
	h.set(time.Time{}, false, errors.New("state backend down"))
	time.Sleep(300 * time.Millisecond)
	if _, rev := f.snapshot(); len(rev) != 0 {
		t.Fatalf("revoked while the holder could not answer: %v", rev)
	}
	h.set(time.Now().Add(time.Hour), false, nil)
	waitUntil(t, "revocation", func() bool { _, rev := f.snapshot(); return len(rev) == 1 })
	if len(a.Leases()) != 0 {
		t.Errorf("leases after revocation %v", a.Leases())
	}
}

func TestLeaseRevokedAtHolderEnd(t *testing.T) {
	f := newFake()
	f.leaseTTL = 3600
	a := newTest(t, f, nil)
	h := &holder{}
	h.set(time.Now().Add(300*time.Millisecond), true, nil)
	s, _, err := a.Issue(t.Context(), stores.MustParseRef("vault://database/creds/ro"), h.lease("grant:2"))
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	waitUntil(t, "revocation at the holder's end", func() bool { _, rev := f.snapshot(); return len(rev) == 1 })
}

func TestLeaseDroppedWhenStoreForgetsIt(t *testing.T) {
	f := newFake()
	f.renewFail = 400
	a := newTest(t, f, nil)
	s, _, err := a.Issue(t.Context(), stores.MustParseRef("vault://database/creds/ro"), stores.LeaseHolder{ID: "grant:3"})
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	waitUntil(t, "the lease to be dropped", func() bool { return len(a.Leases()) == 0 })
	if _, rev := f.snapshot(); len(rev) != 0 {
		t.Errorf("revoked a lease the store no longer has: %v", rev)
	}
}

func TestReleaseAndClose(t *testing.T) {
	f := newFake()
	f.leaseTTL = 3600
	a := newTest(t, f, nil)
	ref := stores.MustParseRef("vault://database/creds/ro")
	for _, id := range []string{"grant:a", "grant:b"} {
		s, _, err := a.Issue(t.Context(), ref, stores.LeaseHolder{ID: id})
		if err != nil {
			t.Fatal(err)
		}
		s.Wipe()
	}
	if err := a.Release(t.Context(), "grant:a"); err != nil {
		t.Fatal(err)
	}
	if _, rev := f.snapshot(); len(rev) != 1 || len(a.Leases()) != 1 || a.Leases()[0].Holder != "grant:b" {
		t.Fatalf("after Release: revoked %v, held %v", rev, a.Leases())
	}
	_ = a.Close()
	if _, rev := f.snapshot(); len(rev) != 2 {
		t.Fatalf("Close revoked %v", rev)
	}
	if _, _, err := a.Issue(t.Context(), ref, stores.LeaseHolder{ID: "grant:c"}); err == nil {
		t.Error("Issue after Close")
	}

	// revoke-on-close off: the leases are left to lapse.
	g := newFake()
	g.leaseTTL = 3600
	b := newTest(t, g, map[string]any{"leases.revoke-on-close": false})
	s, _, err := b.Issue(t.Context(), ref, stores.LeaseHolder{ID: "grant:d"})
	if err != nil {
		t.Fatal(err)
	}
	s.Wipe()
	_ = b.Close()
	if _, rev := g.snapshot(); len(rev) != 0 {
		t.Errorf("revoked on close with revoke-on-close off: %v", rev)
	}
}
