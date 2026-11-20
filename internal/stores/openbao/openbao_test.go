// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func resolveMap(m map[string]string) func(context.Context, config.SecretRef) (secret.Value, error) {
	return func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
		v, ok := m[string(ref)]
		if !ok {
			return secret.Value{}, errors.New("unresolvable")
		}
		return secret.FromString(v), nil
	}
}

func newTest(t *testing.T, srv *httptest.Server, opts map[string]any, creds map[string]string) *Adapter {
	t.Helper()
	o := map[string]any{"address": srv.URL, "auth.method": "token", "token": "test:token", "timeout": "2s"}
	for k, v := range opts {
		if v == nil {
			delete(o, k)
			continue
		}
		o[k] = v
	}
	if creds == nil {
		creds = map[string]string{"test:token": "tok-static"}
	}
	a, err := New(stores.Instance{Name: "bao", Kind: Kind, Options: o, Resolve: resolveMap(creds)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestParseOptions(t *testing.T) {
	_, err := ParseOptions(map[string]any{
		"address": "http://bao:8200", "auth.method": "approle",
		"auth":            map[string]any{"approle": map[string]any{"role-id": "env:R"}},
		"watch.intervall": "5s", "timeout": "soon",
	})
	if err == nil {
		t.Fatal("invalid options accepted")
	}
	msg := err.Error()
	for _, want := range []string{"watch.intervall", "did you mean watch.interval", "secret-id is required", "option timeout"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %s", msg, want)
		}
	}
	o, err := ParseOptions(map[string]any{
		"address": "https://bao.example.test:8200/", "token": "file:/run/bao",
		"mounts": "teams/kv, other", "write-only-paths": []any{"/kv/inbox/"},
		"watch": map[string]any{"interval": "1m", "max-backoff": "10s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if o.AuthMethod != AuthToken || o.Token != "file:/run/bao" || len(o.Mounts) != 2 || o.WriteOnly[0] != "kv/inbox" {
		t.Errorf("decoded %+v", o)
	}
	if o.WatchMaxBackoff != time.Minute {
		t.Errorf("max backoff below the interval was not raised: %s", o.WatchMaxBackoff)
	}
	for _, bad := range []string{"bao:8200", "ftp://x", ""} {
		if _, err := ParseOptions(map[string]any{"address": bad, "token": "env:T"}); err == nil {
			t.Errorf("address %q accepted", bad)
		}
	}
	if _, err := ParseOptions(map[string]any{"address": "http://x", "auth.method": "kubernetes"}); err == nil {
		t.Errorf("unknown auth method accepted")
	}
}

func TestSplitMounts(t *testing.T) {
	a := &Adapter{c: &client{opts: Options{Mounts: []string{"teams/kv", "teams/kv/deep"}}}}
	cases := map[string][2]string{
		"kv/agents/github":  {"kv", "agents/github"},
		"teams/kv/x":        {"teams/kv", "x"},
		"teams/kv/deep/y/z": {"teams/kv/deep", "y/z"},
		"teams/kvx/a":       {"teams", "kvx/a"},
		"kv":                {"kv", ""},
	}
	for in, want := range cases {
		m, r := a.split(in)
		if m != want[0] || r != want[1] {
			t.Errorf("split(%q) = %q, %q, want %q", in, m, r, want)
		}
	}
}

func TestReadDecodesFieldsAndRefusesUnknownSelectors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok-static" {
			writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		if r.Header.Get("X-Vault-Namespace") != "team-a" {
			t.Errorf("namespace header = %q", r.Header.Get("X-Vault-Namespace"))
		}
		if r.URL.Path != "/v1/kv/data/agents/git%20hub" && r.URL.EscapedPath() != "/v1/kv/data/agents/git%20hub" {
			t.Errorf("path %s", r.URL.EscapedPath())
		}
		_, _ = io.WriteString(w, `{"data":{"data":{"token":"a\"bé","port":5432,"on":true,"obj":{"k":[1]}},
			"metadata":{"version":7,"created_time":"2026-01-02T03:04:05.123Z","custom_metadata":{"scrim.hosts":"api.github.com"}}}}`)
	}))
	defer srv.Close()
	a := newTest(t, srv, map[string]any{"namespace": "/team-a/"}, nil)
	s, err := a.Read(t.Context(), stores.MustParseRef("bao://kv/agents/git hub"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Wipe()
	want := map[string]string{"token": `a"bé`, "port": "5432", "on": "true", "obj": `{"k":[1]}`}
	for k, w := range want {
		v, _ := s.Field(k)
		var got string
		_ = v.Expose(func(b []byte) error { got = string(b); return nil })
		if got != w {
			t.Errorf("field %s = %q, want %q", k, got, w)
		}
	}
	if s.Meta.Version != "7" || s.Meta.Labels["scrim.hosts"] != "api.github.com" || s.Meta.UpdatedAt.Year() != 2026 {
		t.Errorf("metadata %+v", s.Meta)
	}
	if strings.Join(s.Meta.Fields, ",") != "obj,on,port,token" {
		t.Errorf("fields %v", s.Meta.Fields)
	}
	for _, sel := range []string{"stage=AWSPREVIOUS", "version=0", "version=x"} {
		_, err := a.Read(t.Context(), stores.MustParseRef("bao://kv/agents/x?"+sel))
		if !errors.Is(err, stores.ErrInvalidRef) {
			t.Errorf("selector %s: %v", sel, err)
		}
	}
	if _, err := a.Read(t.Context(), stores.MustParseRef("bao://kv")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("read of a bare mount: %v", err)
	}
}

func TestReadDeletedVersionIsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]any{"data": map[string]any{"data": nil, "metadata": map[string]any{"version": 2, "deletion_time": "2026-01-01T00:00:00Z"}}})
	}))
	defer srv.Close()
	a := newTest(t, srv, nil, nil)
	if _, err := a.Read(t.Context(), stores.MustParseRef("bao://kv/a")); !errors.Is(err, stores.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		body   string
		kind   error
	}{
		{403, `{"errors":["permission denied"]}`, stores.ErrPermission},
		{404, `{"errors":[]}`, stores.ErrNotFound},
		{400, `{"errors":["check-and-set parameter did not match the current version"]}`, stores.ErrConflict},
		{400, `{"errors":["invalid path"]}`, stores.ErrInvalidRef},
		{429, ``, stores.ErrUnavailable},
		{500, `{"errors":["internal error"]}`, stores.ErrUnavailable},
		{503, `{"errors":["Vault is sealed"]}`, stores.ErrUnavailable},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			_, _ = io.WriteString(w, c.body)
		}))
		a := newTest(t, srv, nil, nil)
		_, err := a.Write(t.Context(), stores.MustParseRef("bao://kv/x"), map[string]secret.Value{"v": secret.FromString("x")}, stores.WriteOptions{})
		if !errors.Is(err, c.kind) {
			t.Errorf("HTTP %d %s: got %v, want %v", c.status, c.body, err, c.kind)
		}
		var se *stores.Error
		if !errors.As(err, &se) || se.Store != "bao" || se.Op != stores.OpWrite {
			t.Errorf("HTTP %d: not a stores.Error naming the store and op: %v", c.status, err)
		}
		srv.Close()
	}
	// An unreachable server is an outage.
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	a := newTest(t, srv, nil, nil)
	if _, err := a.Read(t.Context(), stores.MustParseRef("bao://kv/x")); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("closed server: %v", err)
	}
}

func TestStoreEchoOfValueIsWithheld(t *testing.T) {
	const value = "s3cr3t-value-0123456789"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		// A store that echoes the request back in its error.
		writeJSON(w, 400, map[string]any{"errors": []string{"cannot parse " + string(b)}})
	}))
	defer srv.Close()
	a := newTest(t, srv, nil, nil)
	_, err := a.Write(t.Context(), stores.MustParseRef("bao://kv/x"), map[string]secret.Value{"v": secret.FromString(value)}, stores.WriteOptions{})
	if err == nil {
		t.Fatal("write succeeded")
	}
	for _, s := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(s, value) {
			t.Fatalf("error contains the value: %s", s)
		}
	}
	if !strings.Contains(err.Error(), "withheld") {
		t.Errorf("error %q does not say the message was withheld", err)
	}
}

func TestWriteBodyAndCreateOnly(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/kv/data/agents/new" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		writeJSON(w, 200, map[string]any{"data": map[string]any{"version": 1, "created_time": "2026-05-06T07:08:09Z"}})
	}))
	defer srv.Close()
	a := newTest(t, srv, nil, nil)
	v := secret.FromString("line\n\"q\"")
	m, err := a.Write(t.Context(), stores.MustParseRef("bao://kv/agents/new#ignored"), map[string]secret.Value{"b": v, "a": secret.FromString("x")}, stores.WriteOptions{CreateOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if got["options"].(map[string]any)["cas"].(float64) != 0 {
		t.Errorf("create-only did not send cas=0: %v", got)
	}
	if got["data"].(map[string]any)["b"] != "line\n\"q\"" {
		t.Errorf("body data %v", got["data"])
	}
	if m.Version != "1" || m.CreatedAt.IsZero() || m.Ref.Field != "" {
		t.Errorf("metadata %+v", m)
	}
	if v.Wiped() {
		t.Errorf("caller's value wiped")
	}
	bad := secret.New([]byte{0xff})
	if _, err := a.Write(t.Context(), stores.MustParseRef("bao://kv/agents/new"), map[string]secret.Value{"b": bad}, stores.WriteOptions{}); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("invalid UTF-8: %v", err)
	}
}

// approleServer issues tokens on login and rejects tokens it revoked.
type approleServer struct {
	mu      sync.Mutex
	logins  int
	valid   map[string]bool
	ttl     int
	denyAll bool
}

func (s *approleServer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.URL.Path == "/v1/sys/health" {
			writeJSON(w, 200, map[string]any{"initialized": true, "sealed": false})
			return
		}
		if r.URL.Path == "/v1/auth/approle/login" {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role_id"] != "role-7d1c9e" || body["secret_id"] != "sid" {
				writeJSON(w, 400, map[string]any{"errors": []string{"invalid role or secret ID"}})
				return
			}
			s.logins++
			tok := fmt.Sprintf("hvs.session-%d", s.logins)
			s.valid[tok] = true
			writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": s.ttl}})
			return
		}
		if s.denyAll || !s.valid[r.Header.Get("X-Vault-Token")] {
			writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"data": map[string]any{"v": "x"}, "metadata": map[string]any{"version": 1}}})
	})
}

func approleAdapter(t *testing.T, srv *httptest.Server) *Adapter {
	return newTest(t, srv,
		map[string]any{"auth.method": "approle", "token": nil, "role-id": "test:role", "secret-id": "test:sid"},
		map[string]string{"test:role": "role-7d1c9e", "test:sid": "sid"})
}

func TestAppRoleLoginAndReloginOnRevokedToken(t *testing.T) {
	s := &approleServer{valid: map[string]bool{}, ttl: 3600}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	a := approleAdapter(t, srv)
	ref := stores.MustParseRef("bao://kv/x")
	for range 3 {
		sec, err := a.Read(t.Context(), ref)
		if err != nil {
			t.Fatal(err)
		}
		sec.Wipe()
	}
	if s.logins != 1 {
		t.Fatalf("logins = %d, want 1 (token reused)", s.logins)
	}
	s.mu.Lock()
	clear(s.valid) // revoke every token
	s.mu.Unlock()
	sec, err := a.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("read after revocation: %v", err)
	}
	sec.Wipe()
	if s.logins != 2 {
		t.Fatalf("logins = %d, want a second login after a 403", s.logins)
	}
	s.mu.Lock()
	s.denyAll = true
	s.mu.Unlock()
	if _, err := a.Read(t.Context(), ref); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("policy refusal: %v", err)
	}
	if s.logins != 3 {
		t.Fatalf("logins = %d, want exactly one retry", s.logins)
	}
}

func TestAppRoleTokenReplacedBeforeExpiry(t *testing.T) {
	s := &approleServer{valid: map[string]bool{}, ttl: 30}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	a := approleAdapter(t, srv)
	now := time.Now()
	a.c.now = func() time.Time { return now }
	ref := stores.MustParseRef("bao://kv/x")
	read := func() {
		t.Helper()
		sec, err := a.Read(t.Context(), ref)
		if err != nil {
			t.Fatal(err)
		}
		sec.Wipe()
	}
	read()
	now = now.Add(19 * time.Second)
	read()
	if s.logins != 1 {
		t.Fatalf("logged in again before two thirds of the TTL")
	}
	now = now.Add(2 * time.Second)
	read()
	if s.logins != 2 {
		t.Fatalf("logins = %d, want a fresh login after two thirds of the TTL", s.logins)
	}
}

func TestAppRoleBadCredentials(t *testing.T) {
	s := &approleServer{valid: map[string]bool{}, ttl: 30}
	srv := httptest.NewServer(s.handler(t))
	defer srv.Close()
	a := newTest(t, srv,
		map[string]any{"auth.method": "approle", "role-id": "test:role", "secret-id": "test:sid"},
		map[string]string{"test:role": "role-7d1c9e", "test:sid": "wrong-secret-id-value"})
	err := a.Health(t.Context())
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", err), "wrong-secret-id-value") {
		t.Fatalf("error contains the secret ID")
	}
}

func TestUnresolvableCredentialContactsNoStore(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/health" {
			hits.Add(1)
		}
		writeJSON(w, 200, map[string]any{})
	}))
	defer srv.Close()
	a := newTest(t, srv, map[string]any{"token": "file:/run/missing"}, map[string]string{})
	_, err := a.Read(t.Context(), stores.MustParseRef("bao://kv/x"))
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "file:/run/missing") {
		t.Fatalf("got %v, want a permission error naming the reference", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("store contacted %d times without a credential", hits.Load())
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "" {
			leaked.Store(true)
		}
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	a := newTest(t, srv, nil, nil)
	if _, err := a.Read(t.Context(), stores.MustParseRef("bao://kv/x")); err == nil {
		t.Fatal("read through a redirect succeeded")
	}
	if leaked.Load() {
		t.Fatal("token sent to the redirect target")
	}
}

func TestHealthSealed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 503, map[string]any{"sealed": true})
	}))
	defer srv.Close()
	a := newTest(t, srv, nil, nil)
	if err := a.Health(t.Context()); !errors.Is(err, stores.ErrUnavailable) {
		t.Fatalf("sealed: %v", err)
	}
}

// TestListFallsBackWithoutDetailedMetadata covers Vault, which has no
// detailed-metadata endpoint: List lists keys and reads each one's metadata.
func TestListFallsBackWithoutDetailedMetadata(t *testing.T) {
	var detailedCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/detailed-metadata/"):
			detailedCalls.Add(1)
			writeJSON(w, 405, map[string]any{"errors": []string{"unsupported operation"}})
		case r.Method == "LIST" && r.URL.Path == "/v1/kv/metadata/agents/":
			writeJSON(w, 200, map[string]any{"data": map[string]any{"keys": []string{"a", "deleted", "sub/"}}})
		case r.Method == "LIST" && r.URL.Path == "/v1/kv/metadata/agents/sub/":
			writeJSON(w, 200, map[string]any{"data": map[string]any{"keys": []string{"b"}}})
		case r.URL.Path == "/v1/kv/metadata/agents/deleted":
			writeJSON(w, 200, map[string]any{"data": map[string]any{"current_version": 1,
				"versions": map[string]any{"1": map[string]any{"deletion_time": "2026-01-01T00:00:00Z"}}}})
		case strings.HasPrefix(r.URL.Path, "/v1/kv/metadata/agents/"):
			writeJSON(w, 200, map[string]any{"data": map[string]any{"current_version": 4, "updated_time": "2026-01-01T00:00:00Z",
				"custom_metadata": map[string]string{"scrim.hosts": "h"}, "versions": map[string]any{"4": map[string]any{}}}})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	a := newTest(t, srv, nil, nil)
	for range 2 {
		ms, err := a.List(t.Context(), stores.MustParseRef("bao://kv/agents"))
		if err != nil {
			t.Fatal(err)
		}
		if len(ms) != 2 || ms[0].Ref.Path != "kv/agents/a" || ms[1].Ref.Path != "kv/agents/sub/b" {
			t.Fatalf("list %+v", ms)
		}
		if ms[0].Version != "4" || ms[0].Labels["scrim.hosts"] != "h" {
			t.Errorf("metadata %+v", ms[0])
		}
	}
	if detailedCalls.Load() != 1 {
		t.Errorf("detailed-metadata tried %d times, want once", detailedCalls.Load())
	}
}

func TestWatchBacksOffAndRecovers(t *testing.T) {
	var (
		mu      sync.Mutex
		fail    bool
		version = 1
		polls   []time.Time
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		polls = append(polls, time.Now())
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"keys": []string{"a"}, "key_info": map[string]any{
			"a": map[string]any{"current_version": version, "versions": map[string]any{}}}}})
	}))
	defer srv.Close()
	a := newTest(t, srv, map[string]any{"watch.interval": "20ms", "watch.max-backoff": "80ms"}, nil)
	a.jitter = func(d time.Duration) time.Duration { return d }
	ctx, cancel := context.WithCancel(t.Context())
	ch, err := a.Watch(ctx, stores.MustParseRef("bao://kv/agents"))
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	n := len(polls)
	fail = false
	version = 2
	mu.Unlock()
	// Without backoff, 300ms at 20ms is ~15 polls; with doubling to 80ms
	// it is about 5.
	if n > 9 {
		t.Errorf("%d polls during the outage: no backoff", n)
	}
	select {
	case c := <-ch:
		if c.Ref.Path != "kv/agents/a" || c.Kind != stores.Changed {
			t.Errorf("change %+v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no change after recovery")
	}
	cancel()
	for range ch {
	}
}

func TestWatchPermissionErrorIsImmediate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 403, map[string]any{"errors": []string{"permission denied"}})
	}))
	defer srv.Close()
	a := newTest(t, srv, nil, nil)
	if _, err := a.Watch(t.Context(), stores.MustParseRef("bao://kv/agents")); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("got %v", err)
	}
}

func TestJitterSpreads(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 200 {
		d := defaultJitter(10 * time.Second)
		if d < 8*time.Second || d > 12*time.Second {
			t.Fatalf("jitter %s out of range", d)
		}
		seen[d] = true
	}
	if len(seen) < 50 {
		t.Fatalf("jitter barely varies: %d distinct values", len(seen))
	}
}

func TestClosedAdapterRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"data": map[string]any{"v": "x"}, "metadata": map[string]any{"version": 1}}})
	}))
	defer srv.Close()
	a := newTest(t, srv, nil, nil)
	_ = a.Close()
	if _, err := a.Read(t.Context(), stores.MustParseRef("bao://kv/x")); !errors.Is(err, stores.ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	if len(a.Credentials()) != 0 {
		t.Fatalf("closed adapter still holds credentials")
	}
}
