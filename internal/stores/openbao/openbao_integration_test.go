// SPDX-License-Identifier: AGPL-3.0-only

package openbao_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/podmantest"
	"github.com/heliopsy/scrim/internal/stores/openbao"
	"github.com/heliopsy/scrim/internal/stores/refresh"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// DefaultImage is the OpenBao image the integration tests run, overridable
// with SCRIM_TEST_OPENBAO_IMAGE.
const DefaultImage = "quay.io/openbao/openbao:2.7.3"

// scrimPolicy is what the docs recommend: read and write under the agents
// tree, write without read under the inbox, nothing else.
const scrimPolicy = `
path "kv/data/scrim-conformance/*"              { capabilities = ["create", "read", "update"] }
path "kv/metadata/scrim-conformance/*"          { capabilities = ["list", "read", "update"] }
path "kv/detailed-metadata/scrim-conformance/*" { capabilities = ["list"] }

path "kv/data/inbox/*"              { capabilities = ["create", "update"] }
path "kv/metadata/inbox/*"          { capabilities = ["list"] }
path "kv/detailed-metadata/inbox/*" { capabilities = ["list"] }
`

// server is a running OpenBao with the conformance setup applied.
type server struct {
	addr      string
	root      string
	container *podmantest.Container
	roleID    string
	secretID  string
}

var (
	serverOnce sync.Once
	shared     *server
	sharedErr  string
	cleanup    func()
)

func randHex(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestMain(m *testing.M) {
	code := m.Run()
	if cleanup != nil {
		cleanup()
	}
	os.Exit(code)
}

// cleanupTB lets the shared container outlive the first test that starts
// it: its cleanups run from TestMain.
type cleanupTB struct {
	testing.TB
	fns []func()
}

func (c *cleanupTB) Cleanup(f func()) { c.fns = append(c.fns, f) }

// startServer starts (once per test binary) OpenBao in dev mode under
// rootless podman, or uses SCRIM_TEST_OPENBAO_ADDR and
// SCRIM_TEST_OPENBAO_TOKEN when set (a CI service container).
func startServer(t *testing.T) *server {
	t.Helper()
	serverOnce.Do(func() {
		s := &server{}
		if addr := os.Getenv("SCRIM_TEST_OPENBAO_ADDR"); addr != "" {
			s.addr, s.root = addr, os.Getenv("SCRIM_TEST_OPENBAO_TOKEN")
		} else {
			podmantest.Require(t)
			image := os.Getenv("SCRIM_TEST_OPENBAO_IMAGE")
			if image == "" {
				image = DefaultImage
			}
			ctb := &cleanupTB{TB: t}
			s.root = randHex(t, 16)
			s.container = podmantest.Run(ctb, "openbao", image, 8200,
				map[string]string{"BAO_DEV_ROOT_TOKEN_ID": s.root},
				"server", "-dev", "-dev-listen-address=0.0.0.0:8200")
			cleanup = func() {
				for i := len(ctb.fns) - 1; i >= 0; i-- {
					ctb.fns[i]()
				}
			}
			s.addr = fmt.Sprintf("http://127.0.0.1:%d", s.container.Port)
		}
		podmantest.WaitHTTP(t, s.addr+"/v1/sys/health", 60*time.Second, func(c int) bool { return c == 200 })
		if err := s.setup(); err != nil {
			sharedErr = err.Error()
			return
		}
		shared = s
	})
	if shared == nil {
		if sharedErr == "" {
			t.Skip("OpenBao not available")
		}
		t.Fatalf("OpenBao setup: %s", sharedErr)
	}
	return shared
}

// api calls OpenBao as root. Bodies here are test setup, never adapter
// values, except in Delete which sends none.
func (s *server) api(method, path string, body any) (map[string]any, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.addr+"/v1/"+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", s.root)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	out := map[string]any{}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &out)
	}
	return out, nil
}

func (s *server) setup() error {
	steps := []struct {
		method, path string
		body         any
	}{
		{"POST", "sys/mounts/kv", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}},
		{"POST", "sys/auth/approle", map[string]any{"type": "approle"}},
		{"PUT", "sys/policies/acl/scrim", map[string]any{"policy": scrimPolicy}},
		// A short TTL makes the conformance run cross several token
		// renewals, exercising re-login.
		{"POST", "auth/approle/role/scrim", map[string]any{"token_policies": []string{"scrim"}, "token_ttl": "30s", "token_max_ttl": "60s"}},
	}
	for _, st := range steps {
		if _, err := s.api(st.method, st.path, st.body); err != nil {
			// A reused external server may already have these.
			if !strings.Contains(err.Error(), "HTTP 400") {
				return err
			}
		}
	}
	rid, err := s.api("GET", "auth/approle/role/scrim/role-id", nil)
	if err != nil {
		return err
	}
	sid, err := s.api("POST", "auth/approle/role/scrim/secret-id", map[string]any{})
	if err != nil {
		return err
	}
	s.roleID, _ = rid["data"].(map[string]any)["role_id"].(string)
	s.secretID, _ = sid["data"].(map[string]any)["secret_id"].(string)
	if s.roleID == "" || s.secretID == "" {
		return errors.New("no AppRole credentials")
	}
	return nil
}

// resolver serves credentials from a map, as config references would.
func resolver(m map[string]string) func(context.Context, config.SecretRef) (secret.Value, error) {
	return func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
		v, ok := m[string(ref)]
		if !ok {
			return secret.Value{}, fmt.Errorf("no such reference")
		}
		return secret.FromString(v), nil
	}
}

func (s *server) adapter(t testing.TB, name string, extra map[string]any) *openbao.Adapter {
	t.Helper()
	opts := map[string]any{
		"address":           s.addr,
		"auth":              map[string]any{"method": "approle"},
		"role-id":           "test:role-id",
		"secret-id":         "test:secret-id",
		"timeout":           "2s",
		"watch.interval":    "300ms",
		"watch.max-backoff": "1s",
		"write-only-paths":  []any{"kv/inbox"},
	}
	for k, v := range extra {
		opts[k] = v
	}
	a, err := openbao.New(stores.Instance{
		Name: name, Kind: openbao.Kind, Options: opts,
		Resolve: resolver(map[string]string{"test:role-id": s.roleID, "test:secret-id": s.secretID, "test:root": s.root}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestConformanceOpenBao(t *testing.T) {
	s := startServer(t)
	storetest.Run(t, func(tb storetest.TB) storetest.Harness {
		h := storetest.Harness{
			Adapter:         s.adapter(t, "bao", nil),
			Prefix:          "kv/scrim-conformance/" + randHex(t, 6),
			VersionSelector: true,
			Labels:          true,
			WriteOnlyPrefix: "kv/inbox",
			WatchTimeout:    15 * time.Second,
			Reject: func(storetest.TB) stores.Ref {
				return stores.Ref{Scheme: "bao", Path: "kv/outside-policy/" + randHex(t, 4)}
			},
			Delete: func(tb storetest.TB, ref stores.Ref) {
				p := strings.TrimPrefix(ref.Path, "kv/")
				if _, err := s.api("DELETE", "kv/metadata/"+p, nil); err != nil {
					tb.Fatalf("delete %s: %v", ref, err)
				}
			},
		}
		if s.container != nil {
			h.Outage = func(tb storetest.TB) func() {
				s.container.Pause(t)
				return func() { s.container.Unpause(t) }
			}
		}
		return h
	})
}

// TestTokenAuth covers the static token method and the write-only policy
// from the docs: a token that can create but not read under kv/inbox.
func TestTokenAuth(t *testing.T) {
	s := startServer(t)
	tok, err := s.api("POST", "auth/token/create", map[string]any{"policies": []string{"scrim"}, "ttl": "10m"})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := tok["auth"].(map[string]any)["client_token"].(string)
	a, err := openbao.New(stores.Instance{
		Name: "bao-token", Kind: openbao.Kind,
		Options: map[string]any{"address": s.addr, "auth.method": "token", "token": "test:token"},
		Resolve: resolver(map[string]string{"test:token": client}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	ctx := t.Context()
	if err := a.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}
	// Without write-only-paths configured the adapter does try to read
	// the inbox, and the store's policy refuses it: the store, not only
	// scrim, keeps the value from being read back.
	ref := stores.Ref{Scheme: "bao-token", Path: "kv/inbox/" + randHex(t, 4)}
	value := "tok_" + randHex(t, 16)
	if _, err := a.Write(ctx, ref, map[string]secret.Value{"token": secret.FromString(value)}, stores.WriteOptions{}); err != nil {
		t.Fatalf("Write to the inbox without read: %v", err)
	}
	_, err = a.Read(ctx, ref)
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("Read of the inbox: %v, want permission denied", err)
	}
	if strings.Contains(err.Error(), value) {
		t.Fatalf("error contains the value")
	}
	// The admin can read it: the write really landed.
	got, err := s.api("GET", "kv/data/"+strings.TrimPrefix(ref.Path, "kv/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["data"].(map[string]any)["data"].(map[string]any)["token"] != value {
		t.Fatalf("written value not found in the store")
	}
	// A bad token is a permission error, not an outage.
	bad, _ := openbao.New(stores.Instance{
		Name: "bao-bad", Kind: openbao.Kind,
		Options: map[string]any{"address": s.addr, "auth.method": "token", "token": "test:bad"},
		Resolve: resolver(map[string]string{"test:bad": "not-a-token"}),
	})
	defer func() { _ = bad.Close() }()
	if err := bad.Health(ctx); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("Health with a bad token: %v, want permission denied", err)
	}
}

// TestCredentialsReported checks the adapter hands its AppRole material and
// session token to scrim for redaction.
func TestCredentialsReported(t *testing.T) {
	s := startServer(t)
	a := s.adapter(t, "bao-creds", nil)
	defer func() { _ = a.Close() }()
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range a.Credentials() {
		_ = v.Expose(func(b []byte) error { got = append(got, string(b)); return nil })
		v.Wipe()
	}
	want := map[string]bool{s.roleID: false, s.secretID: false}
	for _, g := range got {
		if _, ok := want[g]; ok {
			want[g] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("credential of length %d not reported", len(k))
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d credentials, want role ID, secret ID and session token", len(got))
	}
}

// TestRefresherOutageMidRun is task 6.4 against a real store: load from
// OpenBao, freeze the container mid-run, check the last known values are
// still redacted, the store reports degraded and injection of a value that
// was never loaded fails closed, then thaw it and see the store recover.
func TestRefresherOutageMidRun(t *testing.T) {
	s := startServer(t)
	if s.container == nil {
		t.Skip("needs a podman-managed OpenBao to pause")
	}
	a := s.adapter(t, "bao-outage", nil)
	prefix := "kv/scrim-conformance/" + randHex(t, 6)
	value := "out_" + randHex(t, 16)
	ctx := t.Context()
	if _, err := a.Write(ctx, stores.Ref{Scheme: "bao-outage", Path: prefix + "/github"},
		map[string]secret.Value{"token": secret.FromString(value)}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	r := refresh.New(a, refresh.Config{
		Targets:  []refresh.Target{{Ref: stores.Ref{Scheme: "bao-outage", Path: prefix}, Prefix: true}},
		Interval: 200 * time.Millisecond, MaxBackoff: 400 * time.Millisecond,
	})
	defer r.Close()
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { r.Run(rctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitUntil(t, "first load", func() bool { return r.Ready(ctx) == nil })

	s.container.Pause(t)
	paused := true
	defer func() {
		if paused {
			s.container.Unpause(t)
		}
	}()
	waitUntil(t, "degraded", func() bool { return r.Status().State == refresh.StateDegraded })
	found := false
	r.EachValue(func(_ refresh.Source, v secret.Value) {
		_ = v.Expose(func(b []byte) error { found = found || string(b) == value; return nil })
	})
	if !found {
		t.Fatal("last known value dropped during the outage")
	}
	_, err := r.Resolve(ctx, stores.Ref{Scheme: "bao-outage", Path: prefix + "/never-loaded", Field: "token"})
	if !errors.Is(err, stores.ErrUnavailable) {
		t.Fatalf("injection of an unloaded value during the outage: %v", err)
	}
	s.container.Unpause(t)
	paused = false
	waitUntil(t, "recovery", func() bool { return r.Status().State == refresh.StateReady })
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
