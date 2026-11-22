// SPDX-License-Identifier: AGPL-3.0-only

package vault_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/podmantest"
	"github.com/heliopsy/scrim/internal/stores/storetest"
	"github.com/heliopsy/scrim/internal/stores/vault"
)

// DefaultImage is the Vault image the integration tests run, overridable
// with SCRIM_TEST_VAULT_IMAGE. Vault is BUSL-licensed; running it to test
// against is permitted use.
const DefaultImage = "docker.io/hashicorp/vault:2.2.2"

// scrimPolicy is what the docs recommend: read and write under the agents
// tree on both KV versions, write without read under the inboxes, dynamic
// database credentials and lease renewal, nothing else.
const scrimPolicy = `
path "secret/data/scrim-conformance/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/scrim-conformance/*" { capabilities = ["list", "read", "update"] }
path "secret/data/inbox/*"                 { capabilities = ["create", "update"] }
path "secret/metadata/inbox/*"             { capabilities = ["list"] }

path "kv1/scrim-conformance/*" { capabilities = ["create", "read", "update", "list"] }
path "kv1/inbox/*"             { capabilities = ["create", "update", "list"] }

path "database/creds/readonly" { capabilities = ["read"] }
path "pki/issue/*"             { capabilities = ["create", "update"] }
path "sys/leases/renew"        { capabilities = ["update"] }
path "sys/leases/revoke"       { capabilities = ["update"] }
`

// server is a running Vault with the conformance setup applied.
type server struct {
	addr, root       string
	pod              string
	roleID, secretID string
	jwtKey           *rsa.PrivateKey
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

// playPod plays yaml with `podman kube play` and returns the function that
// takes it down. The pod is shared by every test in the binary and outlives
// the first test that starts it, so it is taken down from TestMain, and the
// YAML (it holds generated test credentials) lives in a private directory
// of its own rather than a test's TempDir.
func playPod(yaml []byte, publish string) (func(), error) {
	dir, err := os.MkdirTemp("", "scrim-stores-vault-")
	if err != nil {
		return nil, err
	}
	path := dir + "/pod.yaml"
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if _, err := podmantest.Podman(ctx, "kube", "down", path); err != nil {
			fmt.Fprintln(os.Stderr, "cleanup:", err)
		}
		_ = os.RemoveAll(dir)
	}
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := podmantest.Podman(ctx, "kube", "play", "--replace", "--publish", publish, path); err != nil {
		stop()
		return nil, err
	}
	return stop, nil
}

// startServer plays testdata/pod.yaml (Vault dev mode and PostgreSQL) once
// per test binary under rootless podman, or uses SCRIM_TEST_VAULT_ADDR and
// SCRIM_TEST_VAULT_TOKEN when set (no outage or database tests then).
func startServer(t *testing.T) *server {
	t.Helper()
	serverOnce.Do(func() {
		s := &server{}
		if addr := os.Getenv("SCRIM_TEST_VAULT_ADDR"); addr != "" {
			s.addr, s.root = addr, os.Getenv("SCRIM_TEST_VAULT_TOKEN")
		} else {
			podmantest.Require(t)
			image := os.Getenv("SCRIM_TEST_VAULT_IMAGE")
			if image == "" {
				image = DefaultImage
			}
			tmpl, err := os.ReadFile("testdata/pod.yaml")
			if err != nil {
				t.Fatal(err)
			}
			s.root = randHex(t, 16)
			s.pod = podmantest.Name(t, "vault")
			yaml := os.Expand(string(tmpl), func(k string) string {
				return map[string]string{
					"POD_NAME": s.pod, "VAULT_IMAGE": image, "ROOT_TOKEN": s.root, "DB_PASSWORD": randHex(t, 16),
				}[k]
			})
			port := podmantest.FreePort(t)
			stop, err := playPod([]byte(yaml), fmt.Sprintf("127.0.0.1:%d:8200", port))
			if err != nil {
				t.Fatal(err)
			}
			cleanup = stop
			s.addr = fmt.Sprintf("http://127.0.0.1:%d", port)
		}
		podmantest.WaitHTTP(t, s.addr+"/v1/sys/health", 90*time.Second, func(c int) bool { return c == 200 })
		if err := s.setup(); err != nil {
			sharedErr = err.Error()
			return
		}
		shared = s
	})
	if shared == nil {
		if sharedErr == "" {
			t.Skip("Vault not available")
		}
		t.Fatalf("Vault setup: %s", sharedErr)
	}
	return shared
}

// container is the pod's Vault container, for outage tests.
func (s *server) container() *podmantest.Container {
	if s.pod == "" {
		return nil
	}
	return &podmantest.Container{Name: s.pod + "-vault"}
}

// api calls Vault as root. Bodies are test setup, never adapter values.
func (s *server) api(method, path string, body any) (map[string]any, error) {
	return s.apiAs(s.root, method, path, body)
}

func (s *server) apiAs(token, method, path string, body any) (map[string]any, error) {
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
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(b))
	}
	out := map[string]any{}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &out)
	}
	return out, nil
}

func (s *server) setup() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	s.jwtKey = key
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	steps := []struct {
		method, path string
		body         any
	}{
		// Dev mode mounts KV v2 at secret/ already.
		{"POST", "sys/mounts/kv1", map[string]any{"type": "kv", "options": map[string]string{"version": "1"}}},
		{"POST", "sys/auth/approle", map[string]any{"type": "approle"}},
		{"PUT", "sys/policies/acl/scrim", map[string]any{"policy": scrimPolicy}},
		// A short TTL makes the conformance run cross several token
		// renewals, exercising re-login.
		{"POST", "auth/approle/role/scrim", map[string]any{"token_policies": []string{"scrim"}, "token_ttl": "30s", "token_max_ttl": "60s"}},
		{"POST", "sys/auth/jwt", map[string]any{"type": "jwt"}},
		{"POST", "auth/jwt/config", map[string]any{"jwt_validation_pubkeys": []string{pubPEM}}},
		{"POST", "auth/jwt/role/scrim", map[string]any{
			"role_type": "jwt", "user_claim": "sub", "bound_audiences": []string{"vault.scrim.test"},
			"token_policies": []string{"scrim"}, "token_ttl": "30s", "token_max_ttl": "60s",
		}},
		{"POST", "sys/mounts/pki", map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "1h"}}},
		{"POST", "pki/root/generate/internal", map[string]any{"common_name": "scrim.test", "ttl": "1h"}},
		{"POST", "pki/roles/unleased", map[string]any{"allowed_domains": "example.test", "allow_subdomains": true, "ttl": "60s"}},
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

// setupDatabase enables the database engine against the pod's PostgreSQL,
// with leases short enough to see renewals within a test.
func (s *server) setupDatabase(t *testing.T) {
	t.Helper()
	if s.pod == "" {
		t.Skip("database engine needs the podman-managed pod")
	}
	if _, err := s.api("POST", "sys/mounts/database", map[string]any{"type": "database"}); err != nil && !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatal(err)
	}
	pw := s.dbPassword(t)
	cfg := map[string]any{
		"plugin_name":    "postgresql-database-plugin",
		"connection_url": "postgresql://{{username}}:{{password}}@127.0.0.1:5432/app?sslmode=disable",
		"username":       "vault", "password": pw, "allowed_roles": "readonly",
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, err := s.api("POST", "database/config/app", cfg)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("database config: %v", err)
		}
		time.Sleep(time.Second)
	}
	if _, err := s.api("POST", "database/roles/readonly", map[string]any{
		"db_name":             "app",
		"creation_statements": []string{`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`},
		"default_ttl":         "6s", "max_ttl": "5m",
	}); err != nil {
		t.Fatal(err)
	}
}

// dbPassword reads the PostgreSQL password back from the pod, so the
// template value is not kept around in a package variable.
func (s *server) dbPassword(t *testing.T) string {
	t.Helper()
	return podmantest.MustPodman(t, "exec", s.pod+"-postgres", "printenv", "POSTGRES_PASSWORD")
}

// pgRoleExists asks PostgreSQL whether a login role exists.
func (s *server) pgRoleExists(t *testing.T, role string) bool {
	t.Helper()
	out := podmantest.MustPodman(t, "exec", s.pod+"-postgres", "psql", "-U", "vault", "-d", "app", "-tAc",
		"SELECT count(*) FROM pg_roles WHERE rolname = '"+strings.ReplaceAll(role, "'", "''")+"'")
	return strings.TrimSpace(out) == "1"
}

// leaseLive reports whether Vault still knows the lease, and its TTL.
func (s *server) leaseLive(t *testing.T, id string) (bool, time.Duration) {
	t.Helper()
	r, err := s.api("PUT", "sys/leases/lookup", map[string]any{"lease_id": id})
	if err != nil {
		if strings.Contains(err.Error(), "invalid lease") || strings.Contains(err.Error(), "HTTP 400") {
			return false, 0
		}
		t.Fatal(err)
	}
	ttl, _ := r["data"].(map[string]any)["ttl"].(float64)
	return true, time.Duration(ttl) * time.Second
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

func (s *server) adapter(t testing.TB, name string, extra map[string]any) *vault.Adapter {
	t.Helper()
	opts := map[string]any{
		"address":                s.addr,
		"auth":                   map[string]any{"method": "approle"},
		"role-id":                "test:role-id",
		"secret-id":              "test:secret-id",
		"timeout":                "2s",
		"watch.interval":         "300ms",
		"watch.max-backoff":      "1s",
		"write-only-paths":       []any{"secret/inbox", "kv1/inbox"},
		"leases.check-interval":  "200ms",
		"leases.revoke-timeout":  "5s",
		"leases.revoke-on-close": true,
	}
	for k, v := range extra {
		opts[k] = v
	}
	a, err := vault.New(stores.Instance{
		Name: name, Kind: vault.Kind, Options: opts,
		Resolve: resolver(map[string]string{"test:role-id": s.roleID, "test:secret-id": s.secretID, "test:root": s.root, "test:jwt": s.jwt(t)}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// jwt signs a token the JWT auth role accepts.
func (s *server) jwt(t testing.TB) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	now := time.Now()
	head := enc(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims := enc(map[string]any{"sub": "scrim", "aud": "vault.scrim.test", "iat": now.Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix()})
	sum := sha256.Sum256([]byte(head + "." + claims))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.jwtKey, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return head + "." + claims + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func conformance(t *testing.T, s *server, mount string, v2 bool) {
	storetest.Run(t, func(tb storetest.TB) storetest.Harness {
		h := storetest.Harness{
			Adapter:         s.adapter(t, "vault", nil),
			Prefix:          mount + "/scrim-conformance/" + randHex(t, 6),
			VersionSelector: v2,
			Labels:          v2,
			WriteOnlyPrefix: mount + "/inbox",
			WatchTimeout:    15 * time.Second,
			Reject: func(storetest.TB) stores.Ref {
				return stores.Ref{Scheme: "vault", Path: mount + "/outside-policy/" + randHex(t, 4)}
			},
			Delete: func(tb storetest.TB, ref stores.Ref) {
				p := strings.TrimPrefix(ref.Path, mount+"/")
				api := mount + "/" + p
				if v2 {
					api = mount + "/metadata/" + p
				}
				if _, err := s.api("DELETE", api, nil); err != nil {
					tb.Fatalf("delete %s: %v", ref, err)
				}
			},
		}
		if c := s.container(); c != nil {
			h.Outage = func(storetest.TB) func() {
				c.Pause(t)
				return func() { c.Unpause(t) }
			}
		}
		return h
	})
}

func TestConformanceVaultKV2(t *testing.T) { conformance(t, startServer(t), "secret", true) }

func TestConformanceVaultKV1(t *testing.T) { conformance(t, startServer(t), "kv1", false) }

// TestKVVersionDetected: the same adapter reads both KV versions, telling
// them apart from the mount, and labels each with its engine.
func TestKVVersionDetected(t *testing.T) {
	s := startServer(t)
	a := s.adapter(t, "vault-kv", nil)
	defer func() { _ = a.Close() }()
	ctx := t.Context()
	value := "kv_" + randHex(t, 16)
	for _, mount := range []string{"secret", "kv1"} {
		ref := stores.Ref{Scheme: "vault-kv", Path: mount + "/scrim-conformance/" + randHex(t, 4) + "/git hub"}
		if _, err := a.Write(ctx, ref, map[string]secret.Value{"token": secret.FromString(value)}, stores.WriteOptions{}); err != nil {
			t.Fatalf("Write %s: %v", ref, err)
		}
		got, err := a.Read(ctx, ref.WithField("token"))
		if err != nil {
			t.Fatalf("Read %s: %v", ref, err)
		}
		want := map[string]string{"secret": "kv-v2", "kv1": "kv-v1"}[mount]
		if got.Meta.Labels["vault.engine"] != want || got.Meta.Labels["vault.mount"] != mount {
			t.Errorf("%s: labels %v", ref, got.Meta.Labels)
		}
		got.Wipe()
		m, err := a.ReadMetadata(ctx, ref)
		if err != nil || m.Labels["vault.engine"] != want {
			t.Errorf("ReadMetadata %s: %v %v", ref, m.Labels, err)
		}
		// Escaped once: the store has the secret under its own name.
		api := mount + "/" + strings.TrimPrefix(ref.Path, mount+"/")
		if mount == "secret" {
			api = "secret/data/" + strings.TrimPrefix(ref.Path, "secret/")
		}
		if _, err := s.api("GET", strings.ReplaceAll(api, " ", "%20"), nil); err != nil {
			t.Errorf("%s not stored under its own name: %v", ref, err)
		}
	}
	// KV v1 has no versions and no custom metadata: refused, not ignored.
	ref := stores.Ref{Scheme: "vault-kv", Path: "kv1/scrim-conformance/x", Selectors: "version=1"}
	if _, err := a.Read(ctx, ref); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("version selector on KV v1: %v", err)
	}
	_, err := a.Write(ctx, stores.Ref{Scheme: "vault-kv", Path: "kv1/scrim-conformance/labelled"},
		map[string]secret.Value{"v": secret.FromString(value)}, stores.WriteOptions{Labels: map[string]string{"scrim.hosts": "x.test"}})
	if !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("labels on KV v1: %v", err)
	}
}

// TestTokenAndJWTAuth logs in with a static token and with a JWT, and
// checks a refused login is a permission error that does not hold the JWT.
func TestTokenAndJWTAuth(t *testing.T) {
	s := startServer(t)
	tok, err := s.api("POST", "auth/token/create", map[string]any{"policies": []string{"scrim"}, "ttl": "10m"})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := tok["auth"].(map[string]any)["client_token"].(string)
	ctx := t.Context()
	ref := stores.Ref{Path: "secret/scrim-conformance/" + randHex(t, 6)}
	value := "auth_" + randHex(t, 16)
	for _, c := range []struct {
		name string
		opts map[string]any
	}{
		{"token", map[string]any{"auth": map[string]any{"method": "token"}, "token": "test:token"}},
		{"jwt", map[string]any{"auth": map[string]any{"method": "jwt", "jwt": map[string]any{"role": "scrim"}}, "jwt": "test:jwt"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			opts := map[string]any{"address": s.addr}
			for k, v := range c.opts {
				opts[k] = v
			}
			a, err := vault.New(stores.Instance{
				Name: "vault-" + c.name, Kind: vault.Kind, Options: opts,
				Resolve: resolver(map[string]string{"test:token": client, "test:jwt": s.jwt(t)}),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = a.Close() }()
			if err := a.Health(ctx); err != nil {
				t.Fatalf("Health: %v", err)
			}
			r := ref
			r.Scheme = "vault-" + c.name
			if _, err := a.Write(ctx, r, map[string]secret.Value{"v": secret.FromString(value)}, stores.WriteOptions{}); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got, err := a.Read(ctx, r.WithField("v"))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			got.Wipe()
			if n := len(a.Credentials()); n == 0 {
				t.Error("no credentials reported for redaction")
			}
		})
	}
	// A JWT the role does not accept (wrong audience).
	bad := s.jwt(t)
	a, _ := vault.New(stores.Instance{
		Name: "vault-badjwt", Kind: vault.Kind,
		Options: map[string]any{"address": s.addr, "auth.method": "jwt", "auth.jwt.role": "other", "jwt": "test:jwt"},
		Resolve: resolver(map[string]string{"test:jwt": bad}),
	})
	defer func() { _ = a.Close() }()
	err = a.Health(ctx)
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("Health with a refused JWT: %v, want permission denied", err)
	}
	if strings.Contains(err.Error(), bad) {
		t.Fatal("login error holds the JWT")
	}
}

// TestNamespaceHeaderAcceptedByDevMode: Vault community edition, which dev
// mode runs, has no namespaces and ignores X-Vault-Namespace. The adapter
// sends it (see TestNamespaceHeader for the requests) and labels secrets
// with it; here the store accepts the requests as they are.
func TestNamespaceHeaderAcceptedByDevMode(t *testing.T) {
	s := startServer(t)
	a := s.adapter(t, "vault-ns", map[string]any{"namespace": "team-a/eu", "auth.namespace": "team-a"})
	defer func() { _ = a.Close() }()
	ref := stores.Ref{Scheme: "vault-ns", Path: "secret/scrim-conformance/" + randHex(t, 6)}
	if _, err := a.Write(t.Context(), ref, map[string]secret.Value{"v": secret.FromString("ns_" + randHex(t, 8))}, stores.WriteOptions{}); err != nil {
		t.Fatalf("Write with a namespace: %v", err)
	}
	got, err := a.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("Read with a namespace: %v", err)
	}
	got.Wipe()
	if got.Meta.Labels["vault.namespace"] != "team-a/eu" || got.Meta.Labels["vault.namespaces.team-a"] != "true" {
		t.Errorf("namespace labels: %v", got.Meta.Labels)
	}
}

// grantFor creates a grant for a database credential that ends after ttl.
func grantFor(t *testing.T, svc *grant.Service, ref stores.Ref, ttl time.Duration) string {
	t.Helper()
	r := policy.Request{Agent: policy.Agent{ID: "agent-" + randHex(t, 3), Kind: policy.IdentitySession},
		Action: policy.ActionInject, Ref: ref, Host: "db.example.test"}
	g, err := grant.Build(r, policy.ScopeRequest, 0, ttl, "jit", "appr-"+randHex(t, 3), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Create(t.Context(), &g, "alice"); err != nil {
		t.Fatal(err)
	}
	return g.ID
}

func field(t *testing.T, s stores.Secret, name string) string {
	t.Helper()
	v, ok := s.Field(name)
	if !ok {
		t.Fatalf("field %s missing", name)
	}
	var out string
	_ = v.Expose(func(b []byte) error { out = string(b); return nil })
	return out
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestDynamicLeaseRevokedWhenGrantEnds is task 11a.1's verify step: a
// database credential issued for a grant is renewed past its TTL while the
// grant lasts, and its lease is revoked, and the PostgreSQL role dropped,
// as soon as the grant is revoked, or when it expires.
func TestDynamicLeaseRevokedWhenGrantEnds(t *testing.T) {
	s := startServer(t)
	s.setupDatabase(t)
	a := s.adapter(t, "vault-db", nil)
	defer func() { _ = a.Close() }()
	svc := grant.NewService(memstate.New(), nil)
	ref := stores.Ref{Scheme: "vault-db", Path: "database/creds/readonly"}
	ctx := t.Context()

	t.Run("revoked", func(t *testing.T) {
		id := grantFor(t, svc, ref, time.Hour)
		sec, lease, err := a.Issue(ctx, ref, svc.LeaseHolder(id))
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		user, pw := field(t, sec, "username"), field(t, sec, "password")
		for k, v := range sec.Meta.Labels {
			if strings.Contains(v, pw) || strings.Contains(k, pw) {
				t.Fatalf("label %s holds the password", k)
			}
		}
		if sec.Meta.Labels["vault.dynamic"] != "true" || sec.Meta.Labels["vault.engine"] != "database" ||
			sec.Meta.Labels["vault.lease_holder"] != "grant:"+id {
			t.Errorf("labels %v", sec.Meta.Labels)
		}
		sec.Wipe()
		if !s.pgRoleExists(t, user) {
			t.Fatal("issued role missing in PostgreSQL")
		}
		// The role's default TTL is 6s: alive at 9s means it was renewed.
		time.Sleep(9 * time.Second)
		if live, ttl := s.leaseLive(t, lease.ID); !live || ttl <= 0 {
			t.Fatalf("lease not renewed while the grant is active (live %v, ttl %s)", live, ttl)
		}
		if err := svc.Revoke(ctx, id, "alice", "done"); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "lease revoked after the grant was revoked", 5*time.Second, func() bool {
			live, _ := s.leaseLive(t, lease.ID)
			return !live
		})
		if s.pgRoleExists(t, user) {
			t.Error("PostgreSQL role still exists after revocation")
		}
		if len(a.Leases()) != 0 {
			t.Errorf("adapter still holds %v", a.Leases())
		}
	})

	t.Run("expired", func(t *testing.T) {
		id := grantFor(t, svc, ref, 3*time.Second)
		sec, lease, err := a.Issue(ctx, ref, svc.LeaseHolder(id))
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		user := field(t, sec, "username")
		sec.Wipe()
		waitFor(t, "lease revoked at grant expiry", 8*time.Second, func() bool {
			live, _ := s.leaseLive(t, lease.ID)
			return !live
		})
		if s.pgRoleExists(t, user) {
			t.Error("PostgreSQL role still exists after the grant expired")
		}
	})

	t.Run("released and closed", func(t *testing.T) {
		id := grantFor(t, svc, ref, time.Hour)
		sec, l1, err := a.Issue(ctx, ref, svc.LeaseHolder(id))
		if err != nil {
			t.Fatal(err)
		}
		sec.Wipe()
		if err := a.Release(ctx, "grant:"+id); err != nil {
			t.Fatalf("Release: %v", err)
		}
		if live, _ := s.leaseLive(t, l1.ID); live {
			t.Error("Release left the lease")
		}
		b := s.adapter(t, "vault-db2", nil)
		sec, l2, err := b.Issue(ctx, ref, svc.LeaseHolder(id))
		if err != nil {
			t.Fatal(err)
		}
		sec.Wipe()
		_ = b.Close()
		if live, _ := s.leaseLive(t, l2.ID); live {
			t.Error("Close left the lease")
		}
	})

	t.Run("ended holder refused", func(t *testing.T) {
		id := grantFor(t, svc, ref, time.Hour)
		if err := svc.Revoke(ctx, id, "alice", "done"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := a.Issue(ctx, ref, svc.LeaseHolder(id)); !errors.Is(err, stores.ErrPermission) {
			t.Fatalf("Issue for a revoked grant: %v", err)
		}
	})
}

// TestDynamicPathsAreNotKV: a dynamic path is not read, listed or written
// as a stored secret, and a credential issued without a lease is refused.
func TestDynamicPathsAreNotKV(t *testing.T) {
	s := startServer(t)
	a := s.adapter(t, "vault-dyn", nil)
	defer func() { _ = a.Close() }()
	ctx := t.Context()
	ref := stores.Ref{Scheme: "vault-dyn", Path: "pki/issue/unleased", Selectors: "common_name=app.example.test"}
	if _, err := a.Read(ctx, ref); !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("Read of a dynamic path: %v", err)
	}
	plain := stores.Ref{Scheme: ref.Scheme, Path: ref.Path}
	if _, err := a.Write(ctx, plain, map[string]secret.Value{"v": secret.FromString("x")}, stores.WriteOptions{}); !errors.Is(err, stores.ErrUnsupported) {
		t.Errorf("Write to a dynamic path: %v", err)
	}
	_, _, err := a.Issue(ctx, ref, stores.LeaseHolder{ID: "test"})
	if !errors.Is(err, stores.ErrUnsupported) || !strings.Contains(err.Error(), "without a lease") {
		t.Errorf("Issue without a lease: %v", err)
	}
	if _, _, err := a.Issue(ctx, stores.Ref{Scheme: "vault-dyn", Path: "secret/x"}, stores.LeaseHolder{ID: "test"}); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("Issue on KV: %v", err)
	}
}
