// SPDX-License-Identifier: AGPL-3.0-only

package openbao_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/identity/issuer"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/internal/podmantest"
)

// idpBao is an OpenBao dev server in the host's network namespace, so its
// JWT auth can fetch scrim's discovery document from 127.0.0.1.
type idpBao struct {
	addr, root string
}

func startIDPBao(t *testing.T) *idpBao {
	t.Helper()
	podmantest.Require(t)
	image := os.Getenv("SCRIM_TEST_OPENBAO_IMAGE")
	if image == "" {
		image = DefaultImage
	}
	b := &idpBao{root: randHex(t, 16)}
	c := podmantest.RunHostNetwork(t, "idp-openbao", image, map[string]string{"BAO_DEV_ROOT_TOKEN_ID": b.root},
		func(port int) []string {
			return []string{"server", "-dev", fmt.Sprintf("-dev-listen-address=127.0.0.1:%d", port)}
		})
	b.addr = fmt.Sprintf("http://127.0.0.1:%d", c.Port)
	podmantest.WaitHTTP(t, b.addr+"/v1/sys/health", 60*time.Second, func(c int) bool { return c == 200 })
	return b
}

// call sends a request with token (root when empty) and returns the status
// and decoded body.
func (b *idpBao) call(t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, b.addr+"/v1/"+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		token = b.root
	}
	if token != "-" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (b *idpBao) must(t *testing.T, method, path string, body any) {
	t.Helper()
	if code, out := b.call(t, method, path, "", body); code >= 300 {
		t.Fatalf("%s %s: %d %v", method, path, code, out)
	}
}

type testClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return time.Now().Add(c.off) }
func (c *testClock) set(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.off = d
}

// TestOpenBaoTrustsScrimIssuer is 12.2a's verification: OpenBao's JWT auth,
// configured with nothing but scrim's discovery URL, accepts a token scrim
// signs for the agent its role is bound to, and refuses another agent's,
// a wrong-audience and an expired token. After a key rotation it accepts
// tokens signed by the new key and still accepts one the old key signed.
func TestOpenBaoTrustsScrimIssuer(t *testing.T) {
	podmantest.Require(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuerURL := "http://" + ln.Addr().String()
	clk := &testClock{}
	var mintedMu sync.Mutex
	minted := 0
	iss, err := issuer.New(issuer.Options{URL: issuerURL, KeyDir: filepath.Join(t.TempDir(), "issuer"), Now: clk.now,
		TokenTTL: 5 * time.Minute, OnMint: func(v secret.Value, _ time.Time) {
			mintedMu.Lock()
			minted++
			mintedMu.Unlock()
			v.Wipe()
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iss.Close)
	srv := &http.Server{Handler: iss.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	bao := startIDPBao(t)
	const aud = "openbao-scrim-test"
	bao.must(t, http.MethodPost, "sys/auth/jwt", map[string]any{"type": "jwt"})
	// Only the discovery URL: OpenBao finds the JWKS through it.
	bao.must(t, http.MethodPost, "auth/jwt/config", map[string]any{"oidc_discovery_url": issuerURL, "bound_issuer": issuerURL})
	bao.must(t, http.MethodPut, "sys/policies/acl/claude-laptop", map[string]any{
		"policy": `path "kv/data/agents/claude-laptop/*" { capabilities = ["read"] }`})
	bao.must(t, http.MethodPost, "auth/jwt/role/claude-laptop", map[string]any{
		"role_type": "jwt", "user_claim": "sub", "bound_audiences": []string{aud},
		"bound_claims": map[string]any{"agent": "claude-laptop"}, "token_policies": []string{"claude-laptop"},
		"token_ttl": "5m", "token_no_default_policy": true,
	})

	login := func(t *testing.T, tok secret.Value) (int, map[string]any) {
		t.Helper()
		var jwt string
		_ = tok.Expose(func(b []byte) error { jwt = string(b); return nil })
		tok.Wipe()
		return bao.call(t, http.MethodPost, "auth/jwt/login", "-", map[string]any{"role": "claude-laptop", "jwt": jwt})
	}
	session := func(agent, sid string) identity.Identity {
		return identity.Identity{Agent: agent, Source: identity.SourceSession, SessionID: sid,
			ExpiresAt: time.Now().Add(24 * time.Hour), Scopes: identity.AgentScopes}
	}
	mint := func(t *testing.T, id identity.Identity, audience string) secret.Value {
		t.Helper()
		tok, _, err := iss.Mint(id, audience)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	policies := func(out map[string]any) []string {
		auth, _ := out["auth"].(map[string]any)
		var ps []string
		raw, _ := auth["token_policies"].([]any)
		for _, p := range raw {
			ps = append(ps, fmt.Sprint(p))
		}
		return ps
	}

	t.Run("accepted", func(t *testing.T) {
		code, out := login(t, mint(t, session("claude-laptop", "s-ok"), aud))
		if code != 200 || !slices.Equal(policies(out), []string{"claude-laptop"}) {
			t.Fatalf("login: %d %v", code, out)
		}
		meta, _ := out["auth"].(map[string]any)["metadata"].(map[string]any)
		if meta["role"] != "claude-laptop" {
			t.Fatalf("metadata %v", meta)
		}
	})
	t.Run("another agent", func(t *testing.T) {
		if code, out := login(t, mint(t, session("intruder", "s-other"), aud)); code == 200 {
			t.Fatalf("another agent's token logged in: %v", out)
		}
	})
	t.Run("wrong audience", func(t *testing.T) {
		code, out := login(t, mint(t, session("claude-laptop", "s-aud"), "another-store"))
		if code == 200 || !strings.Contains(fmt.Sprint(out["errors"]), "aud") {
			t.Fatalf("wrong-audience token: %d %v", code, out)
		}
	})
	t.Run("expired", func(t *testing.T) {
		// Minted an hour ago with a five-minute life: well past OpenBao's
		// expiry leeway.
		clk.set(-time.Hour)
		tok := mint(t, session("claude-laptop", "s-expired"), aud)
		clk.set(0)
		code, out := login(t, tok)
		if code == 200 || !strings.Contains(fmt.Sprint(out["errors"]), "exp") {
			t.Fatalf("expired token: %d %v", code, out)
		}
	})
	t.Run("rotation", func(t *testing.T) {
		before := mint(t, session("claude-laptop", "s-before"), aud)
		old, _ := iss.KeyIDs()
		if err := iss.Rotate(); err != nil {
			t.Fatal(err)
		}
		if code, out := login(t, mint(t, session("claude-laptop", "s-after"), aud)); code != 200 {
			t.Fatalf("token from the new key: %d %v", code, out)
		}
		if code, out := login(t, before); code != 200 {
			t.Fatalf("token the old key signed before the rotation: %d %v", code, out)
		}
		if cur, pub := iss.KeyIDs(); cur == old || !slices.Contains(pub, old) {
			t.Fatalf("rotation: signing %s published %v", cur, pub)
		}
	})
	mintedMu.Lock()
	defer mintedMu.Unlock()
	if minted != 6 {
		t.Fatalf("OnMint saw %d tokens, want every one of the 6 minted", minted)
	}
}
