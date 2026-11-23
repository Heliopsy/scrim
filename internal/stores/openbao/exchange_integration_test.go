// SPDX-License-Identifier: AGPL-3.0-only

package openbao_test

import (
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agentstore"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/identity/issuer"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/podmantest"
	"github.com/heliopsy/scrim/internal/stores/openbao"
)

// TestAgentsOwnOpenBaoIdentityByTokenExchange is 12.2b's OpenBao
// verification: with `identity.store-login: jwt ...`, scrim logs in to
// OpenBao as each agent with a token its issuer signs, and OpenBao's policy
// for that agent decides. Two agents that scrim's rules would both allow
// get different answers: claude-laptop's role may read the secret,
// intruder's may not, and an agent OpenBao has no role for is refused at
// login. scrim's own identity still reads the value, so redaction never
// depends on the agent's (specs/agent-identity "Redaction coverage is
// separate from use").
func TestAgentsOwnOpenBaoIdentityByTokenExchange(t *testing.T) {
	podmantest.Require(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuerURL := "http://" + ln.Addr().String() + "/idp"
	var minted []string
	iss, err := issuer.New(issuer.Options{URL: issuerURL, KeyDir: filepath.Join(t.TempDir(), "issuer"),
		OnMint: func(v secret.Value, _ time.Time) {
			_ = v.Expose(func(b []byte) error { minted = append(minted, string(b)); return nil })
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
	bao.must(t, http.MethodPost, "sys/mounts/kv", map[string]any{"type": "kv", "options": map[string]any{"version": "2"}})
	secretValue := randHex(t, 20)
	bao.must(t, http.MethodPost, "kv/data/agents/shared/db", map[string]any{"data": map[string]any{"password": secretValue}})
	bao.must(t, http.MethodPost, "sys/auth/jwt-agents", map[string]any{"type": "jwt"})
	bao.must(t, http.MethodPost, "auth/jwt-agents/config", map[string]any{"oidc_discovery_url": issuerURL, "bound_issuer": issuerURL})
	bao.must(t, http.MethodPut, "sys/policies/acl/shared-db", map[string]any{
		"policy": `path "kv/data/agents/shared/*" { capabilities = ["read"] }`})
	bao.must(t, http.MethodPut, "sys/policies/acl/own-tree", map[string]any{
		"policy": `path "kv/data/agents/intruder/*" { capabilities = ["read"] }`})
	for agent, policy := range map[string]string{"claude-laptop": "shared-db", "intruder": "own-tree"} {
		bao.must(t, http.MethodPost, "auth/jwt-agents/role/agent-"+agent, map[string]any{
			"role_type": "jwt", "user_claim": "sub", "bound_audiences": []string{"openbao"},
			"bound_claims": map[string]any{"agent": agent}, "token_policies": []string{policy}, "token_ttl": "5m",
		})
	}

	a, err := openbao.New(stores.Instance{Name: "bao", Kind: openbao.Kind,
		Options: map[string]any{"address": bao.addr, "auth": map[string]any{"method": "token"}, "token": "test:root", "timeout": "5s"},
		Resolve: resolver(map[string]string{"test:root": bao.root})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	set := stores.NewSet()
	if err := set.Add(a); err != nil {
		t.Fatal(err)
	}
	c, err := agentstore.New(agentstore.Options{
		Login:  map[string]string{"bao": "jwt role:agent-{agent_slug} audience:openbao mount:jwt-agents"},
		Lookup: set.Lookup, Issuer: iss, RequireIssuer: true,
		Adapter: func(n string) (stores.Adapter, bool) { return a, n == "bao" },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	ref := stores.MustParseRef("bao://kv/agents/shared/db")
	session := func(agent, sid string) identity.Identity {
		return identity.Identity{Agent: agent, Source: identity.SourceSession, SessionID: sid,
			ExpiresAt: time.Now().Add(time.Hour), Scopes: identity.AgentScopes}
	}

	src, err := c.Check(ctx, session("claude-laptop", "s-laptop"), nil, stores.OpRead, ref)
	if err != nil || src != agentstore.SourceFederated {
		t.Fatalf("claude-laptop, whose OpenBao role may read the secret: %s %v", src, err)
	}
	_, err = c.Check(ctx, session("intruder", "s-intruder"), nil, stores.OpRead, ref)
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("intruder, whose OpenBao role may not: %v", err)
	}
	t.Logf("intruder refused by OpenBao's policy: %v", err)
	denied := err.Error()
	_, err = c.Check(ctx, session("nobody", "s-nobody"), nil, stores.OpRead, ref)
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("an agent OpenBao has no role for: %v", err)
	}
	// The login is cached for the session; the session ending drops it,
	// and the next use logs in again with a fresh token.
	n := len(minted)
	if _, err := c.Check(ctx, session("claude-laptop", "s-laptop"), nil, stores.OpRead, ref); err != nil {
		t.Fatal(err)
	}
	a.ForgetSession("s-laptop")
	iss.Forget("s-laptop")
	if _, err := c.Check(ctx, session("claude-laptop", "s-laptop"), nil, stores.OpRead, ref); err != nil {
		t.Fatal(err)
	}
	if len(minted) != n+1 {
		t.Fatalf("minted %d tokens after the session ended, want one new login", len(minted)-n)
	}

	// scrim's own identity still reads the value for the redaction set.
	sec, err := a.Read(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer sec.Wipe()
	var got string
	_ = sec.Fields["password"].Expose(func(b []byte) error { got = string(b); return nil })
	if got != secretValue {
		t.Fatal("scrim's own read did not return the value")
	}
	for _, tok := range minted {
		if strings.Contains(denied, tok) || strings.Contains(denied, tok[len(tok)-30:]) {
			t.Fatal("an identity token reached an error")
		}
	}
}
