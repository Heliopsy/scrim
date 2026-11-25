// SPDX-License-Identifier: AGPL-3.0-only

package doppler

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// minter stands in for scrim's identity issuer.
type minter struct {
	mu  sync.Mutex
	jwt string
	n   int
}

func (m *minter) token() (secret.Value, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	return secret.FromString(m.jwt), nil
}

func (m *minter) count() int { m.mu.Lock(); defer m.mu.Unlock(); return m.n }

func federated(identity, key, session string, m *minter) stores.AgentCredential {
	return stores.AgentCredential{Agent: key, Federation: &stores.Federation{
		Method: stores.FederationDoppler, Params: map[string]string{"identity": identity, "audience": "doppler"},
		Audience: "doppler", Key: key, Session: session, Token: m.token}}
}

func static(tok string) stores.AgentCredential {
	return stores.AgentCredential{Agent: "laptop", Token: secret.FromString(tok)}
}

// TestAgentCanStaticToken: a Doppler token held for the agent decides
// reads with its own access: a service token opens its one config, a
// personal token is refused a restricted value; writes are not checked.
func TestAgentCanStaticToken(t *testing.T) {
	f, toks := newFake(t)
	val := "v-" + randID(8)
	f.put("billing/dev", "DB_PASSWORD", val, nil)
	f.put("billing/prd", "DB_PASSWORD", "v-"+randID(8), nil)
	f.put("billing/dev", "SIGNING_KEY", "v-"+randID(8), func(s *fakeSecret) { s.visibility = "restricted" })
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	ctx := t.Context()
	dev := static(toks[tokServiceDev])
	before := f.values()
	if err := a.AgentCan(ctx, dev, stores.OpRead, ref("billing/dev/DB_PASSWORD")); err != nil {
		t.Fatal(err)
	}
	if err := a.AgentCan(ctx, dev, stores.OpRead, ref("billing/prd/DB_PASSWORD")); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("service token for dev read prd: %v", err)
	} else {
		noValue(t, "refusal", err, toks[tokServiceDev], val)
	}
	if err := a.AgentCan(ctx, static(toks[tokPersonal]), stores.OpRead, ref("billing/dev/SIGNING_KEY")); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("restricted value withheld from a personal token: %v", err)
	}
	if err := a.AgentCan(ctx, dev, stores.OpRead, ref("billing/dev/MISSING")); !errors.Is(err, stores.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	if err := a.AgentCan(ctx, static("dp.st.dev."+randID(20)), stores.OpRead, ref("billing/dev/DB_PASSWORD")); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("unknown token: %v", err)
	}
	if err := a.AgentCan(ctx, dev, stores.OpWrite, ref("billing/dev/DB_PASSWORD")); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("write check: %v", err)
	}
	if got := f.values() - before; got != 2 {
		t.Fatalf("%d value responses, want 2 (the read allowed and the one withheld)", got)
	}
	if err := a.AgentCan(ctx, stores.AgentCredential{Agent: "laptop"}, stores.OpRead, ref("billing/dev/DB_PASSWORD")); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("no credential: %v", err)
	}
	kube := stores.AgentCredential{Agent: "k8s:agents/a", KubernetesJWT: secret.FromString("eyJ" + randID(10))}
	if err := a.AgentCan(ctx, kube, stores.OpRead, ref("billing/dev/DB_PASSWORD")); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("kubernetes passthrough: %v", err)
	}
	if f.oidcLogins != 0 || a.agents.Len() != 0 {
		t.Fatal("a static token triggered a login or was cached")
	}
}

// TestAgentCanOIDC: each agent logs in to its own service account
// identity with the token scrim signed for it; the identity's configs
// decide; the token is cached per agent until the session ends or Doppler
// stops accepting it; no token reaches an error.
func TestAgentCanOIDC(t *testing.T) {
	f, toks := newFake(t)
	f.put("billing/dev", "DB_PASSWORD", "v-"+randID(8), nil)
	f.put("billing/prd", "DB_PASSWORD", "v-"+randID(8), nil)
	jwtA, jwtB := "eyJ"+randID(24), "eyJ"+randID(24)
	f.oidc["ident-a"] = fakeIdentity{jwt: jwtA, configs: map[string]bool{"billing/prd": true}}
	f.oidc["ident-b"] = fakeIdentity{jwt: jwtB, configs: map[string]bool{"billing/dev": true}}
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	ctx := t.Context()
	prd, dev := ref("billing/prd/DB_PASSWORD"), ref("billing/dev/DB_PASSWORD")
	ma, mb := &minter{jwt: jwtA}, &minter{jwt: jwtB}
	ca, cb := federated("ident-a", "agent-a", "s1", ma), federated("ident-b", "agent-b", "s2", mb)

	if err := a.AgentCan(ctx, ca, stores.OpRead, prd); err != nil {
		t.Fatal(err)
	}
	if err := a.AgentCan(ctx, cb, stores.OpRead, prd); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("agent b read prd: %v", err)
	}
	if err := a.AgentCan(ctx, cb, stores.OpRead, dev); err != nil {
		t.Fatal(err)
	}
	if err := a.AgentCan(ctx, ca, stores.OpRead, prd); err != nil {
		t.Fatal(err)
	}
	if f.oidcLogins != 2 || ma.count() != 1 {
		t.Fatalf("logins %d, tokens minted for a %d: the login is not cached", f.oidcLogins, ma.count())
	}
	// A token for the wrong identity is refused at login.
	wrong := federated("ident-a", "agent-c", "", mb)
	if err := a.AgentCan(ctx, wrong, stores.OpRead, prd); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("token at another identity: %v", err)
	} else {
		noValue(t, "refused login", err, jwtA, jwtB)
	}
	// Doppler stops accepting the cached token: one more login.
	f.revokeOIDC()
	if err := a.AgentCan(ctx, ca, stores.OpRead, prd); err != nil {
		t.Fatalf("after revocation: %v", err)
	}
	if ma.count() != 2 {
		t.Fatalf("tokens minted for a %d, want 2", ma.count())
	}
	a.ForgetSession("s1")
	if err := a.AgentCan(ctx, ca, stores.OpRead, prd); err != nil {
		t.Fatal(err)
	}
	if ma.count() != 3 {
		t.Fatal("the session's token outlived the session")
	}
	other := federated("ident-a", "agent-a", "", ma)
	other.Federation.Method = stores.FederationInfisical
	if err := a.AgentCan(ctx, other, stores.OpRead, prd); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("another method: %v", err)
	}
	f.mu.Lock()
	for _, r := range f.requests {
		if strings.Contains(r, jwtA) || strings.Contains(r, jwtB) {
			t.Fatal("an identity token in a request line")
		}
	}
	f.mu.Unlock()
	if fm := a.FederationMethods(); len(fm) != 1 || fm[0] != stores.FederationDoppler {
		t.Fatalf("methods %v", fm)
	}
	_ = a.Close()
	if a.agents.Len() != 0 {
		t.Fatal("Close kept agent tokens")
	}
}
