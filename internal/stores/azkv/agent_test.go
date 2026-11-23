// SPDX-License-Identifier: AGPL-3.0-only

package azkv

import (
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// Entra ID federated credentials for agents are tested against the fake
// only: there is no Entra ID or Key Vault emulator, so these tests pin the
// client credentials request (client_assertion of type jwt-bearer, the
// vault's challenge scope, the tenant's token endpoint) and the read check
// to what Microsoft documents, not to the real service.

type minter struct {
	jwt   string
	mints atomic.Int32
}

func (m *minter) fed(f *fake, key, session string, params map[string]string) *stores.Federation {
	p := map[string]string{"tenant": f.tenant, "client-id": f.clientID, "authority": f.srv.URL, "audience": "api://AzureADTokenExchange"}
	for k, v := range params {
		p[k] = v
	}
	return &stores.Federation{Method: stores.FederationAzure, Params: p, Audience: p["audience"], Key: key, Session: session,
		Token: func() (secret.Value, error) {
			m.mints.Add(1)
			return secret.FromString(m.jwt), nil
		}}
}

func cred(fd *stores.Federation) stores.AgentCredential {
	return stores.AgentCredential{Agent: "agent", Federation: fd}
}

func kvRef(path string) stores.Ref { return stores.Ref{Scheme: "kv", Path: path} }

func TestAgentFederation(t *testing.T) {
	f := newFake(t)
	jwtA, jwtB := "eyJ.agent-a-"+randHex(16)+".sig", "eyJ.agent-b-"+randHex(16)+".sig"
	f.assertions[jwtA], f.assertions[jwtB] = true, true
	f.agentReads[jwtA], f.agentReads[jwtB] = nameOf("agents/a/"), nameOf("agents/b/")
	f.seed(nameOf("agents/a/key"), "va", nil, nil)
	f.seed(nameOf("agents/b/key"), "vb", nil, nil)
	a := f.adapter(t, "kv", nil)
	ctx := t.Context()
	ma, mb := &minter{jwt: jwtA}, &minter{jwt: jwtB}
	fa, fb := ma.fed(f, "a", "s1", nil), mb.fed(f, "b", "s2", nil)

	if err := a.AgentCan(ctx, cred(fa), stores.OpRead, kvRef("agents/a/key")); err != nil {
		t.Fatalf("agent a on its secret: %v", err)
	}
	err := a.AgentCan(ctx, cred(fa), stores.OpRead, kvRef("agents/b/key"))
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "Entra ID identity") {
		t.Fatalf("agent a on b's secret: %v", err)
	}
	if err := a.AgentCan(ctx, cred(fb), stores.OpRead, kvRef("agents/b/key")); err != nil {
		t.Fatalf("agent b on its secret: %v", err)
	}
	f.mu.Lock()
	forms := slices.Clone(f.forms)
	f.mu.Unlock()
	if ma.mints.Load() != 1 || len(forms) != 2 {
		t.Fatalf("a minted %d identity tokens, %d token requests; want one each per agent (cached)", ma.mints.Load(), len(forms))
	}
	for k, want := range map[string]string{
		"grant_type": "client_credentials", "client_id": f.clientID, "scope": f.resource + "/.default",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": jwtA,
	} {
		if forms[0].Get(k) != want {
			t.Errorf("token request %s = %q, want %q", k, forms[0].Get(k), want)
		}
	}
	if forms[0].Get("client_secret") != "" {
		t.Error("the agent's token request carries scrim's client secret")
	}

	// A session's credentials are dropped when it ends.
	a.ForgetSession("s1")
	if err := a.AgentCan(ctx, cred(fa), stores.OpRead, kvRef("agents/a/key")); err != nil || ma.mints.Load() != 2 {
		t.Fatalf("after ForgetSession: %v, %d mints", err, ma.mints.Load())
	}

	// An assertion without a federated credential is refused, without
	// echoing it.
	stranger := &minter{jwt: "eyJ.stranger-" + randHex(16) + ".sig"}
	err = a.AgentCan(ctx, cred(stranger.fed(f, "x", "", nil)), stores.OpRead, kvRef("agents/a/key"))
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "AADSTS700211") || strings.Contains(err.Error(), stranger.jwt) {
		t.Fatalf("unknown assertion: %v", err)
	}
	f.mu.Lock()
	issued := slices.Clone(f.issued)
	f.mu.Unlock()
	for _, tok := range append(issued, jwtA, jwtB) {
		if strings.Contains(err.Error(), tok) {
			t.Fatal("an error quotes a token")
		}
	}

	if err := a.AgentCan(ctx, cred(fa), stores.OpWrite, kvRef("agents/a/key")); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("write check: %v", err)
	}
	if err := a.AgentCan(ctx, cred(ma.fed(f, "t", "", map[string]string{"tenant": "../x"})), stores.OpRead, kvRef("agents/a/key")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Fatalf("tenant with a path: %v", err)
	}
	if err := a.AgentCan(ctx, stores.AgentCredential{Federation: &stores.Federation{Method: stores.FederationGCP, Key: "g"}},
		stores.OpRead, kvRef("agents/a/key")); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("another method: %v", err)
	}
	if got := a.FederationMethods(); !slices.Equal(got, []string{stores.FederationAzure}) {
		t.Fatalf("methods %v", got)
	}
}

// TestAgentFederationFirstCall: the first thing the adapter does is an
// agent check, so it learns the vault's challenge from an unauthenticated
// probe before it asks Entra ID for the agent's token.
func TestAgentFederationFirstCall(t *testing.T) {
	f := newFake(t)
	jwt := "eyJ.agent-" + randHex(16) + ".sig"
	f.assertions[jwt] = true
	f.agentReads[jwt] = nameOf("agents/")
	f.seed(nameOf("agents/key"), "v", nil, nil)
	a := f.adapter(t, "kv", nil)
	m := &minter{jwt: jwt}
	if err := a.AgentCan(t.Context(), cred(m.fed(f, "k", "", nil)), stores.OpRead, kvRef("agents/key")); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.forms) != 1 || f.forms[0].Get("scope") != f.resource+"/.default" {
		t.Fatalf("token requests %v", f.forms)
	}
}
