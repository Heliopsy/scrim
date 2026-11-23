// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// Workload identity federation for agents is tested against the fake only:
// there is no Google STS or Secret Manager emulator, so these tests pin the
// requests the adapter sends (RFC 8693 form fields, the provider as
// audience, IAM Credentials impersonation, testIamPermissions) to what
// Google documents, not to the real service.

const testProvider = "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/scrim/providers/laptop"

func agentAdapter(t *testing.T, f *fake) *Adapter {
	t.Helper()
	inst := instance(f, map[string]any{"project": f.project, "auth.method": "access-token", "token": "env:T"},
		map[string]string{"env:T": f.token()})
	a, err := newAdapter(inst, nil, f.srv.URL+"/iam")
	if err != nil {
		t.Fatal(err)
	}
	a.c.auth.sts = f.srv.URL + "/sts"
	t.Cleanup(func() { _ = a.Close() })
	return a
}

type minter struct {
	jwt   string
	mints atomic.Int32
}

func (m *minter) fed(key, session string, params map[string]string) *stores.Federation {
	p := map[string]string{"provider": testProvider, "audience": "https:" + testProvider}
	for k, v := range params {
		p[k] = v
	}
	return &stores.Federation{Method: stores.FederationGCP, Params: p, Audience: p["audience"], Key: key, Session: session,
		SessionName: "agent", Token: func() (secret.Value, error) {
			m.mints.Add(1)
			return secret.FromString(m.jwt), nil
		}}
}

func agentCred(f *stores.Federation) stores.AgentCredential {
	return stores.AgentCredential{Agent: "agent", Federation: f}
}

func TestAgentFederation(t *testing.T) {
	f := newFake(t)
	f.stsAud = testProvider
	jwtA, jwtB := "eyJ.agent-a-"+randHex(16)+".sig", "eyJ.agent-b-"+randHex(16)+".sig"
	f.agentSubjects[jwtA], f.agentSubjects[jwtB] = "agent-a", "agent-b"
	f.grants["agent-a"], f.grants["agent-b"] = "agents--a--", "agents--b--"
	f.put("", "agents--a--key", []byte("va"))
	f.put("", "agents--b--key", []byte("vb"))
	a := agentAdapter(t, f)
	ctx := t.Context()
	ma, mb := &minter{jwt: jwtA}, &minter{jwt: jwtB}
	fa, fb := ma.fed("a", "s1", nil), mb.fed("b", "s2", nil)

	if err := a.AgentCan(ctx, agentCred(fa), stores.OpRead, ref("agents/a/key")); err != nil {
		t.Fatalf("agent a on its secret: %v", err)
	}
	err := a.AgentCan(ctx, agentCred(fa), stores.OpRead, ref("agents/b/key"))
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), permAccess) {
		t.Fatalf("agent a on b's secret: %v", err)
	}
	if err := a.AgentCan(ctx, agentCred(fb), stores.OpRead, ref("agents/b/key")); err != nil {
		t.Fatalf("agent b on its secret: %v", err)
	}
	if ma.mints.Load() != 1 || f.stsSeen != 2 {
		t.Fatalf("a minted %d identity tokens and STS saw %d exchanges; want one each per agent (cached)", ma.mints.Load(), f.stsSeen)
	}
	form := f.stsForms[0]
	for k, want := range map[string]string{
		"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "audience": testProvider, "scope": scope,
		"requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"subject_token_type":   "urn:ietf:params:oauth:token-type:jwt", "subject_token": jwtA,
	} {
		if form.Get(k) != want {
			t.Errorf("STS %s = %q, want %q", k, form.Get(k), want)
		}
	}
	if f.accesses != 0 {
		t.Fatalf("the agent check read %d secret values", f.accesses)
	}

	// Writes need versions.add.
	if err := a.AgentCan(ctx, agentCred(fa), stores.OpWrite, ref("agents/a/key")); !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), permAdd) {
		t.Fatalf("write without versions.add: %v", err)
	}
	f.mu.Lock()
	f.addGrants["agent-a"] = "agents--a--"
	f.mu.Unlock()
	if err := a.AgentCan(ctx, agentCred(fa), stores.OpWrite, ref("agents/a/key")); err != nil {
		t.Fatalf("write with versions.add: %v", err)
	}

	// A session's credentials are dropped when it ends.
	a.ForgetSession("s1")
	if err := a.AgentCan(ctx, agentCred(fa), stores.OpRead, ref("agents/a/key")); err != nil || ma.mints.Load() != 2 {
		t.Fatalf("after ForgetSession: %v, %d mints", err, ma.mints.Load())
	}

	// A provider STS does not trust refuses, without echoing a token.
	other := (&minter{jwt: jwtA}).fed("other", "", map[string]string{"provider": testProvider + "-other"})
	err = a.AgentCan(ctx, agentCred(other), stores.OpRead, ref("agents/a/key"))
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "STS") {
		t.Fatalf("wrong audience: %v", err)
	}
	f.mu.Lock()
	issued := slices.Clone(f.issued)
	f.mu.Unlock()
	for _, e := range []error{err} {
		for _, s := range append(issued, jwtA, jwtB) {
			if strings.Contains(e.Error(), s) {
				t.Fatal("an error quotes a token")
			}
		}
	}

	if err := a.AgentCan(ctx, stores.AgentCredential{Federation: &stores.Federation{Method: stores.FederationAzure, Key: "x"}},
		stores.OpRead, ref("agents/a/key")); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("another method: %v", err)
	}
	if got := a.FederationMethods(); !slices.Equal(got, []string{stores.FederationGCP}) {
		t.Fatalf("methods %v", got)
	}
}

func TestAgentFederationImpersonation(t *testing.T) {
	f := newFake(t)
	f.stsAud = testProvider
	jwt := "eyJ.agent-c-" + randHex(16) + ".sig"
	f.agentSubjects[jwt] = "agent-c"
	acct := "agent-c@scrim-test.iam.gserviceaccount.com"
	f.grants["sa:"+acct] = "agents--c--"
	// The federated principal itself holds nothing: only the service
	// account does, so a pass proves the impersonated token was used.
	f.put("", "agents--c--key", []byte("vc"))
	a := agentAdapter(t, f)
	m := &minter{jwt: jwt}
	fed := m.fed("c", "", map[string]string{"service-account": acct})
	err := a.AgentCan(t.Context(), agentCred(fed), stores.OpRead, ref("agents/c/key"))
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "impersonate") {
		t.Fatalf("impersonation not allowed: %v", err)
	}
	f.mu.Lock()
	f.impAllow[acct] = true
	f.mu.Unlock()
	if err := a.AgentCan(t.Context(), agentCred(fed), stores.OpRead, ref("agents/c/key")); err != nil {
		t.Fatalf("impersonated: %v", err)
	}
	if f.impSeen != 2 {
		t.Fatalf("generateAccessToken calls %d, want 2", f.impSeen)
	}
	bad := m.fed("d", "", map[string]string{"service-account": "../../x"})
	if err := a.AgentCan(t.Context(), agentCred(bad), stores.OpRead, ref("agents/c/key")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Fatalf("service account with a path: %v", err)
	}
}
