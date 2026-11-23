// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// minter stands in for scrim's identity issuer: it hands out jwt and
// counts the tokens minted.
type minter struct {
	mu  sync.Mutex
	jwt string
	n   int
	err error
}

func (m *minter) token() (secret.Value, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return secret.Value{}, m.err
	}
	m.n++
	return secret.FromString(m.jwt), nil
}

func (m *minter) count() int { m.mu.Lock(); defer m.mu.Unlock(); return m.n }

func federated(identityID, key, session string, m *minter) stores.AgentCredential {
	return stores.AgentCredential{Agent: key, Federation: &stores.Federation{
		Method: stores.FederationInfisical, Params: map[string]string{"identity-id": identityID, "audience": "infisical"},
		Audience: "infisical", Key: key, Session: session, Token: m.token}}
}

// TestAgentCanOIDC: each agent logs in with OIDC Auth at its own machine
// identity, presenting the token scrim signed for it; the identity's own
// permissions decide (a read refused, or a value Infisical hides, is a
// permission error; a missing secret stays not found); the login is
// cached per agent until the session ends; no token reaches an error.
func TestAgentCanOIDC(t *testing.T) {
	f := newFake(t)
	f.put("dev", "/", "DB_PASSWORD", "v-"+randID(8), nil)
	f.put("prod", "/", "DB_PASSWORD", "v-"+randID(8), nil)
	idA, idB := "a1a1a1a1-0000-4000-8000-"+randID(6), "b2b2b2b2-0000-4000-8000-"+randID(6)
	jwtA, jwtB := fakeJWT(), fakeJWT()
	f.oidcJWT[idA], f.oidcEnv[idA] = jwtA, "prod"
	f.oidcJWT[idB], f.oidcEnv[idB] = jwtB, "dev"
	a := newAdapter(t, f, nil)
	defer func() { _ = a.Close() }()
	ctx := t.Context()
	prod, dev := stores.MustParseRef("inf://proj/prod/DB_PASSWORD"), stores.MustParseRef("inf://proj/dev/DB_PASSWORD")
	ma, mb := &minter{jwt: jwtA}, &minter{jwt: jwtB}
	credA, credB := federated(idA, "agent-a/s1", "s1", ma), federated(idB, "agent-b/s2", "s2", mb)

	var errs []error
	if err := a.AgentCan(ctx, credA, stores.OpRead, prod); err != nil {
		t.Fatalf("agent a on prod: %v", err)
	}
	err := a.AgentCan(ctx, credB, stores.OpRead, prod)
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("agent b on prod: %v, want a permission refusal", err)
	}
	errs = append(errs, err)
	if err := a.AgentCan(ctx, credB, stores.OpRead, dev); err != nil {
		t.Fatalf("agent b on dev: %v", err)
	}
	err = a.AgentCan(ctx, credA, stores.OpRead, stores.MustParseRef("inf://proj/prod/MISSING"))
	if !errors.Is(err, stores.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	if got := f.oidcLogins; len(got) != 2 || got[0].IdentityID != idA || got[0].JWT != jwtA || got[1].IdentityID != idB || got[1].JWT != jwtB {
		t.Fatalf("logins %+v: want one per agent, each with its identity ID and token", got)
	}
	if ma.count() != 1 || mb.count() != 1 {
		t.Fatalf("minted %d and %d identity tokens, want one each (cached login)", ma.count(), mb.count())
	}

	// The session ends: its login is dropped and the next check logs in again.
	a.ForgetSession("s1")
	if err := a.AgentCan(ctx, credA, stores.OpRead, prod); err != nil || ma.count() != 2 {
		t.Fatalf("after the session ended: %v, minted %d", err, ma.count())
	}
	if mb.count() != 1 {
		t.Fatal("ForgetSession dropped another session's login")
	}

	// A value Infisical hides from the identity is a refusal.
	f.mu.Lock()
	f.maskForIdent[idB] = true
	f.mu.Unlock()
	err = a.AgentCan(ctx, credB, stores.OpRead, dev)
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("hidden value: %v", err)
	}
	errs = append(errs, err)

	// A token the identity does not accept, an unknown identity, a failed
	// mint: refused, nothing cached.
	bad := federated(idA, "agent-x", "", &minter{jwt: fakeJWT()})
	err = a.AgentCan(ctx, bad, stores.OpRead, prod)
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("rejected token: %v", err)
	}
	errs = append(errs, err)
	err = a.AgentCan(ctx, federated("c3c3c3c3-0000-4000-8000-000000000000", "agent-y", "", &minter{jwt: jwtA}), stores.OpRead, prod)
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("unknown identity: %v", err)
	}
	errs = append(errs, err)
	if err := a.AgentCan(ctx, federated(idA, "agent-z", "", &minter{err: errors.New("issuer off")}), stores.OpRead, prod); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("mint failure: %v", err)
	}

	// Writes cannot be checked without writing; other methods are not this store's.
	if err := a.AgentCan(ctx, credA, stores.OpWrite, prod); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("write: %v", err)
	}
	other := federated(idA, "k", "", ma)
	other.Federation.Method = stores.FederationJWT
	if err := a.AgentCan(ctx, other, stores.OpRead, prod); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("jwt method: %v", err)
	}

	f.mu.Lock()
	issued := append([]string(nil), f.issued...)
	f.mu.Unlock()
	for _, e := range errs {
		msg := fmt.Sprintf("%v %+v", e, e)
		for _, s := range append(issued, jwtA, jwtB) {
			if strings.Contains(msg, s) {
				t.Fatalf("error %q holds a token", msg)
			}
		}
		if strings.Contains(msg, "eyJ") {
			t.Fatalf("error %q holds a JWT", msg)
		}
	}
	_ = a.Close()
	if a.agents.Len() != 0 {
		t.Fatal("Close kept agent logins")
	}
}

// TestAgentCanStaticToken: a static Infisical access token held for the
// agent (identity.store-credentials) is used as is, without a login.
func TestAgentCanStaticToken(t *testing.T) {
	f := newFake(t)
	f.put("dev", "/", "K", "v-"+randID(8), nil)
	id := "d4d4d4d4-0000-4000-8000-" + randID(6)
	jwt := fakeJWT()
	f.oidcJWT[id], f.oidcEnv[id] = jwt, "dev"
	a := newAdapter(t, f, nil)
	defer func() { _ = a.Close() }()
	// Obtain a token for the identity as an operator would, then hold it.
	m := &minter{jwt: jwt}
	if err := a.AgentCan(t.Context(), federated(id, "op", "", m), stores.OpRead, stores.MustParseRef("inf://proj/dev/K")); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	tok := f.issued[len(f.issued)-1]
	f.mu.Unlock()
	before := len(f.oidcLogins)
	cred := stores.AgentCredential{Agent: "laptop", Token: secret.FromString(tok)}
	if err := a.AgentCan(t.Context(), cred, stores.OpRead, stores.MustParseRef("inf://proj/dev/K")); err != nil {
		t.Fatal(err)
	}
	if err := a.AgentCan(t.Context(), cred, stores.OpRead, stores.MustParseRef("inf://proj/prod/K")); !errors.Is(err, stores.ErrPermission) && !errors.Is(err, stores.ErrNotFound) {
		t.Fatalf("other environment: %v", err)
	}
	if len(f.oidcLogins) != before {
		t.Fatal("a static token triggered a login")
	}
	if fm := a.FederationMethods(); len(fm) != 1 || fm[0] != stores.FederationInfisical {
		t.Fatalf("methods %v", fm)
	}
}
