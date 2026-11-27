// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"errors"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// agentCred is a static per-agent credential as agentstore passes it: a
// fresh copy for each call.
func agentCred(agent, token string) stores.AgentCredential {
	return stores.AgentCredential{Agent: agent, Token: secret.FromString(token)}
}

// tokenParts splits an access token into its client secret and key part,
// for leak checks.
func tokenParts(tok string) (clientSecret, key string) {
	head, key, _ := strings.Cut(tok, ":")
	return head[strings.LastIndexByte(head, '.')+1:], key
}

type agentWorld struct {
	f           *fakeBWS
	a           *Adapter
	app, ops    string // project IDs
	appID       string // secret ID of app/DB
	value       string
	rw, ro      string // tokens of agents with read-write and read-only access to app
	none, alien string // no access; another organisation
	rwID, roID  string
}

func newAgentWorld(t *testing.T) *agentWorld {
	t.Helper()
	f := newFake(t)
	w := &agentWorld{f: f, value: "v_" + newUUID()}
	w.app = f.addProject("app", true)
	w.ops = f.addProject("ops", true)
	w.appID = f.put(w.app, "DB", secret.FromString(w.value))
	f.put(w.ops, "KEY", secret.FromString("o_"+newUUID()))
	w.rw, w.rwID = f.addAgent("")
	w.ro, w.roID = f.addAgent("")
	w.none, _ = f.addAgent("")
	var alienID string
	w.alien, alienID = f.addAgent(newUUID())
	f.grant(w.rwID, w.app, true)
	f.grant(w.roID, w.app, false)
	// The alien account is granted too, so only the organisation check
	// can refuse it.
	f.grant(alienID, w.app, true)
	w.a = newAdapter(t, f, nil)
	t.Cleanup(func() { _ = w.a.Close() })
	return w
}

func wantKind(t *testing.T, what string, err, kind error) {
	t.Helper()
	if !errors.Is(err, kind) {
		t.Errorf("%s: %v, want %v", what, err, kind)
	}
}

// TestAgentCan: the agent's own machine account decides. A read needs the
// secret to be readable by it, a write to an existing secret its write
// flag, a write that creates a secret write access to the project; an
// account of another organisation is refused; a missing secret stays not
// found.
func TestAgentCan(t *testing.T) {
	w := newAgentWorld(t)
	ctx := t.Context()
	db, dbNote, opsKey := ref("app/DB"), ref("app/DB").WithField(FieldNote), ref("ops/KEY")
	newApp, newOps := ref("app/NEW_"+newUUID()[:8]), ref("ops/NEW_"+newUUID()[:8])

	for _, c := range []struct {
		name string
		tok  string
		op   stores.Op
		r    stores.Ref
		want error
		hint string
	}{
		{"rw reads", w.rw, stores.OpRead, db, nil, ""},
		{"rw reads the note", w.rw, stores.OpRead, dbNote, nil, ""},
		{"rw reads by ID", w.rw, stores.OpRead, ref(w.appID), nil, ""},
		{"rw writes", w.rw, stores.OpWrite, db, nil, ""},
		{"rw creates in app", w.rw, stores.OpWrite, newApp, nil, ""},
		{"rw reads ops", w.rw, stores.OpRead, opsKey, stores.ErrPermission, "may not read"},
		{"rw writes ops", w.rw, stores.OpWrite, opsKey, stores.ErrPermission, "may not write"},
		{"rw creates in ops", w.rw, stores.OpWrite, newOps, stores.ErrPermission, "may not write"},
		{"ro reads", w.ro, stores.OpRead, db, nil, ""},
		{"ro writes", w.ro, stores.OpWrite, db, stores.ErrPermission, "may read this secret but not write it"},
		{"ro creates in app", w.ro, stores.OpWrite, newApp, stores.ErrPermission, "may read this project but not write it"},
		{"none reads", w.none, stores.OpRead, db, stores.ErrPermission, "may not read"},
		{"none reads the note", w.none, stores.OpRead, dbNote, stores.ErrPermission, "may not read"},
		{"none writes", w.none, stores.OpWrite, db, stores.ErrPermission, "may not write"},
		{"alien reads", w.alien, stores.OpRead, db, stores.ErrPermission, "another organization"},
		{"alien writes", w.alien, stores.OpWrite, db, stores.ErrPermission, "another organization"},
		{"missing key", w.rw, stores.OpRead, ref("app/MISSING"), stores.ErrNotFound, ""},
		{"missing ID read", w.rw, stores.OpRead, ref(newUUID()), stores.ErrNotFound, ""},
		{"missing ID write", w.rw, stores.OpWrite, ref(newUUID()), stores.ErrNotFound, ""},
		{"missing project", w.rw, stores.OpWrite, ref("nowhere/K"), stores.ErrNotFound, ""},
		{"unknown field", w.rw, stores.OpRead, ref("app/DB").WithField("x"), stores.ErrNotFound, ""},
	} {
		err := w.a.AgentCan(ctx, agentCred("agent-"+c.name, c.tok), c.op, c.r)
		if c.want == nil {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		wantKind(t, c.name, err, c.want)
		if c.hint != "" && err != nil && !strings.Contains(err.Error(), c.hint) {
			t.Errorf("%s: %v, want it to say %q", c.name, err, c.hint)
		}
	}
	// The agent checks created nothing and wrote nothing.
	if got := read(t, w.a, db); got != w.value {
		t.Errorf("value changed by a check: %q", got)
	}
	if _, err := w.a.ReadMetadata(ctx, newApp); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("a write check created %s: %v", newApp, err)
	}
}

// TestAgentCanCredentialKinds: no credential is a refusal; Kubernetes
// passthrough and token exchange are unsupported; a credential that is
// not an access token, or one Bitwarden does not know, is refused.
func TestAgentCanCredentialKinds(t *testing.T) {
	w := newAgentWorld(t)
	ctx := t.Context()
	db := ref("app/DB")
	wantKind(t, "no credential", w.a.AgentCan(ctx, stores.AgentCredential{Agent: "a"}, stores.OpRead, db), stores.ErrPermission)
	k8s := stores.AgentCredential{Agent: "a", KubernetesJWT: secret.FromString("jwt-" + newUUID()), Role: "r"}
	wantKind(t, "kubernetes", w.a.AgentCan(ctx, k8s, stores.OpRead, db), stores.ErrUnsupported)
	fed := stores.AgentCredential{Agent: "a", Federation: &stores.Federation{Method: stores.FederationJWT, Key: "a",
		Token: func() (secret.Value, error) { return secret.FromString("jwt"), nil }}}
	wantKind(t, "federation", w.a.AgentCan(ctx, fed, stores.OpRead, db), stores.ErrUnsupported)
	wantKind(t, "not a token", w.a.AgentCan(ctx, agentCred("a", "pw-"+newUUID()), stores.OpRead, db), stores.ErrPermission)
	unknown := "0." + newUUID() + ".s" + newUUID()[:20] + ":X8vbvA0bduihIDe/qrzIQQ=="
	err := w.a.AgentCan(ctx, agentCred("a", unknown), stores.OpRead, db)
	wantKind(t, "unknown token", err, stores.ErrPermission)
	if err != nil && !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("unknown token: %v, want Bitwarden's invalid_client", err)
	}
	if w.a.agents.Len() != 0 {
		t.Errorf("refused logins cached: %d", w.a.agents.Len())
	}
}

// TestAgentCanCachesLogin: an agent logs in once per access token; a
// rotated token logs in again; a bearer Bitwarden no longer accepts is
// dropped and the login made once more, and stays dropped when that login
// fails; Close wipes the cache. Static
// logins belong to no scrim session, so ForgetSession keeps them.
func TestAgentCanCachesLogin(t *testing.T) {
	w := newAgentWorld(t)
	ctx := t.Context()
	db := ref("app/DB")
	for range 3 {
		if err := w.a.AgentCan(ctx, agentCred("agent-rw", w.rw), stores.OpRead, db); err != nil {
			t.Fatal(err)
		}
	}
	if n := w.f.agentLoginCount(w.rwID); n != 1 {
		t.Fatalf("%d logins for three checks, want 1", n)
	}
	// Another principal with the same token, and the same principal with
	// another token, are separate logins.
	if err := w.a.AgentCan(ctx, agentCred("agent-other", w.rw), stores.OpRead, db); err != nil {
		t.Fatal(err)
	}
	if err := w.a.AgentCan(ctx, agentCred("agent-rw", w.ro), stores.OpRead, db); err != nil {
		t.Fatal(err)
	}
	if n, m := w.f.agentLoginCount(w.rwID), w.f.agentLoginCount(w.roID); n != 2 || m != 1 {
		t.Fatalf("logins rw=%d ro=%d, want 2 and 1", n, m)
	}
	if got := w.a.agents.Len(); got != 3 {
		t.Fatalf("%d cached logins, want 3", got)
	}

	w.f.revokeBearers()
	if err := w.a.AgentCan(ctx, agentCred("agent-rw", w.rw), stores.OpRead, db); err != nil {
		t.Fatalf("after the bearer was revoked: %v", err)
	}
	if n := w.f.agentLoginCount(w.rwID); n != 3 {
		t.Fatalf("%d logins after a 401, want one more (3)", n)
	}
	if err := w.a.AgentCan(ctx, agentCred("agent-rw", w.rw), stores.OpRead, db); err != nil {
		t.Fatal(err)
	}
	if n := w.f.agentLoginCount(w.rwID); n != 3 {
		t.Fatalf("the new login was not cached: %d logins", n)
	}

	// A revoked access token: the cached bearer is refused, the login
	// fails, and the bearer is not kept.
	w.f.revokeAgent(w.roID)
	err := w.a.AgentCan(ctx, agentCred("agent-rw", w.ro), stores.OpRead, db)
	wantKind(t, "revoked token", err, stores.ErrPermission)
	if got := w.a.agents.Len(); got != 2 {
		t.Fatalf("%d cached logins after a revoked token, want 2", got)
	}
	w.a.ForgetSession("s1")
	if got := w.a.agents.Len(); got != 2 {
		t.Errorf("ForgetSession dropped static logins: %d left", got)
	}
	_ = w.a.Close()
	if got := w.a.agents.Len(); got != 0 {
		t.Errorf("Close left %d cached logins", got)
	}
}

// TestAgentCanLeaks: no error names the agent's access token or its
// parts, or the secret's value; the value never leaves scrim and the
// agent's client secret only in its login form.
func TestAgentCanLeaks(t *testing.T) {
	w := newAgentWorld(t)
	ctx := t.Context()
	var errs []error
	for _, tok := range []string{w.rw, w.ro, w.none, w.alien} {
		for _, op := range []stores.Op{stores.OpRead, stores.OpWrite} {
			for _, r := range []stores.Ref{ref("app/DB"), ref("ops/KEY"), ref("app/NEW")} {
				errs = append(errs, w.a.AgentCan(ctx, agentCred("agent", tok), op, r))
			}
		}
	}
	bogus := "0." + newUUID() + ".bogus" + newUUID()[:12] + ":X8vbvA0bduihIDe/qrzIQQ=="
	errs = append(errs, w.a.AgentCan(ctx, agentCred("agent", bogus), stores.OpRead, ref("app/DB")))
	refused := 0
	for _, err := range errs {
		if err != nil {
			refused++
		}
		text := errText(err)
		for _, tok := range []string{w.rw, w.ro, w.none, w.alien, bogus} {
			cs, key := tokenParts(tok)
			if containsAny(text, tok, cs, key, w.value) {
				t.Errorf("error leaks a credential or the value: %s", text)
			}
		}
	}
	if refused == 0 {
		t.Fatal("no refusal to check")
	}
	if w.f.sawPlain(w.value) {
		t.Error("the secret's value went out in a request")
	}
	for _, tok := range []string{w.rw, w.ro, w.none, w.alien} {
		cs, _ := tokenParts(tok)
		w.f.mu.Lock()
		for _, r := range w.f.requests {
			if strings.Contains(r, cs) && !strings.HasPrefix(r, "POST /identity/connect/token ") {
				t.Errorf("an agent's client secret went out outside its login: %.40s", r)
			}
		}
		w.f.mu.Unlock()
	}
}
