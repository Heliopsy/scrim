// SPDX-License-Identifier: AGPL-3.0-only

package onepassword

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

func agentCred(tok string) stores.AgentCredential {
	return stores.AgentCredential{Agent: "agent-" + randHex(4), Token: secret.FromString(tok)}
}

// agentCalls returns the requests made since the log had n entries.
func agentCalls(f *fake, n int) []string { return f.requestLog()[n:] }

// TestAgentCanRead: the agent's own Connect access token decides, per vault:
// a token that may read the vault passes, one for other vaults, for writing
// only, an unknown one, and (where Connect answers so) a 404 are refused as
// permission errors; a missing item keeps scrim's not-found. The check lists
// item summaries only, so no response carrying a value is added, and neither
// token nor value reaches an error.
func TestAgentCanRead(t *testing.T) {
	f := newFake(t)
	prod, vals := seedFixture(t, f)
	dev := f.addVault("Dev")
	f.put(dev, map[string]any{"title": "db", "category": "PASSWORD",
		"fields": []any{map[string]any{"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "value": "dev-" + randHex(8)}}})
	reader := f.addToken(map[string]string{prod.ID: "r"})
	devOnly := f.addToken(map[string]string{dev.ID: "rw"})
	writer := f.addToken(map[string]string{prod.ID: "w"})
	unknown := "agent-connect-token-" + randHex(16)
	a := newAdapter(t, f, nil)
	ctx := t.Context()
	item := ref("Prod/GitHub/deploy#password")
	byID := ref(prod.ID + "/p7eflcy7f5mk7vg6zrzf5rjjyu#API/token")

	gets := f.gets()
	n := len(f.requestLog())
	if err := a.AgentCan(ctx, agentCred(reader), stores.OpRead, item); err != nil {
		t.Fatalf("token reading Prod, by title: %v", err)
	}
	if err := a.AgentCan(ctx, agentCred(reader), stores.OpRead, byID); err != nil {
		t.Fatalf("token reading Prod, by ID: %v", err)
	}
	if err := a.AgentCan(ctx, agentCred(devOnly), stores.OpRead, ref("Dev/db")); err != nil {
		t.Fatalf("token reading Dev: %v", err)
	}

	var errs []error
	refused := func(what, tok string) {
		t.Helper()
		err := a.AgentCan(ctx, agentCred(tok), stores.OpRead, item)
		if !errors.Is(err, stores.ErrPermission) {
			t.Fatalf("%s: %v, want a permission refusal", what, err)
		}
		if !strings.Contains(err.Error(), "Prod") {
			t.Errorf("%s: %q does not name the vault", what, err)
		}
		errs = append(errs, err)
	}
	refused("vault not in the agent's token", devOnly)
	refused("write-only token", writer)
	refused("unknown token", unknown)
	f.mu.Lock()
	f.echo = true
	f.mu.Unlock()
	refused("unknown token, quoted back by the server", unknown)
	f.mu.Lock()
	f.scopeStatus = http.StatusNotFound
	f.mu.Unlock()
	refused("vault outside the token answered with 404", devOnly)

	err := a.AgentCan(ctx, agentCred(reader), stores.OpRead, ref("Prod/missing"))
	if !errors.Is(err, stores.ErrNotFound) {
		t.Fatalf("missing item: %v", err)
	}
	errs = append(errs, err)

	if got := f.gets(); got != gets {
		t.Fatalf("the agent check fetched %d full items, want none", got-gets)
	}
	for _, c := range agentCalls(f, n) {
		if strings.Count(c, "/") > 4 || !strings.HasPrefix(c, "GET ") {
			t.Fatalf("the agent check made %q; want vault and item listings only", c)
		}
	}
	secrets := append(allValues(vals), f.token, reader, devOnly, writer, unknown)
	for _, e := range errs {
		noLeak(t, "agent check error", e, secrets...)
	}
}

// TestAgentCanMatchesByID: an item whose title another item in the vault
// shares is checked by its ID among the agent's summaries, not by title.
func TestAgentCanMatchesByID(t *testing.T) {
	f := newFake(t)
	v := f.addVault("Ops")
	one := f.put(v, map[string]any{"title": "dup", "category": "PASSWORD"})
	two := f.put(v, map[string]any{"title": "dup", "category": "PASSWORD"})
	tok := f.addToken(map[string]string{v.ID: "r"})
	a := newAdapter(t, f, nil)
	ctx := t.Context()
	for _, id := range []string{one, two} {
		if err := a.AgentCan(ctx, agentCred(tok), stores.OpRead, ref("Ops/"+id)); err != nil {
			t.Fatalf("item %s: %v", id, err)
		}
	}
	// The agent's listing still holds a "dup", but not this one.
	f.mu.Lock()
	f.unlisted[two] = true
	f.mu.Unlock()
	if err := a.AgentCan(ctx, agentCred(tok), stores.OpRead, ref("Ops/"+two)); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("item missing from the agent's listing: %v, want a permission refusal", err)
	}
	if err := a.AgentCan(ctx, agentCred(tok), stores.OpRead, ref("Ops/"+one)); err != nil {
		t.Fatalf("the other item: %v", err)
	}
}

// TestAgentCanRefusesUnchecked: writes, Kubernetes passthrough and token
// exchange are unsupported, a missing credential is a permission error, and
// none of them contacts Connect.
func TestAgentCanRefusesUnchecked(t *testing.T) {
	f := newFake(t)
	prod, vals := seedFixture(t, f)
	tok := f.addToken(map[string]string{prod.ID: "rw"})
	jwt := "eyJ" + randHex(24)
	a := newAdapter(t, f, nil)
	ctx := t.Context()
	item := ref("Prod/GitHub/deploy")
	n := len(f.requestLog())

	cases := []struct {
		name string
		cred stores.AgentCredential
		op   stores.Op
		kind error
	}{
		{"write", agentCred(tok), stores.OpWrite, stores.ErrUnsupported},
		{"no credential", stores.AgentCredential{Agent: "a"}, stores.OpRead, stores.ErrPermission},
		{"kubernetes", stores.AgentCredential{Agent: "a", KubernetesJWT: secret.FromString(jwt)}, stores.OpRead, stores.ErrUnsupported},
		{"federation", stores.AgentCredential{Agent: "a", Federation: &stores.Federation{Method: stores.FederationJWT,
			Token: func() (secret.Value, error) { return secret.FromString(jwt), nil }}}, stores.OpRead, stores.ErrUnsupported},
	}
	for _, c := range cases {
		err := a.AgentCan(ctx, c.cred, c.op, item)
		if !errors.Is(err, c.kind) {
			t.Errorf("%s: %v, want %v", c.name, err, c.kind)
		}
		noLeak(t, c.name, err, append(allValues(vals), tok, jwt, f.token)...)
	}
	if calls := agentCalls(f, n); len(calls) != 0 {
		t.Fatalf("refusals contacted Connect: %v", calls)
	}
	if slices.ContainsFunc(f.requestLog(), func(s string) bool { return !strings.HasPrefix(s, "GET ") }) {
		t.Fatal("a check wrote to Connect")
	}
}
