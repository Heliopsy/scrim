// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// TestAgentCanJWT: with a token exchange credential the adapter mints the
// agent's identity token only when it has no cached login, logs in at the
// JWT mount and role, asks for the login token's capabilities on the API
// path the reference reads (KV v2 data path, KV v1 and dynamic paths as
// they are), caches the login per agent and options, and drops it when the
// session ends. Neither token reaches an error.
func TestAgentCanJWT(t *testing.T) {
	var mu sync.Mutex
	logins, mints := 0, 0
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/v1/auth/jwt-agents/login":
			if body["role"] != "agent-claude" || body["jwt"] != "id-token-claude" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":["role or jwt rejected: ` + body["jwt"].(string) + `"]}`))
				return
			}
			logins++
			_, _ = w.Write([]byte(`{"auth":{"client_token":"login-tok-claude","lease_duration":600}}`))
		case "/v1/sys/capabilities-self":
			p := body["paths"].([]any)[0].(string)
			asked = append(asked, p)
			caps := []string{"deny"}
			if r.Header.Get("X-Vault-Token") == "login-tok-claude" && !strings.Contains(p, "other") {
				caps = []string{"read"}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{p: caps, "capabilities": caps})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	a, err := New(stores.Instance{Name: "vault", Kind: Kind, Options: map[string]any{
		"address": srv.URL, "token": "test:token", "mounts.detect": false,
		"kv-v1-mounts": []any{"legacy"}, "dynamic-paths": []any{"database/creds"},
	}, Resolve: func(context.Context, config.SecretRef) (secret.Value, error) {
		return secret.FromString("root-tok"), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	cred := func(agent, session string) stores.AgentCredential {
		return stores.AgentCredential{Agent: agent, Federation: &stores.Federation{
			Method: stores.FederationJWT, Params: map[string]string{"role": "agent-" + agent, "mount": "jwt-agents"},
			Audience: "vault", Key: "jwt\x00" + agent + "\x00" + session, Session: session,
			Token: func() (secret.Value, error) {
				mu.Lock()
				mints++
				mu.Unlock()
				return secret.FromString("id-token-" + agent), nil
			}}}
	}
	ctx := t.Context()
	for _, ref := range []string{"vault://secret/team/db", "vault://legacy/team/db", "vault://database/creds/readonly"} {
		if err := a.AgentCan(ctx, cred("claude", "s1"), stores.OpRead, stores.MustParseRef(ref)); err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
	}
	if want := "secret/data/team/db,legacy/team/db,database/creds/readonly"; strings.Join(asked, ",") != want {
		t.Fatalf("capability paths %v, want %s", asked, want)
	}
	if logins != 1 || mints != 1 {
		t.Fatalf("%d logins and %d mints, want one of each (cached)", logins, mints)
	}
	if err := a.AgentCan(ctx, cred("claude", "s1"), stores.OpRead, stores.MustParseRef("vault://secret/other/db")); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("path the role may not read: %v", err)
	}
	a.ForgetSession("s1")
	if err := a.AgentCan(ctx, cred("claude", "s1"), stores.OpRead, stores.MustParseRef("vault://secret/team/db")); err != nil || logins != 2 {
		t.Fatalf("after the session ended: %v, %d logins", err, logins)
	}
	err = a.AgentCan(ctx, cred("intruder", "s2"), stores.OpRead, stores.MustParseRef("vault://secret/team/db"))
	if err == nil {
		t.Fatal("an agent without a role logged in")
	}
	if strings.Contains(err.Error(), "id-token") || strings.Contains(err.Error(), "login-tok") {
		t.Fatalf("an error holds a token: %v", err)
	}
	other := stores.AgentCredential{Agent: "x", Federation: &stores.Federation{Method: stores.FederationAWS, Key: "k"}}
	if err := a.AgentCan(ctx, other, stores.OpRead, stores.MustParseRef("vault://secret/team/db")); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("another method: %v", err)
	}
	if got := a.FederationMethods(); len(got) != 2 || got[0] != stores.LoginKubernetes || got[1] != stores.FederationJWT {
		t.Fatalf("methods %v", got)
	}
}
