// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// TestAgentCan: passthrough logs in with the agent's service account token
// at the rendered role, caches the login, and the role's capabilities on
// the KV v2 data path decide; a static agent token is used as is; neither
// token appears in an error.
func TestAgentCan(t *testing.T) {
	jwtA, jwtB := fakeJWT(), fakeJWT()
	var mu sync.Mutex
	logins := 0
	// role -> token, token -> readable path
	roles := map[string]string{"agents-a": "tok-role-a", "agents-b": "tok-role-b"}
	readable := map[string]string{"tok-role-a": "kv/data/agents/a/x", "tok-role-b": "kv/data/agents/b/x", "tok-static": "kv/data/laptop/k"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/auth/k8s-agents/login":
			var b struct{ Role, JWT string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			tok, ok := roles[b.Role]
			if !ok || (b.Role == "agents-a") != (b.JWT == jwtA) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":["permission denied for ` + b.JWT + `"]}`))
				return
			}
			logins++
			_, _ = w.Write([]byte(`{"auth":{"client_token":"` + tok + `","lease_duration":600,"renewable":true}}`))
		case "/v1/sys/capabilities-self":
			var b struct{ Paths []string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			caps := []string{"deny"}
			if readable[r.Header.Get("X-Vault-Token")] == b.Paths[0] {
				caps = []string{"read", "list"}
			}
			out := map[string][]string{"capabilities": caps, b.Paths[0]: caps}
			_ = json.NewEncoder(w).Encode(out)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	a := newTest(t, srv, nil, nil)
	ctx := t.Context()
	k8s := func(jwt, role string) stores.AgentCredential {
		return stores.AgentCredential{Agent: "k8s:x", KubernetesJWT: secret.FromString(jwt), Role: role, Mount: "k8s-agents"}
	}
	if err := a.AgentCan(ctx, k8s(jwtA, "agents-a"), stores.OpRead, stores.MustParseRef("bao://kv/agents/a/x")); err != nil {
		t.Fatalf("a on its path: %v", err)
	}
	if err := a.AgentCan(ctx, k8s(jwtA, "agents-a"), stores.OpRead, stores.MustParseRef("bao://kv/agents/b/x")); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("a on b's path: %v", err)
	}
	if logins != 1 {
		t.Fatalf("%d logins, want 1 (cached)", logins)
	}
	if err := a.AgentCan(ctx, k8s(jwtB, "agents-b"), stores.OpRead, stores.MustParseRef("bao://kv/agents/b/x")); err != nil {
		t.Fatalf("b: %v", err)
	}
	// A's token at B's role: the store refuses the login.
	err := a.AgentCan(ctx, k8s(jwtA, "agents-b"), stores.OpRead, stores.MustParseRef("bao://kv/agents/b/x"))
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("wrong role: %v", err)
	}
	for _, s := range []string{jwtA, jwtB, "tok-role"} {
		if strings.Contains(err.Error(), s) || strings.Contains(err.(*stores.Error).Detail, s) {
			t.Fatal("an error holds a token")
		}
	}
	static := stores.AgentCredential{Agent: "laptop", Token: secret.FromString("tok-static")}
	if err := a.AgentCan(ctx, static, stores.OpRead, stores.MustParseRef("bao://kv/laptop/k")); err != nil {
		t.Fatalf("static: %v", err)
	}
	if err := a.AgentCan(ctx, static, stores.OpWrite, stores.MustParseRef("bao://kv/laptop/k")); !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("static write without create/update: %v", err)
	}
	_ = a.Close()
}
