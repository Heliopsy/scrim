// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/heliopsy/scrim/internal/identity"
)

// A caller another transport identified (the edge listener) is served as
// that caller: neither a session token in the request nor missing peer
// credentials change who it is.
func TestWithCallerIsTheCaller(t *testing.T) {
	s := &Server{}
	id := identity.Identity{Agent: "agents/reviewer", Source: identity.SourceKubernetes, Scopes: identity.AgentScopes}
	req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer scrim_st_aaaaaaaaaaaaaaaa_bbbb")
	req = req.WithContext(WithCaller(req.Context(), id))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var got identity.Identity
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("whoami: %d %s", rec.Code, rec.Body)
	}
	if got.Agent != id.Agent || got.Source != identity.SourceKubernetes {
		t.Errorf("whoami = %+v, want %s", got, id.Agent)
	}

	// Without the mark, the same request has no peer and is unknown.
	req = httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Known() {
		t.Errorf("a request without peer credentials or a mark was %+v", got)
	}
}
