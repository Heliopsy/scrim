// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/heliopsy/scrim/internal/identity"
)

// The pod's token reaches the agent API with the request, so a store write
// can log in as the pod's service account, although the edge removes the
// header before passing the request on.
func TestAPIRequestCarriesThePodsToken(t *testing.T) {
	tok := fakeToken(t, "system:serviceaccount:agents:default")
	k := &fakeKube{tokens: map[string]identity.Identity{tok: kubeID("agents/default")}}
	var seen, header string
	s := &Server{Identify: k.identify, API: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, header = string(identity.KubernetesTokenFrom(r.Context())), r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})}
	req := httptest.NewRequest(http.MethodPost, "/v1/secrets/generate", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.api(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	if seen != tok || header != "" {
		t.Fatalf("API saw token %q, header %q", seen, header)
	}
}
