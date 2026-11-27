// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/identity/kube"
)

type acceptReviewer struct{}

func (acceptReviewer) Review(context.Context, []byte) (kube.Account, error) {
	return kube.Account{Namespace: "agents", ServiceAccount: "writer"}, nil
}

// tokenWrites records the service account token each write check saw.
type tokenWrites struct{ seen []string }

func (w *tokenWrites) CheckWrite(ctx context.Context, _ identity.Identity, _ agenttools.Operation) (agenttools.WriteCheck, error) {
	w.seen = append(w.seen, string(identity.KubernetesTokenFrom(ctx)))
	return agenttools.WriteCheck{}, nil
}

// A pod calling with its service account token has that token at hand for
// the write check (Kubernetes passthrough), only for that request.
func TestKubernetesTokenReachesTheWriteCheck(t *testing.T) {
	e := agenttoolstest.NewEnv(t)
	w := &tokenWrites{}
	svc, err := agenttools.New(agenttools.Deps{Policy: e.Policy, Approvals: e.Approvals, Catalog: e.Store, Store: e.Store,
		Auditor: e.Audit, Writes: w})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Tools: svc, Resolver: identity.Resolver{Kubernetes: &identity.KubeResolver{Reviewer: acceptReviewer{}}}}
	const tok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
	req := httptest.NewRequest(http.MethodPost, "/v1/secrets/generate", strings.NewReader(`{"ref":"bao://kv/agents/new"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), peerKey, identity.Peer{UID: 1000, PID: 1}))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", rec.Code, rec.Body)
	}
	if len(w.seen) != 1 || w.seen[0] != tok {
		t.Fatalf("write check saw tokens %q", w.seen)
	}
}
