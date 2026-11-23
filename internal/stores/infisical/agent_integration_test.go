// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/identity/issuer"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// testAgentOIDC is 12.2b against a real Infisical: two machine identities
// with OIDC Auth trust scrim's identity issuer, each bound to one agent's
// subject. Agent a, whose identity may read the project, passes; agent b,
// whose identity is not a member, logs in but is refused the read; agent
// b's token is refused at agent a's identity. Infisical fetches the
// discovery document from a server this test runs on the host's address
// (host.containers.internal), which the pod allows with
// ALLOW_INTERNAL_IP_CONNECTIONS.
func testAgentOIDC(t *testing.T, adm *admin, main, other project, newInf func(testing.TB) *Adapter) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	issuerURL := fmt.Sprintf("http://host.containers.internal:%d", ln.Addr().(*net.TCPAddr).Port)
	iss, err := issuer.New(issuer.Options{URL: issuerURL, KeyDir: filepath.Join(t.TempDir(), "issuer")})
	if err != nil {
		t.Fatal(err)
	}
	defer iss.Close()
	srv := &http.Server{Handler: iss.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	const aud = "infisical-scrim-test"
	oidcIdentity := func(agent string) string {
		var idn struct {
			Identity struct{ ID string } `json:"identity"`
		}
		adm.must("POST", "/api/v1/identities", map[string]string{"name": "scrim-agent-" + agent + "-" + randID(3), "organizationId": adm.org, "role": "no-access"}, &idn)
		adm.must("POST", "/api/v1/auth/oidc-auth/identities/"+idn.Identity.ID, map[string]any{
			"oidcDiscoveryUrl": issuerURL, "boundIssuer": issuerURL, "boundAudiences": aud,
			"boundSubject": "agent:" + agent, "boundClaims": map[string]string{"agent": agent}, "accessTokenTTL": 600,
		}, nil)
		return idn.Identity.ID
	}
	idA, idB := oidcIdentity("agent-a"), oidcIdentity("agent-b")
	adm.member(main, idA, "viewer")
	adm.member(other, idB, "viewer")

	a := newInf(t)
	defer func() { _ = a.Close() }()
	ref := stores.Ref{Scheme: "inf", Path: main.slug + "/dev/AGENT_OIDC"}
	if _, err := a.Write(t.Context(), ref, map[string]secret.Value{Field: secret.FromString("v-" + randID(12))}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	cred := func(agent, identityID string) stores.AgentCredential {
		id := identity.Identity{Agent: agent, Source: identity.SourceSession, SessionID: "s-" + agent,
			ExpiresAt: time.Now().Add(time.Hour), Scopes: identity.AgentScopes}
		return stores.AgentCredential{Agent: id.Principal(), Federation: &stores.Federation{
			Method: stores.FederationInfisical, Params: map[string]string{"identity-id": identityID, "audience": aud},
			Audience: aud, Key: id.Principal() + "|" + identityID, Session: id.SessionID,
			Token: func() (secret.Value, error) { v, _, err := iss.Mint(id, aud); return v, err },
		}}
	}
	if err := a.AgentCan(t.Context(), cred("agent-a", idA), stores.OpRead, ref); err != nil {
		t.Fatalf("agent a, whose identity may read the project: %v", err)
	}
	err = a.AgentCan(t.Context(), cred("agent-b", idB), stores.OpRead, ref)
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("agent b, whose identity is not a member: %v", err)
	}
	t.Logf("agent b refused by Infisical: %v", err)
	err = a.AgentCan(t.Context(), cred("agent-b", idA), stores.OpRead, ref)
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("agent b's token at agent a's identity: %v", err)
	}
	t.Logf("agent b's token at agent a's identity: %v", err)
}
