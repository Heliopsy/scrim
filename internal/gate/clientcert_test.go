// SPDX-License-Identifier: AGPL-3.0-only

package gate

import (
	"context"
	"fmt"
	"testing"
	"time"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/testing/certtest"
)

// TestAnswerCertificateCaller: the chain an ask carries is the caller, the
// rules see its agent and labels, two certificates get different decisions,
// and a certificate that fails verification or maps to no agent is unknown
// (never its Unix peer) with the reason audited.
func TestAnswerCertificateCaller(t *testing.T) {
	r := newRig(t, policy.Config{Rules: []policy.RuleSpec{
		{Name: "builders", Decision: "allow", When: `op == "inject" && agent.kind == "mtls" && agent.labels.spiffe_id.startsWith("spiffe://example.org/agents/")`},
		{Name: "no-reviewer", Decision: "deny", When: `agent.id == "reviewer"`},
		{Name: "no-unknown", Decision: "deny", When: `!agent.known`},
	}})
	peers, err := identity.NewPeerMap([]identity.PeerRule{{Agent: "dev", UIDs: []uint32{1000}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ca := certtest.NewCA(t, "agents CA")
	revoked := ca.Issue(t, certtest.Leaf{CN: "b2", SPIFFE: "spiffe://example.org/agents/builder"})
	trust, err := identity.ParseCertTrust(ca.PEM, [][]byte{ca.CRL(t, time.Time{}, revoked.Cert)})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := identity.CertRulesFromMap(map[string]string{
		"builder":  "spiffe:spiffe://example.org/agents/builder",
		"reviewer": "spiffe:spiffe://example.org/agents/reviewer",
	})
	if err != nil {
		t.Fatal(err)
	}
	r.g.Callers = &identity.Resolver{Peers: peers, Certificates: &identity.CertResolver{
		Trust: func() *identity.CertTrust { return trust }, Rules: rules}}
	ctx := context.Background()

	var id uint64
	ask := func(c certtest.Issued, unix bool) *pb.AskAnswer {
		id++
		a := injectAsk(id, "GET")
		a.Caller = &pb.AskCaller{ClientCertificateChain: [][]byte{c.Cert.Raw}}
		if unix {
			a.Caller.UnixPeer, a.Caller.PeerUid, a.Caller.PeerPid = true, 1000, 300
		}
		return r.g.Answer(ctx, a)
	}
	audited := func() map[string]string {
		var attrs map[string]string
		_ = r.st.View(ctx, func(tx state.Tx) error {
			es, err := tx.QueryAudit(ctx, state.AuditQuery{Action: ActionDecision})
			for _, e := range es {
				if e.RequestID == fmt.Sprintf("dp-%d", id) {
					attrs = e.Attrs
					attrs["agent"], attrs["kind"] = e.Agent.ID, string(e.Agent.Kind)
				}
			}
			return err
		})
		return attrs
	}

	builder := ca.Issue(t, certtest.Leaf{CN: "b1", SPIFFE: "spiffe://example.org/agents/builder"})
	if ans := ask(builder, false); ans.Effect != pb.Effect_EFFECT_ALLOW {
		t.Fatalf("builder: %+v", ans)
	}
	at := audited()
	if at["caller"] != CallerCert || at["agent"] != "builder" || at["kind"] != "mtls" ||
		at["spiffe_id"] != "spiffe://example.org/agents/builder" || at["cert_cn"] != "b1" || len(at["cert_sha256"]) != 64 {
		t.Fatalf("audit %v", at)
	}
	if ans := ask(ca.Issue(t, certtest.Leaf{CN: "r1", SPIFFE: "spiffe://example.org/agents/reviewer"}), false); ans.Effect != pb.Effect_EFFECT_DENY {
		t.Fatalf("reviewer: %+v", ans)
	}
	if at := audited(); at["caller"] != CallerCert || at["agent"] != "reviewer" {
		t.Fatalf("audit %v", at)
	}

	for name, tc := range map[string]struct {
		cert        certtest.Issued
		caller, why string
	}{
		"revoked":   {revoked, CallerRefused, string(identity.RefusedCertRevoked)},
		"untrusted": {certtest.NewCA(t, "x").Issue(t, certtest.Leaf{CN: "b", SPIFFE: "spiffe://example.org/agents/builder"}), CallerRefused, string(identity.RefusedCertUntrusted)},
		"unmapped":  {ca.Issue(t, certtest.Leaf{CN: "s", SPIFFE: "spiffe://example.org/agents/stranger"}), CallerUnmapped, ""},
	} {
		if ans := ask(tc.cert, true); ans.Effect != pb.Effect_EFFECT_DENY {
			t.Errorf("%s: allowed %+v", name, ans)
		}
		if at := audited(); at["caller"] != tc.caller || at["caller_reason"] != tc.why || at["agent"] != "" || len(at["cert_sha256"]) != 64 {
			t.Errorf("%s: audit %v", name, at)
		}
	}
}
