// SPDX-License-Identifier: AGPL-3.0-only

package gate

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/identity/kube"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// fakeReviewer accepts the tokens it knows.
type fakeReviewer map[string]kube.Account

func (f fakeReviewer) Review(_ context.Context, tok []byte) (kube.Account, error) {
	if a, ok := f[string(tok)]; ok {
		return a, nil
	}
	return kube.Account{}, kube.ErrNotAuthenticated
}

// storeAccess records what it was asked and refuses agents in deny.
type storeAccess struct {
	deny  map[string]bool
	calls []string
	toks  [][]byte
}

func (s *storeAccess) Check(_ context.Context, who identity.Identity, tok []byte, op stores.Op, ref stores.Ref) (string, error) {
	s.calls = append(s.calls, who.Agent+" "+string(op)+" "+ref.String())
	s.toks = append(s.toks, tok)
	if s.deny[who.Agent] {
		return "kubernetes", stores.NewError("bao", op, ref, stores.ErrPermission, nil)
	}
	return "kubernetes", nil
}

const (
	tokA = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2lnLWE"
	tokB = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiIn0.c2lnLWI"
	tokX = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnLXg"
)

// TestAnswerKubernetesCaller: a pod's service account token identifies it,
// the rules see its namespace and service account, a refused token is
// unknown (never its Unix peer), the store's answer for the agent's own
// identity is intersected with scrim's, and the token is wiped once the ask
// is answered.
func TestAnswerKubernetesCaller(t *testing.T) {
	r := newRig(t, policy.Config{Rules: []policy.RuleSpec{
		{Name: "agents-inject", Decision: "allow", When: `op == "inject" && agent.kind == "k8s" && agent.labels.namespace == "agents"`},
		{Name: "no-b", Decision: "deny", When: `agent.labels.service_account == "agent-b" && secret.ref == "bao://kv/agents/github"`},
		{Name: "no-unknown", Decision: "deny", When: `!agent.known`},
	}})
	peers, err := identity.NewPeerMap([]identity.PeerRule{{Agent: "dev", UIDs: []uint32{1000}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := identity.KubeRulesFromMap(map[string]string{"alpha": "sa:agents/agent-a label:team=x"})
	if err != nil {
		t.Fatal(err)
	}
	r.g.Callers = &identity.Resolver{Peers: peers, Kubernetes: &identity.KubeResolver{
		Reviewer: fakeReviewer{
			tokA: {Namespace: "agents", ServiceAccount: "agent-a", Pod: "pod-a"},
			tokB: {Namespace: "agents", ServiceAccount: "agent-b", Pod: "pod-b"},
		},
		Rules: rules,
	}}
	sa := &storeAccess{deny: map[string]bool{"agents/agent-b": true}}
	r.g.StoreAccess = sa
	ctx := context.Background()

	var id uint64
	ask := func(tok, ref string, unix bool) (*pb.AskAnswer, []byte) {
		id++
		a := injectAsk(id, "GET")
		a.Request.Ref = ref
		a.Caller = &pb.AskCaller{KubernetesToken: []byte(tok)}
		if unix {
			a.Caller.UnixPeer, a.Caller.PeerUid, a.Caller.PeerPid = true, 1000, 300
		}
		held := a.Caller.KubernetesToken
		return r.g.Answer(ctx, a), held
	}
	audited := func() map[string]string {
		var attrs map[string]string
		_ = r.st.View(ctx, func(tx state.Tx) error {
			es, err := tx.QueryAudit(ctx, state.AuditQuery{Action: ActionDecision})
			for _, e := range es {
				if e.RequestID == fmt.Sprintf("dp-%d", id) {
					attrs = e.Attrs
					attrs["agent"], attrs["kind"], attrs["reason"] = e.Agent.ID, string(e.Agent.Kind), e.Reason
				}
			}
			return err
		})
		return attrs
	}

	// Mapped service account: agent "alpha", labels from the token.
	ans, held := ask(tokA, "bao://kv/agents/github", false)
	if ans.Effect != pb.Effect_EFFECT_ALLOW {
		t.Fatalf("agent-a: %+v", ans)
	}
	at := audited()
	if at["caller"] != CallerKube || at["agent"] != "alpha" || at["kind"] != "k8s" || at["namespace"] != "agents" ||
		at["service_account"] != "agent-a" || at["pod"] != "pod-a" || at["store_identity"] != "kubernetes" {
		t.Fatalf("audit %v", at)
	}
	if !bytes.Equal(held, make([]byte, len(tokA))) {
		t.Fatal("the token was not wiped after the answer")
	}
	if len(sa.toks) != 1 || len(sa.toks[0]) != len(tokA) {
		t.Fatal("the store check did not get the token")
	}

	// Unmapped service account: derived name; scrim's rule denies the
	// github secret before the store is asked.
	calls := len(sa.calls)
	if ans, _ := ask(tokB, "bao://kv/agents/github", false); ans.Effect != pb.Effect_EFFECT_DENY {
		t.Fatalf("agent-b github: %+v", ans)
	}
	if at := audited(); at["agent"] != "agents/agent-b" || at["caller"] != CallerKube {
		t.Fatalf("audit %v", at)
	}
	if len(sa.calls) != calls {
		t.Fatal("a request scrim denies reached the store check")
	}
	// Scrim allows agent-b another secret, the store refuses its identity.
	ans, _ = ask(tokB, "bao://kv/agents/hetzner", false)
	if ans.Effect != pb.Effect_EFFECT_DENY {
		t.Fatalf("store refusal ignored: %+v", ans)
	}
	if at := audited(); at["store_identity"] != "kubernetes" || !containsAll(at["reason"], "store identity", "permission denied") {
		t.Fatalf("audit %v", at)
	}

	// A refused token is unknown, even over a Unix socket whose peer maps
	// to an agent.
	if ans, _ := ask(tokX, "bao://kv/agents/github", true); ans.Effect != pb.Effect_EFFECT_DENY {
		t.Fatalf("refused token allowed: %+v", ans)
	}
	if at := audited(); at["caller"] != CallerRefused || at["caller_reason"] != kube.ErrNotAuthenticated.Error() || at["agent"] != "" {
		t.Fatalf("audit %v", at)
	}
	// Kubernetes identity off: refused, not unknown-but-mapped.
	r.g.Callers.Kubernetes = nil
	if ans, _ := ask(tokA, "bao://kv/agents/github", true); ans.Effect != pb.Effect_EFFECT_DENY {
		t.Fatalf("token accepted without kubernetes identity: %+v", ans)
	}
	if at := audited(); at["caller_reason"] != string(identity.RefusedKubeDisabled) {
		t.Fatalf("audit %v", at)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !bytes.Contains([]byte(s), []byte(sub)) {
			return false
		}
	}
	return true
}
