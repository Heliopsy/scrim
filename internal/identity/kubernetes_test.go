// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"testing"

	"github.com/heliopsy/scrim/internal/identity/kube"
	"github.com/heliopsy/scrim/internal/policy"
)

type reviewer map[string]kube.Account

func (r reviewer) Review(_ context.Context, tok []byte) (kube.Account, error) {
	if a, ok := r[string(tok)]; ok {
		return a, nil
	}
	return kube.Account{}, kube.ErrWrongAudience
}

func TestKubeRulesFromMap(t *testing.T) {
	rules, err := KubeRulesFromMap(map[string]string{
		"reviewer": "sa:agents/reviewer label:team=platform",
		"ci":       "sa:ci/* sa:build/runner scope:secrets:list",
	})
	if err != nil || len(rules) != 2 || rules[0].Agent != "ci" || len(rules[0].Accounts) != 2 {
		t.Fatalf("%+v %v", rules, err)
	}
	for name, m := range map[string]map[string]string{
		"bad agent name":    {"Bad/Name": "sa:a/b"},
		"no sa":             {"a": "label:x=y"},
		"sa without slash":  {"a": "sa:agents"},
		"bad glob":          {"a": "sa:agents/[x"},
		"mint scope":        {"a": "sa:a/b scope:sessions:mint"},
		"token label":       {"a": "sa:a/b label:namespace=x"},
		"unknown selector":  {"a": "sa:a/b uid:1"},
		"selector no value": {"a": "sa:"},
	} {
		if _, err := KubeRulesFromMap(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKubeResolve(t *testing.T) {
	rules, err := KubeRulesFromMap(map[string]string{"reviewer": "sa:agents/rev* label:team=platform scope:secrets:list"})
	if err != nil {
		t.Fatal(err)
	}
	k := &KubeResolver{Reviewer: reviewer{
		"t-rev":   {Namespace: "agents", ServiceAccount: "reviewer", Pod: "rev-0", PodUID: "u0"},
		"t-other": {Namespace: "agents", ServiceAccount: "agent-a", Pod: "a-0"},
	}, Rules: rules}
	ctx := context.Background()
	id, err := k.Resolve(ctx, []byte("t-rev"))
	if err != nil || id.Agent != "reviewer" || id.Source != SourceKubernetes || !id.Has(ScopeSecretsList) || id.Has(ScopeSecretsWrite) {
		t.Fatalf("%+v %v", id, err)
	}
	pa := id.PolicyAgent()
	if pa.Kind != policy.IdentityK8s || pa.Labels["namespace"] != "agents" || pa.Labels["service_account"] != "reviewer" ||
		pa.Labels["pod"] != "rev-0" || pa.Labels["pod_uid"] != "u0" || pa.Labels["team"] != "platform" {
		t.Fatalf("policy agent %+v", pa)
	}
	if _, ok := pa.Labels["uid"]; ok {
		t.Fatal("a Kubernetes identity carries a uid label")
	}
	if id.Principal() != "k8s:reviewer" {
		t.Fatalf("principal %q", id.Principal())
	}
	// Spec scenario "Pod with a projected token": an unmapped account is
	// <namespace>/<name> with its pod attached.
	id, err = k.Resolve(ctx, []byte("t-other"))
	if err != nil || id.Agent != "agents/agent-a" || id.Labels[LabelPod] != "a-0" || !id.Has(ScopeSecretsWrite) || id.Has(ScopeSessionsMint) {
		t.Fatalf("%+v %v", id, err)
	}
	k.Unmapped = UnmappedUnknown
	if id, err := k.Resolve(ctx, []byte("t-other")); err != nil || id.Known() {
		t.Fatalf("unmapped unknown: %+v %v", id, err)
	}
	// Spec scenario "Token with the wrong audience": refused.
	_, err = k.Resolve(ctx, []byte("t-default"))
	if re, ok := IsRefused(err); !ok || re.Reason != RefusalReason(kube.ErrWrongAudience.Error()) {
		t.Fatalf("wrong audience: %v", err)
	}
}

// TestClaimWithKubernetesToken: a refused token is never retried as the
// Unix peer, and a session named next to a token wins (the token is not
// looked at).
func TestClaimWithKubernetesToken(t *testing.T) {
	peers, err := NewPeerMap([]PeerRule{{Agent: "dev", UIDs: []uint32{1000}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := Resolver{Peers: peers, Kubernetes: &KubeResolver{Reviewer: reviewer{"good": {Namespace: "n", ServiceAccount: "s"}}}}
	ctx := context.Background()
	unix := Peer{UID: 1000, PID: 1}
	id, err := r.ResolveClaim(ctx, TransportClaim{KubernetesToken: []byte("good"), UnixPeer: true, Peer: unix})
	if err != nil || id.Agent != "n/s" || id.Peer != unix {
		t.Fatalf("%+v %v", id, err)
	}
	id, err = r.ResolveClaim(ctx, TransportClaim{KubernetesToken: []byte("bad"), UnixPeer: true, Peer: unix})
	if _, ok := IsRefused(err); !ok || id.Known() {
		t.Fatalf("refused token fell back: %+v %v", id, err)
	}
	r.Kubernetes = nil
	if _, err := r.ResolveClaim(ctx, TransportClaim{KubernetesToken: []byte("good")}); err == nil {
		t.Fatal("token accepted with kubernetes identity off")
	}
	// The local API: a bearer JWT is a Kubernetes token, not a session.
	r.Kubernetes = &KubeResolver{Reviewer: reviewer{"eyJa.b.c": {Namespace: "n", ServiceAccount: "s"}}}
	if id, err := r.Resolve(ctx, unix, []byte("eyJa.b.c")); err != nil || id.Agent != "n/s" {
		t.Fatalf("bearer JWT: %+v %v", id, err)
	}
}
