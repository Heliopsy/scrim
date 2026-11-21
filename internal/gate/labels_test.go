// SPDX-License-Identifier: AGPL-3.0-only

package gate

import (
	"context"
	"testing"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/stores"
)

var labelRules = policy.Config{Default: "allow", Rules: []policy.RuleSpec{
	{Name: "prod-collection", Decision: "deny", When: `"vaultwarden.collection.Prod" in secret.labels`},
}}

func prodLabels(ref stores.Ref) map[string]string {
	l := map[string]string{"store.name": ref.Scheme}
	if ref.Path == "prod/db" {
		l["vaultwarden.collection.Prod"] = "true"
	}
	return l
}

// TestCheckFillsSecretLabels: a request that names a secret is decided on
// the labels the control plane knows for it.
func TestCheckFillsSecretLabels(t *testing.T) {
	r := newRig(t, labelRules)
	ctx := context.Background()
	prod := stores.MustParseRef("vw://prod/db")
	write := policy.Request{Agent: agentA, Action: policy.ActionWrite, Ref: prod}
	if v := r.g.Check(ctx, write, Options{}); !v.Allowed() {
		t.Fatalf("without labels: %+v", v)
	}
	r.g.Labels = prodLabels
	if v := r.g.Check(ctx, write, Options{}); v.Allowed() || v.Rule != "prod-collection" {
		t.Fatalf("with labels: %+v", v)
	}
	write.Ref = stores.MustParseRef("vw://dev/db")
	if v := r.g.Check(ctx, write, Options{}); !v.Allowed() {
		t.Fatalf("dev: %+v", v)
	}
}

// TestAnswerIgnoresDataPlaneLabels: the control plane decides a data plane
// ask on its own labels for the secret, not the ones the ask carries.
func TestAnswerIgnoresDataPlaneLabels(t *testing.T) {
	r := newRig(t, labelRules)
	r.g.Labels = prodLabels
	a := injectAsk(1, "GET")
	a.Request.Ref = "vw://prod/db"
	a.Request.SecretLabels = map[string]string{"store.name": "vw"}
	if ans := r.g.Answer(context.Background(), a); ans.GetEffect() != pb.Effect_EFFECT_DENY {
		t.Fatalf("prod ask without its label allowed: %+v", ans)
	}
	a = injectAsk(2, "GET")
	a.Request.Ref = "vw://dev/db"
	a.Request.SecretLabels = map[string]string{"vaultwarden.collection.Prod": "true"}
	if ans := r.g.Answer(context.Background(), a); ans.GetEffect() != pb.Effect_EFFECT_ALLOW {
		t.Fatalf("dev ask with a forged label denied: %+v", ans)
	}
}
