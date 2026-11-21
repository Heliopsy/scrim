// SPDX-License-Identifier: AGPL-3.0-only

package gate

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

var labelRules = policy.Config{Default: "allow", Rules: []policy.RuleSpec{
	{Name: "prod-collection", Decision: "deny", When: `"vaultwarden.collection.Prod" in secret.labels`},
}}

func prodLabels(_ context.Context, ref stores.Ref) (map[string]string, error) {
	l := map[string]string{"store.name": ref.Scheme}
	if ref.Path == "prod/db" {
		l["vaultwarden.collection.Prod"] = "true"
	}
	return l, nil
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

// TestWriteToExistingItemOutsideTheRedactionSet: a write to an item that
// exists in the store but is in no redaction set is decided on the item's
// stored labels, so "any write into this container asks" holds for it.
func TestWriteToExistingItemOutsideTheRedactionSet(t *testing.T) {
	r := newRig(t, policy.Config{Default: "allow", Rules: []policy.RuleSpec{
		{Name: "prod-writes", Decision: "ask", When: `op == "store.write" && "scrim.governed" in secret.labels`},
	}})
	mem := memstore.New("mem")
	existing := stores.MustParseRef("mem://team/db")
	if _, err := mem.Write(context.Background(), existing, map[string]secret.Value{"value": secret.FromString("v-0123456789abcdef")},
		stores.WriteOptions{Labels: map[string]string{"scrim.governed": "true"}}); err != nil {
		t.Fatal(err)
	}
	set := stores.NewSet()
	if err := set.Add(mem); err != nil {
		t.Fatal(err)
	}
	set.SetLabeling("mem", memstore.Kind, nil)
	r.g.Labels = func(ctx context.Context, ref stores.Ref) (map[string]string, error) {
		return refresh.SecretLabels(ctx, set, nil, ref)
	}
	write := policy.Request{Agent: agentA, Action: policy.ActionWrite, Ref: existing}
	if v := r.g.Check(context.Background(), write, Options{}); v.Status != Pending || v.Rule != "prod-writes" {
		t.Fatalf("write to the governed item: %+v", v)
	}
	write.Ref = stores.MustParseRef("mem://team/new")
	if v := r.g.Check(context.Background(), write, Options{}); !v.Allowed() {
		t.Fatalf("write to a new item: %+v", v)
	}
}

// TestLabelLookupFailureFailsClosed: when the store cannot say what a
// secret's labels are, deny and ask rules that read them match, allow rules
// that read them do not, rules that do not read them are unaffected, and
// the decision's audit entry names the failure.
func TestLabelLookupFailureFailsClosed(t *testing.T) {
	r := newRig(t, policy.Config{Default: "deny", Rules: []policy.RuleSpec{
		{Name: "prod-collection", Decision: "deny", When: `op == "store.write" && "vaultwarden.collection.Prod" in secret.labels`},
		{Name: "dev-allowed", Decision: "allow", When: `op == "inject" && "dev" in secret.labels`},
		{Name: "github", Decision: "allow", When: `op == "inject" && secret.ref.startsWith("vw://github")`},
	}})
	r.g.Labels = func(_ context.Context, ref stores.Ref) (map[string]string, error) {
		return map[string]string{"store.name": ref.Scheme}, errors.New("store vw: unavailable")
	}
	ctx := context.Background()
	write := policy.Request{Agent: agentA, Action: policy.ActionWrite, Ref: stores.MustParseRef("vw://dev/db")}
	if v := r.g.Check(ctx, write, Options{}); v.Allowed() || v.Rule != "prod-collection" {
		t.Fatalf("write with unknown labels: %+v", v)
	}
	inj := inject(agentA, stores.MustParseRef("vw://dev/db"), "api.example.test", "GET")
	if v := r.g.Check(ctx, inj, Options{}); v.Allowed() {
		t.Fatalf("an allow rule on unknown labels allowed: %+v", v)
	}
	inj.Ref = stores.MustParseRef("vw://github/token")
	if v := r.g.Check(ctx, inj, Options{}); !v.Allowed() || v.Rule != "github" {
		t.Fatalf("a rule without labels was affected: %+v", v)
	}
	var marked int
	_ = r.st.View(ctx, func(tx state.Tx) error {
		got, err := tx.QueryAudit(ctx, state.AuditQuery{Action: ActionDecision})
		for _, e := range got {
			if strings.Contains(e.Attrs["secret_labels"], "unknown: store vw: unavailable") {
				marked++
			}
		}
		return err
	})
	if marked != 3 {
		t.Fatalf("%d audit entries name the label failure, want 3", marked)
	}
}
