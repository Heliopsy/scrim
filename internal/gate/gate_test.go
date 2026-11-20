// SPDX-License-Identifier: AGPL-3.0-only

package gate

import (
	"context"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
)

type rig struct {
	g    *Gate
	st   state.Store
	live *policy.Live
	apps *approval.Service
	bg   *breakglass.Switch
	rec  *notify.Recorder
}

func newRig(t *testing.T, cfg policy.Config) *rig {
	t.Helper()
	ctx := context.Background()
	st := memstate.New()
	bg, err := breakglass.New(ctx, st, false)
	if err != nil {
		t.Fatal(err)
	}
	live, err := policy.NewLive(cfg)
	if err != nil {
		t.Fatal(err)
	}
	limits := func(gs policy.GrantSettings) grant.Limits {
		l := grant.Limits{Default: 30 * time.Minute, Max: 8 * time.Hour}
		if gs.TTL > 0 {
			l.Default = gs.TTL.D()
		}
		if gs.MaxTTL > 0 && gs.MaxTTL.D() < l.Max {
			l.Max = gs.MaxTTL.D()
		}
		return l
	}
	rec := &notify.Recorder{NotifierName: "rec"}
	apps, err := approval.New(approval.Options{
		State: st, Notifiers: []notify.Notifier{rec}, Signer: approval.RandomSigner(), BreakGlass: bg,
		Timeout: time.Minute, PollInterval: 5 * time.Millisecond,
		Grants: func(rule string) (grant.Limits, policy.GrantSettings) {
			r, _ := live.Rule(rule)
			return limits(r.Grant), r.Grant
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bg.OnChange(func(active bool) {
		if active {
			_, _ = apps.DenyAllPending(context.Background(), "break-glass")
		}
	})
	g := &Gate{
		Engine: bg.Engine(live), Rules: live, Grants: grant.NewService(st, bg), Approvals: apps,
		BreakGlass: bg, State: st, Limits: limits,
	}
	return &rig{g: g, st: st, live: live, apps: apps, bg: bg, rec: rec}
}

var (
	hetzner = stores.MustParseRef("bao://kv/agents/hetzner")
	github  = stores.MustParseRef("bao://kv/agents/github")
	agentA  = policy.Agent{ID: "agent-a", Kind: policy.IdentitySession}
	agentB  = policy.Agent{ID: "agent-b", Kind: policy.IdentitySession}
)

func inject(a policy.Agent, ref stores.Ref, host, method string) policy.Request {
	return policy.Request{Agent: a, Action: policy.ActionInject, Ref: ref, Host: host, Method: method}
}

var rules = policy.Config{Rules: []policy.RuleSpec{
	{Name: "github-read", Decision: "allow", When: `secret.ref == "bao://kv/agents/github" && dest.method == "GET"`},
	{Name: "github-write", Decision: "ask", When: `secret.ref == "bao://kv/agents/github" && dest.method != "GET"`},
	{Name: "hetzner", Decision: "ask", When: `secret.ref == "bao://kv/agents/hetzner"`,
		Grant: policy.GrantSettings{TTL: policy.Duration(30 * time.Minute), Scope: policy.ScopeHost}},
	{Name: "secret-read", Decision: "allow", When: `op == "store.read"`, Grant: policy.GrantSettings{TTL: policy.Duration(10 * time.Minute)}},
	{Name: "no-unknown", Decision: "deny", When: `!agent.known`},
}}

// approveNext approves the next approval the notifier receives.
func (r *rig) approveNext(t *testing.T, n int, approve bool) {
	t.Helper()
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for len(r.rec.Sent()) < n && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		sent := r.rec.Sent()
		if len(sent) < n {
			t.Error("no notification")
			return
		}
		link := sent[n-1].DenyURL
		if approve {
			link = sent[n-1].ApproveURL
		}
		id, tok, _ := approval.TokenFromLink(link)
		if _, err := r.apps.DecideToken(context.Background(), id, tok); err != nil {
			t.Error(err)
		}
	}()
}

func TestGetInjectedPostWaitsForApproval(t *testing.T) {
	r := newRig(t, rules)
	ctx := context.Background()
	if v := r.g.Check(ctx, inject(agentA, github, "api.github.com", "GET"), Options{Wait: true}); !v.Allowed() || v.Rule != "github-read" {
		t.Fatalf("GET: %+v", v)
	}
	r.approveNext(t, 1, true)
	v := r.g.Check(ctx, inject(agentA, github, "api.github.com", "POST"), Options{Wait: true})
	if !v.Allowed() || v.ApprovalID == "" || v.GrantID == "" {
		t.Fatalf("approved POST: %+v", v)
	}
	// The grant covers the next POST without a new approval.
	v = r.g.Check(ctx, inject(agentA, github, "api.github.com", "POST"), Options{Wait: true})
	if !v.Allowed() || v.ApprovalID != "" || v.Reason != "covered by grant" {
		t.Fatalf("second POST: %+v", v)
	}
	if len(r.rec.Sent()) != 1 {
		t.Fatalf("%d notifications", len(r.rec.Sent()))
	}
	r.approveNext(t, 2, false)
	if v := r.g.Check(ctx, inject(agentB, github, "api.github.com", "POST"), Options{Wait: true}); v.Allowed() {
		t.Fatalf("agent B rode agent A's grant: %+v", v)
	}
}

func TestPendingWithoutWait(t *testing.T) {
	r := newRig(t, rules)
	ctx := context.Background()
	v := r.g.Check(ctx, inject(agentA, hetzner, "api.hetzner.cloud", "DELETE"), Options{})
	if v.Status != Pending || v.ApprovalID == "" {
		t.Fatalf("%+v", v)
	}
	if _, err := r.apps.Decide(ctx, v.ApprovalID, approval.Decision{Approve: true, By: "alice", Via: "terminal"}); err != nil {
		t.Fatal(err)
	}
	// The agent retries; the grant (host scope) lets it through.
	if v := r.g.Check(ctx, inject(agentA, hetzner, "api.hetzner.cloud", "GET"), Options{}); !v.Allowed() || v.GrantID == "" {
		t.Fatalf("retry: %+v", v)
	}
}

func TestDeniedOrTimedOutApprovalDenies(t *testing.T) {
	r := newRig(t, rules)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if v := r.g.Check(ctx, inject(agentA, hetzner, "api.hetzner.cloud", "GET"), Options{Wait: true}); v.Allowed() {
		t.Fatalf("cancelled wait allowed: %+v", v)
	}
}

func TestAllowWithDurationLeavesOneGrant(t *testing.T) {
	r := newRig(t, rules)
	ctx := context.Background()
	req := policy.Request{Agent: agentA, Action: policy.ActionRead, Ref: stores.MustParseRef("bao://kv/agents/notes")}
	v1 := r.g.Check(ctx, req, Options{})
	v2 := r.g.Check(ctx, req, Options{})
	if !v1.Allowed() || v1.GrantID == "" || v2.GrantID != v1.GrantID {
		t.Fatalf("%+v %+v", v1, v2)
	}
}

func TestDecisionsAreAudited(t *testing.T) {
	r := newRig(t, rules)
	ctx := context.Background()
	r.g.Check(ctx, inject(agentA, github, "api.github.com", "GET"), Options{})
	r.g.Check(ctx, inject(policy.Agent{}, github, "api.github.com", "GET"), Options{})
	var es int
	_ = r.st.View(ctx, func(tx state.Tx) error {
		got, err := tx.QueryAudit(ctx, state.AuditQuery{Action: ActionDecision})
		es = len(got)
		for _, e := range got {
			if e.Target != "api.github.com" || e.Ref != github {
				t.Errorf("entry %+v", e)
			}
		}
		return err
	})
	if es != 2 {
		t.Fatalf("%d decision entries", es)
	}
}

// TestBreakGlassEveryPathRefuses engages deny-all and checks every way the
// control plane can let something through: an allow rule, an existing
// grant, a new approval, deciding an approval already pending, issuing a
// grant, and the data-plane snapshot.
func TestBreakGlassEveryPathRefuses(t *testing.T) {
	r := newRig(t, rules)
	ctx := context.Background()
	// A grant from before deny-all, and a pending approval.
	pending := r.g.Check(ctx, inject(agentA, hetzner, "api.hetzner.cloud", "GET"), Options{})
	// Notifications are delivered asynchronously: wait for the first, so the
	// second one approveNext approves is the GitHub approval.
	for deadline := time.Now().Add(2 * time.Second); len(r.rec.Sent()) < 1 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	r.approveNext(t, 2, true)
	if v := r.g.Check(ctx, inject(agentA, github, "api.github.com", "POST"), Options{Wait: true}); !v.Allowed() {
		t.Fatalf("setup: %+v", v)
	}
	if err := r.bg.Engage(ctx, "oncall", "drill"); err != nil {
		t.Fatal(err)
	}
	paths := map[string]policy.Request{
		"allow rule":       inject(agentA, github, "api.github.com", "GET"),
		"existing grant":   inject(agentA, github, "api.github.com", "POST"),
		"new approval":     inject(agentB, hetzner, "api.hetzner.cloud", "GET"),
		"allow with grant": {Agent: agentA, Action: policy.ActionRead, Ref: hetzner},
	}
	for name, req := range paths {
		if v := r.g.Check(ctx, req, Options{Wait: true}); v.Allowed() || v.Rule != "break-glass" {
			t.Errorf("%s: %+v", name, v)
		}
	}
	if a, _ := r.apps.Get(ctx, pending.ApprovalID, ""); a.Status != state.ApprovalDenied {
		t.Errorf("pending approval is %s", a.Status)
	}
	if _, err := r.apps.Create(ctx, approval.Request{Policy: paths["new approval"]}); err == nil {
		t.Error("approval created")
	}
	g, _ := grant.Build(paths["new approval"], "", 0, time.Hour, "x", "", time.Now())
	if err := r.g.Grants.Create(ctx, &g, "alice"); err == nil {
		t.Error("grant issued")
	}
	snap := r.live.RuleSet().Snapshot(2, r.bg.Active())
	if res := snap.Evaluate(paths["allow rule"]); res.Outcome != policy.OutcomeDeny || !res.DenyAll {
		t.Errorf("data plane: %+v", res)
	}
	// Release needs an explicit action; then the old grant works again.
	if err := r.bg.Release(ctx, "oncall", "drill over"); err != nil {
		t.Fatal(err)
	}
	if v := r.g.Check(ctx, paths["existing grant"], Options{}); !v.Allowed() {
		t.Fatalf("after release: %+v", v)
	}
}

func TestUnauditableDecisionIsRefused(t *testing.T) {
	r := newRig(t, rules)
	r.g.State = failingStore{r.st}
	if v := r.g.Check(context.Background(), inject(agentA, github, "api.github.com", "GET"), Options{}); v.Allowed() {
		t.Fatalf("unaudited allow: %+v", v)
	}
}

type failingStore struct{ state.Store }

func (failingStore) Update(context.Context, func(state.Tx) error) error {
	return context.DeadlineExceeded
}
