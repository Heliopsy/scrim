// SPDX-License-Identifier: AGPL-3.0-only

package approval

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	st   state.Store
	svc  *Service
	rec  *notify.Recorder
	clk  *clock
	bg   *breakglass.Switch
	req  policy.Request
	dec  policy.Decision
	ctx  context.Context
	opts Options
}

func newFixture(t *testing.T, mutate ...func(*Options)) *fixture {
	t.Helper()
	ctx := context.Background()
	st := memstate.New()
	bg, err := breakglass.New(ctx, st, false)
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	rec := &notify.Recorder{NotifierName: "rec"}
	o := Options{
		State: st, Notifiers: []notify.Notifier{rec}, Signer: RandomSigner(), BreakGlass: bg,
		PublicURL: "https://scrim.example", Timeout: time.Minute, PollInterval: 5 * time.Millisecond, Now: clk.Now,
		Grants: func(string) (grant.Limits, policy.GrantSettings) {
			return grant.Limits{Default: 30 * time.Minute, Max: time.Hour}, policy.GrantSettings{Uses: 2}
		},
	}
	for _, m := range mutate {
		m(&o)
	}
	svc, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		st: st, svc: svc, rec: rec, clk: clk, bg: bg, ctx: ctx, opts: o,
		req: policy.Request{Agent: policy.Agent{ID: "claude-laptop", Kind: policy.IdentitySession},
			Action: policy.ActionInject, Ref: stores.MustParseRef("bao://kv/agents/github"), Host: "api.github.com", Method: "POST", Path: "/repos/a/b/issues"},
		dec: policy.Decision{Effect: policy.Ask, Rule: "github-write", Reason: "writes to GitHub need a human", GrantTTL: 10 * time.Minute},
	}
}

func (f *fixture) create(t *testing.T) *state.Approval {
	t.Helper()
	a, err := f.svc.Create(f.ctx, Request{Policy: f.req, Decision: f.dec})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *fixture) sent(t *testing.T, n int) []notify.Request {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s := f.rec.Sent(); len(s) >= n {
			return s
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("notifier got %d requests, want %d", len(f.rec.Sent()), n)
	return nil
}

func (f *fixture) audit(t *testing.T, action string) int {
	t.Helper()
	n := 0
	_ = f.st.View(f.ctx, func(tx state.Tx) error {
		es, err := tx.QueryAudit(f.ctx, state.AuditQuery{Action: action})
		n = len(es)
		return err
	})
	return n
}

func TestApproveByLinkCreatesGrantAndReleasesWaiter(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	if a.Status != state.ApprovalPending || !a.ExpiresAt.Equal(f.clk.Now().Add(time.Minute)) {
		t.Fatalf("created %+v", a)
	}
	n := f.sent(t, 1)[0]
	if n.ApprovalID != a.ID || n.Rule != "github-write" || !strings.HasPrefix(n.ApproveURL, "https://scrim.example/v1/approvals/"+a.ID+"/decide?t=") {
		t.Fatalf("notification %+v", n)
	}
	done := make(chan state.Approval)
	go func() {
		got, err := f.svc.Wait(f.ctx, a.ID)
		if err != nil {
			t.Error(err)
		}
		done <- got
	}()
	id, tok, err := TokenFromLink(n.ApproveURL)
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.svc.DecideToken(f.ctx, id, tok)
	if err != nil {
		t.Fatal(err)
	}
	if out.Approval.Status != state.ApprovalApproved || out.Approval.DecidedBy != "link:rec" || out.Grant == nil {
		t.Fatalf("outcome %+v", out)
	}
	g := out.Grant
	if g.Agent.ID != "claude-laptop" || g.Ref != f.req.Ref || g.MaxUses != 2 || g.ApprovalID != a.ID ||
		!g.ExpiresAt.Equal(f.clk.Now().Add(10*time.Minute)) || len(g.Scope.Hosts) != 1 || g.Scope.Hosts[0] != "api.github.com" {
		t.Fatalf("grant %+v", g)
	}
	select {
	case got := <-done:
		if got.Status != state.ApprovalApproved {
			t.Fatalf("waiter got %s", got.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter not released")
	}
	for _, action := range []string{ActionCreated, ActionApproved, grant.ActionCreated} {
		if f.audit(t, action) != 1 {
			t.Errorf("audit %s missing", action)
		}
	}
}

func TestSecondUseOfAnyLinkIsRejected(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	n := f.sent(t, 1)[0]
	_, approveTok, _ := TokenFromLink(n.ApproveURL)
	_, denyTok, _ := TokenFromLink(n.DenyURL)
	if _, err := f.svc.DecideToken(f.ctx, a.ID, denyTok); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{denyTok, approveTok} {
		if _, err := f.svc.DecideToken(f.ctx, a.ID, tok); !errors.Is(err, ErrSettled) {
			t.Fatalf("replay accepted: %v", err)
		}
	}
	got, _ := f.svc.Get(f.ctx, a.ID, "")
	if got.Status != state.ApprovalDenied {
		t.Fatalf("status changed by replay: %s", got.Status)
	}
	if gs, _ := grant.NewService(f.st, nil).List(f.ctx, "", false); len(gs) != 0 {
		t.Fatalf("denied approval left grants: %+v", gs)
	}
}

func TestTokenForAnotherApprovalAndForgeryRejected(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	b := f.create(t)
	n := f.sent(t, 2)
	var aTok string
	for _, r := range n {
		if r.ApprovalID == a.ID {
			_, aTok, _ = TokenFromLink(r.ApproveURL)
		}
	}
	if _, err := f.svc.DecideToken(f.ctx, b.ID, aTok); !errors.Is(err, ErrTokenMismatch) {
		t.Fatalf("A's token settled B: %v", err)
	}
	forged, _ := RandomSigner().Mint(b.ID, ActionApprove, f.clk.Now().Add(time.Minute), "")
	if _, err := f.svc.DecideToken(f.ctx, b.ID, forged); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("forged token accepted: %v", err)
	}
	for _, id := range []string{a.ID, b.ID} {
		if got, _ := f.svc.Get(f.ctx, id, ""); got.Status != state.ApprovalPending {
			t.Fatalf("%s moved to %s", id, got.Status)
		}
	}
	if f.audit(t, "approval.token_rejected") != 2 {
		t.Fatal("rejected tokens not audited")
	}
}

func TestExpiredLinkRefused(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	_, tok, _ := TokenFromLink(f.sent(t, 1)[0].ApproveURL)
	f.clk.Add(time.Minute)
	if _, err := f.svc.DecideToken(f.ctx, a.ID, tok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired link accepted: %v", err)
	}
	// A terminal decision after the deadline expires the approval instead.
	if _, err := f.svc.Decide(f.ctx, a.ID, Decision{Approve: true, By: "alice", Via: "terminal"}); !errors.Is(err, ErrExpired) {
		t.Fatalf("late decision accepted: %v", err)
	}
	if got, _ := f.svc.Get(f.ctx, a.ID, ""); got.Status != state.ApprovalExpired {
		t.Fatalf("status %s, want expired", got.Status)
	}
}

func TestNobodyAnswersTimeoutDenies(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.Now = nil; o.Timeout = 50 * time.Millisecond })
	a, err := f.svc.Create(f.ctx, Request{Policy: f.req, Decision: f.dec})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got, err := f.svc.Wait(f.ctx, a.ID)
	if err != nil || got.Status != state.ApprovalExpired {
		t.Fatalf("got %+v %v", got, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("expiry took too long")
	}
	if f.audit(t, ActionExpired) != 1 {
		t.Fatal("expiry not audited")
	}
}

func TestNotifierFailureNeverApproves(t *testing.T) {
	failing := &notify.Recorder{NotifierName: "down", Fail: errors.New("connection refused")}
	f := newFixture(t, func(o *Options) { o.Notifiers = []notify.Notifier{failing} })
	a := f.create(t)
	deadline := time.Now().Add(2 * time.Second)
	for f.audit(t, ActionNotifyErr) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.audit(t, ActionNotifyErr) != 1 {
		t.Fatal("notifier failure not audited")
	}
	if got, _ := f.svc.Get(f.ctx, a.ID, ""); got.Status != state.ApprovalPending {
		t.Fatalf("status %s after notifier failure", got.Status)
	}
	f.clk.Add(time.Hour)
	if n, err := f.svc.Sweep(f.ctx); err != nil || n != 1 {
		t.Fatalf("sweep %d %v", n, err)
	}
	if got, _ := f.svc.Get(f.ctx, a.ID, ""); got.Status != state.ApprovalExpired {
		t.Fatalf("status %s, want expired", got.Status)
	}
}

func TestFirstDecisionSettlesAcrossNotifiers(t *testing.T) {
	r1, r2 := &notify.Recorder{NotifierName: "ntfy"}, &notify.Recorder{NotifierName: "webhook"}
	f := newFixture(t, func(o *Options) { o.Notifiers = []notify.Notifier{r1, r2} })
	a := f.create(t)
	deadline := time.Now().Add(2 * time.Second)
	for (len(r1.Sent()) == 0 || len(r2.Sent()) == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	_, t1, _ := TokenFromLink(r1.Sent()[0].ApproveURL)
	_, t2, _ := TokenFromLink(r2.Sent()[0].DenyURL)
	if t1 == t2 {
		t.Fatal("notifiers share a token")
	}
	if _, err := f.svc.DecideToken(f.ctx, a.ID, t1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideToken(f.ctx, a.ID, t2); !errors.Is(err, ErrSettled) {
		t.Fatalf("second notifier's decision accepted: %v", err)
	}
	if got, _ := f.svc.Get(f.ctx, a.ID, ""); got.DecidedBy != "link:ntfy" {
		t.Fatalf("decided by %q", got.DecidedBy)
	}
}

func TestRuleNotifierSelection(t *testing.T) {
	r1, r2 := &notify.Recorder{NotifierName: "ntfy"}, &notify.Recorder{NotifierName: "webhook"}
	f := newFixture(t, func(o *Options) { o.Notifiers = []notify.Notifier{r1, r2} })
	if _, err := f.svc.Create(f.ctx, Request{Policy: f.req, Decision: f.dec, Notifiers: []string{"webhook"}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(r2.Sent()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if len(r1.Sent()) != 0 || len(r2.Sent()) != 1 {
		t.Fatalf("sent ntfy=%d webhook=%d", len(r1.Sent()), len(r2.Sent()))
	}
}

func TestApproverTTLIsCapped(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	out, err := f.svc.Decide(f.ctx, a.ID, Decision{Approve: true, By: "alice", Via: "terminal", TTL: 5 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Capped || !out.Grant.ExpiresAt.Equal(f.clk.Now().Add(time.Hour)) {
		t.Fatalf("not capped: %+v", out)
	}
}

func TestApprovalBelongsToItsAgent(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	if _, err := f.svc.Get(f.ctx, a.ID, "claude-laptop"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(f.ctx, a.ID, "other-agent"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("other agent sees approval: %v", err)
	}
}

func TestBreakGlassDeniesPendingAndRefusesApprovals(t *testing.T) {
	f := newFixture(t)
	a := f.create(t)
	b := f.create(t)
	if err := f.bg.Engage(f.ctx, "oncall", "suspected leak"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Create(f.ctx, Request{Policy: f.req, Decision: f.dec}); !errors.Is(err, breakglass.ErrActive) {
		t.Fatalf("approval created under deny-all: %v", err)
	}
	if _, err := f.svc.Decide(f.ctx, a.ID, Decision{Approve: true, By: "alice"}); !errors.Is(err, breakglass.ErrActive) {
		t.Fatalf("approved under deny-all: %v", err)
	}
	n, err := f.svc.DenyAllPending(f.ctx, "break-glass")
	if err != nil || n != 2 {
		t.Fatalf("denied %d %v", n, err)
	}
	for _, id := range []string{a.ID, b.ID} {
		if got, _ := f.svc.Get(f.ctx, id, ""); got.Status != state.ApprovalDenied {
			t.Fatalf("%s is %s", id, got.Status)
		}
	}
}

func TestApprovalWithoutIdentityOrRefMakesNoGrant(t *testing.T) {
	f := newFixture(t)
	f.req.Ref = stores.Ref{}
	a := f.create(t)
	out, err := f.svc.Decide(f.ctx, a.ID, Decision{Approve: true, By: "alice"})
	if err != nil || out.Grant != nil {
		t.Fatalf("outcome %+v %v", out, err)
	}
}

func TestWaitSeesDecisionFromAnotherReplica(t *testing.T) {
	f := newFixture(t)
	other, err := New(f.opts) // same state backend, separate process state
	if err != nil {
		t.Fatal(err)
	}
	a := f.create(t)
	done := make(chan state.Approval, 1)
	go func() {
		got, _ := f.svc.Wait(f.ctx, a.ID)
		done <- got
	}()
	time.Sleep(10 * time.Millisecond)
	if _, err := other.Decide(f.ctx, a.ID, Decision{Approve: false, By: "bob", Via: "terminal"}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.Status != state.ApprovalDenied {
			t.Fatalf("got %s", got.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decision on another replica not seen")
	}
}

func TestNotificationsHoldNoValues(t *testing.T) {
	// The request summary a notifier receives is the policy request, which
	// has no field for a value or a body.
	f := newFixture(t)
	f.req.Path = "/v1/items/⟦scrim:github:abcd⟧"
	f.create(t)
	got := f.sent(t, 1)[0]
	if got.Summary.Path != f.req.Path {
		t.Fatalf("summary %+v", got.Summary)
	}
}
