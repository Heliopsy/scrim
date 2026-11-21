// SPDX-License-Identifier: AGPL-3.0-only

// Package gate is the control plane's single decision path (design D7):
// every injection, store write, generation, capture, exec and tool call the
// control plane handles, and every "ask" the data plane sends, goes through
// [Gate.Check]:
//
//  1. break-glass deny-all: deny;
//  2. policy rules: deny stays deny;
//  3. allow: proceed, and leave a grant behind when the rule has a grant TTL;
//  4. ask: a grant that covers the request lets it through; otherwise an
//     approval is created and, in blocking mode, waited for. Approved
//     proceeds; denied, expired, cancelled or any error denies.
//
// A provider request (`llm.forward`) is the exception the data plane makes
// too: neither break-glass nor the default decision stops it, only a deny
// rule or an ask rule that is not approved ([Gate.checkForward]).
//
// Every outcome is audited. Errors always deny.
package gate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// ActionDecision is the audit action of a decision entry.
const ActionDecision = "decision"

// RuleLookup returns a rule's settings by name; [policy.Live] implements it.
type RuleLookup interface {
	Rule(name string) (policy.RuleSpec, bool)
}

// Gate combines policy, grants, approvals and break-glass.
type Gate struct {
	Engine     policy.Engine
	Rules      RuleLookup
	Grants     *grant.Service
	Approvals  *approval.Service
	BreakGlass *breakglass.Switch
	State      state.Store
	// Limits returns grant limits for a rule's grant settings.
	Limits func(policy.GrantSettings) grant.Limits
	// Callers resolves who sent a request the data plane asks about
	// ([Gate.Answer]); nil evaluates every such caller as unknown.
	Callers *identity.Resolver
	// StoreAccess, when set, checks that the caller's own store identity
	// may use a secret scrim's rules allowed it to use ([Gate.Answer]).
	StoreAccess StoreAccess
	// Labels, when set, gives a request that names a secret but carries no
	// secret labels the labels policy sees for it (store-native, store.*
	// and derived).
	Labels func(stores.Ref) map[string]string
	Log    *slog.Logger
	Now    func() time.Time
}

// Status is the outcome of a check.
type Status string

// Statuses.
const (
	Allowed Status = "allowed"
	Denied  Status = "denied"
	// Pending: an approval was created and the caller asked not to wait.
	Pending Status = "pending"
)

// Verdict is what the caller does.
type Verdict struct {
	Status Status
	Rule   string
	Reason string
	// GrantID is the grant that allowed the request or was created by it.
	GrantID       string
	GrantExpires  time.Time
	ApprovalID    string
	ApprovalState state.ApprovalStatus
}

// Allowed reports whether the operation may proceed now.
func (v Verdict) Allowed() bool { return v.Status == Allowed }

// Options select how one check behaves.
type Options struct {
	// Wait blocks on an approval until it is settled. Without it an ask
	// returns Pending with the approval ID (MCP secret_request).
	Wait bool
	// RequestID correlates audit entries with logs and traces.
	RequestID string
	// Attrs are added to the decision's audit entry (how the caller was
	// identified, for example). Metadata only, never a value.
	Attrs map[string]string
	// Confirm, when set, runs after the rules allowed the operation and
	// before it is audited; an error turns the allow into a deny (the
	// store refusing the agent's own identity). Scrim's rules run first, so
	// a request they deny never reaches the store.
	Confirm func(context.Context) error
}

// Check decides req. It never returns an error: failures deny and are
// logged. A decision that cannot be audited is refused, so nothing proceeds
// unaudited.
func (g *Gate) Check(ctx context.Context, req policy.Request, o Options) Verdict {
	req = g.withLabels(req)
	v := g.check(ctx, req, o)
	if v.Status == Allowed && o.Confirm != nil {
		if err := o.Confirm(ctx); err != nil {
			v = Verdict{Status: Denied, Rule: v.Rule, Reason: "refused by the agent's store identity: " + err.Error(), ApprovalID: v.ApprovalID}
		}
	}
	if err := g.record(ctx, req, v, o); err != nil && v.Status != Denied {
		g.logErr("decision could not be audited; refusing", err)
		return Verdict{Status: Denied, Rule: v.Rule, Reason: "decision could not be audited", ApprovalID: v.ApprovalID}
	}
	return v
}

// withLabels fills req.SecretLabels from g.Labels when the request names a
// secret and carries none (the data plane sends the labels its snapshot
// holds, so its asks are evaluated on what it decided on).
func (g *Gate) withLabels(req policy.Request) policy.Request {
	if g.Labels != nil && len(req.SecretLabels) == 0 && !req.Ref.IsZero() {
		req.SecretLabels = g.Labels(req.Ref)
	}
	return req
}

func (g *Gate) check(ctx context.Context, req policy.Request, o Options) Verdict {
	if req.Action == policy.ActionForward {
		return g.checkForward(ctx, req, o)
	}
	if g.BreakGlass != nil && g.BreakGlass.Active() {
		return Verdict{Status: Denied, Rule: "break-glass", Reason: breakglass.ErrActive.Error()}
	}
	d, err := g.Engine.Decide(ctx, req)
	if err != nil {
		g.logErr("policy evaluation failed; denying", err)
		return Verdict{Status: Denied, Rule: d.Rule, Reason: "policy evaluation failed"}
	}
	switch d.Effect {
	case policy.Allow:
		v := Verdict{Status: Allowed, Rule: d.Rule, Reason: d.Reason}
		if d.GrantTTL > 0 {
			g.allowWithDuration(ctx, req, d, &v)
		}
		return v
	case policy.Ask:
		return g.ask(ctx, req, d, o)
	default:
		return Verdict{Status: Denied, Rule: d.Rule, Reason: d.Reason}
	}
}

// Reasons a provider request goes through without a rule allowing it.
const (
	ReasonForwardDefault    = "provider requests are not stopped by the default decision"
	ReasonForwardBreakGlass = "break-glass deny-all does not stop provider requests"
)

// checkForward decides an `llm.forward` request with the data plane's
// semantics (specs/policy-approvals "Provider requests are not stopped by the
// default"): only a deny rule that matches refuses it, an ask rule raises an
// approval, and neither the default decision nor break-glass stops it, since
// the request is redacted whatever the rules say.
func (g *Gate) checkForward(ctx context.Context, req policy.Request, o Options) Verdict {
	if g.BreakGlass != nil && g.BreakGlass.Active() {
		return Verdict{Status: Allowed, Reason: ReasonForwardBreakGlass}
	}
	d, err := g.Engine.Decide(ctx, req)
	if err != nil {
		g.logErr("policy evaluation failed; denying", err)
		return Verdict{Status: Denied, Rule: d.Rule, Reason: "policy evaluation failed"}
	}
	if d.Rule == policy.DefaultRule {
		return Verdict{Status: Allowed, Rule: d.Rule, Reason: ReasonForwardDefault}
	}
	switch d.Effect {
	case policy.Allow:
		v := Verdict{Status: Allowed, Rule: d.Rule, Reason: d.Reason}
		if d.GrantTTL > 0 {
			g.allowWithDuration(ctx, req, d, &v)
		}
		return v
	case policy.Ask:
		return g.ask(ctx, req, d, o)
	default:
		return Verdict{Status: Denied, Rule: d.Rule, Reason: d.Reason}
	}
}

func (g *Gate) rule(name string) policy.RuleSpec {
	if g.Rules != nil {
		if r, ok := g.Rules.Rule(name); ok {
			return r
		}
	}
	return policy.RuleSpec{}
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// allowWithDuration leaves a grant behind for an allow rule with a TTL,
// unless one already covers the request.
func (g *Gate) allowWithDuration(ctx context.Context, req policy.Request, d policy.Decision, v *Verdict) {
	if g.Grants == nil {
		return
	}
	if existing, err := g.Grants.Find(ctx, req); err == nil && existing != nil {
		v.GrantID, v.GrantExpires = existing.ID, existing.ExpiresAt
		return
	}
	r := g.rule(d.Rule)
	ttl := d.GrantTTL
	if g.Limits != nil {
		ttl, _ = g.Limits(r.Grant).TTL(d.GrantTTL)
	}
	gr, err := grant.Build(req, r.Grant.Scope, r.Grant.Uses, ttl, d.Rule, "", g.now())
	if err != nil {
		return // no identity or no reference: the allow stands, no grant
	}
	if err := g.Grants.Create(ctx, &gr, "policy:"+d.Rule); err != nil {
		g.logErr("creating grant for allow rule", err)
		return
	}
	v.GrantID, v.GrantExpires = gr.ID, gr.ExpiresAt
}

func (g *Gate) ask(ctx context.Context, req policy.Request, d policy.Decision, o Options) Verdict {
	if g.Grants != nil {
		gr, err := g.Grants.Use(ctx, req, o.RequestID)
		if err != nil {
			g.logErr("grant lookup failed; asking instead", err)
		}
		if gr != nil {
			return Verdict{Status: Allowed, Rule: d.Rule, Reason: "covered by grant", GrantID: gr.ID, GrantExpires: gr.ExpiresAt}
		}
	}
	if g.Approvals == nil {
		return Verdict{Status: Denied, Rule: d.Rule, Reason: "approval needed but no approval flow is configured"}
	}
	r := g.rule(d.Rule)
	a, err := g.Approvals.Create(ctx, approval.Request{
		Policy: req, Decision: d, Timeout: r.Approval.Timeout.D(), Notifiers: r.Approval.Notifiers, RequestID: o.RequestID,
	})
	if err != nil {
		g.logErr("creating approval failed; denying", err)
		return Verdict{Status: Denied, Rule: d.Rule, Reason: "approval could not be created"}
	}
	if !o.Wait {
		return Verdict{Status: Pending, Rule: d.Rule, Reason: d.Reason, ApprovalID: a.ID, ApprovalState: a.Status}
	}
	settled, err := g.Approvals.Wait(ctx, a.ID)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			g.logErr("waiting for approval failed; denying", err)
		}
		return Verdict{Status: Denied, Rule: d.Rule, Reason: "approval wait ended without a decision", ApprovalID: a.ID, ApprovalState: settled.Status}
	}
	v := Verdict{Rule: d.Rule, ApprovalID: a.ID, ApprovalState: settled.Status}
	switch {
	case settled.Status == state.ApprovalApproved && (g.BreakGlass == nil || !g.BreakGlass.Active()):
		v.Status, v.Reason = Allowed, "approved by "+settled.DecidedBy
		if g.Grants != nil {
			if gr, err := g.Grants.Find(ctx, req); err == nil && gr != nil && gr.ApprovalID == a.ID {
				v.GrantID, v.GrantExpires = gr.ID, gr.ExpiresAt
			}
		}
	case settled.Status == state.ApprovalExpired:
		v.Status, v.Reason = Denied, "approval timed out"
	default:
		v.Status, v.Reason = Denied, fmt.Sprintf("approval %s", settled.Status)
	}
	return v
}

func (g *Gate) record(ctx context.Context, req policy.Request, v Verdict, o Options) error {
	requestID := o.RequestID
	if g.State == nil {
		return nil
	}
	eff := policy.Deny
	switch v.Status {
	case Allowed:
		eff = policy.Allow
	case Pending:
		eff = policy.Ask
	}
	target := req.Host
	if target == "" {
		target = req.Tool
	}
	attrs := make(map[string]string, len(o.Attrs)+6)
	maps.Copy(attrs, o.Attrs)
	attrs["action"], attrs["status"] = string(req.Action), string(v.Status)
	if v.GrantID != "" {
		attrs["grant"] = v.GrantID
	}
	if v.ApprovalID != "" {
		attrs["approval"] = v.ApprovalID
	}
	if req.Method != "" {
		attrs["method"] = req.Method
	}
	if req.Provider != "" {
		attrs["provider"] = req.Provider
	}
	e := audit.Entry{
		Time: g.now(), Action: ActionDecision, Actor: req.Agent.ID, Agent: req.Agent, Ref: req.Ref,
		Effect: eff, Rule: v.Rule, Target: target, Subject: v.ApprovalID, RequestID: requestID, Reason: v.Reason, Attrs: attrs,
	}
	return state.Apply(ctx, g.State, func(state.Tx) (state.Change, error) { return state.Change{Audit: e}, nil })
}

func (g *Gate) logErr(msg string, err error) {
	if g.Log != nil {
		g.Log.Error(msg, "err", err)
	}
}
