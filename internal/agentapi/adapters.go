// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// Agent converts a resolved identity into the policy package's agent. The
// session ID is carried separately, so rules can match the agent name while
// grants and approvals stay owned by one session.
func Agent(id identity.Identity) policy.Agent { return id.PolicyAgent() }

// owns reports whether a stored agent is the same principal as a.
func owns(a, stored policy.Agent) bool {
	return a.ID != "" && a.ID == stored.ID && a.Session == stored.Session
}

// actionFor maps each tool to the policy action it asks for.
var actionFor = map[string]policy.Action{
	agenttools.ToolSecretsList:    policy.ActionTool,
	agenttools.ToolSecretRequest:  policy.ActionGrant,
	agenttools.ToolSecretGen:      policy.ActionGenerate,
	agenttools.ToolSecretCapture:  policy.ActionWrite,
	agenttools.ToolSecretPut:      policy.ActionWrite,
	agenttools.ToolSecretAskHuman: policy.ActionAskHuman,
}

// resolveRef parses a tool reference. A bare name with a store becomes
// <store>://<name>, until the catalog resolves names properly.
func resolveRef(ref, store string) (stores.Ref, error) {
	r, err := stores.ParseRef(ref)
	if err != nil && store != "" && !strings.Contains(ref, "://") {
		r, err = stores.ParseRef(store + "://" + ref)
	}
	if err != nil {
		return stores.Ref{}, err
	}
	if store != "" && r.Scheme != store {
		return stores.Ref{}, fmt.Errorf("%w: the reference names store %s, not %s", stores.ErrInvalidRef, r.Scheme, store)
	}
	return r, nil
}

// Policy adapts a policy.Engine to the agent tools.
type Policy struct {
	Engine policy.Engine
	// Labels, when set, gives the labels policy sees for the secret a tool
	// names (secret.labels): its store's labels, or for a new item the
	// labels it would get.
	Labels func(stores.Ref) map[string]string
}

// Decide implements agenttools.Policy. A reference that does not parse is
// denied: policy cannot be evaluated for something it cannot name.
func (p Policy) Decide(ctx context.Context, id identity.Identity, op agenttools.Operation) (agenttools.Decision, error) {
	req := policy.Request{Agent: Agent(id), Action: actionFor[op.Tool], Store: op.Store, Tool: op.Tool, Time: time.Now()}
	if req.Action == "" {
		req.Action = policy.ActionTool
	}
	if op.Ref != "" {
		r, err := resolveRef(op.Ref, op.Store)
		if err != nil {
			return agenttools.Decision{Effect: agenttools.EffectDeny, Rule: "invalid-ref", Reason: "the reference is not valid"}, nil //nolint:nilerr // an invalid reference is a deny decision, not an error
		}
		req.Ref, req.Store = r, r.Scheme
		if p.Labels != nil {
			req.SecretLabels = p.Labels(r)
		}
	}
	d, err := p.Engine.Decide(ctx, req)
	if err != nil {
		return agenttools.Decision{}, err
	}
	return agenttools.Decision{Effect: effect(d.Effect), Reason: d.Reason, Rule: d.Rule}, nil
}

func effect(e policy.Effect) agenttools.Effect {
	switch e {
	case policy.Allow:
		return agenttools.EffectAllow
	case policy.Ask:
		return agenttools.EffectAsk
	default:
		return agenttools.EffectDeny
	}
}

// valueField is the field a reference without #field writes.
const valueField = "value"

// Placeholders computes the placeholder the model sees for a reference. The
// redaction core provides it; until it is wired, results carry no
// placeholder.
type Placeholders interface {
	Placeholder(ref stores.Ref) string
}

// Stores adapts the configured store set to the agent tools.
type Stores struct {
	Set          *stores.Set
	Placeholders Placeholders
	// Refreshers, when set, take writes to their store, so a written value
	// is in the redaction set before the write is reported.
	Refreshers []*refresh.Refresher
}

func (s Stores) write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, o stores.WriteOptions) error {
	if a, err := s.Set.Lookup(ref); err == nil {
		for _, r := range s.Refreshers {
			if r.Store() == a.Name() {
				_, err := r.Write(ctx, ref, fields, o)
				return err
			}
		}
	}
	_, err := s.Set.Write(ctx, ref, fields, o)
	return err
}

func (s Stores) placeholder(r stores.Ref) string {
	if s.Placeholders == nil {
		return ""
	}
	return s.Placeholders.Placeholder(r)
}

// Write implements agenttools.Store. The reference's field (default
// "value") receives the value; without Overwrite the write is create-only.
func (s Stores) Write(ctx context.Context, _ identity.Identity, w agenttools.Write) (agenttools.Written, error) {
	r, err := resolveRef(w.Ref, w.Store)
	if err != nil {
		return agenttools.Written{}, err
	}
	field := r.Field
	if field == "" {
		field = valueField
	}
	// Copy the value: the store adapter takes ownership and may wipe it,
	// while the caller wipes its own when the call returns.
	var v secret.Value
	if err := w.Value.Expose(func(b []byte) error { v = secret.New(b); return nil }); err != nil {
		return agenttools.Written{}, err
	}
	err = s.write(ctx, r.Secret(), map[string]secret.Value{field: v}, stores.WriteOptions{CreateOnly: !w.Overwrite})
	v.Wipe()
	if errors.Is(err, stores.ErrConflict) {
		return agenttools.Written{}, agenttools.ErrExists
	}
	if err != nil {
		return agenttools.Written{}, err
	}
	out := r.WithField(field)
	return agenttools.Written{Ref: out.String(), Store: r.Scheme, Placeholder: s.placeholder(out)}, nil
}

// bindingsLabel is the store metadata label that lists a secret's bound
// hosts, comma-separated.
const bindingsLabel = "scrim.bindings"

// List implements agenttools.Catalog over every store that can list.
func (s Stores) List(ctx context.Context, _ identity.Identity, f agenttools.ListInput) ([]agenttools.SecretInfo, error) {
	var prefixes []stores.Ref
	if f.Prefix != "" {
		if r, err := stores.ParseRef(strings.TrimSuffix(f.Prefix, "/")); err == nil {
			prefixes = append(prefixes, r)
		}
	}
	if len(prefixes) == 0 {
		for _, a := range s.Set.Adapters() {
			if a.Capabilities().Has(stores.CapList) && (f.Store == "" || f.Store == a.Name()) {
				prefixes = append(prefixes, stores.Ref{Scheme: a.Name()})
			}
		}
	}
	var out []agenttools.SecretInfo
	for _, p := range prefixes {
		metas, err := s.Set.List(ctx, p)
		if err != nil {
			return nil, err
		}
		for _, m := range metas {
			info := agenttools.SecretInfo{Ref: m.Ref.String(), Name: m.Ref.Path, Store: m.Ref.Scheme,
				Placeholder: s.placeholder(m.Ref), UpdatedAt: m.UpdatedAt.UTC()}
			for k, v := range m.Labels {
				if k == bindingsLabel {
					for h := range strings.SplitSeq(v, ",") {
						if h = strings.TrimSpace(h); h != "" {
							info.Bindings = append(info.Bindings, h)
						}
					}
					continue
				}
				if info.Metadata == nil {
					info.Metadata = map[string]string{}
				}
				info.Metadata[k] = v
			}
			out = append(out, info)
		}
	}
	slices.SortFunc(out, func(a, b agenttools.SecretInfo) int { return strings.Compare(a.Ref, b.Ref) })
	return out, nil
}

// Audit writes tool audit entries to the state backend's audit log.
type Audit struct{ State state.Store }

// Record implements agenttools.Auditor.
func (a Audit) Record(ctx context.Context, e agenttools.AuditEntry) error {
	return state.Apply(ctx, a.State, func(state.Tx) (state.Change, error) {
		return state.Change{Audit: Entry(e)}, nil
	})
}

// Entry converts a tool audit entry into the shared audit entry.
func Entry(e agenttools.AuditEntry) audit.Entry {
	out := audit.Entry{
		Time:   e.Time,
		Action: "tool." + e.Tool,
		Actor:  e.Principal,
		Agent: policy.Agent{ID: e.Agent, Kind: policy.IdentityKind(strings.TrimPrefix(e.Source, "unknown")),
			Session: e.SessionID},
		Rule:    e.Rule,
		Target:  e.Tool,
		Outcome: outcome(e.Outcome),
		Reason:  e.Detail,
		Attrs: map[string]string{
			"outcome": e.Outcome,
			"source":  e.Source,
			"uid":     strconv.FormatUint(uint64(e.UID), 10),
		},
	}
	if out.Actor == "" {
		out.Actor = "uid:" + out.Attrs["uid"]
	}
	if e.PID != 0 {
		out.Attrs["pid"] = strconv.FormatInt(int64(e.PID), 10)
	}
	if e.Store != "" {
		out.Attrs["store"] = e.Store
	}
	if e.Decision != "" {
		out.Attrs["decision"] = e.Decision
		if eff, err := policy.ParseEffect(e.Decision); err == nil {
			out.Effect = eff
		}
	}
	if r, err := stores.ParseRef(e.Ref); err == nil {
		out.Ref = r
	} else if e.Ref != "" {
		out.Attrs["ref"] = e.Ref
	}
	switch {
	case e.ApprovalID != "":
		out.Subject = e.ApprovalID
	case e.GrantID != "":
		out.Subject = e.GrantID
	case e.SessionID != "":
		out.Subject = e.SessionID
	}
	if e.GrantID != "" {
		out.Attrs["grant"] = e.GrantID
	}
	return out
}

// outcome maps a tool outcome onto the shared audit outcomes. The finer
// tool outcome stays in Attrs["outcome"].
func outcome(o string) string {
	switch o {
	case agenttools.OutcomeOK:
		return audit.OutcomeOK
	case agenttools.OutcomePending:
		return audit.OutcomePending
	case agenttools.OutcomeError:
		return audit.OutcomeFailed
	case "":
		return ""
	default: // denied, refused, declined, timed out
		return audit.OutcomeRefused
	}
}

// Approvals answers secret_request, approval_status and grants_list through
// the control plane's single decision path: every request goes through
// [gate.Gate.Check] (break-glass, rules, grants, approvals), so the agent
// tools, the data plane's asks and the admin API see the same grants and
// approvals. Status and listings are scoped to the caller's principal.
type Approvals struct {
	Gate *gate.Gate
	// DefaultTTL and MaxTTL bound a grant secret_request creates for an
	// allow rule without a TTL (tools.grant-default-ttl, tools.grant-max-ttl).
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	Now        func() time.Time
}

func (a Approvals) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// Request implements agenttools.Approvals.
func (a Approvals) Request(ctx context.Context, id identity.Identity, req agenttools.GrantRequest) (agenttools.GrantResult, error) {
	r, err := stores.ParseRef(req.Ref)
	if err != nil {
		return agenttools.GrantResult{Status: agenttools.StatusDenied, Reason: "the reference is not valid"}, nil //nolint:nilerr // an invalid reference is a denied request, not an error
	}
	now := a.now()
	preq := policy.Request{Agent: Agent(id), Action: policy.ActionGrant, Ref: r, Store: r.Scheme,
		Tool: agenttools.ToolSecretRequest, Time: now}
	v := a.Gate.Check(ctx, preq, gate.Options{})
	switch v.Status {
	case gate.Allowed:
		if v.GrantID != "" {
			// The rule leaves its own grant behind (allow with a TTL), or an
			// earlier grant already covers the request.
			dur := v.GrantExpires.Sub(now).Round(time.Second)
			return agenttools.GrantResult{Status: agenttools.StatusGranted, GrantID: v.GrantID, ExpiresAt: v.GrantExpires,
				Duration: dur, Capped: req.Duration > dur}, nil
		}
		dur := req.Duration
		if dur <= 0 {
			dur = a.DefaultTTL
		}
		capped := a.MaxTTL > 0 && dur > a.MaxTTL
		if capped {
			dur = a.MaxTTL
		}
		g, err := grant.Build(preq, policy.ScopeSecret, 0, dur, v.Rule, "", now)
		if err != nil {
			return agenttools.GrantResult{Status: agenttools.StatusDenied, Reason: "no grant can be made for this caller"}, nil //nolint:nilerr // an unidentified caller is refused, not an error
		}
		if err := a.Gate.Grants.Create(ctx, &g, id.Principal()); err != nil {
			return agenttools.GrantResult{}, err
		}
		return agenttools.GrantResult{Status: agenttools.StatusGranted, GrantID: g.ID, ExpiresAt: g.ExpiresAt, Duration: dur, Capped: capped}, nil
	case gate.Pending:
		return agenttools.GrantResult{Status: agenttools.StatusPending, ApprovalID: v.ApprovalID, Duration: req.Duration}, nil
	default:
		return agenttools.GrantResult{Status: agenttools.StatusDenied, Reason: v.Reason}, nil
	}
}

// Approval implements agenttools.Approvals.
func (a Approvals) Approval(ctx context.Context, id identity.Identity, approvalID string) (agenttools.ApprovalState, error) {
	me := Agent(id)
	ap, err := a.Gate.Approvals.Get(ctx, approvalID, me.ID)
	if errors.Is(err, state.ErrNotFound) {
		return agenttools.ApprovalState{}, agenttools.ErrNotFound
	}
	if err != nil {
		return agenttools.ApprovalState{}, err
	}
	if !owns(me, ap.Request.Agent) {
		return agenttools.ApprovalState{}, agenttools.ErrNotFound
	}
	out := agenttools.ApprovalState{Status: string(ap.Status), Ref: ap.Request.Ref.String(), ExpiresAt: ap.ExpiresAt}
	if ap.Status == state.ApprovalPending && !a.now().Before(ap.ExpiresAt) {
		out.Status = agenttools.ApprovalExpired
	}
	if ap.Status == state.ApprovalApproved {
		gs, err := a.Gate.Grants.List(ctx, me.ID, false)
		if err != nil {
			return agenttools.ApprovalState{}, err
		}
		for _, g := range gs {
			if g.ApprovalID == ap.ID {
				out.GrantID, out.ExpiresAt = g.ID, g.ExpiresAt
			}
		}
	}
	return out, nil
}

// Grants implements agenttools.Approvals.
func (a Approvals) Grants(ctx context.Context, id identity.Identity) ([]agenttools.Grant, error) {
	me := Agent(id)
	gs, err := a.Gate.Grants.List(ctx, me.ID, false)
	if err != nil {
		return nil, err
	}
	now := a.now()
	var out []agenttools.Grant
	for _, g := range gs {
		if owns(me, g.Agent) && g.Usable(now) {
			out = append(out, grantView(g))
		}
	}
	return out, nil
}

func grantView(g state.Grant) agenttools.Grant {
	out := agenttools.Grant{ID: g.ID, Ref: g.Ref.String(), ExpiresAt: g.ExpiresAt}
	out.Scope = append(append(out.Scope, g.Scope.Hosts...), g.Scope.Tools...)
	if g.MaxUses > 0 {
		left := max(g.MaxUses-g.Uses, 0)
		out.RemainingUses = &left
	}
	return out
}
