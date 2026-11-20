// SPDX-License-Identifier: AGPL-3.0-only

// Package approval runs the approval flow (specs/policy-approvals "Ask
// creates a pending approval", "Single-use, signed decisions", "Durability of
// approvals and grants"): an ask decision becomes a pending approval in the
// state backend, notifiers deliver it, and the held operation waits until a
// decision arrives or the timeout denies it.
//
// Every transition goes through state.Apply with its audit entry and event:
//
//	pending ──approve──▶ approved (+ grant)
//	   │ ───deny──────▶ denied
//	   └───timeout───▶ expired
//
// Only pending moves, and only once, so the first decision settles an
// approval and every later one (a second button tap, a replayed link, a
// second notifier) is refused. Waiting reads the state backend, so a
// decision recorded by any replica or by `scrim approve` reaches the waiter
// within approvals.poll-interval.
package approval

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
)

// Audit actions and event kinds.
const (
	ActionCreated   = "approval.created"
	ActionApproved  = "approval.approved"
	ActionDenied    = "approval.denied"
	ActionExpired   = "approval.expired"
	ActionNotified  = "approval.notified"
	ActionNotifyErr = "approval.notify_failed"
	EventCreated    = "approval.created"
	EventDecided    = "approval.decided"
)

// Settings owned by this package.
var (
	Timeout = config.Register(config.Spec[time.Duration]{
		Key:         "approvals.timeout",
		Default:     2 * time.Minute,
		Description: "How long an approval waits for a decision before it is denied. A rule's approval.timeout overrides it.",
		Flag:        true,
		Validate:    between(time.Second, 24*time.Hour),
	})
	PublicURL = config.Register(config.Spec[string]{
		Key:         "approvals.public-url",
		Default:     "",
		Description: "Base URL under which the decision endpoint is reachable from approvers' devices, for example https://scrim.example.org. Empty means notifiers get no decision links and approvals are decided with scrim approve.",
		Validate: func(s string) error {
			if s == "" {
				return nil
			}
			u, err := url.Parse(s)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return errors.New("must be an absolute http or https URL")
			}
			return nil
		},
	})
	SigningKey = config.Register(config.Spec[config.SecretRef]{
		Key:         "approvals.signing-key",
		Default:     "",
		Description: "Reference to the key (at least 32 bytes) that signs decision links, shared by every replica. Empty means a random key per process: links stop working on restart and on other replicas.",
	})
	PollInterval = config.Register(config.Spec[time.Duration]{
		Key:         "approvals.poll-interval",
		Default:     time.Second,
		Description: "How often a waiting operation re-reads its approval from the state backend; bounds how long a decision recorded elsewhere takes to release it.",
		Validate:    between(10*time.Millisecond, time.Minute),
	})
)

func between(lo, hi time.Duration) func(time.Duration) error {
	return func(d time.Duration) error {
		if d < lo || d > hi {
			return fmt.Errorf("must be between %s and %s", lo, hi)
		}
		return nil
	}
}

// Errors.
var (
	// ErrSettled: the approval was already decided or expired. A replayed
	// link or second button tap gets this.
	ErrSettled = errors.New("approval: already decided")
	// ErrExpired: the approval timed out before the decision arrived.
	ErrExpired = errors.New("approval: expired before a decision arrived")
)

// GrantPolicy returns the grant limits and settings for the rule that asked.
type GrantPolicy func(rule string) (grant.Limits, policy.GrantSettings)

// Options configure a [Service].
type Options struct {
	State      state.Store
	Notifiers  []notify.Notifier
	Signer     *Signer
	BreakGlass *breakglass.Switch
	// PublicURL is approvals.public-url.
	PublicURL string
	// Timeout is approvals.timeout.
	Timeout time.Duration
	// PollInterval is approvals.poll-interval.
	PollInterval time.Duration
	// Grants supplies per-rule grant settings. Nil means the defaults with
	// the request scope.
	Grants  GrantPolicy
	Log     *slog.Logger
	Metrics *obs.Metrics
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Service is the approval flow. It is safe for concurrent use.
type Service struct {
	o Options

	mu      sync.Mutex
	waiters map[string][]chan struct{}

	requested *prometheus.CounterVec
	settled   *prometheus.CounterVec
	waited    *prometheus.HistogramVec
	notified  *prometheus.CounterVec
}

// New returns a service.
func New(o Options) (*Service, error) {
	if o.State == nil || o.Signer == nil {
		return nil, errors.New("approval: State and Signer are required")
	}
	if o.Timeout <= 0 {
		o.Timeout = Timeout.Setting().Default.(time.Duration)
	}
	if o.PollInterval <= 0 {
		o.PollInterval = time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Grants == nil {
		o.Grants = func(string) (grant.Limits, policy.GrantSettings) {
			return grant.Limits{Default: 30 * time.Minute, Max: 8 * time.Hour}, policy.GrantSettings{}
		}
	}
	o.PublicURL = strings.TrimRight(o.PublicURL, "/")
	s := &Service{o: o, waiters: map[string][]chan struct{}{}}
	if o.Metrics != nil {
		s.requested = o.Metrics.Counter("approvals", "requested_total", "Approvals requested.", "rule")
		s.settled = o.Metrics.Counter("approvals", "settled_total", "Approvals settled, by outcome (approved, denied, expired).", "rule", "outcome", "via")
		s.waited = o.Metrics.Histogram("approvals", "wait_seconds", "Time from approval request to settlement.",
			[]float64{1, 5, 15, 30, 60, 120, 300, 900, 3600}, "rule", "outcome")
		s.notified = o.Metrics.Counter("approvals", "notifications_total", "Approval notifications by notifier and result.", "notifier", "result")
	}
	return s, nil
}

// Request is what is held for approval.
type Request struct {
	Policy policy.Request
	// Decision is the ask decision, carrying rule, reason and grant TTL.
	Decision policy.Decision
	// Timeout overrides the default timeout; zero uses it.
	Timeout time.Duration
	// Notifiers restricts delivery to these notifier names; empty means all.
	Notifiers []string
	// RequestID correlates the audit entries with logs.
	RequestID string
}

// Create records a pending approval and starts delivering it. It returns
// once the approval is durable; delivery happens in the background and a
// delivery failure never decides anything.
func (s *Service) Create(ctx context.Context, r Request) (*state.Approval, error) {
	if err := s.breakGlass(); err != nil {
		return nil, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = s.o.Timeout
	}
	now := s.o.Now()
	a := &state.Approval{
		ID:        state.NewID(),
		Status:    state.ApprovalPending,
		Request:   r.Policy,
		Rule:      r.Decision.Rule,
		Reason:    r.Decision.Reason,
		GrantTTL:  r.Decision.GrantTTL,
		CreatedAt: now,
		ExpiresAt: now.Add(timeout),
	}
	err := state.Apply(ctx, s.o.State, func(tx state.Tx) (state.Change, error) {
		if err := tx.CreateApproval(ctx, a); err != nil {
			return state.Change{}, err
		}
		return state.Change{
			Audit:  s.entry(a, ActionCreated, a.Request.Agent.ID, now, r.RequestID, nil),
			Events: []state.Event{{Kind: EventCreated, Subject: a.ID, Time: now}},
		}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("approval: create: %w", err)
	}
	if s.requested != nil {
		s.requested.WithLabelValues(a.Rule).Inc()
	}
	s.deliver(*a, r.Notifiers)
	return a, nil
}

// deliver notifies in the background, bounded by the approval's expiry.
func (s *Service) deliver(a state.Approval, only []string) {
	var targets []notify.Notifier
	for _, n := range s.o.Notifiers {
		if len(only) == 0 || contains(only, n.Name()) {
			targets = append(targets, n)
		}
	}
	if len(targets) == 0 {
		s.o.Log.Warn("approval has no notifier; decide it with scrim approve", "approval", a.ID, "rule", a.Rule)
		return
	}
	for _, n := range targets {
		req, err := s.notifyRequest(a, n.Name())
		if err != nil {
			s.o.Log.Error("approval: minting decision links", "approval", a.ID, "err", err)
			continue
		}
		go func() {
			ctx, cancel := context.WithDeadline(context.Background(), a.ExpiresAt)
			defer cancel()
			err := n.Notify(ctx, req)
			result, action, reason := "ok", ActionNotified, ""
			if err != nil {
				result, action, reason = "error", ActionNotifyErr, err.Error()
				s.o.Log.Warn("approval notification failed; the approval stays pending", "approval", a.ID, "notifier", n.Name(), "err", err)
			}
			if s.notified != nil {
				s.notified.WithLabelValues(n.Name(), result).Inc()
			}
			now := s.o.Now()
			_ = state.Apply(context.Background(), s.o.State, func(state.Tx) (state.Change, error) {
				e := s.entry(&a, action, "scrim", now, "", map[string]string{"notifier": n.Name()})
				e.Reason = reason
				return state.Change{Audit: e}, nil
			})
		}()
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// notifyRequest builds what a notifier shows, with decision links minted
// for that notifier.
func (s *Service) notifyRequest(a state.Approval, via string) (notify.Request, error) {
	r := notify.Request{
		ApprovalID: a.ID,
		Agent:      a.Request.Agent,
		Summary:    a.Request,
		Rule:       a.Rule,
		Reason:     a.Reason,
		ExpiresAt:  a.ExpiresAt,
	}
	var err error
	if r.ApproveURL, err = s.Link(a.ID, ActionApprove, a.ExpiresAt, via); err != nil {
		return r, err
	}
	r.DenyURL, err = s.Link(a.ID, ActionDeny, a.ExpiresAt, via)
	return r, err
}

// DecidePath is the path of the decision endpoint for approval id, relative
// to approvals.public-url.
func DecidePath(id string) string { return "/v1/approvals/" + url.PathEscape(id) + "/decide" }

// Link returns a decision link for id. Without approvals.public-url the link
// is relative (path and query only): notifiers that need an absolute URL
// omit their buttons, but the token in it still works through the API.
func (s *Service) Link(id string, action Action, exp time.Time, via string) (string, error) {
	tok, err := s.o.Signer.Mint(id, action, exp, via)
	if err != nil {
		return "", err
	}
	return s.o.PublicURL + DecidePath(id) + "?" + url.Values{"t": {tok}}.Encode(), nil
}

// TokenFromLink extracts the token from a decision link.
func TokenFromLink(link string) (id, token string, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", "", ErrTokenInvalid
	}
	p, ok := strings.CutSuffix(u.Path, "/decide")
	i := strings.LastIndexByte(p, '/')
	if !ok || i < 0 || u.Query().Get("t") == "" {
		return "", "", ErrTokenInvalid
	}
	if id, err = url.PathUnescape(p[i+1:]); err != nil || id == "" {
		return "", "", ErrTokenInvalid
	}
	return id, u.Query().Get("t"), nil
}

// Decision is a human's answer.
type Decision struct {
	Approve bool
	// By names the approver: an operator name, or "link:<notifier>".
	By string
	// Via is the channel: terminal, api, link, webhook.
	Via string
	// TTL requests a grant duration; zero means the rule's default. It is
	// capped at the rule's maximum.
	TTL    time.Duration
	Reason string
}

// Outcome is what a decision did.
type Outcome struct {
	Approval state.Approval
	// Grant is the grant the approval created, if any.
	Grant *state.Grant
	// Capped is true when the requested TTL exceeded the maximum.
	Capped bool
}

// Decide settles a pending approval. It returns [ErrSettled] if the
// approval is not pending, [ErrExpired] if it timed out first, and
// [breakglass.ErrActive] for an approval while deny-all is engaged.
func (s *Service) Decide(ctx context.Context, id string, d Decision) (Outcome, error) {
	if d.By == "" {
		return Outcome{}, errors.New("approval: the approver must be named")
	}
	if d.Approve {
		if err := s.breakGlass(); err != nil {
			return Outcome{}, err
		}
	}
	now := s.o.Now()
	var out Outcome
	expired := false
	err := state.Apply(ctx, s.o.State, func(tx state.Tx) (state.Change, error) {
		a, err := tx.GetApproval(ctx, id)
		if err != nil {
			return state.Change{}, err
		}
		if a.Status != state.ApprovalPending {
			return state.Change{}, ErrSettled
		}
		if !now.Before(a.ExpiresAt) {
			expired = true
			return state.Change{}, ErrExpired
		}
		status, action := state.ApprovalDenied, ActionDenied
		if d.Approve {
			status, action = state.ApprovalApproved, ActionApproved
		}
		if err := tx.DecideApproval(ctx, id, status, d.By, now); err != nil {
			if errors.Is(err, state.ErrConflict) {
				return state.Change{}, ErrSettled
			}
			return state.Change{}, err
		}
		a.Status, a.DecidedAt, a.DecidedBy = status, now, d.By
		out.Approval = *a
		attrs := map[string]string{"via": d.Via}
		if d.Approve {
			limits, gs := s.o.Grants(a.Rule)
			requested := d.TTL
			if requested == 0 {
				requested = a.GrantTTL
			}
			ttl, capped := limits.TTL(requested)
			out.Capped = capped
			g, err := grant.Build(a.Request, gs.Scope, gs.Uses, ttl, a.Rule, a.ID, now)
			switch {
			case err == nil:
				if err := tx.CreateGrant(ctx, &g); err != nil {
					return state.Change{}, err
				}
				gc := grant.Created(&g, d.By)
				if err := tx.AppendAudit(ctx, &gc.Audit); err != nil {
					return state.Change{}, err
				}
				for i := range gc.Events {
					if err := tx.Emit(ctx, &gc.Events[i]); err != nil {
						return state.Change{}, err
					}
				}
				out.Grant = &g
				attrs["grant"] = g.ID
				attrs["grant_ttl"] = ttl.String()
				if capped {
					attrs["ttl_capped"] = "true"
				}
			case errors.Is(err, grant.ErrNoIdentity), errors.Is(err, grant.ErrNoRef):
				// Approves the held operation only.
			default:
				return state.Change{}, err
			}
		}
		e := s.entry(a, action, d.By, now, "", attrs)
		e.Reason = d.Reason
		return state.Change{Audit: e, Events: []state.Event{{Kind: EventDecided, Subject: id, Time: now}}}, nil
	})
	if expired {
		_ = s.expire(ctx, id)
	}
	if err != nil {
		if errors.Is(err, ErrSettled) || errors.Is(err, ErrExpired) || errors.Is(err, state.ErrNotFound) {
			return Outcome{}, err
		}
		return Outcome{}, fmt.Errorf("approval: decide: %w", err)
	}
	s.observe(&out.Approval, d.Via)
	s.wake(id)
	return out, nil
}

// DecideToken settles approval id with a decision-link token. The token is
// the approver's authority, so it must verify, match id and be unexpired.
func (s *Service) DecideToken(ctx context.Context, id, token string) (Outcome, error) {
	c, err := s.o.Signer.Verify(token, id, s.o.Now())
	if err != nil {
		s.auditRejectedToken(ctx, id, err)
		return Outcome{}, err
	}
	by := "link"
	if c.Via != "" {
		by = "link:" + c.Via
	}
	return s.Decide(ctx, id, Decision{Approve: c.Action == ActionApprove, By: by, Via: "link"})
}

// SettleToken is [Service.DecideToken] without the outcome; it lets
// notifiers that receive decisions (the webhook) settle through the same
// token check as a phone button.
func (s *Service) SettleToken(ctx context.Context, id, token string) error {
	_, err := s.DecideToken(ctx, id, token)
	return err
}

func (s *Service) auditRejectedToken(ctx context.Context, id string, cause error) {
	now := s.o.Now()
	_ = state.Apply(ctx, s.o.State, func(state.Tx) (state.Change, error) {
		return state.Change{Audit: audit.Entry{Time: now, Action: "approval.token_rejected", Actor: "link",
			Subject: id, Effect: policy.Deny, Reason: cause.Error()}}, nil
	})
}

// Wait blocks until approval id is settled, its timeout passes (then it is
// expired and returned as such) or ctx ends. It returns the settled
// approval; only [state.ApprovalApproved] lets the held operation through.
func (s *Service) Wait(ctx context.Context, id string) (state.Approval, error) {
	ch := s.subscribe(id)
	defer s.unsubscribe(id, ch)
	tick := time.NewTicker(s.o.PollInterval)
	defer tick.Stop()
	for {
		a, err := s.get(ctx, id)
		if err != nil {
			return state.Approval{}, err
		}
		if a.Status != state.ApprovalPending {
			return *a, nil
		}
		left := a.ExpiresAt.Sub(s.o.Now())
		if left <= 0 {
			if err := s.expire(ctx, id); err != nil {
				return state.Approval{}, err
			}
			continue
		}
		timer := time.NewTimer(left)
		select {
		case <-ctx.Done():
			timer.Stop()
			return *a, ctx.Err()
		case <-ch:
		case <-tick.C:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// expire marks a pending approval past its deadline as expired.
func (s *Service) expire(ctx context.Context, id string) error {
	now := s.o.Now()
	var a *state.Approval
	err := state.Apply(ctx, s.o.State, func(tx state.Tx) (state.Change, error) {
		var err error
		a, err = tx.GetApproval(ctx, id)
		if err != nil {
			return state.Change{}, err
		}
		if a.Status != state.ApprovalPending || now.Before(a.ExpiresAt) {
			return state.Change{}, errNoop
		}
		if err := tx.DecideApproval(ctx, id, state.ApprovalExpired, "scrim", now); err != nil {
			return state.Change{}, err
		}
		a.Status, a.DecidedAt, a.DecidedBy = state.ApprovalExpired, now, "scrim"
		return state.Change{
			Audit:  s.entry(a, ActionExpired, "scrim", now, "", nil),
			Events: []state.Event{{Kind: EventDecided, Subject: id, Time: now}},
		}, nil
	})
	if errors.Is(err, errNoop) || errors.Is(err, state.ErrConflict) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("approval: expire: %w", err)
	}
	s.observe(a, "timeout")
	s.wake(id)
	return nil
}

var errNoop = errors.New("noop")

// Sweep expires every pending approval past its deadline, including those
// whose waiting replica is gone. It returns how many it expired.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	pending, err := s.List(ctx, state.ApprovalFilter{Status: state.ApprovalPending})
	if err != nil {
		return 0, err
	}
	now, n := s.o.Now(), 0
	for _, a := range pending {
		if now.Before(a.ExpiresAt) {
			continue
		}
		if err := s.expire(ctx, a.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Run sweeps every interval until ctx ends.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Sweep(ctx); err != nil {
				s.o.Log.Warn("approval sweep failed", "err", err)
			}
		}
	}
}

// DenyAllPending denies every pending approval, for break-glass.
func (s *Service) DenyAllPending(ctx context.Context, by string) (int, error) {
	pending, err := s.List(ctx, state.ApprovalFilter{Status: state.ApprovalPending})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range pending {
		_, err := s.Decide(ctx, a.ID, Decision{Approve: false, By: by, Via: "break-glass", Reason: "break-glass deny-all engaged"})
		switch {
		case err == nil:
			n++
		case errors.Is(err, ErrSettled), errors.Is(err, ErrExpired):
		default:
			return n, err
		}
	}
	return n, nil
}

// Get returns approval id. A non-empty agentID restricts it to approvals
// that agent requested: another agent's approval is reported as not found.
func (s *Service) Get(ctx context.Context, id, agentID string) (*state.Approval, error) {
	a, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if agentID != "" && a.Request.Agent.ID != agentID {
		return nil, state.ErrNotFound
	}
	return a, nil
}

func (s *Service) get(ctx context.Context, id string) (*state.Approval, error) {
	var a *state.Approval
	err := s.o.State.View(ctx, func(tx state.Tx) error {
		var err error
		a, err = tx.GetApproval(ctx, id)
		return err
	})
	return a, err
}

// List returns approvals matching f.
func (s *Service) List(ctx context.Context, f state.ApprovalFilter) ([]state.Approval, error) {
	var out []state.Approval
	err := s.o.State.View(ctx, func(tx state.Tx) error {
		var err error
		out, err = tx.ListApprovals(ctx, f)
		return err
	})
	return out, err
}

func (s *Service) breakGlass() error {
	if s.o.BreakGlass != nil {
		return s.o.BreakGlass.Err()
	}
	return nil
}

func (s *Service) entry(a *state.Approval, action, actor string, now time.Time, requestID string, attrs map[string]string) audit.Entry {
	target := a.Request.Host
	if target == "" {
		target = a.Request.Tool
	}
	return audit.Entry{
		Time: now, Action: action, Actor: actor, Agent: a.Request.Agent, Ref: a.Request.Ref,
		Effect: effectOf(a.Status), Rule: a.Rule, Target: target, Subject: a.ID,
		RequestID: requestID, Reason: a.Reason, Attrs: attrs,
	}
}

func effectOf(st state.ApprovalStatus) policy.Effect {
	switch st {
	case state.ApprovalApproved:
		return policy.Allow
	case state.ApprovalPending:
		return policy.Ask
	}
	return policy.Deny
}

func (s *Service) observe(a *state.Approval, via string) {
	if s.settled == nil || a == nil {
		return
	}
	s.settled.WithLabelValues(a.Rule, string(a.Status), via).Inc()
	s.waited.WithLabelValues(a.Rule, string(a.Status)).Observe(a.DecidedAt.Sub(a.CreatedAt).Seconds())
}

func (s *Service) subscribe(id string) chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.waiters[id] = append(s.waiters[id], ch)
	s.mu.Unlock()
	return ch
}

func (s *Service) unsubscribe(id string, ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws := s.waiters[id]
	for i, w := range ws {
		if w == ch {
			ws = append(ws[:i], ws[i+1:]...)
			break
		}
	}
	if len(ws) == 0 {
		delete(s.waiters, id)
	} else {
		s.waiters[id] = ws
	}
}

func (s *Service) wake(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.waiters[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
