// SPDX-License-Identifier: AGPL-3.0-only

// Package grant manages just-in-time grants (specs/policy-approvals
// "Just-in-time grants", "Grant limits and revocation").
//
// A grant is a pre-approval bound to one agent identity and one secret
// reference, with a scope (destination hosts, tools), an expiry and an
// optional use count. It only ever turns an ask into an allow: a deny rule
// and break-glass deny-all always win over a grant.
//
// Grants are read from the state backend on every use; nothing is cached.
// An expiry, revocation or exhausted use count therefore takes effect on the
// next request, on every replica that shares the backend.
package grant

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
)

// Audit actions and event kinds.
const (
	ActionCreated = "grant.created"
	ActionUsed    = "grant.used"
	ActionRevoked = "grant.revoked"
	EventChanged  = "grant.changed"
)

// Settings owned by this package.
var (
	MaxTTL = config.Register(config.Spec[time.Duration]{
		Key:         "grants.max-ttl",
		Default:     8 * time.Hour,
		Description: "Longest grant any rule or approver can create. A rule's grant.max_ttl can only lower it.",
		Validate:    positive,
	})
	DefaultTTL = config.Register(config.Spec[time.Duration]{
		Key:         "grants.default-ttl",
		Default:     30 * time.Minute,
		Description: "Grant duration when neither the rule nor the approver chooses one.",
		Validate:    positive,
	})
)

func positive(d time.Duration) error {
	if d <= 0 {
		return errors.New("must be positive")
	}
	return nil
}

// Errors.
var (
	// ErrNoIdentity: grants need a known agent identity.
	ErrNoIdentity = errors.New("grant: a grant needs a known agent identity")
	// ErrNoRef: grants are per secret reference.
	ErrNoRef = errors.New("grant: a grant needs a secret reference")
)

// Limits are the effective TTL limits for one grant.
type Limits struct {
	// Default applies when no TTL is requested.
	Default time.Duration
	// Max caps any TTL.
	Max time.Duration
}

// LimitsFor combines the global settings with a rule's grant settings. The
// rule can lower the maximum, never raise it.
func LimitsFor(cfg *config.Config, g policy.GrantSettings) Limits {
	l := Limits{Default: DefaultTTL.Get(cfg), Max: MaxTTL.Get(cfg)}
	if g.MaxTTL > 0 && g.MaxTTL.D() < l.Max {
		l.Max = g.MaxTTL.D()
	}
	if g.TTL > 0 {
		l.Default = g.TTL.D()
	}
	if l.Default > l.Max {
		l.Default = l.Max
	}
	return l
}

// TTL returns the duration for a requested TTL (zero means the default) and
// whether it was capped.
func (l Limits) TTL(requested time.Duration) (ttl time.Duration, capped bool) {
	if requested <= 0 {
		return l.Default, false
	}
	if requested > l.Max {
		return l.Max, true
	}
	return requested, false
}

// Build makes the grant for req: bound to the agent and reference, scoped
// per the rule's scope setting. It does not store it.
func Build(req policy.Request, scope policy.GrantScope, uses int, ttl time.Duration, rule, approvalID string, now time.Time) (state.Grant, error) {
	if req.Agent.ID == "" || req.Agent.Kind == policy.IdentityUnknown {
		return state.Grant{}, ErrNoIdentity
	}
	if req.Ref.IsZero() {
		return state.Grant{}, ErrNoRef
	}
	g := state.Grant{
		ID:         state.NewID(),
		Agent:      req.Agent,
		Ref:        req.Ref,
		MaxUses:    uses,
		ApprovalID: approvalID,
		Rule:       rule,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
	}
	switch scope {
	case "", policy.ScopeRequest:
		if req.Host != "" {
			g.Scope.Hosts = []string{strings.ToLower(req.Host)}
		}
		if req.Tool != "" {
			g.Scope.Tools = []string{req.Tool}
		}
	case policy.ScopeHost:
		if req.Host != "" {
			g.Scope.Hosts = []string{strings.ToLower(req.Host)}
		}
	case policy.ScopeSecret:
	default:
		return state.Grant{}, fmt.Errorf("grant: unknown scope %q", scope)
	}
	return g, nil
}

// Covers reports whether g applies to req at t: same agent, same reference,
// inside the scope, not expired, revoked or used up.
func Covers(g *state.Grant, req policy.Request, t time.Time) bool {
	if !g.Usable(t) || req.Agent.Kind == policy.IdentityUnknown || g.Agent.ID != req.Agent.ID || g.Ref != req.Ref {
		return false
	}
	if len(g.Scope.Hosts) > 0 && !slices.Contains(g.Scope.Hosts, strings.ToLower(req.Host)) {
		return false
	}
	if len(g.Scope.Tools) > 0 && !slices.Contains(g.Scope.Tools, req.Tool) {
		return false
	}
	return true
}

// Created returns the audit change for storing g; callers add it to the
// transaction that writes g.
func Created(g *state.Grant, actor string) state.Change {
	return state.Change{
		Audit: audit.Entry{
			Time: g.CreatedAt, Action: ActionCreated, Actor: actor, Agent: g.Agent, Ref: g.Ref,
			Effect: policy.Allow, Rule: g.Rule, Target: target(g), Subject: g.ID,
			Attrs: map[string]string{
				"expires_at": g.ExpiresAt.UTC().Format(time.RFC3339),
				"max_uses":   strconv.Itoa(g.MaxUses),
				"approval":   g.ApprovalID,
			},
		},
		Events: []state.Event{{Kind: EventChanged, Subject: g.ID, Time: g.CreatedAt}},
	}
}

func target(g *state.Grant) string {
	return strings.Join(append(slices.Clone(g.Scope.Hosts), g.Scope.Tools...), ",")
}

// Service uses, lists and revokes grants.
type Service struct {
	st  state.Store
	bg  *breakglass.Switch
	now func() time.Time
}

// NewService returns a service over st. bg may be nil in tests.
func NewService(st state.Store, bg *breakglass.Switch) *Service {
	return &Service{st: st, bg: bg, now: time.Now}
}

// SetClock replaces the clock, for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Create stores g with its audit entry.
func (s *Service) Create(ctx context.Context, g *state.Grant, actor string) error {
	if s.bg != nil && s.bg.Active() {
		return breakglass.ErrActive
	}
	return state.Apply(ctx, s.st, func(tx state.Tx) (state.Change, error) {
		if err := tx.CreateGrant(ctx, g); err != nil {
			return state.Change{}, err
		}
		return Created(g, actor), nil
	})
}

// Use finds a grant that covers req, counts one use and records it. It
// returns nil and no error when no grant covers req. While deny-all is
// active no grant is honoured.
func (s *Service) Use(ctx context.Context, req policy.Request, requestID string) (*state.Grant, error) {
	if s.bg != nil && s.bg.Active() {
		return nil, nil
	}
	if req.Agent.Kind == policy.IdentityUnknown || req.Agent.ID == "" || req.Ref.IsZero() {
		return nil, nil
	}
	now := s.now()
	var used *state.Grant
	err := state.Apply(ctx, s.st, func(tx state.Tx) (state.Change, error) {
		gs, err := tx.ListGrants(ctx, state.GrantFilter{AgentID: req.Agent.ID, Ref: req.Ref, UsableAt: now})
		if err != nil {
			return state.Change{}, err
		}
		for i := range gs {
			if !Covers(&gs[i], req, now) {
				continue
			}
			g, err := tx.UseGrant(ctx, gs[i].ID, now)
			if errors.Is(err, state.ErrGrantUnusable) {
				continue
			}
			if err != nil {
				return state.Change{}, err
			}
			used = g
			return state.Change{Audit: audit.Entry{
				Time: now, Action: ActionUsed, Actor: req.Agent.ID, Agent: req.Agent, Ref: req.Ref,
				Effect: policy.Allow, Rule: g.Rule, Target: req.Host, Subject: g.ID, RequestID: requestID,
				Attrs: map[string]string{"uses": strconv.Itoa(g.Uses), "max_uses": strconv.Itoa(g.MaxUses), "action": string(req.Action)},
			}}, nil
		}
		return state.Change{}, errNone
	})
	if errors.Is(err, errNone) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("grant: %w", err)
	}
	return used, nil
}

// Find returns a grant that covers req without using it, or nil.
func (s *Service) Find(ctx context.Context, req policy.Request) (*state.Grant, error) {
	if (s.bg != nil && s.bg.Active()) || req.Agent.Kind == policy.IdentityUnknown || req.Agent.ID == "" || req.Ref.IsZero() {
		return nil, nil
	}
	now := s.now()
	var found *state.Grant
	err := s.st.View(ctx, func(tx state.Tx) error {
		gs, err := tx.ListGrants(ctx, state.GrantFilter{AgentID: req.Agent.ID, Ref: req.Ref, UsableAt: now})
		if err != nil {
			return err
		}
		for i := range gs {
			if Covers(&gs[i], req, now) {
				found = &gs[i]
				return nil
			}
		}
		return nil
	})
	return found, err
}

// errNone rolls back the empty transaction when no grant applies.
var errNone = errors.New("no grant")

// Revoke ends a grant at once. Revoking an already revoked grant is a
// conflict.
func (s *Service) Revoke(ctx context.Context, id, by, reason string) error {
	if by == "" {
		return errors.New("grant: an operator name is required to revoke")
	}
	now := s.now()
	return state.Apply(ctx, s.st, func(tx state.Tx) (state.Change, error) {
		g, err := tx.GetGrant(ctx, id)
		if err != nil {
			return state.Change{}, err
		}
		if !g.RevokedAt.IsZero() {
			return state.Change{}, fmt.Errorf("%w: grant already revoked", state.ErrConflict)
		}
		if err := tx.RevokeGrant(ctx, id, by, now); err != nil {
			return state.Change{}, err
		}
		return state.Change{
			Audit: audit.Entry{Time: now, Action: ActionRevoked, Actor: by, Agent: g.Agent, Ref: g.Ref,
				Effect: policy.Deny, Rule: g.Rule, Target: target(g), Subject: id, Reason: reason},
			Events: []state.Event{{Kind: EventChanged, Subject: id, Time: now}},
		}, nil
	})
}

// List returns grants. An empty agentID lists every agent's grants (for
// operators); activeOnly keeps grants usable now.
func (s *Service) List(ctx context.Context, agentID string, activeOnly bool) ([]state.Grant, error) {
	f := state.GrantFilter{AgentID: agentID}
	if activeOnly {
		f.UsableAt = s.now()
	}
	var out []state.Grant
	err := s.st.View(ctx, func(tx state.Tx) error {
		var err error
		out, err = tx.ListGrants(ctx, f)
		return err
	})
	return out, err
}

// Get returns one grant. A non-empty agentID restricts it to that agent's
// grants: another agent's grant is reported as not found.
func (s *Service) Get(ctx context.Context, id, agentID string) (*state.Grant, error) {
	var g *state.Grant
	err := s.st.View(ctx, func(tx state.Tx) error {
		var err error
		g, err = tx.GetGrant(ctx, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	if agentID != "" && g.Agent.ID != agentID {
		return nil, state.ErrNotFound
	}
	return g, nil
}
