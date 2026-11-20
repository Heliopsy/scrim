// SPDX-License-Identifier: AGPL-3.0-only

// Package breakglass is the deny-all switch (specs/policy-approvals
// "Break-glass deny-all"). While it is engaged every injection, grant,
// approval and policy decision is refused; redaction is not affected,
// because redaction never asks for permission.
//
// The switch is engaged by the policy.deny-all setting or by an operator
// (CLI or admin API). The operator state lives in the audit log itself: the
// newest of the `breakglass.engaged` and `breakglass.released` entries
// decides. That makes it durable with the state backend, shared between
// replicas that share it, and impossible to change without an audit entry.
// Turning it off needs an explicit [Switch.Release]; a restart never does it
// unless the backend is memory, where every grant and approval is gone too.
package breakglass

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
)

// Audit actions and event kinds.
const (
	ActionEngaged  = "breakglass.engaged"
	ActionReleased = "breakglass.released"
	EventChanged   = "breakglass.changed"
)

// DenyAll is the configuration form of the switch.
var DenyAll = config.Register(config.Spec[bool]{
	Key:         "policy.deny-all",
	Default:     false,
	Description: "Break-glass: deny every injection, grant and approval while redaction continues. While set in configuration it cannot be released from the CLI.",
	Flag:        true,
})

// RefreshInterval bounds how long another replica takes to see a change.
var RefreshInterval = config.Register(config.Spec[time.Duration]{
	Key:         "policy.deny-all-refresh",
	Default:     time.Second,
	Description: "How often each replica re-reads the deny-all state from the state backend; the bound on how long a change on one replica takes to reach the others when no event announces it (events.backend).",
	Validate: func(d time.Duration) error {
		if d <= 0 || d > time.Minute {
			return errors.New("must be between 0 and 1m")
		}
		return nil
	},
})

// ErrConfigured is returned by Release while the switch is set in
// configuration.
var ErrConfigured = errors.New("breakglass: deny-all is set in configuration (policy.deny-all); change it there")

// ErrActive is the error paths return while deny-all is engaged.
var ErrActive = errors.New("break-glass deny-all is active")

// Status is the switch state for status output and the admin API.
type Status struct {
	Active bool `json:"active"`
	// Configured is true when policy.deny-all is set.
	Configured bool `json:"configured"`
	// Engaged is true when an operator engaged it.
	Engaged bool      `json:"engaged"`
	By      string    `json:"by,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Since   time.Time `json:"since,omitzero"`
}

// Switch is the deny-all state. Active is a lock-free read for hot paths.
type Switch struct {
	st         state.Store
	configured atomic.Bool
	engaged    atomic.Bool
	now        func() time.Time

	poke chan struct{}

	mu       sync.Mutex
	status   Status
	onChange []func(active bool)
}

// New loads the switch from st. configured is the policy.deny-all value.
func New(ctx context.Context, st state.Store, configured bool) (*Switch, error) {
	s := &Switch{st: st, now: time.Now, poke: make(chan struct{}, 1)}
	s.configured.Store(configured)
	if err := s.Refresh(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Active reports whether deny-all is in force.
func (s *Switch) Active() bool { return s.configured.Load() || s.engaged.Load() }

// Err returns [ErrActive] while active, nil otherwise.
func (s *Switch) Err() error {
	if s.Active() {
		return ErrActive
	}
	return nil
}

// Status returns the current state.
func (s *Switch) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	st.Configured = s.configured.Load()
	st.Active = st.Configured || st.Engaged
	return st
}

// OnChange registers fn to run whenever Active changes, for example to push
// a snapshot with deny_all set to the data plane.
func (s *Switch) OnChange(fn func(active bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = append(s.onChange, fn)
}

// SetConfigured applies a reloaded policy.deny-all value.
func (s *Switch) SetConfigured(v bool) {
	before := s.Active()
	s.configured.Store(v)
	s.notify(before)
}

// Engage turns deny-all on and records who did it.
func (s *Switch) Engage(ctx context.Context, by, reason string) error {
	return s.set(ctx, true, by, reason)
}

// Release turns operator deny-all off. It fails with [ErrConfigured] while
// the setting holds it on.
func (s *Switch) Release(ctx context.Context, by, reason string) error {
	if s.configured.Load() {
		return ErrConfigured
	}
	return s.set(ctx, false, by, reason)
}

func (s *Switch) set(ctx context.Context, on bool, by, reason string) error {
	if by == "" {
		return errors.New("breakglass: an operator name is required")
	}
	action := ActionReleased
	if on {
		action = ActionEngaged
	}
	now := s.now()
	err := state.Apply(ctx, s.st, func(state.Tx) (state.Change, error) {
		return state.Change{
			Audit:  audit.Entry{Time: now, Action: action, Actor: by, Reason: reason, Effect: effectFor(on), Rule: "break-glass"},
			Events: []state.Event{{Kind: EventChanged, Subject: action, Time: now}},
		}, nil
	})
	if err != nil {
		return fmt.Errorf("breakglass: %w", err)
	}
	return s.Refresh(ctx)
}

func effectFor(on bool) policy.Effect {
	if on {
		return policy.Deny
	}
	return policy.Allow
}

// Refresh re-reads the operator state from the audit log.
func (s *Switch) Refresh(ctx context.Context) error {
	var last *audit.Entry
	err := s.st.View(ctx, func(tx state.Tx) error {
		for _, a := range []string{ActionEngaged, ActionReleased} {
			es, err := tx.QueryAudit(ctx, state.AuditQuery{Action: a})
			if err != nil {
				return err
			}
			for i := range es {
				if last == nil || es[i].ID > last.ID {
					last = &es[i]
				}
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("breakglass: reading state: %w", err)
	}
	before := s.Active()
	s.mu.Lock()
	if last != nil && last.Action == ActionEngaged {
		s.status = Status{Engaged: true, By: last.Actor, Reason: last.Reason, Since: last.Time}
	} else {
		s.status = Status{}
	}
	s.engaged.Store(s.status.Engaged)
	s.mu.Unlock()
	s.notify(before)
	return nil
}

func (s *Switch) notify(before bool) {
	after := s.Active()
	if after == before {
		return
	}
	s.mu.Lock()
	fns := append([]func(bool){}, s.onChange...)
	s.mu.Unlock()
	for _, fn := range fns {
		fn(after)
	}
}

// Poke makes Run refresh now instead of at its next tick: the events
// backend calls it when another replica engages or releases deny-all. It
// never blocks.
func (s *Switch) Poke() {
	select {
	case s.poke <- struct{}{}:
	default:
	}
}

// Run refreshes every interval, and at once after each [Switch.Poke], until
// ctx ends, so a change made on another replica takes effect within
// interval even when no event announces it. A refresh error keeps the last
// known state; if that state was off, the error is the caller's to report
// as degraded.
func (s *Switch) Run(ctx context.Context, interval time.Duration, onErr func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.poke:
		}
		if err := s.Refresh(ctx); err != nil && onErr != nil {
			onErr(err)
		}
	}
}

// Engine wraps e so every decision is deny while the switch is active.
func (s *Switch) Engine(e policy.Engine) policy.Engine {
	return policy.BreakGlass{Engine: e, Active: s.Active}
}
