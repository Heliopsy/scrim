// SPDX-License-Identifier: AGPL-3.0-only

package breakglass

import (
	"context"
	"errors"
	"testing"

	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
)

func TestEngageReleaseAndDurability(t *testing.T) {
	ctx := context.Background()
	st := memstate.New()
	s, err := New(ctx, st, false)
	if err != nil {
		t.Fatal(err)
	}
	var changes []bool
	s.OnChange(func(a bool) { changes = append(changes, a) })
	if s.Active() {
		t.Fatal("active at start")
	}
	if err := s.Engage(ctx, "", ""); err == nil {
		t.Fatal("anonymous engage accepted")
	}
	if err := s.Engage(ctx, "oncall", "token in transcript"); err != nil {
		t.Fatal(err)
	}
	if !s.Active() || s.Err() == nil || s.Status().By != "oncall" {
		t.Fatalf("status %+v", s.Status())
	}
	// A restart (a new switch over the same durable state) keeps it on.
	restarted, err := New(ctx, st, false)
	if err != nil || !restarted.Active() {
		t.Fatalf("deny-all lost on restart: %v", err)
	}
	if err := s.Release(ctx, "oncall", "rotated"); err != nil {
		t.Fatal(err)
	}
	if s.Active() {
		t.Fatal("still active after release")
	}
	// The other instance sees it on its next refresh.
	if err := restarted.Refresh(ctx); err != nil || restarted.Active() {
		t.Fatalf("release not seen by other replica: %v", err)
	}
	if len(changes) != 2 || !changes[0] || changes[1] {
		t.Fatalf("changes %v", changes)
	}
	var n int
	_ = st.View(ctx, func(tx state.Tx) error {
		a, _ := tx.QueryAudit(ctx, state.AuditQuery{Action: ActionEngaged})
		b, _ := tx.QueryAudit(ctx, state.AuditQuery{Action: ActionReleased})
		n = len(a) + len(b)
		return nil
	})
	if n != 2 {
		t.Fatalf("%d audit entries", n)
	}
}

func TestConfiguredCannotBeReleasedFromCLI(t *testing.T) {
	ctx := context.Background()
	s, err := New(ctx, memstate.New(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Active() {
		t.Fatal("configured deny-all inactive")
	}
	if err := s.Release(ctx, "oncall", ""); !errors.Is(err, ErrConfigured) {
		t.Fatalf("release of configured deny-all: %v", err)
	}
	s.SetConfigured(false)
	if s.Active() {
		t.Fatal("still active after config change")
	}
}

func TestEngineDeniesWhileActive(t *testing.T) {
	ctx := context.Background()
	s, _ := New(ctx, memstate.New(), false)
	e := s.Engine(policy.Static{Effect: policy.Allow})
	if d, _ := e.Decide(ctx, policy.Request{}); d.Effect != policy.Allow {
		t.Fatal("not allowed before")
	}
	_ = s.Engage(ctx, "oncall", "")
	if d, _ := e.Decide(ctx, policy.Request{}); d.Effect != policy.Deny || d.Rule != "break-glass" {
		t.Fatalf("decision under deny-all: %+v", d)
	}
}
