// SPDX-License-Identifier: AGPL-3.0-only

package grant

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
)

var (
	t0      = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	hetzner = stores.MustParseRef("bao://kv/agents/hetzner")
	agentA  = policy.Agent{ID: "agent-a", Kind: policy.IdentitySession}
	agentB  = policy.Agent{ID: "agent-b", Kind: policy.IdentitySession}
)

func req(a policy.Agent, host, tool string) policy.Request {
	return policy.Request{Agent: a, Action: policy.ActionInject, Ref: hetzner, Host: host, Tool: tool, Method: "POST"}
}

func setup(t *testing.T) (*Service, state.Store, *time.Time) {
	t.Helper()
	st := memstate.New()
	now := t0
	s := NewService(st, nil)
	s.SetClock(func() time.Time { return now })
	return s, st, &now
}

func issue(t *testing.T, s *Service, r policy.Request, scope policy.GrantScope, uses int, ttl time.Duration) state.Grant {
	t.Helper()
	g, err := Build(r, scope, uses, ttl, "jit", "appr-1", s.now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(context.Background(), &g, "alice"); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGrantCoversRepeatedCallsUntilExpiry(t *testing.T) {
	s, _, now := setup(t)
	ctx := context.Background()
	g := issue(t, s, req(agentA, "api.hetzner.cloud", "bash"), policy.ScopeRequest, 0, 30*time.Minute)
	for i := range 5 {
		*now = t0.Add(time.Duration(i) * 5 * time.Minute)
		got, err := s.Use(ctx, req(agentA, "API.hetzner.cloud", "bash"), "")
		if err != nil || got == nil || got.ID != g.ID || got.Uses != i+1 {
			t.Fatalf("call %d: %+v %v", i, got, err)
		}
	}
	*now = t0.Add(30 * time.Minute)
	if got, _ := s.Use(ctx, req(agentA, "api.hetzner.cloud", "bash"), ""); got != nil {
		t.Fatal("expired grant used on the next request")
	}
}

func TestUseCountExhausted(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	issue(t, s, req(agentA, "api.hetzner.cloud", ""), policy.ScopeRequest, 1, time.Hour)
	if got, _ := s.Use(ctx, req(agentA, "api.hetzner.cloud", ""), ""); got == nil {
		t.Fatal("first use refused")
	}
	if got, _ := s.Use(ctx, req(agentA, "api.hetzner.cloud", ""), ""); got != nil {
		t.Fatal("used-up grant honoured")
	}
}

func TestRevocationEffectiveOnNextRequest(t *testing.T) {
	s, st, _ := setup(t)
	ctx := context.Background()
	g := issue(t, s, req(agentA, "api.hetzner.cloud", ""), policy.ScopeRequest, 0, time.Hour)
	// A second service over the same backend stands in for another replica.
	other := NewService(st, nil)
	other.SetClock(s.now)
	if got, _ := other.Use(ctx, req(agentA, "api.hetzner.cloud", ""), ""); got == nil {
		t.Fatal("grant not visible on other replica")
	}
	if err := s.Revoke(ctx, g.ID, "alice", "done"); err != nil {
		t.Fatal(err)
	}
	if got, _ := other.Use(ctx, req(agentA, "api.hetzner.cloud", ""), ""); got != nil {
		t.Fatal("revoked grant honoured on other replica")
	}
	if err := s.Revoke(ctx, g.ID, "alice", ""); !errors.Is(err, state.ErrConflict) {
		t.Fatalf("double revoke: %v", err)
	}
	if err := s.Revoke(ctx, g.ID, "", ""); err == nil {
		t.Fatal("anonymous revoke accepted")
	}
}

func TestGrantBelongsToOneIdentity(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	g := issue(t, s, req(agentA, "api.hetzner.cloud", ""), policy.ScopeSecret, 0, time.Hour)
	if got, _ := s.Use(ctx, req(agentB, "api.hetzner.cloud", ""), ""); got != nil {
		t.Fatal("agent B used agent A's grant")
	}
	if _, err := s.Get(ctx, g.ID, "agent-b"); !errors.Is(err, state.ErrNotFound) {
		t.Fatal("agent B sees agent A's grant")
	}
	if gs, _ := s.List(ctx, "agent-b", true); len(gs) != 0 {
		t.Fatal("agent B lists agent A's grant")
	}
	unknown := policy.Agent{ID: "agent-a"} // same ID, no established identity
	if got, _ := s.Use(ctx, req(unknown, "api.hetzner.cloud", ""), ""); got != nil {
		t.Fatal("unidentified caller used a grant")
	}
}

func TestScopes(t *testing.T) {
	tests := []struct {
		scope      policy.GrantScope
		host, tool string
		want       bool
	}{
		{policy.ScopeRequest, "api.hetzner.cloud", "bash", true},
		{policy.ScopeRequest, "api.hetzner.cloud", "python", false},
		{policy.ScopeRequest, "evil.example", "bash", false},
		{policy.ScopeHost, "api.hetzner.cloud", "python", true},
		{policy.ScopeHost, "evil.example", "bash", false},
		{policy.ScopeSecret, "evil.example", "python", true},
	}
	for _, tt := range tests {
		g, err := Build(req(agentA, "api.hetzner.cloud", "bash"), tt.scope, 0, time.Hour, "r", "", t0)
		if err != nil {
			t.Fatal(err)
		}
		other := req(agentA, tt.host, tt.tool)
		if got := Covers(&g, other, t0); got != tt.want {
			t.Errorf("scope %s host %s tool %s: %v", tt.scope, tt.host, tt.tool, got)
		}
		other.Ref = stores.MustParseRef("bao://kv/agents/github")
		if Covers(&g, other, t0) {
			t.Errorf("scope %s covers another reference", tt.scope)
		}
	}
	if _, err := Build(req(policy.Agent{}, "h", ""), "", 0, time.Hour, "r", "", t0); !errors.Is(err, ErrNoIdentity) {
		t.Fatal("grant without identity built")
	}
	if _, err := Build(policy.Request{Agent: agentA}, "", 0, time.Hour, "r", "", t0); !errors.Is(err, ErrNoRef) {
		t.Fatal("grant without reference built")
	}
}

func TestLimits(t *testing.T) {
	cfg := config.MustLoadDefaults(config.Default)
	l := LimitsFor(cfg, policy.GrantSettings{})
	if l.Default != 30*time.Minute || l.Max != 8*time.Hour {
		t.Fatalf("defaults %+v", l)
	}
	l = LimitsFor(cfg, policy.GrantSettings{TTL: policy.Duration(time.Hour), MaxTTL: policy.Duration(2 * time.Hour)})
	if ttl, capped := l.TTL(0); ttl != time.Hour || capped {
		t.Fatal(ttl, capped)
	}
	if ttl, capped := l.TTL(3 * time.Hour); ttl != 2*time.Hour || !capped {
		t.Fatal(ttl, capped)
	}
	// A rule cannot raise the global maximum.
	l = LimitsFor(cfg, policy.GrantSettings{MaxTTL: policy.Duration(100 * time.Hour), TTL: policy.Duration(50 * time.Hour)})
	if l.Max != 8*time.Hour || l.Default != 8*time.Hour {
		t.Fatalf("rule raised max: %+v", l)
	}
}

func TestBreakGlassStopsGrants(t *testing.T) {
	ctx := context.Background()
	st := memstate.New()
	bg, err := breakglass.New(ctx, st, false)
	if err != nil {
		t.Fatal(err)
	}
	s := NewService(st, bg)
	g, _ := Build(req(agentA, "api.hetzner.cloud", ""), "", 0, time.Hour, "r", "", time.Now())
	if err := s.Create(ctx, &g, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := bg.Engage(ctx, "oncall", ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Use(ctx, req(agentA, "api.hetzner.cloud", ""), ""); got != nil {
		t.Fatal("grant honoured under deny-all")
	}
	g2, _ := Build(req(agentA, "api.hetzner.cloud", ""), "", 0, time.Hour, "r", "", time.Now())
	if err := s.Create(ctx, &g2, "alice"); !errors.Is(err, breakglass.ErrActive) {
		t.Fatalf("grant created under deny-all: %v", err)
	}
	if err := bg.Release(ctx, "oncall", ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Use(ctx, req(agentA, "api.hetzner.cloud", ""), ""); got == nil {
		t.Fatal("grant not honoured after release")
	}
}
