// SPDX-License-Identifier: AGPL-3.0-only

package grant

import (
	"context"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/policy"
)

func TestLeaseHolderEndsWithTheGrant(t *testing.T) {
	ctx := context.Background()
	active := func(s *Service, id string) (time.Time, bool) {
		t.Helper()
		until, ok, err := s.LeaseHolder(id).Active(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return until, ok
	}

	s, _, now := setup(t)
	g := issue(t, s, req(agentA, "db.example.test", ""), policy.ScopeRequest, 0, 30*time.Minute)
	if h := s.LeaseHolder(g.ID); h.ID != "grant:"+g.ID {
		t.Errorf("holder ID %q", h.ID)
	}
	until, ok := active(s, g.ID)
	if !ok || !until.Equal(g.ExpiresAt) {
		t.Fatalf("live grant: active %v until %v, want until %v", ok, until, g.ExpiresAt)
	}
	*now = g.ExpiresAt
	if _, ok := active(s, g.ID); ok {
		t.Error("expired grant still holds its leases")
	}

	*now = t0
	g2 := issue(t, s, req(agentA, "db.example.test", ""), policy.ScopeRequest, 0, time.Hour)
	if err := s.Revoke(ctx, g2.ID, "alice", "done"); err != nil {
		t.Fatal(err)
	}
	if _, ok := active(s, g2.ID); ok {
		t.Error("revoked grant still holds its leases")
	}

	g3 := issue(t, s, req(agentB, "db.example.test", ""), policy.ScopeRequest, 1, time.Hour)
	if got, err := s.Use(ctx, req(agentB, "db.example.test", ""), ""); err != nil || got == nil || got.ID != g3.ID {
		t.Fatalf("use: %v %v", got, err)
	}
	if _, ok := active(s, g3.ID); ok {
		t.Error("used-up grant still holds its leases")
	}
	if _, ok := active(s, "no-such-grant"); ok {
		t.Error("unknown grant holds leases")
	}
}
