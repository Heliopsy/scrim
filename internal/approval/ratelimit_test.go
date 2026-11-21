// SPDX-License-Identifier: AGPL-3.0-only

package approval

import (
	"errors"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/ratelimit"
	"github.com/heliopsy/scrim/internal/state"
)

// TestCreateIsRateLimitedPerAgent: past its burst an agent's approval
// requests are refused before anything is stored or sent; another agent is
// unaffected.
func TestCreateIsRateLimitedPerAgent(t *testing.T) {
	limits := &ratelimit.Set{Limiter: ratelimit.NewLocal(nil), Limits: map[string]ratelimit.Limit{
		ratelimit.ClassApprovals: {Rate: 1, Interval: time.Hour, Burst: 2},
	}}
	f := newFixture(t, func(o *Options) { o.Limits = limits })
	f.create(t)
	f.create(t)
	_, err := f.svc.Create(f.ctx, Request{Policy: f.req, Decision: f.dec})
	var limited *ratelimit.LimitedError
	if !errors.As(err, &limited) || limited.Class != ratelimit.ClassApprovals {
		t.Fatalf("third approval = %v", err)
	}
	ps, _ := f.svc.List(f.ctx, state.ApprovalFilter{Status: state.ApprovalPending})
	if len(ps) != 2 {
		t.Fatalf("%d approvals stored, want 2", len(ps))
	}
	other := f.req
	other.Agent.ID = "another-agent"
	if _, err := f.svc.Create(f.ctx, Request{Policy: other, Decision: f.dec}); err != nil {
		t.Fatalf("another agent: %v", err)
	}
}
