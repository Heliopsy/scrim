// SPDX-License-Identifier: AGPL-3.0-only

package gate

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/sqlite"
)

// durableGate opens the SQLite file at path and builds a gate over it, the
// way a restarted scrim would.
func durableGate(t *testing.T, path string) (*Gate, *approval.Service, *breakglass.Switch, state.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(ctx, path, sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	bg, err := breakglass.New(ctx, st, false)
	if err != nil {
		t.Fatal(err)
	}
	live, err := policy.NewLive(rules)
	if err != nil {
		t.Fatal(err)
	}
	apps, err := approval.New(approval.Options{State: st, Signer: approval.RandomSigner(), BreakGlass: bg,
		Timeout: time.Minute, PollInterval: 5 * time.Millisecond,
		Grants: func(rule string) (grant.Limits, policy.GrantSettings) {
			r, _ := live.Rule(rule)
			return grant.Limits{Default: 30 * time.Minute, Max: time.Hour}, r.Grant
		}})
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Engine: bg.Engine(live), Rules: live, Grants: grant.NewService(st, bg), Approvals: apps, BreakGlass: bg, State: st}
	return g, apps, bg, st
}

// TestRestartWithSQLite covers "Restart with SQLite": a grant and the
// deny-all switch survive a restart, and a pending approval can still be
// decided after the replica that created it is gone.
func TestRestartWithSQLite(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	g, apps, _, st := durableGate(t, path)
	req := inject(agentA, hetzner, "api.hetzner.cloud", "DELETE")
	v := g.Check(ctx, req, Options{})
	if v.Status != Pending {
		t.Fatalf("%+v", v)
	}
	if _, err := apps.Decide(ctx, v.ApprovalID, approval.Decision{Approve: true, By: "alice", Via: "terminal"}); err != nil {
		t.Fatal(err)
	}
	other := g.Check(ctx, inject(agentA, github, "api.github.com", "POST"), Options{})
	if other.Status != Pending {
		t.Fatalf("%+v", other)
	}
	_ = st.Close()

	g, apps, bg, st := durableGate(t, path)
	defer func() { _ = st.Close() }()
	if v := g.Check(ctx, req, Options{}); !v.Allowed() || v.GrantID == "" {
		t.Fatalf("grant lost on restart: %+v", v)
	}
	if _, err := apps.Decide(ctx, other.ApprovalID, approval.Decision{Approve: true, By: "bob", Via: "terminal"}); err != nil {
		t.Fatalf("pending approval lost on restart: %v", err)
	}
	if err := bg.Engage(ctx, "oncall", "drill"); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	g, _, bg, st = durableGate(t, path)
	defer func() { _ = st.Close() }()
	if !bg.Active() {
		t.Fatal("deny-all lost on restart")
	}
	if v := g.Check(ctx, req, Options{}); v.Allowed() {
		t.Fatalf("allowed under deny-all after restart: %+v", v)
	}
}
