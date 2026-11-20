// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/events/pgevents"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/postgres"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/testing/pgtest"
)

// replicaEnv runs a harness as one of several replicas sharing dsn, with
// every polling fallback far longer than the test, so only the events
// backend can carry a change from one replica to the other in time.
func replicaEnv(dsn string) []string {
	return []string{
		"SCRIM_DEPLOYMENT_REPLICAS=2",
		"SCRIM_STATE_BACKEND=postgres",
		"SCRIM_STATE_POSTGRES_DSN=env:SCRIMTEST_PG_DSN",
		"SCRIMTEST_PG_DSN=" + dsn,
		"SCRIM_EVENTS_BACKEND=postgres",
		"SCRIM_EVENTS_POLL_INTERVAL=50s",
		"SCRIM_APPROVALS_POLL_INTERVAL=50s",
		"SCRIM_POLICY_DENY_ALL_REFRESH=50s",
		"SCRIM_APPROVALS_TIMEOUT=2m",
	}
}

func startReplica(t *testing.T, ctx context.Context, token, dsn string) (*Daemon, *harness) {
	t.Helper()
	h := newHarness(t, token)
	h.opts.Config.Environ = append(h.opts.Config.Environ, replicaEnv(dsn)...)
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatalf("start replica: %v", err)
	}
	t.Cleanup(func() { _ = d.Shutdown(context.Background()) })
	if err := d.WaitReady(ctx); err != nil {
		t.Fatalf("%v\n%s", err, h.logs.String())
	}
	return d, h
}

// fast is the bound the test holds cross-replica delivery to; the polling
// fallbacks are 50s.
const fast = 3 * time.Second

func within(t *testing.T, what string, d time.Duration, fn func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !fn() {
		if time.Since(start) > d {
			t.Fatalf("%s did not happen within %s", what, d)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return time.Since(start)
}

// TestReplicasShareChangesThroughPostgresEvents runs two daemons on one
// PostgreSQL database (specs/state-and-scaling "Consistent approvals and
// grants across replicas", "Selectable event backend"): a decision made on
// A releases the request held on B, a grant revoked on B is refused on A, a
// session revoked on B is refused on A, break-glass engaged on A applies on
// B, and an event committed while B's listener is down still reaches B once
// it reconnects.
func TestReplicasShareChangesThroughPostgresEvents(t *testing.T) {
	dsn := pgtest.FreshDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	token := seed(t, "tok-")
	a, ha := startReplica(t, ctx, token, dsn)
	b, hb := startReplica(t, ctx, token, dsn)
	pa, pb := a.App().PolicyParts, b.App().PolicyParts
	within(t, "both listeners connected", 10*time.Second, func() bool {
		return a.App().Events.Listening() && b.App().Events.Listening()
	})

	agent := policy.Agent{ID: "dev", Kind: policy.IdentityPeer}
	req := policy.Request{Agent: agent, Action: policy.ActionInject, Ref: stores.MustParseRef("testenv://SCRIMTEST_TOKEN"),
		Host: "api.acme.test", Method: "GET"}

	// heldOnB asks on B and waits there; decideOnA settles the approval on A.
	heldOnB := func(id string) (<-chan gate.Verdict, string) {
		t.Helper()
		out := make(chan gate.Verdict, 1)
		go func() { out <- pb.Gate.Check(ctx, req, gate.Options{Wait: true, RequestID: id}) }()
		var approvalID string
		within(t, "the approval held on B", fast, func() bool {
			ps, _ := pa.Approvals.List(ctx, state.ApprovalFilter{Status: state.ApprovalPending})
			if len(ps) == 1 {
				approvalID = ps[0].ID
			}
			return approvalID != ""
		})
		time.Sleep(100 * time.Millisecond) // B's waiter has read the approval once
		return out, approvalID
	}
	decideOnA := func(id string, approve bool) {
		t.Helper()
		if _, err := pa.Approvals.Decide(ctx, id, approval.Decision{Approve: approve, By: "operator", Via: "test"}); err != nil {
			t.Fatalf("decide on A: %v", err)
		}
	}
	released := func(out <-chan gate.Verdict, what string, d time.Duration) gate.Verdict {
		t.Helper()
		select {
		case v := <-out:
			return v
		case <-time.After(d):
			t.Fatalf("%s: the request held on B was not released within %s", what, d)
		}
		return gate.Verdict{}
	}

	// (a) Approved on A, released on B.
	out, id := heldOnB("req-a")
	start := time.Now()
	decideOnA(id, true)
	v := released(out, "approval", fast)
	if !v.Allowed() || v.ApprovalID != id {
		t.Fatalf("B's verdict after approval on A = %+v", v)
	}
	t.Logf("approval decided on A released B's request in %s", time.Since(start))

	// (b) The approval left a grant. A uses it; B revokes it; A refuses the
	// next request and asks again.
	if v.GrantID == "" {
		t.Fatalf("approval created no grant: %+v", v)
	}
	if v := pa.Gate.Check(ctx, req, gate.Options{RequestID: "req-b1"}); !v.Allowed() || v.GrantID == "" {
		t.Fatalf("A with the grant = %+v", v)
	}
	if err := pb.Grants.Revoke(ctx, v.GrantID, "operator", "test"); err != nil {
		t.Fatal(err)
	}
	if v := pa.Gate.Check(ctx, req, gate.Options{RequestID: "req-b2"}); v.Allowed() || v.Status != gate.Pending {
		t.Fatalf("A after the grant was revoked on B = %+v", v)
	}
	// Clear the approval that request raised.
	ps, _ := pa.Approvals.List(ctx, state.ApprovalFilter{Status: state.ApprovalPending})
	for _, p := range ps {
		decideOnA(p.ID, false)
	}

	// Sessions: minted on B, verified on A, revoked on B, refused on A.
	peer := identity.Peer{UID: uint32(os.Getuid()), PID: int32(os.Getpid())} //nolint:gosec // ids fit
	m, err := b.runtime.Sessions.Mint(ctx, identity.Identity{Agent: "dev", Source: identity.SourcePeer, Peer: peer,
		Scopes: []identity.Scope{identity.ScopeSessionsMint}}, identity.MintRequest{Name: "replicas"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Token.Wipe()
	verifyOnA := func() error {
		return m.Token.Expose(func(tok []byte) error { _, err := a.runtime.Sessions.Verify(ctx, peer, tok); return err })
	}
	if err := verifyOnA(); err != nil {
		t.Fatalf("A refused a session minted on B: %v", err)
	}
	if err := b.runtime.Sessions.Revoke(ctx, m.Session.ID, "test"); err != nil {
		t.Fatal(err)
	}
	var refused *identity.RefusedError
	if err := verifyOnA(); !errors.As(err, &refused) || refused.Reason != identity.RefusedRevoked {
		t.Fatalf("A after the session was revoked on B: %v", err)
	}

	// (c) Break-glass engaged on A: B denies and pushes a snapshot with it.
	if err := pa.BreakGlass.Engage(ctx, "operator", "test"); err != nil {
		t.Fatal(err)
	}
	took := within(t, "break-glass on B", fast, func() bool {
		return pb.BreakGlass.Active() && hb.snapshot(t).GetPolicy().GetBreakGlass()
	})
	if v := pb.Gate.Check(ctx, req, gate.Options{RequestID: "req-c"}); v.Allowed() || v.Rule != "break-glass" {
		t.Fatalf("B under break-glass = %+v", v)
	}
	t.Logf("break-glass engaged on A reached B's data plane in %s", took)
	if err := pa.BreakGlass.Release(ctx, "operator", "test"); err != nil {
		t.Fatal(err)
	}
	within(t, "break-glass released on B", fast, func() bool {
		return !pb.BreakGlass.Active() && !hb.snapshot(t).GetPolicy().GetBreakGlass()
	})

	// (d) Terminate the listeners' backends and decide while B's is down:
	// the notification is lost, B's reconnect reads the outbox. A reconnect
	// faster than the decision proves nothing, so that round is repeated.
	nb, ok := b.App().Events.Notifier().(*pgevents.Notifier)
	if !ok {
		t.Fatalf("B's notifier is %T", b.App().Events.Notifier())
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	for round := 1; ; round++ {
		out, id := heldOnB("req-d")
		connects := nb.Connects()
		var killed int
		if err := admin.QueryRowContext(ctx, `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity
			WHERE application_name = $1 AND datname = current_database()`, postgres.ListenerApplicationName).Scan(&killed); err != nil || killed != 2 {
			t.Fatalf("terminated %d listener backends: %v", killed, err)
		}
		within(t, "B's listener notices", fast, func() bool { return !b.App().Events.Listening() })
		decided := time.Now()
		decideOnA(id, true)
		v := released(out, "catch-up", fast)
		if !v.Allowed() {
			t.Fatalf("B's verdict after the reconnect = %+v", v)
		}
		if nb.Connects() <= connects {
			t.Fatalf("B released the request without reconnecting (connects %d)", nb.Connects())
		}
		if nb.LastConnect().After(decided) {
			t.Logf("decided %s before B's listener reconnected; released %s after the decision",
				nb.LastConnect().Sub(decided), time.Since(decided))
			break
		}
		if round == 3 {
			t.Fatal("B's listener reconnected before the decision in every round")
		}
		if err := pb.Grants.Revoke(ctx, v.GrantID, "operator", "test"); err != nil {
			t.Fatal(err)
		}
	}

	// The configuration digests differ (each harness has its own paths):
	// A, which was running when B announced its digest, warns.
	within(t, "the configuration digest warning", fast, func() bool {
		return strings.Contains(ha.logs.String(), "replicas run different configurations")
	})

	// The database password reaches no log.
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("unparsable test DSN")
	}
	if pw, ok := u.User.Password(); ok && pw != "" {
		for name, h := range map[string]*harness{"A": ha, "B": hb} {
			if strings.Contains(h.logs.String(), pw) {
				t.Fatalf("the database password appears in replica %s's log", name)
			}
		}
	}
}
