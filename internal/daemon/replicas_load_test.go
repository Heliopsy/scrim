// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/testing/pgtest"
	"github.com/heliopsy/scrim/internal/testing/podtest"
)

var (
	valkeySvc = podtest.Valkey()
	natsSvc   = podtest.NATS()
)

// eventLog records every event one replica's bus delivers.
type eventLog struct {
	mu  sync.Mutex
	ids []int64
}

func (l *eventLog) add(e state.Event) { l.mu.Lock(); l.ids = append(l.ids, e.ID); l.mu.Unlock() }
func (l *eventLog) get() []int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.ids)
}

// TestReplicasLoad is the 14.1 multi-replica load test: three daemons on
// one PostgreSQL database with Valkey, then NATS, as the events backend
// (and Valkey for rate limits), every polling fallback far longer than the
// test. Concurrently, requests held for approval on every replica are
// decided on another, and the grants they leave are revoked on a third.
// Every held request is released with the decision made elsewhere, every
// revoked grant is refused on a replica that did not revoke it, and at the
// end every replica has delivered exactly the outbox, every event once, in
// the same order: the replicas agree and no event was lost.
func TestReplicasLoad(t *testing.T) {
	for _, backend := range []string{"valkey", "nats"} {
		t.Run(backend, func(t *testing.T) { replicasLoad(t, backend) })
	}
}

func replicasLoad(t *testing.T, backend string) {
	var env []string
	switch backend {
	case "valkey":
		addr := valkeySvc.Addr(t)
		env = []string{"SCRIM_EVENTS_BACKEND=valkey", "SCRIM_VALKEY_ADDRESSES=" + addr,
			"SCRIM_EVENTS_VALKEY_CHANNEL=scrim:load:" + podtest.RandHex(4),
			"SCRIM_RATELIMIT_BACKEND=valkey", "SCRIM_RATELIMIT_VALKEY_PREFIX=scrim:load:" + podtest.RandHex(4) + ":"}
	case "nats":
		url := natsSvc.Addr(t)
		if !strings.Contains(url, "://") {
			url = "nats://" + url
		}
		env = []string{"SCRIM_EVENTS_BACKEND=nats", "SCRIM_NATS_SERVERS=" + url,
			"SCRIM_EVENTS_NATS_SUBJECT=scrim.load." + podtest.RandHex(4)}
	}
	dsn := pgtest.FreshDSN(t)
	env = append(append(env, replicaKeyEnv()...),
		"SCRIM_DEPLOYMENT_REPLICAS=3",
		"SCRIM_STATE_BACKEND=postgres",
		"SCRIM_STATE_POSTGRES_DSN=env:SCRIMTEST_PG_DSN",
		"SCRIMTEST_PG_DSN="+dsn,
		"SCRIM_EVENTS_POLL_INTERVAL=50s",
		"SCRIM_APPROVALS_POLL_INTERVAL=50s",
		"SCRIM_POLICY_DENY_ALL_REFRESH=50s",
		"SCRIM_APPROVALS_TIMEOUT=2m",
		// One agent gets three approvals in total, whichever replica it asks.
		"SCRIM_RATELIMIT_APPROVALS_RATE=1",
		"SCRIM_RATELIMIT_APPROVALS_INTERVAL=24h",
		"SCRIM_RATELIMIT_APPROVALS_BURST=3",
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	token := seed(t, "tok-")
	var (
		ds   []*Daemon
		hs   []*harness
		logs []*eventLog
	)
	for range 3 {
		h := newHarness(t, token)
		h.opts.Config.Environ = append(h.opts.Config.Environ, env...)
		d, err := Start(ctx, h.opts)
		if err != nil {
			t.Fatalf("start replica: %v", err)
		}
		t.Cleanup(func() { _ = d.Shutdown(context.Background()) })
		if err := d.WaitReady(ctx); err != nil {
			t.Fatalf("%v\n%s", err, h.logs.String())
		}
		ds, hs = append(ds, d), append(hs, h)
	}
	within(t, "every replica's events subscription", 15*time.Second, func() bool {
		for _, d := range ds {
			if !d.App().Events.Listening() {
				return false
			}
		}
		return true
	})
	var start int64
	_ = ds[0].App().State.View(ctx, func(tx state.Tx) error {
		var err error
		start, err = tx.LastEventID(ctx)
		return err
	})
	for _, d := range ds {
		l := &eventLog{}
		logs = append(logs, l)
		d.App().Events.Subscribe("", func(e state.Event) {
			if e.ID > start {
				l.add(e)
			}
		})
	}
	part := func(i int) *app.Policy { return ds[i%3].App().PolicyParts }
	ref := stores.MustParseRef("testenv://SCRIMTEST_TOKEN")
	reqFor := func(agent string) policy.Request {
		return policy.Request{Agent: policy.Agent{ID: agent, Kind: policy.IdentityPeer}, Action: policy.ActionInject,
			Ref: ref, Host: "api.acme.test", Method: "GET"}
	}

	// Phase 1: N requests held on replica i%3, decided on (i+1)%3.
	const n = 24
	type outcome struct {
		i int
		v gate.Verdict
	}
	results := make(chan outcome, n)
	for i := range n {
		go func() {
			v := part(i).Gate.Check(ctx, reqFor(fmt.Sprintf("load-%d", i)), gate.Options{Wait: true, RequestID: fmt.Sprintf("held-%d", i)})
			results <- outcome{i, v}
		}()
	}
	pending := map[string]string{}
	within(t, "every held request has a pending approval", fast*3, func() bool {
		ps, err := part(0).Approvals.List(ctx, state.ApprovalFilter{Status: state.ApprovalPending})
		if err != nil {
			return false
		}
		for _, p := range ps {
			pending[p.Request.Agent.ID] = p.ID
		}
		return len(pending) == n
	})
	time.Sleep(200 * time.Millisecond) // every waiter has read its approval once
	began := time.Now()
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			id := pending[fmt.Sprintf("load-%d", i)]
			if _, err := part(i+1).Approvals.Decide(ctx, id, approval.Decision{Approve: i%4 != 0, By: "operator", Via: "load"}); err != nil {
				t.Errorf("decide %d: %v", i, err)
			}
		})
	}
	wg.Wait()
	grants := map[int]string{}
	for range n {
		select {
		case o := <-results:
			want := o.i%4 != 0
			if o.v.Allowed() != want {
				t.Fatalf("request %d held on replica %d: verdict %+v, want allowed=%v", o.i, o.i%3, o.v, want)
			}
			if want {
				if o.v.GrantID == "" {
					t.Fatalf("approved request %d left no grant", o.i)
				}
				grants[o.i] = o.v.GrantID
			}
		case <-time.After(fast * 2):
			t.Fatalf("held requests not all released within %s of their decisions", fast*2)
		}
	}
	t.Logf("%s: %d requests held on three replicas released %s after concurrent decisions elsewhere", backend, n, time.Since(began))

	// Phase 2: every grant works on another replica, then is revoked
	// concurrently on a third; afterwards every replica refuses it.
	for i, g := range grants {
		if v := part(i+2).Gate.Check(ctx, reqFor(fmt.Sprintf("load-%d", i)), gate.Options{RequestID: "use"}); !v.Allowed() || v.GrantID != g {
			t.Fatalf("grant %d on replica %d before revocation: %+v", i, (i+2)%3, v)
		}
	}
	for i, g := range grants {
		wg.Go(func() {
			if err := part(i+1).Grants.Revoke(ctx, g, "operator", "load"); err != nil {
				t.Errorf("revoke %d: %v", i, err)
			}
		})
	}
	wg.Wait()
	for i := range grants {
		for r := range 3 {
			v := part(r).Gate.Check(ctx, reqFor(fmt.Sprintf("load-%d", i)), gate.Options{RequestID: "after"})
			if v.Allowed() {
				t.Fatalf("replica %d honoured grant %d after it was revoked on replica %d: %+v", r, i, (i+1)%3, v)
			}
		}
	}

	// Phase 3 (valkey): the approvals rate limit is shared. The load
	// agents above already used up to three approvals each, so a fresh
	// agent asks through all three replicas in turn.
	if backend == "valkey" {
		allowed := 0
		for k := range 6 {
			v := part(k).Gate.Check(ctx, reqFor("limited"), gate.Options{RequestID: fmt.Sprintf("rl-%d", k)})
			switch {
			case v.Status == gate.Pending:
				allowed++
			case strings.Contains(v.Reason, "rate limit"):
			default:
				t.Fatalf("limited agent ask %d on replica %d: %+v", k, k%3, v)
			}
		}
		if allowed != 3 {
			t.Fatalf("the shared approvals limit allowed %d approvals through three replicas, want 3", allowed)
		}
	}

	// Agreement: every replica delivers exactly the outbox.
	var outbox []int64
	_ = ds[0].App().State.View(ctx, func(tx state.Tx) error {
		evs, err := tx.EventsAfter(ctx, start, 100000)
		for _, e := range evs {
			outbox = append(outbox, e.ID)
		}
		return err
	})
	if len(outbox) < n*2 {
		t.Fatalf("the outbox has only %d events", len(outbox))
	}
	within(t, "every replica delivered the outbox", fast, func() bool {
		for _, l := range logs {
			if len(l.get()) < len(outbox) {
				return false
			}
		}
		return true
	})
	time.Sleep(200 * time.Millisecond)
	for r, l := range logs {
		if got := l.get(); !slices.Equal(got, outbox) {
			t.Fatalf("replica %d delivered %d events, the outbox holds %d (first difference at %d)", r, len(got), len(outbox), firstDiff(got, outbox))
		}
	}
	t.Logf("%s: three replicas each delivered all %d outbox events once, in order", backend, len(outbox))
	for r, h := range hs {
		if strings.Contains(h.logs.String(), token) {
			t.Fatalf("the token reached replica %d's log", r)
		}
	}
}

func firstDiff(a, b []int64) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}
