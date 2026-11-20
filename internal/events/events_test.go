// SPDX-License-Identifier: AGPL-3.0-only

package events_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/events"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
)

// recorder collects delivered events.
type recorder struct {
	mu  sync.Mutex
	evs []state.Event
}

func (r *recorder) add(e state.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, e)
}

func (r *recorder) get() []state.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]state.Event(nil), r.evs...)
}

func (r *recorder) waitFor(t *testing.T, n int, within time.Duration) []state.Event {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		evs := r.get()
		if len(evs) >= n {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("got %d of %d events within %s: %+v", len(evs), n, within, evs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func emit(t *testing.T, s state.Store, kinds ...string) {
	t.Helper()
	err := state.Apply(context.Background(), s, func(state.Tx) (state.Change, error) {
		c := state.Change{Audit: auditEntry()}
		for _, k := range kinds {
			c.Events = append(c.Events, state.Event{Kind: k, Subject: k, Time: time.Now()})
		}
		return c, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func auditEntry() audit.Entry {
	return audit.Entry{Time: time.Now(), Action: "test.change", Actor: "test"}
}

// noHook hides the backend's commit hook, so only polling and the notifier
// can wake the bus.
type noHook struct{ state.Store }

func run(t *testing.T, b *events.Bus) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func TestStartsAfterHistoryAndWakesOnLocalCommit(t *testing.T) {
	st := memstate.New()
	emit(t, st, "old.one", "old.two")
	// A poll interval longer than the test: only the commit hook can
	// deliver in time.
	b, err := events.New(t.Context(), events.Options{State: st, PollInterval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if b.Last() != 2 {
		t.Fatalf("Last = %d, want 2", b.Last())
	}
	var all, decided recorder
	b.Subscribe("", all.add)
	b.Subscribe("approval.decided", decided.add)
	run(t, b)
	time.Sleep(50 * time.Millisecond) // past the first read
	emit(t, st, "approval.decided", "grant.changed")
	evs := all.waitFor(t, 2, 2*time.Second)
	if evs[0].Kind != "approval.decided" || evs[1].Kind != "grant.changed" {
		t.Fatalf("delivered %+v", evs)
	}
	if d := decided.waitFor(t, 1, time.Second); len(d) != 1 || d[0].Kind != "approval.decided" {
		t.Fatalf("kind filter delivered %+v", d)
	}
}

// TestOrderedExactlyOnce: concurrent writers and spurious wake-ups; every
// event arrives once, in increasing ID order.
func TestOrderedExactlyOnce(t *testing.T) {
	st := memstate.New()
	b, err := events.New(t.Context(), events.Options{State: st, PollInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var r recorder
	b.Subscribe("", r.add)
	run(t, b)
	const writers, each = 8, 50
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range each {
				emit(t, st, fmt.Sprintf("w%d.%d", w, i))
				b.Wake()
			}
		})
	}
	wg.Wait()
	r.waitFor(t, writers*each, 5*time.Second)
	time.Sleep(50 * time.Millisecond) // nothing more arrives
	evs := r.get()
	if len(evs) != writers*each {
		t.Fatalf("delivered %d events, want %d", len(evs), writers*each)
	}
	seen := map[string]bool{}
	for i, e := range evs {
		if i > 0 && e.ID <= evs[i-1].ID {
			t.Fatalf("event %d has ID %d after %d", i, e.ID, evs[i-1].ID)
		}
		if seen[e.Kind] {
			t.Fatalf("%s delivered twice", e.Kind)
		}
		seen[e.Kind] = true
	}
}

// fakeNotifier lets a test connect and disconnect the listener.
type fakeNotifier struct {
	ups  chan bool
	wake chan struct{}
}

func (f *fakeNotifier) Run(ctx context.Context, wake func(), up func(bool)) {
	for {
		select {
		case <-ctx.Done():
			return
		case v := <-f.ups:
			up(v)
		case <-f.wake:
			wake()
		}
	}
}

// TestCatchUpAfterReconnect: events committed with no notification (the
// listener was down when they committed) arrive when it reconnects, and
// while it is down the outbox is polled.
func TestCatchUpAfterReconnect(t *testing.T) {
	st := noHook{memstate.New()}
	n := &fakeNotifier{ups: make(chan bool), wake: make(chan struct{})}
	b, err := events.New(t.Context(), events.Options{State: st, Notifier: n, Backend: "fake", PollInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var r recorder
	b.Subscribe("", r.add)
	run(t, b)
	n.ups <- true
	waitUntil(t, "listening", b.Listening)
	time.Sleep(20 * time.Millisecond) // past the read the connect triggers

	// Connected: no notification, no delivery (the safety poll is a minute).
	emit(t, st, "missed.one", "missed.two")
	time.Sleep(300 * time.Millisecond)
	if got := r.get(); len(got) != 0 {
		t.Fatalf("delivered without a notification while listening: %+v", got)
	}
	// A notification delivers both.
	n.wake <- struct{}{}
	r.waitFor(t, 2, time.Second)

	// Down: the outbox is polled at events.poll-interval.
	n.ups <- false
	waitUntil(t, "not listening", func() bool { return !b.Listening() })
	time.Sleep(20 * time.Millisecond) // past the read the disconnect triggers
	emit(t, st, "polled")
	r.waitFor(t, 3, time.Second)

	// Committed while the listener reconnects, never notified: the read on
	// reconnect delivers it.
	n.ups <- true
	waitUntil(t, "listening again", b.Listening)
	time.Sleep(20 * time.Millisecond)
	emit(t, st, "lost.notification")
	time.Sleep(300 * time.Millisecond)
	if got := r.get(); len(got) != 3 {
		t.Fatalf("delivered %d events before the reconnect", len(got))
	}
	n.ups <- false
	n.ups <- true
	evs := r.waitFor(t, 4, time.Second)
	if evs[3].Kind != "lost.notification" {
		t.Fatalf("delivered %+v", evs)
	}
}

func waitUntil(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCheckReplicas(t *testing.T) {
	for _, c := range []struct {
		env  []string
		want string
	}{
		{nil, ""},
		{[]string{"SCRIM_DEPLOYMENT_REPLICAS=1", "SCRIM_STATE_BACKEND=sqlite"}, ""},
		{[]string{"SCRIM_DEPLOYMENT_REPLICAS=2"}, "events.backend"},
		{[]string{"SCRIM_DEPLOYMENT_REPLICAS=3", "SCRIM_STATE_BACKEND=postgres"}, "events.backend"},
		{[]string{"SCRIM_DEPLOYMENT_REPLICAS=2", "SCRIM_EVENTS_BACKEND=postgres", "SCRIM_STATE_BACKEND=memory"}, "state.backend"},
		{[]string{"SCRIM_DEPLOYMENT_REPLICAS=2", "SCRIM_EVENTS_BACKEND=postgres", "SCRIM_STATE_BACKEND=sqlite"}, "state.backend"},
		{[]string{"SCRIM_DEPLOYMENT_REPLICAS=2", "SCRIM_EVENTS_BACKEND=postgres", "SCRIM_STATE_BACKEND=postgres"}, ""},
	} {
		cfg, err := config.Load(config.Default, config.EnvLayer(c.env))
		if err != nil {
			t.Fatal(err)
		}
		err = events.CheckReplicas(cfg)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%v: %v", c.env, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "deployment.replicas")):
			t.Errorf("%v: error %v does not name %s and deployment.replicas", c.env, err, c.want)
		}
	}
	if _, err := config.Load(config.Default, config.EnvLayer([]string{"SCRIM_DEPLOYMENT_REPLICAS=0"})); err == nil {
		t.Error("deployment.replicas 0 accepted")
	}
}
