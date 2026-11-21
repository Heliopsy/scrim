// SPDX-License-Identifier: AGPL-3.0-only

// Package eventstest is the contract every events backend passes
// (specs/state-and-scaling "Selectable event backend", "Ordered event
// outbox", "No event lost when the listener drops"; design D9). [Run] builds
// several replicas on one shared state and one events backend through a
// [Harness], runs a bus on each with polling far longer than the test, and
// checks: a commit on one replica reaches every replica by the backend
// alone; concurrent writers on every replica are delivered to every replica
// once each, in ID order; an event committed while a replica's listener is
// down arrives when it reconnects although its wake-up was lost; a commit
// made while the committing replica is cut off is announced once it is
// back; and a replica whose listener is down polls the outbox.
//
// The memory reference is [Hub] over [Shared] replicas of one memstate.
package eventstest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/events"
	"github.com/heliopsy/scrim/internal/state"
)

// Replica is one replica's view of the shared state and events backend.
type Replica struct {
	// State is this replica's handle on the shared state. Its commit hook
	// ([state.CommitHook]) must fire for commits made through it only.
	State state.Store
	// Notifier is this replica's events backend.
	Notifier events.Notifier
	// Interrupt cuts the replica's connections to the events backend and
	// keeps them down until restore runs. A backend whose hints travel
	// with the state transaction (postgres) cuts only the listener.
	Interrupt func(t *testing.T) (restore func())
}

// Harness builds replicas for one backend.
type Harness struct {
	// Backend names the backend in metrics and logs.
	Backend string
	// Replicas returns n replicas sharing one fresh state and backend.
	// Cleanup is the harness's (t.Cleanup).
	Replicas func(t *testing.T, n int) []Replica
	// Bound is the delivery bound the backend is held to; default 3s.
	Bound time.Duration
}

// Run runs the contract.
func Run(t *testing.T, h Harness) {
	if h.Bound == 0 {
		h.Bound = 3 * time.Second
	}
	t.Run("CrossReplicaDelivery", func(t *testing.T) { testDelivery(t, h) })
	t.Run("OrderedExactlyOnceUnderConcurrentWriters", func(t *testing.T) { testOrdered(t, h) })
	t.Run("CatchUpAfterListenerLoss", func(t *testing.T) { testCatchUp(t, h) })
	t.Run("CommitWhileCommitterCutOff", func(t *testing.T) { testCommitterCutOff(t, h) })
	t.Run("PollsWhileListenerDown", func(t *testing.T) { testPolls(t, h) })
}

// Recorder collects the events a bus delivers.
type Recorder struct {
	mu  sync.Mutex
	evs []state.Event
}

// Add records e; it fits [events.Handler].
func (r *Recorder) Add(e state.Event) { r.mu.Lock(); r.evs = append(r.evs, e); r.mu.Unlock() }

// Len is how many events were delivered.
func (r *Recorder) Len() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.evs) }

// Events returns a copy of the delivered events.
func (r *Recorder) Events() []state.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]state.Event(nil), r.evs...)
}

// node is one running replica.
type node struct {
	Replica
	bus *events.Bus
	rec *Recorder
}

func start(t *testing.T, h Harness, n int, poll time.Duration) []*node {
	t.Helper()
	reps := h.Replicas(t, n)
	nodes := make([]*node, len(reps))
	for i, r := range reps {
		bus, err := events.New(t.Context(), events.Options{State: r.State, Notifier: r.Notifier, Backend: h.Backend, PollInterval: poll})
		if err != nil {
			t.Fatal(err)
		}
		rec := &Recorder{}
		bus.Subscribe("", rec.Add)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { bus.Run(ctx); close(done) }()
		t.Cleanup(func() { cancel(); <-done })
		nodes[i] = &node{Replica: r, bus: bus, rec: rec}
	}
	for i, nd := range nodes {
		WaitUntil(t, fmt.Sprintf("replica %d listening", i), 20*time.Second, nd.bus.Listening)
	}
	// Past the read each connect triggers.
	time.Sleep(50 * time.Millisecond)
	return nodes
}

// Emit commits one change with an event of each kind through s.
func Emit(t testing.TB, s state.Store, kinds ...string) {
	t.Helper()
	err := state.Apply(context.Background(), s, func(state.Tx) (state.Change, error) {
		c := state.Change{Audit: audit.Entry{Time: time.Now(), Action: "test.change", Actor: "test"}}
		for _, k := range kinds {
			c.Events = append(c.Events, state.Event{Kind: k, Subject: k, Time: time.Now()})
		}
		return c, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// WaitUntil polls fn until it holds or d passes.
func WaitUntil(t testing.TB, what string, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting until %s", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func kinds(evs []state.Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Kind
	}
	return out
}

// testDelivery: a commit on A reaches B (and A) by the backend alone; the
// polls are a minute.
func testDelivery(t *testing.T, h Harness) {
	ns := start(t, h, 2, time.Minute)
	a, b := ns[0], ns[1]
	began := time.Now()
	Emit(t, a.State, "approval.decided")
	WaitUntil(t, "B delivers A's event", h.Bound, func() bool { return b.rec.Len() == 1 })
	t.Logf("%s: cross-replica delivery took %s", h.Backend, time.Since(began))
	WaitUntil(t, "A delivers its own event", h.Bound, func() bool { return a.rec.Len() == 1 })
	Emit(t, b.State, "grant.revoked")
	WaitUntil(t, "A delivers B's event", h.Bound, func() bool { return a.rec.Len() == 2 })
	WaitUntil(t, "B delivers its own event", h.Bound, func() bool { return b.rec.Len() == 2 })
	for i, nd := range ns {
		if got := kinds(nd.rec.Events()); fmt.Sprint(got) != "[approval.decided grant.revoked]" {
			t.Fatalf("replica %d delivered %v", i, got)
		}
	}
}

// testOrdered: writers on three replicas commit concurrently; every replica
// delivers every event exactly once, in increasing ID order.
func testOrdered(t *testing.T, h Harness) {
	ns := start(t, h, 3, time.Minute)
	const each = 40
	var wg sync.WaitGroup
	for w, nd := range ns {
		for g := range 2 {
			wg.Go(func() {
				for i := range each {
					Emit(t, nd.State, fmt.Sprintf("w%d.%d.%d", w, g, i))
				}
			})
		}
	}
	wg.Wait()
	total := len(ns) * 2 * each
	for i, nd := range ns {
		WaitUntil(t, fmt.Sprintf("replica %d delivers %d events", i, total), 4*h.Bound, func() bool { return nd.rec.Len() >= total })
	}
	time.Sleep(100 * time.Millisecond) // nothing more arrives
	var first []state.Event
	for i, nd := range ns {
		evs := nd.rec.Events()
		if len(evs) != total {
			t.Fatalf("replica %d delivered %d events, want %d", i, len(evs), total)
		}
		seen := map[string]bool{}
		for j, e := range evs {
			if j > 0 && e.ID <= evs[j-1].ID {
				t.Fatalf("replica %d: event %d has ID %d after %d", i, j, e.ID, evs[j-1].ID)
			}
			if seen[e.Kind] {
				t.Fatalf("replica %d: %s delivered twice", i, e.Kind)
			}
			seen[e.Kind] = true
		}
		if first == nil {
			first = evs
			continue
		}
		for j := range evs {
			if evs[j].ID != first[j].ID || evs[j].Kind != first[j].Kind {
				t.Fatalf("replicas 0 and %d disagree at %d: %+v vs %+v", i, j, first[j], evs[j])
			}
		}
	}
}

// testCatchUp: B's listener is cut and held down; events A commits then are
// not delivered to B (its poll is a minute) until it reconnects, and then
// all of them, in order; wake-ups work again afterwards.
func testCatchUp(t *testing.T, h Harness) {
	ns := start(t, h, 2, time.Minute)
	a, b := ns[0], ns[1]
	restore := b.Interrupt(t)
	WaitUntil(t, "B notices its listener is down", 10*time.Second, func() bool { return !b.bus.Listening() })
	time.Sleep(50 * time.Millisecond) // past the read the disconnect triggers
	Emit(t, a.State, "missed.one")
	Emit(t, a.State, "missed.two")
	WaitUntil(t, "A delivers", h.Bound, func() bool { return a.rec.Len() == 2 })
	time.Sleep(300 * time.Millisecond)
	if got := b.rec.Len(); got != 0 {
		t.Fatalf("B delivered %d events with its listener down and a one-minute poll", got)
	}
	restore()
	WaitUntil(t, "B catches up after reconnecting", 15*time.Second, func() bool { return b.rec.Len() == 2 })
	if got := kinds(b.rec.Events()); fmt.Sprint(got) != "[missed.one missed.two]" {
		t.Fatalf("B delivered %v", got)
	}
	WaitUntil(t, "B listening again", 10*time.Second, b.bus.Listening)
	Emit(t, a.State, "after.reconnect")
	WaitUntil(t, "B delivers a woken event after reconnecting", h.Bound, func() bool { return b.rec.Len() == 3 })
}

// testCommitterCutOff: A is cut off from the backend when it commits; once
// A is back, B learns about the commit without polling.
func testCommitterCutOff(t *testing.T, h Harness) {
	ns := start(t, h, 2, time.Minute)
	a, b := ns[0], ns[1]
	restore := a.Interrupt(t)
	WaitUntil(t, "A notices it is cut off", 10*time.Second, func() bool { return !a.bus.Listening() })
	Emit(t, a.State, "committed.while.cut.off")
	time.Sleep(200 * time.Millisecond)
	restore()
	WaitUntil(t, "B delivers the commit A made while cut off", 15*time.Second, func() bool { return b.rec.Len() == 1 })
}

// testPolls: with a short poll interval, a replica whose listener is down
// still delivers by reading the outbox.
func testPolls(t *testing.T, h Harness) {
	ns := start(t, h, 2, 100*time.Millisecond)
	a, b := ns[0], ns[1]
	restore := b.Interrupt(t)
	defer restore()
	WaitUntil(t, "B notices its listener is down", 10*time.Second, func() bool { return !b.bus.Listening() })
	Emit(t, a.State, "polled")
	WaitUntil(t, "B delivers by polling", 2*time.Second, func() bool { return b.rec.Len() == 1 })
	if b.bus.Listening() {
		t.Fatal("B reconnected while held down; the test proved nothing")
	}
}
