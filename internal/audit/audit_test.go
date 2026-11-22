// SPDX-License-Identifier: AGPL-3.0-only

package audit_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/secret"
)

// gatedSink accepts writes only while open; closed, every write waits for
// its context, like a sink that stopped answering.
type gatedSink struct {
	name string
	mu   sync.Mutex
	open chan struct{}
	got  []audit.Entry
}

func newGated(name string, open bool) *gatedSink {
	g := &gatedSink{name: name, open: make(chan struct{})}
	if open {
		close(g.open)
	}
	return g
}

func (g *gatedSink) Name() string { return g.name }

func (g *gatedSink) Write(ctx context.Context, b []audit.Entry) error {
	g.mu.Lock()
	ch := g.open
	g.mu.Unlock()
	select {
	case <-ch:
	case <-ctx.Done():
		return ctx.Err()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.got = append(g.got, b...)
	return nil
}

func (g *gatedSink) setOpen() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.open:
	default:
		close(g.open)
	}
}

func (g *gatedSink) entries() []audit.Entry {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]audit.Entry(nil), g.got...)
}

type obsRec struct {
	mu      sync.Mutex
	dropped map[string]int
	refused map[string]int
	deliv   map[string]int
	up      map[string]bool
}

func newObs() *obsRec {
	return &obsRec{dropped: map[string]int{}, refused: map[string]int{}, deliv: map[string]int{}, up: map[string]bool{}}
}
func (o *obsRec) AuditSinkDelivered(s string, n int, _ time.Duration) {
	o.mu.Lock()
	o.deliv[s] += n
	o.mu.Unlock()
}
func (o *obsRec) AuditSinkWriteFailed(string, time.Duration) {}
func (o *obsRec) AuditSinkDropped(s, r string, n int) {
	o.mu.Lock()
	o.dropped[s+"/"+r] += n
	o.mu.Unlock()
}
func (o *obsRec) AuditSinkRefused(s string, n int) { o.mu.Lock(); o.refused[s] += n; o.mu.Unlock() }
func (o *obsRec) AuditSinkQueue(string, int, int)  {}
func (o *obsRec) AuditSinkUp(s string, up bool)    { o.mu.Lock(); o.up[s] = up; o.mu.Unlock() }
func (o *obsRec) get(m map[string]int, k string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return m[k]
}

func entries(n int, action string) []audit.Entry {
	out := make([]audit.Entry, n)
	for i := range out {
		out[i] = audit.Entry{ID: int64(i + 1), Action: action}
	}
	return out
}

func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDropPolicyCountsEveryLoss: a stalled drop sink never makes a caller
// wait; what does not fit its queue is counted and logged; the other sink
// receives everything; once the sink answers again its queue drains.
func TestDropPolicyCountsEveryLoss(t *testing.T) {
	ok := newGated("db-mirror", true)
	stalled := newGated("kafka", false)
	o := newObs()
	var logs syncBuf
	f := audit.NewFanout(audit.FanoutOptions{Observer: o, Log: newLog(&logs), MinBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond},
		audit.Target{Sink: ok, Policy: audit.Block, QueueSize: 1000},
		audit.Target{Sink: stalled, Policy: audit.Drop, QueueSize: 10, WriteTimeout: 50 * time.Millisecond})
	f.Start(t.Context())
	start := time.Now()
	for i := range 25 {
		if err := f.Write(t.Context(), entries(1, "e")); err != nil {
			t.Fatalf("write %d: a drop sink must never refuse: %v", i, err)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("writes waited %s on a stalled drop sink", d)
	}
	waitFor(t, "the healthy sink has all 25", func() bool { return len(ok.entries()) == 25 })
	st := f.Status()[1]
	if st.Dropped != 15 || st.Queued != 10 || o.get(o.dropped, "kafka/queue_full") != 15 {
		t.Fatalf("stalled sink status %+v, observed drops %v", st, o.dropped)
	}
	waitFor(t, "the stalled sink reported down", func() bool { return !f.Status()[1].Up })
	if !f.Status()[1].Degraded() {
		t.Fatal("a down sink is not degraded")
	}
	if !strings.Contains(logs.String(), "dropping entries") {
		t.Fatalf("drops were not logged: %s", logs.String())
	}
	stalled.setOpen()
	waitFor(t, "the stalled sink drains", func() bool { return len(stalled.entries()) == 10 })
	waitFor(t, "the sink reported up", func() bool { return f.Status()[1].Up })
	if err := f.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestBlockPolicyRefusesAfterTimeout: a stalled block sink makes callers
// wait for room up to its timeout and then refuses with ErrNotAudited;
// nothing is queued for a refused write; once the sink answers, writes go
// through again.
func TestBlockPolicyRefusesAfterTimeout(t *testing.T) {
	stalled := newGated("loki", false)
	o := newObs()
	f := audit.NewFanout(audit.FanoutOptions{Observer: o, MinBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond},
		audit.Target{Sink: stalled, Policy: audit.Block, QueueSize: 4, Timeout: 150 * time.Millisecond, WriteTimeout: 50 * time.Millisecond})
	f.Start(t.Context())
	for i := range 4 {
		if err := f.Write(t.Context(), entries(1, "fits")); err != nil {
			t.Fatalf("write %d within the queue: %v", i, err)
		}
	}
	start := time.Now()
	err := f.Write(t.Context(), entries(1, "refused"))
	waited := time.Since(start)
	if !errors.Is(err, audit.ErrNotAudited) || !strings.Contains(err.Error(), "loki") {
		t.Fatalf("write past a full block sink = %v", err)
	}
	if waited < 140*time.Millisecond || waited > time.Second {
		t.Fatalf("refused after %s, want about the 150ms timeout", waited)
	}
	if st := f.Status()[0]; st.Refused != 1 || st.Queued != 4 || st.Dropped != 0 || o.get(o.refused, "loki") != 1 {
		t.Fatalf("status %+v", st)
	}
	stalled.setOpen()
	waitFor(t, "the queue drains", func() bool { return len(stalled.entries()) == 4 })
	if err := f.Write(t.Context(), entries(1, "after")); err != nil {
		t.Fatalf("write after recovery: %v", err)
	}
	waitFor(t, "the last entry", func() bool { return len(stalled.entries()) == 5 })
	for _, e := range stalled.entries() {
		if e.Action == "refused" {
			t.Fatal("a refused entry reached the sink")
		}
	}
	if err := f.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestReservationWaitsForRoom: a reservation waiting on a full block sink
// goes through as soon as the sink drains, and a cancelled reservation
// frees its room.
func TestReservationWaitsForRoom(t *testing.T) {
	g := newGated("otlp", false)
	f := audit.NewFanout(audit.FanoutOptions{MinBackoff: 5 * time.Millisecond, MaxBackoff: 10 * time.Millisecond},
		audit.Target{Sink: g, Policy: audit.Block, QueueSize: 2, Timeout: 5 * time.Second, WriteTimeout: 20 * time.Millisecond})
	f.Start(t.Context())
	r, err := f.Reserve(t.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	r.Cancel()
	r, err = f.Reserve(t.Context(), 2)
	if err != nil {
		t.Fatalf("room was not freed by Cancel: %v", err)
	}
	r.Commit(entries(2, "held"))
	done := make(chan error, 1)
	go func() { done <- f.Write(t.Context(), entries(1, "waits")) }()
	select {
	case err := <-done:
		t.Fatalf("write did not wait for room: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	g.setOpen()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write still waiting after the sink drained")
	}
	waitFor(t, "all three", func() bool { return len(g.entries()) == 3 })
	_ = f.Close(t.Context())
}

// TestCloseCountsUndelivered: entries a sink never took by shutdown are
// counted, logged and returned as an error.
func TestCloseCountsUndelivered(t *testing.T) {
	g := newGated("kafka", false)
	o := newObs()
	var logs syncBuf
	f := audit.NewFanout(audit.FanoutOptions{Observer: o, Log: newLog(&logs), MinBackoff: 5 * time.Millisecond},
		audit.Target{Sink: g, Policy: audit.Drop, WriteTimeout: 20 * time.Millisecond})
	f.Start(t.Context())
	_ = f.Write(t.Context(), entries(3, "late"))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	err := f.Close(ctx)
	if err == nil || !strings.Contains(err.Error(), "3 entries not delivered") {
		t.Fatalf("Close = %v", err)
	}
	if o.get(o.dropped, "kafka/shutdown") != 3 || !strings.Contains(logs.String(), "before shutdown") {
		t.Fatalf("shutdown losses not counted or logged: %v %s", o.dropped, logs.String())
	}
}

// TestScrubbedBeforeQueue: every string field passes the scrubber before a
// sink sees it.
func TestScrubbedBeforeQueue(t *testing.T) {
	m := &audit.Memory{SinkName: "m"}
	f := audit.NewFanout(audit.FanoutOptions{Scrub: func(s string) string { return strings.ReplaceAll(s, "SEEDED", "[REDACTED]") }},
		audit.Target{Sink: m, Policy: audit.Drop})
	f.Start(t.Context())
	e := audit.Entry{Action: "a", Reason: "x SEEDED y", Target: "SEEDED", Attrs: map[string]string{"SEEDED": "v SEEDED"}}
	e.Agent.Labels = map[string]string{"l": "SEEDED"}
	if err := f.Write(t.Context(), []audit.Entry{e}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "delivery", func() bool { return len(m.Entries()) == 1 })
	got := m.Entries()[0]
	if strings.Contains(got.Reason+got.Target+got.Attrs["[REDACTED]"]+got.Agent.Labels["l"], "SEEDED") || got.Attrs["SEEDED"] != "" {
		t.Fatalf("not scrubbed: %+v", got)
	}
	if e.Attrs["SEEDED"] != "v SEEDED" {
		t.Fatal("the caller's entry was modified")
	}
	_ = f.Close(t.Context())
}

func TestParsePolicy(t *testing.T) {
	for _, p := range []audit.Policy{audit.Block, audit.Drop} {
		got, err := audit.ParsePolicy(p.String())
		if err != nil || got != p {
			t.Fatalf("%s round trip = %v %v", p, got, err)
		}
	}
	if _, err := audit.ParsePolicy("spill"); err == nil {
		t.Fatal("unknown policy accepted")
	}
}

// The entry type has no field that can carry a secret.Value.
func TestEntryHasNoValueField(t *testing.T) {
	assertNoSecretField(t, reflect.TypeFor[audit.Entry](), "Entry")
}

func assertNoSecretField(t *testing.T, typ reflect.Type, path string) {
	t.Helper()
	secretType := reflect.TypeFor[secret.Value]()
	switch typ.Kind() {
	case reflect.Struct:
		if typ == secretType {
			t.Fatalf("%s is a secret.Value", path)
		}
		for i := range typ.NumField() {
			f := typ.Field(i)
			assertNoSecretField(t, f.Type, path+"."+f.Name)
		}
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		assertNoSecretField(t, typ.Elem(), path+"[]")
	}
}

type rejecting struct{ calls int }

func (r *rejecting) Name() string { return "loki" }
func (r *rejecting) Write(context.Context, []audit.Entry) error {
	r.calls++
	return audit.Permanent(errors.New("400 bad request"))
}

// TestPermanentRejectionIsCounted: a batch the sink rejects for good is
// dropped once, counted with reason rejected, not retried forever.
func TestPermanentRejectionIsCounted(t *testing.T) {
	r := &rejecting{}
	o := newObs()
	f := audit.NewFanout(audit.FanoutOptions{Observer: o}, audit.Target{Sink: r, Policy: audit.Block})
	f.Start(t.Context())
	if err := f.Write(t.Context(), entries(2, "bad")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the rejection counted", func() bool { return o.get(o.dropped, "loki/rejected") == 2 })
	time.Sleep(50 * time.Millisecond)
	if err := f.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r.calls != 1 {
		t.Fatalf("rejected batch written %d times", r.calls)
	}
}
