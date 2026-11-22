// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// Policy is a sink's backpressure behaviour: what happens to an audited
// operation when the sink's queue is full because the sink is slow or down.
type Policy uint8

// Policies.
const (
	// Block makes the audited operation wait for queue space up to the
	// target's Timeout, then refuses it ([ErrNotAudited]): it is not done
	// unaudited.
	Block Policy = iota
	// Drop never makes an operation wait: entries that do not fit are
	// discarded, counted (scrim_audit_sink_dropped_total) and logged.
	Drop
)

// String names the policy as configuration spells it.
func (p Policy) String() string {
	if p == Drop {
		return "drop"
	}
	return "block"
}

// ParsePolicy reads "block" or "drop".
func ParsePolicy(s string) (Policy, error) {
	switch s {
	case "block":
		return Block, nil
	case "drop":
		return Drop, nil
	}
	return Block, fmt.Errorf("audit: unknown backpressure policy %q (want block or drop)", s)
}

// ErrNotAudited is returned when a Block sink could not take an entry
// within its timeout; the caller must refuse the operation it records.
var ErrNotAudited = errors.New("audit: entry not accepted by a blocking sink")

// Defaults of a [Target].
const (
	DefaultTimeout      = 5 * time.Second
	DefaultQueueSize    = 10000
	DefaultBatchSize    = 500
	DefaultWriteTimeout = 10 * time.Second
)

// Target is a sink with its backpressure settings.
type Target struct {
	Sink   Sink
	Policy Policy
	// Timeout bounds how long a Block target makes an audited operation
	// wait for queue space.
	Timeout time.Duration
	// QueueSize is how many entries wait for the sink at most.
	QueueSize int
	// BatchSize is how many entries one Write carries at most.
	BatchSize int
	// WriteTimeout bounds one Write attempt.
	WriteTimeout time.Duration
}

// Observer records sink metrics; obs.Instruments implements it.
type Observer interface {
	AuditSinkDelivered(sink string, n int, took time.Duration)
	AuditSinkWriteFailed(sink string, took time.Duration)
	AuditSinkDropped(sink, reason string, n int)
	AuditSinkRefused(sink string, n int)
	AuditSinkQueue(sink string, queued, capacity int)
	AuditSinkUp(sink string, up bool)
}

// Reasons an entry was dropped.
const (
	// DropQueueFull: a Drop sink's queue had no room.
	DropQueueFull = "queue_full"
	// DropShutdown: the process stopped before the sink took the entry.
	DropShutdown = "shutdown"
	// DropRejected: the sink rejected the batch as invalid, so retrying
	// it could never succeed ([Permanent]).
	DropRejected = "rejected"
)

// permanentError marks a write a retry cannot fix.
type permanentError struct{ err error }

func (p permanentError) Error() string { return p.err.Error() }
func (p permanentError) Unwrap() error { return p.err }

// Permanent marks err as a rejection a retry cannot fix (a sink answering
// 400 to a well-formed request it will never take). The fanout drops that
// batch, counted with reason rejected, instead of retrying it forever and
// blocking every entry behind it.
func Permanent(err error) error { return permanentError{err: err} }

// FanoutOptions configure a [Fanout].
type FanoutOptions struct {
	// Scrub, if set, filters every string of every entry before it is
	// queued, so a value that reached a free-text field never leaves.
	Scrub    func(string) string
	Observer Observer
	Log      *slog.Logger
	// MinBackoff and MaxBackoff bound the wait between failed writes.
	MinBackoff, MaxBackoff time.Duration
}

// Fanout delivers every audit entry to every target, additive to the state
// backend's audit log. Each target has its own bounded queue and writer, so
// a slow sink never slows another or, under Drop, any operation. A failed
// write is retried with backoff until it succeeds; entries leave the queue
// only when a sink accepted them or, counted, when a Drop queue overflows or
// the process stops.
type Fanout struct {
	o   FanoutOptions
	qs  []*queue
	wg  sync.WaitGroup
	mu  sync.Mutex
	ctx context.Context
	end context.CancelFunc
}

// NewFanout returns a fanout over targets; Start runs its writers.
func NewFanout(o FanoutOptions, targets ...Target) *Fanout {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = 100 * time.Millisecond
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 10 * time.Second
	}
	f := &Fanout{o: o}
	for _, t := range targets {
		if t.Timeout <= 0 {
			t.Timeout = DefaultTimeout
		}
		if t.QueueSize <= 0 {
			t.QueueSize = DefaultQueueSize
		}
		if t.BatchSize <= 0 {
			t.BatchSize = DefaultBatchSize
		}
		if t.WriteTimeout <= 0 {
			t.WriteTimeout = DefaultWriteTimeout
		}
		q := &queue{t: t, f: f, name: t.Sink.Name(), space: make(chan struct{}), ready: make(chan struct{}, 1)}
		q.up.Store(true)
		f.qs = append(f.qs, q)
		if o.Observer != nil {
			o.Observer.AuditSinkQueue(q.name, 0, t.QueueSize)
			o.Observer.AuditSinkUp(q.name, true)
		}
	}
	return f
}

// Empty reports whether the fanout has no target.
func (f *Fanout) Empty() bool { return f == nil || len(f.qs) == 0 }

// Start runs one writer per target until Close.
func (f *Fanout) Start(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ctx != nil {
		return
	}
	f.ctx, f.end = context.WithCancel(context.WithoutCancel(ctx))
	for _, q := range f.qs {
		f.wg.Go(func() { q.run(f.ctx) })
	}
}

// Reservation is queue space held on every Block target for entries a
// transaction is about to commit.
type Reservation struct {
	f    *Fanout
	n    int
	held []*queue
	once sync.Once
}

// Reserve holds room for n entries on every Block target, waiting up to
// each target's Timeout. It returns [ErrNotAudited], joined with the sinks
// that had no room, when one cannot make room in time; nothing is held then.
// Drop targets never wait.
func (f *Fanout) Reserve(ctx context.Context, n int) (*Reservation, error) {
	r := &Reservation{f: f, n: n}
	if f.Empty() {
		return r, nil
	}
	for _, q := range f.qs {
		if q.t.Policy != Block {
			continue
		}
		if err := q.reserve(ctx, n); err != nil {
			r.Cancel()
			return nil, errors.Join(ErrNotAudited, err)
		}
		r.held = append(r.held, q)
	}
	return r, nil
}

// Commit queues entries (at most the n reserved) on every target. Call it
// once the change they record has committed.
func (r *Reservation) Commit(entries []Entry) {
	r.once.Do(func() {
		if r.f.Empty() {
			return
		}
		if len(entries) > r.n {
			entries = entries[:r.n]
		}
		clean := make([]Entry, len(entries))
		for i, e := range entries {
			clean[i] = scrubEntry(Clone(e), r.f.o.Scrub)
		}
		for _, q := range r.f.qs {
			if q.t.Policy == Block {
				q.pushReserved(clean, r.n)
			} else {
				q.pushDrop(clean)
			}
		}
	})
}

// Cancel releases the reservation without queueing anything, for a change
// that rolled back.
func (r *Reservation) Cancel() {
	r.once.Do(func() {
		for _, q := range r.held {
			q.release(r.n)
		}
	})
}

// Write reserves and commits in one step, for entries that are already
// durable (the data plane's events after their transaction).
func (f *Fanout) Write(ctx context.Context, entries []Entry) error {
	r, err := f.Reserve(ctx, len(entries))
	if err != nil {
		return err
	}
	r.Commit(entries)
	return nil
}

// Close lets every writer drain its queue until ctx ends, then stops them.
// Entries still queued are counted as dropped (reason shutdown), logged,
// and reported in the returned error: never lost silently.
func (f *Fanout) Close(ctx context.Context) error {
	if f.Empty() {
		return nil
	}
	f.mu.Lock()
	started := f.ctx != nil
	f.mu.Unlock()
	if started {
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
	drain:
		for !f.drained() {
			select {
			case <-ctx.Done():
				break drain
			case <-t.C:
			}
		}
		f.end()
		f.wg.Wait()
	}
	var errs []error
	for _, q := range f.qs {
		if n := q.discard(); n > 0 {
			errs = append(errs, fmt.Errorf("audit sink %s: %d entries not delivered before shutdown", q.name, n))
		}
	}
	return errors.Join(errs...)
}

func (f *Fanout) drained() bool {
	for _, q := range f.qs {
		q.mu.Lock()
		busy := len(q.buf) > 0 || q.reserved > 0
		q.mu.Unlock()
		if busy {
			return false
		}
	}
	return true
}

// SinkStatus is one target as status reports it.
type SinkStatus struct {
	Name      string
	Policy    Policy
	Queued    int
	Capacity  int
	Delivered uint64
	Dropped   uint64
	Refused   uint64
	Up        bool
	LastError string
}

// Degraded reports a sink that is failing or more than 80% full.
func (s SinkStatus) Degraded() bool { return !s.Up || s.Queued*5 > s.Capacity*4 }

// Status reports every target.
func (f *Fanout) Status() []SinkStatus {
	if f.Empty() {
		return nil
	}
	out := make([]SinkStatus, 0, len(f.qs))
	for _, q := range f.qs {
		q.mu.Lock()
		s := SinkStatus{Name: q.name, Policy: q.t.Policy, Queued: len(q.buf), Capacity: q.t.QueueSize,
			Up: q.up.Load(), LastError: q.lastErr}
		q.mu.Unlock()
		s.Delivered, s.Dropped, s.Refused = q.delivered.Load(), q.dropped.Load(), q.refused.Load()
		out = append(out, s)
	}
	return out
}

// queue is one target's bounded queue and writer.
type queue struct {
	t    Target
	f    *Fanout
	name string

	mu       sync.Mutex
	buf      []Entry
	reserved int
	// space is closed and replaced whenever room frees up.
	space   chan struct{}
	ready   chan struct{}
	lastErr string
	lastLog time.Time

	up        atomic.Bool
	delivered atomic.Uint64
	dropped   atomic.Uint64
	refused   atomic.Uint64
}

func (q *queue) observe(fn func(Observer)) {
	if q.f.o.Observer != nil {
		fn(q.f.o.Observer)
	}
}

// freed wakes reservations waiting for room; q.mu is held.
func (q *queue) freed() {
	close(q.space)
	q.space = make(chan struct{})
}

func (q *queue) gauge() {
	q.mu.Lock()
	n := len(q.buf)
	q.mu.Unlock()
	q.observe(func(o Observer) { o.AuditSinkQueue(q.name, n, q.t.QueueSize) })
}

func (q *queue) reserve(ctx context.Context, n int) error {
	timer := time.NewTimer(q.t.Timeout)
	defer timer.Stop()
	for {
		q.mu.Lock()
		used := len(q.buf) + q.reserved
		if used+n <= q.t.QueueSize || used == 0 {
			q.reserved += n
			q.mu.Unlock()
			return nil
		}
		wait := q.space
		q.mu.Unlock()
		select {
		case <-wait:
			continue
		case <-timer.C:
		case <-ctx.Done():
		}
		q.refused.Add(uint64(n)) //nolint:gosec // n is a small positive count
		q.observe(func(o Observer) { o.AuditSinkRefused(q.name, n) })
		q.logf(slog.LevelError, "audit sink is full; refusing the audited operation (block policy)", "queued", used, "capacity", q.t.QueueSize)
		return fmt.Errorf("audit sink %s: queue full (%d of %d) for %s", q.name, used, q.t.QueueSize, q.t.Timeout)
	}
}

func (q *queue) release(n int) {
	q.mu.Lock()
	q.reserved -= n
	q.freed()
	q.mu.Unlock()
}

func (q *queue) signal() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

func (q *queue) pushReserved(es []Entry, n int) {
	q.mu.Lock()
	q.reserved -= n
	q.buf = append(q.buf, es...)
	if len(es) < n {
		q.freed()
	}
	q.mu.Unlock()
	q.signal()
	q.gauge()
}

func (q *queue) pushDrop(es []Entry) {
	q.mu.Lock()
	free := max(q.t.QueueSize-len(q.buf)-q.reserved, 0)
	take := min(free, len(es))
	q.buf = append(q.buf, es[:take]...)
	q.mu.Unlock()
	if take > 0 {
		q.signal()
		q.gauge()
	}
	if lost := len(es) - take; lost > 0 {
		q.dropped.Add(uint64(lost)) //nolint:gosec // positive
		q.observe(func(o Observer) { o.AuditSinkDropped(q.name, DropQueueFull, lost) })
		q.logf(slog.LevelWarn, "audit sink is full; dropping entries (drop policy, counted in scrim_audit_sink_dropped_total)",
			"dropped", lost, "capacity", q.t.QueueSize)
	}
}

// logf logs at most every ten seconds per sink, so an outage under load does
// not flood the log; the metrics count every entry.
func (q *queue) logf(level slog.Level, msg string, args ...any) {
	q.mu.Lock()
	now := time.Now()
	skip := now.Sub(q.lastLog) < 10*time.Second
	if !skip {
		q.lastLog = now
	}
	q.mu.Unlock()
	if !skip {
		q.f.o.Log.Log(context.Background(), level, msg, append([]any{"sink", q.name, "policy", q.t.Policy.String()}, args...)...)
	}
}

func (q *queue) discard() int {
	q.mu.Lock()
	n := len(q.buf)
	q.buf = nil
	q.freed()
	q.mu.Unlock()
	if n > 0 {
		q.dropped.Add(uint64(n)) //nolint:gosec // positive
		q.observe(func(o Observer) { o.AuditSinkDropped(q.name, DropShutdown, n) })
		q.f.o.Log.Error("audit sink did not take every entry before shutdown; they are in the database audit log only",
			"sink", q.name, "dropped", n)
		q.gauge()
	}
	return n
}

func (q *queue) run(ctx context.Context) {
	backoff := q.f.o.MinBackoff
	for {
		q.mu.Lock()
		n := min(len(q.buf), q.t.BatchSize)
		batch := append([]Entry(nil), q.buf[:n]...)
		q.mu.Unlock()
		if n == 0 {
			select {
			case <-ctx.Done():
				return
			case <-q.ready:
				continue
			}
		}
		start := time.Now()
		err := q.write(ctx, batch)
		took := time.Since(start)
		var perm permanentError
		if err != nil && errors.As(err, &perm) {
			q.mu.Lock()
			q.buf = q.buf[n:]
			q.lastErr = q.f.scrub(err.Error())
			q.freed()
			q.mu.Unlock()
			q.dropped.Add(uint64(n)) //nolint:gosec // positive
			q.observe(func(o Observer) {
				o.AuditSinkWriteFailed(q.name, took)
				o.AuditSinkDropped(q.name, DropRejected, n)
			})
			q.f.o.Log.Error("audit sink rejected a batch; dropped (counted in scrim_audit_sink_dropped_total, still in the database audit log)",
				"sink", q.name, "entries", n, "err", err)
			q.gauge()
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			q.mu.Lock()
			q.lastErr = q.f.scrub(err.Error())
			q.mu.Unlock()
			if q.up.Swap(false) {
				q.f.o.Log.Warn("audit sink write failed; retrying with backoff", "sink", q.name, "err", err)
				q.observe(func(o Observer) { o.AuditSinkUp(q.name, false) })
			}
			q.observe(func(o Observer) { o.AuditSinkWriteFailed(q.name, took) })
			d := backoff/2 + rand.N(backoff/2+1) //nolint:gosec // jitter, not a secret
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			backoff = min(backoff*2, q.f.o.MaxBackoff)
			continue
		}
		backoff = q.f.o.MinBackoff
		q.mu.Lock()
		q.buf = q.buf[n:]
		if len(q.buf) == 0 {
			q.buf = nil
		}
		q.lastErr = ""
		q.freed()
		q.mu.Unlock()
		q.delivered.Add(uint64(n)) //nolint:gosec // positive
		if !q.up.Swap(true) {
			q.f.o.Log.Info("audit sink is accepting entries again", "sink", q.name)
			q.observe(func(o Observer) { o.AuditSinkUp(q.name, true) })
		}
		q.observe(func(o Observer) { o.AuditSinkDelivered(q.name, n, took) })
		q.gauge()
	}
}

// write calls the sink with the write timeout, and gives up waiting a
// second after it even if the sink ignores its context, so a stuck sink
// cannot stall the queue or shutdown. A write abandoned that way may still
// complete later, a duplicate of the retry: delivery is at least once.
func (q *queue) write(ctx context.Context, batch []Entry) error {
	wctx, cancel := context.WithTimeout(ctx, q.t.WriteTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- q.t.Sink.Write(wctx, batch) }()
	select {
	case err := <-done:
		return err
	case <-wctx.Done():
	}
	grace := time.NewTimer(time.Second)
	defer grace.Stop()
	select {
	case err := <-done:
		return err
	case <-grace.C:
		return fmt.Errorf("audit sink %s: write did not return within %s", q.name, q.t.WriteTimeout)
	}
}

// scrubEntry filters every string of e.
func scrubEntry(e Entry, scrub func(string) string) Entry {
	if scrub == nil {
		return e
	}
	for _, p := range []*string{&e.Action, &e.Actor, &e.Agent.ID, &e.Agent.Session, &e.Rule, &e.Target, &e.Subject,
		&e.Ref.Scheme, &e.Ref.Path, &e.Ref.Field, &e.Ref.Selectors,
		&e.RequestID, &e.Outcome, &e.Reason} {
		*p = scrub(*p)
	}
	if len(e.Agent.Labels) > 0 {
		l := make(map[string]string, len(e.Agent.Labels))
		for k, v := range e.Agent.Labels {
			l[scrub(k)] = scrub(v)
		}
		e.Agent.Labels = l
	}
	if len(e.Attrs) > 0 {
		a := make(map[string]string, len(e.Attrs))
		for k, v := range e.Attrs {
			a[scrub(k)] = scrub(v)
		}
		e.Attrs = a
	}
	return e
}

func (f *Fanout) scrub(s string) string {
	if f.o.Scrub == nil {
		return s
	}
	return f.o.Scrub(s)
}
