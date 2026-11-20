// SPDX-License-Identifier: AGPL-3.0-only

// Package audit defines the audit entry and the sink contract
// (specs/policy-approvals "Audit log", specs/state-and-scaling "Multiple
// audit sinks" and "Audit backpressure is explicit").
//
// An [Entry] is metadata only: who, what, which reference, which decision.
// It has no field that can hold a value. The `db` sink is the state backend
// itself (the entry is written in the same transaction as the change it
// records); other sinks (OTLP, Loki, Kafka) implement [Sink] and are fed by
// a [Fanout] with a per-sink backpressure [Policy].
package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/stores"
)

// Entry is one audit record.
type Entry struct {
	// ID is assigned by the state backend, increasing.
	ID int64
	// Time is when the audited event happened.
	Time time.Time
	// Action is what happened, dotted: "approval.created", "grant.revoked",
	// "store.write", "decision".
	Action string
	// Actor is who caused it: an agent ID, an operator name, "scrim".
	Actor string
	// Agent is the agent the event concerns, if any.
	Agent policy.Agent
	// Ref is the secret involved, if any.
	Ref stores.Ref
	// Effect and Rule record the policy decision, for decision entries.
	Effect policy.Effect
	Rule   string
	// Target is the destination host, tool or command.
	Target string
	// Subject is the ID of the approval, grant or session the entry is about.
	Subject string
	// RequestID correlates with logs and traces.
	RequestID string
	// Reason is a human-readable explanation without values.
	Reason string
	// Attrs holds extra metadata. Never put a value here.
	Attrs map[string]string
}

// Sink receives audit entries.
type Sink interface {
	Name() string
	// Write delivers a batch. It returns an error if the batch was not
	// accepted; the Fanout then applies the sink's Policy.
	Write(ctx context.Context, batch []Entry) error
}

// Policy is a sink's backpressure behaviour.
type Policy uint8

// Policies.
const (
	// Block makes the caller wait up to the sink's timeout, then fail,
	// so the audited operation is refused rather than done unaudited.
	Block Policy = iota
	// Drop counts and discards entries the sink cannot take.
	Drop
)

// ErrNotAudited is returned by [Fanout.Write] when a Block sink failed; the
// caller must refuse the operation the entries record.
var ErrNotAudited = errors.New("audit: entry not recorded by a blocking sink")

// Target is a sink with its policy.
type Target struct {
	Sink    Sink
	Policy  Policy
	Timeout time.Duration
	dropped atomic.Uint64
}

// Dropped is how many entries this target has dropped.
func (t *Target) Dropped() uint64 { return t.dropped.Load() }

// Fanout delivers every entry to every target.
type Fanout struct {
	Targets []*Target
	// OnDrop, if set, is called after entries are dropped, for metrics.
	OnDrop func(sink string, n int)
}

// Write delivers batch to every target concurrently. It returns
// [ErrNotAudited] (joined with the causes) if any Block target failed.
func (f *Fanout) Write(ctx context.Context, batch []Entry) error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for _, t := range f.Targets {
		wg.Go(func() {
			cctx := ctx
			if t.Timeout > 0 {
				var cancel context.CancelFunc
				cctx, cancel = context.WithTimeout(ctx, t.Timeout)
				defer cancel()
			}
			err := t.Sink.Write(cctx, batch)
			if err == nil {
				return
			}
			if t.Policy == Drop {
				t.dropped.Add(uint64(len(batch)))
				if f.OnDrop != nil {
					f.OnDrop(t.Sink.Name(), len(batch))
				}
				return
			}
			mu.Lock()
			errs = append(errs, fmt.Errorf("sink %s: %w", t.Sink.Name(), err))
			mu.Unlock()
		})
	}
	wg.Wait()
	if len(errs) > 0 {
		return errors.Join(append([]error{ErrNotAudited}, errs...)...)
	}
	return nil
}

// Memory is an in-memory sink for tests.
type Memory struct {
	SinkName string
	// Fail, if set, makes Write return it.
	Fail    error
	mu      sync.Mutex
	entries []Entry
}

// Name implements [Sink].
func (m *Memory) Name() string {
	if m.SinkName == "" {
		return "memory"
	}
	return m.SinkName
}

// Write implements [Sink].
func (m *Memory) Write(_ context.Context, batch []Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.entries = append(m.entries, batch...)
	return nil
}

// Entries returns a copy of everything written.
func (m *Memory) Entries() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Entry(nil), m.entries...)
}
