// SPDX-License-Identifier: AGPL-3.0-only

// Package audit defines the audit entry and the sink contract
// (specs/policy-approvals "Audit log", specs/state-and-scaling "Multiple
// audit sinks" and "Audit backpressure is explicit").
//
// An [Entry] is metadata only: who, what, which reference, which decision.
// It has no field that can hold a value. The `db` sink is the state backend
// itself (the entry is written in the same transaction as the change it
// records); other sinks (OTLP, Loki, Kafka) implement [Sink] and are fed by
// a [Fanout] with a per-sink backpressure [Policy] (fanout.go).
package audit

import (
	"context"
	"maps"
	"sync"
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
	// Outcome is what came of the operation: [OutcomeOK], [OutcomeRefused],
	// [OutcomeFailed] or [OutcomePending]. Empty means not recorded.
	Outcome string
	// Reason is a human-readable explanation without values.
	Reason string
	// Attrs holds extra metadata. Never put a value here.
	Attrs map[string]string
}

// Outcomes of an audited operation (specs/policy-approvals "Audit log").
const (
	// OutcomeOK: the operation was carried out.
	OutcomeOK = "ok"
	// OutcomeRefused: policy, a guard or a human refused it.
	OutcomeRefused = "refused"
	// OutcomeFailed: it was allowed but did not complete.
	OutcomeFailed = "failed"
	// OutcomePending: it waits for an approval.
	OutcomePending = "pending"
)

// Clone returns a deep copy of e.
func Clone(e Entry) Entry {
	e.Agent.Labels = maps.Clone(e.Agent.Labels)
	e.Attrs = maps.Clone(e.Attrs)
	return e
}

// Sink receives audit entries.
type Sink interface {
	Name() string
	// Write delivers a batch. It returns an error if the batch was not
	// accepted; the Fanout then applies the sink's Policy.
	Write(ctx context.Context, batch []Entry) error
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
