// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"context"
	"fmt"
	"strings"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// Locator is implemented by backends that can say where their data lives
// without credentials.
type Locator interface{ Location() string }

// StateOf reports a state backend. Err, when set, is why it could not be
// opened.
type StateOf struct {
	Store state.Store
	// Name is the configured backend, used when Store is nil.
	Name string
	Err  error
	// Info, when set, replaces the detail of a healthy report, for example
	// "held by the running scrim process 4242".
	Info string
}

// StateStatus implements [StateSource].
func (s StateOf) StateStatus(ctx context.Context) State {
	if s.Store == nil {
		st := State{Backend: s.Name, Healthy: s.Err == nil && s.Info != "", Detail: s.Info}
		if s.Err != nil {
			st.Detail = s.Err.Error()
		}
		return st
	}
	st := State{Backend: s.Store.Backend(), Healthy: true, Detail: s.Info}
	if l, ok := s.Store.(Locator); ok {
		st.Location = l.Location()
	}
	if err := s.Store.Health(ctx); err != nil {
		st.Healthy, st.Detail = false, err.Error()
		return st
	}
	v, err := s.Store.SchemaVersion(ctx)
	if err != nil {
		st.Healthy, st.Detail = false, fmt.Sprintf("reading schema version: %v", err)
	}
	st.SchemaVersion = v
	return st
}

// DBAuditSink reports the db audit sink, which is the state backend itself
// and always blocks: an entry it cannot write refuses the change.
// External lists the external sinks a running daemon reported.
type DBAuditSink struct {
	State    StateSource
	External []AuditSink
}

// AuditSinks implements [AuditSource].
func (d DBAuditSink) AuditSinks(ctx context.Context) []AuditSink {
	st := d.State.StateStatus(ctx)
	sink := AuditSink{Name: "db", Policy: "block", Degraded: !st.Healthy}
	if !st.Healthy {
		sink.Detail = "state backend unhealthy"
	}
	return append([]AuditSink{sink}, d.External...)
}

// FromFanout converts the external sinks' state. A sink is degraded while
// its writes fail, while its queue is more than 80% full, and once it has
// dropped or refused an entry since start-up, so a loss stays visible.
func FromFanout(sts []audit.SinkStatus) []AuditSink {
	out := make([]AuditSink, 0, len(sts))
	for _, s := range sts {
		a := AuditSink{Name: s.Name, Policy: s.Policy.String(), Dropped: s.Dropped,
			Degraded: s.Degraded() || s.Dropped > 0 || s.Refused > 0}
		var parts []string
		if !s.Up {
			parts = append(parts, "writes failing: "+s.LastError)
		}
		parts = append(parts, fmt.Sprintf("queue %d/%d", s.Queued, s.Capacity))
		if s.Refused > 0 {
			parts = append(parts, fmt.Sprintf("%d entries refused", s.Refused))
		}
		a.Detail = strings.Join(parts, "; ")
		out = append(out, a)
	}
	return out
}

// StoreSet reports every adapter of a set by its Health check.
type StoreSet struct{ Set *stores.Set }

// StoreHealth implements [StoreSource].
func (s StoreSet) StoreHealth(ctx context.Context) []Store {
	var out []Store
	for _, a := range s.Set.Adapters() {
		st := Store{Name: a.Name(), Reachable: true}
		if err := a.Health(ctx); err != nil {
			st.Reachable, st.Degraded, st.Reason = false, true, err.Error()
		}
		out = append(out, st)
	}
	return out
}
