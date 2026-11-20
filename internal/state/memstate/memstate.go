// SPDX-License-Identifier: AGPL-3.0-only

// Package memstate is the memory state backend: nothing touches disk, and a
// restart loses pending approvals, grants and audit history
// (specs/state-and-scaling "Memory backend writes nothing to disk").
//
// Transactions are serialised by one lock. A read-write transaction keeps
// an undo log and replays it on rollback, so a failed [state.Apply] leaves
// neither the change nor its audit entry.
package memstate

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
)

// Name is the backend name in state.backend.
const Name = "memory"

func init() {
	state.RegisterBackend(Name, func(context.Context, *config.Config) (state.Store, error) { return New(), nil })
}

var errReadOnly = errors.New("memstate: write in a read-only transaction")

// Store is the memory backend.
type Store struct {
	mu        sync.RWMutex
	approvals map[string]*state.Approval
	grants    map[string]*state.Grant
	sessions  map[string]*state.Session
	auditLog  []audit.Entry
	events    []state.Event
	closed    bool
}

// New returns an empty store.
func New() *Store {
	return &Store{
		approvals: map[string]*state.Approval{},
		grants:    map[string]*state.Grant{},
		sessions:  map[string]*state.Session{},
	}
}

// Backend implements state.Store.
func (*Store) Backend() string { return Name }

// Migrate implements state.Store; there is no schema.
func (*Store) Migrate(context.Context) error { return nil }

// SchemaVersion implements state.Store.
func (*Store) SchemaVersion(context.Context) (int, error) { return 0, nil }

// Health implements state.Store.
func (s *Store) Health(context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errors.New("memstate: closed")
	}
	return nil
}

// Close implements state.Store and drops everything.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	clear(s.approvals)
	clear(s.grants)
	clear(s.sessions)
	s.auditLog, s.events = nil, nil
	return nil
}

// View implements state.Store.
func (s *Store) View(ctx context.Context, fn func(state.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errors.New("memstate: closed")
	}
	return fn(&tx{s: s, readOnly: true})
}

// Update implements state.Store.
func (s *Store) Update(ctx context.Context, fn func(state.Tx) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("memstate: closed")
	}
	t := &tx{s: s}
	defer func() {
		if r := recover(); r != nil {
			t.rollback()
			panic(r)
		}
		if err != nil {
			t.rollback()
		}
	}()
	return fn(t)
}

type tx struct {
	s        *Store
	readOnly bool
	undo     []func()
}

func (t *tx) rollback() {
	for i := len(t.undo) - 1; i >= 0; i-- {
		t.undo[i]()
	}
	t.undo = nil
}

func (t *tx) write() error {
	if t.readOnly {
		return errReadOnly
	}
	return nil
}

// put stores v under id in m, recording how to undo it.
func put[T any](t *tx, m map[string]*T, id string, v *T) {
	old, had := m[id]
	m[id] = v
	t.undo = append(t.undo, func() {
		if had {
			m[id] = old
		} else {
			delete(m, id)
		}
	})
}

func (t *tx) CreateApproval(_ context.Context, a *state.Approval) error {
	if err := t.write(); err != nil {
		return err
	}
	if a.ID == "" {
		a.ID = state.NewID()
	}
	if _, dup := t.s.approvals[a.ID]; dup {
		return state.ErrConflict
	}
	if a.Status == "" {
		a.Status = state.ApprovalPending
	}
	c := cloneApproval(*a)
	put(t, t.s.approvals, a.ID, &c)
	return nil
}

func (t *tx) GetApproval(_ context.Context, id string) (*state.Approval, error) {
	a, ok := t.s.approvals[id]
	if !ok {
		return nil, state.ErrNotFound
	}
	c := cloneApproval(*a)
	return &c, nil
}

func (t *tx) ListApprovals(_ context.Context, f state.ApprovalFilter) ([]state.Approval, error) {
	var out []state.Approval
	for _, a := range t.s.approvals {
		if (f.Status == "" || a.Status == f.Status) && (f.AgentID == "" || a.Request.Agent.ID == f.AgentID) {
			out = append(out, cloneApproval(*a))
		}
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i].CreatedAt, out[j].CreatedAt, out[i].ID, out[j].ID) })
	return limit(out, f.Limit), nil
}

func (t *tx) DecideApproval(_ context.Context, id string, status state.ApprovalStatus, by string, at time.Time) error {
	if err := t.write(); err != nil {
		return err
	}
	a, ok := t.s.approvals[id]
	if !ok {
		return state.ErrNotFound
	}
	if a.Status != state.ApprovalPending || status == state.ApprovalPending {
		return state.ErrConflict
	}
	c := cloneApproval(*a)
	c.Status, c.DecidedBy, c.DecidedAt = status, by, at
	put(t, t.s.approvals, id, &c)
	return nil
}

func (t *tx) CreateGrant(_ context.Context, g *state.Grant) error {
	if err := t.write(); err != nil {
		return err
	}
	if g.ID == "" {
		g.ID = state.NewID()
	}
	if _, dup := t.s.grants[g.ID]; dup {
		return state.ErrConflict
	}
	c := cloneGrant(*g)
	put(t, t.s.grants, g.ID, &c)
	return nil
}

func (t *tx) GetGrant(_ context.Context, id string) (*state.Grant, error) {
	g, ok := t.s.grants[id]
	if !ok {
		return nil, state.ErrNotFound
	}
	c := cloneGrant(*g)
	return &c, nil
}

func (t *tx) ListGrants(_ context.Context, f state.GrantFilter) ([]state.Grant, error) {
	var out []state.Grant
	for _, g := range t.s.grants {
		if f.AgentID != "" && g.Agent.ID != f.AgentID {
			continue
		}
		if !f.Ref.IsZero() && g.Ref != f.Ref {
			continue
		}
		if !f.UsableAt.IsZero() && !g.Usable(f.UsableAt) {
			continue
		}
		out = append(out, cloneGrant(*g))
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i].CreatedAt, out[j].CreatedAt, out[i].ID, out[j].ID) })
	return limit(out, f.Limit), nil
}

func (t *tx) UseGrant(_ context.Context, id string, at time.Time) (*state.Grant, error) {
	if err := t.write(); err != nil {
		return nil, err
	}
	g, ok := t.s.grants[id]
	if !ok {
		return nil, state.ErrNotFound
	}
	if !g.Usable(at) {
		return nil, state.ErrGrantUnusable
	}
	c := cloneGrant(*g)
	c.Uses++
	put(t, t.s.grants, id, &c)
	out := cloneGrant(c)
	return &out, nil
}

func (t *tx) RevokeGrant(_ context.Context, id, by string, at time.Time) error {
	if err := t.write(); err != nil {
		return err
	}
	g, ok := t.s.grants[id]
	if !ok {
		return state.ErrNotFound
	}
	if !g.RevokedAt.IsZero() {
		return state.ErrConflict
	}
	c := cloneGrant(*g)
	c.RevokedAt, c.RevokedBy = at, by
	put(t, t.s.grants, id, &c)
	return nil
}

func (t *tx) CreateSession(_ context.Context, s *state.Session) error {
	if err := t.write(); err != nil {
		return err
	}
	if s.RootStart > math.MaxInt64 {
		// Same contract as the SQL backends' signed column.
		return fmt.Errorf("create session: root process start time %d out of range", s.RootStart)
	}
	if s.ID == "" {
		s.ID = state.NewID()
	}
	if _, dup := t.s.sessions[s.ID]; dup {
		return state.ErrConflict
	}
	if s.TokenHash != "" {
		for _, o := range t.s.sessions {
			if o.TokenHash == s.TokenHash {
				return state.ErrConflict
			}
		}
	}
	c := cloneSession(*s)
	put(t, t.s.sessions, s.ID, &c)
	return nil
}

func (t *tx) GetSession(_ context.Context, id string) (*state.Session, error) {
	s, ok := t.s.sessions[id]
	if !ok {
		return nil, state.ErrNotFound
	}
	c := cloneSession(*s)
	return &c, nil
}

func (t *tx) SessionByTokenHash(_ context.Context, hash string) (*state.Session, error) {
	if hash == "" {
		return nil, state.ErrNotFound
	}
	for _, s := range t.s.sessions {
		if s.TokenHash == hash {
			c := cloneSession(*s)
			return &c, nil
		}
	}
	return nil, state.ErrNotFound
}

func (t *tx) ListSessions(_ context.Context, f state.SessionFilter) ([]state.Session, error) {
	var out []state.Session
	for _, s := range t.s.sessions {
		if f.AgentID != "" && s.Agent.ID != f.AgentID {
			continue
		}
		if f.Open && !s.EndedAt.IsZero() {
			continue
		}
		out = append(out, cloneSession(*s))
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i].CreatedAt, out[j].CreatedAt, out[i].ID, out[j].ID) })
	return limit(out, f.Limit), nil
}

func (t *tx) EndSession(_ context.Context, id string, at time.Time, reason string) error {
	if err := t.write(); err != nil {
		return err
	}
	s, ok := t.s.sessions[id]
	if !ok {
		return state.ErrNotFound
	}
	if !s.EndedAt.IsZero() {
		return state.ErrConflict
	}
	c := cloneSession(*s)
	c.EndedAt, c.EndReason = at, reason
	put(t, t.s.sessions, id, &c)
	return nil
}

func (t *tx) EndAgentSessions(ctx context.Context, agentID string, at time.Time, reason string) ([]string, error) {
	if err := t.write(); err != nil {
		return nil, err
	}
	if agentID == "" {
		return nil, nil
	}
	open, _ := t.ListSessions(ctx, state.SessionFilter{AgentID: agentID, Open: true})
	ids := make([]string, 0, len(open))
	for _, s := range open {
		c := cloneSession(s)
		c.EndedAt, c.EndReason = at, reason
		put(t, t.s.sessions, s.ID, &c)
		ids = append(ids, s.ID)
	}
	return ids, nil
}

func (t *tx) AppendAudit(_ context.Context, e *audit.Entry) error {
	if err := t.write(); err != nil {
		return err
	}
	n := len(t.s.auditLog)
	e.ID = int64(n) + 1
	if n > 0 {
		e.ID = t.s.auditLog[n-1].ID + 1
	}
	t.s.auditLog = append(t.s.auditLog, cloneEntry(*e))
	t.undo = append(t.undo, func() { t.s.auditLog = t.s.auditLog[:n] })
	return nil
}

func (t *tx) QueryAudit(_ context.Context, q state.AuditQuery) ([]audit.Entry, error) {
	var out []audit.Entry
	for _, e := range t.s.auditLog {
		switch {
		case e.ID <= q.AfterID,
			q.BeforeID > 0 && e.ID >= q.BeforeID,
			q.Effect != "" && e.Effect.String() != q.Effect,
			q.Outcome != "" && e.Outcome != q.Outcome,
			q.AgentID != "" && e.Agent.ID != q.AgentID,
			!q.Ref.IsZero() && e.Ref != q.Ref,
			q.Action != "" && e.Action != q.Action,
			!q.Since.IsZero() && e.Time.Before(q.Since),
			!q.Until.IsZero() && !e.Time.Before(q.Until):
			continue
		}
		out = append(out, cloneEntry(e))
	}
	if q.Newest {
		slices.Reverse(out)
	}
	return limit(out, q.Limit), nil
}

func (t *tx) Emit(_ context.Context, e *state.Event) error {
	if err := t.write(); err != nil {
		return err
	}
	n := len(t.s.events)
	e.ID = int64(n) + 1
	if n > 0 {
		e.ID = t.s.events[n-1].ID + 1
	}
	t.s.events = append(t.s.events, *e)
	t.undo = append(t.undo, func() { t.s.events = t.s.events[:n] })
	return nil
}

func (t *tx) EventsAfter(_ context.Context, after int64, n int) ([]state.Event, error) {
	i := sort.Search(len(t.s.events), func(i int) bool { return t.s.events[i].ID > after })
	return limit(slices.Clone(t.s.events[i:]), n), nil
}

func less(a, b time.Time, ida, idb string) bool {
	if !a.Equal(b) {
		return a.Before(b)
	}
	return ida < idb
}

func limit[T any](s []T, n int) []T {
	if n > 0 && len(s) > n {
		return s[:n]
	}
	return s
}

func cloneAgent(a policy.Agent) policy.Agent {
	a.Labels = maps.Clone(a.Labels)
	return a
}

func cloneApproval(a state.Approval) state.Approval {
	a.Request.Agent = cloneAgent(a.Request.Agent)
	return a
}

func cloneGrant(g state.Grant) state.Grant {
	g.Agent = cloneAgent(g.Agent)
	g.Scope = state.Scope{Hosts: slices.Clone(g.Scope.Hosts), Tools: slices.Clone(g.Scope.Tools)}
	return g
}

func cloneSession(s state.Session) state.Session {
	s.Agent = cloneAgent(s.Agent)
	s.Scopes = slices.Clone(s.Scopes)
	s.Labels = maps.Clone(s.Labels)
	return s
}

func cloneEntry(e audit.Entry) audit.Entry {
	e.Agent = cloneAgent(e.Agent)
	e.Attrs = maps.Clone(e.Attrs)
	return e
}
