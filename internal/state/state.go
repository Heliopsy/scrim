// SPDX-License-Identifier: AGPL-3.0-only

// Package state is the persistence boundary for scrim's non-secret state:
// approvals, grants, sessions, audit entries and the event outbox
// (specs/state-and-scaling, design D9).
//
// No type here can hold a secret value; a test walks every type to prove it.
// Every mutation goes through [Apply], which writes the change, its audit
// entry and its events in one transaction, so a failure between them leaves
// none of them (the tix shape). Backends: memory (package memstate), SQLite
// and PostgreSQL, all passing the contract suite in package statetest.
package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/stores"
)

// Errors returned by every backend.
var (
	ErrNotFound = errors.New("state: not found")
	// ErrConflict: the row already exists, or a transition is not allowed
	// from the current status (deciding an approval twice).
	ErrConflict = errors.New("state: conflict")
	// ErrGrantUnusable: the grant is expired, revoked or out of uses.
	ErrGrantUnusable = errors.New("state: grant expired, revoked or used up")
	// ErrNoAudit: Apply was given a change without an audit entry.
	ErrNoAudit = errors.New("state: every change needs an audit entry")
	// ErrSchemaTooNew: the database was migrated by a newer scrim.
	ErrSchemaTooNew = errors.New("state: database schema is newer than this binary")
)

// ApprovalStatus is the life cycle of an approval.
type ApprovalStatus string

// Approval statuses. Only pending moves, and only once.
const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalExpired  ApprovalStatus = "expired"
)

// Approval is a request waiting for, or decided by, a human.
type Approval struct {
	ID      string
	Status  ApprovalStatus
	Request policy.Request
	Rule    string
	Reason  string
	// GrantTTL is the grant duration the approval would create.
	GrantTTL  time.Duration
	CreatedAt time.Time
	ExpiresAt time.Time
	DecidedAt time.Time
	DecidedBy string
}

// Scope limits what a grant covers. An empty list means any.
type Scope struct {
	Hosts []string
	Tools []string
}

// Grant is a just-in-time permission.
type Grant struct {
	ID    string
	Agent policy.Agent
	Ref   stores.Ref
	Scope Scope
	// MaxUses is the use limit, 0 for unlimited; Uses counts uses so far.
	MaxUses    int
	Uses       int
	ApprovalID string
	Rule       string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
	RevokedBy  string
}

// Usable reports whether the grant can be used at t.
func (g Grant) Usable(t time.Time) bool {
	return g.RevokedAt.IsZero() && t.Before(g.ExpiresAt) && (g.MaxUses == 0 || g.Uses < g.MaxUses)
}

// Session is one agent session, for example one `scrim run`.
type Session struct {
	ID    string
	Agent policy.Agent
	// TokenHash is a hash of the session token; the token itself is never
	// stored.
	TokenHash string
	CreatedAt time.Time
	ExpiresAt time.Time
	EndedAt   time.Time
	Labels    map[string]string
}

// Event is an outbox row, delivered by the events backend after commit.
type Event struct {
	// ID is assigned by the backend, increasing.
	ID int64
	// Kind is dotted: "approval.decided", "grant.revoked", "config.reloaded".
	Kind string
	// Subject is the ID of what changed.
	Subject string
	Time    time.Time
}

// ApprovalFilter selects approvals. Zero fields match anything.
type ApprovalFilter struct {
	Status  ApprovalStatus
	AgentID string
	Limit   int
}

// GrantFilter selects grants. Zero fields match anything.
type GrantFilter struct {
	AgentID string
	Ref     stores.Ref
	// UsableAt, if set, keeps only grants usable at that time.
	UsableAt time.Time
	Limit    int
}

// AuditQuery selects audit entries (specs/policy-approvals "Querying the
// audit log"). Zero fields match anything.
type AuditQuery struct {
	AgentID string
	Ref     stores.Ref
	Action  string
	// Effect matches the decision by name ("allow", "deny", "ask"); a
	// string so that empty can mean any, since the zero Effect is Deny.
	Effect string
	// Outcome matches audit.Entry.Outcome.
	Outcome string
	Since   time.Time
	Until   time.Time
	// AfterID keeps entries with a larger ID, BeforeID with a smaller one:
	// the cursors for paging oldest first and newest first.
	AfterID  int64
	BeforeID int64
	// Newest returns entries newest first, so Limit keeps the latest.
	// The default is oldest first.
	Newest bool
	Limit  int
}

// Tx is one transaction. Methods return [ErrNotFound] and [ErrConflict]
// where noted; IDs left empty on create are assigned with [NewID].
type Tx interface {
	CreateApproval(ctx context.Context, a *Approval) error
	GetApproval(ctx context.Context, id string) (*Approval, error)
	ListApprovals(ctx context.Context, f ApprovalFilter) ([]Approval, error)
	// DecideApproval moves a pending approval to status; ErrConflict if it
	// is not pending.
	DecideApproval(ctx context.Context, id string, status ApprovalStatus, by string, at time.Time) error

	CreateGrant(ctx context.Context, g *Grant) error
	GetGrant(ctx context.Context, id string) (*Grant, error)
	ListGrants(ctx context.Context, f GrantFilter) ([]Grant, error)
	// UseGrant counts one use at t and returns the updated grant;
	// ErrGrantUnusable if it cannot be used.
	UseGrant(ctx context.Context, id string, at time.Time) (*Grant, error)
	RevokeGrant(ctx context.Context, id string, by string, at time.Time) error

	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	SessionByTokenHash(ctx context.Context, hash string) (*Session, error)
	EndSession(ctx context.Context, id string, at time.Time) error

	// AppendAudit assigns e.ID.
	AppendAudit(ctx context.Context, e *audit.Entry) error
	QueryAudit(ctx context.Context, q AuditQuery) ([]audit.Entry, error)

	// Emit adds an event to the outbox; it is visible only after commit.
	Emit(ctx context.Context, e *Event) error
	// EventsAfter returns committed events with ID > after, oldest first.
	EventsAfter(ctx context.Context, after int64, limit int) ([]Event, error)
}

// Store opens transactions.
type Store interface {
	// View runs fn in a read-only transaction. Mutating methods return an
	// error inside it.
	View(ctx context.Context, fn func(Tx) error) error
	// Update runs fn in a read-write transaction, committing when fn
	// returns nil and rolling back otherwise. Prefer [Apply].
	Update(ctx context.Context, fn func(Tx) error) error
	// Migrate brings the schema to this binary's version; ErrSchemaTooNew
	// if it is ahead.
	Migrate(ctx context.Context) error
	SchemaVersion(ctx context.Context) (int, error)
	Health(ctx context.Context) error
	// Backend is the backend name, as in state.backend.
	Backend() string
	Close() error
}

// Change is what a mutation records besides its own rows.
type Change struct {
	Audit  audit.Entry
	Events []Event
}

// Apply runs fn and records the [Change] it returns in the same
// transaction: the state change, its audit entry and its events commit
// together or not at all.
func Apply(ctx context.Context, s Store, fn func(tx Tx) (Change, error)) error {
	return s.Update(ctx, func(tx Tx) error {
		c, err := fn(tx)
		if err != nil {
			return err
		}
		if c.Audit.Action == "" {
			return ErrNoAudit
		}
		if err := tx.AppendAudit(ctx, &c.Audit); err != nil {
			return fmt.Errorf("state: audit entry: %w", err)
		}
		for i := range c.Events {
			if err := tx.Emit(ctx, &c.Events[i]); err != nil {
				return fmt.Errorf("state: event: %w", err)
			}
		}
		return nil
	})
}

// NewID returns a random 128-bit identifier in hex.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return hex.EncodeToString(b)
}

// Opener opens a backend from the effective configuration.
type Opener func(ctx context.Context, cfg *config.Config) (Store, error)

var (
	backendsMu sync.RWMutex
	backends   = map[string]Opener{}
)

// RegisterBackend makes a backend available under name. Backend packages
// call it from init; internal/app imports each for its side effect. It
// panics on a duplicate name.
func RegisterBackend(name string, open Opener) {
	backendsMu.Lock()
	defer backendsMu.Unlock()
	if _, dup := backends[name]; dup {
		panic("state: backend " + name + " registered twice")
	}
	backends[name] = open
}

// Backends lists the registered backend names.
func Backends() []string {
	backendsMu.RLock()
	defer backendsMu.RUnlock()
	out := make([]string, 0, len(backends))
	for k := range backends {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Open opens the backend named by state.backend.
func Open(ctx context.Context, cfg *config.Config) (Store, error) {
	name := BackendSetting.Get(cfg)
	backendsMu.RLock()
	open, ok := backends[name]
	backendsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("state: backend %q is not built into this binary (have %v)", name, Backends())
	}
	return open(ctx, cfg)
}

// BackendSetting selects the state backend.
//
// The spec's local default is sqlite; until that backend lands the default
// is memory so the binary runs.
var BackendSetting = config.Register(config.Spec[string]{
	Key:             "state.backend",
	Default:         "memory",
	Enum:            []string{"memory", "sqlite", "postgres"},
	Description:     "State backend for approvals, grants, sessions and audit metadata. memory writes nothing to disk.",
	Flag:            true,
	RestartRequired: true,
})
