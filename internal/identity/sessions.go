// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"
)

// ErrSessionNotFound is returned by a SessionStore for an unknown ID.
var ErrSessionNotFound = errors.New("identity: session not found")

// Session is one minted session as it is stored. It holds the hash of the
// token's secret part, never the token.
type Session struct {
	ID        string            `json:"id"`
	Agent     string            `json:"agent"`
	Name      string            `json:"name,omitempty"`
	Hash      []byte            `json:"-"`
	UID       uint32            `json:"uid"`
	Root      Proc              `json:"root"`
	Scopes    []Scope           `json:"scopes"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	RevokedAt time.Time         `json:"revoked_at,omitzero"`
	// RevokeReason says why: "ended", "operator", "root exited", "agent".
	RevokeReason string `json:"revoke_reason,omitempty"`
}

// Revoked reports whether the session was revoked.
func (s Session) Revoked() bool { return !s.RevokedAt.IsZero() }

// Active reports whether the session can still be used at now.
func (s Session) Active(now time.Time) bool { return !s.Revoked() && now.Before(s.ExpiresAt) }

func (s Session) clone() Session {
	s.Hash = slices.Clone(s.Hash)
	s.Scopes = slices.Clone(s.Scopes)
	s.Labels = maps.Clone(s.Labels)
	return s
}

// SessionStore persists sessions. The state backends implement it; Memory is
// the in-process implementation for tests and throwaway runs.
type SessionStore interface {
	CreateSession(ctx context.Context, s Session) error
	GetSession(ctx context.Context, id string) (Session, error)
	// RevokeSession marks one session revoked. Revoking a revoked session
	// keeps the first revocation and is not an error.
	RevokeSession(ctx context.Context, id string, at time.Time, reason string) error
	// RevokeAgentSessions revokes every active session of an agent and
	// reports how many it revoked.
	RevokeAgentSessions(ctx context.Context, agent string, at time.Time, reason string) (int, error)
	// ListSessions returns every session, oldest first.
	ListSessions(ctx context.Context) ([]Session, error)
}

// MemorySessions is a SessionStore in process memory. A restart drops every
// session, which ends every `scrim run` identity: the safe direction.
type MemorySessions struct {
	mu sync.Mutex
	m  map[string]Session
}

// NewMemorySessions returns an empty store.
func NewMemorySessions() *MemorySessions { return &MemorySessions{m: map[string]Session{}} }

// CreateSession stores a new session.
func (m *MemorySessions) CreateSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.m[s.ID]; dup {
		return errors.New("identity: session ID collision")
	}
	m.m[s.ID] = s.clone()
	return nil
}

// GetSession returns one session.
func (m *MemorySessions) GetSession(_ context.Context, id string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.m[id]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	return s.clone(), nil
}

// RevokeSession revokes one session.
func (m *MemorySessions) RevokeSession(_ context.Context, id string, at time.Time, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.m[id]
	if !ok {
		return ErrSessionNotFound
	}
	if !s.Revoked() {
		s.RevokedAt, s.RevokeReason = at, reason
		m.m[id] = s
	}
	return nil
}

// RevokeAgentSessions revokes every unrevoked session of agent.
func (m *MemorySessions) RevokeAgentSessions(_ context.Context, agent string, at time.Time, reason string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, s := range m.m {
		if s.Agent == agent && !s.Revoked() {
			s.RevokedAt, s.RevokeReason = at, reason
			m.m[id] = s
			n++
		}
	}
	return n, nil
}

// ListSessions returns every session, oldest first.
func (m *MemorySessions) ListSessions(context.Context) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Session, 0, len(m.m))
	for _, s := range m.m {
		out = append(out, s.clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
