// SPDX-License-Identifier: AGPL-3.0-only

// Package sessionstate keeps `scrim run` sessions in the state backend, so
// they survive a control plane restart with the sqlite and postgres backends
// and are shared by replicas. With the memory backend a restart still drops
// every session.
//
// Only the hash of a token's secret part is stored, never the token. Every
// mutation goes through [state.Apply] with an audit entry and an event:
// session.created and session.revoked. The entries carry metadata only
// (session ID, agent, user, name, reason), never the hash.
package sessionstate

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
)

// Audit actions and event kinds.
const (
	ActionCreated = "session.created"
	ActionRevoked = "session.revoked"
)

// Store is an identity.SessionStore over a state.Store.
type Store struct{ st state.Store }

var _ identity.SessionStore = (*Store)(nil)

// New returns a session store over st.
func New(st state.Store) *Store { return &Store{st: st} }

// errUnchanged rolls back an Apply that found nothing to change, since Apply
// insists on an audit entry for every commit.
var errUnchanged = errors.New("sessionstate: nothing to change")

// CreateSession implements identity.SessionStore.
func (s *Store) CreateSession(ctx context.Context, sess identity.Session) error {
	row := toRow(sess)
	err := state.Apply(ctx, s.st, func(tx state.Tx) (state.Change, error) {
		if err := tx.CreateSession(ctx, &row); err != nil {
			return state.Change{}, err
		}
		e := entry(ActionCreated, sess, sess.CreatedAt)
		e.Actor = sess.Agent
		return state.Change{Audit: e, Events: []state.Event{{Kind: ActionCreated, Subject: sess.ID, Time: sess.CreatedAt}}}, nil
	})
	if errors.Is(err, state.ErrConflict) {
		return fmt.Errorf("identity: session ID collision: %w", err)
	}
	return err
}

// GetSession implements identity.SessionStore.
func (s *Store) GetSession(ctx context.Context, id string) (identity.Session, error) {
	var out identity.Session
	err := s.st.View(ctx, func(tx state.Tx) error {
		row, err := tx.GetSession(ctx, id)
		if err != nil {
			return err
		}
		out, err = fromRow(*row)
		return err
	})
	if errors.Is(err, state.ErrNotFound) {
		return identity.Session{}, identity.ErrSessionNotFound
	}
	return out, err
}

// RevokeSession implements identity.SessionStore. Revoking a revoked
// session keeps the first revocation, records nothing and is not an error.
func (s *Store) RevokeSession(ctx context.Context, id string, at time.Time, reason string) error {
	err := state.Apply(ctx, s.st, func(tx state.Tx) (state.Change, error) {
		row, err := tx.GetSession(ctx, id)
		if err != nil {
			return state.Change{}, err
		}
		if err := tx.EndSession(ctx, id, at, reason); err != nil {
			if errors.Is(err, state.ErrConflict) {
				return state.Change{}, errUnchanged
			}
			return state.Change{}, err
		}
		return revoked(*row, at, reason), nil
	})
	switch {
	case errors.Is(err, errUnchanged):
		return nil
	case errors.Is(err, state.ErrNotFound):
		return identity.ErrSessionNotFound
	}
	return err
}

// RevokeAgentSessions implements identity.SessionStore. Each revoked
// session gets its own audit entry and event, in one transaction.
func (s *Store) RevokeAgentSessions(ctx context.Context, agent string, at time.Time, reason string) (int, error) {
	n := 0
	err := state.Apply(ctx, s.st, func(tx state.Tx) (state.Change, error) {
		ids, err := tx.EndAgentSessions(ctx, agent, at, reason)
		if err != nil {
			return state.Change{}, err
		}
		if len(ids) == 0 {
			return state.Change{}, errUnchanged
		}
		var c state.Change
		for i, id := range ids {
			row, err := tx.GetSession(ctx, id)
			if err != nil {
				return state.Change{}, err
			}
			rc := revoked(*row, at, reason)
			c.Events = append(c.Events, rc.Events...)
			if i == len(ids)-1 {
				c.Audit = rc.Audit
				break
			}
			if err := tx.AppendAudit(ctx, &rc.Audit); err != nil {
				return state.Change{}, err
			}
		}
		n = len(ids)
		return c, nil
	})
	if errors.Is(err, errUnchanged) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ListSessions implements identity.SessionStore.
func (s *Store) ListSessions(ctx context.Context) ([]identity.Session, error) {
	var out []identity.Session
	err := s.st.View(ctx, func(tx state.Tx) error {
		rows, err := tx.ListSessions(ctx, state.SessionFilter{})
		if err != nil {
			return err
		}
		out = make([]identity.Session, 0, len(rows))
		for _, r := range rows {
			x, err := fromRow(r)
			if err != nil {
				return err
			}
			out = append(out, x)
		}
		return nil
	})
	return out, err
}

func revoked(row state.Session, at time.Time, reason string) state.Change {
	sess := identity.Session{ID: row.ID, Agent: row.Agent.ID, Name: row.Name, UID: row.UID}
	e := entry(ActionRevoked, sess, at)
	e.Actor = "scrim"
	e.Reason = reason
	e.Attrs["reason"] = reason
	return state.Change{Audit: e, Events: []state.Event{{Kind: ActionRevoked, Subject: row.ID, Time: at}}}
}

// entry is the audit entry for a session: metadata only, never the hash.
func entry(action string, s identity.Session, at time.Time) audit.Entry {
	attrs := map[string]string{"uid": strconv.FormatUint(uint64(s.UID), 10)}
	if s.Name != "" {
		attrs["name"] = s.Name
	}
	return audit.Entry{
		Time: at, Action: action, Agent: agentOf(s), Subject: s.ID, Target: "session",
		Outcome: audit.OutcomeOK, Attrs: attrs,
	}
}

func agentOf(s identity.Session) policy.Agent {
	return policy.Agent{ID: s.Agent, Kind: policy.IdentitySession, Session: s.ID}
}

func toRow(s identity.Session) state.Session {
	var scopes []string
	for _, sc := range s.Scopes {
		scopes = append(scopes, string(sc))
	}
	return state.Session{
		ID: s.ID, Agent: agentOf(s), Name: s.Name, TokenHash: hex.EncodeToString(s.Hash),
		UID: s.UID, RootPID: s.Root.PID, RootPPID: s.Root.PPID, RootStart: s.Root.Start, Scopes: scopes,
		CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt, EndedAt: s.RevokedAt, EndReason: s.RevokeReason,
		Labels: maps.Clone(s.Labels),
	}
}

func fromRow(r state.Session) (identity.Session, error) {
	hash, err := hex.DecodeString(r.TokenHash)
	if err != nil {
		// The error names the session, not the stored hash.
		return identity.Session{}, fmt.Errorf("sessionstate: session %s has a malformed token hash", r.ID)
	}
	var scopes []identity.Scope
	for _, sc := range r.Scopes {
		scopes = append(scopes, identity.Scope(sc))
	}
	return identity.Session{
		ID: r.ID, Agent: r.Agent.ID, Name: r.Name, Hash: hash, UID: r.UID,
		Root: identity.Proc{PID: r.RootPID, PPID: r.RootPPID, Start: r.RootStart}, Scopes: scopes, Labels: r.Labels,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, RevokedAt: r.EndedAt, RevokeReason: r.EndReason,
	}, nil
}
