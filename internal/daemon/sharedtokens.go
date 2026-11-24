// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/placeholder"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/tokenseal"
)

// eventRedactionToken announces a token written to the shared state; its
// subject is the row ID.
const eventRedactionToken = "redaction.token"

// Retry bounds of a failed write or read.
const (
	shareRetryMin = time.Second
	shareRetryMax = 30 * time.Second
)

// sharedTokens distributes scrim's own tokens between replicas through the
// state backend (specs/state-and-scaling "Every replica redacts scrim's own
// tokens", shared-session-redaction design S1 to S6). Each token one of the
// sets gets locally is sealed (package tokenseal) and written with an outbox
// event; each event delivered, and every live row at start-up, is read,
// opened and added to its set. The state and the outbox never see a token in
// plaintext, and the events backend carries only the outbox's wake-ups.
type sharedTokens struct {
	st   state.Store
	log  *slog.Logger
	sets map[string]*sessionTokens // by kind
	now  func() time.Time
	kick chan struct{}

	mu     sync.Mutex
	sealer *tokenseal.Sealer
	// pending are sealed rows not written yet, by ID.
	pending map[string]state.RedactionToken
	// inbox are row IDs delivered by the bus and not read yet.
	inbox []string
	// failing is set while writes or reads fail, so the warning is logged
	// once per outage.
	failing bool
}

func newSharedTokens(st state.Store, ring *placeholder.Ring, log *slog.Logger, sets ...*sessionTokens) (*sharedTokens, error) {
	s := &sharedTokens{st: st, log: log, sets: map[string]*sessionTokens{}, now: time.Now,
		kick: make(chan struct{}, 1), pending: map[string]state.RedactionToken{}}
	if err := s.setKeys(ring); err != nil {
		return nil, err
	}
	for _, set := range sets {
		s.sets[set.kind] = set
		set.share = s.offer
	}
	return s, nil
}

// setKeys derives the sealing keys from ring, which stays the caller's.
func (s *sharedTokens) setKeys(ring *placeholder.Ring) error {
	sealer, err := tokenseal.New(ring)
	if err != nil {
		return err
	}
	s.mu.Lock()
	old := s.sealer
	s.sealer = sealer
	s.mu.Unlock()
	old.Wipe()
	return nil
}

func (s *sharedTokens) wake() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// offer seals a token one of the sets got locally and queues its row. It
// owns v. id is the session ID of a session token; any other token's row ID
// is a keyed hash of it.
func (s *sharedTokens) offer(kind, id string, v secret.Value, expires time.Time) {
	defer v.Wipe()
	s.mu.Lock()
	defer s.mu.Unlock()
	err := v.Expose(func(tok []byte) error {
		if kind != state.TokenSession {
			id = s.sealer.ID(tok)
		}
		ver, sealed, err := s.sealer.Seal(kind, id, tok)
		if err != nil {
			return err
		}
		s.pending[id] = state.RedactionToken{ID: id, Kind: kind, KeyVersion: ver, Sealed: sealed,
			CreatedAt: s.now().UTC(), ExpiresAt: expires}
		return nil
	})
	if err != nil {
		// Never happens with a valid key; the token is still redacted here.
		s.log.Error("could not seal a token for the other replicas", "kind", kind, "err", err)
		return
	}
	s.wake()
}

// delivered is the bus subscriber of eventRedactionToken. It never blocks.
func (s *sharedTokens) delivered(e state.Event) {
	s.mu.Lock()
	s.inbox = append(s.inbox, e.Subject)
	s.mu.Unlock()
	s.wake()
}

// run writes queued rows and reads delivered ones until ctx ends, retrying
// failures with backoff.
func (s *sharedTokens) run(ctx context.Context) {
	retry := shareRetryMin
	t := time.NewTimer(time.Hour)
	t.Stop()
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.kick:
		case <-t.C:
		}
		err := errors.Join(s.flush(ctx), s.readInbox(ctx))
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		was := s.failing
		s.failing = err != nil
		s.mu.Unlock()
		switch {
		case err != nil:
			if !was {
				s.log.Warn("sharing tokens with the other replicas failed; retrying (each replica still redacts its own)", "err", err)
			}
			t.Reset(retry)
			retry = min(retry*2, shareRetryMax)
		case was:
			s.log.Info("sharing tokens with the other replicas works again")
			retry = shareRetryMin
		default:
			retry = shareRetryMin
		}
	}
}

// flush writes every queued row with its event in one transaction. Rows
// whose token expired are dropped.
func (s *sharedTokens) flush(ctx context.Context) error {
	s.mu.Lock()
	now := s.now()
	rows := make([]state.RedactionToken, 0, len(s.pending))
	for id, r := range s.pending {
		if !now.Before(r.ExpiresAt) {
			delete(s.pending, id)
			continue
		}
		rows = append(rows, r)
	}
	s.mu.Unlock()
	if len(rows) == 0 {
		return nil
	}
	// The rows replicate tokens whose creation is audited where it happens
	// (session.created) or that scrim itself verified or signed; they carry
	// no decision, so they go through Update without an audit entry.
	err := s.st.Update(ctx, func(tx state.Tx) error {
		for i := range rows {
			if err := tx.PutRedactionToken(ctx, &rows[i]); err != nil {
				return err
			}
			if err := tx.Emit(ctx, &state.Event{Kind: eventRedactionToken, Subject: rows[i].ID, Time: now.UTC()}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("writing %d shared tokens: %w", len(rows), err)
	}
	s.mu.Lock()
	for _, r := range rows {
		// A newer offer of the same row (a moved expiry) stays queued.
		if p, ok := s.pending[r.ID]; ok && p.ExpiresAt.Equal(r.ExpiresAt) && p.KeyVersion == r.KeyVersion {
			delete(s.pending, r.ID)
		}
	}
	s.mu.Unlock()
	return nil
}

// sharedRow is a row read from the state with what its session says.
type sharedRow struct {
	state.RedactionToken
	agent string
	ended bool
}

// read reads rows and, for session tokens, their sessions, in one read
// transaction. A row or session that is gone is left out.
func (s *sharedTokens) read(ctx context.Context, list func(tx state.Tx) ([]state.RedactionToken, error)) ([]sharedRow, error) {
	var out []sharedRow
	err := s.st.View(ctx, func(tx state.Tx) error {
		rows, err := list(tx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			sr := sharedRow{RedactionToken: r}
			if r.Kind == state.TokenSession {
				sess, err := tx.GetSession(ctx, r.ID)
				if errors.Is(err, state.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				sr.agent, sr.ended = sess.Agent.ID, !sess.EndedAt.IsZero()
			}
			out = append(out, sr)
		}
		return nil
	})
	return out, err
}

// add opens rows and adds them to their sets. A row that does not open is
// logged by ID and key version and skipped.
func (s *sharedTokens) add(rows []sharedRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range rows {
		set := s.sets[r.Kind]
		if set == nil {
			continue
		}
		v, err := s.sealer.Open(r.Kind, r.ID, r.KeyVersion, r.Sealed)
		if err != nil {
			s.log.Warn("a token shared by another replica cannot be opened; it is not redacted here",
				"row", r.ID, "kind", r.Kind, "key_version", r.KeyVersion, "err", err)
			continue
		}
		sid := ""
		if r.Kind == state.TokenSession {
			sid = r.ID
		}
		set.addShared(sid, r.agent, r.ended, v, r.ExpiresAt)
	}
}

// readInbox reads the rows the bus announced.
func (s *sharedTokens) readInbox(ctx context.Context) error {
	s.mu.Lock()
	ids := slices.Compact(slices.Sorted(slices.Values(s.inbox)))
	s.inbox = nil
	s.mu.Unlock()
	if len(ids) == 0 {
		return nil
	}
	rows, err := s.read(ctx, func(tx state.Tx) ([]state.RedactionToken, error) {
		var out []state.RedactionToken
		for _, id := range ids {
			r, err := tx.GetRedactionToken(ctx, id)
			if errors.Is(err, state.ErrNotFound) {
				continue // expired and deleted since
			}
			if err != nil {
				return nil, err
			}
			out = append(out, *r)
		}
		return out, nil
	})
	if err != nil {
		s.mu.Lock()
		s.inbox = append(s.inbox, ids...)
		s.mu.Unlock()
		return fmt.Errorf("reading %d shared tokens: %w", len(ids), err)
	}
	s.add(rows)
	return nil
}

// load adds every live shared row. Start runs it before the data plane's
// first snapshot.
func (s *sharedTokens) load(ctx context.Context) error {
	now := s.now()
	rows, err := s.read(ctx, func(tx state.Tx) ([]state.RedactionToken, error) { return tx.ListRedactionTokens(ctx, now) })
	if err != nil {
		return fmt.Errorf("loading the tokens other replicas shared: %w", err)
	}
	s.add(rows)
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Kind]++
	}
	if len(rows) > 0 {
		s.log.Info("loaded the tokens other replicas shared", "rows", len(rows), "kinds", slices.Sorted(maps.Keys(counts)))
	}
	return nil
}

// deleteExpired deletes the rows of expired tokens. Every replica runs it;
// it is idempotent.
func (s *sharedTokens) deleteExpired(ctx context.Context) {
	err := s.st.Update(ctx, func(tx state.Tx) error {
		_, err := tx.DeleteRedactionTokens(ctx, s.now())
		return err
	})
	if err != nil && ctx.Err() == nil {
		s.log.Warn("deleting expired shared tokens failed", "err", err)
	}
}

func (s *sharedTokens) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealer.Wipe()
	clear(s.pending)
}
