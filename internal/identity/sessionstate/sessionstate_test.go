// SPDX-License-Identifier: AGPL-3.0-only

package sessionstate_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/identity/sessionstate"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/state/sqlite"
)

// tree is a fake process table: 100 is `scrim run`, 101 the agent it
// started, 200 an unrelated process of the same user.
type tree map[int32]identity.Proc

func (t tree) Lookup(pid int32) (identity.Proc, error) {
	p, ok := t[pid]
	if !ok {
		return identity.Proc{}, fmt.Errorf("no process %d", pid)
	}
	return p, nil
}

var procs = tree{
	1:   {PID: 1, Start: 1},
	100: {PID: 100, PPID: 1, Start: 1<<62 + 5},
	101: {PID: 101, PPID: 100, Start: 1<<62 + 6},
	200: {PID: 200, PPID: 1, Start: 9},
}

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC)

func minter() identity.Identity {
	return identity.Identity{Agent: "claude", Source: identity.SourcePeer, Peer: identity.Peer{UID: 1000, PID: 100},
		Scopes: identity.AllScopes, Labels: map[string]string{"team": "infra"}}
}

func manager(st state.Store) *identity.Manager {
	return identity.NewManager(sessionstate.New(st), identity.ManagerOptions{Procs: procs, Now: func() time.Time { return t0 }})
}

func openSQLite(t *testing.T, path string) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(t.Context(), path, sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		_ = s.Close()
		t.Fatal(err)
	}
	return s
}

type backend struct {
	name string
	open func(t *testing.T) state.Store
}

func backends() []backend {
	return []backend{
		{"memory", func(*testing.T) state.Store { return memstate.New() }},
		{"sqlite", func(t *testing.T) state.Store { return openSQLite(t, filepath.Join(t.TempDir(), "state.db")) }},
	}
}

func each(t *testing.T, fn func(t *testing.T, st state.Store)) {
	for _, b := range backends() {
		t.Run(b.name, func(t *testing.T) {
			st := b.open(t)
			t.Cleanup(func() { _ = st.Close() })
			fn(t, st)
		})
	}
}

// A session read back equals the one stored, field for field, as with the
// in-memory store.
func TestRoundTrip(t *testing.T) {
	each(t, func(t *testing.T, st state.Store) {
		ctx := t.Context()
		s := sessionstate.New(st)
		want := identity.Session{
			ID: "abcdefghijklmnop", Agent: "claude", Name: "claude code", Hash: bytes.Repeat([]byte{0xab, 0x01}, 16),
			UID: 1000, Root: procs[100], Scopes: []identity.Scope{identity.ScopeSecretsList, identity.ScopeSecretsWrite},
			Labels: map[string]string{"team": "infra"}, CreatedAt: t0, ExpiresAt: t0.Add(time.Hour),
		}
		if err := s.CreateSession(ctx, want); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateSession(ctx, want); err == nil {
			t.Fatal("duplicate session ID accepted")
		}
		got, err := s.GetSession(ctx, want.ID)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("GetSession =\n%+v, %v\nwant\n%+v", got, err, want)
		}
		if _, err := s.GetSession(ctx, "missing"); !errors.Is(err, identity.ErrSessionNotFound) {
			t.Fatalf("missing session: %v", err)
		}
		if err := s.RevokeSession(ctx, "missing", t0, identity.RevokeOperator); !errors.Is(err, identity.ErrSessionNotFound) {
			t.Fatalf("revoking a missing session: %v", err)
		}
		if err := s.RevokeSession(ctx, want.ID, t0.Add(time.Minute), identity.RevokeEnded); err != nil {
			t.Fatal(err)
		}
		// A second revocation keeps the first.
		if err := s.RevokeSession(ctx, want.ID, t0.Add(2*time.Minute), identity.RevokeOperator); err != nil {
			t.Fatal(err)
		}
		want.RevokedAt, want.RevokeReason = t0.Add(time.Minute), identity.RevokeEnded
		if got, _ := s.GetSession(ctx, want.ID); !reflect.DeepEqual(got, want) {
			t.Fatalf("after revoke =\n%+v\nwant\n%+v", got, want)
		}
		list, err := s.ListSessions(ctx)
		if err != nil || len(list) != 1 || !reflect.DeepEqual(list[0], want) {
			t.Fatalf("ListSessions = %+v, %v", list, err)
		}
		if n := countAudit(t, st, sessionstate.ActionRevoked); n != 1 {
			t.Fatalf("%d revocation entries, want 1", n)
		}
	})
}

func TestRevokeAgentSessions(t *testing.T) {
	each(t, func(t *testing.T, st state.Store) {
		ctx := t.Context()
		s := sessionstate.New(st)
		for i, agent := range []string{"claude", "codex", "claude", "claude"} {
			err := s.CreateSession(ctx, identity.Session{ID: fmt.Sprintf("s%d", i), Agent: agent, Hash: []byte{byte(i)},
				Root: procs[100], CreatedAt: t0.Add(time.Duration(i) * time.Second), ExpiresAt: t0.Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := s.RevokeSession(ctx, "s3", t0, identity.RevokeEnded); err != nil {
			t.Fatal(err)
		}
		n, err := s.RevokeAgentSessions(ctx, "claude", t0.Add(time.Minute), identity.RevokeOperator)
		if err != nil || n != 2 {
			t.Fatalf("RevokeAgentSessions = %d, %v, want 2", n, err)
		}
		if n, err := s.RevokeAgentSessions(ctx, "claude", t0.Add(time.Minute), identity.RevokeOperator); err != nil || n != 0 {
			t.Fatalf("second RevokeAgentSessions = %d, %v, want 0", n, err)
		}
		if n, err := s.RevokeAgentSessions(ctx, "nobody", t0, identity.RevokeOperator); err != nil || n != 0 {
			t.Fatalf("RevokeAgentSessions of an unknown agent = %d, %v", n, err)
		}
		list, _ := s.ListSessions(ctx)
		want := map[string]string{"s0": identity.RevokeOperator, "s1": "", "s2": identity.RevokeOperator, "s3": identity.RevokeEnded}
		if len(list) != 4 {
			t.Fatalf("ListSessions = %+v", list)
		}
		for i, x := range list {
			if x.ID != fmt.Sprintf("s%d", i) || x.RevokeReason != want[x.ID] {
				t.Errorf("session %d = %s revoked for %q, want %q", i, x.ID, x.RevokeReason, want[x.ID])
			}
		}
		var subjects []string
		_ = st.View(ctx, func(tx state.Tx) error {
			es, _ := tx.QueryAudit(ctx, state.AuditQuery{Action: sessionstate.ActionRevoked})
			for _, e := range es {
				subjects = append(subjects, e.Subject+"/"+e.Reason)
			}
			return nil
		})
		if got := strings.Join(subjects, " "); got != "s3/ended s0/operator s2/operator" {
			t.Errorf("revocation audit = %s", got)
		}
	})
}

// The token, its secret part and its stored hash never appear in an audit
// entry or an event, in any encoding.
func TestAuditHoldsNoHash(t *testing.T) {
	each(t, func(t *testing.T, st state.Store) {
		ctx := t.Context()
		m := manager(st)
		minted, err := m.Mint(ctx, minter(), identity.MintRequest{Name: "agent"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.RevokeAgent(ctx, "claude"); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Mint(ctx, minter(), identity.MintRequest{Name: "second"}); err != nil {
			t.Fatal(err)
		}
		sess, _ := m.Get(ctx, minted.Session.ID)
		var tok []byte
		_ = minted.Token.Expose(func(b []byte) error { tok = bytes.Clone(b); return nil })
		secretPart := tok[len(identity.TokenPrefix)+17:]
		needles := []string{string(tok), string(secretPart), hex.EncodeToString(sess.Hash),
			base64.StdEncoding.EncodeToString(sess.Hash), base64.RawURLEncoding.EncodeToString(sess.Hash), string(sess.Hash)}

		var dump strings.Builder
		_ = st.View(ctx, func(tx state.Tx) error {
			es, err := tx.QueryAudit(ctx, state.AuditQuery{})
			if err != nil {
				t.Fatal(err)
			}
			if len(es) != 3 || es[0].Action != sessionstate.ActionCreated || es[1].Action != sessionstate.ActionRevoked {
				t.Errorf("audit = %+v", es)
			}
			if es[0].Subject != sess.ID || es[0].Agent.ID != "claude" || es[0].Attrs["uid"] != "1000" || es[0].Attrs["name"] != "agent" {
				t.Errorf("created entry = %+v", es[0])
			}
			if es[1].Reason != identity.RevokeOperator || es[1].Attrs["reason"] != identity.RevokeOperator {
				t.Errorf("revoked entry = %+v", es[1])
			}
			ev, _ := tx.EventsAfter(ctx, 0, 0)
			if len(ev) != 3 || ev[0].Kind != sessionstate.ActionCreated || ev[1].Kind != sessionstate.ActionRevoked || ev[1].Subject != sess.ID {
				t.Errorf("events = %+v", ev)
			}
			fmt.Fprintf(&dump, "%+v %+v %#v", es, ev, es)
			return nil
		})
		for _, n := range needles {
			if strings.Contains(dump.String(), n) {
				t.Fatalf("audit or events contain the token or its hash")
			}
		}
	})
}

// A session minted before a restart verifies after it, and a revocation made
// after the restart survives the next one.
func TestSessionsSurviveRestart(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	agentPeer := identity.Peer{UID: 1000, PID: 101}

	st := openSQLite(t, path)
	minted, err := manager(st).Mint(ctx, minter(), identity.MintRequest{Name: "agent", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer minted.Token.Wipe()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	verify := func(m *identity.Manager, peer identity.Peer) (identity.Identity, error) {
		var id identity.Identity
		err := minted.Token.Expose(func(b []byte) error {
			var err error
			id, err = m.Verify(ctx, peer, b)
			return err
		})
		return id, err
	}
	refused := func(err error) identity.RefusalReason {
		var r *identity.RefusedError
		if errors.As(err, &r) {
			return r.Reason
		}
		return ""
	}

	st = openSQLite(t, path)
	m := manager(st)
	id, err := verify(m, agentPeer)
	if err != nil || id.Source != identity.SourceSession || id.SessionID != minted.Session.ID || id.Agent != "claude" ||
		id.SessionName != "agent" || id.Labels["team"] != "infra" || !id.ExpiresAt.Equal(t0.Add(time.Hour)) ||
		!reflect.DeepEqual(id.Scopes, identity.AgentScopes) {
		t.Fatalf("after restart: %+v, %v", id, err)
	}
	if _, err := verify(m, identity.Peer{UID: 1000, PID: 200}); refused(err) != identity.RefusedWrongTree {
		t.Fatalf("outside the tree after restart: %v", err)
	}
	if _, err := verify(m, identity.Peer{UID: 1001, PID: 101}); refused(err) != identity.RefusedWrongUser {
		t.Fatalf("wrong user after restart: %v", err)
	}
	if err := m.Revoke(ctx, minted.Session.ID, identity.RevokeEnded); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st = openSQLite(t, path)
	defer func() { _ = st.Close() }()
	m = manager(st)
	if _, err := verify(m, agentPeer); refused(err) != identity.RefusedRevoked {
		t.Fatalf("revoked session after restart: %v", err)
	}
	got, err := m.Get(ctx, minted.Session.ID)
	if err != nil || got.RevokeReason != identity.RevokeEnded {
		t.Fatalf("revocation not kept: %+v, %v", got, err)
	}
}

func countAudit(t *testing.T, st state.Store, action string) int {
	t.Helper()
	n := 0
	err := st.View(context.Background(), func(tx state.Tx) error {
		es, err := tx.QueryAudit(context.Background(), state.AuditQuery{Action: action})
		n = len(es)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
