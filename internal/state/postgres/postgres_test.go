// SPDX-License-Identifier: AGPL-3.0-only

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/postgres"
	"github.com/heliopsy/scrim/internal/state/statetest"
)

func open(t *testing.T, o postgres.Options) *postgres.Store {
	t.Helper()
	s, err := postgres.Open(t.Context(), secret.FromString(freshDSN(t)), o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestContract(t *testing.T) {
	statetest.Run(t, func(t *testing.T) state.Store { return open(t, postgres.Options{}) })
}

func applyGrant(ctx context.Context, s state.Store, id string, maxUses int) error {
	return state.Apply(ctx, s, func(tx state.Tx) (state.Change, error) {
		err := tx.CreateGrant(ctx, &state.Grant{ID: id, MaxUses: maxUses, CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)})
		return state.Change{
			Audit:  audit.Entry{Action: "grant.created", Subject: id, Time: t0},
			Events: []state.Event{{Kind: "grant.created", Subject: id, Time: t0}},
		}, err
	})
}

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func assertNothing(t *testing.T, s state.Store, id string) {
	t.Helper()
	err := s.View(t.Context(), func(tx state.Tx) error {
		if _, err := tx.GetGrant(t.Context(), id); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("grant survived the fault: %v", err)
		}
		if es, _ := tx.QueryAudit(t.Context(), state.AuditQuery{}); len(es) != 0 {
			t.Errorf("audit survived the fault: %+v", es)
		}
		if ev, _ := tx.EventsAfter(t.Context(), 0, 0); len(ev) != 0 {
			t.Errorf("events survived the fault: %+v", ev)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAuditFaultInjection kills the transaction's server connection between
// the grant insert and its audit entry: a real failure, not a simulated
// error. Neither row may survive.
func TestAuditFaultInjection(t *testing.T) {
	dsn := freshDSN(t)
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	var armed atomic.Bool
	s, err := postgres.Open(t.Context(), secret.FromString(dsn), postgres.Options{Faults: func(op string) error {
		if armed.Load() && op == "AppendAudit" {
			_, err := admin.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity
				WHERE datname = current_database() AND pid <> pg_backend_pid() AND application_name = 'scrim'`)
			return err
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	if err := applyGrant(t.Context(), s, "g1", 0); err == nil {
		t.Fatal("Apply succeeded although its connection was killed before the audit write")
	}
	armed.Store(false)
	assertNothing(t, s, "g1")
	if err := applyGrant(t.Context(), s, "g1", 0); err != nil {
		t.Fatalf("Apply after the fault: %v", err)
	}
}

func TestInjectedFaultAtCommit(t *testing.T) {
	boom := errors.New("injected")
	var armed atomic.Bool
	s := open(t, postgres.Options{Faults: func(op string) error {
		if armed.Load() && op == "commit" {
			return boom
		}
		return nil
	}})
	defer func() { _ = s.Close() }()
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	if err := applyGrant(t.Context(), s, "g1", 0); !errors.Is(err, boom) {
		t.Fatalf("Apply = %v", err)
	}
	assertNothing(t, s, "g1")
}

// replicas opens n stores on one database, as n scrim replicas would, and
// migrates them concurrently.
func replicas(t *testing.T, n int) []*postgres.Store {
	t.Helper()
	dsn := freshDSN(t)
	out := make([]*postgres.Store, n)
	for i := range out {
		s, err := postgres.Open(t.Context(), secret.FromString(dsn), postgres.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		out[i] = s
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i, s := range out {
		wg.Go(func() { errs[i] = s.Migrate(t.Context()) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d Migrate: %v", i, err)
		}
	}
	return out
}

func TestReplicasMigrateConcurrently(t *testing.T) {
	rs := replicas(t, 4)
	for _, r := range rs {
		if v, err := r.SchemaVersion(t.Context()); err != nil || v != 1 {
			t.Fatalf("SchemaVersion = %d, %v", v, err)
		}
	}
}

func TestRevokeOnOneReplicaSeenByAnother(t *testing.T) {
	rs := replicas(t, 2)
	a, b := rs[0], rs[1]
	ctx := t.Context()
	if err := applyGrant(ctx, a, "g1", 0); err != nil {
		t.Fatal(err)
	}
	if err := state.Apply(ctx, a, func(tx state.Tx) (state.Change, error) {
		return state.Change{Audit: audit.Entry{Action: "grant.revoked", Subject: "g1", Time: t0}},
			tx.RevokeGrant(ctx, "g1", "operator", t0.Add(time.Minute))
	}); err != nil {
		t.Fatal(err)
	}
	err := b.Update(ctx, func(tx state.Tx) error { _, err := tx.UseGrant(ctx, "g1", t0.Add(2*time.Minute)); return err })
	if !errors.Is(err, state.ErrGrantUnusable) {
		t.Fatalf("replica B used a grant revoked on A: %v", err)
	}
}

// TestLastUseAcrossReplicas races many uses of a one-use grant through two
// replicas; exactly one may win.
func TestLastUseAcrossReplicas(t *testing.T) {
	rs := replicas(t, 2)
	ctx := t.Context()
	if err := applyGrant(ctx, rs[0], "g1", 1); err != nil {
		t.Fatal(err)
	}
	var wins, unusable atomic.Int64
	var wg sync.WaitGroup
	for i := range 20 {
		s := rs[i%2]
		wg.Go(func() {
			err := s.Update(ctx, func(tx state.Tx) error { _, err := tx.UseGrant(ctx, "g1", t0.Add(time.Minute)); return err })
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, state.ErrGrantUnusable):
				unusable.Add(1)
			default:
				t.Errorf("UseGrant: %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 || unusable.Load() != 19 {
		t.Fatalf("wins %d, unusable %d; want 1 and 19", wins.Load(), unusable.Load())
	}
}

// TestOutboxTailNeverSkips writes events from two replicas concurrently, some
// transactions holding their event open while others commit, and tails the
// outbox by ID meanwhile. The tail must end with every event exactly once.
func TestOutboxTailNeverSkips(t *testing.T) {
	rs := replicas(t, 2)
	ctx := t.Context()
	const writers, each = 6, 15
	var wg sync.WaitGroup
	for w := range writers {
		s := rs[w%2]
		wg.Go(func() {
			for i := range each {
				err := s.Update(ctx, func(tx state.Tx) error {
					if err := tx.Emit(ctx, &state.Event{Kind: "k", Subject: fmt.Sprintf("%d-%d", w, i), Time: t0}); err != nil {
						return err
					}
					if i%3 == 0 {
						time.Sleep(2 * time.Millisecond) // hold the ID uncommitted
					}
					return nil
				})
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	seen := map[string]int{}
	var cursor int64
	tail := func() {
		_ = rs[1].View(ctx, func(tx state.Tx) error {
			ev, err := tx.EventsAfter(ctx, cursor, 0)
			if err != nil {
				t.Error(err)
			}
			for _, e := range ev {
				if e.ID <= cursor {
					t.Errorf("event %d out of order after %d", e.ID, cursor)
				}
				cursor = e.ID
				seen[e.Subject]++
			}
			return nil
		})
	}
	for {
		select {
		case <-done:
			tail()
			if len(seen) != writers*each {
				t.Fatalf("tail saw %d distinct events, want %d", len(seen), writers*each)
			}
			for k, n := range seen {
				if n != 1 {
					t.Errorf("event %s seen %d times", k, n)
				}
			}
			return
		default:
			tail()
		}
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	dsn := freshDSN(t)
	s, err := postgres.Open(t.Context(), secret.FromString(dsn), postgres.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	raw, _ := sql.Open("pgx", dsn)
	defer func() { _ = raw.Close() }()
	if _, err := raw.Exec(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (9, 'future', 'x')`); err != nil {
		t.Fatal(err)
	}
	err = s.Migrate(t.Context())
	if !errors.Is(err, state.ErrSchemaTooNew) || !strings.Contains(err.Error(), "version 9") || !strings.Contains(err.Error(), "version 1") {
		t.Fatalf("Migrate on a newer schema = %v", err)
	}
}

func TestLocationHidesPassword(t *testing.T) {
	dsn := freshDSN(t)
	s, err := postgres.Open(t.Context(), secret.FromString(dsn), postgres.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	u, _ := url.Parse(dsn)
	pw, _ := u.User.Password()
	if strings.Contains(s.Location(), pw) || !strings.Contains(s.Location(), u.Host) {
		t.Fatalf("Location = %q", s.Location())
	}
}

func TestOpenErrorsHoldNoPassword(t *testing.T) {
	const pw = "hunter2-not-a-real-password"
	_, err := postgres.Open(t.Context(), secret.FromString("postgres://scrim:"+pw+"@127.0.0.1:1/scrim?sslmode=disable&connect_timeout=1"),
		postgres.Options{ConnectTimeout: 2 * time.Second})
	if err == nil || strings.Contains(err.Error(), pw) {
		t.Fatalf("Open error = %v", err)
	}
	_, err = postgres.Open(t.Context(), secret.FromString("postgres://scrim:"+pw+"@[bad"), postgres.Options{})
	if err == nil || strings.Contains(err.Error(), pw) {
		t.Fatalf("parse error = %v", err)
	}
}

func TestResolveDSN(t *testing.T) {
	t.Setenv("SCRIM_TEST_DSN_REF", "postgres://u:p@h/db")
	v, err := postgres.ResolveDSN("env:SCRIM_TEST_DSN_REF")
	if err != nil || v.Len() == 0 {
		t.Fatalf("env ref: %v", err)
	}
	f := filepath.Join(t.TempDir(), "dsn")
	_ = os.WriteFile(f, []byte("postgres://u:p@h/db\n"), 0o600)
	if v, err := postgres.ResolveDSN(config.SecretRef("file:" + f)); err != nil || v.Len() != len("postgres://u:p@h/db") {
		t.Fatalf("file ref: %v", err)
	}
	for _, bad := range []config.SecretRef{"", "postgres://u:p@h/db", "env:SCRIM_TEST_UNSET_VAR"} {
		_, err := postgres.ResolveDSN(bad)
		if err == nil || strings.Contains(err.Error(), "u:p@h") {
			t.Errorf("ResolveDSN(%q) = %v", bad, err)
		}
	}
}
