// SPDX-License-Identifier: AGPL-3.0-only

package pgevents_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/events"
	"github.com/heliopsy/scrim/internal/events/pgevents"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/state/postgres"
	"github.com/heliopsy/scrim/internal/testing/pgtest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	pgtest.Stop()
	os.Exit(code)
}

func open(t *testing.T, dsn string) *postgres.Store {
	t.Helper()
	s, err := postgres.Open(t.Context(), secret.FromString(dsn), postgres.Options{MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return s
}

// gated holds Listen while closed, so a test decides when the listener
// reconnects.
type gated struct {
	l    pgevents.Listener
	mu   sync.Mutex
	open chan struct{}
}

func (g *gated) Listen(ctx context.Context) (*pgx.Conn, error) {
	g.mu.Lock()
	ch := g.open
	g.mu.Unlock()
	select {
	case <-ch:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return g.l.Listen(ctx)
}

func (g *gated) set(open bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if open {
		select {
		case <-g.open:
		default:
			close(g.open)
		}
		return
	}
	g.open = make(chan struct{})
}

// noHook hides the commit hook, so only notifications and reconnects wake
// the bus.
type noHook struct{ state.Store }

type recorder struct {
	mu  sync.Mutex
	evs []state.Event
}

func (r *recorder) add(e state.Event) { r.mu.Lock(); r.evs = append(r.evs, e); r.mu.Unlock() }
func (r *recorder) n() int            { r.mu.Lock(); defer r.mu.Unlock(); return len(r.evs) }
func (r *recorder) get() []state.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]state.Event(nil), r.evs...)
}

func waitUntil(t *testing.T, what string, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting until %s", d, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func emit(t *testing.T, s state.Store, kind string) {
	t.Helper()
	err := state.Apply(t.Context(), s, func(state.Tx) (state.Change, error) {
		return state.Change{Audit: audit.Entry{Time: time.Now(), Action: "test.change", Actor: "test"},
			Events: []state.Event{{Kind: kind, Subject: kind, Time: time.Now()}}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestNotifyAndCatchUp: replica B's bus, polling only once a minute, gets a
// commit made through replica A's pool by NOTIFY; survives idle checks
// without reconnecting; and after its listener's backend is terminated,
// gets the events committed while it was down from the outbox once it
// reconnects.
func TestNotifyAndCatchUp(t *testing.T) {
	dsn := pgtest.FreshDSN(t)
	a, b := open(t, dsn), open(t, dsn)
	emit(t, a, "history")

	g := &gated{l: b, open: make(chan struct{})}
	g.set(true)
	n := pgevents.New(g, nil)
	n.Min, n.Idle = 50*time.Millisecond, 200*time.Millisecond
	bus, err := events.New(t.Context(), events.Options{State: noHook{b}, Notifier: n, Backend: events.Postgres, PollInterval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var r recorder
	bus.Subscribe("", r.add)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { bus.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitUntil(t, "the listener connects", 10*time.Second, bus.Listening)

	start := time.Now()
	emit(t, a, "approval.decided")
	waitUntil(t, "the notified event", 2*time.Second, func() bool { return r.n() == 1 })
	t.Logf("cross-replica delivery by NOTIFY took %s", time.Since(start))

	// Several idle checks pass without a reconnect.
	time.Sleep(700 * time.Millisecond)
	if c := n.Connects(); c != 1 {
		t.Fatalf("listener connected %d times while idle", c)
	}

	// Kill the listener's backend and hold the reconnect.
	g.set(false)
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	var killed int
	if err := admin.QueryRowContext(t.Context(), `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity
		WHERE application_name = $1 AND datname = current_database()`, postgres.ListenerApplicationName).Scan(&killed); err != nil || killed != 1 {
		t.Fatalf("terminated %d listener backends: %v", killed, err)
	}
	waitUntil(t, "the listener notices", 5*time.Second, func() bool { return !bus.Listening() })
	emit(t, a, "grant.changed")
	emit(t, a, "breakglass.changed")
	time.Sleep(300 * time.Millisecond)
	if got := r.n(); got != 1 {
		t.Fatalf("delivered %d events while the listener was down and polling is a minute", got)
	}
	g.set(true)
	waitUntil(t, "the events missed while down", 5*time.Second, func() bool { return r.n() == 3 })
	evs := r.get()
	if evs[0].Kind != "approval.decided" || evs[1].Kind != "grant.changed" || evs[2].Kind != "breakglass.changed" {
		t.Fatalf("delivered %+v", evs)
	}
	if c := n.Connects(); c != 2 {
		t.Fatalf("listener connected %d times, want 2", c)
	}
	// And notifications work on the new connection.
	emit(t, a, "session.revoked")
	waitUntil(t, "a notified event after the reconnect", 2*time.Second, func() bool { return r.n() == 4 })
}

func TestNeedsPostgresState(t *testing.T) {
	cfg, err := config.Load(config.Default, config.EnvLayer([]string{"SCRIM_EVENTS_BACKEND=postgres"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := events.NotifierFor(cfg, memstate.New(), nil); err == nil || !strings.Contains(err.Error(), "state.backend postgres") {
		t.Fatalf("postgres events over memory state: %v", err)
	}
}
