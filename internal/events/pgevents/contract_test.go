// SPDX-License-Identifier: AGPL-3.0-only

package pgevents_test

import (
	"context"
	"database/sql"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/heliopsy/scrim/internal/events/eventstest"
	"github.com/heliopsy/scrim/internal/events/pgevents"
	"github.com/heliopsy/scrim/internal/testing/pgtest"
)

// pidListener records the backend PID of the connection it opened, so a
// test terminates one replica's listener and no other.
type pidListener struct {
	*gated
	mu  sync.Mutex
	pid uint32
}

func (p *pidListener) Listen(ctx context.Context) (*pgx.Conn, error) {
	c, err := p.gated.Listen(ctx)
	if err == nil {
		p.mu.Lock()
		p.pid = c.PgConn().PID()
		p.mu.Unlock()
	}
	return c, err
}

// TestContractPostgres runs the events contract against PostgreSQL
// LISTEN/NOTIFY, each replica with its own pool on one database.
func TestContractPostgres(t *testing.T) {
	eventstest.Run(t, eventstest.Harness{
		Backend: "postgres",
		Replicas: func(t *testing.T, n int) []eventstest.Replica {
			dsn := pgtest.FreshDSN(t)
			admin, err := sql.Open("pgx", dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = admin.Close() })
			out := make([]eventstest.Replica, n)
			for i := range out {
				s := open(t, dsn)
				g := &gated{l: s, open: make(chan struct{})}
				g.set(true)
				pl := &pidListener{gated: g}
				nt := pgevents.New(pl, nil)
				nt.Min = 50e6 // 50ms
				out[i] = eventstest.Replica{State: s, Notifier: nt, Interrupt: func(t *testing.T) func() {
					g.set(false)
					pl.mu.Lock()
					pid := pl.pid
					pl.mu.Unlock()
					if _, err := admin.ExecContext(t.Context(), `SELECT pg_terminate_backend($1)`, pid); err != nil {
						t.Fatal(err)
					}
					return func() { g.set(true) }
				}}
			}
			return out
		},
	})
}
