// SPDX-License-Identifier: AGPL-3.0-only

// Package pgevents is the postgres events backend: a dedicated LISTEN
// connection on the state database that turns every NOTIFY the PostgreSQL
// state backend sends with an outbox write into a wake-up for the bus
// (package events). It reconnects with backoff; while it is down the bus
// polls the outbox, and after every reconnect the bus reads everything it
// missed, so a notification lost with the connection loses no event.
package pgevents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/events"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/postgres"
)

func init() {
	events.RegisterBackend(events.Postgres, func(_ *config.Config, st state.Store, log *slog.Logger) (events.Notifier, error) {
		l, ok := st.(Listener)
		if !ok {
			return nil, fmt.Errorf("events: events.backend %s needs state.backend postgres, not %s", events.Postgres, st.Backend())
		}
		return New(l, log), nil
	})
}

// Listener opens a connection that listens on the events channel;
// *postgres.Store implements it.
type Listener interface {
	Listen(ctx context.Context) (*pgx.Conn, error)
}

var _ Listener = (*postgres.Store)(nil)

// Backoff bounds between reconnect attempts.
const (
	MinBackoff = 250 * time.Millisecond
	MaxBackoff = 30 * time.Second
)

// Notifier implements [events.Notifier] over LISTEN/NOTIFY.
type Notifier struct {
	l   Listener
	log *slog.Logger
	// Min and Max bound the reconnect backoff; Idle is how long the
	// connection waits for a notification before it checks the server is
	// still there. Tests shorten them.
	Min, Max, Idle time.Duration

	connects    atomic.Int64
	lastConnect atomic.Int64
}

// New returns a notifier over l.
func New(l Listener, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Notifier{l: l, log: log, Min: MinBackoff, Max: MaxBackoff, Idle: 30 * time.Second}
}

// Connects is how many times the listener has connected.
func (n *Notifier) Connects() int64 { return n.connects.Load() }

// LastConnect is when the listener last connected.
func (n *Notifier) LastConnect() time.Time {
	if ns := n.lastConnect.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// Run implements [events.Notifier].
func (n *Notifier) Run(ctx context.Context, wake func(), up func(bool)) {
	backoff := n.Min
	failing := false
	for ctx.Err() == nil {
		conn, err := n.l.Listen(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if !failing {
				failing = true
				n.log.Warn("events: the postgres listener cannot connect; polling the outbox until it does", "err", err)
			}
			sleep(ctx, jitter(backoff))
			backoff = min(backoff*2, n.Max)
			continue
		}
		if failing || n.connects.Load() > 0 {
			n.log.Info("events: the postgres listener is connected again; reading what was missed")
		}
		failing, backoff = false, n.Min
		n.connects.Add(1)
		n.lastConnect.Store(time.Now().UnixNano())
		// LISTEN is in force: whatever commits from now on notifies, and
		// the read up() triggers covers everything before.
		up(true)
		err = n.wait(ctx, conn, wake)
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		_ = conn.Close(cctx)
		cancel()
		up(false)
		if ctx.Err() != nil {
			return
		}
		n.log.Warn("events: the postgres listener lost its connection; polling the outbox until it reconnects", "err", postgres.ScrubError(err))
		sleep(ctx, jitter(backoff))
	}
}

// wait delivers notifications until the connection fails. Every Idle
// without one it checks the server answers, so a connection that died
// silently is noticed.
func (n *Notifier) wait(ctx context.Context, conn *pgx.Conn, wake func()) error {
	for {
		wctx, cancel := context.WithTimeout(ctx, n.Idle)
		_, err := conn.WaitForNotification(wctx)
		cancel()
		switch {
		case err == nil:
			wake()
			continue
		case ctx.Err() != nil:
			return ctx.Err()
		case !errors.Is(err, context.DeadlineExceeded) || conn.IsClosed():
			return err
		}
		pctx, cancel := context.WithTimeout(ctx, n.Idle)
		err = conn.Ping(pctx)
		cancel()
		if err != nil {
			return err
		}
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + rand.N(d/2+1) //nolint:gosec // jitter, not a secret
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
