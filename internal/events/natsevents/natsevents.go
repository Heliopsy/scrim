// SPDX-License-Identifier: AGPL-3.0-only

// Package natsevents is the nats events backend (specs/state-and-scaling
// "Selectable event backend", design D9). Every replica publishes an empty
// hint on a NATS subject after each of its own commits that emitted an
// event, and subscribes to that subject; every hint wakes the bus (package
// events), which reads the outbox. The client reconnects on its own with
// jittered backoff and buffers hints published while it is down. After
// every reconnect the notifier confirms the resent subscription with a
// round trip before reporting the subscription up, so the read that follows
// covers every commit a lost hint announced.
package natsevents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/events"
	"github.com/heliopsy/scrim/internal/natsconn"
	"github.com/heliopsy/scrim/internal/state"
)

// Subject is the NATS subject hints are published on.
var Subject = config.Register(config.Spec[string]{
	Key:     "events.nats.subject",
	Default: "scrim.events",
	Description: "NATS subject the nats events backend publishes and subscribes to. Replicas of one deployment share it; " +
		"two deployments on one NATS account need different subjects.",
	Validate: func(s string) error {
		if s == "" {
			return errors.New("must not be empty")
		}
		return nil
	},
	RestartRequired: true,
})

func init() {
	events.RegisterBackend(events.NATS, func(cfg *config.Config, st state.Store, log *slog.Logger) (events.Notifier, error) {
		o, err := natsconn.FromConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("events: events.backend nats: %w", err)
		}
		o.Name = "scrim-events"
		n := New(o, Subject.Get(cfg), log)
		if err := events.OnLocalCommit(st, n.Hint); err != nil {
			return nil, err
		}
		return n, nil
	})
}

// Notifier implements [events.Notifier] over NATS core pub/sub.
type Notifier struct {
	o       natsconn.Options
	subject string
	log     *slog.Logger

	pending events.Signal
	state   chan bool

	connects    atomic.Int64
	published   atomic.Int64
	lastConnect atomic.Int64
	conn        atomic.Pointer[nats.Conn]
}

// New returns a notifier for the servers in o. Register [Notifier.Hint] as
// the state backend's commit hook so the replica's commits are announced.
func New(o natsconn.Options, subject string, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Notifier{o: o, subject: subject, log: log, pending: events.NewSignal(), state: make(chan bool, 16)}
}

// Hint asks for a hint to be published. It never blocks.
func (n *Notifier) Hint() { n.pending.Raise() }

// Connects is how many times the subscription has been confirmed.
func (n *Notifier) Connects() int64 { return n.connects.Load() }

// Published is how many hints have been handed to the client.
func (n *Notifier) Published() int64 { return n.published.Load() }

// LastConnect is when the subscription was last confirmed.
func (n *Notifier) LastConnect() time.Time {
	if ns := n.lastConnect.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

func (n *Notifier) changed(up bool) {
	select {
	case n.state <- up:
	default:
		// The loop is behind; it re-checks the connection on its own.
	}
}

// Run implements [events.Notifier].
func (n *Notifier) Run(ctx context.Context, wake func(), up func(bool)) {
	opts := append(n.o.NATSOptions(),
		nats.ConnectHandler(func(*nats.Conn) { n.changed(true) }),
		nats.ReconnectHandler(func(*nats.Conn) { n.changed(true) }),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			n.log.Warn("events: the nats connection is down; polling the outbox until it is back", "err", err)
			n.changed(false)
		}),
		nats.ClosedHandler(func(*nats.Conn) { n.changed(false) }),
	)
	nc, err := nats.Connect(n.o.URL(), opts...)
	if err != nil {
		// RetryOnFailedConnect makes this a configuration error only.
		n.log.Error("events: the nats client could not be created; polling the outbox", "err", err)
		<-ctx.Done()
		return
	}
	n.conn.Store(nc)
	defer nc.Close()
	if _, err := nc.Subscribe(n.subject, func(*nats.Msg) { wake() }); err != nil {
		n.log.Error("events: subscribing to the nats subject failed; polling the outbox", "err", err)
		<-ctx.Done()
		return
	}
	if nc.IsConnected() {
		n.changed(true)
	}
	timeout := n.o.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	listening := false
	recheck := time.NewTicker(timeout)
	defer recheck.Stop()
	for {
		select {
		case <-ctx.Done():
			up(false)
			return
		case <-n.pending:
			// Buffered by the client while it reconnects, sent after.
			if err := nc.Publish(n.subject, nil); err == nil {
				n.published.Add(1)
			} else {
				n.log.Debug("events: publishing a nats hint failed", "err", err)
				go func() { events.Sleep(ctx, timeout); n.Hint() }()
			}
		case v := <-n.state:
			listening = n.apply(nc, v, listening, timeout, up)
		case <-recheck.C:
			listening = n.apply(nc, nc.IsConnected(), listening, timeout, up)
		}
	}
}

// apply moves the reported state to v. Going up needs a round trip: once
// the server answers a flush it has processed the resent SUB, so a hint
// published from then on arrives and the read up() triggers covers
// everything before.
func (n *Notifier) apply(nc *nats.Conn, v, listening bool, timeout time.Duration, up func(bool)) bool {
	if v && !listening {
		if err := nc.FlushTimeout(timeout); err != nil {
			return false
		}
		if n.connects.Load() > 0 {
			n.log.Info("events: the nats subscription is back; reading what was missed")
		}
		n.connects.Add(1)
		n.lastConnect.Store(time.Now().UnixNano())
		up(true)
		return true
	}
	if !v && listening {
		up(false)
		return false
	}
	if listening && !nc.IsConnected() {
		up(false)
		return false
	}
	return listening
}
