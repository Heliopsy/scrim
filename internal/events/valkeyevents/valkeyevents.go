// SPDX-License-Identifier: AGPL-3.0-only

// Package valkeyevents is the valkey events backend (specs/state-and-scaling
// "Selectable event backend", design D9). Every replica publishes a hint on
// a Valkey channel after each of its own commits that emitted an event, and
// holds a dedicated subscription to that channel that turns every hint into
// a wake-up for the bus (package events). A hint carries nothing: the bus
// reads the outbox. The subscription reconnects with backoff; while it is
// down the bus polls the outbox, and every (re)subscription makes the bus
// read everything it missed. A hint that could not be published is retried
// until the connection is back.
package valkeyevents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/events"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/valkeyconn"
)

// Channel is the Valkey channel hints are published on.
var Channel = config.Register(config.Spec[string]{
	Key:     "events.valkey.channel",
	Default: "scrim:events",
	Description: "Valkey channel the valkey events backend publishes and subscribes to. Replicas of one deployment share it; " +
		"two deployments on one Valkey need different channels.",
	Validate: func(s string) error {
		if s == "" {
			return errors.New("must not be empty")
		}
		return nil
	},
	RestartRequired: true,
})

func init() {
	events.RegisterBackend(events.Valkey, func(cfg *config.Config, st state.Store, log *slog.Logger) (events.Notifier, error) {
		o, err := valkeyconn.FromConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("events: events.backend valkey: %w", err)
		}
		o.ClientName = "scrim-events"
		c, err := valkeyconn.New(o)
		if err != nil {
			return nil, fmt.Errorf("events: events.backend valkey: %w", err)
		}
		n := New(c, Channel.Get(cfg), log)
		n.ownsClient = true
		if err := events.OnLocalCommit(st, n.Hint); err != nil {
			c.Close()
			return nil, err
		}
		return n, nil
	})
}

// Backoff bounds between reconnect and publish attempts.
const (
	MinBackoff = 250 * time.Millisecond
	MaxBackoff = 30 * time.Second
)

// hint is the published payload: the channel is the message.
const hint = "1"

// Notifier implements [events.Notifier] over Valkey pub/sub.
type Notifier struct {
	c       valkey.Client
	channel string
	log     *slog.Logger
	// Min and Max bound the backoff; SubscribeTimeout bounds the wait for
	// the server to confirm a subscription. Tests shorten them.
	Min, Max, SubscribeTimeout time.Duration

	ownsClient bool
	pending    events.Signal

	connects    atomic.Int64
	published   atomic.Int64
	lastConnect atomic.Int64
}

// New returns a notifier over c. Register [Notifier.Hint] as the state
// backend's commit hook so the replica's commits are announced.
func New(c valkey.Client, channel string, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Notifier{c: c, channel: channel, log: log, Min: MinBackoff, Max: MaxBackoff,
		SubscribeTimeout: 10 * time.Second, pending: events.NewSignal()}
}

// Hint asks for a hint to be published. It never blocks; hints raised
// before the publisher runs coalesce into one.
func (n *Notifier) Hint() { n.pending.Raise() }

// Connects is how many times the subscription has been established.
func (n *Notifier) Connects() int64 { return n.connects.Load() }

// Published is how many hints have been published.
func (n *Notifier) Published() int64 { return n.published.Load() }

// LastConnect is when the subscription was last established.
func (n *Notifier) LastConnect() time.Time {
	if ns := n.lastConnect.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// Run implements [events.Notifier]. It also runs the publisher, and closes
// the client when ctx ends if the notifier built it.
func (n *Notifier) Run(ctx context.Context, wake func(), up func(bool)) {
	if n.ownsClient {
		defer n.c.Close()
	}
	done := make(chan struct{})
	go func() { defer close(done); n.publish(ctx) }()
	defer func() { <-done }()
	backoff := n.Min
	failing := false
	for ctx.Err() == nil {
		err := n.subscribe(ctx, wake, func() {
			if failing || n.connects.Load() > 0 {
				n.log.Info("events: the valkey subscription is back; reading what was missed")
			}
			failing, backoff = false, n.Min
			n.connects.Add(1)
			n.lastConnect.Store(time.Now().UnixNano())
			up(true)
		})
		up(false)
		if ctx.Err() != nil {
			return
		}
		if !failing {
			failing = true
			n.log.Warn("events: the valkey subscription is down; polling the outbox until it is back", "err", err)
		}
		events.Sleep(ctx, events.Jitter(backoff))
		backoff = min(backoff*2, n.Max)
	}
}

// subscribe holds one subscription until its connection fails. subscribed
// runs once the server has confirmed it, so every hint published from then
// on reaches this replica and the read it triggers covers everything
// before.
func (n *Notifier) subscribe(ctx context.Context, wake func(), subscribed func()) error {
	dc, cancel := n.c.Dedicate()
	defer cancel()
	confirmed := make(chan struct{}, 1)
	failed := dc.SetPubSubHooks(valkey.PubSubHooks{
		OnMessage: func(valkey.PubSubMessage) { wake() },
		OnSubscription: func(s valkey.PubSubSubscription) {
			if s.Kind == "subscribe" && s.Channel == n.channel {
				select {
				case confirmed <- struct{}{}:
				default:
				}
			}
		},
	})
	sctx, scancel := context.WithTimeout(ctx, n.SubscribeTimeout)
	err := dc.Do(sctx, dc.B().Subscribe().Channel(n.channel).Build()).Error()
	scancel()
	if err != nil {
		return err
	}
	t := time.NewTimer(n.SubscribeTimeout)
	defer t.Stop()
	select {
	case <-confirmed:
	case err := <-failed:
		return orClosed(err)
	case <-t.C:
		return errors.New("the server did not confirm the subscription")
	case <-ctx.Done():
		return ctx.Err()
	}
	subscribed()
	select {
	case err := <-failed:
		return orClosed(err)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func orClosed(err error) error {
	if err == nil {
		return errors.New("connection closed")
	}
	return err
}

// publish sends one hint per raised signal, retrying with backoff until it
// is accepted, so a commit made while Valkey was unreachable is announced
// once it is back.
func (n *Notifier) publish(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.pending:
		}
		backoff := n.Min
		for {
			pctx, cancel := context.WithTimeout(ctx, n.SubscribeTimeout)
			err := n.c.Do(pctx, n.c.B().Publish().Channel(n.channel).Message(hint).Build()).Error()
			cancel()
			if err == nil {
				n.published.Add(1)
				break
			}
			if ctx.Err() != nil {
				return
			}
			n.log.Debug("events: publishing a valkey hint failed; retrying", "err", err)
			events.Sleep(ctx, events.Jitter(backoff))
			backoff = min(backoff*2, n.Max)
		}
	}
}
