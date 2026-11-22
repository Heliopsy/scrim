// SPDX-License-Identifier: AGPL-3.0-only

// Package events delivers the state outbox to in-process subscribers
// (specs/state-and-scaling "Selectable event backend", design D9).
//
// Every state change writes its events to the outbox in the same
// transaction ([state.Apply]). A [Bus] follows the outbox by increasing ID
// from where it started and calls the subscribers of each event in order,
// once. The outbox is the only source of truth; the events backend
// (events.backend) only decides how fast a reader learns that there is
// something new to read:
//
//   - local: the bus reads the outbox every events.poll-interval, and at
//     once after a commit made by this process. It reaches one process only,
//     so more than one replica refuses it at start-up.
//   - postgres: every outbox write also sends a NOTIFY, delivered on commit
//     to a dedicated LISTEN connection on every replica. Each notification,
//     each (re)connection and the start read the outbox from the last event
//     seen, so a notification lost while the listener was down costs
//     nothing. While the listener is down the bus polls at
//     events.poll-interval.
//   - valkey and nats: every replica publishes a hint on a Valkey channel or
//     a NATS subject after each of its own commits that emitted an event
//     (state.CommitHook), and subscribes to it. A hint carries nothing; the
//     subscription works like the postgres listener: each hint, each
//     (re)subscription and the start read the outbox, and while the
//     subscription is down the bus polls. A hint that could not be published
//     is published once the connection is back, and every connected bus
//     also reads the outbox every minute, which bounds a hint lost with a
//     replica that died between its commit and the publish.
//
// The shared contract every backend passes is in package eventstest.
package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/state"
)

// Backend names.
const (
	Local    = "local"
	Postgres = "postgres"
	Valkey   = "valkey"
	NATS     = "nats"
)

// Settings owned by this package.
var (
	BackendSetting = config.Register(config.Spec[string]{
		Key:     "events.backend",
		Default: Local,
		Enum:    []string{Local, Postgres, Valkey, NATS},
		Description: "How replicas learn about state changes made elsewhere (approval decisions, grant and session changes, break-glass, configuration reloads). " +
			"local reads the outbox every events.poll-interval and serves one process; postgres adds LISTEN/NOTIFY on the state database " +
			"(needs state.backend postgres); valkey and nats publish a wake-up on a Valkey channel (valkey.*) or a NATS subject (nats.*). " +
			"Every backend delivers from the outbox, so a lost wake-up costs latency, never an event. One of postgres, valkey or nats is required when deployment.replicas is more than 1.",
		Flag:            true,
		RestartRequired: true,
	})
	PollInterval = config.Register(config.Spec[time.Duration]{
		Key:     "events.poll-interval",
		Default: time.Second,
		Description: "How often the outbox is read when nothing announces new events: always with events.backend local, and while the postgres " +
			"listener or the valkey or nats subscription is disconnected. It bounds how long a change made on another replica takes to arrive then.",
		Validate:        between(10*time.Millisecond, time.Minute),
		RestartRequired: true,
	})
	Replicas = config.Register(config.Spec[int]{
		Key:     "deployment.replicas",
		Default: 1,
		Description: "How many control plane replicas share this configuration and state. More than 1 needs a shared state backend " +
			"(state.backend postgres) and a shared events backend (events.backend postgres, valkey or nats); start-up fails otherwise.",
		Validate: func(n int) error {
			if n < 1 {
				return errors.New("must be at least 1")
			}
			return nil
		},
		RestartRequired: true,
	})
)

func between(lo, hi time.Duration) func(time.Duration) error {
	return func(d time.Duration) error {
		if d < lo || d > hi {
			return fmt.Errorf("must be between %s and %s", lo, hi)
		}
		return nil
	}
}

// CheckReplicas refuses a configuration that runs more than one replica on
// something that reaches one process only (specs/state-and-scaling
// "Multiple replicas with local events").
func CheckReplicas(cfg *config.Config) error {
	n := Replicas.Get(cfg)
	if n <= 1 {
		return nil
	}
	if b := BackendSetting.Get(cfg); b == Local {
		return fmt.Errorf("events.backend is %s, which reaches one process only, but deployment.replicas is %d: set events.backend to %s, %s or %s", b, n, Postgres, Valkey, NATS)
	}
	if b := state.BackendSetting.Get(cfg); b != "postgres" {
		return fmt.Errorf("state.backend is %s, which is not shared between processes, but deployment.replicas is %d: set state.backend to postgres", b, n)
	}
	return nil
}

// Notifier tells a [Bus] that new events may have committed. Run calls
// wake on every hint and up with the connection state, until ctx ends. A
// hint carries nothing: the bus reads the outbox.
type Notifier interface {
	Run(ctx context.Context, wake func(), up func(bool))
}

// Factory builds the notifier of an events backend; nil means none (local).
type Factory func(cfg *config.Config, st state.Store, log *slog.Logger) (Notifier, error)

var (
	backendsMu sync.RWMutex
	backends   = map[string]Factory{Local: func(*config.Config, state.Store, *slog.Logger) (Notifier, error) { return nil, nil }}
)

// RegisterBackend makes an events backend available under name. Backend
// packages call it from init; internal/app imports each for its side
// effect. It panics on a duplicate name.
func RegisterBackend(name string, f Factory) {
	backendsMu.Lock()
	defer backendsMu.Unlock()
	if _, dup := backends[name]; dup {
		panic("events: backend " + name + " registered twice")
	}
	backends[name] = f
}

// NotifierFor builds the notifier events.backend names.
func NotifierFor(cfg *config.Config, st state.Store, log *slog.Logger) (Notifier, error) {
	name := BackendSetting.Get(cfg)
	backendsMu.RLock()
	f, ok := backends[name]
	backendsMu.RUnlock()
	if !ok {
		backendsMu.RLock()
		have := make([]string, 0, len(backends))
		for k := range backends {
			have = append(have, k)
		}
		backendsMu.RUnlock()
		sort.Strings(have)
		return nil, fmt.Errorf("events: events.backend %q is not built into this binary (have %v)", name, have)
	}
	return f(cfg, st, log)
}

// listeningPoll is how often the outbox is read while a notifier is
// connected: a safety net only, since notifications reach a connected
// listener.
const listeningPoll = time.Minute

// batch is how many events one outbox read returns.
const batch = 256

// Options configure a [Bus].
type Options struct {
	State state.Store
	// Notifier is the backend's; nil polls (local).
	Notifier Notifier
	// Backend names the backend, for logs and metrics.
	Backend string
	// PollInterval is events.poll-interval.
	PollInterval time.Duration
	Log          *slog.Logger
	Metrics      *obs.Metrics
}

// Handler receives one event. It runs on the bus goroutine, in event order,
// and must not block: hand slow work to another goroutine.
type Handler func(state.Event)

type sub struct {
	kind string
	fn   Handler
}

// Bus follows the outbox and calls subscribers. It is safe for concurrent
// use.
type Bus struct {
	o         Options
	last      atomic.Int64
	listening atomic.Bool
	kick      chan struct{}

	mu   sync.RWMutex
	subs []sub

	delivered *prometheus.CounterVec
	up        prometheus.Gauge
	lastID    prometheus.Gauge
}

// New returns a bus that starts after the newest committed event: history
// is not replayed. A backend that reports its commits ([state.CommitHook])
// wakes the bus after each local commit that emitted an event.
func New(ctx context.Context, o Options) (*Bus, error) {
	if o.State == nil {
		return nil, errors.New("events: State is required")
	}
	if o.PollInterval <= 0 {
		o.PollInterval = time.Second
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Backend == "" {
		o.Backend = Local
	}
	var last int64
	err := o.State.View(ctx, func(tx state.Tx) error {
		var err error
		last, err = tx.LastEventID(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("events: reading the outbox position: %w", err)
	}
	b := &Bus{o: o, kick: make(chan struct{}, 1)}
	b.last.Store(last)
	if h, ok := o.State.(state.CommitHook); ok {
		h.OnEventCommit(b.Wake)
	}
	if o.Metrics != nil {
		b.delivered = o.Metrics.Counter("events", "delivered_total", "Outbox events delivered to this replica's subscribers, by kind.", "kind")
		b.up = o.Metrics.Gauge("events", "listener_up", "1 while the events backend's listener or subscription is connected (postgres, valkey, nats), 0 while the outbox is polled.").WithLabelValues()
		b.lastID = o.Metrics.Gauge("events", "last_id", "The newest outbox event ID this replica has delivered.").WithLabelValues()
		b.lastID.Set(float64(last))
	}
	return b, nil
}

// Subscribe calls fn for every event of kind ("" for every event) read
// after it returns.
func (b *Bus) Subscribe(kind string, fn Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs = append(b.subs, sub{kind: kind, fn: fn})
}

// Wake makes the bus read the outbox now. It never blocks.
func (b *Bus) Wake() {
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

// Last is the ID of the newest event delivered.
func (b *Bus) Last() int64 { return b.last.Load() }

// Listening reports whether the notifier is connected; false for local.
func (b *Bus) Listening() bool { return b.listening.Load() }

// Notifier is the backend's notifier, nil for local.
func (b *Bus) Notifier() Notifier { return b.o.Notifier }

// Backend is the events backend name.
func (b *Bus) Backend() string { return b.o.Backend }

func (b *Bus) setUp(v bool) {
	if b.listening.Swap(v) != v {
		if b.up != nil {
			if v {
				b.up.Set(1)
			} else {
				b.up.Set(0)
			}
		}
		b.Wake()
	}
}

// interval is the time to the next unprompted read.
func (b *Bus) interval() time.Duration {
	if b.o.Notifier != nil && b.listening.Load() {
		return listeningPoll
	}
	return b.o.PollInterval
}

// Run follows the outbox until ctx ends.
func (b *Bus) Run(ctx context.Context) {
	if b.o.Notifier != nil {
		go b.o.Notifier.Run(ctx, b.Wake, b.setUp)
	}
	t := time.NewTimer(0)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.kick:
		case <-t.C:
		}
		err := b.CatchUp(ctx)
		switch {
		case err != nil && ctx.Err() != nil:
			return
		case err != nil && !failing:
			failing = true
			b.o.Log.Warn("events: reading the outbox failed; retrying", "backend", b.o.Backend, "err", err)
		case err == nil && failing:
			failing = false
			b.o.Log.Info("events: reading the outbox again", "backend", b.o.Backend)
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(b.interval())
	}
}

// CatchUp reads every event after the last one delivered and delivers it.
// Run calls it; it must not run concurrently with Run.
func (b *Bus) CatchUp(ctx context.Context) error {
	for {
		var evs []state.Event
		after := b.last.Load()
		err := b.o.State.View(ctx, func(tx state.Tx) error {
			var err error
			evs, err = tx.EventsAfter(ctx, after, batch)
			return err
		})
		if err != nil {
			return err
		}
		for _, e := range evs {
			if e.ID <= b.last.Load() {
				continue
			}
			b.dispatch(e)
			b.last.Store(e.ID)
		}
		if b.lastID != nil && len(evs) > 0 {
			b.lastID.Set(float64(b.last.Load()))
		}
		if len(evs) < batch {
			return nil
		}
	}
}

func (b *Bus) dispatch(e state.Event) {
	b.mu.RLock()
	subs := b.subs
	b.mu.RUnlock()
	for _, s := range subs {
		if s.kind == "" || s.kind == e.Kind {
			s.fn(e)
		}
	}
	if b.delivered != nil {
		b.delivered.WithLabelValues(e.Kind).Inc()
	}
}

// OnLocalCommit registers fn to run after every commit made through st that
// emitted an event, the trigger a backend that announces commits itself
// (valkey, nats) publishes on. fn runs on the committing goroutine and must
// not block. It fails for a state backend that does not report its commits.
func OnLocalCommit(st state.Store, fn func()) error {
	h, ok := st.(state.CommitHook)
	if !ok {
		return fmt.Errorf("events: state backend %s does not report its commits", st.Backend())
	}
	h.OnEventCommit(fn)
	return nil
}

// Signal is a coalescing, non-blocking wake-up: any number of Raise calls
// before the receiver runs leave one pending signal.
type Signal chan struct{}

// NewSignal returns a Signal.
func NewSignal() Signal { return make(Signal, 1) }

// Raise sets the signal. It never blocks.
func (s Signal) Raise() {
	select {
	case s <- struct{}{}:
	default:
	}
}

// Jitter returns a duration between d/2 and d, so replicas that lost a
// connection together do not reconnect together.
func Jitter(d time.Duration) time.Duration {
	return d/2 + rand.N(d/2+1) //nolint:gosec // jitter, not a secret
}

// Sleep waits d or until ctx ends.
func Sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
