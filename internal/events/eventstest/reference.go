// SPDX-License-Identifier: AGPL-3.0-only

package eventstest

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/state"
)

// Shared returns n replica handles on one store. Each has its own commit
// hook, fired only for commits made through it, the way separate processes
// on one database see their own commits; s's hook is not used.
func Shared(s state.Store, n int) []state.Store {
	out := make([]state.Store, n)
	for i := range out {
		out[i] = &replicaStore{Store: s}
	}
	return out
}

type replicaStore struct {
	state.Store
	mu    sync.Mutex
	hooks []func()
}

var _ state.CommitHook = (*replicaStore)(nil)

func (r *replicaStore) OnEventCommit(fn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks = append(r.hooks, fn)
}

func (r *replicaStore) Update(ctx context.Context, fn func(state.Tx) error) error {
	var emitted bool
	err := r.Store.Update(ctx, func(tx state.Tx) error { return fn(emitTx{Tx: tx, emitted: &emitted}) })
	if err == nil && emitted {
		r.mu.Lock()
		hooks := append([]func(){}, r.hooks...)
		r.mu.Unlock()
		for _, h := range hooks {
			h()
		}
	}
	return err
}

type emitTx struct {
	state.Tx
	emitted *bool
}

func (e emitTx) Emit(ctx context.Context, ev *state.Event) error {
	err := e.Tx.Emit(ctx, ev)
	if err == nil {
		*e.emitted = true
	}
	return err
}

// Hub is the in-memory reference events backend: a commit through any
// attached replica wakes every connected notifier.
type Hub struct {
	mu   sync.Mutex
	subs map[*HubNotifier]bool
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[*HubNotifier]bool{}} }

// Notifier returns a notifier for the replica st, announcing its commits.
func (h *Hub) Notifier(st state.Store) *HubNotifier {
	n := &HubNotifier{hub: h, ups: make(chan bool, 4)}
	st.(state.CommitHook).OnEventCommit(func() {
		n.mu.Lock()
		cut := n.cut
		if cut {
			n.owed = true
		}
		n.mu.Unlock()
		if !cut {
			h.broadcast()
		}
	})
	return n
}

func (h *Hub) broadcast() {
	h.mu.Lock()
	subs := make([]*HubNotifier, 0, len(h.subs))
	for s := range h.subs {
		subs = append(subs, s)
	}
	h.mu.Unlock()
	for _, s := range subs {
		s.mu.Lock()
		wake := s.wake
		s.mu.Unlock()
		if wake != nil {
			wake()
		}
	}
}

// HubNotifier is one replica's connection to a [Hub].
type HubNotifier struct {
	hub  *Hub
	ups  chan bool
	mu   sync.Mutex
	wake func()
	cut  bool
	owed bool
}

// Run implements events.Notifier.
func (n *HubNotifier) Run(ctx context.Context, wake func(), up func(bool)) {
	connect := func() {
		n.mu.Lock()
		n.wake = wake
		owed := n.owed
		n.owed = false
		n.mu.Unlock()
		n.hub.mu.Lock()
		n.hub.subs[n] = true
		n.hub.mu.Unlock()
		up(true)
		if owed {
			n.hub.broadcast()
		}
	}
	disconnect := func() {
		n.hub.mu.Lock()
		delete(n.hub.subs, n)
		n.hub.mu.Unlock()
		n.mu.Lock()
		n.wake = nil
		n.mu.Unlock()
		up(false)
	}
	connect()
	for {
		select {
		case <-ctx.Done():
			disconnect()
			return
		case v := <-n.ups:
			if v {
				connect()
			} else {
				disconnect()
			}
		}
	}
}

// Interrupt cuts the notifier off the hub until restore runs: it neither
// receives nor sends wake-ups, and announces a commit made meanwhile once
// it is back.
func (n *HubNotifier) Interrupt(*testing.T) (restore func()) {
	n.mu.Lock()
	n.cut = true
	n.mu.Unlock()
	n.ups <- false
	var once sync.Once
	return func() {
		once.Do(func() {
			n.mu.Lock()
			n.cut = false
			n.mu.Unlock()
			n.ups <- true
		})
	}
}

// Cutter is a dialer whose connections a test can cut and hold down, to
// simulate a network partition between one replica and the events backend.
type Cutter struct {
	mu    sync.Mutex
	down  bool
	conns map[net.Conn]bool
}

// ErrCut is returned by a dial while the cutter is down.
var ErrCut = errors.New("eventstest: connection cut by the test")

// DialContext dials addr unless the cutter is down.
func (c *Cutter) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c.mu.Lock()
	down := c.down
	c.mu.Unlock()
	if down {
		return nil, ErrCut
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		_ = conn.Close()
		return nil, ErrCut
	}
	if c.conns == nil {
		c.conns = map[net.Conn]bool{}
	}
	c.conns[conn] = true
	return conn, nil
}

// Dial is DialContext without a context, for nats.CustomDialer.
func (c *Cutter) Dial(network, addr string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, addr)
}

// Cut closes every connection and refuses new ones until restore runs.
func (c *Cutter) Cut(*testing.T) (restore func()) {
	c.mu.Lock()
	c.down = true
	for conn := range c.conns {
		_ = conn.Close()
	}
	clear(c.conns)
	c.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			c.down = false
			c.mu.Unlock()
		})
	}
}
