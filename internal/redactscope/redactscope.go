// SPDX-License-Identifier: AGPL-3.0-only

// Package redactscope keeps redaction coverage apart from use (specs
// agent-identity "Redaction coverage is separate from use").
//
// The redaction set is loaded by each store's refresher with the store
// instance's own credentials, scrim's redaction identity. No per-agent
// identity is involved: a store login or token exchange for an agent
// (identity.store-login, identity.store-credentials, and later federated
// per-agent identities) only decides what that agent may use or write. So a
// value an agent's own identity cannot read is still in the redaction set,
// and is redacted when the agent sends it by accident.
//
// The one exception is the weakening setting
// redaction.limit-to-agent-identity. With it on, a [Checker] asks each
// store, as each agent with its own identity there, whether that agent can
// read each value of the redaction set, and the snapshot lists, per agent,
// the references it cannot read. The data plane leaves those out of the
// redaction of that agent's sessions' provider requests. Everything that is
// not known to be unreadable stays redacted: a value not yet checked, a
// check that failed, a result older than the recheck interval, a caller
// that is not a proven session, every path other than the LLM proxy.
//
// [AgentReader] is the boundary a per-agent identity plugs into: the static
// per-agent credentials of internal/agentstore implement it today, and a
// federated per-agent identity implements it the same way.
package redactscope

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/stores"
)

// LimitKey is the weakening setting's key.
const LimitKey = "redaction.limit-to-agent-identity"

// LimitToAgentIdentity narrows each agent's redaction to what its own store
// identity can read.
var LimitToAgentIdentity = config.Register(config.Spec[bool]{
	Key:             LimitKey,
	Weakening:       true,
	RestartRequired: true,
	Description: "Leave out of the redaction of an agent's provider requests the values that agent's own store identity cannot read. " +
		"Off (the default), the redaction set is loaded with each store's own credentials and covers every value, whatever " +
		"each agent may use, so a value an agent reads by accident is still redacted. On, scrim checks each value of a store " +
		"with per-agent identity (identity.store-credentials) as each such agent, and the provider requests of that agent's " +
		"`scrim run` sessions are no longer redacted for the values its store refused it. Kubernetes callers, peers, the tool " +
		"proxy and every value not yet checked keep the whole redaction set.",
})

// RecheckInterval is how long one check's answer is used. After it the
// value counts as readable (redacted) again until it is checked anew.
const RecheckInterval = 5 * time.Minute

// checkTimeout bounds one check against a store.
const checkTimeout = 10 * time.Second

// AgentReader answers, for the stores where agents have their own identity,
// whether an agent's own identity can read a reference. It never reads the
// value with the agent's identity, and its errors never hold a value.
type AgentReader interface {
	// ReadAgents lists, sorted, the agents with their own identity for
	// store that can be checked while the agent is not calling (a static
	// credential scrim holds, not a token only the caller presents). Empty
	// for a store every agent uses with scrim's identity.
	ReadAgents(store string) []string
	// AgentCanRead reports whether agent's own identity for ref's store can
	// read ref. A refusal is (false, nil); an error means the answer is not
	// known.
	AgentCanRead(ctx context.Context, agent string, ref stores.Ref) (bool, error)
}

// Value is one entry of the redaction set as the snapshot lists it.
type Value struct {
	// Store is the store instance the value came from.
	Store string
	// Ref is its reference; zero for a store's own credentials, which are
	// always redacted.
	Ref stores.Ref
}

type key struct {
	agent string
	ref   string
}

type answer struct {
	readable bool
	at       time.Time
}

// Checker caches what each agent's own identity can read and answers from
// the cache, so building a snapshot never waits on a store. Unknown pairs
// are queued for [Checker.Run].
type Checker struct {
	reader   AgentReader
	onChange func()
	log      *slog.Logger
	now      func() time.Time
	interval time.Duration

	mu      sync.Mutex
	known   map[key]answer
	queued  map[key]stores.Ref
	wake    chan struct{}
	exempts map[string][]string
}

// Options build a Checker.
type Options struct {
	// Reader checks an agent's own identity.
	Reader AgentReader
	// OnChange is called, outside any lock, after a check changed what is
	// exempt, so the snapshot is rebuilt. It must not block.
	OnChange func()
	// Log receives the weakening warnings. Nil discards them.
	Log *slog.Logger
	// Now and Interval are for tests; zero values mean time.Now and
	// [RecheckInterval].
	Now      func() time.Time
	Interval time.Duration
}

// New returns a Checker; call Run to start checking.
func New(o Options) *Checker {
	c := &Checker{reader: o.Reader, onChange: o.OnChange, log: o.Log, now: o.Now, interval: o.Interval,
		known: map[key]answer{}, queued: map[key]stores.Ref{}, wake: make(chan struct{}, 1), exempts: map[string][]string{}}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.interval <= 0 {
		c.interval = RecheckInterval
	}
	return c
}

// Exempt returns, per agent, the sorted references among values that the
// agent's own identity is known not to read. A pair not known, or known
// longer than the recheck interval, is queued and is not exempt.
func (c *Checker) Exempt(values []Value) map[string][]string {
	out := map[string][]string{}
	agentsOf := map[string][]string{}
	now := c.now()
	queued := false
	c.mu.Lock()
	for _, v := range values {
		if v.Ref.IsZero() || v.Store == "" {
			continue
		}
		agents, ok := agentsOf[v.Store]
		if !ok {
			agents = c.reader.ReadAgents(v.Store)
			agentsOf[v.Store] = agents
		}
		ref := v.Ref.String()
		for _, a := range agents {
			k := key{agent: a, ref: ref}
			ans, ok := c.known[k]
			if !ok || now.Sub(ans.at) >= c.interval {
				if _, in := c.queued[k]; !in {
					c.queued[k] = v.Ref
					queued = true
				}
				continue
			}
			if !ans.readable && !slices.Contains(out[a], ref) {
				out[a] = append(out[a], ref)
			}
		}
	}
	changed := false
	for a := range out {
		slices.Sort(out[a])
	}
	if !maps.EqualFunc(out, c.exempts, slices.Equal) {
		changed = true
		c.exempts = out
	}
	c.mu.Unlock()
	if queued {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
	if changed {
		for _, a := range slices.Sorted(maps.Keys(out)) {
			c.log.Warn("weakened redaction: values this agent's own store identity cannot read are not redacted from its sessions' provider requests",
				"setting", LimitKey, "agent", a, "values", len(out[a]), "refs", out[a])
		}
	}
	return out
}

// Run checks queued pairs until ctx ends, and rechecks each answer after
// the recheck interval by requeueing it on the next [Checker.Exempt].
func (c *Checker) Run(ctx context.Context) {
	tick := time.NewTicker(c.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
		case <-tick.C:
			// Answers past the interval stop counting; a rebuild requeues them.
			if c.onChange != nil {
				c.onChange()
			}
			continue
		}
		c.drain(ctx)
	}
}

// drain checks every queued pair once.
func (c *Checker) drain(ctx context.Context) {
	for ctx.Err() == nil {
		c.mu.Lock()
		var (
			k   key
			ref stores.Ref
			ok  bool
		)
		for kk, r := range c.queued {
			k, ref, ok = kk, r, true
			break
		}
		c.mu.Unlock()
		if !ok {
			return
		}
		cctx, cancel := context.WithTimeout(ctx, checkTimeout)
		readable, err := c.reader.AgentCanRead(cctx, k.agent, ref)
		cancel()
		if err != nil {
			// Not known: keep it redacted, and check again after the interval.
			readable = true
			c.log.Warn("could not check what an agent's own store identity can read; the value stays redacted",
				"setting", LimitKey, "agent", k.agent, "ref", k.ref, "err", err)
		}
		c.mu.Lock()
		prev, had := c.known[k]
		c.known[k] = answer{readable: readable, at: c.now()}
		delete(c.queued, k)
		c.mu.Unlock()
		// An unreadable answer adds an exemption (again, after a recheck); a
		// readable one after an unreadable one removes it.
		if (!readable || (had && !prev.readable)) && c.onChange != nil {
			c.onChange()
		}
	}
}
