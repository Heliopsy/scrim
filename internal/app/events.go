// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/events"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
)

// Configuration announcements: every replica records the digest of the
// configuration it runs when it starts serving and after each reload, and
// warns when a peer announces a different one.
const (
	ActionConfigReloaded = "config.reloaded"
	EventConfigReloaded  = "config.reloaded"
)

// initEvents builds the events bus over the state backend. It starts
// nothing; [App.RunPolicy] runs it.
func (a *App) initEvents(ctx context.Context, cfg *config.Config) error {
	log := obs.WithComponent(a.Log, "events")
	n, err := events.NotifierFor(cfg, a.State, log)
	if err != nil {
		return err
	}
	a.Events, err = events.New(ctx, events.Options{
		State: a.State, Notifier: n, Backend: events.BackendSetting.Get(cfg),
		PollInterval: events.PollInterval.Get(cfg), Log: log, Metrics: a.Metrics,
	})
	return err
}

// subscribeEvents connects the policy components to the bus: a decision
// made on any replica releases the operations waiting on it here, and a
// break-glass change made on any replica is applied here (which pushes a
// snapshot to the data plane and denies pending approvals). Grants and
// sessions need no subscriber: they are read from the state backend on
// every use.
func (a *App) subscribeEvents(p *Policy) {
	a.Events.Subscribe(approval.EventDecided, func(e state.Event) { p.Approvals.Wake(e.Subject) })
	a.Events.Subscribe(breakglass.EventChanged, func(state.Event) { p.BreakGlass.Poke() })
	a.configs = &configDigests{log: obs.WithComponent(a.Log, "events"), warned: map[string]bool{}}
	a.configs.set(ConfigDigest(a.Config.Current()))
	a.Events.Subscribe(EventConfigReloaded, a.configs.peer)
	a.Config.Subscribe(func(old, cur *config.Config) {
		a.configs.set(ConfigDigest(cur))
		a.announceConfig(context.Background(), "reload", len(config.Changed(old, cur)))
	})
}

// announceConfig records this replica's configuration digest in the audit
// log and the outbox.
func (a *App) announceConfig(ctx context.Context, trigger string, changed int) {
	if a.configs == nil {
		return
	}
	digest := a.configs.get()
	now := time.Now().UTC()
	err := state.Apply(ctx, a.State, func(state.Tx) (state.Change, error) {
		attrs := map[string]string{"trigger": trigger}
		if trigger == "reload" {
			attrs["changed"] = strconv.Itoa(changed)
		}
		return state.Change{
			Audit: audit.Entry{Time: now, Action: ActionConfigReloaded, Actor: "scrim", Subject: digest,
				Effect: policy.Allow, Attrs: attrs},
			Events: []state.Event{{Kind: EventConfigReloaded, Subject: digest, Time: now}},
		}, nil
	})
	if err != nil {
		a.Log.Warn("could not record the configuration digest", "err", err)
	}
}

// configDigests compares this replica's configuration with its peers'.
type configDigests struct {
	log    *slog.Logger
	mu     sync.Mutex
	own    string
	warned map[string]bool
}

func (c *configDigests) set(d string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d != c.own {
		c.own = d
		clear(c.warned)
	}
}

func (c *configDigests) get() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.own
}

func (c *configDigests) peer(e state.Event) {
	c.mu.Lock()
	own, seen := c.own, c.warned[e.Subject]
	differs := e.Subject != "" && e.Subject != own && !seen
	if differs && len(c.warned) < 64 {
		c.warned[e.Subject] = true
	}
	c.mu.Unlock()
	if differs {
		c.log.Warn("replicas run different configurations: a peer announced another configuration digest",
			"this_digest", own, "peer_digest", e.Subject)
	}
}

// ConfigDigest identifies an effective configuration without revealing it:
// a SHA-256 over every setting's key and effective value, with secret-ref
// settings in their reference form (never a value) and without where each
// value came from.
func ConfigDigest(cfg *config.Config) string {
	type row struct {
		K string `json:"k"`
		V any    `json:"v"`
		R string `json:"r,omitempty"`
	}
	entries := config.Effective(cfg)
	rows := make([]row, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, row{K: e.Key, V: e.Value, R: e.Reference})
	}
	b, _ := json.Marshal(rows) // plain values; cannot fail
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:8])
}
