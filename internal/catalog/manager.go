// SPDX-License-Identifier: AGPL-3.0-only

package catalog

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// ConfigSource is what the manager needs from the configuration:
// *config.Manager and *config.Holder implement it.
type ConfigSource interface {
	Current() *config.Config
	Subscribe(fn func(old, cur *config.Config)) (cancel func())
}

// Manager keeps the current catalog and reloads it without a restart when
// the configuration changes (catalog.* settings and entries) or a catalog
// file changes. A reload is all or nothing: an invalid catalog, for example
// one holding a literal value, is not loaded and the previous one stays in
// effect.
type Manager struct {
	src    ConfigSource
	lister Lister
	log    *slog.Logger

	cur     atomic.Pointer[Catalog]
	trigger chan struct{}
	cancel  func()

	mu      sync.Mutex
	subs    map[int]func(*Catalog)
	next    int
	lastErr error
	prints  map[string][32]byte
}

// NewManager loads the first catalog. It fails if the catalog is invalid.
// lister may be nil, in which case bulk prefixes and store metadata are not
// read.
func NewManager(ctx context.Context, src ConfigSource, lister Lister, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	m := &Manager{src: src, lister: lister, log: log, trigger: make(chan struct{}, 1), subs: map[int]func(*Catalog){}}
	if err := m.Reload(ctx); err != nil {
		return nil, err
	}
	m.cancel = src.Subscribe(func(old, cur *config.Config) {
		for _, k := range config.Changed(old, cur) {
			if strings.HasPrefix(k, "catalog.") {
				m.Trigger()
				return
			}
		}
	})
	return m, nil
}

// Current returns the catalog in effect.
func (m *Manager) Current() *Catalog { return m.cur.Load() }

// LastError returns why the last reload was rejected, or nil.
func (m *Manager) LastError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

// Subscribe calls fn with every newly applied catalog and returns a
// function that removes it. fn must not block.
func (m *Manager) Subscribe(fn func(*Catalog)) (cancel func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.next
	m.next++
	m.subs[id] = fn
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.subs, id)
	}
}

// Trigger asks Run to reload soon. It never blocks.
func (m *Manager) Trigger() {
	select {
	case m.trigger <- struct{}{}:
	default:
	}
}

// Reload rebuilds the catalog now. On error the current catalog stays.
func (m *Manager) Reload(ctx context.Context) error {
	c := m.src.Current()
	prints := fingerprints(Files.Get(c))
	cat, err := Load(ctx, c, m.lister, SelectionFrom(c))
	m.mu.Lock()
	m.prints = prints
	m.lastErr = err
	if err != nil {
		m.mu.Unlock()
		m.log.Error("catalog not reloaded; the previous catalog stays in effect", "error", err.Error())
		return err
	}
	m.cur.Store(cat)
	subs := make([]func(*Catalog), 0, len(m.subs))
	for _, fn := range m.subs {
		subs = append(subs, fn)
	}
	m.mu.Unlock()
	for _, w := range cat.Warnings() {
		m.log.Warn("catalog", "warning", w)
	}
	for _, fn := range subs {
		fn(cat)
	}
	return nil
}

// Run reloads on configuration changes and polls catalog files every
// catalog.reload-interval until ctx ends.
func (m *Manager) Run(ctx context.Context) error {
	defer m.Close()
	for {
		interval := ReloadInterval.Get(m.src.Current())
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-m.trigger:
			t.Stop()
			_ = m.Reload(ctx)
		case <-t.C:
			if m.filesChanged() {
				_ = m.Reload(ctx)
			}
		}
	}
}

// Close stops listening to configuration changes.
func (m *Manager) Close() {
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *Manager) filesChanged() bool {
	now := fingerprints(Files.Get(m.src.Current()))
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(now) != len(m.prints) {
		return true
	}
	for p, h := range now {
		if m.prints[p] != h {
			return true
		}
	}
	return false
}

// fingerprints hashes each file's content; a missing file hashes as zero.
func fingerprints(paths []string) map[string][32]byte {
	out := make(map[string][32]byte, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec // the path is configuration
		if err != nil {
			out[p] = [32]byte{}
			continue
		}
		out[p] = sha256.Sum256(data)
	}
	return out
}
