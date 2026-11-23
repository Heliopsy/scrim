// SPDX-License-Identifier: AGPL-3.0-only

// Package agentcache holds the store credentials adapters obtain for an
// agent (a login token, assumed-role keys, an access token) until shortly
// before they expire, keyed by the agent identity and parameters they were
// obtained for, and drops a scrim session's credentials when it ends
// (specs/agent-identity "Token exchange per store").
package agentcache

import (
	"crypto/sha256"
	"sync"
	"time"
)

// MaxEntries bounds a cache; when full, expired entries go first and then
// everything.
const MaxEntries = 1024

// Cache maps a key to a credential of type T. wipe is called on every
// credential the cache drops; Get returns a copy made by clone, which the
// caller owns.
type Cache[T any] struct {
	mu    sync.Mutex
	m     map[[32]byte]entry[T]
	wipe  func(T)
	clone func(T) T
	now   func() time.Time
}

type entry[T any] struct {
	v       T
	until   time.Time
	session string
}

// New returns an empty cache.
func New[T any](clone func(T) T, wipe func(T)) *Cache[T] {
	return &Cache[T]{m: map[[32]byte]entry[T]{}, clone: clone, wipe: wipe, now: time.Now}
}

// SetNow replaces the clock, for tests.
func (c *Cache[T]) SetNow(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func hash(key string) [32]byte { return sha256.Sum256([]byte(key)) }

// Get returns a copy of the credential for key while it is fresh.
func (c *Cache[T]) Get(key string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[hash(key)]
	if !ok || !c.now().Before(e.until) {
		var zero T
		return zero, false
	}
	return c.clone(e.v), true
}

// Put takes ownership of v and keeps it for key until two thirds of ttl
// have passed (one minute when ttl is unknown), tagged with session.
func (c *Cache[T]) Put(key, session string, v T, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	until := now.Add(ttl * 2 / 3)
	if ttl <= 0 {
		until = now.Add(time.Minute)
	}
	if len(c.m) >= MaxEntries {
		for k, e := range c.m {
			if !now.Before(e.until) {
				c.wipe(e.v)
				delete(c.m, k)
			}
		}
		if len(c.m) >= MaxEntries {
			c.clearLocked()
		}
	}
	h := hash(key)
	if old, ok := c.m[h]; ok {
		c.wipe(old.v)
	}
	c.m[h] = entry[T]{v: v, until: until, session: session}
}

// ForgetSession drops every credential tagged with session.
func (c *Cache[T]) ForgetSession(session string) {
	if session == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.m {
		if e.session == session {
			c.wipe(e.v)
			delete(c.m, k)
		}
	}
}

// Len is the number of credentials held, fresh or not.
func (c *Cache[T]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// Close drops everything.
func (c *Cache[T]) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
}

func (c *Cache[T]) clearLocked() {
	for k, e := range c.m {
		c.wipe(e.v)
		delete(c.m, k)
	}
}
