// SPDX-License-Identifier: AGPL-3.0-only

// Package ratelimit enforces per-agent rate limits on the agent API,
// approval requests and asks for a human (specs/state-and-scaling
// "Selectable rate-limit backend", design D9).
//
// Every backend implements the same generic cell rate algorithm (GCRA): a
// limit of Rate per Interval with a Burst allows Burst requests at once and
// then one every Interval/Rate. The state per key is one timestamp, the
// theoretical arrival time of the next request.
//
//   - local keeps it in process memory: exact for one replica, and with N
//     replicas an agent can get up to N times the limit (documented as
//     approximate).
//   - valkey keeps it in Valkey and updates it with one atomic script that
//     reads Valkey's clock, so every replica shares one exact limit.
//
// Keys are a hash of the limit class and the agent, so Valkey never sees an
// agent name. A backend error refuses the request (fail closed): an
// unreachable limiter is not a reason to lift a limit.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// Classes of limited operations.
const (
	// ClassAgentAPI is every agent tool call, through the local API or MCP.
	ClassAgentAPI = "agent-api"
	// ClassApprovals is every approval created for an agent, by a tool call
	// or a proxied request that policy holds for a human.
	ClassApprovals = "approvals"
	// ClassAsks is every secret_ask_human an agent opens.
	ClassAsks = "asks"
)

// Classes lists every class.
var Classes = []string{ClassAgentAPI, ClassApprovals, ClassAsks}

// Limit allows Rate requests per Interval after an initial Burst.
type Limit struct {
	Rate     int
	Interval time.Duration
	Burst    int
}

// Off reports whether the limit is disabled (Rate 0).
func (l Limit) Off() bool { return l.Rate <= 0 || l.Interval <= 0 }

// emission is the time one request uses up.
func (l Limit) emission() time.Duration { return l.Interval / time.Duration(l.Rate) }

func (l Limit) burst() int { return max(l.Burst, 1) }

// Result is one decision.
type Result struct {
	Allowed bool
	// RetryAfter is how long until a refused request would be allowed.
	RetryAfter time.Duration
	// Remaining is how many more requests would be allowed now.
	Remaining int
}

// Limiter is a rate-limit backend. key is already hashed.
type Limiter interface {
	Allow(ctx context.Context, key string, l Limit) (Result, error)
	// Backend is the backend name, as in ratelimit.backend.
	Backend() string
	Close() error
}

// Key hashes a class and an agent into a backend key.
func Key(class, agent string) string {
	sum := sha256.Sum256([]byte(class + "\x00" + agent))
	return class + ":" + hex.EncodeToString(sum[:12])
}

// gcra decides one request at now for a key whose stored theoretical
// arrival time is tat (zero for none). It returns the new tat to store when
// allowed.
func gcra(now, tat time.Time, l Limit) (Result, time.Time) {
	t := l.emission()
	if tat.Before(now) {
		tat = now
	}
	next := tat.Add(t)
	allowAt := next.Add(-t * time.Duration(l.burst()))
	if now.Before(allowAt) {
		return Result{RetryAfter: allowAt.Sub(now)}, time.Time{}
	}
	return Result{Allowed: true, Remaining: int(now.Sub(allowAt) / t)}, next
}

// Local is the in-process backend.
type Local struct {
	mu   sync.Mutex
	tats map[string]time.Time
	now  func() time.Time
	ops  int
}

// NewLocal returns an empty local limiter. now may be nil.
func NewLocal(now func() time.Time) *Local {
	if now == nil {
		now = time.Now
	}
	return &Local{tats: map[string]time.Time{}, now: now}
}

// Allow implements [Limiter].
func (b *Local) Allow(_ context.Context, key string, l Limit) (Result, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	r, next := gcra(now, b.tats[key], l)
	if r.Allowed {
		b.tats[key] = next
	}
	if b.ops++; b.ops >= 4096 {
		b.ops = 0
		for k, t := range b.tats {
			if t.Before(now) {
				delete(b.tats, k)
			}
		}
	}
	return r, nil
}

// Backend implements [Limiter].
func (*Local) Backend() string { return "local" }

// Close implements [Limiter].
func (*Local) Close() error { return nil }

// ErrLimited is wrapped by the error [Set.Check] returns for a refused
// request.
var ErrLimited = errors.New("rate limit exceeded")

// ErrUnavailable is wrapped by the error [Set.Check] returns when the
// backend could not decide; the request is refused.
var ErrUnavailable = errors.New("rate limiter unavailable")

// LimitedError is a refused request.
type LimitedError struct {
	Class      string
	RetryAfter time.Duration
}

func (e *LimitedError) Error() string {
	return fmt.Sprintf("%s rate limit exceeded; retry in %s", e.Class, e.RetryAfter.Round(time.Second))
}

// Unwrap makes errors.Is(err, ErrLimited) hold.
func (e *LimitedError) Unwrap() error { return ErrLimited }

// Observer records decisions; obs.Instruments implements it.
type Observer interface {
	RateLimit(backend, class, result string)
}

// Set applies the configured limit of each class through one backend. A
// nil *Set allows everything.
type Set struct {
	Limiter Limiter
	Limits  map[string]Limit
	Observe Observer
	mu      sync.RWMutex
}

// SetLimits replaces the limits (a configuration reload).
func (s *Set) SetLimits(l map[string]Limit) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Limits = l
}

// Check decides one request of class by agent: nil when allowed, a
// *LimitedError when refused, an error wrapping ErrUnavailable when the
// backend failed (also a refusal).
func (s *Set) Check(ctx context.Context, class, agent string) error {
	if s == nil || s.Limiter == nil {
		return nil
	}
	s.mu.RLock()
	l, ok := s.Limits[class]
	s.mu.RUnlock()
	if !ok || l.Off() {
		return nil
	}
	r, err := s.Limiter.Allow(ctx, Key(class, agent), l)
	result := "allowed"
	switch {
	case err != nil:
		result = "error"
	case !r.Allowed:
		result = "limited"
	}
	if s.Observe != nil {
		s.Observe.RateLimit(s.Limiter.Backend(), class, result)
	}
	if err != nil {
		return fmt.Errorf("%w: %s backend: %w", ErrUnavailable, s.Limiter.Backend(), err)
	}
	if !r.Allowed {
		return &LimitedError{Class: class, RetryAfter: r.RetryAfter}
	}
	return nil
}

// Close closes the backend.
func (s *Set) Close() error {
	if s == nil || s.Limiter == nil {
		return nil
	}
	return s.Limiter.Close()
}

// Opener builds a backend from its settings.
type Opener func(cfg *config.Config) (Limiter, error)

var (
	backendsMu sync.RWMutex
	backends   = map[string]Opener{"local": func(*config.Config) (Limiter, error) { return NewLocal(nil), nil }}
)

// RegisterBackend makes a backend available under name; it panics on a
// duplicate.
func RegisterBackend(name string, open Opener) {
	backendsMu.Lock()
	defer backendsMu.Unlock()
	if _, dup := backends[name]; dup {
		panic("ratelimit: backend " + name + " registered twice")
	}
	backends[name] = open
}

func backendNames() []string {
	backendsMu.RLock()
	defer backendsMu.RUnlock()
	out := make([]string, 0, len(backends))
	for k := range backends {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func opener(name string) (Opener, bool) {
	backendsMu.RLock()
	defer backendsMu.RUnlock()
	o, ok := backends[name]
	return o, ok
}
