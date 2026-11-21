// SPDX-License-Identifier: AGPL-3.0-only

// Package ratelimittest is the contract every rate-limit backend passes
// (specs/state-and-scaling "Selectable rate-limit backend"): a burst is
// allowed and the next request refused with a retry time; the limit
// refills at its rate; keys are independent; concurrent callers never get
// more than the burst; and a shared backend enforces one limit across two
// replicas while a local one counts per replica.
package ratelimittest

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/ratelimit"
)

// Harness builds two limiters as two replicas would have them.
type Harness struct {
	// New returns two limiters; with Shared they count together.
	New    func(t *testing.T) (a, b ratelimit.Limiter)
	Shared bool
}

var seq atomic.Int64

func key(t *testing.T) string {
	return ratelimit.Key("test", fmt.Sprintf("%s-%d-%d", t.Name(), time.Now().UnixNano(), seq.Add(1)))
}

func allow(t *testing.T, l ratelimit.Limiter, k string, lim ratelimit.Limit) ratelimit.Result {
	t.Helper()
	r, err := l.Allow(context.Background(), k, lim)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Run runs the contract.
func Run(t *testing.T, h Harness) {
	// 10 per second: one request every 100ms, bursting to 5.
	lim := ratelimit.Limit{Rate: 10, Interval: time.Second, Burst: 5}

	t.Run("BurstThenRefused", func(t *testing.T) {
		a, _ := h.New(t)
		k := key(t)
		for i := range lim.Burst {
			r := allow(t, a, k, lim)
			if !r.Allowed {
				t.Fatalf("request %d of the burst refused", i+1)
			}
			if i == 0 && r.Remaining != lim.Burst-1 {
				t.Fatalf("remaining after the first request = %d, want %d", r.Remaining, lim.Burst-1)
			}
		}
		r := allow(t, a, k, lim)
		if r.Allowed {
			t.Fatal("request past the burst allowed")
		}
		if r.RetryAfter <= 0 || r.RetryAfter > 150*time.Millisecond {
			t.Fatalf("retry after %s, want within one emission interval (100ms)", r.RetryAfter)
		}
	})

	t.Run("RefillsAtRate", func(t *testing.T) {
		a, _ := h.New(t)
		k := key(t)
		for range lim.Burst {
			allow(t, a, k, lim)
		}
		r := allow(t, a, k, lim)
		if r.Allowed {
			t.Fatal("request past the burst allowed")
		}
		time.Sleep(r.RetryAfter + 20*time.Millisecond)
		if !allow(t, a, k, lim).Allowed {
			t.Fatal("refused after waiting the retry time")
		}
		if allow(t, a, k, lim).Allowed {
			t.Fatal("two requests allowed after waiting one emission interval")
		}
	})

	t.Run("KeysIndependent", func(t *testing.T) {
		a, _ := h.New(t)
		k1, k2 := key(t), key(t)
		for range lim.Burst {
			allow(t, a, k1, lim)
		}
		if allow(t, a, k1, lim).Allowed {
			t.Fatal("k1 past its burst allowed")
		}
		if !allow(t, a, k2, lim).Allowed {
			t.Fatal("k2 refused because k1 is exhausted")
		}
	})

	t.Run("ExactUnderConcurrency", func(t *testing.T) {
		a, b := h.New(t)
		ls := []ratelimit.Limiter{a}
		if h.Shared {
			ls = append(ls, b)
		}
		slow := ratelimit.Limit{Rate: 1, Interval: time.Hour, Burst: 20}
		k := key(t)
		var allowed atomic.Int64
		var wg sync.WaitGroup
		for g := range 8 {
			wg.Go(func() {
				for range 10 {
					r, err := ls[g%len(ls)].Allow(context.Background(), k, slow)
					if err != nil {
						t.Error(err)
						return
					}
					if r.Allowed {
						allowed.Add(1)
					}
				}
			})
		}
		wg.Wait()
		if got := allowed.Load(); got != int64(slow.Burst) {
			t.Fatalf("%d of 80 concurrent requests allowed, want exactly the burst of %d", got, slow.Burst)
		}
	})

	t.Run("AcrossReplicas", func(t *testing.T) {
		a, b := h.New(t)
		k := key(t)
		slow := ratelimit.Limit{Rate: 1, Interval: time.Hour, Burst: 5}
		for range 3 {
			if !allow(t, a, k, slow).Allowed {
				t.Fatal("refused within the burst on A")
			}
		}
		allowedOnB := 0
		for range 5 {
			if allow(t, b, k, slow).Allowed {
				allowedOnB++
			}
		}
		if h.Shared && allowedOnB != 2 {
			t.Fatalf("shared limit: B allowed %d after A used 3 of 5, want 2", allowedOnB)
		}
		if !h.Shared && allowedOnB != 5 {
			t.Fatalf("local limit: B allowed %d, want its own burst of 5", allowedOnB)
		}
	})
}
