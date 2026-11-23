// SPDX-License-Identifier: AGPL-3.0-only

// Package poll turns a listing into a change feed, for store adapters
// without native change notification (stores.Adapter.Watch).
//
// The adapter supplies a snapshot function that returns a fingerprint per
// secret path (version, update time, etag: metadata, never a value). Watch
// takes a baseline before it returns, so a change made right after the call
// is reported, then polls every interval with +-20% jitter and reports paths
// whose fingerprint changed, appeared or disappeared. Errors back off
// exponentially up to maxBackoff; the channel stays open through an outage
// and closes only when ctx ends.
package poll

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// Snapshot lists the secrets under the watched prefix: path to fingerprint.
type Snapshot func(ctx context.Context) (map[string]string, error)

// Watch starts polling. A first snapshot that fails with
// stores.ErrUnavailable still starts the watch (everything present is
// reported once the store answers); any other error is returned.
func Watch(ctx context.Context, scheme string, interval, maxBackoff time.Duration, snap Snapshot) (<-chan stores.Change, error) {
	base, err := snap(ctx)
	if err != nil && !errors.Is(err, stores.ErrUnavailable) {
		return nil, err
	}
	ch := make(chan stores.Change, 64)
	go run(ctx, scheme, interval, maxBackoff, snap, base, err == nil, ch)
	return ch, nil
}

// jitter is uniform in [0.8d, 1.2d).
func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

func run(ctx context.Context, scheme string, interval, maxBackoff time.Duration, snap Snapshot, prev map[string]string, haveBase bool, ch chan<- stores.Change) {
	defer close(ch)
	backoff := time.Duration(0)
	for {
		wait := jitter(interval)
		if backoff > 0 {
			wait = jitter(backoff)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		cur, err := snap(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if backoff == 0 {
				backoff = interval
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = 0
		if !haveBase {
			// No baseline yet (the store was down when Watch started):
			// everything present is reported once as changed.
			prev, haveBase = map[string]string{}, true
		}
		for path, v := range cur {
			if old, ok := prev[path]; !ok || old != v {
				if !send(ctx, ch, stores.Change{Ref: stores.Ref{Scheme: scheme, Path: path}, Kind: stores.Changed}) {
					return
				}
			}
		}
		for path := range prev {
			if _, ok := cur[path]; !ok {
				if !send(ctx, ch, stores.Change{Ref: stores.Ref{Scheme: scheme, Path: path}, Kind: stores.Deleted}) {
					return
				}
			}
		}
		prev = cur
	}
}

func send(ctx context.Context, ch chan<- stores.Change, c stores.Change) bool {
	select {
	case ch <- c:
		return true
	case <-ctx.Done():
		return false
	}
}
