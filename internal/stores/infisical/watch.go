// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// Watch implements stores.Adapter. Infisical has no change feed in the
// self-hosted free edition, so the adapter polls the listing (names and
// versions only, never values) every watch.interval with +-20% jitter and
// reports what changed. Errors back off exponentially up to
// watch.max-backoff; the channel stays open through an outage and closes
// only when ctx ends.
func (a *Adapter) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	if _, ok := splitPrefix(prefix.Path); !ok {
		return nil, a.invalid(stores.OpWatch, prefix, "want <project>/<environment>[/<folder>...]")
	}
	// The baseline is taken before Watch returns, so a change made right
	// after the call is reported.
	base, err := a.snapshot(ctx, prefix)
	if err != nil && !errors.Is(err, stores.ErrUnavailable) {
		return nil, err
	}
	ch := make(chan stores.Change, 64)
	go a.poll(ctx, prefix, base, err == nil, ch)
	return ch, nil
}

func (a *Adapter) snapshot(ctx context.Context, prefix stores.Ref) (map[string]string, error) {
	ms, err := a.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(ms))
	for _, m := range ms {
		out[m.Ref.Path] = m.Version + "@" + m.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out, nil
}

func jitter(d time.Duration) time.Duration {
	// Uniform in [0.8d, 1.2d).
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

func (a *Adapter) poll(ctx context.Context, prefix stores.Ref, prev map[string]string, haveBase bool, ch chan<- stores.Change) {
	defer close(ch)
	backoff := time.Duration(0)
	for {
		wait := jitter(a.s.watchInterval)
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
		cur, err := a.snapshot(ctx, prefix)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if backoff == 0 {
				backoff = a.s.watchInterval
			}
			backoff = min(backoff*2, a.s.watchBackoff)
			continue
		}
		backoff = 0
		if !haveBase {
			// No baseline yet (the store was down when Watch started):
			// everything present is reported once as changed, so the
			// consumer reloads it.
			prev, haveBase = map[string]string{}, true
		}
		for path, v := range cur {
			if old, ok := prev[path]; !ok || old != v {
				if !send(ctx, ch, stores.Change{Ref: stores.Ref{Scheme: prefix.Scheme, Path: path}, Kind: stores.Changed}) {
					return
				}
			}
		}
		for path := range prev {
			if _, ok := cur[path]; !ok {
				if !send(ctx, ch, stores.Change{Ref: stores.Ref{Scheme: prefix.Scheme, Path: path}, Kind: stores.Deleted}) {
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
