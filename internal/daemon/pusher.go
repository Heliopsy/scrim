// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"log/slog"
	"time"
)

// pushTarget is what the pusher drives; *dataplane.Supervisor implements it.
type pushTarget interface {
	Ready() bool
	Push(ctx context.Context) error
}

// pusher turns change notifications into debounced snapshot pushes. Trigger
// never blocks, so stores, the catalog, policy and configuration can call it
// from any goroutine; a burst of changes becomes one push. While the data
// plane is not ready the change is kept: the supervisor pushes a fresh
// snapshot on every (re)start, and the pusher pushes again once it is ready
// so nothing that changed during the start is lost.
type pusher struct {
	target   pushTarget
	debounce func() time.Duration
	log      *slog.Logger
	kick     chan struct{}
	// pushed is signalled after each successful push, for tests.
	pushed func()
}

func newPusher(t pushTarget, debounce func() time.Duration, log *slog.Logger) *pusher {
	return &pusher{target: t, debounce: debounce, log: log, kick: make(chan struct{}, 1)}
}

// Trigger asks for a push soon.
func (p *pusher) Trigger() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// Run pushes until ctx ends.
func (p *pusher) Run(ctx context.Context) {
	const notReadyPoll = 100 * time.Millisecond
	retry := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.kick:
		}
		if d := p.debounce(); d > 0 {
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		// Changes that arrive from here on are covered by this push only if
		// they land before the snapshot is built; a later kick pushes again.
		select {
		case <-p.kick:
		default:
		}
		for !p.target.Ready() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(notReadyPoll):
			}
		}
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := p.target.Push(pctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.log.Error("snapshot push failed; retrying", "err", err, "retry_in", retry)
			time.AfterFunc(retry, p.Trigger)
			retry = min(retry*2, 30*time.Second)
			continue
		}
		retry = time.Second
		if p.pushed != nil {
			p.pushed()
		}
	}
}
