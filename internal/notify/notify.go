// SPDX-License-Identifier: AGPL-3.0-only

// Package notify is the contract for approval notifiers (specs/
// policy-approvals "Notifiers"): ntfy, Telegram, webhook, terminal, tix.
//
// A notifier only delivers. Decisions come back through scrim's own
// single-use signed links or `scrim approve`, never through the notifier's
// return value, so a notifier failure can never approve anything.
package notify

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/policy"
)

// Request is what a notifier shows a human. It holds no value and no
// unredacted request body.
type Request struct {
	ApprovalID string
	Agent      policy.Agent
	// Summary is the policy request: action, reference, destination, tool.
	Summary   policy.Request
	Rule      string
	Reason    string
	ExpiresAt time.Time
	// ApproveURL and DenyURL are single-use signed decision links; empty
	// when the decision page is not reachable from the notifier.
	ApproveURL string
	DenyURL    string
}

// Notifier delivers approval requests.
type Notifier interface {
	// Name is the instance name from configuration.
	Name() string
	// Notify delivers r. It must return promptly; retries are the
	// notifier's own business within ctx.
	Notify(ctx context.Context, r Request) error
}

// Multi delivers to every notifier and succeeds if at least one did, so one
// broken channel does not strand an approval. All failures are returned
// joined when none succeeded.
type Multi []Notifier

// Name implements [Notifier].
func (Multi) Name() string { return "multi" }

// Notify implements [Notifier].
func (m Multi) Notify(ctx context.Context, r Request) error {
	if len(m) == 0 {
		return errors.New("notify: no notifier configured")
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for _, n := range m {
		wg.Go(func() {
			if err := n.Notify(ctx, r); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("notifier %s: %w", n.Name(), err))
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(errs) == len(m) {
		return errors.Join(errs...)
	}
	return nil
}

// Recorder is a notifier that keeps what it was sent, for tests.
type Recorder struct {
	NotifierName string
	// Fail, if set, is returned by Notify after recording.
	Fail error
	mu   sync.Mutex
	sent []Request
}

// Name implements [Notifier].
func (r *Recorder) Name() string {
	if r.NotifierName == "" {
		return "recorder"
	}
	return r.NotifierName
}

// Notify implements [Notifier].
func (r *Recorder) Notify(_ context.Context, req Request) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, req)
	return r.Fail
}

// Sent returns a copy of what was delivered.
func (r *Recorder) Sent() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Request(nil), r.sent...)
}
