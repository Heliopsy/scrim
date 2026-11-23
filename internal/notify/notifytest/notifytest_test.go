// SPDX-License-Identifier: AGPL-3.0-only

package notifytest_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/notify/notifytest"
)

// fake is a notifier whose far end is a slice, with switches that break one
// behaviour each.
type fake struct {
	failing atomic.Bool
	mu      sync.Mutex
	inbox   []notifytest.Delivery

	dropDeny        bool // delivers without the deny link
	lie             bool // reports success without delivering
	leakLink        bool // puts the approve link in its error
	swallowFailures bool // reports success while failing
	noName          bool
}

func (f *fake) Name() string {
	if f.noName {
		return ""
	}
	return "fake"
}

func (f *fake) Notify(ctx context.Context, r notify.Request) error {
	if f.failing.Load() {
		if f.swallowFailures {
			return nil
		}
		if f.leakLink {
			return fmt.Errorf("fake: posting %s failed", r.ApproveURL)
		}
		return errors.New("fake: channel down")
	}
	if f.lie {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("fake: %w", ctx.Err())
	}
	d := notifytest.FromRequest(r)
	if f.dropDeny {
		d.DenyURL = ""
	}
	f.mu.Lock()
	f.inbox = append(f.inbox, d)
	f.mu.Unlock()
	return nil
}

func harness(f *fake) notifytest.Factory {
	return func(notifytest.TB) notifytest.Harness {
		return notifytest.Harness{
			Notifier: f,
			Delivered: func(notifytest.TB) []notifytest.Delivery {
				f.mu.Lock()
				defer f.mu.Unlock()
				return append([]notifytest.Delivery(nil), f.inbox...)
			},
			Fail: func(notifytest.TB) func() {
				f.failing.Store(true)
				return func() { f.failing.Store(false) }
			},
		}
	}
}

func TestFakePasses(t *testing.T) { notifytest.Run(t, harness(&fake{})) }

func TestRecorderPasses(t *testing.T) {
	notifytest.Run(t, func(notifytest.TB) notifytest.Harness {
		r := &notify.Recorder{NotifierName: "recorder"}
		return notifytest.Harness{
			Notifier: r,
			Delivered: func(notifytest.TB) []notifytest.Delivery {
				var out []notifytest.Delivery
				for _, req := range r.Sent() {
					out = append(out, notifytest.FromRequest(req))
				}
				return out
			},
		}
	})
}

type recorder struct {
	ctx      context.Context
	mu       sync.Mutex
	failures []string
	cleanups []func()
}

func (r *recorder) Helper()                  {}
func (r *recorder) Context() context.Context { return r.ctx }
func (r *recorder) Cleanup(f func())         { r.cleanups = append(r.cleanups, f) }
func (r *recorder) Errorf(format string, args ...any) {
	r.mu.Lock()
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
	r.mu.Unlock()
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	runtime.Goexit()
}

func run(t *testing.T, f notifytest.Factory, name string) []string {
	t.Helper()
	var c notifytest.Case
	for _, x := range notifytest.Cases() {
		if x.Name == name {
			c = x
		}
	}
	if c.Run == nil {
		t.Fatalf("no case %s", name)
	}
	r := &recorder{ctx: t.Context()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		notifytest.Check(r, f, c)
	}()
	<-done
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
	}
	return r.failures
}

// Each broken notifier fails the case aimed at it.
func TestSuiteCatchesBrokenNotifiers(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *fake
		cs   string
	}{
		{"no name", &fake{noName: true}, "Name"},
		{"drops the deny link", &fake{dropDeny: true}, "Delivers"},
		{"lies about delivery", &fake{lie: true}, "Delivers"},
		{"lies with a cancelled context", &fake{lie: true}, "SuccessMeansDelivered"},
		{"leaks a decision link", &fake{leakLink: true}, "FailureIsAnError"},
		{"swallows failures", &fake{swallowFailures: true}, "FailureIsAnError"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(t, harness(tc.f), tc.cs); len(got) == 0 {
				t.Fatalf("case %s passed a notifier that %s", tc.cs, tc.name)
			}
		})
	}
}
