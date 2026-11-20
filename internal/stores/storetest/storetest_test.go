// SPDX-License-Identifier: AGPL-3.0-only

package storetest_test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// recorder is a storetest.TB that records failures instead of failing.
type recorder struct {
	ctx      context.Context
	mu       sync.Mutex
	failures []string
	cleanups []func()
}

func (r *recorder) Helper()                        {}
func (r *recorder) Context() context.Context       { return r.ctx }
func (r *recorder) Cleanup(f func())               { r.cleanups = append(r.cleanups, f) }
func (r *recorder) Errorf(format string, a ...any) { r.add(fmt.Sprintf(format, a...)) }
func (r *recorder) Fatalf(format string, a ...any) {
	r.add(fmt.Sprintf(format, a...))
	runtime.Goexit()
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, s)
}

// runCases runs every case against f and returns the failures per case.
func runCases(t *testing.T, f storetest.Factory) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, c := range storetest.Cases() {
		r := &recorder{ctx: t.Context()}
		done := make(chan struct{})
		go func() {
			defer close(done)
			h := storetest.Prepare(r, f)
			c.Run(r, h)
		}()
		<-done
		for i := len(r.cleanups) - 1; i >= 0; i-- {
			r.cleanups[i]()
		}
		out[c.Name] = r.failures
	}
	return out
}

// leaky echoes the reference's secret value in its errors, as a store
// client that includes the request body in error messages would.
type leaky struct{ *memstore.Store }

func (l leaky) Write(ctx context.Context, ref stores.Ref, f map[string]secret.Value, o stores.WriteOptions) (stores.Metadata, error) {
	m, err := l.Store.Write(ctx, ref, f, o)
	if err != nil {
		var text string
		_ = f["value"].Expose(func(b []byte) error { text = string(b); return nil })
		return m, fmt.Errorf("rejected body {\"value\":%q}: %w", text, err)
	}
	return m, nil
}

// wrongKind reports a missing secret as an outage.
type wrongKind struct{ *memstore.Store }

func (w wrongKind) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	s, err := w.Store.Read(ctx, ref)
	if err != nil {
		return s, stores.NewError(w.Name(), stores.OpRead, ref, stores.ErrUnavailable, nil)
	}
	return s, nil
}

func TestSuiteCatchesBrokenAdapters(t *testing.T) {
	cases := map[string]struct {
		adapter func() stores.Adapter
		failing string
	}{
		"value in error": {func() stores.Adapter { return leaky{memstore.New("mem")} }, "WriteCreateOnly"},
		"wrong kind":     {func() stores.Adapter { return wrongKind{memstore.New("mem")} }, "ReadMissing"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := runCases(t, func(storetest.TB) storetest.Harness { return storetest.Harness{Adapter: tc.adapter()} })
			if len(res[tc.failing]) == 0 {
				t.Fatalf("case %s passed against a broken adapter; results: %v", tc.failing, res)
			}
		})
	}
}

func TestSuitePassesReferenceAdapter(t *testing.T) {
	res := runCases(t, func(storetest.TB) storetest.Harness { return storetest.Harness{Adapter: memstore.New("mem")} })
	for name, f := range res {
		if len(f) > 0 {
			t.Errorf("%s: %v", name, f)
		}
	}
}
