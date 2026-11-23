// SPDX-License-Identifier: AGPL-3.0-only

package poll

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

type source struct {
	mu   sync.Mutex
	m    map[string]string
	fail error
}

func (s *source) snap(context.Context) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	return maps.Clone(s.m), nil
}

func (s *source) set(fn func()) {
	s.mu.Lock()
	fn()
	s.mu.Unlock()
}

func next(t *testing.T, ch <-chan stores.Change) stores.Change {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no change")
	}
	return stores.Change{}
}

func TestChanges(t *testing.T) {
	src := &source{m: map[string]string{"a": "1"}}
	ctx, cancel := context.WithCancel(t.Context())
	ch, err := Watch(ctx, "s", 10*time.Millisecond, 50*time.Millisecond, src.snap)
	if err != nil {
		t.Fatal(err)
	}
	src.set(func() { src.m["a"] = "2" })
	if c := next(t, ch); c.Ref != (stores.Ref{Scheme: "s", Path: "a"}) || c.Kind != stores.Changed {
		t.Errorf("got %v", c)
	}
	src.set(func() { src.fail = stores.ErrUnavailable })
	time.Sleep(30 * time.Millisecond)
	src.set(func() { src.fail = nil; delete(src.m, "a") })
	if c := next(t, ch); c.Ref.Path != "a" || c.Kind != stores.Deleted {
		t.Errorf("got %v", c)
	}
	cancel()
	for range ch {
	}
}

func TestStartsDuringOutage(t *testing.T) {
	src := &source{m: map[string]string{"a": "1"}, fail: stores.ErrUnavailable}
	ch, err := Watch(t.Context(), "s", 10*time.Millisecond, 20*time.Millisecond, src.snap)
	if err != nil {
		t.Fatal(err)
	}
	src.set(func() { src.fail = nil })
	if c := next(t, ch); c.Ref.Path != "a" || c.Kind != stores.Changed {
		t.Errorf("got %v", c)
	}
	other := errors.New("bad prefix")
	if _, err := Watch(t.Context(), "s", time.Second, time.Second, func(context.Context) (map[string]string, error) { return nil, other }); !errors.Is(err, other) {
		t.Errorf("Watch with a failing first listing: %v", err)
	}
}
