// SPDX-License-Identifier: AGPL-3.0-only

package redactscope

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// fakeReader: agent-a and agent-b have their own identity on store bao;
// agent-a cannot read kv/prod/*, agent-b can read everything, and checks
// of kv/broken fail.
type fakeReader struct {
	mu    sync.Mutex
	calls map[string]int
	deny  map[string]bool
}

func (f *fakeReader) ReadAgents(store string) []string {
	if store == "bao" {
		return []string{"agent-a", "agent-b"}
	}
	return nil
}

func (f *fakeReader) AgentCanRead(_ context.Context, agent string, ref stores.Ref) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[agent+" "+ref.String()]++
	if ref.Path == "kv/broken" {
		return false, errors.New("store unreachable")
	}
	return !f.deny[agent+" "+ref.Path], nil
}

func (f *fakeReader) count(k string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[k]
}

func values(t *testing.T) []Value {
	t.Helper()
	var out []Value
	for _, s := range []string{"bao://kv/prod/payments#key", "bao://kv/agents/a#key", "bao://kv/broken", "plain://x"} {
		r, err := stores.ParseRef(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, Value{Store: r.Scheme, Ref: r})
	}
	// A store's own credentials: never checked, never exempt.
	return append(out, Value{Store: "bao"})
}

// TestExemptOnlyWhatIsKnownUnreadable: nothing is exempt before a check;
// after one, only the pair the store refused; a failed check and an
// unknown store stay redacted; an answer older than the interval stops
// counting until it is checked again.
func TestExemptOnlyWhatIsKnownUnreadable(t *testing.T) {
	f := &fakeReader{calls: map[string]int{}, deny: map[string]bool{"agent-a kv/prod/payments": true}}
	var (
		changes atomic.Int32
		now     atomic.Int64
	)
	now.Store(time.Now().UnixNano())
	c := New(Options{Reader: f, OnChange: func() { changes.Add(1) },
		Now: func() time.Time { return time.Unix(0, now.Load()) }, Interval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()

	vs := values(t)
	if got := c.Exempt(vs); len(got) != 0 {
		t.Fatalf("exempt before any check: %v", got)
	}
	waitFor(t, func() bool {
		return f.count("agent-b bao://kv/broken") == 1 && f.count("agent-a bao://kv/prod/payments#key") == 1
	})
	waitFor(t, func() bool { return changes.Load() > 0 })
	got := c.Exempt(vs)
	if len(got) != 1 || !slices.Equal(got["agent-a"], []string{"bao://kv/prod/payments#key"}) {
		t.Fatalf("exempt = %v", got)
	}
	if f.count("agent-a plain://x") != 0 {
		t.Fatal("a store without per-agent identity was checked")
	}
	// Cached: no second check within the interval.
	if f.count("agent-a bao://kv/prod/payments#key") != 1 {
		t.Fatal("checked again within the interval")
	}
	// Past the interval the answer no longer counts and is checked again.
	now.Add(int64(2 * time.Hour))
	if got := c.Exempt(vs); len(got) != 0 {
		t.Fatalf("exempt after the interval: %v", got)
	}
	waitFor(t, func() bool { return f.count("agent-a bao://kv/prod/payments#key") == 2 })
	waitFor(t, func() bool { return len(c.Exempt(vs)) == 1 })
	cancel()
	<-done
}

func waitFor(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
