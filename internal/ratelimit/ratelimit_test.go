// SPDX-License-Identifier: AGPL-3.0-only

package ratelimit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/ratelimit"
	"github.com/heliopsy/scrim/internal/ratelimit/ratelimittest"
)

func TestContractLocal(t *testing.T) {
	ratelimittest.Run(t, ratelimittest.Harness{New: func(*testing.T) (a, b ratelimit.Limiter) {
		return ratelimit.NewLocal(nil), ratelimit.NewLocal(nil)
	}})
}

type obsRec struct{ got []string }

func (o *obsRec) RateLimit(backend, class, result string) {
	o.got = append(o.got, backend+"/"+class+"/"+result)
}

type failing struct{}

func (failing) Allow(context.Context, string, ratelimit.Limit) (ratelimit.Result, error) {
	return ratelimit.Result{}, errors.New("down")
}
func (failing) Backend() string { return "failing" }
func (failing) Close() error    { return nil }

func TestSet(t *testing.T) {
	var nilSet *ratelimit.Set
	if err := nilSet.Check(t.Context(), ratelimit.ClassAsks, "a"); err != nil {
		t.Fatalf("nil set: %v", err)
	}
	o := &obsRec{}
	s := &ratelimit.Set{Limiter: ratelimit.NewLocal(nil), Observe: o, Limits: map[string]ratelimit.Limit{
		ratelimit.ClassAsks:     {Rate: 1, Interval: time.Hour, Burst: 1},
		ratelimit.ClassAgentAPI: {Rate: 0, Interval: time.Hour},
	}}
	if err := s.Check(t.Context(), ratelimit.ClassAsks, "a"); err != nil {
		t.Fatal(err)
	}
	err := s.Check(t.Context(), ratelimit.ClassAsks, "a")
	var le *ratelimit.LimitedError
	if !errors.As(err, &le) || !errors.Is(err, ratelimit.ErrLimited) || le.RetryAfter <= 0 {
		t.Fatalf("second ask: %v", err)
	}
	if err := s.Check(t.Context(), ratelimit.ClassAsks, "b"); err != nil {
		t.Fatalf("another agent: %v", err)
	}
	for range 10 {
		if err := s.Check(t.Context(), ratelimit.ClassAgentAPI, "a"); err != nil {
			t.Fatalf("disabled class: %v", err)
		}
	}
	s.Limiter = failing{}
	if err := s.Check(t.Context(), ratelimit.ClassAsks, "c"); !errors.Is(err, ratelimit.ErrUnavailable) {
		t.Fatalf("failing backend must refuse: %v", err)
	}
	want := []string{"local/asks/allowed", "local/asks/limited", "local/asks/allowed", "failing/asks/error"}
	if len(o.got) != len(want) {
		t.Fatalf("observed %v", o.got)
	}
	for i := range want {
		if o.got[i] != want[i] {
			t.Fatalf("observed %v, want %v", o.got, want)
		}
	}
}

func TestFromConfig(t *testing.T) {
	cfg, err := config.Load(config.Default, config.EnvLayer([]string{"SCRIM_RATELIMIT_ASKS_RATE=7", "SCRIM_RATELIMIT_ASKS_BURST=2"}))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ratelimit.FromConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Limiter.Backend() != "local" || s.Limits[ratelimit.ClassAsks] != (ratelimit.Limit{Rate: 7, Interval: time.Hour, Burst: 2}) {
		t.Fatalf("set = %s %+v", s.Limiter.Backend(), s.Limits)
	}
	if _, err := config.Load(config.Default, config.EnvLayer([]string{"SCRIM_RATELIMIT_BACKEND=redis"})); err == nil {
		t.Fatal("unknown backend accepted")
	}
}
