// SPDX-License-Identifier: AGPL-3.0-only

package agenttools_test

import (
	"context"
	"errors"
	"testing"
	"time"

	at "github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/ratelimit"
)

type brokenLimiter struct{}

func (brokenLimiter) Allow(context.Context, string, ratelimit.Limit) (ratelimit.Result, error) {
	return ratelimit.Result{}, errors.New("valkey: connection refused")
}
func (brokenLimiter) Backend() string { return "broken" }
func (brokenLimiter) Close() error    { return nil }

// TestRateLimits: the agent API limit refuses an agent's calls past its
// burst with rate_limited and an audit entry, other agents are unaffected;
// secret_ask_human has its own limit; a limiter that cannot answer refuses.
func TestRateLimits(t *testing.T) {
	e := env(t)
	limits := &ratelimit.Set{Limiter: ratelimit.NewLocal(nil), Limits: map[string]ratelimit.Limit{
		ratelimit.ClassAgentAPI: {Rate: 1, Interval: time.Hour, Burst: 3},
		ratelimit.ClassAsks:     {Rate: 1, Interval: time.Hour, Burst: 1},
	}}
	svc, err := at.New(at.Deps{Policy: e.Policy, Approvals: e.Approvals, Catalog: e.Store, Store: e.Store, Auditor: e.Audit,
		Notifier: e.Notifier, Links: agenttoolstest.Links{Base: "http://127.0.0.1:1"}, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	dev, other := agenttoolstest.Agent("dev", 1000), agenttoolstest.Agent("other", 1001)
	for i := range 3 {
		if _, err := svc.List(ctx, dev, at.ListInput{}); err != nil {
			t.Fatalf("call %d within the burst: %v", i, err)
		}
	}
	_, err = svc.List(ctx, dev, at.ListInput{})
	if code(t, err) != at.CodeRateLimited {
		t.Fatalf("call past the burst: %v", err)
	}
	if last := e.Audit.Last(); last.Outcome != at.OutcomeRefused || last.Detail != string(at.CodeRateLimited) {
		t.Fatalf("audit = %+v", last)
	}
	if _, err := svc.List(ctx, other, at.ListInput{}); err != nil {
		t.Fatalf("another agent was limited: %v", err)
	}

	// Asks: one per hour for "other"; the second is refused before any
	// human is notified.
	limits.SetLimits(map[string]ratelimit.Limit{ratelimit.ClassAsks: {Rate: 1, Interval: time.Hour, Burst: 1}})
	if _, err := svc.Ask(ctx, other, at.AskInput{Ref: "bao://kv/agents/a1", Prompt: "token"}); err != nil {
		t.Fatalf("first ask: %v", err)
	}
	notices := len(e.Notifier.Notices)
	if _, err := svc.Ask(ctx, other, at.AskInput{Ref: "bao://kv/agents/a2", Prompt: "token"}); code(t, err) != at.CodeRateLimited {
		t.Fatalf("second ask: %v", err)
	}
	if len(e.Notifier.Notices) != notices {
		t.Fatal("a rate-limited ask still notified a human")
	}

	limits.Limiter = brokenLimiter{}
	limits.SetLimits(map[string]ratelimit.Limit{ratelimit.ClassAgentAPI: {Rate: 1, Interval: time.Hour, Burst: 100}})
	if _, err := svc.List(ctx, other, at.ListInput{}); code(t, err) != at.CodeUnavailable {
		t.Fatalf("an unavailable limiter must refuse: %v", err)
	}
}
