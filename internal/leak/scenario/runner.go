// SPDX-License-Identifier: AGPL-3.0-only

package scenario

import (
	"bytes"
	"context"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/matrix"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// Result is the outcome of one scenario on one API.
type Result struct {
	Scenario string         `json:"scenario"`
	API      fp.API         `json:"api"`
	Stream   bool           `json:"stream"`
	Requests int            `json:"requests"`
	Findings []leak.Finding `json:"findings,omitempty"`
	// Cache: every request after the first should find the previous
	// request's whole prompt in the provider's prefix cache.
	CacheTurns     int     `json:"cache_turns"`
	CacheHits      int     `json:"cache_hits"`
	CacheableBytes int     `json:"cacheable_bytes"`
	CachedBytes    int     `json:"cached_bytes"`
	CacheHitRate   float64 `json:"cache_hit_rate"`
	// Deterministic is true when replaying the session produced
	// byte-identical requests.
	Deterministic bool `json:"deterministic"`
	// Restored counts tool calls in which the agent received a real value.
	Restored int    `json:"restored_tool_calls"`
	Error    string `json:"error,omitempty"`
	Pass     bool   `json:"pass"`
}

// Runner runs scenarios. It needs the fake provider in process, because each
// scenario scripts its replies.
type Runner struct {
	Target  matrix.Target
	Fake    *fp.Server
	Checker *leak.Checker
}

// Run plays a scenario twice on one API and checks what the fake received.
func (r *Runner) Run(ctx context.Context, sc Scenario, api fp.API, stream bool, seeds []leak.Seed) Result {
	res := Result{Scenario: sc.Name, API: api, Stream: stream}
	r.Fake.Reset()
	r.Fake.SetResponder(fp.Script(sc.script()))
	defer r.Fake.SetResponder(nil)

	first := runSession(ctx, r.Target, sc, api, stream, seeds)
	ex1 := r.Fake.Exchanges()
	second := runSession(ctx, r.Target, sc, api, stream, seeds)
	all := r.Fake.Exchanges()
	ex2 := all[len(ex1):]

	res.Requests = first.requests
	res.Restored = first.restored
	if first.err != nil {
		res.Error = first.err.Error()
	} else if second.err != nil {
		res.Error = "replay: " + second.err.Error()
	}

	checker := r.Checker
	if checker == nil {
		checker = leak.NewChecker(seeds)
	} else {
		checker = checker.WithSeeds(seeds)
	}
	for _, e := range all {
		res.Findings = append(res.Findings, checker.Check(e.Capture)...)
	}

	for i := 1; i < len(ex1); i++ {
		res.CacheTurns++
		want := ex1[i-1].PromptBytes
		got := min(ex1[i].CachedBytes, want)
		res.CacheableBytes += want
		res.CachedBytes += got
		if got >= want {
			res.CacheHits++
		}
	}
	if res.CacheableBytes > 0 {
		res.CacheHitRate = float64(res.CachedBytes) / float64(res.CacheableBytes)
	}

	res.Deterministic = len(ex1) == len(ex2) && len(ex1) > 0
	for i := 0; res.Deterministic && i < len(ex1); i++ {
		if !bytes.Equal(ex1[i].Body, ex2[i].Body) {
			res.Deterministic = false
		}
	}
	res.Pass = res.Error == "" && len(res.Findings) == 0 && res.Deterministic && res.CacheHits == res.CacheTurns
	return res
}

// RunAll runs every scenario on every API, streaming and not.
func (r *Runner) RunAll(ctx context.Context, scs []Scenario, apis []fp.API, seeds []leak.Seed, progress func(Result)) []Result {
	var out []Result
	for _, sc := range scs {
		for _, api := range apis {
			for _, stream := range []bool{false, true} {
				if ctx.Err() != nil {
					return out
				}
				res := r.Run(ctx, sc, api, stream, seeds)
				out = append(out, res)
				if progress != nil {
					progress(res)
				}
			}
		}
	}
	return out
}

// CacheSummary aggregates cache figures over results.
type CacheSummary struct {
	Turns          int     `json:"turns"`
	Hits           int     `json:"hits"`
	CacheableBytes int     `json:"cacheable_bytes"`
	CachedBytes    int     `json:"cached_bytes"`
	HitRate        float64 `json:"hit_rate"`
	Deterministic  int     `json:"deterministic_sessions"`
	Sessions       int     `json:"sessions"`
}

// Cache aggregates cache figures over results.
func Cache(results []Result) CacheSummary {
	var c CacheSummary
	for _, r := range results {
		c.Turns += r.CacheTurns
		c.Hits += r.CacheHits
		c.CacheableBytes += r.CacheableBytes
		c.CachedBytes += r.CachedBytes
		c.Sessions++
		if r.Deterministic {
			c.Deterministic++
		}
	}
	if c.CacheableBytes > 0 {
		c.HitRate = float64(c.CachedBytes) / float64(c.CacheableBytes)
	}
	return c
}
