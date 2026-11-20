// SPDX-License-Identifier: AGPL-3.0-only

package scenario_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/matrix"
	"github.com/heliopsy/scrim/internal/leak/scenario"
	"github.com/heliopsy/scrim/internal/leak/stub"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

func runner(t *testing.T, proxy func(*url.URL) *httptest.Server) *scenario.Runner {
	t.Helper()
	fake := fp.New(fp.Options{})
	up := httptest.NewServer(fake)
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	px := proxy(u)
	t.Cleanup(px.Close)
	return &scenario.Runner{Target: matrix.Target{BaseURL: px.URL}, Fake: fake}
}

func TestCorpusRenders(t *testing.T) {
	scs, err := scenario.Corpus()
	if err != nil {
		t.Fatal(err)
	}
	if len(scs) < 8 {
		t.Fatalf("corpus has %d scenarios", len(scs))
	}
	seeds := leak.GenerateSet()
	byKind := map[leak.Kind]leak.Seed{}
	for _, s := range seeds {
		byKind[s.Kind] = s
	}
	for _, sc := range scs {
		for _, st := range append([]scenario.Step{{Output: sc.Prompt}}, sc.Steps...) {
			out, err := scenario.Render(st.Output, byKind)
			if err != nil {
				t.Errorf("%s: %v", sc.Name, err)
			}
			if strings.Contains(out, "{{secret") {
				t.Errorf("%s: unrendered slot", sc.Name)
			}
		}
	}
}

// Through a pass-through proxy every scenario leaks, is deterministic and
// keeps the cache: this proves the scenarios carry secrets and that the cache
// measurement works.
func TestScenariosPassThrough(t *testing.T) {
	r := runner(t, func(u *url.URL) *httptest.Server { return httptest.NewServer(stub.PassThrough(u)) })
	scs, _ := scenario.Corpus()
	results := r.RunAll(context.Background(), scs, fp.APIs, leak.GenerateSet(), nil)
	for _, res := range results {
		if res.Error != "" {
			t.Errorf("%s/%s: %s", res.Scenario, res.API, res.Error)
		}
		if len(res.Findings) == 0 || res.Pass {
			t.Errorf("%s/%s stream=%v: pass-through not reported as a leak", res.Scenario, res.API, res.Stream)
		}
		if !res.Deterministic || res.CacheHits != res.CacheTurns || res.CacheTurns == 0 {
			t.Errorf("%s/%s stream=%v: deterministic=%v cache %d/%d", res.Scenario, res.API, res.Stream, res.Deterministic, res.CacheHits, res.CacheTurns)
		}
	}
	if c := scenario.Cache(results); c.HitRate != 1 {
		t.Errorf("pass-through cache hit rate %.3f", c.HitRate)
	}
}

// The naive stub redacts verbatim values, so verbatim scenarios are clean,
// while the Kubernetes secret (base64 values) still leaks.
func TestScenariosNaive(t *testing.T) {
	seeds := leak.GenerateSet()
	r := runner(t, func(u *url.URL) *httptest.Server { return httptest.NewServer(stub.Naive(u, seeds)) })
	scs, _ := scenario.Corpus()
	results := r.RunAll(context.Background(), scs, []fp.API{fp.Anthropic}, seeds, nil)
	for _, res := range results {
		switch res.Scenario {
		case "kubectl-secret", "error-log":
			if len(res.Findings) == 0 {
				t.Errorf("%s: encoded values should leak through the naive stub", res.Scenario)
			}
		case "curl-verbose", "dotenv-read":
			if !res.Pass {
				t.Errorf("%s stream=%v: %+v", res.Scenario, res.Stream, res)
			}
			// The fake echoes a placeholder into a tool call; the naive stub
			// restores it, so the agent saw a real value, which the next
			// request must carry redacted again (the session passing proves
			// it was).
			if !res.Stream && res.Restored == 0 {
				t.Errorf("%s: no value was restored into a tool call", res.Scenario)
			}
		}
	}
}

// A proxy whose output varies between requests breaks prompt caching; the
// runner must report it.
func TestUnstableProxyBreaksCache(t *testing.T) {
	n := 0
	r := runner(t, func(u *url.URL) *httptest.Server {
		pass := stub.PassThrough(u)
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(req.Body)
			n++
			b = bytes.Replace(b, []byte("You are a coding agent."), []byte(fmt.Sprintf("You are agent %06d.", n)), 1)
			req.Body = io.NopCloser(bytes.NewReader(b))
			req.ContentLength = int64(len(b))
			pass.ServeHTTP(w, req)
		}))
	})
	scs, _ := scenario.Corpus()
	res := r.Run(context.Background(), scs[0], fp.Anthropic, false, leak.GenerateSet())
	if res.Deterministic || res.CacheHits == res.CacheTurns || res.Pass {
		t.Fatalf("unstable proxy not reported: %+v", res)
	}
}
