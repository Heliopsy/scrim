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
	"os"
	"os/exec"
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

// agentBin finds an agent CLI for the driver tests: SCRIM_E2E_<AGENT> names
// the binary (CI installs pinned versions into a temporary directory), else
// it is looked up on PATH. A missing agent skips the test, or fails it when
// SCRIM_E2E_REQUIRE_TOOLS=1 (the e2e-agents CI job).
func agentBin(t *testing.T, agent string) string {
	t.Helper()
	if p := os.Getenv("SCRIM_E2E_" + strings.ToUpper(agent)); p != "" {
		return p
	}
	p, err := exec.LookPath(agent)
	if err == nil {
		return p
	}
	if os.Getenv("SCRIM_E2E_REQUIRE_TOOLS") == "1" {
		t.Fatalf("%s is not installed and SCRIM_E2E_REQUIRE_TOOLS is set", agent)
	}
	t.Skipf("%s is not installed (set SCRIM_E2E_%s)", agent, strings.ToUpper(agent))
	return ""
}

// Each real agent CLI, through the pass-through stand-in behind route
// prefixes: every session completes, runs every command (so the transforms
// reach the provider) and leaks. The real proxy's gate over the same
// sessions is `scrim audit run --driver <agent>` in the leak workflow.
func TestAgentDriversPassThrough(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the real agent CLIs")
	}
	for _, agent := range scenario.Agents {
		t.Run(agent, func(t *testing.T) {
			bin := agentBin(t, agent)
			fake := fp.New(fp.Options{})
			up := httptest.NewServer(fake)
			t.Cleanup(up.Close)
			u, _ := url.Parse(up.URL)
			px := httptest.NewServer(stub.PassThrough(u))
			t.Cleanup(px.Close)
			target := matrix.Target{BaseURL: px.URL, Prefix: map[fp.API]string{
				fp.Anthropic: "/anthropic", fp.OpenAIResponses: "/openai",
			}}
			seeds := leak.GenerateSet()
			for _, s := range scenario.AgentSessions {
				var out bytes.Buffer
				d := scenario.AgentDriver{Agent: agent, Bin: bin, Output: &out}
				res := d.Run(context.Background(), target, fake, leak.NewChecker(nil), s, seeds)
				if res.Error != "" {
					t.Fatalf("%s: %s\n%s", s.Name, res.Error, out.String())
				}
				if len(res.Findings) == 0 || res.Pass {
					t.Errorf("%s: pass-through not reported as a leak", s.Name)
				}
				want := map[string]string{"claude": "/anthropic/", "codex": "/openai/", "opencode": "/anthropic/"}[agent]
				for _, e := range fake.Exchanges() {
					if !strings.HasPrefix(e.Path, want) {
						t.Errorf("%s: request to %s, outside the route prefix", s.Name, e.Path)
					}
				}
				t.Logf("%s: api %s, %d requests, %d findings, cache %d/%d", s.Name, res.API, res.Requests, len(res.Findings), res.CacheHits, res.CacheTurns)
				if agent == "claude" && (res.CacheTurns == 0 || res.CacheHits != res.CacheTurns) {
					t.Errorf("%s: cache %d/%d", s.Name, res.CacheHits, res.CacheTurns)
				}
			}
		})
	}
}

func TestAgentDriverUnknown(t *testing.T) {
	res := scenario.AgentDriver{Agent: "nope"}.Run(context.Background(), matrix.Target{}, fp.New(fp.Options{}), leak.NewChecker(nil), scenario.AgentSessions[0], nil)
	if res.Pass || !strings.Contains(res.Error, "unknown agent") {
		t.Fatalf("unknown agent accepted: %+v", res)
	}
}
