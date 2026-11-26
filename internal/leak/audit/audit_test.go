// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/heliopsy/scrim/internal/fsperm/fspermtest"
	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

func TestPassThroughFailsAndReportHoldsNoValue(t *testing.T) {
	dir := t.TempDir()
	seedsPath := filepath.Join(dir, "seeds.json")
	rep, err := Run(context.Background(), Options{
		Proxy:    BuiltinPassThrough,
		SeedsOut: seedsPath,
		Rows:     []string{"anthropic-messages/tool-result/", "openai-chat/header/"},
	})
	if !errors.Is(err, ErrGate) || rep == nil || rep.Pass {
		t.Fatalf("pass-through: err=%v pass=%v", err, rep != nil && rep.Pass)
	}
	if rep.Summary.GatedLeaks == 0 || rep.Summary.ScenarioFailures == 0 {
		t.Fatalf("summary %+v", rep.Summary)
	}
	if runtime.GOOS == "windows" {
		fspermtest.Private(t, seedsPath)
	} else if fi, err := os.Stat(seedsPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("seed file: %v %v", fi, err)
	}
	seeds, err := leak.ReadSeedFile(seedsPath)
	if err != nil {
		t.Fatal(err)
	}
	var js bytes.Buffer
	if err := rep.WriteJSON("-", &js); err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	rep.WriteText(&text)
	if !json.Valid(js.Bytes()) {
		t.Fatal("report is not JSON")
	}
	for _, s := range seeds {
		esc, _ := json.Marshal(s.Value())
		for _, out := range []string{js.String(), text.String()} {
			if strings.Contains(out, s.Value()) || strings.Contains(out, string(esc[1:len(esc)-1])) {
				t.Fatalf("report contains the value of %s", s.Name)
			}
		}
	}
	if !strings.Contains(text.String(), "FAIL anthropic-messages/tool-result/raw") {
		t.Errorf("text report does not name the failing row:\n%s", text.String())
	}
}

func TestSeedsInAndNaiveRedactsRaw(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "seeds.json")
	if err := leak.WriteSeedFile(p, leak.GenerateSet(leak.KindGitHubToken, leak.KindPassword)); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), Options{
		Proxy: BuiltinNaive, SeedsIn: p, Suites: []string{SuiteMatrix},
		Rows: []string{"anthropic-messages/tool-result/raw", "openai-responses/user-text/raw"},
	})
	if err != nil {
		t.Fatalf("naive stub on raw rows: %v %+v", err, rep.Summary)
	}
	if !rep.Pass || len(rep.Seeds) != 2 || rep.Matrix.Totals.Cases != 4 {
		t.Fatalf("report %+v", rep.Summary)
	}
}

// TestWrapUpstream puts a front end before the fake provider: requests
// pass through it, results are still read from the fake.
func TestWrapUpstream(t *testing.T) {
	var seen atomic.Int32
	rep, err := Run(context.Background(), Options{
		Proxy: BuiltinNaive, Suites: []string{SuiteMatrix}, Rows: []string{"anthropic-messages/tool-result/raw"},
		WrapUpstream: func(s *fp.Server) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen.Add(1)
				s.ServeHTTP(w, r)
			})
		},
	})
	if err != nil || !rep.Pass {
		t.Fatalf("naive stub behind a front end: %v", err)
	}
	if n := int(seen.Load()); n == 0 || n != rep.Matrix.Totals.Cases {
		t.Errorf("the front end saw %d requests for %d cases", n, rep.Matrix.Totals.Cases)
	}
}

func TestBadOptions(t *testing.T) {
	for _, o := range []Options{{}, {Proxy: BuiltinNaive, Driver: "aider"}, {Proxy: BuiltinNaive, Suites: []string{"nope"}}} {
		if _, err := Run(context.Background(), o); err == nil || errors.Is(err, ErrGate) {
			t.Errorf("%+v: err %v", o, err)
		}
	}
	if _, err := Run(context.Background(), Options{Proxy: BuiltinNaive, Driver: "aider"}); err == nil ||
		!strings.Contains(err.Error(), "synthetic, claude, codex, opencode") {
		t.Errorf("unknown driver: %v", err)
	}
}

func TestParseRoutesGemini(t *testing.T) {
	m, err := ParseRoutes([]string{"gemini=/gemini/", "anthropic=anthropic"})
	if err != nil {
		t.Fatal(err)
	}
	if m[fp.Gemini] != "/gemini" || m[fp.Anthropic] != "/anthropic" {
		t.Errorf("routes %v", m)
	}
	if _, err := ParseAPI("vertex"); err == nil || !strings.Contains(err.Error(), "gemini") {
		t.Errorf("unknown api error does not list gemini: %v", err)
	}
}

// The WebSocket APIs parse by name and alias, run by default, and take the
// openai-responses route when they have none of their own.
func TestWebSocketAPIs(t *testing.T) {
	for in, want := range map[string]fp.API{"openai-realtime": fp.OpenAIRealtime, "realtime": fp.OpenAIRealtime, "openai-responses-ws": fp.OpenAIResponsesWS, "responses-ws": fp.OpenAIResponsesWS} {
		if got, err := ParseAPI(in); err != nil || got != want {
			t.Errorf("ParseAPI(%q) = %q, %v", in, got, err)
		}
	}
	var paths sync.Map
	rep, err := Run(context.Background(), Options{
		Proxy: BuiltinNaive, Suites: []string{SuiteMatrix, SuiteScenarios},
		APIs:   []fp.API{fp.OpenAIRealtime, fp.OpenAIResponsesWS},
		Rows:   []string{"openai-realtime/tool-result/raw", "openai-responses-ws/tool-result/raw"},
		Prefix: map[fp.API]string{fp.OpenAIResponses: "/openai"},
		WrapUpstream: func(s *fp.Server) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths.Store(r.URL.Path, true)
				s.ServeHTTP(w, r)
			})
		},
	})
	if err != nil || !rep.Pass {
		t.Fatalf("naive stub on WebSocket raw rows: %v %+v", err, rep.Summary)
	}
	if rep.Matrix.Totals.Rows != 2 || rep.Matrix.Totals.ByOutcome["redacted"] != rep.Matrix.Totals.Cases {
		t.Errorf("matrix %+v", rep.Matrix.Totals)
	}
	if len(rep.Scenarios.Results) != 0 {
		t.Errorf("scenarios ran on a WebSocket API: %d results", len(rep.Scenarios.Results))
	}
	for _, p := range []string{"/openai/v1/realtime", "/openai/v1/responses"} {
		if _, ok := paths.Load(p); !ok {
			t.Errorf("no request to %s", p)
		}
	}
}
