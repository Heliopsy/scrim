// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/leak/scenario"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// opencodeWhoami is the URL OpenCode's webfetch tool fetches: OpenCode's
// own HTTPS through scrim's forward proxy, trusting the session CA.
const opencodeWhoami = "https://" + harness.APIHost + "/v1/whoami"

// opencodeModel plays the model for OpenCode over the Messages API: one bash
// call per step, scrim's secrets_list through MCP, a webfetch, then done.
func opencodeModel(t fp.Turn) fp.Reply {
	tools := scenario.ToolNames(t.Body)
	if len(tools) == 0 {
		return fp.Reply{Text: "scrim e2e session"}
	}
	switch n := t.ToolResults; {
	case n < len(steps):
		return fp.Reply{Text: steps[n].why + ".", ToolCalls: []fp.ToolCall{{Name: "bash",
			Input: map[string]any{"command": steps[n].command, "description": steps[n].why}}}}
	case n == len(steps):
		// OpenCode names an MCP tool <server>_<tool>.
		i := slices.IndexFunc(tools, func(name string) bool {
			return strings.HasPrefix(name, "scrim") && strings.HasSuffix(name, "secrets_list")
		})
		if i < 0 {
			return fp.Reply{Text: "no scrim MCP tool offered: " + strings.Join(tools, ",")}
		}
		return fp.Reply{Text: "Listing the secrets scrim offers.", ToolCalls: []fp.ToolCall{{Name: tools[i], Input: map[string]any{}}}}
	case n == len(steps)+1:
		return fp.Reply{Text: "Fetching the API.", ToolCalls: []fp.ToolCall{{Name: "webfetch",
			Input: map[string]any{"url": opencodeWhoami, "format": "text"}}}}
	}
	return fp.Reply{Text: "Done."}
}

// TestOpenCodeSession is TestClaudeCodeSession for OpenCode: `opencode run`
// under `scrim run`, on its anthropic provider, which the opencode preset
// points at scrim's LLM proxy with the session header. A policy rule denies
// every provider request that does not come from the session, so the run
// only completes when OpenCode sends the header. SCRIM_E2E_OPENCODE names
// the opencode binary (the native one from the opencode-ai npm package);
// otherwise it is looked up on PATH.
func TestOpenCodeSession(t *testing.T) {
	s, _ := runOpenCode(t, "anthropic/claude-sonnet-4-6", "ANTHROPIC_API_KEY")

	var main []fp.Exchange
	for _, e := range s.checkLeaks(t) {
		if e.API != fp.Anthropic || e.Path != "/v1/messages" {
			t.Errorf("not a Messages request through the anthropic route: %s %s", e.API, e.Path)
		}
		if e.Header.Get("X-Scrim-Session") != "" {
			t.Errorf("the session header reached the provider")
		}
		if len(scenario.ToolNames(decode(t, e.Body))) > 0 {
			main = append(main, e)
		}
	}
	if len(main) < len(steps)+3 {
		t.Fatalf("%d tool-enabled requests, want %d", len(main), len(steps)+3)
	}
	results := toolResults(t, main[len(main)-1].Body)
	if len(results) < len(steps)+2 {
		t.Fatalf("%d tool results reached the model, want %d", len(results), len(steps)+2)
	}
	for i, r := range results {
		t.Logf("tool result %d as the model saw it: %.160q", i, r)
	}
	for i, st := range steps {
		if !fp.DefaultPlaceholderPattern.MatchString(results[i]) && !strings.Contains(results[i], "SCRIM_API_TOKEN") {
			t.Errorf("result of %q reached the model without placeholders: %.300s", st.command, results[i])
		}
	}
	if !strings.Contains(results[3], "deploy-bot") {
		t.Errorf("the tool API call failed: %.300s", results[3])
	}
	if !strings.Contains(results[len(steps)], "e2e://tools/") {
		t.Errorf("the MCP result did not reach the model: %.300s", results[len(steps)])
	}
	// webfetch sends no credential: the API answers 401, which is what
	// shows OpenCode reached it through the forward proxy and trusted the
	// session CA.
	if !strings.Contains(results[len(steps)+1], "bad token") && !strings.Contains(results[len(steps)+1], "401") {
		t.Errorf("OpenCode's webfetch did not reach the API: %.300s", results[len(steps)+1])
	}
	s.mu.Lock()
	auth := slices.Clone(s.apiAuth)
	s.mu.Unlock()
	if len(auth) != 2 || auth[0] != "Bearer "+s.token.Value() || auth[1] != "" {
		t.Errorf("the tool API saw %d requests, want the curl with the real token, then webfetch without one", len(auth))
	}
}

// runOpenCode runs the session with `opencode run -m model` under scrim
// run, with a fake key in keyVar, and checks it completed.
func runOpenCode(t *testing.T, model, keyVar string) (*session, harness.Result) {
	t.Helper()
	bin := harness.Require(t)
	opencode := os.Getenv("SCRIM_E2E_OPENCODE")
	if opencode == "" {
		opencode = harness.LookPath(t, "opencode")
	}
	// Run it as `opencode` so scrim run picks the OpenCode preset by name.
	if filepath.Base(opencode) != "opencode" {
		t.Fatalf("SCRIM_E2E_OPENCODE must name an executable called opencode, not %s", opencode)
	}
	s := newSessionRules(t, bin, opencodeModel, nil, `  - name: only-the-session-reaches-the-model
    decision: deny
    when: op == "llm.forward" && agent.kind != "session"
`)
	r := s.d.Run(t, s.work, []string{
		"PATH=" + filepath.Dir(opencode) + string(os.PathListSeparator) + os.Getenv("PATH"),
		keyVar + "=fake-provider-key-not-a-seed",
		"OPENCODE_DISABLE_AUTOUPDATE=1", "OPENCODE_DISABLE_MODELS_FETCH=1", "OPENCODE_DISABLE_LSP_DOWNLOAD=1",
		// opencode run has no terminal to ask on.
		`OPENCODE_PERMISSION={"bash":"allow","webfetch":"allow"}`,
	}, "opencode", "run", "--pure", "-m", model,
		"Check the deploy setup and list the secrets scrim offers.")
	if r.Code != 0 {
		t.Fatalf("opencode under scrim run: exit %d\n%s", r.Code, r.Output())
	}
	if !strings.Contains(r.Stdout, "Done.") {
		t.Errorf("the task did not complete: %s", r.Output())
	}
	return s, r
}

// TestOpenCodeSessionProviders runs the session on OpenCode's openai
// (Responses API) and google (Gemini) providers: it completes as the
// session, every request reaches the provider's route, and nothing leaks.
// The tool results themselves are checked on the anthropic provider.
func TestOpenCodeSessionProviders(t *testing.T) {
	for _, c := range []struct {
		model, key string
		api        fp.API
	}{
		{"openai/gpt-5", "OPENAI_API_KEY", fp.OpenAIResponses},
		{"google/gemini-2.5-pro", "GOOGLE_GENERATIVE_AI_API_KEY", fp.Gemini},
	} {
		t.Run(c.model, func(t *testing.T) {
			s, _ := runOpenCode(t, c.model, c.key)
			var main int
			for _, e := range s.checkLeaks(t) {
				if e.API != c.api {
					t.Errorf("request outside the %s route: %s %s", c.api, e.API, e.Path)
				}
				if e.Header.Get("X-Scrim-Session") != "" {
					t.Errorf("the session header reached the provider")
				}
				if len(scenario.ToolNames(decode(t, e.Body))) > 0 {
					main++
				}
			}
			if main < len(steps)+3 {
				t.Errorf("%d tool-enabled requests, want %d", main, len(steps)+3)
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if len(s.apiAuth) != 2 || s.apiAuth[0] != "Bearer "+s.token.Value() {
				t.Errorf("the tool API saw %d requests, want the curl with the real token, then webfetch", len(s.apiAuth))
			}
		})
	}
}

// decode is a recorded request body as JSON, or nil.
func decode(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return m
}
