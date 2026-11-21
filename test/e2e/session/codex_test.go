// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// codexModel plays the model for Codex over the Responses API: one shell
// call per step, then scrim's secrets_list through MCP, then done. Codex
// names its shell tool differently across releases and model families, so
// the call is shaped for whichever tool the request offers.
func codexModel(t fp.Turn) fp.Reply {
	tools := toolNames(t.Body)
	if len(tools) == 0 {
		return fp.Reply{Text: "scrim e2e session"}
	}
	switch n := t.ToolResults; {
	case n < len(steps):
		call, ok := codexShell(tools, steps[n].command)
		if !ok {
			return fp.Reply{Text: "no shell tool offered: " + strings.Join(tools, ",")}
		}
		return fp.Reply{ToolCalls: []fp.ToolCall{call}}
	case n == len(steps):
		for _, name := range tools {
			ns, tool, nested := strings.Cut(name, "/")
			switch {
			case nested && tool == "secrets_list":
				return fp.Reply{ToolCalls: []fp.ToolCall{{Namespace: ns, Name: tool, Input: map[string]any{}}}}
			case !nested && strings.HasSuffix(name, "secrets_list"):
				return fp.Reply{ToolCalls: []fp.ToolCall{{Name: name, Input: map[string]any{}}}}
			}
		}
		return fp.Reply{Text: "no scrim MCP tool offered: " + strings.Join(tools, ",")}
	}
	return fp.Reply{Text: "Done."}
}

// codexShell is a call of the shell tool Codex offers.
func codexShell(tools []string, command string) (fp.ToolCall, bool) {
	for _, name := range tools {
		switch name {
		case "exec_command":
			return fp.ToolCall{Name: name, Input: map[string]any{"cmd": command}}, true
		case "shell_command":
			return fp.ToolCall{Name: name, Input: map[string]any{"command": command}}, true
		case "shell":
			return fp.ToolCall{Name: name, Input: map[string]any{"command": []any{"bash", "-c", command}}}, true
		}
	}
	return fp.ToolCall{}, false
}

// toolNames lists the function tools of a Responses request. A tool inside a
// namespace tool (Codex puts each MCP server's tools in one) is listed as
// namespace/name.
func toolNames(body map[string]any) []string {
	list, _ := body["tools"].([]any)
	var out []string
	for _, it := range list {
		m, _ := it.(map[string]any)
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		nested, _ := m["tools"].([]any)
		if len(nested) == 0 {
			out = append(out, name)
			continue
		}
		for _, n := range nested {
			nm, _ := n.(map[string]any)
			if sub, _ := nm["name"].(string); sub != "" {
				out = append(out, name+"/"+sub)
			}
		}
	}
	return out
}

// TestCodexSession is TestClaudeCodeSession for the Codex CLI: `codex exec`
// under `scrim run`, talking the OpenAI Responses API to the fake model
// through scrim's LLM proxy. SCRIM_E2E_CODEX names the codex binary (the
// native one from the @openai/codex npm package, installed for the test
// only); otherwise codex is looked up on PATH.
func TestCodexSession(t *testing.T) {
	bin := harness.Require(t)
	codex := os.Getenv("SCRIM_E2E_CODEX")
	if codex == "" {
		codex = harness.LookPath(t, "codex")
	}
	// Run it as `codex` so scrim run picks the Codex preset by name.
	if filepath.Base(codex) != "codex" {
		t.Fatalf("SCRIM_E2E_CODEX must name an executable called codex, not %s", codex)
	}
	s := newSession(t, bin, codexModel)

	r := s.d.Run(t, s.work, []string{
		"PATH=" + filepath.Dir(codex) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"CODEX_API_KEY=fake-provider-key-not-a-seed",
		"OPENAI_API_KEY=fake-provider-key-not-a-seed",
	}, "codex", "exec", "--skip-git-repo-check", "--color", "never",
		// The sandbox would run each command in namespaces of its own, which
		// the e2e sandbox already is; approvals have no terminal to ask on.
		"--dangerously-bypass-approvals-and-sandbox",
		"-m", "gpt-5.1-codex",
		"Check the deploy setup and list the secrets scrim offers.")
	if r.Code != 0 {
		t.Fatalf("codex under scrim run: exit %d\n%s", r.Code, r.Output())
	}
	if !strings.Contains(r.Stdout, "Done.") {
		t.Errorf("the task did not complete: %s", r.Output())
	}

	var last *fp.Exchange
	ex := s.checkLeaks(t)
	for i := range ex {
		if ex[i].API == fp.OpenAIResponses && ex[i].Status == 200 {
			last = &ex[i]
		}
	}
	if last == nil {
		t.Fatal("no Responses request reached the fake model")
	}
	results := responsesOutputs(t, last.Body)
	if len(results) < len(steps)+1 {
		t.Fatalf("%d tool results reached the model, want %d", len(results), len(steps)+1)
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
	s.checkAPI(t)
}

// responsesOutputs returns the output of every function_call_output item in
// a Responses request, in order.
func responsesOutputs(t *testing.T, body []byte) []string {
	t.Helper()
	var req struct {
		Input []struct {
			Type   string          `json:"type"`
			Output json.RawMessage `json:"output"`
		} `json:"input"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, it := range req.Input {
		if it.Type == "function_call_output" {
			out = append(out, string(it.Output))
		}
	}
	return out
}
