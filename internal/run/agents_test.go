// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// buildScrim builds the scrim binary the agent starts as its MCP server.
func buildScrim(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "scrim")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/heliopsy/scrim")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building scrim: %v\n%s", err, out)
	}
	return bin
}

// testNetwork is run.network for the real agent CLIs:
// SCRIM_TEST_RUN_NETWORK=proxy-only runs them in the agent network
// namespace (CI runs both).
func testNetwork(t *testing.T) string {
	t.Helper()
	mode := os.Getenv("SCRIM_TEST_RUN_NETWORK")
	if mode == NetworkProxyOnly {
		requireNetwork(t)
	}
	return mode
}

// agentEnv is a clean environment for a real agent CLI: an empty HOME so it
// reads none of the user's settings or credentials, and a fake provider key
// the stand-in proxy passes through to the fake model.
func agentEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	return append(isolatedEnv(t), append([]string{"TERM=dumb"}, extra...)...)
}

// toolRoundTrip asks for one shell command, then one MCP tool call, then
// finishes. Requests without tools (titles, summaries) get a short text.
func toolRoundTrip(bash, mcpTool string, bashInput map[string]any) fp.Responder {
	return func(t fp.Turn) fp.Reply {
		if _, ok := t.Body["tools"]; !ok {
			return fp.Reply{Text: "Scrim run test"}
		}
		switch t.Assistant {
		case 0:
			return fp.Reply{Text: "Reading the notes.", ToolCalls: []fp.ToolCall{{Name: bash, Input: bashInput}}}
		case 1:
			return fp.Reply{Text: "Listing secrets.", ToolCalls: []fp.ToolCall{{Name: mcpTool, Input: map[string]any{}}}}
		}
		return fp.Reply{Text: "Done."}
	}
}

// TestClaudeCodeThroughScrimRun runs real Claude Code under scrim run
// against the fake model: it reads a file holding seeded secrets with its
// Bash tool and calls scrim's secrets_list over the MCP server scrim run
// registered. The model must see placeholders only, the MCP call must come
// from the session, and the task must complete.
func TestClaudeCodeThroughScrimRun(t *testing.T) {
	claude, err := exec.LookPath("claude")
	if err != nil {
		t.Skip("claude (Claude Code) is not installed")
	}
	if testing.Short() {
		t.Skip("runs a real agent CLI")
	}
	h := newHarness(t, true)
	h.api.Store.Seed(agenttools.SecretInfo{Ref: "bao://kv/agents/github", Bindings: []string{"api.github.com"}}, []byte(h.seeds[1].Value()))
	h.fake.SetResponder(toolRoundTrip("Bash", "mcp__scrim__secrets_list",
		map[string]any{"command": "cat notes.txt", "description": "Read the notes"}))
	work := seedFile(t, h.seeds)
	scrim := buildScrim(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var out, errb syncBuf
	err = Run(ctx, Options{
		Command: []string{claude, "-p", "Read notes.txt and list the secrets scrim offers.",
			"--allowedTools", "Bash(cat:*),mcp__scrim__secrets_list", "--model", "claude-sonnet-4-5"},
		Environ: agentEnv(t, "ANTHROPIC_API_KEY=fake-provider-key-not-a-seed", "DISABLE_AUTOUPDATER=1",
			"DISABLE_TELEMETRY=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"),
		Dir: work, Daemon: h.daemon(), MCP: true, ScrimPath: scrim,
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, RuntimeDir: t.TempDir(),
		Network: NetworkOptions{Mode: testNetwork(t)},
	})
	if err != nil {
		t.Fatalf("claude under scrim run: %v\nstdout: %s\nstderr: %s", err, out.String(), errb.String())
	}
	assertAgentRun(t, h, out.String()+errb.String(), fp.Anthropic, "/v1/messages")
}

// assertAgentRun checks a real agent's run: zero leaks in every request, the
// shell tool's result went back to the model as placeholders, the MCP
// result reached the model, the MCP call was made as the session, and the
// session ended.
func assertAgentRun(t *testing.T, h *harness, output string, api fp.API, suffix string) {
	t.Helper()
	ex := h.fake.Exchanges()
	checker := leak.NewChecker(h.seeds)
	var main []fp.Exchange
	for _, e := range ex {
		if f := checker.Check(e.Capture); len(f) > 0 {
			raw, _ := json.Marshal(f)
			t.Errorf("leak in request %s: %s", e.Path, raw)
		}
		if e.API == api && strings.HasSuffix(e.Path, suffix) {
			var body map[string]any
			if json.Unmarshal(e.Body, &body) == nil && body["tools"] != nil {
				main = append(main, e)
			}
		}
	}
	if len(main) < 3 {
		t.Logf("forward proxy tunnels: %v; %d provider requests", h.tunnels(), len(ex))
		for _, e := range ex {
			t.Logf("%s %s %s status %d, encoding %q, %d bytes, tools %s", e.Method, e.Path, e.API, e.Status, e.Header.Get("Content-Encoding"), len(e.Body), toolNames(e.Body))
		}
		t.Fatalf("agent sent %d tool-enabled model requests, want 3 (shell result, MCP result, done)", len(main))
	}
	if len(main[1].Placeholders) == 0 {
		t.Error("the shell result reached the model without placeholders")
	}
	if !strings.Contains(string(main[2].Body), "bao://kv/agents/github") {
		t.Error("the MCP result did not reach the model")
	}
	assertSessionCall(t, h)
	// codex exec echoes command output on the local terminal, where the
	// user may see it; only what reaches the model is checked for seeds.
	if !strings.Contains(output, "Done.") {
		t.Errorf("task did not complete: %q", output)
	}
}

// TestCodexThroughScrimRun is the same round trip with the Codex CLI. Codex
// (0.17x) offers its tools through one code-mode `exec` tool that runs
// JavaScript calling nested tools, so its model is codexModel rather than
// the fake provider: it asks for `exec_command` on the seeded file, then
// for scrim's secrets_list over MCP, then finishes.
func TestCodexThroughScrimRun(t *testing.T) {
	codex, err := exec.LookPath("codex")
	if err != nil {
		t.Skip("codex (Codex CLI) is not installed")
	}
	if testing.Short() {
		t.Skip("runs a real agent CLI")
	}
	model := &codexModel{steps: []string{
		// Text results go back as they are: JSON.stringify of a result that
		// holds the file would escape it a second time, a form the stand-in
		// redactor does not match (the real redactor's job, not the wrapper's).
		`const r = await tools.exec_command({cmd: "cat notes.txt"}); text(typeof r === "string" ? r : (r.output ?? JSON.stringify(r)));`,
		`const r = await tools.mcp__scrim__secrets_list({}); text(JSON.stringify(r));`,
	}}
	h := newHarnessUpstream(t, true, model)
	h.api.Store.Seed(agenttools.SecretInfo{Ref: "bao://kv/agents/github", Bindings: []string{"api.github.com"}}, []byte(h.seeds[1].Value()))
	work := seedFile(t, h.seeds)
	scrim := buildScrim(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var out, errb syncBuf
	err = Run(ctx, Options{
		Command: []string{codex, "exec", "--skip-git-repo-check", "--sandbox", "workspace-write",
			"Read notes.txt and list the secrets scrim offers."},
		Environ: agentEnv(t, "OPENAI_API_KEY=fake-provider-key-not-a-seed"),
		Dir:     work, Daemon: h.daemon(), MCP: true, ScrimPath: scrim,
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, RuntimeDir: t.TempDir(),
		Network: NetworkOptions{Mode: testNetwork(t)},
	})
	output := out.String() + errb.String()
	if err != nil {
		t.Fatalf("codex under scrim run: %v\n%s", err, output)
	}
	reqs := model.requests()
	checker := leak.NewChecker(h.seeds)
	for _, c := range reqs {
		if f := checker.Check(c); len(f) > 0 {
			raw, _ := json.Marshal(f)
			t.Errorf("leak in request %s: %s", c.Path, raw)
		}
	}
	outputs := model.outputs()
	if len(outputs) < 2 {
		t.Fatalf("codex returned %d tool outputs, want 2\n%s", len(outputs), output)
	}
	if !fp.DefaultPlaceholderPattern.MatchString(outputs[0]) {
		t.Errorf("the shell result reached the model without placeholders: %.300s", outputs[0])
	}
	if !strings.Contains(outputs[1], "bao://kv/agents/github") {
		t.Errorf("the MCP result did not reach the model: %.500s", outputs[1])
	}
	assertSessionCall(t, h)
	// codex exec echoes command output on the local terminal, where the
	// user may see it; only what reaches the model is checked for seeds.
	if !strings.Contains(output, "Done.") {
		t.Errorf("task did not complete: %q", output)
	}
}

// codexModel is a minimal OpenAI Responses model for Codex: one scripted
// code-mode `exec` call per turn, then "Done.". It records every request.
type codexModel struct {
	steps []string
	mu    sync.Mutex
	reqs  []leak.Capture
	outs  []string // custom_tool_call_output texts of the last request
}

func (m *codexModel) requests() []leak.Capture {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.reqs)
}

func (m *codexModel) outputs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.outs)
}

func (m *codexModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/responses") {
		// Responses over WebSocket and model discovery are not served;
		// Codex falls back to HTTPS.
		http.Error(w, "not served", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Input []map[string]any `json:"input"`
		Tools []any            `json:"tools"`
	}
	_ = json.Unmarshal(body, &req)
	var outs []string
	tools := len(req.Tools) > 0
	for _, it := range req.Input {
		switch it["type"] {
		case "additional_tools":
			tools = true
		case "custom_tool_call_output", "function_call_output":
			b, _ := json.Marshal(it["output"])
			outs = append(outs, string(b))
		}
	}
	m.mu.Lock()
	m.reqs = append(m.reqs, leak.Capture{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Header: r.Header.Clone(), Body: body})
	if tools {
		m.outs = outs
	}
	m.mu.Unlock()

	var item map[string]any
	switch {
	case tools && len(outs) < len(m.steps):
		n := len(outs)
		item = map[string]any{"type": "custom_tool_call", "id": fmt.Sprintf("ctc_%d", n), "call_id": fmt.Sprintf("call_%d", n),
			"name": "exec", "input": m.steps[n], "status": "completed"}
	case tools:
		item = map[string]any{"type": "message", "id": "msg_done", "role": "assistant", "status": "completed",
			"content": []any{map[string]any{"type": "output_text", "text": "Done.", "annotations": []any{}}}}
	default:
		item = map[string]any{"type": "message", "id": "msg_title", "role": "assistant", "status": "completed",
			"content": []any{map[string]any{"type": "output_text", "text": "Scrim run test", "annotations": []any{}}}}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	fl, _ := w.(http.Flusher)
	ev := func(name string, v map[string]any) {
		v["type"] = name
		b, _ := json.Marshal(v)
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, b)
		if fl != nil {
			fl.Flush()
		}
	}
	resp := map[string]any{"id": "resp_1", "object": "response", "status": "in_progress", "model": "gpt-test", "output": []any{}}
	ev("response.created", map[string]any{"response": resp})
	ev("response.output_item.added", map[string]any{"output_index": 0, "item": item})
	ev("response.output_item.done", map[string]any{"output_index": 0, "item": item})
	done := map[string]any{"id": "resp_1", "object": "response", "status": "completed", "model": "gpt-test", "output": []any{item},
		"usage": map[string]any{"input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
			"input_tokens_details": map[string]any{"cached_tokens": 0}, "output_tokens_details": map[string]any{"reasoning_tokens": 0}}}
	ev("response.completed", map[string]any{"response": done})
}

// assertSessionCall checks that scrim mcp called secrets_list as the
// session and that the session ended.
func assertSessionCall(t *testing.T, h *harness) {
	t.Helper()
	var call *agenttools.AuditEntry
	for _, e := range h.api.Audit.All() {
		if e.Tool == "secrets_list" {
			call = &e
		}
	}
	if call == nil {
		t.Fatal("scrim mcp never called secrets_list")
	}
	if call.Source != "session" || call.SessionID == "" || !strings.Contains(call.Principal, "/") {
		t.Errorf("MCP call not made as the session: %+v", *call)
	}
	if s, err := h.api.Sessions.Get(context.Background(), call.SessionID); err != nil || !s.Revoked() {
		t.Errorf("session not ended: %v %v", s.RevokedAt, err)
	}
}

// toolNames lists the tools a request offers, for diagnosing a run.
func toolNames(body []byte) string {
	var req struct {
		Tools []struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(body, &req)
	var names []string
	for _, tl := range req.Tools {
		names = append(names, tl.Type+":"+tl.Name+tl.Function.Name)
	}
	return strings.Join(names, ",")
}
