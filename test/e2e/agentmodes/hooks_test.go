// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

// Package agentmodes runs the agent-side interception modes with the real
// Claude Code CLI inside test/e2e/sandbox.sh. TestHooksOnly is hooks-only
// interception (tasks.md 15.3): Claude Code talks to the fake provider
// directly, never through scrim, and only `scrim install --hooks` stands
// between a tool result and the model. Run it with `just e2e-agentmodes`;
// it is skipped when Claude Code is not installed.
package agentmodes

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// readEnv has the agent read .env with Bash, then with Read, then finish.
// Requests without tools (titles) get a short text.
func readEnv(envPath string) fp.Responder {
	return func(t fp.Turn) fp.Reply {
		if _, ok := t.Body["tools"]; !ok {
			return fp.Reply{Text: "scrim hooks e2e"}
		}
		switch t.Assistant {
		case 0:
			return fp.Reply{Text: "Reading the environment file.", ToolCalls: []fp.ToolCall{{Name: "Bash",
				Input: map[string]any{"command": "cat .env", "description": "Read the environment file"}}}}
		case 1:
			return fp.Reply{Text: "Reading it again.", ToolCalls: []fp.ToolCall{{Name: "Read",
				Input: map[string]any{"file_path": envPath}}}}
		}
		return fp.Reply{Text: "Done."}
	}
}

// session runs one Claude Code session straight against the provider (no
// scrim run, no base URL of scrim's) and returns the tool results of the
// last request that carried tools, as the model saw them, with the
// exchanges of this session.
func session(t *testing.T, d *harness.Daemon, work, claude string, fake *fp.Server, provider string) ([]string, []fp.Exchange) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, claude, "-p", "Check the environment file.", //nolint:gosec // the CLI under test
		"--allowedTools", "Bash(cat:*),Read", "--model", "claude-sonnet-4-5")
	cmd.Dir = work
	cmd.Env = d.Env(
		"ANTHROPIC_BASE_URL="+provider,
		"ANTHROPIC_API_KEY=fake-provider-key-not-a-seed",
		// The hooks find scrim's local API through its configuration.
		"SCRIM_CONFIG="+d.Config,
		"DISABLE_AUTOUPDATER=1", "DISABLE_TELEMETRY=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
	)
	cmd.Stdin = strings.NewReader("")
	before := len(fake.Exchanges())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("claude: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Done.") {
		t.Fatalf("the session did not complete:\n%s", out)
	}
	var last []byte
	ex := fake.Exchanges()[before:]
	for _, e := range ex {
		var body map[string]any
		if json.Unmarshal(e.Body, &body) == nil && body["tools"] != nil {
			last = e.Body
		}
	}
	if last == nil {
		t.Fatal("no request with tools reached the provider")
	}
	return toolResults(t, last), ex
}

func TestHooksOnly(t *testing.T) {
	bin := harness.Require(t)
	claude := harness.RealPath(t, "claude")

	key := leak.Generate(leak.KindAPIKey)
	var envPath string
	fake := fp.New(fp.Options{Responder: func(turn fp.Turn) fp.Reply { return readEnv(envPath)(turn) }})
	provider := httptest.NewServer(fake)
	defer provider.Close()
	d := harness.Start(t, bin, harness.Options{Secrets: map[string]string{"api-key": key.Value()}, Upstream: provider.URL})

	work := filepath.Join(d.Dir, "project")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	envPath = filepath.Join(work, ".env")
	if err := os.WriteFile(envPath, []byte("DEPLOY_API_KEY="+key.Value()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checker := leak.NewChecker([]leak.Seed{key})

	// Without hooks the value reaches the provider: this is what the hooks
	// have to stop, and it shows the check below can see a leak.
	results, _ := session(t, d, work, claude, fake, provider.URL)
	if len(results) < 2 || !strings.Contains(results[0], key.Value()) {
		t.Fatalf("without hooks the tool result should carry the value; got %d results", len(results))
	}

	r := d.Scrim(t, work, nil, "install", "--hooks", "--agent", "claude")
	if r.Code != 0 {
		t.Fatalf("scrim install --hooks: exit %d\n%s", r.Code, r.Output())
	}
	settings := filepath.Join(d.Home, ".claude", "settings.json")
	if b, err := os.ReadFile(settings); err != nil || !strings.Contains(string(b), "# scrim-hook") { //nolint:gosec // test file
		t.Fatalf("hooks not in %s: %v\n%s", settings, err, b)
	}

	st := d.Scrim(t, work, nil, "status", "--json")
	var rep struct {
		Coverage   string `json:"coverage"`
		AgentModes []struct {
			Mode       string   `json:"mode"`
			Coverage   string   `json:"coverage"`
			NotCovered []string `json:"not_covered"`
		} `json:"agent_modes"`
	}
	if err := json.Unmarshal([]byte(st.Stdout), &rep); err != nil {
		t.Fatalf("status --json: %v\n%s", err, st.Output())
	}
	if rep.Coverage != "partial" || len(rep.AgentModes) != 1 || rep.AgentModes[0].Mode != "hooks" || rep.AgentModes[0].Coverage != "partial" || len(rep.AgentModes[0].NotCovered) == 0 {
		t.Fatalf("status does not report the hooks as partial:\n%s", st.Stdout)
	}
	t.Logf("status: coverage %q, agent modes %+v", rep.Coverage, rep.AgentModes)

	results, ex := session(t, d, work, claude, fake, provider.URL)
	for _, e := range ex {
		if f := checker.Check(e.Capture); len(f) > 0 {
			raw, _ := json.Marshal(f)
			t.Errorf("leak in provider request %d (%s): %s", e.Seq, e.Path, raw)
		}
	}
	if len(results) < 2 {
		t.Fatalf("%d tool results reached the model, want 2", len(results))
	}
	for i, res := range results[:2] {
		t.Logf("tool result %d as the model saw it: %.200q", i, res)
		if !fp.DefaultPlaceholderPattern.MatchString(res) {
			t.Errorf("tool result %d has no placeholder: %.300s", i, res)
		}
	}
	if strings.Contains(d.Log.String(), key.Value()) {
		t.Error("the value reached scrim's log")
	}

	// A prompt holding the value is blocked before it is sent.
	before := len(fake.Exchanges())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, claude, "-p", "deploy with "+key.Value(), "--model", "claude-sonnet-4-5") //nolint:gosec // the CLI under test
	cmd.Dir = work
	cmd.Env = d.Env("ANTHROPIC_BASE_URL="+provider.URL, "ANTHROPIC_API_KEY=fake-provider-key-not-a-seed", "SCRIM_CONFIG="+d.Config,
		"DISABLE_AUTOUPDATER=1", "DISABLE_TELEMETRY=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1")
	cmd.Stdin = strings.NewReader("")
	out, _ := cmd.CombinedOutput()
	t.Logf("prompt with the value: %.300q", out)
	for _, e := range fake.Exchanges()[before:] {
		if f := checker.Check(e.Capture); len(f) > 0 {
			t.Errorf("the prompt with the value reached the provider (request %d)", e.Seq)
		}
	}
	if !strings.Contains(string(out), "scrim did not send it") {
		t.Errorf("the prompt was not blocked by scrim's hook: %s", out)
	}

	r = d.Scrim(t, work, nil, "uninstall", "--hooks")
	if r.Code != 0 {
		t.Fatalf("scrim uninstall --hooks: exit %d\n%s", r.Code, r.Output())
	}
	if b, err := os.ReadFile(settings); err == nil && strings.Contains(string(b), "# scrim-hook") { //nolint:gosec // test file
		t.Fatalf("uninstall left scrim's hooks:\n%s", b)
	}
}

// toolResults returns the text of every tool_result in a Messages request,
// in order.
func toolResults(t *testing.T, body []byte) []string {
	t.Helper()
	var req struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range req.Messages {
		var blocks []struct {
			Type    string          `json:"type"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(m.Content, &blocks) != nil {
			continue
		}
		for _, b := range blocks {
			if b.Type == "tool_result" {
				out = append(out, string(b.Content))
			}
		}
	}
	return out
}
