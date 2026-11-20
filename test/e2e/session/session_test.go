// SPDX-License-Identifier: AGPL-3.0-only

// Package session runs a realistic Claude Code session under `scrim run`
// against a real `scrim proxy`: empty HOME, a fake key, and a fake model
// that has the agent read a .env of seeded secrets, cat a config, git diff a
// file with a key in it, call a bound tool API through HTTPS_PROXY and call
// scrim's MCP tool. Every request the provider received, and scrim's capture
// of them, must hold zero seeded values. Run it with `just e2e-session`; it
// is skipped when Claude Code is not installed.
package session

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// bash is one scripted Bash tool call.
type bash struct{ command, why string }

var steps = []bash{
	{"cat .env", "Read the environment file"},
	{"cat config/app.yaml", "Read the app configuration"},
	{"git diff", "Show the uncommitted change"},
	{`curl -sS --fail-with-body -H "Authorization: Bearer SCRIM_API_TOKEN" https://` + harness.APIHost + `/v1/whoami`, "Call the deploy API"},
}

// model asks for each Bash step, then scrim's secrets_list, then finishes.
// Requests without tools (titles, summaries) get a short text.
func model(t fp.Turn) fp.Reply {
	if _, ok := t.Body["tools"]; !ok {
		return fp.Reply{Text: "scrim e2e session"}
	}
	switch n := t.Assistant; {
	case n < len(steps):
		return fp.Reply{Text: steps[n].why + ".", ToolCalls: []fp.ToolCall{{Name: "Bash",
			Input: map[string]any{"command": steps[n].command, "description": steps[n].why}}}}
	case n == len(steps):
		return fp.Reply{Text: "Listing the secrets scrim offers.", ToolCalls: []fp.ToolCall{{Name: "mcp__scrim__secrets_list", Input: map[string]any{}}}}
	}
	return fp.Reply{Text: "Done."}
}

func TestClaudeCodeSession(t *testing.T) {
	bin := harness.Require(t)
	// Run it as `claude`, the way users do: scrim run picks its preset from
	// the command name, and the native installer's symlink target is a
	// version number.
	claudeDir := filepath.Dir(harness.LookPath(t, "claude"))
	harness.LookPath(t, "git")
	harness.LookPath(t, "curl")

	seeds := leak.GenerateSet()
	token := leak.Generate(leak.KindAPIKey)
	all := append([]leak.Seed{token}, seeds...)
	secrets := map[string]string{"api-token": token.Value()}
	for i, s := range seeds {
		secrets[fmt.Sprintf("seed-%d", i)] = s.Value()
	}

	// The tool API the agent calls with the bound credential.
	pki := harness.NewPKI(t)
	var mu sync.Mutex
	var apiAuth []string
	harness.ServeTLS(t, pki, harness.APIHost, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		apiAuth = append(apiAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+token.Value() {
			http.Error(w, `{"error":"bad token"}`, http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(w, `{"user":"deploy-bot","token":%q}`, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}))

	fake := fp.New(fp.Options{Responder: model})
	provider := httptest.NewServer(fake)
	defer provider.Close()

	d := harness.Start(t, bin, harness.Options{
		Secrets:  secrets,
		Upstream: provider.URL,
		Capture:  true,
		Catalog: `    api-token:
      ref: e2e://tools/api-token
      hosts: [` + harness.APIHost + `]
      placeholder: SCRIM_API_TOKEN
`,
		UpstreamCA: pki.CAPEM,
		// The session may see what the store holds (references, never
		// values); injection is left to the built-in rule.
		Rules: `default: deny
rules:
  - name: session-lists-secrets
    decision: allow
    when: op == "mcp.tool" && tool.name == "secrets_list" && agent.kind == "session"
`,
	})

	// A project with secrets where agents find them.
	work := filepath.Join(d.Dir, "project")
	write := func(name, body string) {
		p := filepath.Join(work, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var env strings.Builder
	for _, s := range seeds {
		if s.Kind == leak.KindPrivateKey {
			fmt.Fprintf(&env, "%s=%q\n", strings.ToUpper(strings.ReplaceAll(string(s.Kind), "-", "_")), s.Value())
			continue
		}
		fmt.Fprintf(&env, "%s=%s\n", strings.ToUpper(strings.ReplaceAll(string(s.Kind), "-", "_")), s.Value())
	}
	fmt.Fprintf(&env, "DEPLOY_API_TOKEN=%s\n", token.Value())
	write(".env", env.String())
	write("config/app.yaml", fmt.Sprintf("database:\n  host: db.internal\n  user: app\n  password: %s\naws:\n  access_key_id: %s\n  secret_access_key: %s\n",
		byKind(seeds, leak.KindDBPassword), byKind(seeds, leak.KindAWSAccessKey), byKind(seeds, leak.KindAWSSecret)))
	write("deploy.sh", "#!/bin/sh\ncurl -H \"Authorization: Bearer $DEPLOY_API_TOKEN\" https://"+harness.APIHost+"/v1/deploy\n")
	if err := os.WriteFile(filepath.Join(d.Home, ".gitconfig"), []byte("[user]\n\tname = scrim e2e\n\temail = e2e@scrim.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = work, d.Env()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	git("add", "deploy.sh", "config/app.yaml")
	git("commit", "-q", "-m", "initial")
	// The uncommitted change pastes a key into the script.
	write("deploy.sh", "#!/bin/sh\nexport GITHUB_TOKEN="+byKind(seeds, leak.KindGitHubToken)+"\ncurl -H \"Authorization: Bearer "+token.Value()+"\" https://"+harness.APIHost+"/v1/deploy\n")

	allowed := "Bash(cat:*),Bash(git diff:*),Bash(curl:*),mcp__scrim__secrets_list"
	r := d.Run(t, work, []string{
		"PATH=" + claudeDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"ANTHROPIC_API_KEY=fake-provider-key-not-a-seed",
		"DISABLE_AUTOUPDATER=1", "DISABLE_TELEMETRY=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
	}, "claude", "-p", "Check the deploy setup and list the secrets scrim offers.",
		"--allowedTools", allowed, "--model", "claude-sonnet-4-5")
	if r.Code != 0 {
		t.Fatalf("claude under scrim run: exit %d\n%s", r.Code, r.Output())
	}
	if !strings.Contains(r.Stdout, "Done.") {
		t.Errorf("the task did not complete: %s", r.Output())
	}

	// The audit: every provider request, and every byte scrim captured on
	// the way out, checked for every seeded value under every encoding the
	// leak suite knows.
	checker := leak.NewChecker(all)
	ex := fake.Exchanges()
	var main []fp.Exchange
	for _, e := range ex {
		if f := checker.Check(e.Capture); len(f) > 0 {
			raw, _ := json.Marshal(f)
			t.Errorf("leak in provider request %d (%s): %s", e.Seq, e.Path, raw)
		}
		var body map[string]any
		if json.Unmarshal(e.Body, &body) == nil && body["tools"] != nil {
			main = append(main, e)
		}
	}
	captured := scanCaptures(t, checker, d.CaptureDir())
	t.Logf("%d provider requests (%d with tools), %d captured files, zero leaks unless reported above", len(ex), len(main), captured)

	if len(main) < len(steps)+2 {
		t.Fatalf("%d tool-enabled requests, want %d (one per tool result and the final one)", len(main), len(steps)+2)
	}
	results := toolResults(t, main[len(main)-1].Body)
	if len(results) < len(steps)+1 {
		t.Fatalf("%d tool results reached the model, want %d", len(results), len(steps)+1)
	}
	for i, r := range results {
		t.Logf("tool result %d as the model saw it: %.160q", i, r)
	}
	for i, s := range steps {
		if !fp.DefaultPlaceholderPattern.MatchString(results[i]) && !strings.Contains(results[i], "SCRIM_API_TOKEN") {
			t.Errorf("result of %q reached the model without placeholders: %.300s", s.command, results[i])
		}
	}
	if !strings.Contains(results[3], "deploy-bot") {
		t.Errorf("the tool API call failed: %.300s", results[3])
	}
	if !strings.Contains(results[len(steps)], "e2e://tools/") {
		t.Errorf("the MCP result did not reach the model: %.300s", results[len(steps)])
	}
	mu.Lock()
	defer mu.Unlock()
	if len(apiAuth) != 1 || apiAuth[0] != "Bearer "+token.Value() {
		t.Errorf("the tool API did not receive the real token (%d requests)", len(apiAuth))
	}
}

func byKind(seeds []leak.Seed, k leak.Kind) string {
	for _, s := range seeds {
		if s.Kind == k {
			return s.Value()
		}
	}
	panic("no seed of kind " + string(k))
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

// scanCaptures checks scrim's capture directory and returns how many files
// it holds.
func scanCaptures(t *testing.T, checker *leak.Checker, dir string) int {
	t.Helper()
	var n int
	err := filepath.WalkDir(dir, func(p string, de fs.DirEntry, err error) error {
		if err != nil || !de.Type().IsRegular() {
			return err
		}
		f, err := os.Open(p) //nolint:gosec // test output
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		b, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		n++
		if found := checker.Check(leak.Capture{Body: b}); len(found) > 0 {
			raw, _ := json.Marshal(found)
			t.Errorf("scrim capture %s holds a seeded value: %s", filepath.Base(p), raw)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("scrim captured nothing")
	}
	return n
}
