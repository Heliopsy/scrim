// SPDX-License-Identifier: AGPL-3.0-only

package scenario

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/matrix"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// AgentSession is a session for a real agent CLI: files in a scratch
// workspace and the shell commands the fake model asks the agent to run on
// them. The agent runs each command for real, so its output (including the
// transforms of the bypass matrix: reversal, base64, byte dumps) is what the
// proxy has to contain.
type AgentSession struct {
	Name     string
	Prompt   string
	Files    map[string]string
	Commands []string
}

// AgentSessions are the sessions real agent drivers run.
var AgentSessions = []AgentSession{
	{
		Name:   "agent-dotenv-transforms",
		Prompt: "The billing service fails to start. Inspect .env in every way you can.",
		Files: map[string]string{
			".env": "# billing service\nDATABASE_URL=postgres://billing:{{secret:db-password}}@db.internal:5432/billing\nPAYMENTS_API_KEY={{secret:api-key}}\nGITHUB_TOKEN={{secret:github-token}}\nSESSION_SECRET='{{secret:password}}'\nAWS_ACCESS_KEY_ID={{secret:aws-access-key-id}}\nAWS_SECRET_ACCESS_KEY={{secret:aws-secret-access-key}}\n",
		},
		Commands: []string{"cat .env", "rev .env", "base64 .env", "xxd .env", "tr a-z A-Z < .env", "od -c .env"},
	},
	{
		Name:   "agent-config-and-key",
		Prompt: "Why does the worker fail its TLS handshake?",
		Files: map[string]string{
			"config/production.yaml": "database:\n  password: '{{secret:password}}'\ntls:\n  token: {{secret:jwt}}\n",
			"tls/worker.key":         "{{secret:private-key}}\n",
		},
		Commands: []string{"cat config/production.yaml", "cat tls/worker.key", "head -c 200 tls/worker.key"},
	},
}

// ClaudeDriver runs Claude Code (`claude -p`) through the proxy.
type ClaudeDriver struct {
	// Bin is the claude binary; default "claude" from PATH.
	Bin string
	// Timeout bounds one session. Default 3 minutes.
	Timeout time.Duration
}

// claudeTools lists the commands the sessions use, so Claude Code runs them
// without asking and runs nothing else.
func claudeTools(cmds []string) string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cmds {
		name := strings.Fields(c)[0]
		if !seen[name] {
			seen[name] = true
			out = append(out, "Bash("+name+":*)")
		}
	}
	return strings.Join(out, ",")
}

// Run plays one session with Claude Code. Claude Code runs with an empty HOME
// in a scratch workspace, so it reads none of the user's settings, hooks,
// MCP servers or credentials, and authenticates with a fake key the proxy
// passes through to the fake provider.
func (d ClaudeDriver) Run(ctx context.Context, t matrix.Target, fake *fp.Server, checker *leak.Checker, s AgentSession, seeds []leak.Seed) Result {
	res := Result{Scenario: "claude/" + s.Name, API: fp.Anthropic, Stream: true, Driver: "claude"}
	bin := d.Bin
	if bin == "" {
		bin = "claude"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		res.Error = "claude not found: " + err.Error()
		return res
	}
	root, err := os.MkdirTemp("", "scrim-leak-claude-")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer func() { _ = os.RemoveAll(root) }()
	home, work := filepath.Join(root, "home"), filepath.Join(root, "work")
	byKind := seedsByKind(seeds)
	for rel, tmpl := range s.Files {
		content, err := Render(tmpl, byKind)
		if err == nil {
			err = os.MkdirAll(filepath.Dir(filepath.Join(work, rel)), 0o700)
		}
		if err == nil {
			err = os.WriteFile(filepath.Join(work, rel), []byte(content), 0o600)
		}
		if err != nil {
			res.Error = err.Error()
			return res
		}
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		res.Error = err.Error()
		return res
	}

	fake.Reset()
	fake.SetResponder(agentResponder(s.Commands))
	defer fake.SetResponder(nil)

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, "-p", s.Prompt, "--allowedTools", claudeTools(s.Commands), "--model", "claude-sonnet-4-5")
	cmd.Dir = work
	cmd.Stdin = strings.NewReader("")
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"ANTHROPIC_BASE_URL=" + strings.TrimRight(t.BaseURL, "/") + t.Prefix[fp.Anthropic],
		"ANTHROPIC_API_KEY=fake-provider-key-not-a-seed",
		"DISABLE_TELEMETRY=1",
		"DISABLE_AUTOUPDATER=1",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()

	ex := fake.Exchanges()
	var main []fp.Exchange
	for _, e := range ex {
		res.Findings = append(res.Findings, checker.WithSeeds(seeds).Check(e.Capture)...)
		if e.API == fp.Anthropic && strings.HasSuffix(e.Path, "/v1/messages") {
			main = append(main, e)
		}
	}
	res.Requests = len(ex)
	measureCache(&res, main)
	switch {
	case runErr != nil:
		res.Error = fmt.Sprintf("claude exited: %v", runErr)
	case len(main) < len(s.Commands)+1:
		res.Error = fmt.Sprintf("claude sent %d model requests, want %d (did the proxy refuse a request?)", len(main), len(s.Commands)+1)
	}
	res.Pass = res.Error == "" && len(res.Findings) == 0
	return res
}

// agentResponder asks for one command per assistant turn, then finishes.
// Requests without tools (titles, summaries) get a short text.
func agentResponder(cmds []string) fp.Responder {
	return func(t fp.Turn) fp.Reply {
		if _, ok := t.Body["tools"]; !ok {
			return fp.Reply{Text: "Leak audit"}
		}
		if t.Assistant < len(cmds) {
			return fp.Reply{Text: "Running " + strings.Fields(cmds[t.Assistant])[0] + ".", ToolCalls: []fp.ToolCall{{
				Name: "Bash", Input: map[string]any{"command": cmds[t.Assistant], "description": "Inspect the file"},
			}}}
		}
		return fp.Reply{Text: "Done."}
	}
}

func measureCache(res *Result, ex []fp.Exchange) {
	for i := 1; i < len(ex); i++ {
		res.CacheTurns++
		want := ex[i-1].PromptBytes
		got := min(ex[i].CachedBytes, want)
		res.CacheableBytes += want
		res.CachedBytes += got
		if got >= want {
			res.CacheHits++
		}
	}
	if res.CacheableBytes > 0 {
		res.CacheHitRate = float64(res.CachedBytes) / float64(res.CacheableBytes)
	}
}
