// SPDX-License-Identifier: AGPL-3.0-only

package scenario

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// Agents names the real agent CLIs an [AgentDriver] runs.
var Agents = []string{"claude", "codex", "opencode"}

// fakeKey is the provider key the agents authenticate with. The proxy passes
// it through to the fake provider; it is not a seed.
const fakeKey = "fake-provider-key-not-a-seed"

// Models the agents are started with. The fake provider answers any model;
// these are names each CLI knows, so it starts without fetching a catalogue.
const (
	claudeModel   = "claude-sonnet-4-5"
	codexModel    = "gpt-5.1-codex"
	opencodeModel = "anthropic/claude-sonnet-4-6"
)

// AgentDriver runs a real agent CLI through the proxy: Claude Code
// (`claude -p`), Codex (`codex exec`) or OpenCode (`opencode run`).
type AgentDriver struct {
	// Agent is one of [Agents].
	Agent string
	// Bin is the agent's binary; default the agent's name from PATH.
	Bin string
	// Timeout bounds one session. Default 3 minutes.
	Timeout time.Duration
	// Output, when set, receives the agent's output of a session that
	// failed, for debugging a test. It may hold seeded values the agent
	// read, so `scrim audit run` never sets it: its report holds none.
	Output io.Writer
}

// agent is what differs between the agent CLIs.
type agent struct {
	// api is the provider API the agent talks in the sessions.
	api fp.API
	// invoke returns the agent's arguments and its own environment for a
	// session; base is the proxy URL with the API's route prefix.
	invoke func(base string, s AgentSession) (args, env []string, err error)
	// shell is a call of the agent's shell tool, chosen from the tools the
	// request offers.
	shell func(tools []string, command string) (fp.ToolCall, bool)
	// turn is the index of the next command for a request.
	turn func(fp.Turn) int
}

var agents = map[string]agent{
	"claude": {
		api: fp.Anthropic,
		invoke: func(base string, s AgentSession) ([]string, []string, error) {
			return []string{"-p", s.Prompt, "--allowedTools", claudeTools(s.Commands), "--model", claudeModel},
				[]string{
					"ANTHROPIC_BASE_URL=" + base,
					"ANTHROPIC_API_KEY=" + fakeKey,
					"DISABLE_TELEMETRY=1",
					"DISABLE_AUTOUPDATER=1",
					"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
				}, nil
		},
		shell: namedShell("Bash"),
		turn:  func(t fp.Turn) int { return t.Assistant },
	},
	"codex": {
		api: fp.OpenAIResponses,
		invoke: func(base string, s AgentSession) ([]string, []string, error) {
			// openai_base_url is the built-in provider's base URL; Codex
			// ignores OPENAI_BASE_URL. Approvals have no terminal to ask on,
			// and Codex's own sandbox needs namespaces a CI runner may not
			// allow: the commands are the session's, in a scratch directory.
			return []string{
				"-c", "openai_base_url=" + string(marshal(base+"/v1")),
				"-c", "check_for_update_on_startup=false",
				"exec", "--skip-git-repo-check", "--color", "never",
				"--dangerously-bypass-approvals-and-sandbox",
				"-m", codexModel, s.Prompt,
			}, []string{
				"CODEX_API_KEY=" + fakeKey,
			}, nil
		},
		shell: CodexShell,
		// Codex chains WebSocket turns by previous_response_id; the fake
		// provider counts the tool results of the whole chain.
		turn: func(t fp.Turn) int { return t.ToolResults },
	},
	"opencode": {
		api: fp.Anthropic,
		invoke: func(base string, s AgentSession) ([]string, []string, error) {
			// OPENCODE_CONFIG_CONTENT is merged over every configuration
			// file, so the base URL holds whatever the empty HOME finds.
			cfg, err := json.Marshal(map[string]any{
				"$schema":           "https://opencode.ai/config.json",
				"enabled_providers": []string{"anthropic"},
				"provider": map[string]any{"anthropic": map[string]any{
					"options": map[string]any{"baseURL": base + "/v1"},
				}},
				"permission": map[string]any{"bash": "allow"},
				"autoupdate": false,
			})
			if err != nil {
				return nil, nil, err
			}
			return []string{"run", "--pure", "-m", opencodeModel, s.Prompt}, []string{
				"OPENCODE_CONFIG_CONTENT=" + string(cfg),
				"ANTHROPIC_API_KEY=" + fakeKey,
				"OPENCODE_DISABLE_AUTOUPDATE=1",
				"OPENCODE_DISABLE_MODELS_FETCH=1",
				"OPENCODE_DISABLE_LSP_DOWNLOAD=1",
			}, nil
		},
		shell: namedShell("bash"),
		turn:  func(t fp.Turn) int { return t.ToolResults },
	},
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

// namedShell calls a shell tool that takes {command, description}, as
// Claude Code's Bash and OpenCode's bash do.
func namedShell(name string) func([]string, string) (fp.ToolCall, bool) {
	return func(tools []string, command string) (fp.ToolCall, bool) {
		if !slices.Contains(tools, name) {
			return fp.ToolCall{}, false
		}
		return fp.ToolCall{Name: name, Input: map[string]any{"command": command, "description": "Inspect the file"}}, true
	}
}

// CodexShell is a call of the shell tool Codex offers. Codex names it
// differently across releases and model families.
func CodexShell(tools []string, command string) (fp.ToolCall, bool) {
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

// ToolNames lists the function tools of a request in the Anthropic, Chat
// Completions, Responses or Gemini shape. A tool inside a namespace tool
// (Codex puts each MCP server's tools in one) is listed as namespace/name.
func ToolNames(body map[string]any) []string {
	list, _ := body["tools"].([]any)
	var out []string
	for _, it := range list {
		m, _ := it.(map[string]any)
		if decls, ok := m["functionDeclarations"].([]any); ok {
			for _, d := range decls {
				dm, _ := d.(map[string]any)
				if name, _ := dm["name"].(string); name != "" {
					out = append(out, name)
				}
			}
			continue
		}
		name, _ := m["name"].(string)
		if fn, ok := m["function"].(map[string]any); ok && name == "" {
			name, _ = fn["name"].(string)
		}
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

// Run plays one session with the agent. The agent runs with an empty HOME
// in a scratch workspace, so it reads none of the user's settings, hooks, MCP
// servers or credentials, and authenticates with a fake key the proxy passes
// through to the fake provider.
func (d AgentDriver) Run(ctx context.Context, t matrix.Target, fake *fp.Server, checker *leak.Checker, s AgentSession, seeds []leak.Seed) Result {
	ag, ok := agents[d.Agent]
	res := Result{Scenario: d.Agent + "/" + s.Name, API: ag.api, Stream: true, Driver: d.Agent}
	if !ok {
		res.Error = fmt.Sprintf("unknown agent %q (%s)", d.Agent, strings.Join(Agents, ", "))
		return res
	}
	bin := d.Bin
	if bin == "" {
		bin = d.Agent
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		res.Error = d.Agent + " not found: " + err.Error()
		return res
	}
	root, err := os.MkdirTemp("", "scrim-leak-"+d.Agent+"-")
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
	base := strings.TrimRight(t.BaseURL, "/") + t.Prefix[ag.api]
	args, env, err := ag.invoke(base, s)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	fake.Reset()
	fake.SetResponder(agentResponder(ag, s.Commands))
	defer fake.SetResponder(nil)

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, args...)
	cmd.Dir = work
	cmd.Stdin = strings.NewReader("")
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_DATA_HOME=" + filepath.Join(home, ".local", "share"),
		"XDG_STATE_HOME=" + filepath.Join(home, ".local", "state"),
		"XDG_CACHE_HOME=" + filepath.Join(home, ".cache"),
	}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()

	ex := fake.Exchanges()
	var main []fp.Exchange
	for _, e := range ex {
		res.Findings = append(res.Findings, checker.WithSeeds(seeds).Check(e.Capture)...)
		if e.Status == 200 && offersTools(e.Body) {
			main = append(main, e)
		}
	}
	if len(main) > 0 {
		// Codex talks the Responses API over WebSocket when it can.
		res.API = main[0].API
	}
	res.Requests = len(ex)
	// Over a WebSocket each message carries only the new input and chains
	// to the previous response, so there is no prompt prefix to measure.
	if !res.API.WebSocket() {
		measureCache(&res, main)
	}
	switch {
	case runErr != nil:
		res.Error = fmt.Sprintf("%s exited: %v", d.Agent, runErr)
	case len(main) < len(s.Commands)+1:
		res.Error = fmt.Sprintf("%s sent %d model requests, want %d (did the proxy refuse a request?)",
			d.Agent, len(main), len(s.Commands)+1)
	}
	if res.Error != "" && d.Output != nil {
		_, _ = d.Output.Write(out.Bytes())
	}
	res.Pass = res.Error == "" && len(res.Findings) == 0
	return res
}

// offersTools reports whether a recorded request (or WebSocket
// response.create message) offers the model tools: the agent's own turns, as
// opposed to titles and summaries.
func offersTools(body []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	if _, ok := m["tools"]; ok {
		return true
	}
	var inner map[string]json.RawMessage
	if r, ok := m["response"]; ok && json.Unmarshal(r, &inner) == nil {
		_, ok := inner["tools"]
		return ok
	}
	return false
}

// agentResponder asks for one command per assistant turn, then finishes.
// Requests without tools (titles, summaries) get a short text.
func agentResponder(ag agent, cmds []string) fp.Responder {
	return func(t fp.Turn) fp.Reply {
		tools := ToolNames(t.Body)
		if len(tools) == 0 {
			return fp.Reply{Text: "Leak audit"}
		}
		n := ag.turn(t)
		if n >= len(cmds) {
			return fp.Reply{Text: "Done."}
		}
		call, ok := ag.shell(tools, cmds[n])
		if !ok {
			return fp.Reply{Text: "No shell tool offered: " + strings.Join(tools, ",")}
		}
		return fp.Reply{Text: "Running " + strings.Fields(cmds[n])[0] + ".", ToolCalls: []fp.ToolCall{call}}
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
