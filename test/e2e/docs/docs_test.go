// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

// Package docs runs the shell commands of the user documentation as written.
//
// Every fenced shell block (sh, bash, shell, console) in the documents below
// is either runnable, marked by "test" after the language:
//
//	```sh test [env|session|proxied|daemon] [exit=N]
//
// or excluded with the reason on the line above it:
//
//	<!-- docs-test: skip: downloads a release from GitHub -->
//
// A block with neither fails the test, so a new command cannot be documented
// without being run or explained. Runnable blocks run with bash -euo pipefail
// inside test/e2e/sandbox.sh (loopback only, no route out) with an empty HOME
// and XDG directories of their own, the scrim binary under test first on PATH,
// stub `claude` and `codex` agents that send one request to the base URL
// scrim gives them, and a fake model provider behind every provider route.
// The configuration is the README quickstart's, plus a writable `bao` store
// for the agent-tools examples and the sandbox's sockets and upstreams.
//
// Modes:
//   - (none): the block runs as is and must exit 0.
//   - env: the block's assignments are exported and `scrim config validate`
//     must accept them.
//   - session: the block runs as an agent would, under `scrim run -- bash`,
//     against a shared `scrim proxy` (so stores and approvals persist from
//     block to block of one document).
//   - proxied: the block runs as is while the shared `scrim proxy` is up.
//   - daemon: every command line is a long-running process: it is started,
//     must become ready (the agent API answers), and must exit 0 on SIGTERM.
//
// exit=N expects the block to exit with N instead of 0 (for example 4, the
// documented status of a request still pending approval).
//
// Run it with `just docs-test`.
package docs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.yaml.in/yaml/v4"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// Documents is every document whose shell blocks are checked, relative to the
// repository root.
var Documents = []string{
	"README.md",
	"docs/install.md",
	"docs/run.md",
	"docs/running.md",
	"docs/configuration.md",
	"docs/agent-tools.md",
	"docs/ca.md",
}

// Block is one fenced code block.
type Block struct {
	File  string
	Line  int // of the opening fence
	Lang  string
	Test  bool
	Mode  string
	Skip  string // reason, from the comment above
	Exit  int    // expected exit status
	Attrs []string
	Body  string
}

func (b Block) String() string { return fmt.Sprintf("%s:%d", b.File, b.Line) }

var (
	fence   = regexp.MustCompile("^(\\s*)(`{3,})\\s*(\\S*)\\s*(.*)$")
	skipTag = regexp.MustCompile(`^\s*<!--\s*docs-test:\s*skip:\s*(.+?)\s*-->\s*$`)
)

// Parse returns the fenced blocks of a Markdown document.
func Parse(file string, data []byte) ([]Block, error) {
	var out []Block
	var cur *Block
	var indent, ticks, prev string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if cur != nil {
			if m := fence.FindStringSubmatch(line); m != nil && m[2] == ticks && m[3] == "" {
				out = append(out, *cur)
				cur = nil
				continue
			}
			cur.Body += strings.TrimPrefix(line, indent) + "\n"
			continue
		}
		if m := fence.FindStringSubmatch(line); m != nil {
			indent, ticks = m[1], m[2]
			b := Block{File: file, Line: n, Lang: m[3], Attrs: strings.Fields(m[4])}
			if len(b.Attrs) > 0 && b.Attrs[0] == "test" {
				b.Test = true
				for _, a := range b.Attrs[1:] {
					if v, ok := strings.CutPrefix(a, "exit="); ok {
						code, err := strconv.Atoi(v)
						if err != nil {
							return nil, fmt.Errorf("%s:%d: bad %s", file, n, a)
						}
						b.Exit = code
						continue
					}
					b.Mode = a
				}
			}
			if s := skipTag.FindStringSubmatch(prev); s != nil {
				b.Skip = s[1]
			}
			cur = &b
			continue
		}
		if strings.TrimSpace(line) != "" {
			prev = line
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("%s:%d: unterminated code block", file, cur.Line)
	}
	return out, sc.Err()
}

// Shell reports whether a block holds shell commands.
func (b Block) Shell() bool {
	switch b.Lang {
	case "sh", "bash", "shell", "console":
		return true
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

func load(t *testing.T) map[string][]Block {
	t.Helper()
	root := repoRoot(t)
	out := map[string][]Block{}
	for _, f := range Documents {
		data, err := os.ReadFile(filepath.Join(root, f)) //nolint:gosec // the repository's own docs
		if err != nil {
			t.Fatal(err)
		}
		blocks, err := Parse(f, data)
		if err != nil {
			t.Fatal(err)
		}
		out[f] = blocks
	}
	return out
}

// TestEveryShellBlockIsClassified needs no sandbox: it is the gate that keeps
// new commands from being documented without a test or a reason.
func TestEveryShellBlockIsClassified(t *testing.T) {
	modes := map[string]bool{"": true, "env": true, "session": true, "proxied": true, "daemon": true}
	var runnable int
	for _, f := range Documents {
		for _, b := range load(t)[f] {
			switch {
			case b.Test && b.Skip != "":
				t.Errorf("%s: marked both test and skip", b)
			case b.Test && !modes[b.Mode]:
				t.Errorf("%s: unknown docs-test mode %q", b, b.Mode)
			case b.Test && !b.Shell():
				t.Errorf("%s: only shell blocks run (language %q)", b, b.Lang)
			case b.Shell() && !b.Test && b.Skip == "":
				t.Errorf("%s: shell block neither runs (```%s test) nor says why not (<!-- docs-test: skip: reason -->)", b, b.Lang)
			case b.Test:
				runnable++
			}
		}
	}
	t.Logf("%d runnable shell blocks", runnable)
}

func TestParse(t *testing.T) {
	doc := "# x\n\n<!-- docs-test: skip: needs the network -->\n\n```sh\ncurl x\n```\n\n" +
		"1. step\n\n   ```sh test session exit=4\n   scrim api whoami\n   ```\n\n```yaml\na: 1\n```\n"
	blocks, err := Parse("x.md", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 3 {
		t.Fatalf("%d blocks, want 3: %+v", len(blocks), blocks)
	}
	if b := blocks[0]; b.Skip != "needs the network" || b.Test || b.Body != "curl x\n" || b.Line != 5 {
		t.Errorf("first block %+v", b)
	}
	if b := blocks[1]; !b.Test || b.Mode != "session" || b.Exit != 4 || b.Body != "scrim api whoami\n" || b.Skip != "" {
		t.Errorf("second block %+v", b)
	}
	if b := blocks[2]; b.Shell() || b.Test {
		t.Errorf("third block %+v", b)
	}
}

// env is one document's sandbox: its own HOME and XDG directories, the
// configuration, the stubs and, while up, the shared `scrim proxy`.
type env struct {
	t     *testing.T
	bin   harness.Binaries
	dir   string
	home  string
	work  string
	stubs string
	seed  leak.Seed
	vars  []string
	proxy *exec.Cmd
	pdone chan error
	plog  *harness.SyncBuffer
}

const claudeStub = `#!/bin/sh
# A stand-in for Claude Code: one Messages request to the base URL scrim set.
set -eu
: "${ANTHROPIC_BASE_URL:?ANTHROPIC_BASE_URL is not set}"
curl -sS --fail-with-body -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
  -H 'x-api-key: fake-provider-key-not-a-seed' "$ANTHROPIC_BASE_URL/v1/messages" \
  --data "{\"model\":\"claude-sonnet-4-5\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"the token is ${SCRIM_SECRET_GITHUB_TOKEN:-unset}\"}]}"
echo
`

const codexStub = `#!/bin/sh
# A stand-in for the Codex CLI: one Responses request to the openai_base_url
# scrim passes with -c.
set -eu
base=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -c) shift; case "$1" in openai_base_url=*) base=${1#openai_base_url=}; base=${base#\"}; base=${base%\"} ;; esac ;;
  esac
  shift
done
: "${base:?no -c openai_base_url}"
curl -sS --fail-with-body -H 'content-type: application/json' -H 'authorization: Bearer fake-provider-key-not-a-seed' \
  "$base/responses" \
  --data "{\"model\":\"gpt-5.1-codex\",\"input\":[{\"role\":\"user\",\"content\":\"the token is ${SCRIM_SECRET_GITHUB_TOKEN:-unset}\"}]}"
echo
`

func newEnv(t *testing.T, bin harness.Binaries, upstream string, blocks []Block) *env {
	t.Helper()
	// Unix socket paths are short: keep the directory out of t.TempDir().
	dir, err := os.MkdirTemp("", "scrim-docs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e := &env{t: t, bin: bin, dir: dir, home: filepath.Join(dir, "home"), work: filepath.Join(dir, "work"),
		stubs: filepath.Join(dir, "stubs"), seed: leak.Generate(leak.KindGitHubToken)}
	for _, d := range []string{e.home, e.work, e.stubs, filepath.Join(dir, "bin"), filepath.Join(e.home, ".config/scrim")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// scrim from the build under test, as `scrim` on PATH.
	if err := os.Symlink(bin.Scrim, filepath.Join(dir, "bin", "scrim")); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"claude": claudeStub, "codex": codexStub} {
		if err := os.WriteFile(filepath.Join(e.stubs, name), []byte(body), 0o700); err != nil { //nolint:gosec // test stub
			t.Fatal(err)
		}
	}
	e.vars = []string{
		"PATH=" + filepath.Join(dir, "bin") + string(os.PathListSeparator) + e.stubs + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + e.home,
		"TERM=dumb",
		"LANG=C.UTF-8",
		"XDG_CONFIG_HOME=" + filepath.Join(e.home, ".config"),
		"XDG_STATE_HOME=" + filepath.Join(e.home, ".local/state"),
		"XDG_DATA_HOME=" + filepath.Join(e.home, ".local/share"),
		"XDG_CACHE_HOME=" + filepath.Join(e.home, ".cache"),
		"SCRIM_DATAPLANE_PATH=" + bin.DataPlane,
		"SCRIM_SECRET_GITHUB_TOKEN=" + e.seed.Value(),
	}
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
		e.vars = append(e.vars, "XDG_RUNTIME_DIR="+v)
	}
	e.writeConfig(upstream, blocks)
	return e
}

// writeConfig writes the README quickstart's configuration (the yaml block
// marked "config") to ~/.config/scrim/config.yaml with the sandbox's
// additions.
func (e *env) writeConfig(upstream string, readme []Block) {
	t := e.t
	var base string
	for _, b := range readme {
		if b.Lang == "yaml" && len(b.Attrs) > 0 && b.Attrs[0] == "config" {
			base = b.Body
		}
	}
	if base == "" {
		t.Fatal("README.md has no ```yaml config block (the quickstart configuration)")
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(base), &cfg); err != nil {
		t.Fatalf("the README quickstart configuration is not YAML: %v", err)
	}
	stores, _ := cfg["stores"].(map[string]any)
	if stores == nil {
		t.Fatal("the README quickstart configuration has no stores")
	}
	// The agent-tools examples use references under bao://kv/agents/.
	stores["bao"] = map[string]any{"kind": "memory"}
	// Sockets in the sandbox directory, never the user's runtime directory,
	// so no scrim the user runs is reached.
	cfg["api"] = map[string]any{"socket": filepath.Join(e.dir, "api.sock")}
	cfg["admin"] = map[string]any{"url": "unix:" + filepath.Join(e.dir, "admin.sock")}
	cfg["notify"] = map[string]any{"terminal": map[string]any{"enabled": false}}
	proxy, _ := cfg["proxy"].(map[string]any)
	if proxy == nil {
		proxy = map[string]any{}
		cfg["proxy"] = proxy
	}
	proxy["upstream"] = map[string]any{"anthropic": upstream, "openai": upstream}
	rules := filepath.Join(e.dir, "rules.yaml")
	// Agents may use their tools, write and generate secrets under
	// bao://kv/agents/, and ask for grants, which a person approves.
	if err := os.WriteFile(rules, []byte(`default: deny
rules:
  - name: docs-agent-tools
    decision: allow
    when: op == "mcp.tool" && agent.kind == "session"
  - name: docs-agents-write
    decision: allow
    when: op in ["store.write", "secret.gen"] && secret.ref.startsWith("bao://kv/agents/")
  - name: docs-agents-grant
    decision: ask
    when: op == "grant" && secret.ref.startsWith("bao://kv/agents/")
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg["policy"] = map[string]any{"rules-file": rules}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.home, ".config/scrim/config.yaml"), out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// command is bash -euo pipefail -c script in the document's work directory.
func (e *env) command(ctx context.Context, script string, extra ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "bash", "-euo", "pipefail", "-c", script)
	cmd.Dir = e.work
	cmd.Env = append(append([]string{}, e.vars...), extra...)
	cmd.Stdin = strings.NewReader("")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return cmd
}

func (e *env) run(b Block, script string) {
	t := e.t
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := e.command(ctx, script).CombinedOutput()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Errorf("%s: %v", b, err)
		return
	}
	if code != b.Exit {
		t.Errorf("%s: exit status %d, want %d\n--- block\n%s--- output\n%s", b, code, b.Exit, b.Body, out)
		return
	}
	t.Logf("%s: ok\n%s", b, indent(out))
}

// ready waits until the process is ready or done closes: for `scrim proxy`
// until the admin API reports it ready (its data plane holds a snapshot and
// every listener is bound), for anything else until the agent API answers.
func (e *env) ready(script string, done <-chan error, log *harness.SyncBuffer) error {
	probe := func(ctx context.Context) error { return e.command(ctx, "scrim api whoami >/dev/null 2>&1").Run() }
	if strings.HasPrefix(script, "scrim proxy") {
		probe = e.daemonReady
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			return fmt.Errorf("exited before it was ready (%w):\n%s", err, log.String())
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := probe(ctx)
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("not ready after 90s:\n%s", log.String())
}

// daemonReady asks the admin API whether the daemon is ready.
func (e *env) daemonReady(ctx context.Context) error {
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(e.dir, "admin.sock"))
	}}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://scrim/v1/daemon", nil)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var info struct {
		Ready bool `json:"ready"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return err
	}
	if !info.Ready {
		return errors.New("not ready")
	}
	return nil
}

// start runs a long-running command and waits until it is ready.
func (e *env) start(script string) (*exec.Cmd, chan error, *harness.SyncBuffer, error) {
	log := &harness.SyncBuffer{}
	cmd := e.command(context.Background(), "exec "+script)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if err := e.ready(script, done, log); err != nil {
		_ = cmd.Process.Kill()
		return nil, nil, log, err
	}
	return cmd, done, log, nil
}

// stop sends SIGTERM and wants exit 0.
func stop(cmd *exec.Cmd, done chan error) error {
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		if err := <-done; err != nil {
			return fmt.Errorf("did not exit within 30s of SIGTERM, killed: %w", err)
		}
		return errors.New("did not exit within 30s of SIGTERM")
	}
}

func (e *env) ensureProxy() {
	if e.proxy != nil {
		return
	}
	cmd, done, log, err := e.start("scrim proxy")
	if err != nil {
		e.t.Fatalf("shared scrim proxy: %v", err)
	}
	e.proxy, e.pdone, e.plog = cmd, done, log
	// The memory store starts empty: put the secrets the agent-tools
	// examples name.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	seed := "for r in bao://kv/agents/github bao://kv/agents/hetzner; do\n" +
		"  head -c 24 /dev/urandom | base64 | scrim secret put \"$r\" --stdin\n" +
		"done"
	if out, err := e.command(ctx, "exec scrim run -- bash -euo pipefail -c "+shellQuote(seed)).CombinedOutput(); err != nil {
		e.t.Fatalf("seeding the bao store: %v\n%s", err, out)
	}
}

func (e *env) stopProxy() {
	if e.proxy == nil {
		return
	}
	if err := stop(e.proxy, e.pdone); err != nil {
		e.t.Errorf("shared scrim proxy: %v\n%s", err, e.plog.String())
	}
	e.proxy = nil
}

// commands splits a block into its command lines: comments and blank lines
// dropped, backslash continuations joined.
func commands(body string) []string {
	var out []string
	var cur strings.Builder
	for line := range strings.SplitSeq(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if cur.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if s, ok := strings.CutSuffix(line, "\\"); ok {
			cur.WriteString(s)
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	return out
}

func (e *env) block(b Block) {
	t := e.t
	switch b.Mode {
	case "":
		e.run(b, b.Body)
	case "env":
		e.run(b, "set -a\n"+b.Body+"set +a\nscrim config validate")
	case "session":
		e.ensureProxy()
		e.run(b, "exec scrim run -- bash -euo pipefail -c "+shellQuote(b.Body))
	case "proxied":
		e.ensureProxy()
		e.run(b, b.Body)
	case "daemon":
		e.stopProxy()
		for _, c := range commands(b.Body) {
			cmd, done, log, err := e.start(c)
			if err != nil {
				t.Errorf("%s: %s: %v", b, c, err)
				continue
			}
			if err := stop(cmd, done); err != nil {
				t.Errorf("%s: %s: %v\n%s", b, c, err, log.String())
				continue
			}
			t.Logf("%s: %s: ready, stopped cleanly", b, c)
		}
	}
}

func TestDocumentedCommands(t *testing.T) {
	bin := harness.Require(t)
	harness.LookPath(t, "curl")
	docs := load(t)
	fake := fp.New(fp.Options{})
	provider := httptest.NewServer(fake)
	t.Cleanup(provider.Close)

	var seeds []leak.Seed
	for _, f := range Documents {
		t.Run(f, func(t *testing.T) {
			e := newEnv(t, bin, provider.URL, docs["README.md"])
			seeds = append(seeds, e.seed)
			defer e.stopProxy()
			for _, b := range docs[f] {
				if b.Test {
					e.block(b)
				}
			}
		})
	}

	// No request the agents made may hold the secret scrim was told about.
	checker := leak.NewChecker(seeds)
	ex := fake.Exchanges()
	for _, x := range ex {
		if f := checker.Check(x.Capture); len(f) > 0 {
			t.Errorf("provider request %d (%s) holds the seeded token", x.Seq, x.Path)
		}
	}
	if len(ex) == 0 {
		t.Error("no documented command reached the fake provider")
	}
	t.Logf("%d provider requests, none with the seeded token unless reported above", len(ex))
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func indent(b []byte) string {
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return ""
	}
	return "    " + strings.ReplaceAll(s, "\n", "\n    ")
}
