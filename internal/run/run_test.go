// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/localapi"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

func selfAgent(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func seedFile(t *testing.T, seeds []leak.Seed) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("# service settings\n")
	for i, s := range seeds {
		b.WriteString("KEY_" + string(rune('A'+i)) + "=" + s.Value() + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestRunTinyAgentThroughScrim is the wrapper end to end with a tiny agent:
// the provider sees placeholders only, the agent's tool call goes through
// the forward proxy trusting the session CA, the agent's identity is its
// session, the exit code comes back and the session ends.
func TestRunTinyAgentThroughScrim(t *testing.T) {
	h := newHarness(t, true)
	work := seedFile(t, h.seeds)
	rt := t.TempDir()
	var out, errb syncBuf
	err := Run(context.Background(), Options{
		Command: []string{selfAgent(t)},
		Environ: baseEnv(t, envAgent+"=llm", "TEST_TOOL_URL=https://tool.test/", "ANTHROPIC_BASE_URL=https://api.anthropic.com"),
		Dir:     work, Daemon: h.daemon(), Stdout: &out, Stderr: &errb, RuntimeDir: rt,
	})
	var xe *ExitError
	if !errors.As(err, &xe) || xe.Code != 7 {
		t.Fatalf("want agent exit 7, got %v\nstdout: %s\nstderr: %s", err, out.String(), errb.String())
	}

	ex := h.fake.Exchanges()
	apis := map[fp.API]bool{}
	for _, e := range ex {
		apis[e.API] = true
		if len(e.Placeholders) == 0 {
			t.Errorf("%s request carries no placeholder", e.API)
		}
	}
	if !apis[fp.Anthropic] || !apis[fp.OpenAIChat] {
		t.Fatalf("provider saw %v, want both APIs", apis)
	}
	checker := leak.NewChecker(h.seeds)
	for _, e := range ex {
		if f := checker.Check(e.Capture); len(f) > 0 {
			t.Errorf("%d leak findings in the %s request: %+v", len(f), e.API, f)
		}
	}

	m := regexp.MustCompile(`session=(\S+) agent=dev`).FindStringSubmatch(out.String())
	if m == nil || m[1] == "" {
		t.Fatalf("agent was not identified by a session: %q", out.String())
	}
	sess, err := h.api.Sessions.Get(context.Background(), m[1])
	if err != nil {
		t.Fatal(err)
	}
	if sess.RevokedAt.IsZero() {
		t.Error("session not ended after the agent exited")
	}
	if !strings.Contains(out.String(), "tool=tool-ok") || !slices.Contains(h.tunnels(), "tool.test:443") {
		t.Errorf("tool call did not go through the forward proxy: tunnels %v, stdout %q", h.tunnels(), out.String())
	}
	if !strings.Contains(errb.String(), "ANTHROPIC_BASE_URL from your environment is replaced") {
		t.Errorf("no warning about the replaced base URL: %q", errb.String())
	}
	for _, s := range h.seeds {
		for _, o := range []string{out.String(), errb.String()} {
			if strings.Contains(o, s.Value()) {
				t.Errorf("seed %s in scrim run output", s.Name)
			}
		}
	}
	if strings.Contains(out.String()+errb.String(), "scrim_st_") {
		t.Error("session token in output")
	}
	if left, _ := os.ReadDir(rt); len(left) != 0 {
		t.Errorf("session directory left behind: %v", left)
	}
}

func TestRunEnvironmentSeenByTheAgent(t *testing.T) {
	h := newHarness(t, true)
	var out syncBuf
	err := Run(context.Background(), Options{
		Command: []string{selfAgent(t)}, Daemon: h.daemon(), Stdout: &out, RuntimeDir: t.TempDir(),
		Environ: baseEnv(t, envAgent+"=env", "ALL_PROXY=socks5://127.0.0.1:1", "SCRIM_ACME_KEY=stale"),
		Placeholders: func(context.Context, string) ([]string, error) {
			return []string{"SCRIM_ACME_KEY", "SCRIM_API_SOCKET"}, nil
		},
		Reserved: func(n string) bool { return n == "SCRIM_API_SOCKET" },
	})
	if err != nil {
		t.Fatal(err)
	}
	env := envMap(strings.Split(strings.TrimSpace(out.String()), "\n"))
	want := map[string]string{
		"ANTHROPIC_BASE_URL":     h.llm.URL + "/anthropic",
		"OPENAI_BASE_URL":        h.llm.URL + "/openai/v1",
		"GOOGLE_GEMINI_BASE_URL": h.llm.URL + "/gemini",
		"HTTPS_PROXY":            strings.Replace(h.ep.ForwardProxy, "http://", "http://"+env[EnvSessionID]+":"+TokenMarker+"@", 1),
		"https_proxy":            strings.Replace(h.ep.ForwardProxy, "http://", "http://"+env[EnvSessionID]+":"+TokenMarker+"@", 1),
		"NO_PROXY":               "localhost,127.0.0.1,::1",
		"SCRIM_API_SOCKET":       h.api.Socket,
		"SCRIM_ACME_KEY":         "SCRIM_ACME_KEY",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
	if _, ok := env["ALL_PROXY"]; ok {
		t.Error("ALL_PROXY kept")
	}
	if !regexp.MustCompile(`^<\d+ bytes>$`).MatchString(env[localapi.EnvToken]) {
		t.Errorf("no session token: %q", env[localapi.EnvToken])
	}
	if env[EnvSessionID] == "" {
		t.Error("no session ID")
	}
	for _, v := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO"} {
		if !strings.HasSuffix(env[v], ".pem") {
			t.Errorf("%s = %q", v, env[v])
		}
	}
}

func TestRunFailsClosed(t *testing.T) {
	h := newHarness(t, false)
	marker := filepath.Join(t.TempDir(), "started")
	// The agent would leave a marker if it ran.
	cmd := []string{"sh", "-c", "touch " + marker}
	cases := map[string]Options{
		"no daemon":   {Daemon: Unavailable{Reason: "cannot start"}},
		"not ready":   {Daemon: Fixed{Instance: &Static{EP: h.ep, ReadyFn: func(context.Context) error { return errors.New("no snapshot") }}}},
		"no base URL": {Daemon: Fixed{Instance: &Static{EP: Endpoints{APISocket: h.api.Socket}}}},
		"no API":      {Daemon: Fixed{Instance: &Static{EP: Endpoints{APISocket: filepath.Join(t.TempDir(), "none.sock"), LLMBaseURL: h.llm.URL}}}},
		"nested":      {Daemon: h.daemon(), Environ: baseEnv(t, localapi.EnvToken+"=scrim_st_x_y")},
		"caveman":     {Daemon: h.daemon(), Command: []string{"caveman", "claude"}},
		"bedrock":     {Daemon: h.daemon(), Command: []string{"claude"}, Environ: baseEnv(t, "CLAUDE_CODE_USE_BEDROCK=1")},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			if o.Command == nil {
				o.Command = cmd
			}
			if o.Environ == nil {
				o.Environ = baseEnv(t)
			}
			o.RuntimeDir = t.TempDir()
			err := Run(context.Background(), o)
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("want ErrRefused, got %v", err)
			}
			if _, serr := os.Stat(marker); serr == nil {
				t.Fatal("the agent was started")
			}
			if left, _ := os.ReadDir(o.RuntimeDir); len(left) != 0 {
				t.Errorf("session directory left behind: %v", left)
			}
		})
	}
}

func TestRunAllowUnredactedStart(t *testing.T) {
	var out, errb syncBuf
	err := Run(context.Background(), Options{
		Command: []string{selfAgent(t)}, Environ: baseEnv(t, envAgent+"=env", "ANTHROPIC_BASE_URL=https://api.anthropic.com"),
		Daemon: Unavailable{Reason: "cannot start"}, AllowUnredacted: true, Stdout: &out, Stderr: &errb,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errb.String(), "WITHOUT scrim") {
		t.Errorf("no warning: %q", errb.String())
	}
	env := envMap(strings.Split(strings.TrimSpace(out.String()), "\n"))
	if env["ANTHROPIC_BASE_URL"] != "https://api.anthropic.com" || env[localapi.EnvToken] != "" {
		t.Errorf("unprotected run changed the environment: %v", env)
	}
}

func TestRunForwardsSignalsAndPropagatesStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM forwarding is Unix only")
	}
	h := newHarness(t, false)
	sigs := make(chan os.Signal, 1)
	done := make(chan error, 1)
	var out syncBuf
	go func() {
		done <- Run(context.Background(), Options{Command: []string{selfAgent(t)}, Environ: baseEnv(t, envAgent+"=sleep"),
			Daemon: h.daemon(), Signals: sigs, Stdout: &out, RuntimeDir: t.TempDir()})
	}()
	// Wait until the agent runs: its session exists.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !h.hasLiveSession(t) {
		time.Sleep(20 * time.Millisecond)
	}
	sigs <- syscall.SIGTERM
	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not stop on SIGTERM")
	}
	var xe *ExitError
	if !errors.As(err, &xe) || xe.Code != 128+int(syscall.SIGTERM) || xe.Signal != "SIGTERM" {
		t.Fatalf("want exit 143 by SIGTERM, got %v", err)
	}
	if h.hasLiveSession(t) {
		t.Error("session still live after the agent was stopped")
	}
}

func (h *harness) hasLiveSession(t *testing.T) bool {
	t.Helper()
	for _, e := range h.api.Audit.All() {
		if e.Tool != "session_mint" || e.SessionID == "" {
			continue
		}
		s, err := h.api.Sessions.Get(context.Background(), e.SessionID)
		if err != nil {
			t.Fatal(err)
		}
		if !s.Revoked() {
			return true
		}
	}
	return false
}

func TestRunAgentNotFound(t *testing.T) {
	h := newHarness(t, false)
	err := Run(context.Background(), Options{Command: []string{"scrim-no-such-agent"}, Environ: baseEnv(t),
		Daemon: h.daemon(), RuntimeDir: t.TempDir()})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("got %v", err)
	}
	if h.hasLiveSession(t) {
		t.Error("session left live")
	}
}

func TestPrintEnvMintsNothing(t *testing.T) {
	h := newHarness(t, true)
	rt := t.TempDir()
	plan, err := PrintEnv(context.Background(), Options{Command: []string{"claude", "-p", "hi"}, Environ: baseEnv(t),
		Daemon: h.daemon(), MCP: true, ScrimPath: "/usr/bin/scrim", RuntimeDir: rt})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Preset != "claude" || filepath.ToSlash(plan.Args[1]) != "--mcp-config=<session-dir>/mcp.json" {
		t.Errorf("plan %+v", plan)
	}
	if h.hasLiveSession(t) {
		t.Error("print-env minted a session")
	}
	if left, _ := os.ReadDir(rt); len(left) != 0 {
		t.Errorf("print-env wrote %v", left)
	}
}

// Ensure the agent sees exec errors from a non-executable file as refusal.
func TestLookPathUsesAgentPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "myagent")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := lookPath("myagent", []string{"PATH=" + dir})
	if err != nil || got != bin {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := exec.LookPath("sh"); err == nil {
		if _, err := lookPath("sh", []string{"PATH=" + dir}); err == nil {
			t.Error("found sh outside the agent's PATH")
		}
	}
}
