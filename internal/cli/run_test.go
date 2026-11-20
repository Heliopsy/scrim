// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/localapi/localapitest"
	agentrun "github.com/heliopsy/scrim/internal/run"
)

const testCA = "-----BEGIN CERTIFICATE-----\nc2NyaW0tdGVzdA==\n-----END CERTIFICATE-----\n"

func withDaemon(t *testing.T, d agentrun.Daemon) {
	t.Helper()
	old := runDaemon
	runDaemon = func(context.Context, *Env) (agentrun.Daemon, error) { return d, nil }
	t.Cleanup(func() { runDaemon = old })
}

func fixedDaemon(ts *localapitest.Server) agentrun.Daemon {
	return agentrun.Fixed{Instance: &agentrun.Static{EP: agentrun.Endpoints{
		APISocket: ts.Socket, LLMBaseURL: "http://127.0.0.1:9790",
		ForwardProxy: "http://127.0.0.1:9791", CACertPEM: []byte(testCA),
	}}}
}

func runScrim(environ []string, args ...string) result {
	var out, errb bytes.Buffer
	e := &Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Registry: config.Default, Environ: environ}
	code := Run(context.Background(), e, args)
	return result{stdout: out.String(), stderr: errb.String(), code: code}
}

func runEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	home := t.TempDir()
	return append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "XDG_CONFIG_HOME=" + home, "XDG_RUNTIME_DIR=" + home}, extra...)
}

func TestRunPrintEnv(t *testing.T) {
	ts := cliServer(t)
	withDaemon(t, fixedDaemon(ts))
	env := runEnv(t, `SCRIM_CATALOG_ENTRIES={"acme":{"ref":"bao://kv/agents/acme#key","hosts":["api.acme.example"],"placeholder":"SCRIM_ACME_KEY"}}`)
	r := runScrim(env, "run", "--print-env", "--", "claude", "-p", "hi")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{
		"preset   claude",
		"command  claude --mcp-config=<session-dir>/mcp.json -p hi",
		"ANTHROPIC_BASE_URL=http://127.0.0.1:9790/anthropic",
		"OPENAI_BASE_URL=http://127.0.0.1:9790/openai/v1",
		"HTTPS_PROXY=http://127.0.0.1:9791",
		"NODE_EXTRA_CA_CERTS=<session-dir>/scrim-ca.pem",
		"SCRIM_SESSION_TOKEN=<secret>",
		"SCRIM_ACME_KEY=SCRIM_ACME_KEY",
		"SCRIM_API_SOCKET=" + ts.Socket,
		"ca-bundle.pem",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("print-env lacks %q:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "scrim_st_") {
		t.Error("print-env printed a token")
	}

	r = runScrim(env, "run", "--print-env", "-o", "json", "--run-mcp=false", "--", "codex", "exec", "x")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var plan struct {
		Preset string `json:"preset"`
		Args   []string
		Set    []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Secret bool   `json:"secret"`
		} `json:"set"`
		Files []string `json:"files"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &plan); err != nil {
		t.Fatalf("%v\n%s", err, r.stdout)
	}
	if plan.Preset != "codex" || strings.Contains(strings.Join(plan.Args, " "), "mcp_servers") {
		t.Errorf("plan %+v", plan)
	}
	for _, v := range plan.Set {
		if v.Name == "SCRIM_SESSION_TOKEN" && (!v.Secret || v.Value != "") {
			t.Errorf("token in JSON: %+v", v)
		}
	}
}

func TestRunRefusesWithoutDaemon(t *testing.T) {
	// The default daemon on this build is unavailable.
	r := runScrim(runEnv(t), "run", "--", "sh", "-c", "echo started")
	if r.code != ExitRunRefused || strings.Contains(r.stdout, "started") {
		t.Fatalf("exit %d stdout %q", r.code, r.stdout)
	}
	if !strings.Contains(r.stderr, "the agent was not started") || !strings.Contains(r.stderr, "run.allow-unredacted-start") {
		t.Errorf("stderr %q", r.stderr)
	}
	r = runScrim(runEnv(t), "run", "--run-allow-unredacted-start", "--", "sh", "-c", "echo started")
	if r.code != 0 || !strings.Contains(r.stdout, "started") || !strings.Contains(r.stderr, "WITHOUT scrim") {
		t.Fatalf("weakened: exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
}

func TestRunPropagatesExitCode(t *testing.T) {
	ts := cliServer(t)
	withDaemon(t, fixedDaemon(ts))
	// Flags after the agent's name belong to the agent.
	r := runScrim(runEnv(t), "run", "sh", "-c", `test -n "$SCRIM_SESSION_TOKEN" && test -f "$SSL_CERT_FILE" && exit 3`)
	if r.code != 3 {
		t.Fatalf("exit %d, want 3: %s", r.code, r.stderr)
	}
	r = runScrim(runEnv(t), "run", "--agent", "nope", "--", "sh")
	if r.code != ExitRunRefused || !strings.Contains(r.stderr, "unknown agent preset") {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
}
