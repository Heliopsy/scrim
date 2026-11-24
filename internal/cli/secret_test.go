// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/localapi/localapitest"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Generated test values, never real secrets.
var (
	cliSeeded   = []byte("ghp_TESTc0ffee0123456789abcdef0123456789")
	cliPiped    = []byte("piped-test-value-4b3a2918")
	cliCaptured = []byte("cap-test-value-0d1e2f3a4b5c")
)

type result struct {
	stdout, stderr string
	code           int
}

func runCLI(ts *localapitest.Server, stdin io.Reader, args ...string) result {
	var out, errb bytes.Buffer
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	e := &Env{Stdin: stdin, Stdout: &out, Stderr: &errb, Registry: config.Default,
		Environ: []string{localapi.EnvSocket + "=" + ts.Socket}}
	code := Run(context.Background(), e, args)
	return result{stdout: out.String(), stderr: errb.String(), code: code}
}

func cliServer(t *testing.T) *localapitest.Server {
	t.Helper()
	ts := localapitest.Start(t)
	fixed := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	ts.Approvals.Now = func() time.Time { return fixed }
	ts.Store.Seed(agenttools.SecretInfo{Ref: "bao://kv/agents/github", Name: "github", Bindings: []string{"api.github.com"}}, cliSeeded)
	return ts
}

// TestSecretGolden runs every agent-facing command against a real local API
// over the fakes and compares stdout, stderr and the exit code with
// testdata/secret.golden.
func TestSecretGolden(t *testing.T) {
	ts := cliServer(t)
	dir := t.TempDir()
	capFile := filepath.Join(dir, "token.json")
	if err := os.WriteFile(capFile, []byte(`{"token":"`+string(cliCaptured)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		stdin string
		args  []string
	}{
		{"", []string{"secret", "ls"}},
		{"", []string{"secret", "ls", "-o", "json"}},
		{"", []string{"secret", "ls", "--prefix", "bao://kv/other/"}},
		{"", []string{"secret", "request", "bao://kv/agents/github", "--duration", "30m", "--reason", "open a PR"}},
		{"", []string{"secret", "request", "bao://kv/agents/github", "--duration", "5h", "--reason", "long job", "-o", "json"}},
		{"", []string{"secret", "request", "bao://kv/agents/ask/hetzner", "--reason", "deploy"}},
		{"", []string{"secret", "status", "apr_0003"}},
		{"", []string{"secret", "request", "bao://kv/agents/deny/prod", "--reason", "curious"}},
		{"", []string{"secret", "request", "bao://kv/agents/github"}},
		{"", []string{"secret", "gen", "bao://kv/agents/app-db#password", "--length", "32"}},
		{"", []string{"secret", "gen", "bao://kv/prod/payments"}},
		{"", []string{"secret", "gen", "bao://kv/prod/payments", "-o", "json"}},
		{"", []string{"secret", "gen", "bao://kv/agents/app-db#password"}},
		{string(cliPiped) + "\n", []string{"secret", "put", "bao://kv/agents/new-token", "--stdin"}},
		{string(cliPiped) + "\n", []string{"secret", "put", "bao://kv/agents/new-token"}},
		{"", []string{"secret", "capture", "bao://kv/agents/captured", "--json-path", ".token", "--", "cat", capFile}},
		{"id=1 token=" + string(cliCaptured) + "\n", []string{"secret", "capture", "bao://kv/agents/from-stdin", "--pattern", `token=(\S+)`, "--stdin"}},
		{"", []string{"secret", "capture", "bao://kv/agents/fail", "--", "sh", "-c", "cat " + capFile + "; exit 2"}},
		{"", []string{"secret", "grants"}},
		{"", []string{"secret", "status", "apr_9999"}},
	}
	var got bytes.Buffer
	for _, c := range cases {
		var stdin io.Reader
		if c.stdin != "" {
			stdin = strings.NewReader(c.stdin)
		}
		r := runCLI(ts, stdin, c.args...)
		line := filepath.ToSlash(strings.ReplaceAll(strings.Join(c.args, " "), dir, "$TMP"))
		fmt.Fprintf(&got, "$ scrim %s\n--- stdout\n%s--- stderr\n%s--- exit %d\n\n", line, r.stdout, r.stderr, r.code)
	}
	agenttoolstest.AssertNoValues(t, "CLI output", got.Bytes(), cliSeeded, cliPiped, cliCaptured)

	path := filepath.Join("testdata", "secret.golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("output differs from %s; run go test ./internal/cli -run TestSecretGolden -update after reviewing:\n%s", path, got.String())
	}
	for ref, want := range map[string][]byte{"bao://kv/agents/new-token": cliPiped, "bao://kv/agents/captured": cliCaptured, "bao://kv/agents/from-stdin": cliCaptured} {
		if v, _ := ts.Store.Value(ref); !bytes.Equal(v, want) {
			t.Errorf("%s: stored value differs", ref)
		}
	}
}

// TestPutPipeNeverEchoes is the 8.3 pipe test: a command's output is piped
// into `scrim secret put --stdin`; the value is stored and appears in
// neither stdout nor stderr, in any encoding, on success or failure.
func TestPutPipeNeverEchoes(t *testing.T) {
	ts := cliServer(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = w.Write(append(append([]byte(nil), cliPiped...), '\n'))
		_ = w.Close()
	}()
	res := runCLI(ts, r, "secret", "put", "bao://kv/agents/piped", "--stdin")
	_ = r.Close()
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	if v, _ := ts.Store.Value("bao://kv/agents/piped"); !bytes.Equal(v, cliPiped) {
		t.Fatal("piped value not stored exactly")
	}
	all := []byte(res.stdout + res.stderr)
	agenttoolstest.AssertNoValues(t, "put output", all, cliPiped)
	if !strings.Contains(res.stdout, "stored bao://kv/agents/piped") {
		t.Fatalf("stdout = %q", res.stdout)
	}

	// The same value again fails (no --overwrite), still without echoing it.
	res = runCLI(ts, bytes.NewReader(cliPiped), "secret", "put", "bao://kv/agents/piped", "--stdin", "-o", "json")
	if res.code != ExitError || !strings.Contains(res.stdout, `"conflict"`) {
		t.Fatalf("second put: exit %d %q", res.code, res.stdout)
	}
	agenttoolstest.AssertNoValues(t, "failed put output", []byte(res.stdout+res.stderr), cliPiped)

	// A store that echoes the value in its error does not leak it either.
	ts.Store.WriteErr = fmt.Errorf("backend rejected %s", cliPiped)
	res = runCLI(ts, bytes.NewReader(cliPiped), "secret", "put", "bao://kv/agents/other", "--stdin")
	if res.code != ExitError {
		t.Fatalf("store failure: exit %d", res.code)
	}
	agenttoolstest.AssertNoValues(t, "store failure output", []byte(res.stdout+res.stderr), cliPiped)
	audit := fmt.Sprintf("%+v", ts.Audit.All())
	agenttoolstest.AssertNoValues(t, "audit", []byte(audit), cliPiped)
}

func TestSecretUnreachableServer(t *testing.T) {
	var out, errb bytes.Buffer
	e := &Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Registry: config.Default,
		Environ: []string{localapi.EnvSocket + "=" + filepath.Join(t.TempDir(), "none.sock")}}
	if code := Run(context.Background(), e, []string{"secret", "grants"}); code != ExitError {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "cannot reach scrim") {
		t.Fatalf("stderr %q", errb.String())
	}
}

func TestSessionTokenFromEnvironment(t *testing.T) {
	ts := cliServer(t)
	var out, errb bytes.Buffer
	e := &Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Registry: config.Default,
		Environ: []string{localapi.EnvSocket + "=" + ts.Socket, localapi.EnvToken + "=scrim_st_not-a-real-token"}}
	if code := Run(context.Background(), e, []string{"secret", "grants"}); code != ExitDenied {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "session token was refused") || strings.Contains(errb.String(), "not-a-real-token") {
		t.Fatalf("stderr %q", errb.String())
	}
}
