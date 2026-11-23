// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// execHelperArg makes the test binary the brokered command (see TestMain).
const execHelperArg = "-scrim-exec-helper"

// execHelper is the brokered test command: it reports whether $SCRIM_KEY
// hashes to its first argument, prints the value raw and encoded on stdout
// and stderr, and exits with status 7.
func execHelper(args []string) int {
	v := os.Getenv("SCRIM_KEY")
	sum := sha256.Sum256([]byte(v))
	if len(args) > 0 && hex.EncodeToString(sum[:]) == args[0] {
		fmt.Println("secret received")
	} else {
		fmt.Println("secret missing")
	}
	mode := ""
	if len(args) > 1 {
		mode = args[1]
	}
	switch mode {
	case "raw":
		fmt.Println("stdout:", v)
		fmt.Fprintln(os.Stderr, "stderr:", v)
	case "b64":
		fmt.Println("stdout:", base64.StdEncoding.EncodeToString([]byte(v)))
	case "hex":
		fmt.Fprintln(os.Stderr, "stderr:", hex.EncodeToString([]byte(v)))
	case "json":
		raw, _ := json.Marshal(map[string]string{"token": v})
		fmt.Println(string(raw))
	}
	return 7
}

// TestExecBrokerRealDataPlane runs the exec broker on a daemon with the
// real data plane: the brokered command receives the credential named by
// its declared placeholder, its output comes back with the credential
// redacted by the data plane (raw, JSON) or withheld (encoded forms the
// redactor does not undo), the exit status is the command's, and the
// independent leak checker finds the value in no answer, log or audit
// entry. A transform command is refused and audited.
func TestExecBrokerRealDataPlane(t *testing.T) {
	bin := realDataPlane(t)
	up := httptest.NewServer(fakeprovider.New(fakeprovider.Options{}))
	defer up.Close()
	token := seed(t, "sk-exec-")
	h := newHarness(t, token)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h.opts.Config.Environ = append(h.opts.Config.Environ,
		"SCRIM_EXEC_ALLOW_SAME_USER=true",
		`SCRIM_EXEC_COMMANDS={"helper":{"path":`+strconv.Quote(exe)+`,"secrets":["acme"],"env-names":["SCRIM_KEY"],"inject":["env","args"]}}`)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	d := h.startReal(t, ctx, bin, up.URL)
	c := localapi.NewClient(d.Addrs().AgentAPI, secret.Value{})
	defer c.Close()

	sum := sha256.Sum256([]byte(token))
	digest := hex.EncodeToString(sum[:])
	var answers []string
	run := func(mode string) agenttools.ExecOutput {
		t.Helper()
		out, err := c.Exec(ctx, agenttools.ExecInput{Command: []string{"helper", execHelperArg, digest, mode},
			Env: map[string]string{"SCRIM_KEY": "SCRIM_ACME_KEY"}})
		if err != nil {
			t.Fatalf("%s: %v\n%s", mode, err, h.logs.String())
		}
		raw, _ := json.Marshal(out)
		answers = append(answers, string(raw))
		if out.ExitCode != 7 || !strings.HasPrefix(out.Stdout+out.Withheld["stdout"], "secret received\n") &&
			out.Withheld["stdout"] == "" {
			t.Fatalf("%s: %+v", mode, out)
		}
		return out
	}

	out := run("raw")
	if !strings.Contains(out.Stdout, "stdout: ⟦scrim:acme:") || !strings.Contains(out.Stderr, "stderr: ⟦scrim:acme:") ||
		out.Redactions < 2 {
		t.Fatalf("raw: %+v", out)
	}
	out = run("json")
	if !strings.Contains(out.Stdout, `{"token":"⟦scrim:acme:`) {
		t.Fatalf("json: %+v", out)
	}
	// Encoded forms: the data plane redacts them or the broker's guard
	// withholds the stream; either way the leak checker below finds nothing.
	for mode, stream := range map[string]string{"b64": "stdout", "hex": "stderr"} {
		out = run(mode)
		text := map[string]string{"stdout": out.Stdout, "stderr": out.Stderr}[stream]
		t.Logf("%s: %s=%q withheld=%v", mode, stream, text, out.Withheld)
		if !strings.Contains(text, "⟦scrim:acme:") && out.Withheld[stream] == "" {
			t.Fatalf("%s: %+v", mode, out)
		}
	}

	// A placeholder the agent got from the model, in an argument.
	ph := d.builder.PlaceholderFor(mustRef(t, "testenv://SCRIMTEST_TOKEN"))
	if ph == "" {
		t.Fatal("no placeholder for the seeded credential")
	}
	res, err := c.Exec(ctx, agenttools.ExecInput{Command: []string{"helper", execHelperArg, digest, "none", ph},
		Env: map[string]string{"SCRIM_KEY": ph}})
	if err != nil || res.Stdout != "secret received\n" {
		t.Fatalf("bracket placeholder: %+v, %v", res, err)
	}

	_, err = c.Exec(ctx, agenttools.ExecInput{Command: []string{"base64"}, Env: map[string]string{"SCRIM_KEY": "SCRIM_ACME_KEY"}})
	if agenttools.CodeOf(err) != agenttools.CodeDenied {
		t.Fatalf("base64: %v", err)
	}

	logs := h.logs.String()
	auditLog := auditText(t, ctx, d)
	if !strings.Contains(auditLog, "blocked transform: base64") || !strings.Contains(auditLog, "tool.secret_exec") {
		t.Fatalf("audit log lacks the exec entries:\n%s", auditLog)
	}
	checker := leak.NewChecker([]leak.Seed{leak.NewSeed("acme", leak.KindAPIKey, token)})
	for i, text := range append(answers, logs, auditLog) {
		if f := checker.CheckText(i, text); len(f) > 0 {
			t.Fatalf("the credential leaked (%d findings, first %+v)", len(f), f[0])
		}
	}
}

func mustRef(t *testing.T, s string) stores.Ref {
	t.Helper()
	r, err := stores.ParseRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// auditText is every audit entry the daemon's state holds, as JSON.
func auditText(t *testing.T, ctx context.Context, d *Daemon) string {
	t.Helper()
	var entries []audit.Entry
	err := d.App().State.View(ctx, func(tx state.Tx) error {
		var err error
		entries, err = tx.QueryAudit(ctx, state.AuditQuery{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(entries)
	return string(raw)
}
