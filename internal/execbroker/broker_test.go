// SPDX-License-Identifier: AGPL-3.0-only

package execbroker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
)

// TestMain doubles as the brokered test command: with SCRIM_EXEC_HELPER set
// (the allow-list entry's fixed environment), the test binary runs the
// actions in its arguments instead of the tests.
func TestMain(m *testing.M) {
	if os.Getenv("SCRIM_EXEC_HELPER") == "1" {
		os.Exit(helper(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// helper actions:
//
//	hash=NAME:HEX   print "match NAME" or "mismatch NAME": does $NAME hash to HEX
//	out=NAME:ENC    print $NAME to stdout as raw, b64 or hex
//	err=NAME:ENC    the same on stderr
//	stdin=HEX       print "stdin match" when stdin hashes to HEX
//	arg=HEX:VALUE   print "arg match" when VALUE hashes to HEX
//	uid             print "uid N"
//	exit=N          exit with N
//	sleep=D         sleep for a Go duration
func helper(args []string) int {
	code := 0
	for _, a := range args {
		k, v, _ := strings.Cut(a, "=")
		switch k {
		case "hash":
			name, want, _ := strings.Cut(v, ":")
			sum := sha256.Sum256([]byte(os.Getenv(name)))
			if hex.EncodeToString(sum[:]) == want {
				fmt.Println("match", name)
			} else {
				fmt.Println("mismatch", name)
			}
		case "out", "err":
			name, enc, _ := strings.Cut(v, ":")
			w := os.Stdout
			if k == "err" {
				w = os.Stderr
			}
			val := os.Getenv(name)
			switch enc {
			case "b64":
				val = base64.StdEncoding.EncodeToString([]byte(val))
			case "hex":
				val = hex.EncodeToString([]byte(val))
			}
			_, _ = fmt.Fprintf(w, "%s=%s\n", name, val)
		case "stdin":
			b, _ := io.ReadAll(os.Stdin)
			sum := sha256.Sum256(b)
			if hex.EncodeToString(sum[:]) == v {
				fmt.Println("stdin match")
			}
		case "arg":
			want, val, _ := strings.Cut(v, ":")
			sum := sha256.Sum256([]byte(val))
			if hex.EncodeToString(sum[:]) == want {
				fmt.Println("arg match")
			}
		case "uid":
			fmt.Println("uid", os.Getuid())
		case "exit":
			code, _ = strconv.Atoi(v)
		case "sleep":
			d, _ := time.ParseDuration(v)
			time.Sleep(d)
		case "readenv":
			if _, err := os.ReadFile("/proc/" + v + "/environ"); err != nil {
				fmt.Println("denied")
			} else {
				fmt.Println("read")
			}
		case "dump":
			_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 4096))
		}
	}
	return code
}

func token(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(b)
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// fakeValues is a redaction set of one or more credentials.
type fakeValues struct {
	entries []fakeEntry
	err     error
}

type fakeEntry struct {
	ref, name, form, value string
}

func (f fakeValues) Find(_ context.Context, occurs func(string) bool) ([]Match, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []Match
	for _, e := range f.entries {
		if occurs(e.form) {
			out = append(out, Match{Form: e.form, Ref: stores.MustParseRef(e.ref), Name: e.name, Class: "credential",
				Value: secret.FromString(e.value)})
		}
	}
	return out, nil
}

// fakeRedactor replaces each known value verbatim, like the redactor
// without its decoding guard, so encoded output reaches the broker's own
// guard.
type fakeRedactor struct {
	values []fakeEntry
	fail   bool
	calls  int
	mu     sync.Mutex
}

func (r *fakeRedactor) redact(_ context.Context, text []byte) (Redacted, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.fail {
		secret.WipeBytes(text)
		return Redacted{}, fmt.Errorf("data plane unavailable")
	}
	out, n := string(text), 0
	for _, e := range r.values {
		n += strings.Count(out, e.value)
		out = strings.ReplaceAll(out, e.value, e.form)
	}
	secret.WipeBytes(text)
	return Redacted{Text: []byte(out), Replacements: n}, nil
}

type recAuditor struct {
	mu      sync.Mutex
	entries []agenttools.AuditEntry
}

func (a *recAuditor) Record(_ context.Context, e agenttools.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *recAuditor) last() agenttools.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.entries[len(a.entries)-1]
}

type rig struct {
	b     *Broker
	cfg   Config
	audit *recAuditor
	red   *fakeRedactor
	st    *memstate.Store
	apps  *approval.Service
	rec   *notify.Recorder
	val   string
	other string
	logs  *bytes.Buffer
}

const (
	refGitHub = "bao://kv/agents/github#token"
	refDB     = "bao://kv/agents/db#password"
	formGH    = "⟦scrim:github:01aabbccddeeff0011⟧"
	formDB    = "SCRIM_DB_PASSWORD"
)

func newRig(t *testing.T, rules []policy.RuleSpec) *rig {
	t.Helper()
	ctx := context.Background()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{val: token(t, "ghp_"), other: token(t, "db-"), audit: &recAuditor{}, logs: &bytes.Buffer{}}
	entries := []fakeEntry{{refGitHub, "github", formGH, r.val}, {refDB, "db", formDB, r.other}}
	r.red = &fakeRedactor{values: entries}
	r.cfg = Config{Path: "/usr/bin:/bin", Timeout: 20 * time.Second, MaxOutput: 1 << 16, Commands: map[string]*Command{
		"helper": {Name: "helper", Path: self, Secrets: []string{"bao://kv/agents/github*"}, Inject: []Location{InEnv, InArgs, InStdin},
			EnvNames: []string{"TOKEN", "DB*"}, Env: map[string]string{"SCRIM_EXEC_HELPER": "1"}},
	}}
	st := memstate.New()
	r.st = st
	bg, err := breakglass.New(ctx, st, false)
	if err != nil {
		t.Fatal(err)
	}
	live, err := policy.NewLive(policy.Config{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	r.rec = &notify.Recorder{NotifierName: "rec"}
	limits := func(policy.GrantSettings) grant.Limits { return grant.Limits{Default: time.Minute, Max: time.Hour} }
	r.apps, err = approval.New(approval.Options{State: st, Notifiers: []notify.Notifier{r.rec}, Signer: approval.RandomSigner(),
		BreakGlass: bg, Timeout: 5 * time.Second, PollInterval: 5 * time.Millisecond,
		Grants: func(string) (grant.Limits, policy.GrantSettings) {
			return limits(policy.GrantSettings{}), policy.GrantSettings{}
		}})
	if err != nil {
		t.Fatal(err)
	}
	g := &gate.Gate{Engine: bg.Engine(live), Rules: live, Grants: grant.NewService(st, bg), Approvals: r.apps,
		BreakGlass: bg, State: st, Limits: limits}
	r.b, err = New(Deps{
		Config:   func() (Config, error) { return r.cfg, nil },
		Values:   fakeValues{entries: entries},
		Gate:     g,
		Redactor: r.red.redact,
		Auditor:  r.audit,
		Logger:   nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// agent is a caller on another Unix user than the one commands run as.
func agent() identity.Identity {
	return identity.Identity{Agent: "claude", Source: identity.SourcePeer,
		Peer: identity.Peer{UID: uint32(os.Geteuid()) + 1000, PID: 4242}, Scopes: identity.AllScopes} //nolint:gosec // test
}

// leakCheck fails when v appears in anything the broker produced: the
// result, the error, the audit log, the state store's audit entries.
func (r *rig) leakCheck(t *testing.T, res Result, err error) {
	t.Helper()
	raw, _ := json.Marshal(res)
	all := string(raw)
	if err != nil {
		all += err.Error()
	}
	auditRaw, _ := json.Marshal(r.audit.entries)
	all += string(auditRaw)
	entries := r.stateAudit(t)
	stRaw, _ := json.Marshal(entries)
	all += string(stRaw)
	for _, v := range []string{r.val, r.other} {
		for _, form := range []string{v, base64.StdEncoding.EncodeToString([]byte(v)), hex.EncodeToString([]byte(v))} {
			if strings.Contains(all, form) {
				t.Fatalf("a secret reached the broker's output")
			}
		}
	}
}

func TestAllowedCommandRunsWithTheSecret(t *testing.T) {
	r := newRig(t, nil)
	ctx := context.Background()
	res, err := r.b.Run(ctx, agent(), Request{
		Command: []string{"helper", "hash=TOKEN:" + sum(r.val), "exit=3"},
		Env:     map[string]string{"TOKEN": formGH},
	})
	r.leakCheck(t, res, err)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "match TOKEN\n" || res.Stderr != "" || len(res.Withheld) != 0 || res.ExitCode != 3 ||
		len(res.Refs) != 1 || res.Refs[0] != refGitHub {
		t.Fatalf("result = %+v", res)
	}
	e := r.audit.last()
	if e.Tool != ToolSecretExec || e.Outcome != agenttools.OutcomeOK || e.Rule != RuleAllowList || e.Ref != refGitHub ||
		!strings.Contains(e.Detail, "exit 3") {
		t.Fatalf("audit = %+v", e)
	}
	// The gate audited the decision with the command line, placeholders kept.
	entries := r.stateAudit(t)
	found := false
	for _, a := range entries {
		if a.Action == gate.ActionDecision && a.Attrs["action"] == "exec" && a.Rule == RuleAllowList && a.Target == "helper" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no exec decision in %+v", entries)
	}
}

func TestSecretInArgsAndStdin(t *testing.T) {
	r := newRig(t, nil)
	res, err := r.b.Run(context.Background(), agent(), Request{
		Command: []string{"helper", "arg=" + sum(r.val) + ":" + formGH, "stdin=" + sum("pw="+r.val+"\n")},
		Stdin:   "pw=" + formGH + "\n",
	})
	r.leakCheck(t, res, err)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "arg match\nstdin match\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

func TestOutputIsRedacted(t *testing.T) {
	r := newRig(t, nil)
	res, err := r.b.Run(context.Background(), agent(), Request{
		Command: []string{"helper", "out=TOKEN:raw", "err=TOKEN:raw", "exit=1"},
		Env:     map[string]string{"TOKEN": formGH},
	})
	r.leakCheck(t, res, err)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "TOKEN="+formGH+"\n" || res.Stderr != "TOKEN="+formGH+"\n" || res.Redactions != 2 || res.ExitCode != 1 {
		t.Fatalf("result = %+v", res)
	}
}

// TestEncodedOutputIsWithheld: the stand-in redactor only matches values
// verbatim, so base64 and hex output reach the broker's own guard, which
// withholds the stream instead of returning it.
func TestEncodedOutputIsWithheld(t *testing.T) {
	for _, enc := range []string{"b64", "hex"} {
		t.Run(enc, func(t *testing.T) {
			r := newRig(t, nil)
			res, err := r.b.Run(context.Background(), agent(), Request{
				Command: []string{"helper", "out=TOKEN:" + enc, "err=TOKEN:" + enc},
				Env:     map[string]string{"TOKEN": formGH},
			})
			r.leakCheck(t, res, err)
			if err != nil {
				t.Fatal(err)
			}
			if res.Stdout != "" || res.Stderr != "" || res.Withheld["stdout"] == "" || res.Withheld["stderr"] == "" {
				t.Fatalf("result = %+v", res)
			}
			if !strings.Contains(r.audit.last().Detail, "stdout withheld") {
				t.Fatalf("audit = %+v", r.audit.last())
			}
		})
	}
}

func TestRedactionFailureWithholds(t *testing.T) {
	r := newRig(t, nil)
	r.red.fail = true
	res, err := r.b.Run(context.Background(), agent(), Request{
		Command: []string{"helper", "out=TOKEN:raw"}, Env: map[string]string{"TOKEN": formGH},
	})
	r.leakCheck(t, res, err)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "" || res.Withheld["stdout"] != "scrim could not redact it" {
		t.Fatalf("result = %+v", res)
	}
}

func TestOversizedOutputWithheldWhole(t *testing.T) {
	r := newRig(t, nil)
	r.cfg.MaxOutput = 1024
	res, err := r.b.Run(context.Background(), agent(), Request{
		Command: []string{"helper", "dump", "out=TOKEN:raw"}, Env: map[string]string{"TOKEN": formGH},
	})
	r.leakCheck(t, res, err)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "" || !strings.Contains(res.Withheld["stdout"], "exec.max-output") {
		t.Fatalf("result = %+v", res)
	}
}

func TestTimeoutKillsTheCommand(t *testing.T) {
	r := newRig(t, nil)
	start := time.Now()
	res, err := r.b.Run(context.Background(), agent(), Request{
		Command: []string{"helper", "out=TOKEN:raw", "sleep=30s"}, Env: map[string]string{"TOKEN": formGH}, TimeoutSeconds: 1,
	})
	r.leakCheck(t, res, err)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.ExitCode != -1 || time.Since(start) > 10*time.Second {
		t.Fatalf("result = %+v after %s", res, time.Since(start))
	}
}

// TestTransformCommandsAreBlocked: programs that print or encode their
// input, shells and interpreters are refused before anything is looked up,
// and the refusal is audited as a blocked transform.
func TestTransformCommandsAreBlocked(t *testing.T) {
	for _, argv := range [][]string{
		{"base64"}, {"sh", "-c", "echo $TOKEN | base64"}, {"echo", formGH}, {"printenv", "TOKEN"},
		{"env"}, {"python3", "-c", "import os"}, {"perl", "-e", "print"}, {"xxd"}, {"rev"}, {"od", "-c"},
		{"bash"}, {"awk", "{print}"}, {"python3.12"},
	} {
		t.Run(argv[0], func(t *testing.T) {
			r := newRig(t, []policy.RuleSpec{{Name: "anything", Decision: "allow", When: `op == "exec"`}})
			res, err := r.b.Run(context.Background(), agent(), Request{Command: argv, Env: map[string]string{"TOKEN": formGH}})
			r.leakCheck(t, res, err)
			if agenttools.CodeOf(err) != agenttools.CodeDenied || !strings.Contains(err.Error(), "never run by the exec broker") {
				t.Fatalf("err = %v", err)
			}
			e := r.audit.last()
			if e.Outcome != agenttools.OutcomeDenied || !strings.HasPrefix(e.Detail, "blocked transform: "+argv[0]) {
				t.Fatalf("audit = %+v", e)
			}
		})
	}
}

func TestTransformCannotBeAllowListed(t *testing.T) {
	for _, path := range []string{"/bin/sh", "/usr/bin/base64", "/usr/bin/python3"} {
		if transformOf("tool", path) == "" {
			t.Errorf("%s is not refused as a transform", path)
		}
	}
	if transformOf("git", "/usr/bin/git") != "" || transformOf("kubectl", "/usr/local/bin/kubectl") != "" {
		t.Error("git or kubectl refused as a transform")
	}
}

func TestNotOnAllowListFollowsPolicy(t *testing.T) {
	// A secret the entry does not list: denied by default.
	r := newRig(t, nil)
	res, err := r.b.Run(context.Background(), agent(), Request{
		Command: []string{"helper", "hash=DB:" + sum(r.other)}, Env: map[string]string{"DB": formDB},
	})
	r.leakCheck(t, res, err)
	if agenttools.CodeOf(err) != agenttools.CodeDenied || !strings.Contains(err.Error(), "not on the allow list") {
		t.Fatalf("err = %v", err)
	}
	// A rule may allow it.
	r = newRig(t, []policy.RuleSpec{{Name: "db-helper", Decision: "allow",
		When: `op == "exec" && secret.ref == "` + refDB + `" && tool.name == "helper"`}})
	res, err = r.b.Run(context.Background(), agent(), Request{
		Command: []string{"helper", "hash=DB:" + sum(r.other)}, Env: map[string]string{"DB": formDB},
	})
	r.leakCheck(t, res, err)
	if err != nil || res.Stdout != "match DB\n" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if e := r.audit.last(); e.Rule != "db-helper" {
		t.Fatalf("audit = %+v", e)
	}
}

func TestDenyRuleBeatsAllowList(t *testing.T) {
	r := newRig(t, []policy.RuleSpec{{Name: "no-exec", Decision: "deny", When: `op == "exec"`, Reason: "not today"}})
	res, err := r.b.Run(context.Background(), agent(), Request{
		Command: []string{"helper", "hash=TOKEN:" + sum(r.val)}, Env: map[string]string{"TOKEN": formGH},
	})
	r.leakCheck(t, res, err)
	if agenttools.CodeOf(err) != agenttools.CodeDenied || !strings.Contains(err.Error(), "not today") {
		t.Fatalf("err = %v", err)
	}
}

func TestAskWaitsForApproval(t *testing.T) {
	for _, approve := range []bool{true, false} {
		t.Run(strconv.FormatBool(approve), func(t *testing.T) {
			r := newRig(t, []policy.RuleSpec{{Name: "push-asks", Decision: "ask",
				When: `op == "exec" && tool.command.startsWith("helper hash=")`}})
			go func() {
				deadline := time.Now().Add(5 * time.Second)
				for len(r.rec.Sent()) == 0 && time.Now().Before(deadline) {
					time.Sleep(5 * time.Millisecond)
				}
				sent := r.rec.Sent()
				if len(sent) == 0 {
					t.Error("no approval was sent")
					return
				}
				if !strings.Contains(sent[0].Summary.Tool+" "+sent[0].Summary.Command, "helper hash=") {
					t.Errorf("approval shows %q %q", sent[0].Summary.Tool, sent[0].Summary.Command)
				}
				link := sent[0].DenyURL
				if approve {
					link = sent[0].ApproveURL
				}
				id, tok, _ := approval.TokenFromLink(link)
				if _, err := r.apps.DecideToken(context.Background(), id, tok); err != nil {
					t.Error(err)
				}
			}()
			res, err := r.b.Run(context.Background(), agent(), Request{
				Command: []string{"helper", "hash=TOKEN:" + sum(r.val)}, Env: map[string]string{"TOKEN": formGH},
			})
			r.leakCheck(t, res, err)
			if approve && (err != nil || res.Stdout != "match TOKEN\n") {
				t.Fatalf("approved: res = %+v, err = %v", res, err)
			}
			if !approve && agenttools.CodeOf(err) != agenttools.CodeDenied {
				t.Fatalf("denied: err = %v", err)
			}
			if r.audit.last().ApprovalID == "" {
				t.Fatalf("audit = %+v", r.audit.last())
			}
		})
	}
}

func TestSameUserRefused(t *testing.T) {
	r := newRig(t, nil)
	me := agent()
	me.Peer.UID = uint32(os.Geteuid()) //nolint:gosec // test
	req := Request{Command: []string{"helper", "hash=TOKEN:" + sum(r.val)}, Env: map[string]string{"TOKEN": formGH}}
	res, err := r.b.Run(context.Background(), me, req)
	r.leakCheck(t, res, err)
	if agenttools.CodeOf(err) != agenttools.CodeUnavailable || !strings.Contains(err.Error(), "own user") {
		t.Fatalf("err = %v", err)
	}
	r.cfg.AllowSameUser = true
	res, err = r.b.Run(context.Background(), me, req)
	if err != nil || res.Stdout != "match TOKEN\n" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestRequestRefusals(t *testing.T) {
	cases := []struct {
		name string
		req  func(r *rig) Request
		code agenttools.Code
		msg  string
	}{
		{"no secret", func(*rig) Request { return Request{Command: []string{"helper", "uid"}} }, agenttools.CodeInvalid, "names no secret"},
		{"path", func(*rig) Request { return Request{Command: []string{"/bin/true"}} }, agenttools.CodeInvalid, "not a path"},
		{"unknown placeholder", func(*rig) Request {
			return Request{Command: []string{"helper"}, Env: map[string]string{"TOKEN": "⟦scrim:nope:01ffffffffffffffff⟧"}}
		}, agenttools.CodeUnavailable, "names no credential"},
		{"denied env", func(*rig) Request {
			return Request{Command: []string{"helper"}, Env: map[string]string{"LD_PRELOAD": formGH}}
		}, agenttools.CodeDenied, "LD_PRELOAD"},
		{"env not listed", func(*rig) Request {
			return Request{Command: []string{"helper"}, Env: map[string]string{"OTHER": formGH}}
		}, agenttools.CodeDenied, "env-names"},
		{"fixed env", func(*rig) Request {
			return Request{Command: []string{"helper"}, Env: map[string]string{"SCRIM_EXEC_HELPER": formGH}}
		}, agenttools.CodeDenied, "env-names"},
		{"dir not allowed", func(*rig) Request {
			return Request{Command: []string{"helper"}, Env: map[string]string{"TOKEN": formGH}, Dir: "/tmp"}
		}, agenttools.CodeDenied, "dirs"},
		{"unknown command", func(*rig) Request {
			return Request{Command: []string{"no-such-command-here"}, Env: map[string]string{"TOKEN": formGH}}
		}, agenttools.CodeNotFound, "not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			res, err := r.b.Run(context.Background(), agent(), tc.req(r))
			r.leakCheck(t, res, err)
			if agenttools.CodeOf(err) != tc.code || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestInjectLocationsAndArgs(t *testing.T) {
	r := newRig(t, nil)
	r.cfg.Commands["helper"].Inject = []Location{InEnv}
	res, err := r.b.Run(context.Background(), agent(), Request{Command: []string{"helper", "arg=x:" + formGH}})
	r.leakCheck(t, res, err)
	if agenttools.CodeOf(err) != agenttools.CodeDenied || !strings.Contains(err.Error(), "does not take secrets in args") {
		t.Fatalf("err = %v", err)
	}
	r.cfg.Commands["helper"].Args = []*regexp.Regexp{regexp.MustCompile(`\A(?:hash=TOKEN:[0-9a-f]+)\z`)}
	_, err = r.b.Run(context.Background(), agent(), Request{Command: []string{"helper", "uid"}, Env: map[string]string{"TOKEN": formGH}})
	if agenttools.CodeOf(err) != agenttools.CodeDenied || !strings.Contains(err.Error(), ".args") {
		t.Fatalf("err = %v", err)
	}
	res, err = r.b.Run(context.Background(), agent(), Request{Command: []string{"helper", "hash=TOKEN:" + sum(r.val)},
		Env: map[string]string{"TOKEN": formGH}})
	if err != nil || res.Stdout != "match TOKEN\n" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestDirMustBeListed(t *testing.T) {
	r := newRig(t, nil)
	dir := t.TempDir()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.cfg.Commands["helper"].Dirs = []string{real}
	res, err := r.b.Run(context.Background(), agent(), Request{Command: []string{"helper", "hash=TOKEN:" + sum(r.val)},
		Env: map[string]string{"TOKEN": formGH}, Dir: real})
	if err != nil || res.Stdout != "match TOKEN\n" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	r.cfg.Commands["helper"].Dirs = []string{real, link}
	_, err = r.b.Run(context.Background(), agent(), Request{Command: []string{"helper"}, Env: map[string]string{"TOKEN": formGH}, Dir: link})
	if agenttools.CodeOf(err) != agenttools.CodeDenied || !strings.Contains(err.Error(), "resolves to") {
		t.Fatalf("err = %v", err)
	}
}

func TestBuiltinToolRules(t *testing.T) {
	git := builtinTools["git"]
	for _, args := range [][]string{
		{"-c", "core.sshCommand=sh", "push"}, {"-ccore.pager=sh", "push"}, {"push", "--receive-pack=sh"},
		{"--exec-path=/tmp", "push"}, {"config", "alias.x", "!sh"}, {"push", "ext::sh -c id"}, {"-C", "/", "push"},
		{"clone", "-u", "sh", "https://x"}, {"log"},
	} {
		if _, why := git.checkArgs(args); why == "" {
			t.Errorf("git %v passed", args)
		}
	}
	for _, args := range [][]string{{"push", "-u", "origin", "main"}, {"fetch", "origin"}, {"push", "--force-with-lease"}} {
		if a, why := git.checkArgs(args); why != "" {
			t.Errorf("git %v refused at %q: %s", args, a, why)
		}
	}
	kubectl := builtinTools["kubectl"]
	for _, args := range [][]string{{"exec", "pod", "--", "sh"}, {"--kubeconfig=/tmp/k", "get", "pods"}, {"config", "view", "--raw"}} {
		if _, why := kubectl.checkArgs(args); why == "" {
			t.Errorf("kubectl %v passed", args)
		}
	}
	if _, why := kubectl.checkArgs([]string{"apply", "-f", "deploy.yaml"}); why != "" {
		t.Error("kubectl apply refused")
	}
}

func TestSubstituteBoundaries(t *testing.T) {
	m := []Match{{Form: "SCRIM_KEY", Value: secret.FromString("v1")}, {Form: "⟦scrim:a:01aa⟧", Value: secret.FromString("v2")}}
	out, used, left := substitute("x=SCRIM_KEY y=SCRIM_KEY_2 z=⟦scrim:a:01aa⟧⟦scrim:b:01bb⟧", m)
	if string(out) != "x=v1 y=SCRIM_KEY_2 z=v2⟦scrim:b:01bb⟧" || len(used) != 2 || !left {
		t.Fatalf("out=%q used=%v left=%v", out, used, left)
	}
}

func TestRender(t *testing.T) {
	if got := render([]string{"git", "push", "origin", "it's mine", ""}); got != `git push origin 'it'\''s mine' ''` {
		t.Fatal(got)
	}
}

func TestConfigFromRejectsTransforms(t *testing.T) {
	if _, err := commandOf(instance("shell", map[string]any{"path": "/bin/sh", "secrets": []any{"bao://x"}})); err == nil {
		t.Fatal("a shell was accepted as an allow-listed command")
	}
	c, err := commandOf(instance("git", map[string]any{"path": "/usr/bin/git", "secrets": "github", "inject": []any{"env", "args"},
		"args": []any{`push origin [a-z-]+`}, "env": map[string]any{"GIT_SSH": "ssh"}, "timeout": "30s"}))
	if err != nil {
		t.Fatal(err)
	}
	if !c.allowsSecret("bao://kv/x", "github") || c.allowsSecret("bao://kv/x", "gitlab") || !c.injects(InArgs) ||
		!c.Args[0].MatchString("push origin main") || c.Args[0].MatchString("push origin main; id") {
		t.Fatalf("command = %+v", c)
	}
	for _, f := range []map[string]any{
		{"path": "git", "secrets": "x"},
		{"path": "/usr/bin/git", "secrets": "x", "inject": "files"},
		{"path": "/usr/bin/git", "secrets": "x", "bogus": "1"},
		{"path": "/usr/bin/git", "secrets": "x", "args": "("},
		{"path": "/usr/bin/git", "secrets": "x", "dirs": "relative"},
	} {
		if _, err := commandOf(instance("git", f)); err == nil {
			t.Errorf("%v accepted", f)
		}
	}
}

func TestGuardForms(t *testing.T) {
	v := "s3cr3t-value-0123456789"
	vals := []secret.Value{secret.FromString(v)}
	for _, out := range []string{
		v, "prefix " + base64.StdEncoding.EncodeToString([]byte("ab"+v+"cd")), hex.EncodeToString([]byte(v)),
		"x" + base64.RawURLEncoding.EncodeToString([]byte("z"+v)), reverse(v),
	} {
		if !leaks([]byte(out), vals) {
			t.Errorf("guard missed %q", out)
		}
	}
	if leaks([]byte("nothing here"), vals) {
		t.Error("guard matched clean text")
	}
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func (r *rig) stateAudit(t *testing.T) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	err := r.st.View(context.Background(), func(tx state.Tx) error {
		var err error
		out, err = tx.QueryAudit(context.Background(), state.AuditQuery{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func instance(name string, fields map[string]any) config.Instance {
	return config.Instance{Name: name, Fields: fields}
}
