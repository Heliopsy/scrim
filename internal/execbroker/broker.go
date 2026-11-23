// SPDX-License-Identifier: AGPL-3.0-only

// Package execbroker runs commands on an agent's behalf with secrets the
// agent never holds (specs/credential-injection "Exec broker", "Exec broker
// output is redacted"; design D5).
//
// The agent names a command and puts placeholders where a secret belongs:
// in an environment variable, and where the command's allow-list entry
// permits it, in an argument or on standard input. The broker
//
//  1. refuses programs that print, encode or split their input or
//     environment, run other programs or interpret code, whatever policy
//     says, and arguments known to turn an allowed tool into one of those;
//  2. resolves each placeholder to a credential in the redaction set and
//     decides `op == "exec"` for each through the control plane's gate
//     (break-glass, rules, grants, approvals, audit). A command on the
//     credential's allow list (exec.commands) is allowed when no rule
//     decides; any other command needs a rule that allows it;
//  3. runs the program with a clean environment, outside the agent's
//     process tree and file system view, as a different operating-system
//     user than the caller (exec.user), so the agent cannot read the
//     process's environment or memory;
//  4. redacts standard output and standard error through the data plane's
//     redactor, checks the result again with its own guard, and withholds a
//     stream that still holds a value or cannot be redacted.
//
// [Broker.Run] is the whole API: it takes the caller's identity from the
// transport and a [Request], so the local socket (POST /v1/exec), the MCP
// tool, the CLI and an edge forwarder in an agent pod all reach the same
// checks.
package execbroker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
)

// ToolSecretExec is the tool name in audit, MCP and the CLI.
const ToolSecretExec = agenttools.ToolSecretExec

const maxRendered = 512

// Request is one command an agent asks the broker to run. It never holds a
// value, only placeholders.
type Request = agenttools.ExecInput

// Result is what came back from a command, after redaction.
type Result = agenttools.ExecOutput

// Redacted is the redactor's answer.
type Redacted struct {
	Text         []byte
	Replacements int
}

// Redactor redacts text with the data plane's redactor and guard. It owns
// text and wipes it.
type Redactor func(ctx context.Context, text []byte) (Redacted, error)

// Deps are what a Broker is built from. Every field but Logger and Now is
// required.
type Deps struct {
	// Config returns the broker configuration in force.
	Config   func() (Config, error)
	Values   Values
	Gate     *gate.Gate
	Redactor Redactor
	Auditor  agenttools.Auditor
	Logger   *slog.Logger
	Now      func() time.Time
	// runner starts processes; tests replace it.
	runner func(ctx context.Context, s spec) (outcome, error)
}

// Broker runs brokered commands.
type Broker struct{ d Deps }

// New returns a Broker.
func New(d Deps) (*Broker, error) {
	if d.Config == nil || d.Values == nil || d.Gate == nil || d.Redactor == nil || d.Auditor == nil {
		return nil, errors.New("execbroker: config, values, gate, redactor and auditor are required")
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.runner == nil {
		d.runner = start
	}
	return &Broker{d: d}, nil
}

// call is one Run being audited.
type call struct {
	b     *Broker
	id    identity.Identity
	entry agenttools.AuditEntry
}

// Run runs req for the caller id. Errors are *agenttools.Error, safe to
// show; none holds a value.
func (b *Broker) Run(ctx context.Context, id identity.Identity, req Request) (Result, error) {
	c := &call{b: b, id: id, entry: agenttools.AuditEntry{
		Agent: id.Agent, Principal: id.Principal(), Source: string(id.Source), SessionID: id.SessionID,
		UID: id.Peer.UID, PID: id.Peer.PID, Tool: ToolSecretExec,
	}}
	res, err := c.run(ctx, req)
	return res, c.finish(ctx, err)
}

func (c *call) finish(ctx context.Context, err error) error {
	c.entry.Time = c.b.d.Now().UTC()
	if c.entry.Outcome == "" {
		switch agenttools.CodeOf(err) {
		case agenttools.CodeDenied, agenttools.CodeForbidden, agenttools.CodeNeedsApproval:
			c.entry.Outcome = agenttools.OutcomeDenied
		case agenttools.CodeUnauthenticated, agenttools.CodeInvalid:
			c.entry.Outcome = agenttools.OutcomeRefused
		default:
			c.entry.Outcome = agenttools.OutcomeError
		}
		if err == nil {
			c.entry.Outcome = agenttools.OutcomeOK
		}
	}
	if err != nil && c.entry.Detail == "" {
		c.entry.Detail = agenttools.Public(err).Message
	}
	if aerr := c.b.d.Auditor.Record(ctx, c.entry); aerr != nil {
		c.b.d.Logger.Error("audit write failed", "tool", ToolSecretExec, "error", aerr)
		if err == nil {
			return agenttools.Errorf(agenttools.CodeUnavailable, "the audit log is unavailable")
		}
	}
	if err != nil {
		return agenttools.Public(err)
	}
	return nil
}

func refuse(code agenttools.Code, format string, args ...any) error {
	return agenttools.Errorf(code, format, args...)
}

func (c *call) run(ctx context.Context, req Request) (Result, error) {
	if !c.id.Known() {
		return Result{}, refuse(agenttools.CodeUnauthenticated, "the caller has no agent identity")
	}
	if !c.id.Has(identity.ScopeSecretsRequest) {
		return Result{}, refuse(agenttools.CodeForbidden, "the caller's identity lacks scope %s", identity.ScopeSecretsRequest)
	}
	if err := checkRequest(req); err != nil {
		return Result{}, err
	}
	cfg, err := c.b.d.Config()
	if err != nil {
		c.b.d.Logger.Warn("exec broker configuration is not usable", "error", err)
		return Result{}, refuse(agenttools.CodeUnavailable, "the exec broker is not configured correctly")
	}
	name := req.Command[0]
	args := req.Command[1:]
	rendered := render(req.Command)

	// 1. The command itself.
	cmd := cfg.Commands[name]
	var path string
	if cmd != nil {
		path = cmd.Path
	} else {
		path = lookPath(name, cfg.Path)
	}
	if t := transformOf(name, orName(path, name)); t != "" {
		c.entry.Detail = "blocked transform: " + name + " (" + t + ")"
		return Result{}, refuse(agenttools.CodeDenied, "%s is never run by the exec broker: it can print or transform a secret (%s)", name, t)
	}
	if path == "" {
		return Result{}, refuse(agenttools.CodeNotFound, "command %s is not in exec.commands and not found in exec.path", name)
	}
	rules := builtinTools[filepath.Base(path)]
	if arg, why := rules.checkArgs(args); why != "" {
		c.entry.Detail = "blocked argument for " + name
		return Result{}, refuse(agenttools.CodeDenied, "%s %s: %s", name, render([]string{arg}), why)
	}
	if cmd != nil && len(cmd.Args) > 0 {
		ra := render(args)
		if !slices.ContainsFunc(cmd.Args, func(re *regexp.Regexp) bool { return re.MatchString(ra) }) {
			c.entry.Detail = "arguments not allowed for " + name
			return Result{}, refuse(agenttools.CodeDenied, "the arguments do not match any pattern exec.commands.%s.args allows", name)
		}
	}
	inject := []Location{InEnv}
	var envNames []string
	if cmd != nil {
		inject, envNames = cmd.Inject, cmd.EnvNames
	}
	for k := range req.Env {
		if envDenied(k) {
			return Result{}, refuse(agenttools.CodeDenied, "environment variable %s cannot be set through the exec broker", k)
		}
		if cmd != nil && !slices.ContainsFunc(envNames, func(p string) bool { return policy.Glob(p, k) }) {
			return Result{}, refuse(agenttools.CodeDenied, "environment variable %s is not in exec.commands.%s.env-names", k, name)
		}
		if _, fixed := rules.Env[k]; fixed {
			return Result{}, refuse(agenttools.CodeDenied, "environment variable %s is fixed for %s", k, name)
		}
		if cmd != nil {
			if _, fixed := cmd.Env[k]; fixed {
				return Result{}, refuse(agenttools.CodeDenied, "environment variable %s is fixed for %s", k, name)
			}
		}
	}
	dir, err := chooseDir(cmd, name, req.Dir)
	if err != nil {
		return Result{}, err
	}

	// 2. Who runs it.
	who, err := runAs(cfg.User)
	if err != nil {
		c.b.d.Logger.Warn("exec.user cannot be resolved", "error", err)
		return Result{}, refuse(agenttools.CodeUnavailable, "exec.user cannot be resolved")
	}
	if who.UID == 0 {
		return Result{}, refuse(agenttools.CodeUnavailable, "brokered commands never run as root; set exec.user")
	}
	if callerUID, local := localUID(c.id); local && callerUID == who.UID && !cfg.AllowSameUser {
		return Result{}, refuse(agenttools.CodeUnavailable,
			"the command would run as the calling agent's own user, who could read the secret from it; set exec.user to another user")
	}

	// 3. Which secrets.
	texts := map[Location][]string{InArgs: args, InStdin: {req.Stdin}}
	for _, v := range req.Env {
		texts[InEnv] = append(texts[InEnv], v)
	}
	matches, err := c.b.d.Values.Find(ctx, func(form string) bool {
		for _, ts := range texts {
			for _, t := range ts {
				if strings.Contains(t, form) {
					return true
				}
			}
		}
		return false
	})
	if err != nil {
		c.b.d.Logger.Warn("resolving placeholders failed", "error", err)
		return Result{}, refuse(agenttools.CodeUnavailable, "the secrets could not be looked up")
	}
	defer func() {
		for _, m := range matches {
			m.Value.Wipe()
		}
	}()

	sub := substitution{matches: matches}
	defer sub.wipe()
	argv := make([][]byte, 0, len(req.Command))
	argv = append(argv, []byte(filepath.Base(path)))
	for _, a := range args {
		b, err := sub.apply(a, InArgs, slices.Contains(inject, InArgs))
		if err != nil {
			return Result{}, err
		}
		argv = append(argv, b)
	}
	stdin, err := sub.apply(req.Stdin, InStdin, slices.Contains(inject, InStdin))
	if err != nil {
		return Result{}, err
	}
	env := baseEnv(cfg, who)
	for k, v := range rules.Env {
		env = append(env, []byte(k+"="+v))
	}
	if cmd != nil {
		for k, v := range cmd.fixedEnv() {
			env = append(env, []byte(k+"="+v))
		}
	}
	for _, k := range sortedKeys(req.Env) {
		b, err := sub.apply(req.Env[k], InEnv, slices.Contains(inject, InEnv))
		if err != nil {
			return Result{}, err
		}
		kv := append([]byte(k+"="), b...)
		sub.track(kv)
		env = append(env, kv)
	}
	if len(sub.used) == 0 {
		return Result{}, refuse(agenttools.CodeInvalid, "the command names no secret by placeholder; run it yourself")
	}
	used := sub.usedMatches()
	refs := make([]string, 0, len(used))
	for _, m := range used {
		refs = append(refs, m.Ref.String())
	}
	slices.Sort(refs)
	refs = slices.Compact(refs)
	c.entry.Ref = strings.Join(refs, ",")

	// 4. Policy, per secret.
	for _, m := range used {
		allowListed := cmd != nil && cmd.allowsSecret(m.Ref.String(), m.Name)
		v := c.decide(ctx, m, name, rendered, allowListed)
		c.entry.Rule, c.entry.Decision = v.Rule, string(v.Status)
		if v.ApprovalID != "" {
			c.entry.ApprovalID = v.ApprovalID
		}
		if v.GrantID != "" {
			c.entry.GrantID = v.GrantID
		}
		if !v.Allowed() {
			reason := v.Reason
			if reason == "" {
				reason = "denied by policy"
			}
			if !allowListed {
				reason += fmt.Sprintf("; %s is not on the allow list of %s", name, m.Ref)
			}
			return Result{}, refuse(agenttools.CodeDenied, "%s with %s: %s", name, m.Ref, reason)
		}
	}

	// 5. Run.
	timeout := cfg.Timeout
	if cmd != nil && cmd.Timeout > 0 && cmd.Timeout < timeout {
		timeout = cmd.Timeout
	}
	if req.TimeoutSeconds > 0 && time.Duration(req.TimeoutSeconds)*time.Second < timeout {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	if dir == "" {
		tmp, err := scratchDir(who)
		if err != nil {
			c.b.d.Logger.Warn("creating the command's working directory failed", "error", err)
			return Result{}, refuse(agenttools.CodeUnavailable, "the command's working directory could not be created")
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		dir = tmp
	}
	out, err := c.b.d.runner(ctx, spec{path: path, argv: argv, env: env, stdin: stdin, dir: dir, who: who,
		timeout: timeout, maxOutput: cfg.MaxOutput})
	sub.wipe()
	if err != nil {
		c.b.d.Logger.Warn("starting a brokered command failed", "command", name, "error", err)
		return Result{}, refuse(agenttools.CodeUnavailable, "%s could not be started", name)
	}
	defer out.wipe()

	// 6. Output.
	res := Result{ExitCode: out.exitCode, TimedOut: out.timedOut, Refs: refs}
	values := make([]secret.Value, 0, len(used))
	for _, m := range used {
		values = append(values, m.Value)
	}
	res.Stdout = c.redact(ctx, &res, "stdout", out.stdout, out.stdoutOver, values)
	res.Stderr = c.redact(ctx, &res, "stderr", out.stderr, out.stderrOver, values)
	c.entry.Detail = "exit " + strconv.Itoa(res.ExitCode)
	if res.TimedOut {
		c.entry.Detail += ", timed out"
	}
	if res.Redactions > 0 {
		c.entry.Detail += fmt.Sprintf(", %d values redacted", res.Redactions)
	}
	for _, s := range sortedKeys(res.Withheld) {
		c.entry.Detail += ", " + s + " withheld"
	}
	return res, nil
}

// decide runs one secret's use through the gate. An allow-listed command
// is allowed when no rule decides; rules still deny or ask.
func (c *call) decide(ctx context.Context, m Match, name, rendered string, allowListed bool) gate.Verdict {
	g := *c.b.d.Gate
	if allowListed {
		g.Engine = allowList{Engine: g.Engine, command: name}
	}
	req := policy.Request{Agent: c.id.PolicyAgent(), Action: policy.ActionExec, Ref: m.Ref, Name: m.Name,
		Store: m.Ref.Scheme, SecretClass: m.Class, Tool: name, Command: rendered, Time: c.b.d.Now()}
	return g.Check(ctx, req, gate.Options{Wait: true, Attrs: map[string]string{"tool": ToolSecretExec}})
}

// allowList turns the default decision into allow for a command on the
// secret's allow list: the operator's exec.commands entry is the allow.
type allowList struct {
	policy.Engine
	command string
}

// RuleAllowList names the decision an allow-list entry makes.
const RuleAllowList = "exec.allow-list"

func (a allowList) Decide(ctx context.Context, req policy.Request) (policy.Decision, error) {
	d, err := a.Engine.Decide(ctx, req)
	if err == nil && d.Rule == policy.DefaultRule {
		return policy.Decision{Effect: policy.Allow, Rule: RuleAllowList,
			Reason: "exec.commands." + a.command + " lists this secret"}, nil
	}
	return d, err
}

// redact returns one output stream as the agent may see it, or "" with
// the reason recorded in res.Withheld.
func (c *call) redact(ctx context.Context, res *Result, stream string, raw []byte, over bool, values []secret.Value) string {
	withhold := func(why string) string {
		if res.Withheld == nil {
			res.Withheld = map[string]string{}
		}
		res.Withheld[stream] = why
		return ""
	}
	if over {
		return withhold("larger than exec.max-output; withheld whole, never cut")
	}
	if len(raw) == 0 {
		return ""
	}
	r, err := c.b.d.Redactor(ctx, slices.Clone(raw))
	if err != nil {
		c.b.d.Logger.Warn("redacting brokered command output failed; withholding it", "stream", stream, "error", err)
		return withhold("scrim could not redact it")
	}
	defer secret.WipeBytes(r.Text)
	if leaks(r.Text, values) {
		c.b.d.Logger.Warn("brokered command output still held an injected value after redaction; withholding it", "stream", stream)
		return withhold("it still held a secret after redaction")
	}
	if !utf8.Valid(r.Text) {
		return withhold("it is not text")
	}
	res.Redactions += r.Replacements
	return string(r.Text)
}

// checkRequest validates the shape of a request.
func checkRequest(req Request) error {
	if len(req.Command) == 0 || req.Command[0] == "" {
		return refuse(agenttools.CodeInvalid, "command is required")
	}
	if strings.ContainsAny(req.Command[0], "/\\") {
		return refuse(agenttools.CodeInvalid, "command must be a name such as git, not a path; the broker decides which program runs")
	}
	if len(req.Command) > agenttools.MaxExecArgs+1 {
		return refuse(agenttools.CodeInvalid, "at most %d arguments", agenttools.MaxExecArgs)
	}
	for _, a := range req.Command {
		if len(a) > agenttools.MaxExecArgLen || strings.ContainsRune(a, 0) {
			return refuse(agenttools.CodeInvalid, "an argument is longer than %d bytes or holds a NUL byte", agenttools.MaxExecArgLen)
		}
	}
	if len(req.Env) > agenttools.MaxExecEnv {
		return refuse(agenttools.CodeInvalid, "at most %d environment variables", agenttools.MaxExecEnv)
	}
	for k, v := range req.Env {
		if !validEnvName(k) || len(v) > agenttools.MaxExecArgLen || strings.ContainsRune(v, 0) {
			return refuse(agenttools.CodeInvalid, "environment variable %q is not a valid name with a value up to %d bytes", k, agenttools.MaxExecArgLen)
		}
	}
	if len(req.Stdin) > agenttools.MaxExecStdin {
		return refuse(agenttools.CodeInvalid, "stdin is larger than %d bytes", agenttools.MaxExecStdin)
	}
	if req.TimeoutSeconds < 0 {
		return refuse(agenttools.CodeInvalid, "timeout_seconds must not be negative")
	}
	return nil
}

// chooseDir checks the requested working directory against the command's
// dirs. Empty means a fresh empty directory.
func chooseDir(cmd *Command, name, dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return "", refuse(agenttools.CodeInvalid, "dir must be an absolute, clean path")
	}
	if cmd == nil || !slices.ContainsFunc(cmd.Dirs, func(p string) bool { return policy.Glob(p, dir) }) {
		return "", refuse(agenttools.CodeDenied, "%s may not run in %s; exec.commands.%s.dirs decides where it may", name, dir, name)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", refuse(agenttools.CodeInvalid, "dir %s does not exist", dir)
	}
	if real != dir && !slices.ContainsFunc(cmd.Dirs, func(p string) bool { return policy.Glob(p, real) }) {
		return "", refuse(agenttools.CodeDenied, "dir %s resolves to %s, which exec.commands.%s.dirs does not allow", dir, real, name)
	}
	return real, nil
}

// localUID is the caller's Unix user when it reached scrim over a local
// socket.
func localUID(id identity.Identity) (uint32, bool) {
	switch id.Source {
	case identity.SourcePeer, identity.SourceSession:
		return id.Peer.UID, true
	}
	return 0, false
}

// lookPath finds name in the broker's PATH, never the agent's.
func lookPath(name, path string) string {
	for d := range strings.SplitSeq(path, ":") {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func orName(path, name string) string {
	if path == "" {
		return name
	}
	return path
}

// render shell-quotes argv for policy (tool.command), approvals and audit.
// It is built from the request, never from substituted values.
func render(argv []string) string {
	var b strings.Builder
	for i, a := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		if a != "" && !strings.ContainsFunc(a, needsQuote) {
			b.WriteString(a)
		} else {
			b.WriteString("'" + strings.ReplaceAll(a, "'", `'\''`) + "'")
		}
	}
	s := b.String()
	if len(s) > maxRendered {
		cut := maxRendered
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return s
}

// needsQuote reports whether r makes a word need shell quoting.
func needsQuote(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r >= 0x80:
		return false
	}
	return !strings.ContainsRune("-_./:=@,+", r)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// substitution replaces placeholders and keeps every buffer that may hold a
// value, so they are all wiped.
type substitution struct {
	matches []Match
	used    []int
	bufs    [][]byte
}

func (s *substitution) apply(text string, where Location, allowed bool) ([]byte, error) {
	out, used, leftover := substitute(text, s.matches)
	if leftover {
		secret.WipeBytes(out)
		return nil, refuse(agenttools.CodeUnavailable,
			"a placeholder in %s names no credential with a value; nothing was run", where)
	}
	if len(used) > 0 && !allowed {
		secret.WipeBytes(out)
		return nil, refuse(agenttools.CodeDenied, "this command does not take secrets in %s", where)
	}
	for _, u := range used {
		if !slices.Contains(s.used, u) {
			s.used = append(s.used, u)
		}
	}
	s.track(out)
	return out, nil
}

func (s *substitution) track(bufs ...[]byte) { s.bufs = append(s.bufs, bufs...) }

func (s *substitution) usedMatches() []Match {
	out := make([]Match, 0, len(s.used))
	for _, u := range s.used {
		out = append(out, s.matches[u])
	}
	return out
}

func (s *substitution) wipe() {
	for _, b := range s.bufs {
		secret.WipeBytes(b)
	}
	s.bufs = nil
}
