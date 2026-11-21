// SPDX-License-Identifier: AGPL-3.0-only

// Package run implements `scrim run -- <agent>` (specs/interception,
// "Wrapper mode"; specs/agent-identity, "Session tokens from scrim run").
//
// It makes sure a scrim is running and its data plane is ready, mints a
// session token bound to this process tree, and starts the agent as a child
// with its provider base URLs, forward proxy, CA trust, MCP registration,
// session token and declared placeholders set for that process only. Nothing
// persistent is changed: generated files live in a per-session directory
// removed when the agent exits. Signals are forwarded, the agent's exit code
// is returned, and the session is ended on the way out.
//
// It fails closed: if scrim cannot be started, its data plane is not ready
// or the session cannot be minted, the agent is not started, unless the
// weakening setting run.allow-unredacted-start says otherwise.
package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/profiles"
	"github.com/heliopsy/scrim/internal/secret"
)

// Options configure one run.
type Options struct {
	// Command is the agent and its arguments.
	Command []string
	// Preset forces an agent preset; nil picks one from Command.
	Preset *Preset
	// Environ is the environment to start from; nil means os.Environ.
	Environ []string
	// Dir is the agent's working directory; empty is the current one.
	Dir string
	// Daemon provides the running scrim.
	Daemon Daemon
	// Stdin, Stdout and Stderr are the agent's streams. Messages from
	// scrim run itself go to Stderr.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// MCP registers `scrim mcp` with agents whose preset supports it.
	MCP bool
	// ScrimPath is the scrim executable for MCP; empty is os.Executable.
	ScrimPath string
	// Placeholders returns the declared placeholders to export for the
	// session's agent. Optional.
	Placeholders func(ctx context.Context, agent string) ([]string, error)
	// Profiles renders the session's tool profiles. Optional.
	Profiles func(ctx context.Context, agent string, sess profiles.Session) (*profiles.Rendered, error)
	// Reserved reports names that must not be exported as placeholders.
	Reserved func(name string) bool
	// SessionName names the session; empty is the agent's base name.
	SessionName string
	// SessionTTL asks for a session lifetime; zero is the server default.
	SessionTTL time.Duration
	// AllowUnredacted starts the agent without scrim when scrim cannot
	// serve it (weakening; run.allow-unredacted-start).
	AllowUnredacted bool
	// RuntimeDir holds session directories; empty is the agent
	// environment's $XDG_RUNTIME_DIR/scrim/run or a per-user temporary
	// directory.
	RuntimeDir string
	// Signals, when set, replaces the process's signal subscription; tests
	// feed it.
	Signals <-chan os.Signal
	// Log receives operational messages. Optional.
	Log *slog.Logger

	// dryRun builds the plan only (PrintEnv).
	dryRun bool
}

// ErrRefused wraps every reason scrim run refuses to start the agent.
var ErrRefused = errors.New("scrim run: the agent was not started")

func refused(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, a...))
}

// ExitError carries the agent's exit status.
type ExitError struct {
	Code int
	// Signal is set when the agent was killed by a signal.
	Signal string
}

func (e *ExitError) Error() string {
	if e.Signal != "" {
		return fmt.Sprintf("agent killed by %s", e.Signal)
	}
	return fmt.Sprintf("agent exited with status %d", e.Code)
}

func (o *Options) environ() []string {
	if o.Environ != nil {
		return o.Environ
	}
	return os.Environ()
}

func (o *Options) stderr() io.Writer {
	if o.Stderr == nil {
		return io.Discard
	}
	return o.Stderr
}

func (o *Options) say(format string, a ...any) {
	_, _ = fmt.Fprintf(o.stderr(), "scrim run: "+format+"\n", a...)
}

// Prepared is a run that is ready to start: scrim is up, the session is
// minted and the plan is built. Close releases everything.
type Prepared struct {
	Plan *Plan
	// Session is the minted session; zero when the agent runs unprotected.
	Session localapi.SessionInfo
	// Dir is the session directory.
	Dir string
	// Unprotected is true when the agent starts without scrim.
	Unprotected bool

	opts     Options
	instance Instance
	token    secret.Value
	client   *localapi.Client
}

// Prepare ensures scrim runs, mints the session, writes the session
// directory and builds the plan. Close undoes it.
func Prepare(ctx context.Context, o Options) (*Prepared, error) {
	if len(o.Command) == 0 {
		return nil, errors.New("scrim run: no agent command; usage: scrim run [flags] -- <agent> [args...]")
	}
	if err := checkCommand(o.Command); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	env := envMap(o.environ())
	if env[localapi.EnvToken] != "" {
		return nil, refused("already inside a scrim run session (%s is set); a session cannot start another", localapi.EnvToken)
	}
	p := &Prepared{opts: o}
	if o.Daemon == nil {
		o.Daemon = Unavailable{}
	}
	inst, err := o.Daemon.Ensure(ctx)
	if err != nil {
		return p.unprotected(fmt.Errorf("scrim is not running and could not be started: %w", err))
	}
	p.instance = inst
	if err := inst.Ready(ctx); err != nil {
		return p.unprotected(fmt.Errorf("scrim's data plane is not ready: %w", err))
	}
	ep := inst.Endpoints()
	if ep.LLMBaseURL == "" {
		return p.unprotected(errors.New("scrim has no LLM base URL listener"))
	}
	if ep.APISocket == "" {
		return p.unprotected(errors.New("scrim has no local agent API"))
	}
	if !o.dry() {
		p.client = localapi.NewClient(ep.APISocket, secret.Value{})
		name := o.SessionName
		if name == "" {
			name = filepath.Base(o.Command[0])
		}
		m, err := p.client.Mint(ctx, localapi.MintInput{Name: name, TTLSeconds: int(o.SessionTTL / time.Second)})
		p.client.Close()
		p.client = nil
		if err != nil {
			return p.unprotected(fmt.Errorf("minting a session failed: %w", err))
		}
		p.token, p.Session = m.Token, m.Session
		p.client = localapi.NewClient(ep.APISocket, p.token)
	}
	if err := p.build(ctx, ep); err != nil {
		p.Close(ctx)
		return nil, err
	}
	return p, nil
}

func (o *Options) dry() bool { return o.dryRun }

func (p *Prepared) build(ctx context.Context, ep Endpoints) error {
	o := p.opts
	dir := "<session-dir>"
	if !o.dry() {
		d, err := sessionDir(o.RuntimeDir, envMap(o.environ())["XDG_RUNTIME_DIR"], p.Session.ID)
		if err != nil {
			return refused("creating the session directory failed: %v", err)
		}
		p.Dir, dir = d, d
	}
	scrimPath := o.ScrimPath
	if scrimPath == "" {
		if exe, err := os.Executable(); err == nil {
			scrimPath = exe
		} else {
			scrimPath = "scrim"
		}
	}
	var phs []string
	if o.Placeholders != nil {
		var err error
		if phs, err = o.Placeholders(ctx, p.Session.Agent); err != nil {
			return refused("loading declared placeholders failed: %v", err)
		}
	}
	var rendered *profiles.Rendered
	if o.Profiles != nil {
		if ep.ForwardProxy == "" {
			o.say("tool profiles are not applied: scrim has no forward proxy, so their placeholders would never be injected")
		} else {
			sess := profiles.Session{Dir: filepath.Join(dir, ProfilesDir), CABundle: filepath.Join(dir, FileBundle),
				Home: envMap(o.environ())["HOME"]}
			var err error
			if rendered, err = o.Profiles(ctx, p.Session.Agent, sess); err != nil {
				return refused("tool profiles: %v", err)
			}
		}
	}
	in := Input{
		Command: o.Command, Preset: o.Preset, Environ: o.environ(), Endpoints: ep,
		SessionDir: dir, SessionID: p.Session.ID, Token: !p.token.IsZero() || o.dry(),
		MCP: o.MCP, ScrimPath: scrimPath, Placeholders: phs, Reserved: o.Reserved, Profiles: rendered,
	}
	if ep.ForwardProxy != "" {
		in.SystemRoots, in.NodeExtra = trustInputs(envMap(o.environ()))
	}
	plan, err := Build(in)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRefused, err)
	}
	p.Plan = plan
	if o.dry() {
		return nil
	}
	for _, d := range plan.Dirs {
		if err := os.MkdirAll(filepath.Join(p.Dir, filepath.FromSlash(d)), 0o700); err != nil {
			return refused("creating %s failed: %v", d, err)
		}
	}
	for name, data := range plan.Files {
		f := filepath.Join(p.Dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			return refused("creating the directory of %s failed: %v", name, err)
		}
		if err := os.WriteFile(f, data, 0o600); err != nil {
			return refused("writing %s failed: %v", name, err)
		}
	}
	return nil
}

// unprotected either refuses (the default) or, with AllowUnredacted,
// prepares a run that starts the agent as if scrim were not there.
func (p *Prepared) unprotected(cause error) (*Prepared, error) {
	if p.instance != nil {
		_ = p.instance.Release(context.Background())
		p.instance = nil
	}
	if !p.opts.AllowUnredacted {
		return nil, fmt.Errorf("%w: %w; refusing to start it without redaction (run.allow-unredacted-start weakens this)", ErrRefused, cause)
	}
	p.opts.say("WARNING: %v", cause)
	p.opts.say("WARNING: run.allow-unredacted-start is set: starting %s WITHOUT scrim; its traffic reaches providers unredacted", filepath.Base(p.opts.Command[0]))
	p.Unprotected = true
	p.Plan = &Plan{Preset: "none", Args: p.opts.Command}
	return p, nil
}

// Close ends the session, removes the session directory and releases the
// instance. It is safe to call more than once.
func (p *Prepared) Close(ctx context.Context) {
	if p.client != nil {
		if err := p.client.EndSession(ctx); err != nil && p.opts.Log != nil {
			// The sweep revokes it once this process is gone.
			p.opts.Log.Warn("ending the session failed", "session", p.Session.ID, "error", err)
		}
		p.client.Close()
		p.client = nil
	}
	p.token.Wipe()
	if p.Dir != "" {
		_ = os.RemoveAll(p.Dir)
		p.Dir = ""
	}
	if p.instance != nil {
		_ = p.instance.Release(ctx)
		p.instance = nil
	}
}

// Start runs the agent, forwards signals and waits for it. It returns nil
// for exit status 0 and an *ExitError otherwise.
func (p *Prepared) Start(ctx context.Context) error {
	o := p.opts
	for _, w := range p.Plan.Warnings {
		o.say("%s", w)
	}
	env := o.environ()
	if !p.Unprotected {
		var err error
		if env, err = p.Plan.Environ(env, p.token); err != nil {
			return fmt.Errorf("%w: %w", ErrRefused, err)
		}
		if err := p.instance.Ready(ctx); err != nil {
			return refused("scrim's data plane stopped being ready: %v", err)
		}
	}
	path, err := lookPath(p.Plan.Args[0], env)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRefused, err)
	}
	cmd := &exec.Cmd{Path: path, Args: p.Plan.Args, Env: env, Dir: o.Dir,
		Stdin: o.Stdin, Stdout: o.Stdout, Stderr: o.Stderr}
	return supervise(cmd, o.Signals, o.stderr())
}

// lookPath resolves name against the agent's own PATH.
func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	path := envMap(env)["PATH"]
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		f := filepath.Join(dir, name)
		if st, err := os.Stat(f); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return f, nil
		}
	}
	return "", fmt.Errorf("%s: not found in PATH", name)
}

// Run prepares, starts and cleans up one run.
func Run(ctx context.Context, o Options) error {
	p, err := Prepare(ctx, o)
	if err != nil {
		return err
	}
	defer p.Close(context.WithoutCancel(ctx))
	return p.Start(ctx)
}

// PrintEnv returns the plan without minting a session or writing files.
func PrintEnv(ctx context.Context, o Options) (*Plan, error) {
	o.dryRun = true
	o.AllowUnredacted = false
	p, err := Prepare(ctx, o)
	if err != nil {
		return nil, err
	}
	defer p.Close(ctx)
	return p.Plan, nil
}

// sessionDir creates the per-session directory, mode 0700, under root or
// the agent's XDG_RUNTIME_DIR.
func sessionDir(root, xdg, id string) (string, error) {
	if root == "" {
		if xdg != "" {
			root = filepath.Join(xdg, "scrim", "run")
		} else {
			root = filepath.Join(os.TempDir(), fmt.Sprintf("scrim-%d", os.Getuid()), "run")
		}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	if id == "" {
		id = "session"
	}
	return os.MkdirTemp(root, id+"-")
}
