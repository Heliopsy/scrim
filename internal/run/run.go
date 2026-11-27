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
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/fsview"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/profiles"
	"github.com/heliopsy/scrim/internal/projectscan"
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
	// ScanProject scans the working directory for secret values in project
	// files (.env*, *.tfvars, application config) and registers them for
	// redaction before the agent starts (run.scan-project).
	ScanProject bool
	// ScanInterval is how often the project files are rescanned while the
	// agent runs; zero or negative scans once.
	ScanInterval time.Duration
	// FSView configures the session filesystem view; the zero value is
	// off.
	FSView FSViewOptions
	// SSHAgent serves scrim's ssh-agent on a socket in the session
	// directory and points SSH_AUTH_SOCK at it (run.ssh-agent).
	SSHAgent bool

	// dryRun builds the plan only (PrintEnv).
	dryRun bool
}

// FSViewOptions configure the session filesystem view (package fsview).
type FSViewOptions struct {
	// Mode is run.fs-view; empty is off.
	Mode string
	// Hide are run.fs-view-hide patterns.
	Hide []string
	// Helper is the executable that sets up the namespace view (it calls
	// fsview.Main); empty is os.Executable.
	Helper string
	// Probe checks the namespace view works; nil is fsview.Probe.
	Probe func(ctx context.Context, helper string) fsview.Availability
	// PasswdHome overrides the password-database home; tests set it.
	PasswdHome string
	// AllowReadableOwn starts the agent although the view cannot hide some
	// of scrim's own files its user can read
	// (run.fs-view-allow-readable-own-files, weakening).
	AllowReadableOwn bool
}

func (f FSViewOptions) helper() string {
	if f.Helper != "" {
		return f.Helper
	}
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return "scrim"
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
	project  *projectscan.Result
	stopSSH  func()
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
				Home: envMap(o.environ())["HOME"], Scrim: scrimPath}
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
		SSHAgent: o.SSHAgent,
	}
	if ep.ForwardProxy != "" {
		in.SystemRoots, in.NodeExtra = trustInputs(envMap(o.environ()))
	}
	plan, err := Build(in)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRefused, err)
	}
	p.Plan = plan
	if o.ScanProject {
		if err := p.scanProject(ctx); err != nil {
			return err
		}
	}
	if !o.dry() {
		if err := p.writeFiles(); err != nil {
			return err
		}
		if err := p.startSSHAgent(); err != nil {
			return err
		}
	}
	return p.buildView(ctx, ep, dir, scrimPath, rendered)
}

// writeFiles writes the plan's directories and files into the session
// directory.
func (p *Prepared) writeFiles() error {
	plan := p.Plan
	for _, d := range plan.Dirs {
		if err := os.MkdirAll(filepath.Join(p.Dir, filepath.FromSlash(d)), 0o700); err != nil {
			return refused("creating %s failed: %v", d, err)
		}
	}
	for name, target := range plan.Links {
		l := filepath.Join(p.Dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(l), 0o700); err != nil {
			return refused("creating the directory of %s failed: %v", name, err)
		}
		if err := linkBin(target, l); err != nil {
			return refused("linking %s failed: %v", name, err)
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

// SessionConfigFile is the empty config file SCRIM_CONFIG points at inside
// a session whose view hides scrim's config files, so `scrim mcp` and
// `scrim secret` there still start; they find the agent API through
// SCRIM_API_SOCKET.
const SessionConfigFile = "scrim-config.yaml"

// buildView builds the session filesystem view over the profiles' fixed
// paths, run.fs-view-hide and scrim's own files, and prepares it outside a
// dry run.
func (p *Prepared) buildView(ctx context.Context, ep Endpoints, dir, scrimPath string, rendered *profiles.Rendered) error {
	o := p.opts
	env := o.environ()
	in := fsview.Input{Mode: o.FSView.Mode, Home: envMap(env)["HOME"], PasswdHome: o.FSView.PasswdHome,
		Hide: o.FSView.Hide, SessionDir: dir, Paths: viewPaths(rendered, filepath.Join(dir, ProfilesDir)),
		Keep: []string{ep.APISocket, scrimPath, o.FSView.helper()}, AllowReadableOwn: o.FSView.AllowReadableOwn}
	if !o.dry() {
		in.Keep = append(in.Keep, dir)
	}
	if in.Mode != "" && in.Mode != fsview.ModeOff && runtime.GOOS != "windows" {
		own, warn, err := ownPaths(ctx, ep.APISocket)
		if err != nil {
			return refused("session filesystem view: %v", err)
		}
		if warn != "" {
			p.Plan.Warnings = append(p.Plan.Warnings, warn)
		}
		in.Own = own
	}
	in.Available = func() fsview.Availability {
		probe := o.FSView.Probe
		if probe == nil {
			probe = fsview.Probe
		}
		return probe(ctx, o.FSView.helper())
	}
	v, err := fsview.Build(in)
	if err != nil {
		return refused("session filesystem view: %v", err)
	}
	p.Plan.FSView = v
	for _, x := range v.Exposed {
		p.Plan.Warnings = append(p.Plan.Warnings, "filesystem view: NOT hidden ("+fsview.AllowReadableOwn.Name()+" is set): "+x)
	}
	if !v.Active() {
		return nil
	}
	if slices.ContainsFunc(v.Entries, func(e fsview.Entry) bool { return e.Own && e.Origin == config.OwnOriginConfigFile }) {
		cf := filepath.Join(dir, SessionConfigFile)
		p.Plan.Set = slices.DeleteFunc(p.Plan.Set, func(x Var) bool { return x.Name == config.EnvConfig })
		p.Plan.Set = append(p.Plan.Set, Var{Name: config.EnvConfig, Value: cf,
			Why: "scrim's config files are hidden from the session; scrim commands in it read this empty one"})
		if !o.dry() {
			data := fmt.Sprintf("# scrim run session %s: scrim's own config files are hidden from the agent.\napiVersion: %s\nkind: %s\n",
				p.Session.ID, config.APIVersion, config.FileKind)
			if err := os.WriteFile(cf, []byte(data), 0o600); err != nil {
				return refused("writing %s failed: %v", SessionConfigFile, err)
			}
		}
	}
	if v.Mode == fsview.ModeHome {
		for _, fv := range v.Vars(env) {
			p.Plan.Set = slices.DeleteFunc(p.Plan.Set, func(x Var) bool { return x.Name == fv.Name })
			p.Plan.Set = append(p.Plan.Set, Var{Name: fv.Name, Value: fv.Value, Why: fv.Why})
		}
		why := "run.fs-view is home"
		if v.Fallback != "" {
			why = "user namespaces are unavailable: " + v.Fallback
		}
		p.Plan.Warnings = append(p.Plan.Warnings, "filesystem view: HOME points at a mirror of your home without its credential files ("+why+"); not covered: "+strings.Join(v.Gaps, "; "))
	}
	if o.dry() {
		return nil
	}
	if err := v.Prepare(); err != nil {
		return refused("preparing the session filesystem view failed: %v", err)
	}
	return nil
}

// ownPaths asks the daemon behind socket, as the local user (the session
// token is not sent: sessions may not ask), which files it reads secrets
// or key material from. A daemon too old to say gives a warning and no
// paths; any other failure is an error, so the view never silently misses
// them.
func ownPaths(ctx context.Context, socket string) ([]fsview.OwnPath, string, error) {
	c := localapi.NewClient(socket, secret.Value{})
	defer c.Close()
	got, err := c.OwnPaths(ctx)
	if agenttools.CodeOf(err) == agenttools.CodeNotFound {
		return nil, "filesystem view: this scrim does not report its own files (an older version), so they are not hidden; restart it", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("asking scrim for its own files failed: %w", err)
	}
	out := make([]fsview.OwnPath, 0, len(got))
	for _, g := range got {
		out = append(out, fsview.OwnPath{Path: g.Path, Origin: g.Origin})
	}
	return out, "", nil
}

// viewPaths are the profiles' fixed paths, each with its replacement only
// when the profile generates it.
func viewPaths(r *profiles.Rendered, profilesDir string) []fsview.Path {
	if r == nil {
		return nil
	}
	generated := func(abs string) bool {
		for _, f := range r.Files {
			g := filepath.Join(profilesDir, filepath.FromSlash(f.Path))
			if g == abs || strings.HasPrefix(g, abs+string(filepath.Separator)) {
				return true
			}
		}
		for _, d := range r.Dirs {
			if filepath.Join(profilesDir, filepath.FromSlash(d)) == abs {
				return true
			}
		}
		return false
	}
	out := make([]fsview.Path, 0, len(r.Paths))
	for _, pv := range r.Paths {
		fp := fsview.Path{Home: pv.Home, Origin: pv.Profile}
		if pv.Generated != "" && generated(pv.Generated) {
			fp.Source = pv.Generated
		}
		out = append(out, fp)
	}
	return out
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
	if p.stopSSH != nil {
		p.stopSSH()
		p.stopSSH = nil
	}
	if p.client != nil {
		if err := p.client.EndSession(ctx); err != nil && p.opts.Log != nil {
			// The sweep revokes it once this process is gone.
			p.opts.Log.Warn("ending the session failed", "session", p.Session.ID, "error", err)
		}
		p.client.Close()
		p.client = nil
	}
	p.token.Wipe()
	p.project.Wipe()
	p.project = nil
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
	started := func() error { return nil }
	if v := p.Plan.FSView; !p.Unprotected && v.Active() && v.Mode == fsview.ModeNamespace {
		launch, err := fsview.Wrap(cmd, o.FSView.helper(), v)
		if err != nil {
			return refused("session filesystem view: %v", err)
		}
		defer launch.Close()
		started = func() error {
			if err := launch.Started(); err != nil {
				return refused("session filesystem view: %v", err)
			}
			return nil
		}
	}
	wctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); p.watchProject(wctx) }()
	defer func() { stop(); <-done }()
	return supervise(cmd, o.Signals, o.stderr(), started)
}

// lookPath resolves name against the agent's own PATH. On Windows a name
// without an extension is also tried with each of the agent's PATHEXT
// extensions, and any regular file counts as executable (there are no mode
// bits), as cmd.exe does.
func lookPath(name string, env []string) (string, error) {
	if strings.ContainsRune(name, '/') || (runtime.GOOS == "windows" && (strings.ContainsRune(name, '\\') || filepath.VolumeName(name) != "")) {
		return name, nil
	}
	vars := envMap(env)
	get := func(k string) string { return envGet(vars, k) }
	exts := []string{""}
	if runtime.GOOS == "windows" {
		pathext := get("PATHEXT")
		if pathext == "" {
			pathext = ".COM;.EXE;.BAT;.CMD"
		}
		if filepath.Ext(name) == "" {
			exts = nil
		}
		for e := range strings.SplitSeq(pathext, ";") {
			if e != "" {
				exts = append(exts, strings.ToLower(e))
			}
		}
	}
	for _, dir := range filepath.SplitList(get("PATH")) {
		if dir == "" {
			dir = "."
		}
		for _, ext := range exts {
			f := filepath.Join(dir, name+ext)
			if st, err := os.Stat(f); err == nil && st.Mode().IsRegular() && (runtime.GOOS == "windows" || st.Mode()&0o111 != 0) {
				return f, nil
			}
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
