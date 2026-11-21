// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/ca"
	"github.com/heliopsy/scrim/internal/daemon"
	"github.com/heliopsy/scrim/internal/install"
	"github.com/heliopsy/scrim/internal/version"
)

// Injection points for tests: the tools install runs, the probe of the
// started service, the filesystem root, the running binary, the effective
// user, the memlock check and ownership changes.
var (
	installRunner     install.Runner = ca.ExecRunner{}
	installProbe      install.Probe  = install.SocketProbe{}
	installRoot                      = ""
	installExecutable                = os.Executable
	installEUID                      = os.Geteuid
	installGOOS                      = runtime.GOOS
	installMemlock                   = memlockUnlimited
	installChown      func(string, int, int) error
	installUsername   = func() string {
		if u, err := user.Current(); err == nil {
			return u.Username
		}
		return ""
	}
)

type installFlags struct {
	user, system, quadlet, dryRun, purge bool
	image                                string
	agents                               []string
	// hooks and managed select an agent-side mode; agentNames are its
	// agents and forwardProxy also pins the forward proxy.
	hooks, managed, forwardProxy bool
	agentNames                   []string
}

// Install sets scrim up as a local service (specs/deployment "Local service
// installation").
func (Commands) Install(e *Env) *cobra.Command {
	var f installFlags
	c := &cobra.Command{
		Use:   "install (--user | --system | --quadlet [--system] | --hooks | --managed-settings)",
		Short: "Run scrim as a service: a systemd user unit, a hardened system unit, or a podman Quadlet container",
		Long: "Shows every change before making it and records it in a manifest, so `scrim uninstall` reverts exactly " +
			"those changes. Running it again with a new binary upgrades the service.\n\n" +
			"--user: a systemd user unit for this user, sockets in $XDG_RUNTIME_DIR/scrim, the CA trusted through " +
			"`scrim ca install --user`.\n" +
			"--system (as root): the dedicated system user scrim, /etc/scrim/config.yaml, state in /var/lib/scrim, " +
			"sockets in /run/scrim (the agent API for the group scrim-agents), a hardened unit, the CA in the system " +
			"trust store.\n" +
			"--quadlet: the container image under rootless podman for this user; with --system under root's podman as " +
			"the user scrim.\n\n" +
			"Agent-side modes, recorded in a manifest of their own and also reverted by `scrim uninstall`:\n" +
			"--hooks: scrim's PostToolUse and UserPromptSubmit hooks in this user's Claude Code and Codex configuration " +
			"(partial protection: tool results and prompts only; see docs/interception.md, method 6).\n" +
			"--managed-settings (as root): Claude Code's managed settings drop-in and Codex's requirements.toml, pinning " +
			"each agent to scrim's endpoint so its own settings cannot point it elsewhere.\n\n" +
			"See docs/service.md and docs/interception.md.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			in, err := newInstaller(cmd, e, f, true)
			if err != nil {
				return err
			}
			return in.Install(cmd.Context())
		},
	}
	c.Flags().BoolVar(&f.user, "user", false, "install a systemd user unit for this user")
	c.Flags().BoolVar(&f.system, "system", false, "install system-wide, as the dedicated user scrim (needs root)")
	c.Flags().BoolVar(&f.quadlet, "quadlet", false, "run the container image through a podman Quadlet unit (rootless, or with --system as root)")
	c.Flags().StringVar(&f.image, "image", "", "image for --quadlet (default "+install.DefaultImage+":<this version>)")
	c.Flags().StringSliceVar(&f.agents, "agent-user", nil, "with --system: add this user to the group scrim-agents and map it to an agent of the same name (repeatable)")
	c.Flags().BoolVar(&f.hooks, "hooks", false, "install scrim's hooks into this user's agent configuration (partial protection)")
	c.Flags().BoolVar(&f.managed, "managed-settings", false, "write the agents' managed settings so they can only use scrim's endpoint (needs root)")
	c.Flags().StringSliceVar(&f.agentNames, "agent", nil, "with --hooks or --managed-settings: claude or codex (repeatable; default the agents found on this machine)")
	c.Flags().BoolVar(&f.forwardProxy, "forward-proxy", false, "with --managed-settings: also pin Claude Code's HTTPS_PROXY to scrim's forward proxy (the CA must be in the system trust store)")
	c.Flags().BoolVar(&f.dryRun, "dry-run", false, "show the changes without making them")
	return c
}

// Uninstall reverts what `scrim install` recorded (specs/deployment
// "Complete uninstall").
func (Commands) Uninstall(e *Env) *cobra.Command {
	var f installFlags
	c := &cobra.Command{
		Use:   "uninstall [--user | --system | --hooks | --managed-settings] [--purge]",
		Short: "Revert every change `scrim install` recorded",
		Long: "Reverts each change in the install manifest, newest first: the CA trust, the service, the unit, the " +
			"configuration file it wrote, the binary, the users and groups it created. A change that cannot be " +
			"reverted (a file edited since) stays listed with the manual step, and the command exits 1.\n\n" +
			"The state (CA, placeholder keys, state database, audit log), and for Quadlet the volume and the pulled " +
			"image, are kept unless --purge is given.\n\n" +
			"Without --user or --system: the system install when run as root, otherwise this user's. Each also reverts " +
			"the agent-side mode of its scope: managed settings for the system, hooks for a user. --hooks or " +
			"--managed-settings reverts only that mode.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f.hooks || f.managed {
				if f.user || f.system || (f.hooks && f.managed) {
					return errors.New("--hooks and --managed-settings each stand alone")
				}
				in, err := newInstaller(cmd, e, f, false)
				if err != nil {
					return err
				}
				return in.Uninstall(cmd.Context())
			}
			if f.user && f.system {
				return errors.New("choose one of --user and --system")
			}
			if !f.user && !f.system {
				f.system = installEUID() == 0
				f.user = !f.system
			}
			in, err := newInstaller(cmd, e, f, false)
			if err != nil {
				return err
			}
			if err := in.Uninstall(cmd.Context()); err != nil {
				return err
			}
			// The agent-side mode of the same scope, when one is recorded.
			af := installFlags{dryRun: f.dryRun, hooks: f.user, managed: f.system}
			ain, err := newInstaller(cmd, e, af, false)
			if err != nil {
				return err
			}
			if _, found, err := install.ReadManifest(ain.ManifestPath()); err != nil || !found {
				return err
			}
			return ain.Uninstall(cmd.Context())
		},
	}
	c.Flags().BoolVar(&f.user, "user", false, "uninstall this user's service")
	c.Flags().BoolVar(&f.system, "system", false, "uninstall the system service (needs root)")
	c.Flags().BoolVar(&f.hooks, "hooks", false, "revert only the agent hooks of this user")
	c.Flags().BoolVar(&f.managed, "managed-settings", false, "revert only the managed agent settings (needs root)")
	c.Flags().BoolVar(&f.purge, "purge", false, "also remove the state directory, the podman volume and the pulled image")
	c.Flags().BoolVar(&f.dryRun, "dry-run", false, "show what would be reverted without changing anything")
	return c
}

func newInstaller(cmd *cobra.Command, e *Env, f installFlags, installing bool) (*install.Installer, error) {
	if installGOOS != "linux" {
		return nil, errors.New("scrim install supports Linux with systemd; on " + installGOOS + " run `scrim proxy` from a launch agent (not automated yet)")
	}
	in := &install.Installer{Root: installRoot, Runner: installRunner, Probe: installProbe, Chown: installChown,
		Out: cmd.OutOrStdout(), DryRun: f.dryRun, Purge: f.purge, AgentUsers: f.agents}
	if f.hooks || f.managed {
		return agentInstaller(in, cmd, e, f, installing)
	}
	switch {
	case f.quadlet:
		in.Mode, in.System = install.ModeQuadlet, f.system
	case f.system && f.user:
		return nil, errors.New("choose one of --user and --system")
	case f.system:
		in.Mode = install.ModeSystem
	case f.user:
		in.Mode = install.ModeUser
	default:
		return nil, errors.New("choose --user (a user unit), --system (the dedicated scrim user) or --quadlet (a podman container)")
	}
	root := installEUID() == 0
	switch {
	case in.SystemScope() && !root && !f.dryRun:
		return nil, errors.New("a system install changes users, units and the system trust store: run it as root (or with --dry-run)")
	case !in.SystemScope() && root && installRoot == "":
		return nil, errors.New("a user install as root would run scrim as root: use --system for a system-wide service")
	}
	if in.Mode == install.ModeQuadlet {
		in.Image = f.image
		if in.Image == "" {
			in.Image = defaultImage()
		}
	}
	if installing && (in.Mode == install.ModeUser || in.Mode == install.ModeSystem) {
		exe, err := installExecutable()
		if err != nil {
			return nil, err
		}
		in.Executable = exe
	}
	if in.SystemScope() {
		return in, nil
	}

	// User scope.
	getenv := e.getenv
	in.Home = getenv("HOME")
	if in.Home == "" || !filepath.IsAbs(in.Home) {
		return nil, errors.New("install: $HOME is not set")
	}
	in.RuntimeDir = getenv("XDG_RUNTIME_DIR")
	in.Username = installUsername()
	cfg, err := e.Config()
	if err != nil {
		return nil, err
	}
	if in.StateDir, err = cfg.StateDir(); err != nil {
		return nil, err
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" && filepath.IsAbs(x) {
		in.ConfigDir = filepath.Join(x, "scrim")
	} else {
		in.ConfigDir = filepath.Join(in.Home, ".config", "scrim")
	}
	if in.TrustDataDir, err = ca.DefaultDataDir(getenv); err != nil {
		return nil, err
	}
	in.MemlockUnlimited = installMemlock()
	quadletDir := filepath.Join(in.StateDir, "quadlet-ca")
	in.TrustFor = func(m install.Mode) install.UserTrust {
		if m == install.ModeQuadlet {
			return &bundleTrust{e: e, cmd: cmd, dir: quadletDir}
		}
		return &dirTrust{e: e, cmd: cmd}
	}
	return in, nil
}

// agentInstaller sets up an agent-side mode: hooks for this user, or
// managed settings for the machine.
func agentInstaller(in *install.Installer, cmd *cobra.Command, e *Env, f installFlags, installing bool) (*install.Installer, error) {
	switch {
	case f.hooks && f.managed:
		return nil, errors.New("choose one of --hooks and --managed-settings")
	case f.user || f.system || f.quadlet:
		return nil, errors.New("--hooks and --managed-settings change agents, not the service: run them on their own")
	case f.forwardProxy && !f.managed:
		return nil, errors.New("--forward-proxy goes with --managed-settings")
	}
	cfg, err := e.Config()
	if err != nil {
		return nil, err
	}
	if installing {
		if in.Agents, err = agentsFor(f.agentNames, e.getenv); err != nil {
			return nil, err
		}
	}
	if f.managed {
		in.Mode = install.ModeManaged
		if installEUID() != 0 && !f.dryRun && installRoot == "" {
			return nil, errors.New("managed settings live in system directories (/etc/claude-code, /etc/codex): run it as root (or with --dry-run)")
		}
		listen := daemon.ProxyListen.Get(cfg)
		if listen == "" {
			return nil, errors.New("proxy.listen is empty: managed settings pin the agents to scrim's LLM proxy base URL, so it must be on")
		}
		in.Managed = install.ManagedOptions{AnthropicBaseURL: "http://" + listen + "/anthropic", OpenAIBaseURL: "http://" + listen + "/openai/v1"}
		if f.forwardProxy {
			fwd := daemon.ForwardListen.Get(cfg)
			if fwd == "" {
				return nil, errors.New("--forward-proxy: proxy.forward-listen is empty")
			}
			in.Managed.ForwardProxy = "http://" + fwd
		}
		return in, nil
	}
	in.Mode = install.ModeHooks
	getenv := e.getenv
	in.Home = getenv("HOME")
	if in.Home == "" || !filepath.IsAbs(in.Home) {
		return nil, errors.New("install: $HOME is not set")
	}
	if in.StateDir, err = cfg.StateDir(); err != nil {
		return nil, err
	}
	in.ClaudeConfigDir = filepath.Join(in.Home, ".claude")
	if d := getenv("CLAUDE_CONFIG_DIR"); d != "" && filepath.IsAbs(d) {
		in.ClaudeConfigDir = d
	}
	in.CodexHome = filepath.Join(in.Home, ".codex")
	if d := getenv("CODEX_HOME"); d != "" && filepath.IsAbs(d) {
		in.CodexHome = d
	}
	if installing {
		exe, err := installExecutable()
		if err != nil {
			return nil, err
		}
		if in.HookExecutable, err = filepath.EvalSymlinks(exe); err != nil {
			return nil, fmt.Errorf("install: %w", err)
		}
	}
	return in, nil
}

// agentsFor checks the agents named, or finds the agents on this machine:
// an executable on PATH or a configuration directory in HOME.
func agentsFor(names []string, getenv func(string) string) ([]string, error) {
	if len(names) > 0 {
		var out []string
		for _, n := range names {
			if n != install.AgentClaude && n != install.AgentCodex {
				return nil, fmt.Errorf("--agent %q: one of claude, codex", n)
			}
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
		return out, nil
	}
	home := getenv("HOME")
	var out []string
	for _, a := range []struct{ name, dir string }{{install.AgentClaude, ".claude"}, {install.AgentCodex, ".codex"}} {
		_, err := installRunner.LookPath(a.name)
		if err == nil || (home != "" && dirExists(filepath.Join(home, a.dir))) {
			out = append(out, a.name)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no agent found (claude or codex on PATH, or ~/.claude, ~/.codex): name one with --agent")
	}
	return out, nil
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

var releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// defaultImage is the image of this binary's release, or latest for a
// development build.
func defaultImage() string {
	v := strings.TrimPrefix(version.Version, "v")
	if !releaseVersion.MatchString(v) {
		v = "latest"
	}
	return install.DefaultImage + ":" + v
}

// memlockUnlimited reports whether this process's hard memlock limit is
// unlimited, which the user manager it runs under inherits.
func memlockUnlimited() bool {
	f, err := os.Open("/proc/self/limits")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line, ok := strings.CutPrefix(sc.Text(), "Max locked memory"); ok {
			fields := strings.Fields(line)
			return len(fields) >= 2 && fields[1] == "unlimited"
		}
	}
	return false
}

// dirTrust is `scrim ca install --user` on the CA directory the user
// service uses (the same configuration, the same user).
type dirTrust struct {
	e   *Env
	cmd *cobra.Command
}

func (t *dirTrust) Install(ctx context.Context, _ string, dryRun bool) error {
	m, err := openCA(t.cmd, t.e, true)
	if err != nil {
		return err
	}
	defer m.Close()
	in, err := installer(t.e, t.cmd, m.Dir(), dryRun)
	if err != nil {
		return err
	}
	return in.Install(ctx, m.Certificates())
}

func (t *dirTrust) Uninstall(ctx context.Context, dryRun bool) error {
	in, err := installer(t.e, t.cmd, "", dryRun)
	if err != nil {
		return err
	}
	return in.Uninstall(ctx)
}

// bundleTrust trusts the CA a Quadlet container reported, with the trust
// manifest in its own directory: the CA directory is inside the container's
// volume.
type bundleTrust struct {
	e   *Env
	cmd *cobra.Command
	dir string
}

func (t *bundleTrust) Install(ctx context.Context, caPEM string, dryRun bool) error {
	in, err := installer(t.e, t.cmd, t.dir, dryRun)
	if err != nil {
		return err
	}
	return in.Install(ctx, certsFromPEM(caPEM))
}

func (t *bundleTrust) Uninstall(ctx context.Context, dryRun bool) error {
	in, err := installer(t.e, t.cmd, t.dir, dryRun)
	if err != nil {
		return err
	}
	if err := in.Uninstall(ctx); err != nil {
		return err
	}
	if !dryRun {
		// The trust installer's lock file and directory are ours.
		_ = os.Remove(filepath.Join(t.dir, ".lock"))
		_ = os.Remove(t.dir)
	}
	return nil
}

// certsFromPEM splits a bundle into certificates named by fingerprint; the
// first is the current CA.
func certsFromPEM(s string) []ca.Certificate {
	var out []ca.Certificate
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		sum := sha256.Sum256(b.Bytes)
		out = append(out, ca.Certificate{ID: hex.EncodeToString(sum[:8]), PEM: string(pem.EncodeToMemory(b)), Current: len(out) == 0})
	}
}
