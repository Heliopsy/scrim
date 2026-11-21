// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
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
	intercept                            install.Interception
}

// Install sets scrim up as a local service (specs/deployment "Local service
// installation").
func (Commands) Install(e *Env) *cobra.Command {
	var f installFlags
	c := &cobra.Command{
		Use:   "install (--user | --system | --quadlet [--system])",
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
			"Host-level interception, with --system (Linux):\n" +
			"--transparent: nftables rules redirect TCP 80 and 443 of the --cover-user users and --cover-cgroup control " +
			"groups to scrim's transparent listener, which routes by TLS server name; their direct and QUIC egress is " +
			"rejected, so an agent needs no configuration and cannot reach providers around scrim. The rules load from " +
			"scrim-transparent.service and stay while scrim is stopped (connections fail instead of going direct).\n" +
			"--dns: provider host names resolve to scrim's SNI listener through /etc/hosts. Connections made by address " +
			"bypass it; combine it with --transparent where that matters.\n" +
			"Both add the CA to the Java truststores as well as the system store.\n\n" +
			"See docs/service.md.",
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
	c.Flags().BoolVar(&f.dryRun, "dry-run", false, "show the changes without making them")
	c.Flags().BoolVar(&f.intercept.Transparent, "transparent", false, "with --system: redirect the covered users' and control groups' provider connections to scrim with nftables and block their direct egress")
	c.Flags().StringSliceVar(&f.intercept.CoverUsers, "cover-user", nil, "with --transparent: a user whose connections are redirected (repeatable)")
	c.Flags().StringSliceVar(&f.intercept.CoverCgroups, "cover-cgroup", nil, "with --transparent: a control group below /sys/fs/cgroup, such as agents.slice, whose connections are redirected (repeatable)")
	c.Flags().IntVar(&f.intercept.Port, "transparent-port", install.DefaultTransparentPort, "with --transparent: the port of the transparent listener on 127.0.0.1 and ::1")
	c.Flags().BoolVar(&f.intercept.BlockUnrouted, "block-unrouted", false, "with --transparent or --dns: close connections to hosts scrim has no route for instead of passing them through untouched")
	c.Flags().BoolVar(&f.intercept.DNS, "dns", false, "with --system: resolve provider host names to scrim's SNI listener through /etc/hosts (connections by address bypass it)")
	c.Flags().StringSliceVar(&f.intercept.DNSHosts, "dns-host", nil, "with --dns: a host name to resolve to scrim (repeatable; default the provider hosts of the configured routes)")
	c.Flags().StringVar(&f.intercept.DNSAddress, "dns-address", install.DefaultDNSAddress, "with --dns: the loopback address the names resolve to; the SNI listener binds port 443 on it")
	c.Flags().StringSliceVar(&f.intercept.JavaHomes, "java-home", nil, "with --transparent or --dns: a JDK outside /usr/lib/jvm whose truststore gets the CA (repeatable)")
	return c
}

// Uninstall reverts what `scrim install` recorded (specs/deployment
// "Complete uninstall").
func (Commands) Uninstall(e *Env) *cobra.Command {
	var f installFlags
	c := &cobra.Command{
		Use:   "uninstall [--user | --system] [--purge]",
		Short: "Revert every change `scrim install` recorded",
		Long: "Reverts each change in the install manifest, newest first: the CA trust, the service, the unit, the " +
			"configuration file it wrote, the binary, the users and groups it created. A change that cannot be " +
			"reverted (a file edited since) stays listed with the manual step, and the command exits 1.\n\n" +
			"The state (CA, placeholder keys, state database, audit log), and for Quadlet the volume and the pulled " +
			"image, are kept unless --purge is given.\n\n" +
			"Without --user or --system: the system install when run as root, otherwise this user's.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			return in.Uninstall(cmd.Context())
		},
	}
	c.Flags().BoolVar(&f.user, "user", false, "uninstall this user's service")
	c.Flags().BoolVar(&f.system, "system", false, "uninstall the system service (needs root)")
	c.Flags().BoolVar(&f.purge, "purge", false, "also remove the state directory, the podman volume and the pulled image")
	c.Flags().BoolVar(&f.dryRun, "dry-run", false, "show what would be reverted without changing anything")
	return c
}

func newInstaller(cmd *cobra.Command, e *Env, f installFlags, installing bool) (*install.Installer, error) {
	if installGOOS != "linux" {
		return nil, errors.New("scrim install supports Linux with systemd; on " + installGOOS + " run `scrim proxy` from a launch agent (not automated yet)")
	}
	in := &install.Installer{Root: installRoot, Runner: installRunner, Probe: installProbe, Chown: installChown,
		Out: cmd.OutOrStdout(), DryRun: f.dryRun, Purge: f.purge, AgentUsers: f.agents, Intercept: f.intercept}
	if f.intercept.DNS && len(f.intercept.DNSHosts) == 0 {
		cfg, err := e.Config()
		if err != nil {
			return nil, err
		}
		in.Intercept.DNSHosts = daemon.ProviderHosts(cfg)
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
