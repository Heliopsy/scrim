// SPDX-License-Identifier: AGPL-3.0-only

// Package install sets scrim up as a local service and removes it again
// (specs/deployment "Local service installation" and "Complete uninstall").
//
// Three modes: a systemd user unit for the current user, a hardened system
// unit running as the dedicated user scrim, and a podman Quadlet container
// (rootless, or system-wide as the dedicated user). Every change is shown
// before it is made and recorded in a manifest; uninstall reverts exactly
// the recorded changes, newest first, and lists what it could not revert
// with the manual step. The CA trust of the mode is part of the install:
// the per-user stores through `scrim ca install --user`, or the system
// trust store.
package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/ca"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
)

// Mode is what is installed.
type Mode string

// Install modes.
const (
	ModeUser    Mode = "user"
	ModeSystem  Mode = "system"
	ModeQuadlet Mode = "quadlet"
)

// Names and paths of an install. The system paths are fixed so agents and
// `scrim status` find the service without configuration.
const (
	ServiceUser       = "scrim"
	AgentGroup        = localapi.SystemAgentGroup
	UnitName          = "scrim.service"
	SystemBinary      = "/usr/local/bin/scrim"
	SystemConfigDir   = "/etc/scrim"
	SystemConfigFile  = "/etc/scrim/config.yaml"
	SystemManifest    = "/etc/scrim/install.json"
	SystemStateDir    = "/var/lib/scrim"
	SystemRuntimeDir  = "/run/scrim"
	SystemUnitPath    = "/etc/systemd/system/scrim.service"
	SystemQuadletPath = "/etc/containers/systemd/scrim.container"
	QuadletVolume     = "scrim-state"
	// DefaultImage is the image repository; the tag is the binary's version.
	DefaultImage = "ghcr.io/heliopsy/scrim"
	// ManifestName is the user install's manifest in the user state dir.
	ManifestName = "install.json"
)

// System trust store tools: the anchor directory each reads and the command
// that rebuilds the store after a change.
var trustTools = []struct {
	tool, anchor string
	add, remove  []string
}{
	{"update-ca-certificates", "/usr/local/share/ca-certificates/scrim-ca.crt", nil, []string{"--fresh"}},          // Debian, Ubuntu
	{"update-ca-trust", "/etc/pki/ca-trust/source/anchors/scrim-ca.pem", []string{"extract"}, []string{"extract"}}, // Fedora, RHEL
}

// Runner runs the external tools (systemctl, useradd, podman, the trust
// store tools). Tests substitute a fake.
type Runner = ca.Runner

// Probe waits for the installed daemon and reads its public CA.
type Probe interface {
	WaitReady(ctx context.Context, adminSocket string) error
	CA(ctx context.Context, adminSocket string) (string, error)
}

// UserTrust is `scrim ca install --user` and its uninstall. caPEM is the
// CA the daemon reported; an implementation that opens the CA directory
// itself may ignore it.
type UserTrust interface {
	Install(ctx context.Context, caPEM string, dryRun bool) error
	Uninstall(ctx context.Context, dryRun bool) error
}

// ErrNotReverted is returned when a change could not be made or reverted;
// each is reported with the manual step.
var ErrNotReverted = errors.New("some changes could not be reverted")

// Installer installs and uninstalls one mode.
type Installer struct {
	Mode Mode
	// System selects the system-wide Quadlet (with ModeQuadlet). ModeSystem
	// implies it.
	System bool
	// Root prefixes every system path; empty is the real root. For tests.
	Root string
	// Executable is the running scrim binary, copied into place for the
	// user and system units.
	Executable string
	// Image is the Quadlet image reference.
	Image string
	// AgentUsers are added to the agent group and mapped to agents in a
	// new system config file.
	AgentUsers []string

	// The user scope: home, the scrim state directory (holds the manifest),
	// the scrim config directory and $XDG_RUNTIME_DIR.
	Home, StateDir, ConfigDir, RuntimeDir string
	// Username is the user a user install is for.
	Username string
	// TrustDataDir is where the per-user trust writes its bundle files
	// ($XDG_DATA_HOME/scrim); install records it and its parents when it
	// creates them, so uninstall removes them again.
	TrustDataDir string
	// MemlockUnlimited says the user's hard memlock limit is unlimited, so
	// the user unit may raise it.
	MemlockUnlimited bool

	// Agents are the agents of an agent-side mode (ModeHooks,
	// ModeManaged).
	Agents []string
	// ClaudeConfigDir ($CLAUDE_CONFIG_DIR or ~/.claude) and CodexHome
	// ($CODEX_HOME or ~/.codex) hold the agents' user hooks files.
	ClaudeConfigDir, CodexHome string
	// HookExecutable is the scrim binary the hooks run.
	HookExecutable string
	// Managed are the endpoints managed settings pin.
	Managed ManagedOptions

	Runner Runner
	Probe  Probe
	// UserTrust installs the CA for a user install; TrustFor, when set,
	// picks it by mode instead (the mode of an uninstall comes from the
	// manifest).
	UserTrust UserTrust
	TrustFor  func(Mode) UserTrust
	// Chown sets ownership; nil is os.Chown.
	Chown func(path string, uid, gid int) error
	Out   io.Writer
	// DryRun shows every change without making it; Purge also removes the
	// state, volume and pulled image on uninstall.
	DryRun, Purge bool
	Now           func() time.Time
	// ReadyTimeout bounds the wait for the started service; zero is 90s.
	ReadyTimeout time.Duration

	mf    Manifest
	mpath string
	// wrote is set once a file was written, so a second install restarts
	// the service.
	wrote bool
}

// SystemScope reports whether the install is system-wide.
func (in *Installer) SystemScope() bool {
	return in.Mode == ModeSystem || in.Mode == ModeManaged || in.System
}

// AgentMode reports whether the mode changes agents' configuration rather
// than installing the service.
func (in *Installer) AgentMode() bool { return in.Mode == ModeHooks || in.Mode == ModeManaged }

func (in *Installer) path(p string) string {
	if in.Root == "" {
		return p
	}
	return filepath.Join(in.Root, p)
}

// ManifestPath is where the manifest of this scope lives.
func (in *Installer) ManifestPath() string {
	switch in.Mode {
	case ModeManaged:
		return in.path(ManagedManifest)
	case ModeHooks:
		return filepath.Join(in.StateDir, HooksManifestName)
	}
	if in.SystemScope() {
		return in.path(SystemManifest)
	}
	return filepath.Join(in.StateDir, ManifestName)
}

func (in *Installer) scope() string {
	if in.SystemScope() {
		return ScopeSystem
	}
	return ScopeUser
}

// uninstallFlag is the `scrim uninstall` flag that reverts this install.
func (in *Installer) uninstallFlag() string {
	if in.AgentMode() {
		return string(in.Mode)
	}
	return in.scope()
}

func (in *Installer) printf(format string, a ...any) { _, _ = fmt.Fprintf(in.Out, format, a...) }

func (in *Installer) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

func (in *Installer) verb() string {
	if in.DryRun {
		return "would "
	}
	return ""
}

func (in *Installer) systemctl(ctx context.Context, scope string, args ...string) error {
	if scope == ScopeUser {
		args = append([]string{"--user"}, args...)
	}
	return in.run(ctx, "systemctl", args...)
}

func (in *Installer) run(ctx context.Context, name string, args ...string) error {
	out, err := in.Runner.Run(ctx, name, args...)
	if err != nil {
		msg := strings.TrimSpace(string(bytes.ToValidUTF8(out, nil)))
		if len(msg) > 400 {
			msg = msg[:400] + "..."
		}
		if msg != "" {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func (in *Installer) chown(path string, uid, gid int) error {
	if in.Chown != nil {
		return in.Chown(path, uid, gid)
	}
	return os.Chown(path, uid, gid)
}

// record adds or replaces e in the manifest and writes it.
func (in *Installer) record(e Entry) error {
	if in.DryRun {
		return nil
	}
	e.At = in.now().UTC()
	if i := in.mf.find(e); i >= 0 {
		in.mf.Entries[i] = e
	} else {
		in.mf.Entries = append(in.mf.Entries, e)
	}
	if !exists(filepath.Dir(in.mpath)) {
		// The parents of the directory that will hold the manifest are
		// created first; their entries are written with the next record.
		return nil
	}
	return writeManifest(in.mpath, in.mf)
}

func (in *Installer) recorded(e Entry) bool { return in.mf.find(e) >= 0 }

// change shows desc, then (unless dry-run) makes it with fn and records e.
func (in *Installer) change(desc string, e Entry, fn func() error) error {
	in.printf("+ %s%s\n", in.verb(), desc)
	if in.DryRun {
		return nil
	}
	if err := fn(); err != nil {
		return err
	}
	return in.record(e)
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func fileSum(p string) (string, error) {
	b, err := os.ReadFile(p) // #nosec G304 -- a path install wrote
	if err != nil {
		return "", err
	}
	return sum(b), nil
}

// Install makes every change of the mode, in order, showing each first.
// It can be run again: recorded changes are kept, files whose content
// changed (a new binary, a new unit) are rewritten and the service is
// restarted. A failure stops it; `scrim uninstall` reverts what was made.
func (in *Installer) Install(ctx context.Context) error {
	if in.Mode == ModeQuadlet && in.Image == "" {
		return errors.New("install: no image for the Quadlet container")
	}
	for _, u := range in.AgentUsers {
		if !in.SystemScope() {
			return errors.New("install: --agent-user needs a system install (--system)")
		}
		if !identity.ValidAgentName(u) {
			return fmt.Errorf("install: agent user %q cannot name an agent (lower-case letters, digits, '.', '_', '-')", u)
		}
	}
	in.mpath = in.ManifestPath()
	mf, found, err := ReadManifest(in.mpath)
	if err != nil {
		return err
	}
	if found && (mf.Mode != in.Mode || mf.System != in.SystemScope()) {
		return fmt.Errorf("install: scrim is already installed here as %s (manifest %s); run scrim uninstall first", describeMode(mf.Mode, mf.System), in.mpath)
	}
	mf.Mode, mf.System, mf.Image = in.Mode, in.SystemScope(), in.Image
	in.mf = mf
	if in.DryRun {
		in.printf("scrim install (%s) would make these changes, in order:\n", describeMode(in.Mode, in.SystemScope()))
	} else {
		in.printf("scrim install (%s), every change in order (recorded in %s):\n", describeMode(in.Mode, in.SystemScope()), in.mpath)
	}
	if err := in.install(ctx, found); err != nil {
		if !in.DryRun {
			in.printf("\ninstall stopped: %v\nscrim uninstall --%s reverts the changes made so far.\n", err, in.uninstallFlag())
		}
		return err
	}
	in.summary()
	return nil
}

func describeMode(m Mode, system bool) string {
	switch {
	case m == ModeHooks:
		return "agent hooks"
	case m == ModeManaged:
		return "managed agent settings"
	case m == ModeQuadlet && system:
		return "system Quadlet container"
	case m == ModeQuadlet:
		return "rootless Quadlet container"
	case m == ModeSystem:
		return "system service"
	}
	return "user service"
}

func (in *Installer) install(ctx context.Context, again bool) error {
	switch in.Mode {
	case ModeHooks:
		return in.installHooks()
	case ModeManaged:
		return in.installManaged()
	}
	if in.SystemScope() {
		return in.installSystem(ctx, again)
	}
	return in.installUser(ctx, again)
}

func (in *Installer) installSystem(ctx context.Context, again bool) error {
	stateExisted := exists(in.path(SystemStateDir))
	if err := in.ensureDir(in.path(SystemConfigDir), 0o755); err != nil {
		return err
	}
	if err := in.ensureGroup(ctx, ServiceUser); err != nil {
		return err
	}
	if err := in.ensureGroup(ctx, AgentGroup); err != nil {
		return err
	}
	if err := in.ensureUser(ctx); err != nil {
		return err
	}
	var agents []Account
	for _, u := range in.AgentUsers {
		a, err := in.ensureMember(ctx, u, AgentGroup)
		if err != nil {
			return err
		}
		agents = append(agents, a)
	}
	// The config file is readable by the agent group: scrim run and the
	// agent tools of those users load it too. It holds references, never
	// secret values.
	agentGroup, _, err := in.group(AgentGroup)
	if err != nil {
		return err
	}
	if in.Mode == ModeSystem {
		if err := in.installBinary(in.path(SystemBinary)); err != nil {
			return err
		}
	}
	_, err = in.file(fileSpec{path: in.path(SystemConfigFile), content: []byte(SystemConfig(agents)), mode: 0o640,
		what: "the configuration file", keepForeign: true, owner: &[2]int{0, agentGroup.UID}})
	if err != nil {
		return err
	}
	if !stateExisted {
		if err := in.noteState(in.path(SystemStateDir), false); err != nil {
			return err
		}
	}
	if in.Mode == ModeSystem {
		_, err = in.unitFile(in.path(SystemUnitPath), []byte(SystemUnit(SystemBinary)), ScopeSystem)
	} else {
		var unit string
		unit, err = in.systemQuadlet()
		if err != nil {
			return err
		}
		if err := in.ensureDir(filepath.Dir(in.path(SystemQuadletPath)), 0o755); err != nil {
			return err
		}
		if err := in.noteImage(ctx); err != nil {
			return err
		}
		_, err = in.unitFile(in.path(SystemQuadletPath), []byte(unit), ScopeSystem)
	}
	if err != nil {
		return err
	}
	if err := in.startService(ctx, again && in.wrote); err != nil {
		return err
	}
	pem, err := in.waitReady(ctx, filepath.Join(in.path(SystemRuntimeDir), "admin.sock"))
	if err != nil {
		return err
	}
	return in.systemTrust(ctx, pem)
}

func (in *Installer) systemQuadlet() (string, error) {
	u, ok, err := in.user(ServiceUser)
	if err != nil {
		return "", err
	}
	g, gok, err := in.group(AgentGroup)
	if err != nil {
		return "", err
	}
	if !ok || !gok {
		if in.DryRun {
			return QuadletSystem(in.Image, -1, -1, -1), nil
		}
		return "", fmt.Errorf("install: user %s or group %s missing after creating them", ServiceUser, AgentGroup)
	}
	return QuadletSystem(in.Image, u.UID, u.GID, g.UID), nil
}

func (in *Installer) installUser(ctx context.Context, again bool) error {
	if in.Home == "" || in.StateDir == "" || in.RuntimeDir == "" {
		return errors.New("install: a user install needs $HOME, a state directory and $XDG_RUNTIME_DIR (log in with a systemd user session)")
	}
	if !exists(in.StateDir) {
		if err := in.noteState(in.StateDir, true); err != nil {
			return err
		}
	}
	if in.Mode == ModeUser {
		bin := filepath.Join(in.Home, ".local", "bin", "scrim")
		if err := in.installBinary(bin); err != nil {
			return err
		}
		unitPath := filepath.Join(in.Home, ".config", "systemd", "user", UnitName)
		if err := in.ensureDir(filepath.Dir(unitPath), 0o755); err != nil {
			return err
		}
		if _, err := in.unitFile(unitPath, []byte(UserUnit(bin, in.MemlockUnlimited)), ScopeUser); err != nil {
			return err
		}
	} else {
		if err := in.noteVolume(ctx); err != nil {
			return err
		}
		if err := in.noteImage(ctx); err != nil {
			return err
		}
		cfgDir := ""
		if exists(in.ConfigDir) {
			cfgDir = in.ConfigDir
		}
		unitPath := filepath.Join(in.Home, ".config", "containers", "systemd", "scrim.container")
		if err := in.ensureDir(filepath.Dir(unitPath), 0o755); err != nil {
			return err
		}
		if _, err := in.unitFile(unitPath, []byte(QuadletRootless(in.Image, cfgDir)), ScopeUser); err != nil {
			return err
		}
	}
	if err := in.startService(ctx, again && in.wrote); err != nil {
		return err
	}
	pem, err := in.waitReady(ctx, filepath.Join(in.RuntimeDir, "scrim", "admin.sock"))
	if err != nil {
		return err
	}
	return in.userTrust(ctx, pem)
}

// ensureDir creates p and its missing parents, each recorded.
func (in *Installer) ensureDir(p string, mode fs.FileMode) error {
	var missing []string
	for d := p; !exists(d); d = filepath.Dir(d) {
		missing = append(missing, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		d := missing[i]
		if err := in.change("create the directory "+d, Entry{Kind: KindDir, Target: d}, func() error {
			if err := os.Mkdir(d, mode); err != nil {
				return fmt.Errorf("install: %w", err)
			}
			return os.Chmod(d, mode) // #nosec G302 -- directories that hold public files
		}); err != nil {
			return err
		}
	}
	return nil
}

func (in *Installer) ensureGroup(ctx context.Context, name string) error {
	_, ok, err := in.group(name)
	if err != nil {
		return err
	}
	e := Entry{Kind: KindGroup, Target: name}
	if ok {
		if !in.recorded(e) {
			in.printf("  group %s exists; used as is (uninstall leaves it)\n", name)
		}
		return nil
	}
	return in.change(fmt.Sprintf("create the system group %s (groupadd --system %s)", name, name), e, func() error {
		return in.run(ctx, "groupadd", "--system", name)
	})
}

func (in *Installer) nologin() string {
	for _, p := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
		if exists(in.path(p)) {
			return p
		}
	}
	return "/bin/false"
}

func (in *Installer) ensureUser(ctx context.Context) error {
	_, ok, err := in.user(ServiceUser)
	if err != nil {
		return err
	}
	e := Entry{Kind: KindUser, Target: ServiceUser}
	if ok {
		if !in.recorded(e) {
			in.printf("  user %s exists; used as is (uninstall leaves it)\n", ServiceUser)
		}
		return nil
	}
	args := []string{"--system", "--gid", ServiceUser, "--no-create-home", "--home-dir", SystemStateDir,
		"--shell", in.nologin(), "--comment", "scrim daemon", ServiceUser}
	return in.change(fmt.Sprintf("create the system user %s, no login, home %s (useradd %s)", ServiceUser, SystemStateDir, strings.Join(args, " ")), e,
		func() error { return in.run(ctx, "useradd", args...) })
}

func (in *Installer) ensureMember(ctx context.Context, user, group string) (Account, error) {
	a, ok, err := in.user(user)
	if err != nil {
		return Account{}, err
	}
	if !ok {
		return Account{}, fmt.Errorf("install: agent user %s does not exist", user)
	}
	is, err := in.member(user, group)
	if err != nil {
		return Account{}, err
	}
	e := Entry{Kind: KindMember, Target: user, Group: group}
	if is {
		if !in.recorded(e) {
			in.printf("  %s is already in the group %s\n", user, group)
		}
		return a, nil
	}
	return a, in.change(fmt.Sprintf("add %s to the group %s, so its agents can use the sockets (usermod -a -G %s %s)", user, group, group, user), e,
		func() error { return in.run(ctx, "usermod", "-a", "-G", group, user) })
}

func (in *Installer) installBinary(target string) error {
	if in.Executable == "" {
		return errors.New("install: the running scrim binary is unknown")
	}
	src, err := filepath.EvalSymlinks(in.Executable)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if dst, err := filepath.EvalSymlinks(target); err == nil && dst == src {
		in.printf("  the service runs this binary, %s\n", target)
		return nil
	}
	b, err := os.ReadFile(src) // #nosec G304 -- the running executable
	if err != nil {
		return fmt.Errorf("install: reading the running binary: %w", err)
	}
	if err := in.ensureDir(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	_, err = in.file(fileSpec{path: target, content: b, mode: 0o755, what: "the scrim binary " + src})
	return err
}

type fileSpec struct {
	path    string
	content []byte
	mode    fs.FileMode
	what    string
	// keepForeign keeps a file install did not write, with a note, instead
	// of failing.
	keepForeign bool
	owner       *[2]int
	reload      string
}

// file writes a file and records its hash. It reports whether it wrote.
func (in *Installer) file(f fileSpec) (bool, error) {
	e := Entry{Kind: KindFile, Target: f.path, SHA256: sum(f.content), Reload: f.reload}
	i := in.mf.find(e)
	if exists(f.path) {
		cur, err := fileSum(f.path)
		if err != nil {
			return false, fmt.Errorf("install: %w", err)
		}
		switch {
		case i >= 0 && cur == e.SHA256:
			return false, nil
		case i >= 0 && cur != in.mf.Entries[i].SHA256:
			return false, fmt.Errorf("install: %s was changed since scrim installed it; move it away to install again", f.path)
		case i < 0 && f.keepForeign:
			in.printf("  %s exists and was not written by scrim; kept as is\n", f.path)
			return false, nil
		case i < 0:
			return false, fmt.Errorf("install: %s exists and was not written by scrim; remove it first", f.path)
		}
		in.printf("+ %sreplace %s with %s\n", in.verb(), f.path, f.what)
	} else {
		in.printf("+ %swrite %s (%s, mode %04o)\n", in.verb(), f.path, f.what, f.mode)
	}
	if in.DryRun {
		return true, nil
	}
	if err := writeAtomic(f.path, f.content, f.mode); err != nil {
		return false, err
	}
	in.wrote = true
	if f.owner != nil {
		if err := in.chown(f.path, f.owner[0], f.owner[1]); err != nil {
			return false, fmt.Errorf("install: %w", err)
		}
	}
	return true, in.record(e)
}

// unitFile writes a unit or Quadlet file and reloads the manager when it
// changed. It reports whether it changed.
func (in *Installer) unitFile(path string, content []byte, scope string) (bool, error) {
	changed, err := in.file(fileSpec{path: path, content: content, mode: 0o644, what: "the unit", reload: scope})
	if err != nil || !changed {
		return changed, err
	}
	in.printf("+ %sreload the systemd %s manager (systemctl daemon-reload)\n", in.verb(), scope)
	if in.DryRun {
		return true, nil
	}
	return true, in.systemctl(context.Background(), scope, "daemon-reload")
}

// noteState records a state directory that did not exist, so a purge
// removes it. A user state directory is created here because it holds the
// manifest; the system one is created by systemd (StateDirectory).
func (in *Installer) noteState(dir string, create bool) error {
	e := Entry{Kind: KindState, Target: dir}
	if in.recorded(e) {
		return nil
	}
	desc := "create the state directory " + dir + " (kept by uninstall unless --purge)"
	if !create {
		desc = "let systemd create the state directory " + dir + " at the first start (kept by uninstall unless --purge)"
	}
	if create {
		if err := in.ensureDir(filepath.Dir(dir), 0o755); err != nil {
			return err
		}
	}
	in.printf("+ %s%s\n", in.verb(), desc)
	if in.DryRun {
		return nil
	}
	if create {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fmt.Errorf("install: %w", err)
		}
	}
	// The manifest may live in dir: write the entry once dir exists.
	return in.record(e)
}

func (in *Installer) podman(ctx context.Context, args ...string) error {
	return in.run(ctx, "podman", args...)
}

func (in *Installer) noteVolume(ctx context.Context) error {
	e := Entry{Kind: KindVolume, Target: QuadletVolume, Scope: in.scope()}
	if in.recorded(e) || in.podman(ctx, "volume", "exists", QuadletVolume) == nil {
		return nil
	}
	return in.change("let podman create the volume "+QuadletVolume+" for the state at the first start (kept by uninstall unless --purge)", e, func() error { return nil })
}

func (in *Installer) noteImage(ctx context.Context) error {
	e := Entry{Kind: KindImage, Target: in.Image, Scope: in.scope()}
	if in.recorded(e) || in.podman(ctx, "image", "exists", in.Image) == nil {
		return nil
	}
	return in.change("let podman pull "+in.Image+" at the first start (kept by uninstall unless --purge)", e, func() error { return nil })
}

// startService enables and starts the unit (only starts a Quadlet unit,
// which its [Install] section enables), or restarts it when restart is set
// (the binary or unit changed on a second install).
func (in *Installer) startService(ctx context.Context, restart bool) error {
	scope := in.scope()
	e := Entry{Kind: KindService, Target: UnitName, Scope: scope}
	if in.recorded(e) {
		if !restart {
			return nil
		}
		in.printf("+ %srestart %s (systemctl restart)\n", in.verb(), UnitName)
		if in.DryRun {
			return nil
		}
		return in.systemctl(ctx, scope, "restart", UnitName)
	}
	if in.Mode == ModeQuadlet {
		return in.change("start "+UnitName+", generated by Quadlet from scrim.container (systemctl start)", e,
			func() error { return in.systemctl(ctx, scope, "start", UnitName) })
	}
	return in.change("enable and start "+UnitName+" (systemctl enable --now)", e,
		func() error { return in.systemctl(ctx, scope, "enable", "--now", UnitName) })
}

func (in *Installer) waitReady(ctx context.Context, adminSocket string) (string, error) {
	if in.DryRun {
		return "", nil
	}
	in.printf("  waiting for scrim to report ready on %s\n", adminSocket)
	t := in.ReadyTimeout
	if t == 0 {
		t = 90 * time.Second
	}
	wctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	if err := in.Probe.WaitReady(wctx, adminSocket); err != nil {
		journal := "journalctl -u scrim"
		if !in.SystemScope() {
			journal = "journalctl --user -u scrim"
		}
		return "", fmt.Errorf("the service did not become ready (see %s): %w", journal, err)
	}
	pem, err := in.Probe.CA(ctx, adminSocket)
	if err != nil {
		return "", fmt.Errorf("reading the CA from the service: %w", err)
	}
	return pem, nil
}

func (in *Installer) trustTool() (tool, anchor string, add []string, ok bool) {
	for _, t := range trustTools {
		if _, err := in.Runner.LookPath(t.tool); err == nil {
			return t.tool, in.path(t.anchor), t.add, true
		}
	}
	return "", "", nil, false
}

func removeArgs(tool string) []string {
	for _, t := range trustTools {
		if t.tool == tool {
			return t.remove
		}
	}
	return nil
}

// systemTrust adds the CA to the system trust store.
func (in *Installer) systemTrust(ctx context.Context, pem string) error {
	tool, anchor, add, ok := in.trustTool()
	if !ok {
		in.printf("  no system trust store tool found (update-ca-certificates, update-ca-trust); add the output of\n" +
			"  `scrim ca export` to the system trust store yourself\n")
		return nil
	}
	e := Entry{Kind: KindSystemTrust, Target: anchor, Tool: tool, SHA256: sum([]byte(pem))}
	if i := in.mf.find(e); i >= 0 && in.mf.Entries[i].SHA256 == e.SHA256 && exists(anchor) {
		return nil
	}
	if !in.recorded(e) && exists(anchor) {
		return fmt.Errorf("install: %s exists and was not written by scrim; remove it first", anchor)
	}
	cmd := strings.TrimSpace(tool + " " + strings.Join(add, " "))
	in.printf("+ %strust the scrim CA system-wide: write %s, then run %s\n", in.verb(), anchor, cmd)
	if in.DryRun {
		return nil
	}
	if err := in.ensureDir(filepath.Dir(anchor), 0o755); err != nil {
		return err
	}
	if err := writeAtomic(anchor, []byte(pem), 0o644); err != nil {
		return err
	}
	if err := in.record(e); err != nil {
		return err
	}
	return in.run(ctx, tool, add...)
}

func (in *Installer) userTrust(ctx context.Context, pem string) error {
	e := Entry{Kind: KindUserTrust, Target: "per-user trust stores"}
	if in.TrustDataDir != "" {
		if err := in.ensureDir(in.TrustDataDir, 0o755); err != nil {
			return err
		}
	}
	in.printf("+ %strust the scrim CA for this user (scrim ca install --user):\n", in.verb())
	if err := in.trust().Install(ctx, pem, in.DryRun); err != nil {
		if in.DryRun {
			return err
		}
		// Some stores may have been changed: record so uninstall reverts them.
		_ = in.record(e)
		return err
	}
	return in.record(e)
}

func (in *Installer) trust() UserTrust {
	if in.TrustFor != nil {
		return in.TrustFor(in.Mode)
	}
	return in.UserTrust
}

func (in *Installer) summary() {
	if in.DryRun {
		in.printf("\nNothing was changed (dry run).\n")
		return
	}
	switch in.Mode {
	case ModeHooks:
		in.printf("\nHooks installed for %s. This is partial protection: model traffic does not pass scrim, and nothing\n"+
			"restores placeholders. `scrim status` lists what is not covered. scrim must be running (scrim install --user,\n"+
			"or scrim proxy) for the hooks to redact; while it is not, tool results are withheld and prompts blocked.\n", strings.Join(in.Agents, " and "))
		if slices.Contains(in.Agents, AgentCodex) {
			in.printf("Codex runs a new user hook only after you trust it: open /hooks in Codex once.\n")
		}
		in.printf("Remove them with `scrim uninstall --hooks`.\n")
		return
	case ModeManaged:
		in.printf("\nManaged settings installed for %s: the agent can only use %s", strings.Join(in.Agents, " and "), in.Managed.AnthropicBaseURL)
		if slices.Contains(in.Agents, AgentCodex) {
			in.printf(" (Codex: %s)", in.Managed.OpenAIBaseURL)
		}
		in.printf(".\nThey take effect when the agent next starts; run /status in Claude Code to see the managed source.\n" +
			"Remove them with `scrim uninstall --managed-settings`.\n")
		return
	}
	in.printf("\nscrim runs as %s. Check it with `scrim status`; logs: ", UnitName)
	if in.SystemScope() {
		in.printf("journalctl -u scrim\n")
		in.printf("Agents of users in the %s group reach it through %s/api.sock; map each user in\n"+
			"identity.peers of %s. Remove everything with `scrim uninstall --system`.\n", AgentGroup, SystemRuntimeDir, SystemConfigFile)
		return
	}
	in.printf("journalctl --user -u scrim\n")
	if !exists(in.path(filepath.Join("/var/lib/systemd/linger", in.Username))) {
		in.printf("The service runs while you are logged in. To start it at boot without a login: loginctl enable-linger\n")
	}
	if in.Mode == ModeUser && !in.MemlockUnlimited {
		in.printf("Your memlock limit is finite, so the data plane cannot lock its memory and warns. Raise the hard\n" +
			"limit (limits.conf, or DefaultLimitMEMLOCK= of the user manager) or use --system.\n")
	}
	in.printf("Remove everything with `scrim uninstall --user`.\n")
}
