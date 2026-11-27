// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package run

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/heliopsy/scrim/internal/fsview"
)

// requireUserns skips unless unprivileged user and mount namespaces work
// here; SCRIM_TEST_REQUIRE_USERNS=1 (CI) fails instead.
func requireUserns(t *testing.T) {
	t.Helper()
	a := fsview.Probe(context.Background(), selfAgent(t))
	if a.Namespace {
		return
	}
	if os.Getenv("SCRIM_TEST_REQUIRE_USERNS") == "1" {
		t.Fatalf("user namespaces unavailable: %s", a.Reason)
	}
	t.Skipf("user namespaces unavailable: %s", a.Reason)
}

// TestFSViewNamespace is task 10a.7: inside the session, a tool reading
// ~/.aws/credentials gets the generated placeholder file, the hidden ssh key
// and doctl config cannot be read (cat fails), the rest of the home is
// unchanged, the agent cannot unmount the view and is still identified by
// its session, and nothing changes on disk.
func TestFSViewNamespace(t *testing.T) {
	requireUserns(t)
	home := plantHome(t, t.TempDir())
	r, stderr, err := runView(t, home, FSViewOptions{Mode: fsview.ModeAuto, PasswdHome: home.dir})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	checkNamespaceView(t, r, home)
	t.Logf("in a namespace of the agent's own: %s", r.Nested)
	if r.RealAWS != r.HomeAWS {
		t.Errorf("the real path shows %q, not the view", r.RealAWS)
	}
	if strings.Contains(stderr, "filesystem view") {
		t.Errorf("namespace view warned: %q", stderr)
	}
	if b, _ := os.ReadFile(filepath.Join(home.dir, ".aws/credentials")); !strings.Contains(string(b), home.decoy) {
		t.Error("the real file changed")
	}
}

func checkNamespaceView(t *testing.T, r viewReport, home viewHome) {
	t.Helper()
	noDecoy(t, r, home.decoy)
	if !strings.Contains(r.HomeAWS, viewPlaceholder) {
		t.Errorf("~/.aws/credentials in the session = %q, want the placeholder", r.HomeAWS)
	}
	if !strings.HasPrefix(r.SSHKey, "ERR:") || !strings.HasPrefix(r.CatSSHKey, "FAIL:") {
		t.Errorf("hidden key readable: read %q, cat %q", r.SSHKey, r.CatSSHKey)
	}
	if !strings.HasPrefix(r.Doctl, "ERR:") {
		t.Errorf("hidden doctl config readable: %q", r.Doctl)
	}
	if r.SSHPub != home.pub || r.Notes != home.notes {
		t.Errorf("the rest of the home changed: pub %q, notes %q", r.SSHPub, r.Notes)
	}
	if !strings.HasPrefix(r.Unmount, "ERR:") {
		t.Errorf("the agent could unmount the view: %q", r.Unmount)
	}
	if r.UID != os.Getuid() {
		t.Errorf("agent uid %d, want %d", r.UID, os.Getuid())
	}
	if r.Agent != "dev" {
		t.Errorf("agent not identified by its session through the namespace: %q", r.Agent)
	}
}

// envOuterHome runs TestFSViewPasswdHome's body inside a namespace whose
// password-database home is a temporary directory.
const envOuterHome = "SCRIM_RUN_TEST_OUTER_HOME"

// TestFSViewPasswdHome is the 10a.7 check: a tool that finds the home
// directory through the password database, not HOME, reads the placeholder.
// The test starts itself again in a user and mount namespace with a
// temporary directory mounted over the password-database home, so the real
// home is never read, and runs the session there.
func TestFSViewPasswdHome(t *testing.T) {
	requireUserns(t)
	if dir := os.Getenv(envOuterHome); dir != "" {
		passwdHomeInner(t, dir)
		return
	}
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skipf("no password-database home: %v", err)
	}
	dir := t.TempDir()
	var out bytes.Buffer
	cmd := exec.Command(selfAgent(t), "-test.run=^TestFSViewPasswdHome$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), envOuterHome+"="+dir)
	cmd.Stdout, cmd.Stderr = &out, &out
	uid, gid := os.Getuid(), os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN},
	}
	err = cmd.Run()
	t.Logf("inner run:\n%s", out.String())
	if err != nil || !strings.Contains(out.String(), "--- PASS: TestFSViewPasswdHome") {
		t.Fatalf("inner run failed: %v", err)
	}
}

func passwdHomeInner(t *testing.T, dir string) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	// Private first, so nothing below reaches the host's mount table.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(dir, u.HomeDir, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	home := plantHome(t, u.HomeDir)
	// HOME points elsewhere: only the password database leads to the
	// planted file.
	other := t.TempDir()
	r, stderr, err := runView(t, viewHome{dir: other, decoy: home.decoy}, FSViewOptions{Mode: fsview.ModeNamespace},
		envViewPasswd+"=1")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	noDecoy(t, r, home.decoy)
	if !strings.Contains(r.PasswdAWS, viewPlaceholder) {
		t.Errorf("~/.aws/credentials through the password database = %q, want the placeholder", r.PasswdAWS)
	}
	if out, err := exec.Command("cat", filepath.Join(u.HomeDir, ".aws/credentials")).Output(); err != nil || !strings.Contains(string(out), home.decoy) {
		t.Errorf("outside the session the planted file should be intact: %q %v", out, err)
	}
}

// TestFSViewOwnFiles: scrim's own files the daemon reports (its config
// file, a Vaultwarden unlock file behind a file: reference, a signing key
// outside the home) cannot be read from a session in the namespace view,
// while the session still reaches the agent API and the rest of the home;
// scrim commands in the session read the empty SCRIM_CONFIG instead.
func TestFSViewOwnFiles(t *testing.T) {
	requireUserns(t)
	home := plantHome(t, t.TempDir())
	h := newHarness(t, true)
	cfg, unlock, outside, env := ownView(t, h, home)
	r, stderr, err := runViewWith(t, h, home, FSViewOptions{Mode: fsview.ModeNamespace, PasswdHome: home.dir}, env)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	checkNamespaceView(t, r, home)
	for _, p := range []string{cfg, unlock, outside} {
		if got, ok := r.Own[p]; !ok || !strings.HasPrefix(got, "ERR:") {
			t.Errorf("%s readable in the session: %q", p, got)
		}
	}
	if r.ScrimConfig == "" || strings.HasPrefix(r.ScrimConfigData, "ERR:") || !strings.Contains(r.ScrimConfigData, "kind: Config") {
		t.Errorf("SCRIM_CONFIG = %q (%q), want the session's empty config", r.ScrimConfig, r.ScrimConfigData)
	}
	for _, p := range []string{cfg, unlock, outside} {
		if b, _ := os.ReadFile(p); !strings.Contains(string(b), home.decoy) {
			t.Errorf("%s changed on disk", p)
		}
	}
}

// TestFSViewHelperMustRun: a helper executable that does not set the view
// up (here /bin/true) refuses the start; the agent never runs unviewed.
func TestFSViewHelperMustRun(t *testing.T) {
	requireUserns(t)
	tr, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true(1)")
	}
	home := plantHome(t, t.TempDir())
	_, stderr, err := runView(t, home, FSViewOptions{Mode: fsview.ModeNamespace, PasswdHome: home.dir, Helper: tr,
		Probe: func(context.Context, string) fsview.Availability { return fsview.Availability{Namespace: true} }})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "did not run") {
		t.Fatalf("want a refusal, got %v\n%s", err, stderr)
	}
}
