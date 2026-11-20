// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeHost is a fake root filesystem with account files, and a runner that
// edits them as groupadd, useradd and friends would. systemctl "starts" a
// service by creating its state directory and sockets the way systemd and
// scrim would.
type fakeHost struct {
	t     *testing.T
	root  string
	calls []string
	tools map[string]bool
	// volumes and images podman "has".
	volumes, images map[string]bool
	// started simulates what the running service creates.
	started func()
	fail    map[string]error
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{t: t, root: t.TempDir(), tools: map[string]bool{"update-ca-certificates": true},
		volumes: map[string]bool{}, images: map[string]bool{}, fail: map[string]error{}}
	for _, d := range []string{"etc/systemd/system", "usr/local/bin", "usr/sbin", "usr/local/share/ca-certificates", "var/lib", "run"} {
		if err := os.MkdirAll(filepath.Join(h.root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
	h.write("etc/group", "root:x:0:\nalice:x:1000:\n")
	h.write("usr/sbin/nologin", "")
	return h
}

func (h *fakeHost) write(rel, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.root, rel), []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) read(rel string) string {
	b, _ := os.ReadFile(filepath.Join(h.root, rel))
	return string(b)
}

func (h *fakeHost) LookPath(name string) (string, error) {
	if h.tools[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (h *fakeHost) edit(rel string, fn func([]string) []string) {
	lines := strings.Split(strings.TrimSuffix(h.read(rel), "\n"), "\n")
	h.write(rel, strings.Join(fn(lines), "\n")+"\n")
}

func (h *fakeHost) nextID(rel string) int {
	n := 900
	for _, l := range strings.Split(h.read(rel), "\n") {
		if f := strings.Split(l, ":"); len(f) > 3 && strings.HasPrefix(l, "scrim") {
			n++
		}
	}
	return n
}

func (h *fakeHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	h.calls = append(h.calls, call)
	for prefix, err := range h.fail {
		if strings.HasPrefix(call, prefix) {
			return []byte("simulated failure"), err
		}
	}
	if len(args) == 0 {
		return nil, nil
	}
	last := args[len(args)-1]
	switch name {
	case "groupadd":
		h.edit("etc/group", func(l []string) []string { return append(l, fmt.Sprintf("%s:x:%d:", last, h.nextID("etc/group"))) })
	case "groupdel":
		h.edit("etc/group", func(l []string) []string {
			return slices.DeleteFunc(l, func(s string) bool { return strings.HasPrefix(s, last+":") })
		})
	case "useradd":
		gid := ""
		for _, g := range strings.Split(h.read("etc/group"), "\n") {
			if strings.HasPrefix(g, "scrim:") {
				gid = strings.Split(g, ":")[2]
			}
		}
		h.edit("etc/passwd", func(l []string) []string {
			return append(l, fmt.Sprintf("%s:x:%d:%s::/var/lib/scrim:/usr/sbin/nologin", last, h.nextID("etc/passwd"), gid))
		})
	case "userdel":
		h.edit("etc/passwd", func(l []string) []string {
			return slices.DeleteFunc(l, func(s string) bool { return strings.HasPrefix(s, last+":") })
		})
	case "usermod": // usermod -a -G group user
		group := args[2]
		h.edit("etc/group", func(l []string) []string {
			for i, s := range l {
				if strings.HasPrefix(s, group+":") {
					if strings.HasSuffix(s, ":") {
						l[i] = s + last
					} else {
						l[i] = s + "," + last
					}
				}
			}
			return l
		})
	case "gpasswd": // gpasswd -d user group
		user, group := args[1], args[2]
		h.edit("etc/group", func(l []string) []string {
			for i, s := range l {
				if strings.HasPrefix(s, group+":") {
					f := strings.Split(s, ":")
					f[3] = strings.Join(slices.DeleteFunc(strings.Split(f[3], ","), func(m string) bool { return m == user }), ",")
					l[i] = strings.Join(f, ":")
				}
			}
			return l
		})
	case "systemctl":
		if slices.Contains(args, "--now") || slices.Contains(args, "start") {
			if slices.Contains(args, "disable") {
				return nil, nil
			}
			if h.started != nil {
				h.started()
			}
		}
		if slices.Contains(args, "show") {
			return []byte("loaded\n"), nil
		}
	case "podman":
		switch {
		case len(args) >= 3 && args[0] == "volume" && args[1] == "exists":
			if !h.volumes[last] {
				return nil, errors.New("exit status 1")
			}
		case len(args) >= 3 && args[0] == "image" && args[1] == "exists":
			if !h.images[last] {
				return nil, errors.New("exit status 1")
			}
		case args[0] == "volume" && args[1] == "rm":
			delete(h.volumes, last)
		case args[0] == "rmi":
			delete(h.images, last)
		}
	}
	return nil, nil
}

type fakeProbe struct{ ready error }

func (p fakeProbe) WaitReady(context.Context, string) error { return p.ready }
func (p fakeProbe) CA(context.Context, string) (string, error) {
	return "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n", nil
}

// fakeTrust writes a bundle file into dir, as `scrim ca install --user`
// would, and removes it again.
type fakeTrust struct {
	dir                  string
	installed, uninstall int
}

func (f *fakeTrust) Install(_ context.Context, pem string, dry bool) error {
	f.installed++
	if dry {
		return nil
	}
	return os.WriteFile(filepath.Join(f.dir, "scrim-ca.pem"), []byte(pem), 0o644)
}

func (f *fakeTrust) Uninstall(_ context.Context, _ bool) error {
	f.uninstall++
	return os.Remove(filepath.Join(f.dir, "scrim-ca.pem"))
}

// snapshot lists every path under root with its mode and content hash.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		v := fi.Mode().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s := sha256.Sum256(b)
			v += " " + hex.EncodeToString(s[:])
		}
		rel, _ := filepath.Rel(root, p)
		out[rel] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func diff(before, after map[string]string) []string {
	var d []string
	for k, v := range after {
		if b, ok := before[k]; !ok {
			d = append(d, "added "+k)
		} else if b != v {
			d = append(d, "changed "+k)
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			d = append(d, "removed "+k)
		}
	}
	slices.Sort(d)
	return d
}

func fakeBinary(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scrim")
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func (h *fakeHost) system(t *testing.T, mode Mode, out *bytes.Buffer) *Installer {
	t.Helper()
	return &Installer{Mode: mode, System: true, Root: h.root, Executable: fakeBinary(t, "scrim binary v1"),
		Image: "ghcr.io/heliopsy/scrim:0.1.0", Runner: h, Probe: fakeProbe{}, Out: out,
		Chown: func(string, int, int) error { return nil }}
}

func TestSystemInstallAndUninstallLeaveNoTrace(t *testing.T) {
	h := newFakeHost(t)
	h.started = func() {
		// What systemd and the daemon create.
		_ = os.MkdirAll(filepath.Join(h.root, "var/lib/scrim/ca"), 0o700)
		_ = os.WriteFile(filepath.Join(h.root, "var/lib/scrim/state.db"), []byte("db"), 0o600)
	}
	before := snapshot(t, h.root)
	var out bytes.Buffer
	in := h.system(t, ModeSystem, &out)
	in.AgentUsers = []string{"alice"}
	if err := in.Install(context.Background()); err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	unit := h.read("etc/systemd/system/scrim.service")
	for _, want := range []string{
		"User=scrim", "SupplementaryGroups=scrim-agents", "ExecStart=/usr/local/bin/scrim proxy",
		"ProtectSystem=strict", "NoNewPrivileges=yes", "PrivateTmp=yes", "CapabilityBoundingSet=\n",
		"MemoryDenyWriteExecute=yes", "LockPersonality=yes", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"SystemCallFilter=@system-service", "LimitMEMLOCK=infinity", "LimitCORE=0", "StateDirectory=scrim",
		"RuntimeDirectory=scrim", "Environment=SCRIM_API_GROUP=scrim-agents", "Environment=SCRIM_API_PERMISSIONS=0660",
		"Environment=SCRIM_ADMIN_URL=unix:/run/scrim/admin.sock",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	if got := h.read("usr/local/bin/scrim"); got != "scrim binary v1" {
		t.Errorf("binary = %q", got)
	}
	if cfg := h.read("etc/scrim/config.yaml"); !strings.Contains(cfg, `alice: "uid:1000"`) {
		t.Errorf("config does not map alice:\n%s", cfg)
	}
	if !strings.Contains(h.read("etc/group"), "scrim-agents:x:") || !strings.Contains(h.read("etc/group"), ":alice") {
		t.Errorf("groups: %s", h.read("etc/group"))
	}
	if ca := h.read("usr/local/share/ca-certificates/scrim-ca.crt"); !strings.Contains(ca, "BEGIN CERTIFICATE") {
		t.Errorf("trust anchor = %q", ca)
	}
	wantCalls := []string{"groupadd --system scrim", "groupadd --system scrim-agents", "useradd --system --gid scrim",
		"usermod -a -G scrim-agents alice", "systemctl daemon-reload", "systemctl enable --now scrim.service", "update-ca-certificates"}
	checkOrder(t, h.calls, wantCalls)
	// Every change was shown first.
	for _, w := range []string{"+ create the system user scrim", "+ write " + filepath.Join(h.root, SystemUnitPath),
		"+ trust the scrim CA system-wide"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("output lacks %q:\n%s", w, out.String())
		}
	}

	h.calls = nil
	out.Reset()
	un := h.system(t, "", &out)
	un.Purge = true
	if err := un.Uninstall(context.Background()); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out.String())
	}
	checkOrder(t, h.calls, []string{"update-ca-certificates --fresh", "systemctl disable --now scrim.service",
		"systemctl daemon-reload", "gpasswd -d alice scrim-agents", "userdel scrim", "groupdel scrim-agents", "groupdel scrim"})
	if d := diff(before, snapshot(t, h.root)); len(d) > 0 {
		t.Errorf("uninstall left traces: %v\n%s", d, out.String())
	}
}

func checkOrder(t *testing.T, calls, want []string) {
	t.Helper()
	i := 0
	for _, c := range calls {
		if i < len(want) && strings.HasPrefix(c, want[i]) {
			i++
		}
	}
	if i < len(want) {
		t.Errorf("calls %q\nwant in order %q (missing %q)", calls, want, want[i])
	}
}

func TestUninstallKeepsStateUnlessPurged(t *testing.T) {
	h := newFakeHost(t)
	h.started = func() { _ = os.MkdirAll(filepath.Join(h.root, "var/lib/scrim"), 0o700) }
	before := snapshot(t, h.root)
	var out bytes.Buffer
	if err := h.system(t, ModeSystem, &out).Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := h.system(t, "", &out).Uninstall(context.Background()); err != nil {
		t.Fatalf("uninstall without purge: %v\n%s", err, out.String())
	}
	if !exists(filepath.Join(h.root, SystemStateDir)) {
		t.Fatal("state removed without --purge")
	}
	if !strings.Contains(out.String(), "kept "+filepath.Join(h.root, SystemStateDir)) {
		t.Errorf("kept state not reported:\n%s", out.String())
	}
	mf, found, err := ReadManifest(filepath.Join(h.root, SystemManifest))
	if err != nil || !found {
		t.Fatalf("manifest gone though state was kept: %v", err)
	}
	if len(mf.Entries) != 2 {
		t.Errorf("manifest entries = %+v, want the state and its directory", mf.Entries)
	}
	out.Reset()
	un := h.system(t, "", &out)
	un.Purge = true
	if err := un.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := diff(before, snapshot(t, h.root)); len(d) > 0 {
		t.Errorf("purge left traces: %v", d)
	}
}

func TestUninstallReportsWhatItCannotRevert(t *testing.T) {
	h := newFakeHost(t)
	var out bytes.Buffer
	if err := h.system(t, ModeSystem, &out).Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.write("etc/scrim/config.yaml", "# edited by the operator\n")
	h.fail["groupdel scrim-agents"] = errors.New("exit status 8")
	out.Reset()
	err := h.system(t, "", &out).Uninstall(context.Background())
	if !errors.Is(err, ErrNotReverted) {
		t.Fatalf("err = %v, want ErrNotReverted", err)
	}
	o := out.String()
	for _, w := range []string{"not reverted: " + filepath.Join(h.root, SystemConfigFile), "manual step: rm " + filepath.Join(h.root, SystemConfigFile),
		"not reverted: scrim-agents", "manual step: groupdel scrim-agents"} {
		if !strings.Contains(o, w) {
			t.Errorf("output lacks %q:\n%s", w, o)
		}
	}
	if h.read("etc/scrim/config.yaml") != "# edited by the operator\n" {
		t.Error("an edited config file was removed")
	}
	mf, _, _ := ReadManifest(filepath.Join(h.root, SystemManifest))
	var targets []string
	for _, e := range mf.Entries {
		targets = append(targets, e.Target)
	}
	if !slices.Contains(targets, "scrim-agents") || !slices.Contains(targets, filepath.Join(h.root, SystemConfigFile)) {
		t.Errorf("not-reverted changes missing from the manifest: %v", targets)
	}
	if slices.Contains(targets, "scrim") {
		t.Errorf("reverted user still listed: %v", targets)
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	h := newFakeHost(t)
	before := snapshot(t, h.root)
	var out bytes.Buffer
	in := h.system(t, ModeSystem, &out)
	in.DryRun = true
	in.AgentUsers = []string{"alice"}
	if err := in.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := diff(before, snapshot(t, h.root)); len(d) > 0 {
		t.Errorf("dry run changed %v", d)
	}
	if len(h.calls) > 0 {
		t.Errorf("dry run ran %q", h.calls)
	}
	for _, w := range []string{"would create the system group scrim", "would create the system user scrim", "would add alice to the group scrim-agents",
		"would write " + filepath.Join(h.root, SystemUnitPath), "would enable and start scrim.service", "would trust the scrim CA system-wide",
		"Nothing was changed"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("dry run output lacks %q:\n%s", w, out.String())
		}
	}
}

func TestSecondInstallUpgradesAndRestarts(t *testing.T) {
	h := newFakeHost(t)
	var out bytes.Buffer
	if err := h.system(t, ModeSystem, &out).Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.calls = nil
	in := h.system(t, ModeSystem, &out)
	in.Executable = fakeBinary(t, "scrim binary v2")
	if err := in.Install(context.Background()); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, out.String())
	}
	if got := h.read("usr/local/bin/scrim"); got != "scrim binary v2" {
		t.Errorf("binary after upgrade = %q", got)
	}
	checkOrder(t, h.calls, []string{"systemctl restart scrim.service"})
	if slices.ContainsFunc(h.calls, func(c string) bool { return strings.HasPrefix(c, "useradd") || strings.HasPrefix(c, "groupadd") }) {
		t.Errorf("upgrade recreated accounts: %q", h.calls)
	}
	// The manifest still lists the binary once, with the new hash.
	mf, _, _ := ReadManifest(filepath.Join(h.root, SystemManifest))
	n := 0
	for _, e := range mf.Entries {
		if e.Target == filepath.Join(h.root, SystemBinary) {
			n++
			if e.SHA256 != sum([]byte("scrim binary v2")) {
				t.Error("binary hash not updated")
			}
		}
	}
	if n != 1 {
		t.Errorf("binary listed %d times", n)
	}
}

func TestInstallRefusesForeignFiles(t *testing.T) {
	h := newFakeHost(t)
	h.write("etc/systemd/system/scrim.service", "[Unit]\nDescription=someone else's\n")
	var out bytes.Buffer
	err := h.system(t, ModeSystem, &out).Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "was not written by scrim") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out.String(), "scrim uninstall --system reverts") {
		t.Errorf("no hint to revert the partial install:\n%s", out.String())
	}
	if h.read("etc/systemd/system/scrim.service") != "[Unit]\nDescription=someone else's\n" {
		t.Error("foreign unit overwritten")
	}
	// A partial install is fully reverted.
	out.Reset()
	if err := h.system(t, "", &out).Uninstall(context.Background()); err != nil {
		t.Fatalf("revert partial install: %v\n%s", err, out.String())
	}
	if strings.Contains(h.read("etc/passwd"), "scrim:") {
		t.Error("partial install's user left behind")
	}
}

func TestInstallFailsWhenServiceNotReady(t *testing.T) {
	h := newFakeHost(t)
	var out bytes.Buffer
	in := h.system(t, ModeSystem, &out)
	in.Probe = fakeProbe{ready: errors.New("data plane not ready")}
	err := in.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "journalctl -u scrim") {
		t.Fatalf("err = %v", err)
	}
}

func TestNoTrustToolIsReported(t *testing.T) {
	h := newFakeHost(t)
	h.tools = map[string]bool{}
	var out bytes.Buffer
	if err := h.system(t, ModeSystem, &out).Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no system trust store tool found") {
		t.Errorf("missing tool not reported:\n%s", out.String())
	}
}

func TestFedoraTrustStore(t *testing.T) {
	h := newFakeHost(t)
	h.tools = map[string]bool{"update-ca-trust": true}
	var out bytes.Buffer
	if err := h.system(t, ModeSystem, &out).Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.read("etc/pki/ca-trust/source/anchors/scrim-ca.pem"), "BEGIN CERTIFICATE") {
		t.Error("anchor not written")
	}
	checkOrder(t, h.calls, []string{"update-ca-trust extract"})
	before := len(h.calls)
	un := h.system(t, "", &out)
	un.Purge = true
	if err := un.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkOrder(t, h.calls[before:], []string{"update-ca-trust extract"})
	if exists(filepath.Join(h.root, "etc/pki")) {
		t.Error("anchor directories created by install were left behind")
	}
}

type userFixture struct {
	h                  *fakeHost
	home, state, rdir  string
	trust              *fakeTrust
	dataDir, configDir string
}

func newUserFixture(t *testing.T) *userFixture {
	t.Helper()
	h := newFakeHost(t)
	f := &userFixture{h: h, home: t.TempDir(), rdir: t.TempDir()}
	f.state = filepath.Join(f.home, ".local", "state", "scrim")
	f.dataDir = filepath.Join(f.home, ".local", "share", "scrim")
	f.configDir = filepath.Join(f.home, ".config", "scrim")
	f.trust = &fakeTrust{dir: f.dataDir}
	return f
}

func (f *userFixture) installer(t *testing.T, mode Mode, out *bytes.Buffer) *Installer {
	t.Helper()
	return &Installer{Mode: mode, Root: f.h.root, Executable: fakeBinary(t, "user binary"), Image: "ghcr.io/heliopsy/scrim:0.1.0",
		Home: f.home, StateDir: f.state, ConfigDir: f.configDir, RuntimeDir: f.rdir, Username: "alice", TrustDataDir: f.dataDir,
		Runner: f.h, Probe: fakeProbe{}, UserTrust: f.trust, Out: out}
}

func TestUserInstallAndUninstall(t *testing.T) {
	f := newUserFixture(t)
	f.h.started = func() { _ = os.WriteFile(filepath.Join(f.state, "state.db"), []byte("db"), 0o600) }
	before := snapshot(t, f.home)
	var out bytes.Buffer
	if err := f.installer(t, ModeUser, &out).Install(context.Background()); err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	unit, err := os.ReadFile(filepath.Join(f.home, ".config/systemd/user/scrim.service"))
	if err != nil {
		t.Fatal(err)
	}
	u := string(unit)
	if !strings.Contains(u, "ExecStart="+filepath.Join(f.home, ".local/bin/scrim")+" proxy") || !strings.Contains(u, "WantedBy=default.target") {
		t.Errorf("unit:\n%s", u)
	}
	if strings.Contains(u, "LimitMEMLOCK") {
		t.Error("user unit raises memlock although the hard limit is finite")
	}
	if !strings.Contains(out.String(), "loginctl enable-linger") || !strings.Contains(out.String(), "memlock limit is finite") {
		t.Errorf("notes missing:\n%s", out.String())
	}
	checkOrder(t, f.h.calls, []string{"systemctl --user daemon-reload", "systemctl --user enable --now scrim.service"})
	if f.trust.installed != 1 {
		t.Errorf("user trust installed %d times", f.trust.installed)
	}
	if slices.ContainsFunc(f.h.calls, func(c string) bool {
		return strings.HasPrefix(c, "useradd") || strings.HasPrefix(c, "systemctl enable")
	}) {
		t.Errorf("user install touched the system: %q", f.h.calls)
	}

	out.Reset()
	un := f.installer(t, ModeUser, &out)
	un.Purge = true
	if err := un.Uninstall(context.Background()); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out.String())
	}
	if f.trust.uninstall != 1 {
		t.Errorf("user trust uninstalled %d times", f.trust.uninstall)
	}
	checkOrder(t, f.h.calls, []string{"systemctl --user disable --now scrim.service", "systemctl --user daemon-reload"})
	if d := diff(before, snapshot(t, f.home)); len(d) > 0 {
		t.Errorf("uninstall left traces in the home directory: %v\n%s", d, out.String())
	}
}

func TestUserUnitRaisesMemlockWhenAllowed(t *testing.T) {
	if !strings.Contains(UserUnit("/bin/scrim", true), "LimitMEMLOCK=infinity") {
		t.Error("memlock not raised")
	}
}

func TestQuadletRootless(t *testing.T) {
	f := newUserFixture(t)
	if err := os.MkdirAll(f.configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.h.started = func() { f.h.volumes[QuadletVolume] = true; f.h.images["ghcr.io/heliopsy/scrim:0.1.0"] = true }
	before := snapshot(t, f.home)
	var out bytes.Buffer
	if err := f.installer(t, ModeQuadlet, &out).Install(context.Background()); err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	b, err := os.ReadFile(filepath.Join(f.home, ".config/containers/systemd/scrim.container"))
	if err != nil {
		t.Fatal(err)
	}
	q := string(b)
	for _, w := range []string{"Image=ghcr.io/heliopsy/scrim:0.1.0", "UserNS=keep-id:uid=65532,gid=65532", "Volume=%t/scrim:%t/scrim",
		"Environment=XDG_RUNTIME_DIR=%t", "ReadOnly=true", "DropCapability=all", "Network=host", "Volume=" + f.configDir + ":/etc/scrim:ro"} {
		if !strings.Contains(q, w) {
			t.Errorf("quadlet lacks %q:\n%s", w, q)
		}
	}
	checkOrder(t, f.h.calls, []string{"systemctl --user daemon-reload", "systemctl --user start scrim.service"})
	if exists(filepath.Join(f.home, ".local/bin/scrim")) {
		t.Error("Quadlet install copied the binary")
	}

	out.Reset()
	un := f.installer(t, ModeUser, &out) // the manifest says it is Quadlet
	if err := un.Uninstall(context.Background()); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out.String())
	}
	if !f.h.volumes[QuadletVolume] || !strings.Contains(out.String(), "keep the podman volume") {
		t.Errorf("volume removed without --purge:\n%s", out.String())
	}
	checkOrder(t, f.h.calls, []string{"systemctl --user stop scrim.service"})
	un = f.installer(t, ModeUser, &out)
	un.Purge = true
	if err := un.Uninstall(context.Background()); err != nil {
		t.Fatalf("purge: %v\n%s", err, out.String())
	}
	if f.h.volumes[QuadletVolume] || f.h.images["ghcr.io/heliopsy/scrim:0.1.0"] {
		t.Errorf("purge kept the volume or image: %v %v", f.h.volumes, f.h.images)
	}
	if d := diff(before, snapshot(t, f.home)); len(d) > 0 {
		t.Errorf("uninstall left traces: %v", d)
	}
}

func TestQuadletSystemRunsAsServiceUser(t *testing.T) {
	h := newFakeHost(t)
	var out bytes.Buffer
	in := h.system(t, ModeQuadlet, &out)
	if err := in.Install(context.Background()); err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	q := h.read("etc/containers/systemd/scrim.container")
	for _, w := range []string{"User=900", "Group=900", "--group-add=901", "Volume=/run/scrim:/run/scrim", "Environment=SCRIM_API_GROUP=scrim-agents",
		"Ulimit=memlock=-1:-1", "ExecStartPre=/usr/bin/chown 900:900 /var/lib/scrim /run/scrim"} {
		if !strings.Contains(q, w) {
			t.Errorf("quadlet lacks %q:\n%s", w, q)
		}
	}
	if exists(filepath.Join(h.root, SystemBinary)) {
		t.Error("system Quadlet installed the binary")
	}
	checkOrder(t, h.calls, []string{"systemctl start scrim.service", "update-ca-certificates"})
}

func TestInstallOtherModeRefused(t *testing.T) {
	h := newFakeHost(t)
	var out bytes.Buffer
	if err := h.system(t, ModeSystem, &out).Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := h.system(t, ModeQuadlet, &out).Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already installed here as system service") {
		t.Fatalf("err = %v", err)
	}
}

func TestAgentUserValidation(t *testing.T) {
	h := newFakeHost(t)
	var out bytes.Buffer
	in := h.system(t, ModeSystem, &out)
	in.AgentUsers = []string{"Bad Name"}
	if err := in.Install(context.Background()); err == nil {
		t.Error("invalid agent name accepted")
	}
	in = h.system(t, ModeSystem, &out)
	in.AgentUsers = []string{"nobody-here"}
	if err := in.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing agent user: %v", err)
	}
}

func TestNothingToUninstall(t *testing.T) {
	h := newFakeHost(t)
	var out bytes.Buffer
	if err := h.system(t, "", &out).Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nothing to uninstall") {
		t.Errorf("output: %s", out.String())
	}
}
