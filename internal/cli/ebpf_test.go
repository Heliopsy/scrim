// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/heliopsy/scrim/internal/bpfredirect"
	"github.com/heliopsy/scrim/internal/install"
	"github.com/heliopsy/scrim/internal/status"
)

type fakeLoader struct {
	attached []string
	detached []string
	port     int
	err      error
}

func (f *fakeLoader) Attach(cg string, port int) (bpfredirect.Attachment, error) {
	if f.err != nil {
		return bpfredirect.Attachment{}, f.err
	}
	f.attached, f.port = append(f.attached, cg), port
	return bpfredirect.Attachment{Cgroup: cg, CgroupID: 42, Port: port, PinDir: "/sys/fs/bpf/scrim/cg-42-1"}, nil
}

func (f *fakeLoader) Detach(cg string) error {
	f.detached = append(f.detached, cg)
	return f.err
}

func withEBPF(t *testing.T, l *fakeLoader) {
	t.Helper()
	oldL, oldI := ebpfLoader, ebpfInspector
	ebpfLoader = l
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ebpfInspector = bpfredirect.Inspector{
		CgroupRoot: root, RecordPath: filepath.Join(t.TempDir(), "attachments.json"),
		Caps: func() bpfredirect.Caps { return 0 }, Dial: func(string) error { return errors.New("refused") },
	}
	t.Cleanup(func() { ebpfLoader, ebpfInspector = oldL, oldI })
}

func TestEBPFAttachUsesSettings(t *testing.T) {
	l := &fakeLoader{}
	withEBPF(t, l)
	env := runEnv(t, "SCRIM_INTERCEPTION_EBPF_CGROUPS=agents.slice,/sys/fs/cgroup/ci.slice/", "SCRIM_INTERCEPTION_EBPF_PORT=9800")
	r := runScrim(env, "ebpf", "attach")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !slices.Equal(l.attached, []string{"agents.slice", "ci.slice"}) || l.port != 9800 {
		t.Fatalf("attached %v on %d", l.attached, l.port)
	}
	for _, want := range []string{"+ attach connect4, connect6, sendmsg4, sendmsg6, sockops, egress to /sys/fs/cgroup/agents.slice",
		"getsockopt to /sys/fs/cgroup: the listener's SO_ORIGINAL_DST",
		"127.0.0.1:9800 and [::1]:9800", "pinned in /sys/fs/bpf/scrim/cg-42-1"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, r.stdout)
		}
	}
	if !strings.Contains(r.stderr, "nothing accepts connections on 127.0.0.1:9800") {
		t.Errorf("no listener warning:\n%s", r.stderr)
	}

	l2 := &fakeLoader{}
	withEBPF(t, l2)
	if r := runScrim(runEnv(t), "ebpf", "attach", "--cgroup", "x.slice", "--port", "1234"); r.code != 0 || l2.port != 1234 || l2.attached[0] != "x.slice" {
		t.Fatalf("flags: exit %d %v %d %s", r.code, l2.attached, l2.port, r.stderr)
	}
	if r := runScrim(runEnv(t), "ebpf", "attach", "--cgroup", "x.slice", "--no-listener-check"); r.code != 0 || r.stderr != "" {
		t.Fatalf("--no-listener-check: exit %d, stderr %q", r.code, r.stderr)
	}
}

func TestEBPFAttachRefusals(t *testing.T) {
	withEBPF(t, &fakeLoader{})
	if r := runScrim(runEnv(t), "ebpf", "attach"); r.code == 0 || !strings.Contains(r.stderr, "interception.ebpf.cgroups") {
		t.Fatalf("no cgroups: exit %d %s", r.code, r.stderr)
	}
	if r := runScrim(runEnv(t), "ebpf", "attach", "--cgroup", "../etc"); r.code == 0 || !strings.Contains(r.stderr, "cgroup v2 path") {
		t.Fatalf("bad cgroup: exit %d %s", r.code, r.stderr)
	}
	withEBPF(t, &fakeLoader{err: &bpfredirect.PrivilegeError{Op: "attaching eBPF programs", Missing: []string{"CAP_BPF", "CAP_NET_ADMIN"}}})
	if r := runScrim(runEnv(t), "ebpf", "attach", "--cgroup", "a.slice"); r.code == 0 || !strings.Contains(r.stderr, "lacks CAP_BPF and CAP_NET_ADMIN") {
		t.Fatalf("unprivileged: exit %d %s", r.code, r.stderr)
	}
}

func TestEBPFDetach(t *testing.T) {
	l := &fakeLoader{}
	withEBPF(t, l)
	env := runEnv(t, "SCRIM_INTERCEPTION_EBPF_CGROUPS=agents.slice")
	if r := runScrim(env, "ebpf", "detach"); r.code == 0 || len(l.detached) != 0 {
		t.Fatalf("detach without --cgroup or --all: exit %d %v", r.code, l.detached)
	}
	if r := runScrim(env, "ebpf", "detach", "--all"); r.code != 0 || !strings.Contains(r.stdout, "nothing attached") {
		t.Fatalf("--all with an empty record: exit %d %s %s", r.code, r.stdout, r.stderr)
	}
	if r := runScrim(env, "ebpf", "detach", "--cgroup", "agents.slice"); r.code != 0 || !slices.Equal(l.detached, []string{"agents.slice"}) {
		t.Fatalf("detach: exit %d %v %s", r.code, l.detached, r.stderr)
	}
}

// TestEBPFStatusConfiguredNotAttached is specs/interception "Loader not
// available": configured, never attached, and this process without the
// privilege: status and doctor do not report the mode active and name what
// is missing.
func TestEBPFStatusConfiguredNotAttached(t *testing.T) {
	withEBPF(t, &fakeLoader{})
	env := runEnv(t, "SCRIM_INTERCEPTION_EBPF_CGROUPS=agents.slice")

	r := runScrim(env, "ebpf", "status", "--json")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var e status.EBPF
	if err := json.Unmarshal([]byte(r.stdout), &e); err != nil {
		t.Fatal(err)
	}
	if len(e.Cgroups) != 1 || e.Cgroups[0].State == "active" || !strings.Contains(e.Cgroups[0].Detail, "CAP_BPF and CAP_NET_ADMIN") {
		t.Fatalf("ebpf status %+v", e)
	}

	r = runScrim(env, "status", "--json")
	var rep status.Report
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("%v: %s %s", err, r.stdout, r.stderr)
	}
	if rep.EBPF == nil || slices.ContainsFunc(rep.Interception, func(m string) bool { return strings.Contains(m, "ebpf") }) {
		t.Fatalf("status: ebpf %+v, interception %v", rep.EBPF, rep.Interception)
	}
	if !slices.ContainsFunc(rep.Degraded, func(c status.Component) bool { return c.Name == "ebpf:agents.slice" }) {
		t.Fatalf("degraded %+v", rep.Degraded)
	}

	r = runScrim(env, "doctor")
	if r.code == 0 || !strings.Contains(r.stdout, "[fail] ebpf: agents.slice: not attached") {
		t.Fatalf("doctor: exit %d\n%s", r.code, r.stdout)
	}

	// With nothing configured or attached the mode stays out of the report.
	r = runScrim(runEnv(t), "status", "--json")
	rep = status.Report{}
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil || rep.EBPF != nil {
		t.Fatalf("unused mode in status: %+v %v", rep.EBPF, err)
	}
}

// The programs redirect to the transparent listener scrim install
// --transparent sets up, so both default to the same port.
func TestEBPFPortIsTheTransparentListener(t *testing.T) {
	if bpfredirect.DefaultPort != install.DefaultTransparentPort {
		t.Fatalf("interception.ebpf.port defaults to %d, the transparent listener to %d", bpfredirect.DefaultPort, install.DefaultTransparentPort)
	}
}

// withInstalledEBPFUnit writes the boot unit `scrim install --ebpf
// --transparent-port port` writes, under a fake install root.
func withInstalledEBPFUnit(t *testing.T, port int) {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, install.EBPFUnitPath)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(install.EBPFUnitFile(install.SystemBinary, []string{"agents.slice"}, port)), 0o644); err != nil {
		t.Fatal(err)
	}
	old := installRoot
	installRoot = root
	t.Cleanup(func() { installRoot = old })
}

// An install with a non-default --transparent-port sets no
// interception.ebpf.port. Status and a manual attach take the port from the
// installed boot unit, and an explicit setting still wins.
func TestEBPFPortFromInstalledUnit(t *testing.T) {
	withEBPF(t, &fakeLoader{})
	withInstalledEBPFUnit(t, 9800)
	ebpfStatusPort := func(env []string) int {
		t.Helper()
		r := runScrim(env, "ebpf", "status", "--json")
		if r.code != 0 {
			t.Fatalf("exit %d: %s", r.code, r.stderr)
		}
		var e status.EBPF
		if err := json.Unmarshal([]byte(r.stdout), &e); err != nil {
			t.Fatalf("%v\n%s", err, r.stdout)
		}
		return e.Port
	}
	if got := ebpfStatusPort(runEnv(t, "SCRIM_INTERCEPTION_EBPF_CGROUPS=agents.slice")); got != 9800 {
		t.Fatalf("status checks port %d, want the installed unit's 9800", got)
	}
	if got := ebpfStatusPort(runEnv(t, "SCRIM_INTERCEPTION_EBPF_CGROUPS=agents.slice", "SCRIM_INTERCEPTION_EBPF_PORT=9900")); got != 9900 {
		t.Fatalf("status checks port %d, want the explicit 9900", got)
	}
	l := &fakeLoader{}
	withEBPF(t, l)
	if r := runScrim(runEnv(t), "ebpf", "attach", "--cgroup", "agents.slice", "--no-listener-check"); r.code != 0 || l.port != 9800 {
		t.Fatalf("attach without --port: exit %d port %d %s", r.code, l.port, r.stderr)
	}
}

// With the boot unit installed, status names the unit reload as the fix for
// an attachment made by an older scrim; without it, a manual attach.
func TestEBPFStatusFixNamesTheBootUnit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("control group IDs are read on Linux only")
	}
	withEBPF(t, &fakeLoader{})
	ebpfInspector.Caps = func() bpfredirect.Caps { return 1 << 12 } // CAP_NET_ADMIN
	cg := filepath.Join(ebpfInspector.CgroupRoot, "agents.slice")
	if err := os.Mkdir(cg, 0o700); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(cg, &st); err != nil {
		t.Fatal(err)
	}
	rec := fmt.Sprintf(`{"attachments":[{"cgroup":"agents.slice","cgroup_id":%d,"port":9793,"programs":{"connect4":1,"connect6":2,"sendmsg4":3,"sendmsg6":4,"egress":5},"pin_dir":"/sys/fs/bpf/scrim/x","attached_at":"2026-11-01T00:00:00Z"}]}`, st.Ino)
	if err := os.WriteFile(ebpfInspector.RecordPath, []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
	fixOf := func() status.EBPFCgroup {
		t.Helper()
		r := runScrim(runEnv(t, "SCRIM_INTERCEPTION_EBPF_CGROUPS=agents.slice"), "ebpf", "status", "--json")
		var e status.EBPF
		if err := json.Unmarshal([]byte(r.stdout), &e); err != nil || len(e.Cgroups) != 1 {
			t.Fatalf("%v\n%s%s", err, r.stdout, r.stderr)
		}
		return e.Cgroups[0]
	}
	if c := fixOf(); c.State != "lost" || c.Fix != "sudo scrim ebpf attach" || !strings.Contains(c.Detail, "without the sockops program") {
		t.Fatalf("without the boot unit: %+v", c)
	}
	withInstalledEBPFUnit(t, 9793)
	if c := fixOf(); c.State != "lost" || c.Fix != "sudo systemctl reload-or-restart scrim-ebpf" {
		t.Fatalf("with the boot unit: %+v", c)
	}
	r := runScrim(runEnv(t, "SCRIM_INTERCEPTION_EBPF_CGROUPS=agents.slice"), "doctor")
	if !strings.Contains(r.stdout+r.stderr, "sudo systemctl reload-or-restart scrim-ebpf") {
		t.Errorf("doctor does not name the fix:\n%s%s", r.stdout, r.stderr)
	}
}
