// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/bpfredirect"
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
	for _, want := range []string{"+ attach connect4, connect6, sendmsg4, sendmsg6, egress to /sys/fs/cgroup/agents.slice",
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
