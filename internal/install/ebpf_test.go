// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeEBPF is the loader: Check returns err, Detach is logged into the
// host's calls so its order against systemctl shows.
type fakeEBPF struct {
	h   *fakeHost
	err error
}

func (f fakeEBPF) Check() error { return f.err }

func (f fakeEBPF) Detach(cg string) error {
	f.h.calls = append(f.h.calls, "ebpf detach "+cg)
	return nil
}

func ebpfInstaller(t *testing.T, h *fakeHost, j *javaHost, out *bytes.Buffer, cgroups ...string) *Installer {
	t.Helper()
	in := h.system(t, ModeSystem, out)
	in.Runner = j
	in.EBPF = fakeEBPF{h: h}
	in.Intercept = Interception{EBPF: true, CoverCgroups: cgroups}
	return in
}

func TestEBPFInstallAndUninstallLeaveNoTrace(t *testing.T) {
	h, j := interceptHost(t)
	before := snapshot(t, h.root)
	var out bytes.Buffer
	in := ebpfInstaller(t, h, j, &out, "agents.slice", "/sys/fs/cgroup/user.slice/user-agents.slice/")
	if err := in.Install(context.Background()); err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	unit := h.read("etc/systemd/system/scrim-ebpf.service")
	for _, want := range []string{
		"Type=oneshot\nRemainAfterExit=yes\n",
		"ExecStart=/usr/local/bin/scrim ebpf attach --cgroup agents.slice --cgroup user.slice/user-agents.slice --port 9793 --no-listener-check\n",
		"ExecReload=/usr/local/bin/scrim ebpf attach --cgroup agents.slice --cgroup user.slice/user-agents.slice --port 9793 --no-listener-check\n",
		"ExecStop=/usr/local/bin/scrim ebpf detach --cgroup agents.slice --cgroup user.slice/user-agents.slice\n",
		"DefaultDependencies=no", "RequiresMountsFor=/sys/fs/bpf /sys/fs/cgroup /usr/local/bin/scrim",
		"Before=network-pre.target scrim.service shutdown.target", "Conflicts=shutdown.target",
		"Wants=agents.slice\nAfter=agents.slice\n", "Wants=user-agents.slice\nAfter=user-agents.slice\n",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	drop := h.read("etc/systemd/system/scrim.service.d/interception.conf")
	if !strings.Contains(drop, "Environment=SCRIM_PROXY_TRANSPARENT_LISTEN=127.0.0.1:9793,[::1]:9793\n") {
		t.Errorf("drop-in lacks the transparent listener:\n%s", drop)
	}
	if strings.Contains(drop, "SNI") || h.read("etc/scrim/transparent.nft") != "" {
		t.Errorf("--ebpf installed another mode: drop-in\n%s", drop)
	}
	checkOrder(t, h.calls, []string{"systemctl enable --now scrim.service", "update-ca-certificates",
		"systemctl daemon-reload", "systemctl enable --now scrim-ebpf.service"})
	for _, c := range h.calls {
		if strings.HasPrefix(c, "nft") {
			t.Errorf("--ebpf ran %s", c)
		}
	}

	// A second install with the same flags changes nothing.
	h.calls = nil
	again := ebpfInstaller(t, h, j, &out, "agents.slice", "user.slice/user-agents.slice")
	again.Executable = in.Executable
	if err := again.Install(context.Background()); err != nil {
		t.Fatalf("second install: %v\n%s", err, out.String())
	}
	if c := strings.Join(h.calls, "\n"); strings.Contains(c, "restart") || strings.Contains(c, "reload") || strings.Contains(c, "ebpf detach") {
		t.Errorf("second install changed things:\n%s", c)
	}

	// Dropping a control group reattaches in place and detaches the dropped one.
	h.calls = nil
	out.Reset()
	fewer := ebpfInstaller(t, h, j, &out, "agents.slice")
	fewer.Executable = in.Executable
	if err := fewer.Install(context.Background()); err != nil {
		t.Fatalf("install with fewer control groups: %v\n%s", err, out.String())
	}
	checkOrder(t, h.calls, []string{"systemctl daemon-reload", "systemctl reload-or-restart scrim-ebpf.service",
		"ebpf detach user.slice/user-agents.slice"})
	if strings.Contains(h.read("etc/systemd/system/scrim-ebpf.service"), "user-agents") {
		t.Errorf("unit still covers the dropped control group")
	}
	mf, _, err := ReadManifest(fewer.ManifestPath())
	if err != nil {
		t.Fatal(err)
	}
	var cgs []string
	for _, e := range mf.Entries {
		if e.Kind == KindEBPF {
			cgs = append(cgs, e.Target)
		}
	}
	if strings.Join(cgs, ",") != "agents.slice" {
		t.Errorf("recorded attachments %v, want agents.slice", cgs)
	}

	h.calls = nil
	out.Reset()
	un := h.system(t, "", &out)
	un.Runner = j
	un.EBPF = fakeEBPF{h: h}
	un.Purge = true
	if err := un.Uninstall(context.Background()); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out.String())
	}
	// Detached (and confirmed by the loader) before the unit is stopped,
	// the unit and drop-in removed with a reload each, then the service.
	checkOrder(t, h.calls, []string{"ebpf detach agents.slice", "systemctl disable --now scrim-ebpf.service",
		"systemctl daemon-reload", "update-ca-certificates --fresh", "systemctl disable --now scrim.service"})
	if !strings.Contains(out.String(), "- detach the eBPF programs from the control group agents.slice (scrim ebpf detach --cgroup agents.slice)") {
		t.Errorf("detach not shown:\n%s", out.String())
	}
	if d := diff(before, snapshot(t, h.root)); len(d) > 0 {
		t.Errorf("uninstall left traces: %v\n%s", d, out.String())
	}

	// Uninstalling again is a no-op.
	h.calls = nil
	out.Reset()
	if err := un.Uninstall(context.Background()); err != nil || len(h.calls) > 0 || !strings.Contains(out.String(), "nothing to uninstall") {
		t.Fatalf("second uninstall: %v, calls %v\n%s", err, h.calls, out.String())
	}
}

func TestEBPFDryRunPrintsUnitsAndChangesNothing(t *testing.T) {
	h, j := interceptHost(t)
	before := snapshot(t, h.root)
	var out bytes.Buffer
	in := ebpfInstaller(t, h, j, &out, "agents.slice")
	in.DryRun = true
	// Without privileges a dry run still shows everything.
	in.EBPF = fakeEBPF{h: h, err: errors.New("attaching eBPF programs needs root, or CAP_BPF and CAP_NET_ADMIN")}
	if err := in.Install(context.Background()); err != nil {
		t.Fatalf("dry run: %v\n%s", err, out.String())
	}
	for _, want := range []string{
		"note: the install itself would stop here: attaching eBPF programs needs root",
		"+ would write " + h.root + "/etc/systemd/system/scrim-ebpf.service",
		"    ExecStart=/usr/local/bin/scrim ebpf attach --cgroup agents.slice --port 9793 --no-listener-check\n",
		"    ExecStop=/usr/local/bin/scrim ebpf detach --cgroup agents.slice\n",
		"    Environment=SCRIM_PROXY_TRANSPARENT_LISTEN=127.0.0.1:9793,[::1]:9793\n",
		"+ would enable and start scrim-ebpf.service",
		"Nothing was changed (dry run).",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out.String())
		}
	}
	if d := diff(before, snapshot(t, h.root)); len(d) > 0 {
		t.Errorf("dry run changed files: %v", d)
	}
	for _, c := range h.calls {
		if strings.HasPrefix(c, "systemctl") || strings.HasPrefix(c, "ebpf") {
			t.Errorf("dry run ran %s", c)
		}
	}
}

func TestEBPFChecks(t *testing.T) {
	h, j := interceptHost(t)
	cases := []struct {
		name string
		mode Mode
		ic   Interception
		err  error
		want string
	}{
		{"user unit", ModeUser, Interception{EBPF: true, CoverCgroups: []string{"agents.slice"}}, nil, "need the system service"},
		{"no cgroup", ModeSystem, Interception{EBPF: true}, nil, "at least one --cover-cgroup"},
		{"users", ModeSystem, Interception{EBPF: true, CoverUsers: []string{"agent1"}, CoverCgroups: []string{"a.slice"}}, nil, "control groups only"},
		{"with nftables", ModeSystem, Interception{EBPF: true, Transparent: true, CoverCgroups: []string{"a.slice"}}, nil, "alternatives"},
		{"scrim's slice", ModeSystem, Interception{EBPF: true, CoverCgroups: []string{"system.slice"}}, nil, "back to itself"},
		{"scrim's unit", ModeSystem, Interception{EBPF: true, CoverCgroups: []string{"/sys/fs/cgroup/system.slice/scrim.service"}}, nil, "back to itself"},
		{"specifier", ModeSystem, Interception{EBPF: true, CoverCgroups: []string{"a%n.slice"}}, nil, "control group path"},
		{"missing cgroup", ModeSystem, Interception{EBPF: true, CoverCgroups: []string{"no/such.scope"}}, nil, "does not exist"},
		{"unprivileged", ModeSystem, Interception{EBPF: true, CoverCgroups: []string{"a.slice"}},
			errors.New("attaching eBPF programs needs root, or CAP_BPF and CAP_NET_ADMIN"), "--ebpf: attaching eBPF programs needs root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h.calls = nil
			var out bytes.Buffer
			in := h.system(t, c.mode, &out)
			in.System = c.mode != ModeUser
			in.Runner = j
			in.EBPF = fakeEBPF{h: h, err: c.err}
			in.Intercept = c.ic
			err := in.Install(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q\n%s", err, c.want, out.String())
			}
			if c.name != "missing cgroup" && len(h.calls) > 0 {
				t.Errorf("refused install ran %v", h.calls)
			}
		})
	}
	var out bytes.Buffer
	in := h.system(t, ModeSystem, &out)
	in.Intercept = Interception{EBPF: true, CoverCgroups: []string{"a.slice"}}
	if err := in.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "no eBPF loader") {
		t.Fatalf("no loader: %v", err)
	}
}

// EBPFUnitPort reads back the port EBPFUnitFile writes, so status can check
// an install with a non-default --transparent-port.
func TestEBPFUnitPort(t *testing.T) {
	root := t.TempDir()
	if p, ok := EBPFUnitPort(root); ok {
		t.Fatalf("no unit: got %d", p)
	}
	path := filepath.Join(root, EBPFUnitPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{DefaultTransparentPort, 9800} {
		if err := os.WriteFile(path, []byte(EBPFUnitFile(SystemBinary, []string{"agents.slice", "ci.slice"}, port)), 0o644); err != nil {
			t.Fatal(err)
		}
		if p, ok := EBPFUnitPort(root); !ok || p != port {
			t.Fatalf("EBPFUnitPort = %d %v, want %d", p, ok, port)
		}
	}
	if err := os.WriteFile(path, []byte("[Service]\nExecStart=/usr/bin/true --port x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, ok := EBPFUnitPort(root); ok {
		t.Fatalf("unparsable port: got %d", p)
	}
}
