// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// The eBPF variant of the transparent mode as a system install
// (specs/interception "Transparent mode with eBPF", specs/deployment
// "Host-level interception install"): a oneshot unit runs the privileged
// loader, `scrim ebpf attach`, at every boot before the network and before
// scrim.service, and the drop-in turns on the transparent listener the
// programs redirect to. The links are pinned in bpffs by the loader, so they
// stay after the oneshot exits; stopping the unit detaches them.

const (
	// EBPFUnit attaches the programs at boot and detaches them when stopped.
	EBPFUnit = "scrim-ebpf.service"
	// EBPFUnitPath is the unit file.
	EBPFUnitPath = "/etc/systemd/system/" + EBPFUnit
	// KindEBPF is a control group the programs were attached to; reverted
	// with the loader's detach, which waits until the kernel confirms it.
	KindEBPF = "ebpf"
	// scrimCgroup is the control group of the system unit. Covering it, or
	// a parent, would redirect scrim's own upstream connections to itself:
	// unlike the nftables rules, the programs cannot exempt scrim's user.
	scrimCgroup = "system.slice/" + UnitName
)

// EBPFLoader is the privileged loader of internal/bpfredirect. Tests
// substitute a fake.
type EBPFLoader interface {
	// Check reports why this process cannot attach on this host (no cgroup
	// v2, missing capabilities, not Linux).
	Check() error
	// Detach removes a control group's attachment; detaching one that is
	// not attached is not an error.
	Detach(cgroup string) error
}

// EBPFUnitFile is the oneshot unit that attaches the programs to cgroups.
func EBPFUnitFile(binary string, cgroups []string, port int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `# Written by scrim install --ebpf; scrim uninstall --system removes it.
[Unit]
Description=scrim transparent interception (eBPF cgroup hooks)
Documentation=%s
# Attached before the network and before scrim, so the covered control groups
# never reach a provider directly; the pinned links stay after this exits.
DefaultDependencies=no
RequiresMountsFor=/sys/fs/bpf /sys/fs/cgroup %s
After=local-fs.target
Before=network-pre.target %s shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target
`, docURL, binary, UnitName)
	for _, c := range cgroups {
		// The programs attach to an existing control group; a slice's is
		// created when the slice starts.
		if s := filepath.Base(c); strings.HasSuffix(s, ".slice") {
			fmt.Fprintf(&b, "Wants=%s\nAfter=%s\n", s, s)
		}
	}
	var sel strings.Builder
	for _, c := range cgroups {
		sel.WriteString(" --cgroup " + c)
	}
	attach := fmt.Sprintf("%s ebpf attach%s --port %d --no-listener-check", binary, sel.String(), port)
	fmt.Fprintf(&b, `
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s
# Attaching again replaces each attachment in place, never leaving a gap.
ExecReload=%s
ExecStop=%s ebpf detach%s

[Install]
WantedBy=multi-user.target
`, attach, attach, binary, sel.String())
	return b.String()
}

func (in *Installer) checkEBPF() error {
	ic := in.Intercept
	if ic.Transparent {
		return errors.New("install: --ebpf and --transparent are alternatives; choose one")
	}
	if len(ic.CoverUsers) > 0 {
		return errors.New("install: --ebpf covers control groups only (--cover-cgroup); cover users with --transparent")
	}
	if len(ic.CoverCgroups) == 0 {
		return errors.New("install: --ebpf needs at least one --cover-cgroup, such as agents.slice")
	}
	for _, c := range ic.CoverCgroups {
		p, err := cgroupPath(c)
		if err != nil {
			return err
		}
		if p == scrimCgroup || strings.HasPrefix(scrimCgroup, p+"/") {
			return fmt.Errorf("install: --cover-cgroup %s holds %s, so the eBPF programs would redirect scrim's own upstream connections back to itself", p, UnitName)
		}
	}
	if in.EBPF == nil {
		return errors.New("install: --ebpf: no eBPF loader on this platform")
	}
	if err := in.EBPF.Check(); err != nil {
		if !in.DryRun {
			return fmt.Errorf("install: --ebpf: %w", err)
		}
		in.printf("note: the install itself would stop here: %v\n", err)
	}
	return nil
}

func (in *Installer) ebpfCgroups() ([]string, error) {
	var out []string
	for _, c := range in.Intercept.CoverCgroups {
		p, _ := cgroupPath(c)
		if !strings.HasSuffix(p, ".slice") && !exists(in.path(filepath.Join("/sys/fs/cgroup", p))) {
			return nil, fmt.Errorf("install: control group /sys/fs/cgroup/%s does not exist; the eBPF programs attach to an existing one (a systemd slice is created at boot)", p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// ebpfAttach installs the boot unit, starts it (which attaches), detaches
// control groups an earlier install covered and this one does not, and
// records each attached control group.
func (in *Installer) ebpfAttach(ctx context.Context) error {
	cgroups, err := in.ebpfCgroups()
	if err != nil {
		return err
	}
	port := in.Intercept.port()
	in.printf("  the eBPF mode redirects TCP 80 and 443 of the control groups %s to scrim on 127.0.0.1:%d and [::1]:%d,\n"+
		"  refuses their QUIC and drops their other egress to those ports, from now on and at every boot\n",
		strings.Join(cgroups, ", "), port, port)
	unit := EBPFUnitFile(SystemBinary, cgroups, port)
	changed, err := in.unitFile(in.path(EBPFUnitPath), []byte(unit), ScopeSystem)
	if err != nil {
		return err
	}
	if changed {
		in.show(unit)
	}
	svc := Entry{Kind: KindService, Target: EBPFUnit, Scope: ScopeSystem}
	if changed && in.recorded(svc) {
		in.printf("+ %sreload %s (attach to the control groups in place)\n", in.verb(), EBPFUnit)
		if !in.DryRun {
			if err := in.systemctl(ctx, ScopeSystem, "reload-or-restart", EBPFUnit); err != nil {
				return fmt.Errorf("%w (see journalctl -u %s)", err, strings.TrimSuffix(EBPFUnit, ".service"))
			}
		}
	}
	if err := in.enableUnit(ctx, EBPFUnit, "attach the eBPF programs now and at every boot"); err != nil {
		return fmt.Errorf("%w (see journalctl -u %s)", err, strings.TrimSuffix(EBPFUnit, ".service"))
	}
	for _, e := range slices.Clone(in.mf.Entries) {
		if e.Kind != KindEBPF || slices.Contains(cgroups, e.Target) {
			continue
		}
		in.printf("+ %sdetach the eBPF programs from %s, no longer covered (scrim ebpf detach --cgroup %s)\n", in.verb(), e.Target, e.Target)
		if in.DryRun {
			continue
		}
		if err := in.EBPF.Detach(e.Target); err != nil {
			return fmt.Errorf("install: detaching %s: %w", e.Target, err)
		}
		in.mf.Entries = deleteEntry(in.mf.Entries, e)
		if err := writeManifest(in.mpath, in.mf); err != nil {
			return err
		}
	}
	for _, cg := range cgroups {
		e := Entry{Kind: KindEBPF, Target: cg}
		if in.recorded(e) {
			continue
		}
		if err := in.change("record the eBPF attachment of "+cg+" (scrim ebpf status shows it)", e, func() error { return nil }); err != nil {
			return err
		}
	}
	return nil
}

func (in *Installer) revertEBPF(e Entry) result {
	manual := "scrim ebpf detach --cgroup " + e.Target
	if in.EBPF == nil {
		return fail(errors.New("no eBPF loader on this platform"), manual)
	}
	return resultOf(in.EBPF.Detach(e.Target), manual)
}

// show prints a file a dry run would write, indented.
func (in *Installer) show(content string) {
	if !in.DryRun {
		return
	}
	for _, l := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		in.printf("    %s\n", l)
	}
}
