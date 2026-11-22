// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/bpfredirect"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/install"
	"github.com/heliopsy/scrim/internal/status"
)

// Injection points for tests: the privileged loader and what status reads.
var (
	ebpfLoader interface {
		Attach(cgroup string, port int) (bpfredirect.Attachment, error)
		Detach(cgroup string) error
	} = bpfredirect.Loader{}
	ebpfInspector = bpfredirect.Inspector{}
)

// EBPF is the privileged loader of the eBPF transparent mode
// (specs/interception "Transparent mode with eBPF").
func (Commands) EBPF(e *Env) *cobra.Command {
	c := &cobra.Command{
		Use:   "ebpf",
		Short: "Attach, detach and inspect the eBPF transparent mode (Linux, cgroup v2)",
		Long: "The eBPF transparent mode attaches programs to the connect, sendmsg and egress hooks of selected control " +
			"groups. Their TCP connections to ports 80 and 443 of any address that is not loopback are rewritten to scrim's " +
			"transparent listener on 127.0.0.1 and ::1 (interception.ebpf.port), their QUIC (UDP 443) is refused, and any " +
			"packet to those ports that still leaves for another address is dropped. Processes outside the control groups " +
			"are not affected.\n\n" +
			"attach and detach are the privileged loader: they need root, or CAP_BPF and CAP_NET_ADMIN with write access to " +
			bpfredirect.PinRoot + ". The programs stay attached when scrim or the loader stops, so covered connections then " +
			"fail instead of going direct; they last until `scrim ebpf detach` or a reboot. The listener itself is the " +
			"transparent listener (proxy.transparent-listen), which terminates TLS with scrim's CA: clients in the control " +
			"groups must trust it.",
	}
	c.AddCommand(ebpfAttach(e), ebpfDetach(e), ebpfStatus(e))
	return c
}

type ebpfTargets struct {
	cgroups []string
	port    int
	// noListenerCheck skips the warning about the listener, for the boot
	// unit of `scrim install --ebpf`, which attaches before scrim starts.
	noListenerCheck bool
}

func (t *ebpfTargets) bind(c *cobra.Command) {
	c.Flags().StringSliceVar(&t.cgroups, "cgroup", nil,
		"control group below /sys/fs/cgroup (repeatable; default interception.ebpf.cgroups)")
}

func (t *ebpfTargets) resolve(e *Env, what string) ([]string, error) {
	cgs := t.cgroups
	if len(cgs) == 0 {
		cfg, err := e.Config()
		if err != nil {
			return nil, err
		}
		cgs = bpfredirect.CgroupsSetting.Get(cfg)
	}
	if len(cgs) == 0 {
		return nil, fmt.Errorf("no control group to %s: pass --cgroup or set interception.ebpf.cgroups", what)
	}
	var out []string
	for _, c := range cgs {
		cc, err := bpfredirect.CleanCgroup(c)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, cc) {
			out = append(out, cc)
		}
	}
	return out, nil
}

func ebpfAttach(e *Env) *cobra.Command {
	var t ebpfTargets
	c := &cobra.Command{
		Use:   "attach",
		Short: "Attach the programs to the control groups (privileged; replaces an existing attachment in place)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cgs, err := t.resolve(e, "attach to")
			if err != nil {
				return err
			}
			port := t.port
			if !cmd.Flags().Changed("port") {
				cfg, err := e.Config()
				if err != nil {
					return err
				}
				port = ebpfPort(cfg)
			}
			w := cmd.OutOrStdout()
			for _, cg := range cgs {
				_, _ = fmt.Fprintf(w, "+ attach %s to %s/%s: TCP 80 and 443 of other hosts to 127.0.0.1:%d and [::1]:%d, "+
					"UDP 443 refused, other egress to those ports dropped; %s to %s: the listener's SO_ORIGINAL_DST for them\n",
					strings.Join(bpfredirect.Hooks, ", "), bpfredirect.CgroupRoot, cg, port, port,
					strings.Join(bpfredirect.ListenerHooks, ", "), bpfredirect.CgroupRoot)
				a, err := ebpfLoader.Attach(cg, port)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(w, "  attached %s, links pinned in %s (`scrim ebpf detach --cgroup %s` removes them)\n", a, a.PinDir, cg)
			}
			if t.noListenerCheck {
				return nil
			}
			if up, msg := ebpfInspector.CheckListener(port); !up {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s; start scrim with proxy.transparent-listen on port %d\n", msg, port)
			}
			return nil
		},
	}
	t.bind(c)
	c.Flags().IntVar(&t.port, "port", bpfredirect.DefaultPort, "transparent listener port (default interception.ebpf.port)")
	c.Flags().BoolVar(&t.noListenerCheck, "no-listener-check", false,
		"do not warn when nothing listens on the port yet (the boot unit of `scrim install --ebpf` attaches before scrim starts)")
	return c
}

func ebpfDetach(e *Env) *cobra.Command {
	var (
		t   ebpfTargets
		all bool
	)
	c := &cobra.Command{
		Use:   "detach",
		Short: "Detach the programs from the control groups (privileged)",
		Long: "Removes the pinned links of each control group, which detaches its programs, and waits until the kernel " +
			"confirms it. With --all, every control group the loader's record lists. Afterwards the control groups reach " +
			"providers directly again unless another mode covers them.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var cgs []string
			if all {
				rec, err := bpfredirect.ReadRecord(recordPath())
				if err != nil {
					return err
				}
				for _, a := range rec.Attachments {
					cgs = append(cgs, a.Cgroup)
				}
				if len(cgs) == 0 {
					_, err := fmt.Fprintln(cmd.OutOrStdout(), "nothing attached")
					return err
				}
			} else {
				if len(t.cgroups) == 0 {
					return errors.New("name the control groups with --cgroup, or pass --all")
				}
				var err error
				if cgs, err = t.resolve(e, "detach from"); err != nil {
					return err
				}
			}
			for _, cg := range cgs {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- detach %s/%s\n", bpfredirect.CgroupRoot, cg)
				if err := ebpfLoader.Detach(cg); err != nil {
					return err
				}
			}
			return nil
		},
	}
	t.bind(c)
	c.Flags().BoolVar(&all, "all", false, "detach every control group the loader attached")
	return c
}

func ebpfStatus(e *Env) *cobra.Command {
	var out outputFlags
	c := &cobra.Command{
		Use:   "status",
		Short: "Report each covered control group; only a process with CAP_NET_ADMIN can confirm one as active",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := out.format()
			if err != nil {
				return err
			}
			r := ebpfReport(e)
			if r == nil {
				r = &status.EBPF{Cgroups: []status.EBPFCgroup{}, Configured: []string{}}
			}
			return writeOut(cmd.OutOrStdout(), format, r, func(w io.Writer) error { return status.WriteEBPF(w, r) })
		},
	}
	out.bind(c)
	return c
}

func recordPath() string {
	if ebpfInspector.RecordPath != "" {
		return ebpfInspector.RecordPath
	}
	return bpfredirect.RecordPath
}

// ebpfPort is the listener port the eBPF mode redirects to: an explicit
// interception.ebpf.port, else the port the boot unit of `scrim install
// --ebpf` attaches with (its --transparent-port), else the default.
func ebpfPort(cfg *config.Config) int {
	if e, ok := cfg.Entry(bpfredirect.PortSetting.Name()); ok && e.Source.Kind != config.SourceDefault {
		return bpfredirect.PortSetting.Get(cfg)
	}
	if p, ok := install.EBPFUnitPort(installRoot); ok {
		return p
	}
	return bpfredirect.PortSetting.Get(cfg)
}

// ebpfReport is the eBPF mode as status shows it, nil when it is neither
// configured nor attached.
func ebpfReport(e *Env) *status.EBPF {
	var cgs []string
	port := bpfredirect.DefaultPort
	if cfg, err := e.Config(); err == nil {
		cgs, port = bpfredirect.CgroupsSetting.Get(cfg), ebpfPort(cfg)
	}
	r := bpfredirect.Inspect(ebpfInspector, cgs, port)
	if r == nil {
		return nil
	}
	s := &status.EBPF{
		Configured: r.Configured, Port: r.Port, Problem: r.Problem,
		Listener: r.Listener, ListenerUp: r.ListenerUp, Cgroups: []status.EBPFCgroup{},
	}
	for _, c := range r.Cgroups {
		s.Cgroups = append(s.Cgroups, status.EBPFCgroup{
			Cgroup: c.Cgroup, State: string(c.State), Detail: c.Detail, AttachedAt: c.AttachedAt.UTC().Truncate(time.Second),
		})
	}
	return s
}

// ebpfSource adapts ebpfReport to status.Sources.
type ebpfSource struct{ e *Env }

func (s ebpfSource) EBPFStatus() *status.EBPF { return ebpfReport(s.e) }
