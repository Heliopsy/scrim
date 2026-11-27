// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// WriteJSON writes r as indented JSON. Field names are part of the
// machine-readable contract; weakened settings are under
// "weakened_protections".
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// WriteHuman writes r for a terminal.
func WriteHuman(w io.Writer, r Report) error {
	p := &printer{w: w}
	p.line("scrim %s", orDefault(r.Version, "(unknown version)"))
	if r.Profile != "" {
		p.line("profile: %s", r.Profile)
	}
	if r.OK() {
		p.line("overall: ok")
	} else {
		p.line("overall: DEGRADED (%d degraded, %d weakened)", len(r.Degraded), len(r.Weakened))
	}
	if r.Coverage == CoveragePartial {
		p.line("protection: PARTIAL (agent hooks only: no scrim run session, enforcing interception or managed settings puts model traffic on scrim)")
	}

	if c := r.Config; c != nil {
		p.section("Configuration")
		files := "none"
		if len(c.Files) > 0 {
			files = strings.Join(c.Files, ", ")
		}
		p.line("  version %d, loaded %s, files: %s", c.Version, when(c.LoadedAt), files)
		if lr := c.LastReload; lr != nil {
			p.line("  last reload %s (%s): %s", when(lr.At), lr.Trigger, onOff(lr.Applied, "applied", "REJECTED"))
			for _, pr := range lr.Problems {
				p.line("    %s", pr)
			}
		}
		for _, k := range c.PendingRestart {
			p.line("  pending restart: %s", k)
		}
		for _, w := range c.Warnings {
			p.line("  warning: %s", w)
		}
	}

	if sv := r.Service; sv != nil {
		p.section("Service")
		kind := sv.Mode + " service"
		if sv.Mode == "quadlet" {
			kind = "rootless Quadlet container"
			if sv.System {
				kind = "system Quadlet container"
			}
		}
		p.line("  %s: %s (%s, manifest %s)", sv.Unit, sv.Active, kind, sv.Manifest)
	}

	p.section("Interception")
	if len(r.Interception) == 0 {
		p.line("  none active")
	}
	for _, m := range r.Interception {
		p.line("  %s", m)
	}
	if r.UpstreamProxy != "" {
		p.line("  outbound: %s", outbound(r.UpstreamProxy))
	}
	for _, m := range r.AgentModes {
		p.line("  %s:", m.Mode)
		for _, f := range m.Files {
			p.line("    file: %s", f)
		}
		for _, c := range m.Covers {
			p.line("    covers: %s", c)
		}
		for _, c := range m.NotCovered {
			p.line("    not covered: %s", c)
		}
		for _, c := range m.Changed {
			p.line("    CHANGED since install: %s", c)
		}
	}

	if v := r.RunView; v != nil {
		p.section("Filesystem view (scrim run)")
		switch {
		case v.Mode == RunViewRefused:
			p.line("  REFUSED: run.fs-view is namespace, but %s", v.Fallback)
		case v.Fallback != "":
			p.line("  %s (fallback: %s)", v.Mode, v.Fallback)
		case v.Mode == "namespace":
			p.line("  namespace (user and mount namespace)")
		default:
			p.line("  %s (run.fs-view %s)", v.Mode, v.Requested)
		}
		for _, g := range v.Gaps {
			p.line("    not covered: %s", g)
		}
		if len(v.ReadableOwn) > 0 {
			p.line("  scrim's own secret files readable by this user (scrim run hides them from sessions):")
			for _, f := range v.ReadableOwn {
				p.line("    %s", f)
			}
		}
	}

	if r.EBPF != nil {
		p.section("eBPF transparent mode")
		writeEBPF(p, r.EBPF)
	}

	p.section("Protections")
	p.table(len(r.Protections), func(tw io.Writer) {
		for _, pr := range r.Protections {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\n", pr.Name, onOff(pr.Active, "active", "INACTIVE"), pr.Detail)
		}
	})

	p.section("Providers")
	p.table(len(r.Providers), func(tw io.Writer) {
		for _, pv := range r.Providers {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\n", pv.Name, pv.Upstream)
		}
	})

	p.section("Stores")
	p.table(len(r.Stores), func(tw io.Writer) {
		for _, s := range r.Stores {
			state := "ok"
			switch {
			case !s.Reachable:
				state = "UNREACHABLE"
			case s.Degraded:
				state = "DEGRADED"
			}
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%d values\trefreshed %s\t%s\n",
				s.Name, s.Kind, state, s.Values, when(s.LastRefresh), s.Reason)
			for _, t := range s.Targets {
				_, _ = fmt.Fprintf(tw, "    redact %s\t\t%s\t%d values\t\t\n", t.Target, onOff(t.Values > 0, "ok", "EMPTY"), t.Values)
			}
		}
	})

	p.section("State")
	loc := ""
	if r.State.Location != "" {
		loc = " at " + r.State.Location
	}
	p.line("  %s%s, schema %d, %s", r.State.Backend, loc, r.State.SchemaVersion, onOff(r.State.Healthy, "healthy", "UNHEALTHY"))
	if r.State.Detail != "" {
		p.line("  %s", r.State.Detail)
	}

	p.section("Audit sinks")
	p.table(len(r.Audit), func(tw io.Writer) {
		for _, a := range r.Audit {
			_, _ = fmt.Fprintf(tw, "  %s\tpolicy %s\t%s\t%d dropped\t%s\n",
				a.Name, a.Policy, onOff(!a.Degraded, "ok", "DEGRADED"), a.Dropped, a.Detail)
		}
	})

	p.section("Data plane")
	dp := r.DataPlane
	if dp.Running {
		p.line("  running, pid %d, version %s, up %s, %s", dp.PID, orDefault(dp.Version, "unknown"),
			dp.Uptime.Round(time.Second), onOff(dp.Healthy, "healthy", "UNHEALTHY"))
	} else {
		p.line("  NOT RUNNING")
	}
	if dp.Detail != "" {
		p.line("  %s", dp.Detail)
	}

	p.section("Degraded")
	if len(r.Degraded) == 0 {
		p.line("  none")
	}
	for _, c := range r.Degraded {
		p.line("  %s: %s", c.Name, c.Reason)
	}

	p.section("Weakened protections")
	if len(r.Weakened) == 0 {
		p.line("  none")
	}
	for _, wk := range r.Weakened {
		p.line("  %s = %s (from %s)", wk.Key, wk.Value, wk.Source)
		if wk.Description != "" {
			p.line("    %s", wk.Description)
		}
	}
	return p.err
}

// WriteEBPF writes the eBPF mode for a terminal (`scrim ebpf status`).
func WriteEBPF(w io.Writer, e *EBPF) error {
	p := &printer{w: w}
	writeEBPF(p, e)
	return p.err
}

func writeEBPF(p *printer, e *EBPF) {
	if len(e.Cgroups) == 0 && e.Problem == "" {
		p.line("  off (interception.ebpf.cgroups is empty and nothing is attached)")
		return
	}
	if e.Problem != "" {
		p.line("  NOT AVAILABLE: %s", e.Problem)
	}
	p.table(len(e.Cgroups), func(tw io.Writer) {
		for _, c := range e.Cgroups {
			state := strings.ToUpper(c.State)
			if c.State == "active" {
				state = c.State
			}
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.Cgroup, state, c.Detail)
		}
	})
	if len(e.Cgroups) > 0 {
		p.line("  listener: %s", e.Listener)
	}
}

type printer struct {
	w   io.Writer
	err error
}

func (p *printer) line(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, strings.TrimRight(format, "\n")+"\n", args...)
}

func (p *printer) section(name string) {
	p.line("")
	p.line("%s", name)
}

func (p *printer) table(n int, rows func(io.Writer)) {
	if p.err != nil {
		return
	}
	if n == 0 {
		p.line("  none")
		return
	}
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	rows(tw)
	if p.err = tw.Flush(); p.err != nil {
		return
	}
	for _, l := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		p.line("%s", strings.TrimRight(l, " "))
	}
}

func onOff(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func when(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// outbound describes where scrim's own connections go.
func outbound(up string) string {
	if up == "direct" {
		return "direct (no upstream proxy)"
	}
	return "through upstream proxy " + up
}
