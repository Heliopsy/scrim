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

	p.section("Interception")
	if len(r.Interception) == 0 {
		p.line("  none active")
	}
	for _, m := range r.Interception {
		p.line("  %s", m)
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
