// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/fsperm"
)

// Outcome is a doctor check's result.
type Outcome string

// Outcomes. Only Fail makes `scrim doctor` exit non-zero.
const (
	Pass Outcome = "pass"
	Warn Outcome = "warn"
	Fail Outcome = "fail"
	Skip Outcome = "skip"
)

// Finding is one check's result: what is wrong and the command or change
// that fixes it.
type Finding struct {
	Check   string  `json:"check"`
	Outcome Outcome `json:"outcome"`
	Message string  `json:"message"`
	Fix     string  `json:"fix,omitempty"`
}

// Check is one doctor check. Packages that own a part of the setup (CA
// trust per runtime, interception rules, agent configuration) provide their
// own through [CheckSource].
type Check struct {
	Name string
	Run  func(ctx context.Context) []Finding
}

// CheckSource contributes checks to `scrim doctor`.
type CheckSource interface {
	DoctorChecks() []Check
}

// Diagnosis is the full `scrim doctor` answer.
type Diagnosis struct {
	Findings []Finding `json:"findings"`
	Failed   int       `json:"failed"`
	Warned   int       `json:"warned"`
}

// OK reports whether no check failed.
func (d Diagnosis) OK() bool { return d.Failed == 0 }

// Diagnose runs every check concurrently, each bounded by timeout, and sorts
// the findings by check name. A check that returns nothing passes; one that
// does not finish in time fails.
func Diagnose(ctx context.Context, timeout time.Duration, checks ...Check) Diagnosis {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	results := make([][]Finding, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			done := make(chan []Finding, 1)
			go func() { done <- c.Run(cctx) }()
			select {
			case fs := <-done:
				if len(fs) == 0 {
					fs = []Finding{{Check: c.Name, Outcome: Pass, Message: "ok"}}
				}
				for j := range fs {
					if fs[j].Check == "" {
						fs[j].Check = c.Name
					}
				}
				results[i] = fs
			case <-cctx.Done():
				results[i] = []Finding{{Check: c.Name, Outcome: Fail,
					Message: fmt.Sprintf("did not finish within %s", timeout)}}
			}
		}()
	}
	wg.Wait()

	d := Diagnosis{Findings: []Finding{}}
	for _, fs := range results {
		d.Findings = append(d.Findings, fs...)
	}
	sort.SliceStable(d.Findings, func(i, j int) bool { return d.Findings[i].Check < d.Findings[j].Check })
	for _, f := range d.Findings {
		switch f.Outcome {
		case Fail:
			d.Failed++
		case Warn:
			d.Warned++
		}
	}
	return d
}

// WriteDiagnosis writes d for a terminal.
func WriteDiagnosis(w io.Writer, d Diagnosis) error {
	p := &printer{w: w}
	for _, f := range d.Findings {
		p.line("[%s] %s: %s", f.Outcome, f.Check, f.Message)
		if f.Fix != "" && f.Outcome != Pass {
			p.line("       fix: %s", f.Fix)
		}
	}
	p.line("")
	switch {
	case d.Failed > 0:
		p.line("%d check(s) failed, %d warning(s)", d.Failed, d.Warned)
	case d.Warned > 0:
		p.line("all checks passed, %d warning(s)", d.Warned)
	default:
		p.line("all checks passed")
	}
	return p.err
}

// ReportChecks turns a status report into doctor checks: the data plane,
// the state backend, each store and each audit sink, and one warning per
// weakened setting.
func ReportChecks(r Report) []Check {
	checks := []Check{
		{Name: "data-plane", Run: func(context.Context) []Finding {
			dp := r.DataPlane
			if dp.Running && dp.Healthy {
				return nil
			}
			return []Finding{{Outcome: Fail, Message: orDefault(dp.Detail, "data plane is not running or unhealthy"),
				Fix: "restart scrim; check its log for the data plane's exit reason"}}
		}},
		{Name: "state", Run: func(context.Context) []Finding {
			if r.State.Healthy {
				return nil
			}
			return []Finding{{Outcome: Fail, Message: orDefault(r.State.Detail, r.State.Backend+" state backend is unhealthy"),
				Fix: "check state.backend and its location or DSN with `scrim config show --effective`"}}
		}},
	}
	if v := r.RunView; v != nil {
		checks = append(checks, Check{Name: "run-fs-view", Run: func(context.Context) []Finding {
			fix := "allow unprivileged user namespaces (on Ubuntu: sysctl kernel.apparmor_restrict_unprivileged_userns=0, " +
				"or an AppArmor profile for scrim that allows userns), or accept the gaps listed in `scrim status`"
			switch {
			case v.Mode == RunViewRefused:
				return []Finding{{Outcome: Fail, Message: "run.fs-view is namespace, but this host has no unprivileged user namespaces: " + v.Fallback,
					Fix: fix + "; or set run.fs-view: auto to fall back to the home mirror"}}
			case v.Fallback != "":
				return []Finding{{Outcome: Warn, Message: "scrim run falls back to the home mirror: " + v.Fallback +
					"; tools that bypass HOME still read the real credential files", Fix: fix}}
			case v.Mode == "home":
				return []Finding{{Outcome: Warn, Message: "run.fs-view is home: tools that bypass HOME still read the real credential files",
					Fix: "set run.fs-view: auto where the host allows user namespaces"}}
			case v.Mode == "off":
				return []Finding{{Outcome: Warn, Message: "run.fs-view is off: real credential files in the home directory are readable from scrim run sessions",
					Fix: "set run.fs-view: auto"}}
			}
			return nil
		}})
		if len(v.ReadableOwn) > 0 {
			checks = append(checks, Check{Name: "own-files", Run: func(context.Context) []Finding {
				return []Finding{{Outcome: Warn,
					Message: "scrim runs as the user agents run as, and that user can read scrim's own secret files: " +
						strings.Join(v.ReadableOwn, ", ") + "; scrim run hides them from its sessions, anything else this user runs can read them",
					Fix: "run scrim as its own user: sudo scrim install --system --agent-user $USER (docs/service.md), " +
						"or give its secrets as systemd credentials (cred:) instead of files"}}
			}})
		}
	}
	if n := r.RunNetwork; n != nil {
		checks = append(checks, Check{Name: "run-network", Run: func(context.Context) []Finding {
			switch {
			case n.Refused():
				return []Finding{{Outcome: Fail, Message: "run.network is proxy-only, but this host cannot give an agent a network namespace of its own: " + n.Reason,
					Fix: "allow unprivileged user namespaces (on Ubuntu: sysctl kernel.apparmor_restrict_unprivileged_userns=0), or set run.network: open"}}
			case n.Requested == "proxy-only":
				return nil
			case n.Available:
				return []Finding{{Outcome: Pass, Message: "run.network is open: a command in a scrim run session that ignores the proxy settings reaches the network directly; " +
					"run.network: proxy-only works on this host and stops that"}}
			}
			return []Finding{{Outcome: Pass, Message: "run.network is open: a command in a scrim run session that ignores the proxy settings reaches the network directly; " +
				"run.network: proxy-only is not available on this host: " + n.Reason}}
		}})
	}
	for _, s := range r.Stores {
		checks = append(checks, Check{Name: "store:" + s.Name, Run: func(context.Context) []Finding {
			if !s.Reachable {
				return []Finding{{Outcome: Fail, Message: orDefault(s.Reason, "store is unreachable"),
					Fix: "check the store's address and credentials in the stores." + s.Name + " settings"}}
			}
			var out []Finding
			for _, t := range s.Targets {
				if t.Values == 0 {
					out = append(out, Finding{Outcome: Warn, Message: "redact target " + t.Target + " holds 0 values: it protects nothing",
						Fix: "check the target's name, glob and the store's prefix or allow list in stores." + s.Name + ".redact"})
				}
			}
			if len(out) > 0 {
				return out
			}
			if s.Degraded {
				return []Finding{{Outcome: Warn, Message: orDefault(s.Reason, "store values are stale"),
					Fix: "check the store's reachability; values are refreshed on the next successful poll"}}
			}
			return nil
		}})
	}
	for _, a := range r.Audit {
		checks = append(checks, Check{Name: "audit:" + a.Name, Run: func(context.Context) []Finding {
			if !a.Degraded {
				return nil
			}
			o := Warn
			if a.Policy == "block" {
				o = Fail
			}
			return []Finding{{Outcome: o, Message: orDefault(a.Detail, "audit sink is degraded") +
				fmt.Sprintf(" (%d dropped)", a.Dropped), Fix: "check the sink's endpoint in audit.sinks"}}
		}})
	}
	if e := r.EBPF; e != nil {
		checks = append(checks, Check{Name: "ebpf", Run: func(context.Context) []Finding { return ebpfFindings(e) }})
	}
	for _, m := range r.AgentModes {
		checks = append(checks, Check{Name: "agent-mode:" + m.Mode, Run: func(context.Context) []Finding {
			var fs []Finding
			for _, c := range m.Changed {
				fs = append(fs, Finding{Outcome: Fail, Message: c + " was changed or removed since scrim installed it",
					Fix: "scrim install --" + m.Mode + " to write it again, or scrim uninstall --" + m.Mode})
			}
			if len(fs) > 0 {
				return fs
			}
			if m.Mode == AgentModeHooks && r.Coverage == CoveragePartial {
				return []Finding{{Outcome: Warn,
					Message: "agent hooks are the only interception: partial protection; not covered: " + strings.Join(m.NotCovered, "; "),
					Fix:     "run the agent with scrim run, or point it at the forward proxy, for full coverage"}}
			}
			return []Finding{{Outcome: Pass, Message: m.Mode + " in force for " + strings.Join(m.Agents, ", ")}}
		}})
	}
	if len(r.Weakened) > 0 {
		checks = append(checks, Check{Name: "weakened-settings", Run: func(context.Context) []Finding {
			var fs []Finding
			for _, wk := range r.Weakened {
				fs = append(fs, Finding{Outcome: Warn, Message: wk.Key + " is set (" + wk.Source + "): " + wk.Description,
					Fix: "unset " + wk.Key + " unless you accept the weaker protection"})
			}
			return fs
		}})
	}
	return checks
}

// ebpfFindings checks the eBPF mode: every covered control group attached
// and confirmed, and something listening where the programs redirect to.
func ebpfFindings(e *EBPF) []Finding {
	if e.Problem != "" {
		return []Finding{{Outcome: Fail, Message: e.Problem,
			Fix: "use a Linux host with the unified cgroup v2 hierarchy, or the nftables transparent mode"}}
	}
	var fs []Finding
	for _, c := range e.Cgroups {
		switch c.State {
		case "active":
		case "unverified":
			fs = append(fs, Finding{Outcome: Warn, Message: c.Cgroup + ": " + c.Detail,
				Fix: "run `sudo scrim doctor` to confirm the attachment with the kernel"})
		case "stale":
			fs = append(fs, Finding{Outcome: Warn, Message: c.Cgroup + ": " + c.Detail, Fix: "run `" + c.Fix + "`"})
		default:
			fix := "run `sudo scrim ebpf attach`"
			if c.Fix != "" {
				fix = "run `" + c.Fix + "`"
			}
			if !slices.Contains(e.Configured, c.Cgroup) {
				fix += ", or `sudo scrim ebpf detach --cgroup " + c.Cgroup + "` if it is no longer wanted"
			}
			fs = append(fs, Finding{Outcome: Fail, Message: c.Cgroup + ": " + c.Detail, Fix: fix})
		}
	}
	if len(e.Cgroups) > 0 && !e.ListenerUp {
		fs = append(fs, Finding{Outcome: Fail, Message: e.Listener,
			Fix: fmt.Sprintf("start scrim with proxy.transparent-listen on port %d, or set interception.ebpf.port to its port and attach again", e.Port)})
	}
	return fs
}

// StateLocationCheck checks a SQLite state path: its directory exists or
// can be created, is not readable by others, and the file, if present, is
// mode 0600 or stricter.
func StateLocationCheck(path string) Check {
	return Check{Name: "state-location", Run: func(context.Context) []Finding {
		dir := filepath.Dir(path)
		st, err := os.Stat(dir)
		if os.IsNotExist(err) {
			return []Finding{{Outcome: Warn, Message: dir + " does not exist yet",
				Fix: "it is created on first start; or run: mkdir -p -m 0700 " + dir}}
		}
		if err != nil {
			return []Finding{{Outcome: Fail, Message: "cannot stat " + dir + ": " + err.Error()}}
		}
		var fs []Finding
		if !st.IsDir() {
			return []Finding{{Outcome: Fail, Message: dir + " is not a directory"}}
		}
		fixDir, fixFile := "chmod 0700 "+dir, "chmod 0600 "+path
		if runtime.GOOS == "windows" {
			fixDir, fixFile = fsperm.FixHint(dir, true), fsperm.FixHint(path, false)
		}
		if loose, detail, _ := fsperm.Loose(dir, st); loose {
			fs = append(fs, Finding{Outcome: Fail,
				Message: fmt.Sprintf("%s is %s, readable by other users", dir, detail),
				Fix:     fixDir})
		}
		if fst, err := os.Stat(path); err == nil {
			if loose, detail, _ := fsperm.Loose(path, fst); loose {
				fs = append(fs, Finding{Outcome: Fail,
					Message: fmt.Sprintf("%s is %s, readable by other users", path, detail),
					Fix:     fixFile})
			}
		}
		return fs
	}}
}
