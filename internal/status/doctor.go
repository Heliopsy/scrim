// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
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
	for _, s := range r.Stores {
		checks = append(checks, Check{Name: "store:" + s.Name, Run: func(context.Context) []Finding {
			switch {
			case !s.Reachable:
				return []Finding{{Outcome: Fail, Message: orDefault(s.Reason, "store is unreachable"),
					Fix: "check the store's address and credentials in the stores." + s.Name + " settings"}}
			case s.Degraded:
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
		if st.Mode().Perm()&0o077 != 0 {
			fs = append(fs, Finding{Outcome: Fail,
				Message: fmt.Sprintf("%s is mode %04o, readable by other users", dir, st.Mode().Perm()),
				Fix:     "chmod 0700 " + dir})
		}
		if fst, err := os.Stat(path); err == nil && fst.Mode().Perm()&0o077 != 0 {
			fs = append(fs, Finding{Outcome: Fail,
				Message: fmt.Sprintf("%s is mode %04o, readable by other users", path, fst.Mode().Perm()),
				Fix:     "chmod 0600 " + path})
		}
		return fs
	}}
}
