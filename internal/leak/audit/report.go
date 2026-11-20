// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/matrix"
	"github.com/heliopsy/scrim/internal/leak/scenario"
)

// Report is the JSON report of one run. It never contains a seed value:
// seeds appear as name, kind, length and a short SHA-256.
type Report struct {
	Version   int             `json:"version"`
	Started   time.Time       `json:"started"`
	Finished  time.Time       `json:"finished"`
	Proxy     string          `json:"proxy"`
	Upstream  string          `json:"upstream"`
	Driver    string          `json:"driver"`
	Checker   CheckerSettings `json:"checker"`
	Seeds     []leak.SeedRef  `json:"seeds"`
	Matrix    *MatrixReport   `json:"matrix,omitempty"`
	Scenarios *ScenarioReport `json:"scenarios,omitempty"`
	Summary   Summary         `json:"summary"`
	Pass      bool            `json:"pass"`
}

// CheckerSettings records the leak checker thresholds used.
type CheckerSettings struct {
	MinPartial      int     `json:"min_partial"`
	PartialFraction float64 `json:"partial_fraction"`
	MaxPartial      int     `json:"max_partial"`
}

// MatrixReport is the bypass matrix part.
type MatrixReport struct {
	Totals  matrix.Totals   `json:"totals"`
	Results []matrix.Result `json:"results"`
}

// ScenarioReport is the scenario part.
type ScenarioReport struct {
	Results []scenario.Result     `json:"results"`
	Cache   scenario.CacheSummary `json:"cache"`
}

// Summary is the headline of a run.
type Summary struct {
	GatedLeaks       int     `json:"gated_leaks"`
	LimitationLeaks  int     `json:"limitation_leaks"`
	UnexpectedRows   int     `json:"unexpected_outcomes"`
	ScenarioLeaks    int     `json:"scenario_leaks"`
	ScenarioFailures int     `json:"scenario_failures"`
	CacheHitRate     float64 `json:"cache_hit_rate"`
	Errors           int     `json:"errors"`
}

func (r *Report) finish() {
	s := &r.Summary
	if m := r.Matrix; m != nil {
		s.GatedLeaks += m.Totals.GatedLeaks
		s.LimitationLeaks = m.Totals.Limitations
		s.Errors += m.Totals.Errors
		s.UnexpectedRows = m.Totals.Failed - m.Totals.GatedLeaks
	}
	if sc := r.Scenarios; sc != nil {
		for _, res := range sc.Results {
			s.ScenarioLeaks += len(res.Findings)
			if !res.Pass {
				s.ScenarioFailures++
			}
			if res.Error != "" {
				s.Errors++
			}
		}
		s.CacheHitRate = sc.Cache.HitRate
	}
	r.Pass = s.GatedLeaks == 0 && s.UnexpectedRows == 0 && s.ScenarioFailures == 0 && s.Errors == 0
}

// WriteJSON writes the report to path with mode 0600, or to w when path is
// "-".
func (r *Report) WriteJSON(path string, w io.Writer) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if path == "-" {
		_, err = w.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// WriteText writes a human summary: totals, then every failure with the
// request, location and encoding of each finding.
func (r *Report) WriteText(w io.Writer) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	p("scrim leak audit: proxy %s, %d seeds, checker min_partial=%d fraction=%.2f max_partial=%d",
		r.Proxy, len(r.Seeds), r.Checker.MinPartial, r.Checker.PartialFraction, r.Checker.MaxPartial)
	if m := r.Matrix; m != nil {
		t := m.Totals
		p("")
		p("bypass matrix: %d rows, %d cases: %d passed, %d failed (%d gated leaks), %d limitation leaks, %d errors",
			t.Rows, t.Cases, t.Passed, t.Failed, t.GatedLeaks, t.Limitations, t.Errors)
		outcomes := make([]string, 0, len(t.ByOutcome))
		for o, n := range t.ByOutcome {
			outcomes = append(outcomes, fmt.Sprintf("%s=%d", o, n))
		}
		sort.Strings(outcomes)
		p("  outcomes: %v", outcomes)
		// Group failures by row so a broken transform reads as one line per
		// row with the seeds it failed for.
		type agg struct {
			first matrix.Result
			seeds []string
		}
		var order []string
		byRow := map[string]*agg{}
		for _, res := range m.Results {
			if res.Pass {
				continue
			}
			a := byRow[res.Row]
			if a == nil {
				a = &agg{first: res}
				byRow[res.Row] = a
				order = append(order, res.Row)
			}
			a.seeds = append(a.seeds, string(res.Seed.Kind))
		}
		for _, row := range order {
			a := byRow[row]
			p("  FAIL %s expect=%s got=%s seeds=%v", row, a.first.Expect, a.first.Outcome, a.seeds)
			if a.first.Error != "" {
				p("       %s", a.first.Error)
			}
			for i, f := range a.first.Findings {
				if i == 3 {
					p("       ... %d more", len(a.first.Findings)-3)
					break
				}
				enc := ""
				if len(f.Encodings) > 0 {
					enc = f.Encodings[0]
				}
				p("       request %d %s via %s (%s %d/%d, seed sha256 %s)", f.Request, f.Location, enc, f.Match, f.Matched, f.Of, f.Seed.SHA256)
			}
		}
	}
	if sc := r.Scenarios; sc != nil {
		p("")
		c := sc.Cache
		p("scenarios: %d sessions, cache hit rate %.1f%% (%d/%d turns), %d/%d deterministic on replay",
			c.Sessions, 100*c.HitRate, c.Hits, c.Turns, c.Deterministic, c.Sessions)
		for _, res := range sc.Results {
			status := "ok  "
			if !res.Pass {
				status = "FAIL"
			}
			p("  %s %-16s %-17s stream=%-5v requests=%d leaks=%d cache=%d/%d deterministic=%v restored=%d %s",
				status, res.Scenario, res.API, res.Stream, res.Requests, len(res.Findings), res.CacheHits, res.CacheTurns, res.Deterministic, res.Restored, res.Error)
			if !res.Pass {
				for i, f := range res.Findings {
					if i == 3 {
						p("       ... %d more", len(res.Findings)-3)
						break
					}
					p("       request %d %s: %s via %s (%s)", f.Request, f.Location, f.Seed.Name, f.Encodings[0], f.Match)
				}
			}
		}
	}
	p("")
	s := r.Summary
	verdict := "PASS"
	if !r.Pass {
		verdict = "FAIL"
	}
	p("%s: %d gated leaks, %d unexpected outcomes, %d scenario failures, %d errors (%d known-limitation leaks, not gated)",
		verdict, s.GatedLeaks, s.UnexpectedRows, s.ScenarioFailures, s.Errors, s.LimitationLeaks)
}
