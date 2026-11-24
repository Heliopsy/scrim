// Command perfgate compares the latency gate's results with a baseline: the
// results the previous release published (scripts/release/results.sh
// regression), or any other run of the gate.
//
//	go run ./scripts/perfgate -current NEW.json -baseline OLD.json \
//	    -config dataplane/crates/scrim-llm/benches/budget.json [-report OUT.md]
//
// Both files are written by the latency gate (`SCRIM_PERF_JSON`,
// dataplane/crates/scrim-llm/benches/latency_gate.rs). Every gated
// measurement in the current run is compared with the measurement of the same
// id in the baseline, for each statistic both runs recorded rounds of (p50 and
// p99 of a latency, MB/s of a throughput). The value compared is the median of
// the rounds. A statistic regresses when it is worse than the baseline by more
// than the allowed change and by more than the unit's floor:
//
//	allowed = threshold + noise_factor * spread
//
// where spread is the larger relative median absolute deviation of the two
// runs' rounds: the noisier either run was, the more change it takes to call a
// regression. A run that dropped no sample and agreed with itself is held to
// the bare threshold.
//
// Runs are compared only on the same reference conditions: the fields named
// by the config's "match" list (runner class, CPU model, CPU count,
// architecture) must agree. When they do not, nothing is compared, the report
// says why, and the exit status is 0 unless -require-comparable is set.
//
// Exit status: 0 when nothing regressed (or nothing was comparable), 1 on a
// regression, 2 on a usage or input error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strings"
)

// Results is the part of the latency gate's JSON this tool reads.
type Results struct {
	Schema       int            `json:"schema"`
	Version      string         `json:"version"`
	Runner       string         `json:"runner"`
	Machine      map[string]any `json:"machine"`
	Method       map[string]any `json:"method"`
	Measurements []Measurement  `json:"measurements"`
}

// Measurement is one measurement of the gate.
type Measurement struct {
	ID     string               `json:"id"`
	Unit   string               `json:"unit"`
	Better string               `json:"better"`
	Gated  bool                 `json:"gated"`
	Rounds map[string][]float64 `json:"rounds"`
}

// Config is the "regression" object of the budget file.
type Config struct {
	Threshold   float64            `json:"threshold"`
	NoiseFactor float64            `json:"noise_factor"`
	MaxAllowed  float64            `json:"max_allowed"`
	Floor       map[string]float64 `json:"floor"`
	Calibrate   bool               `json:"calibrate"`
	Stats       []string           `json:"stats"`
	Match       []string           `json:"match"`
}

// Verdict of one comparison.
type Verdict string

// Verdicts.
const (
	Same       Verdict = "same"
	Regressed  Verdict = "REGRESSED"
	Improved   Verdict = "improved"
	NoBaseline Verdict = "new"
)

// Row is one compared statistic.
type Row struct {
	ID, Stat, Unit string
	Base, Cur      float64
	Change         float64 // relative, positive is worse
	Allowed        float64 // relative
	Calibrated     bool    // Change is relative to the calibration workload
	Verdict        Verdict
}

// Comparison is the outcome of comparing two runs.
type Comparison struct {
	Comparable bool
	Reason     string // why the runs are not comparable
	Rows       []Row
}

// Regressions returns the rows that regressed.
func (c Comparison) Regressions() []Row {
	var out []Row
	for _, r := range c.Rows {
		if r.Verdict == Regressed {
			out = append(out, r)
		}
	}
	return out
}

func median(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	n := len(s)
	if n == 0 {
		return math.NaN()
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// spread is the median absolute deviation of v relative to its median.
func spread(v []float64) float64 {
	m := median(v)
	if len(v) < 2 || m == 0 || math.IsNaN(m) {
		return 0
	}
	d := make([]float64, len(v))
	for i, x := range v {
		d[i] = math.Abs(x - m)
	}
	return median(d) / math.Abs(m)
}

// field returns the value of a dotted path ("runner", "machine.cpu") of r.
func field(r Results, path string) string {
	switch {
	case path == "runner":
		return r.Runner
	case strings.HasPrefix(path, "machine."):
		return fmt.Sprint(r.Machine[strings.TrimPrefix(path, "machine.")])
	case strings.HasPrefix(path, "method."):
		return fmt.Sprint(r.Method[strings.TrimPrefix(path, "method.")])
	}
	return ""
}

// Compare compares cur with base under cfg.
func Compare(cur, base Results, cfg Config) Comparison {
	for _, f := range cfg.Match {
		if a, b := field(cur, f), field(base, f); a != b {
			return Comparison{Reason: fmt.Sprintf("%s differs: %q here, %q in the baseline", f, a, b)}
		}
	}
	byID := make(map[string]Measurement, len(base.Measurements))
	for _, m := range base.Measurements {
		byID[m.ID] = m
	}
	c := Comparison{Comparable: true}
	for _, m := range cur.Measurements {
		if !m.Gated {
			continue
		}
		b, ok := byID[m.ID]
		for _, stat := range cfg.Stats {
			cr := m.Rounds[stat]
			if len(cr) == 0 {
				continue
			}
			row := Row{ID: m.ID, Stat: stat, Unit: m.Unit, Cur: median(cr), Base: math.NaN()}
			br := b.Rounds[stat]
			if !ok || len(br) == 0 || b.Unit != m.Unit {
				row.Verdict = NoBaseline
				c.Rows = append(c.Rows, row)
				continue
			}
			row.Base = median(br)
			// With calibration, each round is compared relative to how long the
			// fixed workload took before it: a run on a slower clock is slower
			// everywhere, and that is not a regression.
			nb, nc := br, cr
			if cfg.Calibrate {
				xb := calibrated(br, b.Rounds["cal"], m.Better)
				xc := calibrated(cr, m.Rounds["cal"], m.Better)
				if xb != nil && xc != nil {
					nb, nc, row.Calibrated = xb, xc, true
				}
			}
			row.Allowed = cfg.Threshold + cfg.NoiseFactor*math.Max(spread(nb), spread(nc))
			if cfg.MaxAllowed > 0 {
				row.Allowed = math.Min(row.Allowed, cfg.MaxAllowed)
			}
			// worse is how much worse the current run is, in the unit; change
			// is that relative to the baseline.
			worse := row.Cur - row.Base
			if m.Better == "higher" {
				worse = -worse
			}
			if mb, mc := median(nb), median(nc); mb != 0 {
				if m.Better == "higher" {
					row.Change = (mb - mc) / math.Abs(mb)
				} else {
					row.Change = (mc - mb) / math.Abs(mb)
				}
			}
			switch {
			case row.Change > row.Allowed && worse > cfg.Floor[m.Unit]:
				row.Verdict = Regressed
			case -row.Change > row.Allowed && -worse > cfg.Floor[m.Unit]:
				row.Verdict = Improved
			default:
				row.Verdict = Same
			}
			c.Rows = append(c.Rows, row)
		}
	}
	return c
}

// calibrated returns each round's value relative to its calibration time
// (divided for a latency, multiplied for a throughput), or nil when the
// rounds carry no calibration.
func calibrated(v, cal []float64, better string) []float64 {
	if len(cal) != len(v) || len(v) == 0 {
		return nil
	}
	out := make([]float64, len(v))
	for i, x := range v {
		if cal[i] <= 0 {
			return nil
		}
		if better == "higher" {
			out[i] = x * cal[i]
		} else {
			out[i] = x / cal[i]
		}
	}
	return out
}

func num(x float64) string {
	if math.IsNaN(x) {
		return "-"
	}
	return fmt.Sprintf("%.3f", x)
}

// Markdown writes the comparison as a Markdown section.
func Markdown(w io.Writer, cur, base Results, cfg Config, c Comparison) {
	printf := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	printf("# Latency regression check\n\n")
	printf("This run (%s, runner %s) against the baseline (%s, runner %s). ", cur.Version, cur.Runner, base.Version, base.Runner)
	printf("Each value is the median of the run's rounds. A statistic regresses when it is worse by more than "+
		"%.0f %% plus %.1f times the larger relative spread (median absolute deviation) of the two runs' rounds", cfg.Threshold*100, cfg.NoiseFactor)
	if cfg.MaxAllowed > 0 {
		printf(", at most %.0f %%", cfg.MaxAllowed*100)
	}
	printf(", and by more than the unit's floor.")
	if cfg.Calibrate {
		printf(" Where both runs timed the calibration workload before each round, the change is computed " +
			"on each round's value relative to it (marked *), so a machine running at a different clock " +
			"speed does not count as a regression; the values shown are the raw medians.")
	}
	printf("\n\n")
	if !c.Comparable {
		printf("Not compared: %s. Results are compared only on the same reference conditions.\n", c.Reason)
		return
	}
	printf("| measurement | stat | baseline | this run | change | allowed | verdict |\n|---|---|---|---|---|---|---|\n")
	for _, r := range c.Rows {
		change, allowed := "-", "-"
		if r.Verdict != NoBaseline {
			change = fmt.Sprintf("%+.1f %%", r.Change*100)
			if r.Calibrated {
				change += "*"
			}
			allowed = fmt.Sprintf("%.1f %%", r.Allowed*100)
		}
		printf("| `%s` | %s | %s %s | %s %s | %s | %s | %s |\n",
			r.ID, r.Stat, num(r.Base), r.Unit, num(r.Cur), r.Unit, change, allowed, r.Verdict)
	}
	reg := c.Regressions()
	printf("\n")
	if len(reg) == 0 {
		printf("No regression.\n")
		return
	}
	for _, r := range reg {
		printf("REGRESSION: %s %s %s %s -> %s %s (%+.1f %%, allowed %.1f %%)\n",
			r.ID, r.Stat, num(r.Base), r.Unit, num(r.Cur), r.Unit, r.Change*100, r.Allowed*100)
	}
}

func load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func loadResults(path string) (Results, error) {
	var r Results
	if err := load(path, &r); err != nil {
		return r, err
	}
	if r.Schema != 1 {
		return r, fmt.Errorf("%s: unsupported schema %d", path, r.Schema)
	}
	return r, nil
}

func loadConfig(path string) (Config, error) {
	var doc struct {
		Regression *Config `json:"regression"`
	}
	if err := load(path, &doc); err != nil {
		return Config{}, err
	}
	if doc.Regression == nil {
		return Config{}, fmt.Errorf("%s: no \"regression\" object", path)
	}
	c := *doc.Regression
	if c.Threshold <= 0 || len(c.Stats) == 0 {
		return c, fmt.Errorf("%s: regression needs a positive threshold and a list of stats", path)
	}
	return c, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("perfgate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	current := fs.String("current", "", "results of this run (latency gate JSON)")
	baseline := fs.String("baseline", "", "results to compare with (latency gate JSON)")
	config := fs.String("config", "", "budget file with the \"regression\" object")
	report := fs.String("report", "", "also write the Markdown report to this file")
	strict := fs.Bool("require-comparable", false, "fail when the runs' reference conditions differ")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *current == "" || *baseline == "" || *config == "" {
		_, _ = fmt.Fprintln(stderr, "perfgate: -current, -baseline and -config are required")
		return 2
	}
	cfg, err := loadConfig(*config)
	if err == nil {
		var cur, base Results
		if cur, err = loadResults(*current); err == nil {
			if base, err = loadResults(*baseline); err == nil {
				return finish(cur, base, cfg, *report, *strict, stdout, stderr)
			}
		}
	}
	_, _ = fmt.Fprintln(stderr, "perfgate:", err)
	return 2
}

func finish(cur, base Results, cfg Config, report string, strict bool, stdout, stderr io.Writer) int {
	c := Compare(cur, base, cfg)
	var sb strings.Builder
	Markdown(&sb, cur, base, cfg, c)
	_, _ = fmt.Fprint(stdout, sb.String())
	if report != "" {
		if err := os.WriteFile(report, []byte(sb.String()), 0o644); err != nil {
			_, _ = fmt.Fprintln(stderr, "perfgate:", err)
			return 2
		}
	}
	switch {
	case !c.Comparable && strict:
		_, _ = fmt.Fprintln(stderr, "perfgate: not comparable:", c.Reason)
		return 1
	case len(c.Regressions()) > 0:
		for _, r := range c.Regressions() {
			_, _ = fmt.Fprintf(stderr, "perfgate: %s %s regressed %+.1f %% (allowed %.1f %%)\n", r.ID, r.Stat, r.Change*100, r.Allowed*100)
		}
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
