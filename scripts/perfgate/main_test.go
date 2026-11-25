package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var cfg = Config{
	Threshold:   0.10,
	NoiseFactor: 3,
	MaxAllowed:  0.5,
	Floor:       map[string]float64{"ms": 0.05, "us": 0.5, "MB/s": 5},
	Stats:       []string{"p50", "p99", "mbps"},
	Match:       []string{"runner", "machine.cpu", "machine.logical_cpus"},
}

func results(ms ...Measurement) Results {
	return Results{
		Schema:       1,
		Version:      "1.1.0",
		Runner:       "ho-z10",
		Machine:      map[string]any{"cpu": "Example CPU", "logical_cpus": 3.0},
		Measurements: ms,
	}
}

func latency(id string, p50, p99 []float64) Measurement {
	return Measurement{ID: id, Unit: "ms", Better: "lower", Gated: true,
		Rounds: map[string][]float64{"p50": p50, "p99": p99}}
}

func verdicts(c Comparison) map[string]Verdict {
	out := map[string]Verdict{}
	for _, r := range c.Rows {
		out[r.ID+" "+r.Stat] = r.Verdict
	}
	return out
}

func TestRegressionBeyondThreshold(t *testing.T) {
	base := results(latency("request/1000/1MB/hits", []float64{20, 20, 20, 20, 20}, []float64{25, 25, 25, 25, 25}))
	cur := results(latency("request/1000/1MB/hits", []float64{23, 23, 23, 23, 23}, []float64{26, 26, 26, 26, 26}))
	c := Compare(cur, base, cfg)
	v := verdicts(c)
	if v["request/1000/1MB/hits p50"] != Regressed {
		t.Errorf("p50 +15%% with no spread: got %s, want regressed", v["request/1000/1MB/hits p50"])
	}
	if v["request/1000/1MB/hits p99"] != Same {
		t.Errorf("p99 +4%%: got %s, want same", v["request/1000/1MB/hits p99"])
	}
	if len(c.Regressions()) != 1 {
		t.Errorf("regressions: %+v", c.Regressions())
	}
}

func TestNoiseWidensTheThreshold(t *testing.T) {
	// The same +15 % median, but the baseline's rounds spread by about 10 %: the
	// allowed change becomes 10 % + 3 * 10 %, and the shift is noise.
	base := results(latency("x", []float64{18, 20, 22, 20, 24}, []float64{30, 30, 30, 30, 30}))
	cur := results(latency("x", []float64{23, 23, 23, 23, 23}, []float64{30, 30, 30, 30, 30}))
	c := Compare(cur, base, cfg)
	if v := verdicts(c)["x p50"]; v != Same {
		t.Fatalf("got %s, want same: %+v", v, c.Rows)
	}
	// Noise never allows more than max_allowed.
	cur = results(latency("x", []float64{40, 40, 40, 40, 40}, []float64{30, 30, 30, 30, 30}))
	if v := verdicts(Compare(cur, base, cfg))["x p50"]; v != Regressed {
		t.Fatalf("a doubling within noise: got %s, want regressed", v)
	}
}

func TestOneSlowRoundIsNotARegression(t *testing.T) {
	base := results(latency("x", []float64{1, 1, 1, 1, 1}, []float64{2, 2, 2, 2, 2}))
	cur := results(latency("x", []float64{1, 1, 1, 1, 1}, []float64{2, 2, 2, 2, 9}))
	if r := Compare(cur, base, cfg).Regressions(); len(r) != 0 {
		t.Fatalf("one disturbed round out of five: %+v", r)
	}
}

func TestFloorIgnoresTinyAbsoluteChanges(t *testing.T) {
	base := results(latency("x", []float64{0.1, 0.1, 0.1}, []float64{0.12, 0.12, 0.12}))
	cur := results(latency("x", []float64{0.14, 0.14, 0.14}, []float64{0.15, 0.15, 0.15}))
	if r := Compare(cur, base, cfg).Regressions(); len(r) != 0 {
		t.Fatalf("+40 µs is under the 50 µs floor: %+v", r)
	}
}

func TestThroughputLowerIsWorse(t *testing.T) {
	m := func(v float64) Measurement {
		return Measurement{ID: "tp", Unit: "MB/s", Better: "higher", Gated: true,
			Rounds: map[string][]float64{"mbps": {v, v, v}}}
	}
	if v := verdicts(Compare(results(m(800)), results(m(1000)), cfg))["tp mbps"]; v != Regressed {
		t.Errorf("throughput -20%%: got %s", v)
	}
	if v := verdicts(Compare(results(m(1200)), results(m(1000)), cfg))["tp mbps"]; v != Improved {
		t.Errorf("throughput +20%%: got %s", v)
	}
}

func TestUngatedAndNewMeasurements(t *testing.T) {
	ungated := latency("ungated", []float64{1}, []float64{1})
	ungated.Gated = false
	slow := latency("ungated", []float64{9}, []float64{9})
	slow.Gated = false
	base := results(ungated)
	cur := results(slow, latency("added", []float64{1}, []float64{1}))
	c := Compare(cur, base, cfg)
	v := verdicts(c)
	if _, ok := v["ungated p50"]; ok {
		t.Error("an ungated measurement was compared")
	}
	if v["added p50"] != NoBaseline {
		t.Errorf("a measurement the baseline lacks: got %s", v["added p50"])
	}
	if len(c.Regressions()) != 0 {
		t.Errorf("regressions: %+v", c.Regressions())
	}
}

func TestDifferentMachinesAreNotCompared(t *testing.T) {
	base := results(latency("x", []float64{1}, []float64{1}))
	cur := results(latency("x", []float64{9}, []float64{9}))
	cur.Machine["cpu"] = "Other CPU"
	c := Compare(cur, base, cfg)
	if c.Comparable || !strings.Contains(c.Reason, "machine.cpu") {
		t.Fatalf("got %+v", c)
	}
	cur.Machine["cpu"] = "Example CPU"
	cur.Runner = "ubuntu-24.04"
	if c := Compare(cur, base, cfg); c.Comparable {
		t.Fatal("different runner classes were compared")
	}
}

func write(t *testing.T, dir, name string, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunExitStatus(t *testing.T) {
	dir := t.TempDir()
	conf := write(t, dir, "budget.json", map[string]any{"regression": cfg})
	base := write(t, dir, "base.json", results(latency("request/1000/1MB/hits", []float64{20, 20, 20}, []float64{25, 25, 25})))
	same := write(t, dir, "same.json", results(latency("request/1000/1MB/hits", []float64{20.5, 20, 19.5}, []float64{25, 26, 25})))
	slow := write(t, dir, "slow.json", results(latency("request/1000/1MB/hits", []float64{30, 30, 30}, []float64{36, 36, 36})))
	other := results(latency("request/1000/1MB/hits", []float64{30, 30, 30}, []float64{36, 36, 36}))
	other.Runner = "local"
	elsewhere := write(t, dir, "elsewhere.json", other)
	off := false
	reportOnly := cfg
	reportOnly.Enforce = &off
	confReport := write(t, dir, "budget-report-only.json", map[string]any{"regression": reportOnly})
	report := filepath.Join(dir, "report.md")

	cases := []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"no regression", []string{"-current", same, "-baseline", base, "-config", conf}, 0, "No regression."},
		{"regression", []string{"-current", slow, "-baseline", base, "-config", conf, "-report", report}, 1, "REGRESSION: request/1000/1MB/hits p50"},
		{"regression, report only", []string{"-current", slow, "-baseline", base, "-config", confReport}, 0, "Report only: regression.enforce is false"},
		{"other runner", []string{"-current", elsewhere, "-baseline", base, "-config", conf}, 0, "Not compared: runner differs"},
		{"other runner, strict", []string{"-current", elsewhere, "-baseline", base, "-config", conf, "-require-comparable"}, 1, "Not compared"},
		{"missing flag", []string{"-current", same}, 2, ""},
		{"no regression config", []string{"-current", same, "-baseline", base, "-config", base}, 2, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := run(tc.args, &out, &errb); code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tc.code, out.String(), errb.String())
			}
			if !strings.Contains(out.String(), tc.out) {
				t.Fatalf("stdout lacks %q:\n%s", tc.out, out.String())
			}
		})
	}
	b, err := os.ReadFile(report)
	if err != nil || !strings.Contains(string(b), "REGRESSED") {
		t.Fatalf("report: %v\n%s", err, b)
	}
}

func TestCalibrationAbsorbsAClockChange(t *testing.T) {
	with := func(p50, cal float64) Measurement {
		m := latency("x", []float64{p50, p50, p50}, []float64{p50 * 1.5, p50 * 1.5, p50 * 1.5})
		m.Rounds["cal"] = []float64{cal, cal, cal}
		return m
	}
	c := cfg
	c.Calibrate = true
	base := results(with(20, 500))
	// The whole machine ran 1.6 times slower: the workload took 1.6 times as long too.
	slowClock := results(with(32, 800))
	if r := Compare(slowClock, base, c).Regressions(); len(r) != 0 {
		t.Fatalf("a slower clock counted as a regression: %+v", r)
	}
	if r := Compare(slowClock, base, cfg).Regressions(); len(r) == 0 {
		t.Fatal("without calibration the same runs should regress")
	}
	// Same clock, slower code.
	if r := Compare(results(with(32, 500)), base, c).Regressions(); len(r) != 2 {
		t.Fatalf("a real slowdown at the same clock: %+v", r)
	}
	// A baseline without calibration falls back to the raw values.
	raw := results(latency("x", []float64{20, 20, 20}, []float64{30, 30, 30}))
	rows := Compare(slowClock, raw, c).Rows
	if rows[0].Calibrated || rows[0].Verdict != Regressed {
		t.Fatalf("fallback: %+v", rows[0])
	}
}

func TestCalibratedThroughput(t *testing.T) {
	m := func(v, cal float64) Measurement {
		return Measurement{ID: "tp", Unit: "MB/s", Better: "higher", Gated: true,
			Rounds: map[string][]float64{"mbps": {v, v, v}, "cal": {cal, cal, cal}}}
	}
	c := cfg
	c.Calibrate = true
	if r := Compare(results(m(800, 1000)), results(m(1600, 500)), c).Regressions(); len(r) != 0 {
		t.Fatalf("half the throughput at half the clock: %+v", r)
	}
	if r := Compare(results(m(800, 500)), results(m(1600, 500)), c).Regressions(); len(r) != 1 {
		t.Fatalf("half the throughput at the same clock: %+v", r)
	}
}
