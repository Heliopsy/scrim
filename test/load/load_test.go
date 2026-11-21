// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/base64"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestScannerFindsEveryForm(t *testing.T) {
	values := [][]byte{seedValue(), seedValue(), []byte("with space/and+plus-chars-0123")}
	s := newScanner(values, len(values))
	for i, v := range values {
		for _, f := range leakForms(v) {
			buf := []byte("prefix " + string(f) + " suffix")
			if got := s.find(buf); !slices.Equal(got, []int{i}) {
				t.Errorf("value %d form %q: found %v", i, f, got)
			}
		}
	}
	// A value at the very start and end of the buffer, twice: reported once.
	both := append(append([]byte{}, values[0]...), values[0]...)
	if got := s.find(both); !slices.Equal(got, []int{0}) {
		t.Errorf("repeated value: %v", got)
	}
	// One byte changed, or the value cut short: no hit.
	near := append([]byte{}, values[1]...)
	near[len(near)/2] ^= 1
	if got := s.find(append(near, values[1][:20]...)); len(got) != 0 {
		t.Errorf("near miss reported as %v", got)
	}
	// A partially redacted base64 run (what the redactor leaves around a
	// placeholder) no longer contains the full encoded form.
	enc := base64.StdEncoding.EncodeToString(values[0])
	if got := s.find([]byte(enc[:3] + "⟦scrim:x:y⟧" + enc[len(enc)-2:])); len(got) != 0 {
		t.Errorf("redacted base64 reported as %v", got)
	}
}

func TestSummarizeNearestRank(t *testing.T) {
	var v []float64
	for i := 1; i <= 1000; i++ {
		v = append(v, float64(i))
	}
	s := summarize(v)
	if s.Count != 1000 || s.P50 != 500 || s.P95 != 950 || s.P99 != 990 || s.Max != 1000 || s.Mean != 500.5 {
		t.Fatalf("%+v", s)
	}
	if (summarize(nil) != Summary{}) {
		t.Fatal("empty summary")
	}
	var r recorder
	r.add(1500 * time.Microsecond)
	if got := r.summary(); got.P99 != 1.5 {
		t.Fatalf("recorder: %+v", got)
	}
}

const page = `# HELP scrim_dataplane_restore_chunk_seconds Latency.
# TYPE scrim_dataplane_restore_chunk_seconds histogram
scrim_dataplane_restore_chunk_seconds_bucket{route="anthropic",provider="anthropic",le="1e-05"} 50
scrim_dataplane_restore_chunk_seconds_bucket{route="anthropic",provider="anthropic",le="5e-05"} 99
scrim_dataplane_restore_chunk_seconds_bucket{route="anthropic",provider="anthropic",le="0.0001"} 100
scrim_dataplane_restore_chunk_seconds_bucket{route="anthropic",provider="anthropic",le="+Inf"} 100
scrim_dataplane_restore_chunk_seconds_sum{route="anthropic",provider="anthropic"} 0.002
scrim_dataplane_restore_chunk_seconds_count{route="anthropic",provider="anthropic"} 100
scrim_dataplane_request_added_seconds_bucket{route="a",provider="p",stage="total",le="0.005"} 10
scrim_dataplane_request_added_seconds_bucket{route="a",provider="p",stage="total",le="+Inf"} 10
scrim_dataplane_request_added_seconds_count{route="a",provider="p",stage="total"} 10
scrim_dataplane_request_added_seconds_bucket{route="a",provider="p",stage="guard",le="0.005"} 3
scrim_dataplane_request_added_seconds_bucket{route="a",provider="p",stage="guard",le="+Inf"} 7
scrim_dataplane_request_added_seconds_count{route="a",provider="p",stage="guard"} 7
scrim_events_last_id 42
scrim_label_escape{v="a\"b,c"} 1
`

func TestPromHistogramAndGauge(t *testing.T) {
	s := parseProm(page)
	h := histogramOf(s, "scrim_dataplane_restore_chunk_seconds", nil)
	if !slices.Equal(h.Bounds, []float64{1e-05, 5e-05, 0.0001}) || h.Count != 100 {
		t.Fatalf("%+v", h)
	}
	if f := h.FractionWithin(0.00005); f != 0.99 {
		t.Fatalf("fraction within 50µs = %v", f)
	}
	if f := h.FractionWithin(0.00004); f != -1 {
		t.Fatalf("fraction for a bound that is not a bucket = %v", f)
	}
	if q := h.Quantile(0.5); math.Abs(q-1e-05) > 1e-12 {
		t.Fatalf("p50 = %v", q)
	}
	if q := h.Quantile(0.995); q <= 5e-05 || q > 0.0001 {
		t.Fatalf("p99.5 = %v", q)
	}
	total := histogramOf(s, "scrim_dataplane_request_added_seconds", map[string]string{"stage": "total"})
	if total.Count != 10 || total.FractionWithin(0.005) != 1 {
		t.Fatalf("stage filter: %+v", total)
	}
	if v, ok := gaugeOf(s, "scrim_events_last_id", nil); !ok || v != 42 {
		t.Fatalf("gauge %v %v", v, ok)
	}
	if _, ok := gaugeOf(s, "scrim_label_escape", map[string]string{"v": `a"b,c`}); !ok {
		t.Fatal("escaped label value not parsed")
	}
	// The window is the difference of two scrapes; replicas are summed.
	d := h.sub(Histogram{Bounds: h.Bounds, Counts: []float64{50, 50, 50}, Count: 50})
	if d.Count != 50 || d.Counts[0] != 0 || d.FractionWithin(0.00005) != 0.98 {
		t.Fatalf("sub: %+v", d)
	}
	sum := Histogram{}.add(d).add(d)
	if sum.Count != 100 || sum.Counts[2] != 100 {
		t.Fatalf("add: %+v", sum)
	}
}

func TestProfilesAreValid(t *testing.T) {
	for _, name := range []string{"smoke", "full"} {
		p, err := loadProfile("profiles.json", name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		th := p.Thresholds
		// Correctness limits are absolute.
		if th.MaxLeaks != 0 || th.MaxRestoreFailures != 0 || th.MaxInjectionFailures != 0 || th.MaxApprovalFailures != 0 {
			t.Errorf("%s: correctness limits must be zero: %+v", name, th)
		}
		// The performance spec's budgets are the ceiling.
		if th.ScrimRequestAddedP99Ms > 5 || th.ScrimChunkP99Us > 50 {
			t.Errorf("%s: thresholds looser than the performance spec: %+v", name, th)
		}
		for _, m := range []string{p.Run.ReplicaMemory, p.Run.DriverMemory, p.Run.PostgresMemory} {
			if _, err := parseMem(m); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
	full, _ := loadProfile("profiles.json", "full")
	if full.Run.Streams < 1000 || full.Run.Replicas < 3 {
		t.Errorf("the full profile must drive at least 1,000 streams through 3 replicas (tasks.md 14.3): %+v", full.Run)
	}
}

func passing() Result {
	h := Histogram{Bounds: []float64{0.005, 0.00005}, Counts: []float64{100, 100}, Count: 100}
	return Result{
		Drive: DriveResult{
			Streams:     StreamStats{Target: 10, Mean: 9, Max: 10},
			Throughput:  Throughput{LLMPerSecond: 100},
			Latency:     Latency{TotalAdded: Summary{Count: 1, P99: 1}},
			Correctness: Correctness{RestoreChecks: 10, Injections: 10},
			Approvals:   Approvals{Released: 5, Revoked: 3, ReleaseLag: Summary{Count: 5, P99: 10}},
			Scrim:       ScrimStats{RequestAdded: h, RequestWithin5ms: 1, RestoreChunk: h, RestoreChunkWithin50u: 1},
			Events:      EventStats{Agree: true, LastIDs: []float64{3, 3, 3}},
		},
		Resources: []Resources{{Role: "r0", LimitMiB: 1000, MemMaxMiB: 100}},
	}
}

func TestEvaluate(t *testing.T) {
	p, err := loadProfile("profiles.json", "smoke")
	if err != nil {
		t.Fatal(err)
	}
	checks, pass := evaluate(passing(), p.Thresholds)
	if !pass {
		t.Fatalf("a passing result failed: %+v", checks)
	}
	for name, breakIt := range map[string]func(*Result){
		"leaks":                     func(r *Result) { r.Drive.Correctness.Leaks = 1 },
		"restore failures":          func(r *Result) { r.Drive.Correctness.RestoreFailures = 1 },
		"injection failures":        func(r *Result) { r.Drive.Correctness.Injections = 0 },
		"approval failures":         func(r *Result) { r.Drive.Approvals.Released = 0 },
		"events agree":              func(r *Result) { r.Drive.Events.Agree = false },
		"error rate":                func(r *Result) { r.Drive.Errors.Rate = 0.5 },
		"concurrent streams":        func(r *Result) { r.Drive.Streams.Mean = 1 },
		"scrim restore chunk p99":   func(r *Result) { r.Drive.Scrim.RestoreChunkWithin50u = 0.98 },
		"scrim request added p99":   func(r *Result) { r.Drive.Scrim.RequestAdded.Count = 0 },
		"approval release p99":      func(r *Result) { r.Drive.Approvals.ReleaseLag.P99 = 60000 },
		"replica memory":            func(r *Result) { r.Resources[0].OOMKills = 1 },
		"client-observed added p99": func(r *Result) { r.Drive.Latency.TotalAdded.P99 = 1e6 },
		"throughput":                func(r *Result) { r.Drive.Throughput.LLMPerSecond = 0 },
		"memory per stream":         func(r *Result) { r.MemPerStreamKiB = 1e9 },
	} {
		r := passing()
		breakIt(&r)
		checks, pass := evaluate(r, p.Thresholds)
		if pass {
			t.Errorf("%s: broken result passed", name)
		}
		for _, c := range checks {
			if !c.Pass && c.Name != name {
				t.Errorf("breaking %s also failed %s", name, c.Name)
			}
		}
	}
	md := markdown(passing())
	if !strings.Contains(md, "| Check |") {
		t.Fatal("report has no checks table")
	}
}

func TestBuildBodyCarriesEveryInsert(t *testing.T) {
	rng := newRand(1)
	inserts := []string{"[[b1]] AAAA", "[[n2]] BBBB", "[[c3]] CCCC"}
	b := buildBody(rng, 4, inserts)
	if len(b) < 4*1024 {
		t.Fatalf("body of %d bytes", len(b))
	}
	for _, in := range inserts {
		if !strings.Contains(string(b), in) {
			t.Errorf("missing %q", in)
		}
	}
	got := markerRE.FindAllStringSubmatch(string(b), -1)
	if len(got) != 3 {
		t.Fatalf("markers: %v", got)
	}
}
