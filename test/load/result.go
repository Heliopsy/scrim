// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"time"
)

// DriveResult is what the load generator measured (run/drive.json).
type DriveResult struct {
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Seconds     float64   `json:"seconds"`

	Throughput  Throughput          `json:"throughput"`
	Streams     StreamStats         `json:"streams"`
	Latency     Latency             `json:"latency_ms"`
	Errors      Errors              `json:"errors"`
	Correctness Correctness         `json:"correctness"`
	Approvals   Approvals           `json:"approvals"`
	Scrim       ScrimStats          `json:"scrim"`
	Events      EventStats          `json:"events"`
	Failures    map[string][]string `json:"failure_samples,omitempty"`
}

// Throughput over the measured window.
type Throughput struct {
	LLMRequests        int64   `json:"llm_requests"`
	LLMPerSecond       float64 `json:"llm_requests_per_second"`
	ToolRequests       int64   `json:"tool_requests"`
	ToolPerSecond      float64 `json:"tool_requests_per_second"`
	ChunksPerSecond    float64 `json:"stream_events_per_second"`
	RequestMBPerSecond float64 `json:"request_mb_per_second"`
}

// StreamStats is how many provider streams were open at once, sampled
// every 100 ms during the window.
type StreamStats struct {
	Target int     `json:"target"`
	Mean   float64 `json:"mean"`
	Max    float64 `json:"max"`
}

// Latency is measured by the load generator, which also runs the fake
// upstreams, so both ends share one clock. Added latency excludes the
// upstream's own time.
type Latency struct {
	RequestAdded Summary `json:"request_added"`
	FirstByte    Summary `json:"first_byte_added"`
	TotalAdded   Summary `json:"total_added"`
	ClientTotal  Summary `json:"client_total"`
	Tool         Summary `json:"tool_request"`
}

// Errors counted in the window.
type Errors struct {
	LLM       int64   `json:"llm"`
	Tool      int64   `json:"tool"`
	Approvals int64   `json:"approvals"`
	Total     int64   `json:"total"`
	Ops       int64   `json:"operations"`
	Rate      float64 `json:"rate"`
}

// Correctness counts over the whole run, warm-up included.
type Correctness struct {
	LeaksToProvider   int64 `json:"leaks_to_provider"`
	LeaksToToolAPI    int64 `json:"leaks_to_tool_api"`
	LeaksToAgent      int64 `json:"leaks_to_agent"`
	UnredactedMarkers int64 `json:"unredacted_markers"`
	Leaks             int64 `json:"leaks"`
	RestoreChecks     int64 `json:"restore_checks"`
	RestoreFailures   int64 `json:"restore_failures"`
	Injections        int64 `json:"injections"`
	InjectionFailures int64 `json:"injection_failures"`
	LogLeaks          int64 `json:"log_leaks"`
}

// Approvals: held on one replica, decided on another, revoked on a third.
type Approvals struct {
	Held           int64   `json:"held"`
	Released       int64   `json:"released_cross_replica"`
	Approved       int64   `json:"approved"`
	Denied         int64   `json:"denied"`
	Revoked        int64   `json:"grants_revoked"`
	NotHeld        int64   `json:"not_held"`
	Timeouts       int64   `json:"timeouts"`
	Late           int64   `json:"late"`
	RevokeFailures int64   `json:"revoke_failures"`
	Failures       int64   `json:"failures"`
	ReleaseLag     Summary `json:"release_lag_ms"`
}

// ScrimStats are scrim's own added-latency histograms, the difference
// between scrapes at the start and the end of the window, summed over the
// replicas.
type ScrimStats struct {
	RequestAdded          Histogram `json:"request_added_seconds"`
	RequestAddedP99Ms     float64   `json:"request_added_p99_ms"`
	RequestWithin5ms      float64   `json:"request_added_within_5ms"`
	RestoreChunk          Histogram `json:"restore_chunk_seconds"`
	RestoreChunkP99Us     float64   `json:"restore_chunk_p99_us"`
	RestoreChunkWithin50u float64   `json:"restore_chunk_within_50us"`
}

// EventStats: every replica's newest delivered outbox event after the run.
type EventStats struct {
	LastIDs []float64 `json:"last_ids"`
	Agree   bool      `json:"agree"`
}

func (d *driver) result(measured time.Duration, start, end [][]promSample, lastIDs []float64, agree bool, from time.Time) DriveResult {
	secs := measured.Seconds()
	m := &d.m
	r := DriveResult{WindowStart: from, WindowEnd: from.Add(measured), Seconds: round3(secs)}
	r.Throughput = Throughput{
		LLMRequests: m.llmOK.Load(), LLMPerSecond: round3(float64(m.llmOK.Load()) / secs),
		ToolRequests: m.toolOK.Load(), ToolPerSecond: round3(float64(m.toolOK.Load()) / secs),
		ChunksPerSecond:    round3(float64(m.chunks.Load()) / secs),
		RequestMBPerSecond: round3(float64(m.reqBytes.Load()) / secs / 1e6),
	}
	g := d.streamGauge.summary()
	r.Streams = StreamStats{Target: d.p.Streams, Mean: g.Mean, Max: g.Max}
	r.Latency = Latency{
		RequestAdded: m.requestAdded.summary(), FirstByte: m.ttfbAdded.summary(), TotalAdded: m.totalAdded.summary(),
		ClientTotal: m.clientTotal.summary(), Tool: m.toolLatency.summary(),
	}
	r.Errors = Errors{LLM: m.llmErr.Load(), Tool: m.toolErr.Load(), Approvals: m.apprErr.Load() + m.apprTimeout.Load()}
	r.Errors.Total = r.Errors.LLM + r.Errors.Tool + r.Errors.Approvals
	r.Errors.Ops = r.Errors.Total + m.llmOK.Load() + m.toolOK.Load() + m.apprOK.Load()
	if r.Errors.Ops > 0 {
		r.Errors.Rate = float64(r.Errors.Total) / float64(r.Errors.Ops)
	}
	r.Correctness = Correctness{
		LeaksToProvider: m.leaksProvider.Load(), LeaksToToolAPI: m.leaksTool.Load(), LeaksToAgent: m.leaksAgent.Load(),
		UnredactedMarkers: m.unredactedMarkers.Load(),
		RestoreChecks:     m.restoreOK.Load() + m.restoreFail.Load(), RestoreFailures: m.restoreFail.Load(),
		Injections: m.injectOK.Load() + m.injectFail.Load(), InjectionFailures: m.injectFail.Load(),
	}
	r.Correctness.Leaks = r.Correctness.LeaksToProvider + r.Correctness.LeaksToToolAPI + r.Correctness.LeaksToAgent + r.Correctness.UnredactedMarkers
	r.Approvals = Approvals{
		Held: m.held.Load(), Released: m.released.Load(), Approved: m.approvedN.Load(), Denied: m.deniedN.Load(),
		Revoked: m.revoked.Load(), NotHeld: m.notHeld.Load(), Timeouts: m.apprTimeout.Load(), Late: m.apprLate.Load(), RevokeFailures: m.revokeFail.Load(),
		ReleaseLag: m.releaseLag.summary(),
	}
	r.Approvals.Failures = r.Approvals.NotHeld + r.Approvals.Timeouts + r.Approvals.Late + r.Approvals.RevokeFailures + m.apprErr.Load()

	var req, chunk Histogram
	for i := range end {
		reqEnd := histogramOf(end[i], "scrim_dataplane_request_added_seconds", map[string]string{"stage": "total"})
		reqStart := histogramOf(start[i], "scrim_dataplane_request_added_seconds", map[string]string{"stage": "total"})
		req = req.add(reqEnd.sub(reqStart))
		chEnd := histogramOf(end[i], "scrim_dataplane_restore_chunk_seconds", nil)
		chStart := histogramOf(start[i], "scrim_dataplane_restore_chunk_seconds", nil)
		chunk = chunk.add(chEnd.sub(chStart))
	}
	r.Scrim = ScrimStats{
		RequestAdded: req, RequestAddedP99Ms: round3(req.Quantile(0.99) * 1000), RequestWithin5ms: round6(req.FractionWithin(0.005)),
		RestoreChunk: chunk, RestoreChunkP99Us: round3(chunk.Quantile(0.99) * 1e6), RestoreChunkWithin50u: round6(chunk.FractionWithin(0.00005)),
	}
	r.Events = EventStats{LastIDs: lastIDs, Agree: agree}
	m.mu.Lock()
	r.Failures = m.samples
	m.mu.Unlock()
	return r
}

func round6(x float64) float64 { return float64(int64(x*1e6+0.5)) / 1e6 }
