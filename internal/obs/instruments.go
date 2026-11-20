// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Stage names for the added-latency histograms.
const (
	StageRedaction  = "redaction"
	StageGuard      = "guard"
	StageResolution = "resolution"
)

// Approval outcomes for [Instruments.Approval].
const (
	ApprovalRequested = "requested"
	ApprovalApproved  = "approved"
	ApprovalDenied    = "denied"
	ApprovalTimedOut  = "timed_out"
)

// Instruments are the metrics specs/observability names, registered once on
// a [Metrics] registry and shared by every package that records them. Label
// values are configured names (provider, rule, agent, store, sink, setting);
// each still passes the scrubber before it becomes a series.
type Instruments struct {
	sc Scrubber

	redactions     *prometheus.CounterVec
	guardRepairs   *prometheus.CounterVec
	guardRefusals  *prometheus.CounterVec
	fallbackHits   *prometheus.CounterVec
	addedLatency   *prometheus.HistogramVec
	chunkLatency   *prometheus.HistogramVec
	storeUp        *prometheus.GaugeVec
	storeRefreshed *prometheus.GaugeVec
	storeValues    *prometheus.GaugeVec
	storeDegraded  *prometheus.GaugeVec
	approvals      *prometheus.CounterVec
	approvalWait   *prometheus.HistogramVec
	auditDelivered *prometheus.CounterVec
	auditDropped   *prometheus.CounterVec
	stateUp        *prometheus.GaugeVec
	stateTx        *prometheus.HistogramVec
	weakened       *prometheus.GaugeVec
}

// NewInstruments registers every instrument on m. sc may be nil.
func NewInstruments(m *Metrics, sc Scrubber) *Instruments {
	if sc == nil {
		sc = noScrub{}
	}
	return &Instruments{
		sc:             sc,
		redactions:     m.Counter("redaction", "replacements_total", "Known values replaced by placeholders.", "provider", "rule", "agent"),
		guardRepairs:   m.Counter("guard", "repairs_total", "Outbound requests the guard repaired.", "provider", "rule", "agent"),
		guardRefusals:  m.Counter("guard", "refusals_total", "Outbound requests the guard refused.", "provider", "agent"),
		fallbackHits:   m.Counter("detector", "fallback_hits_total", "Fallback detector matches.", "provider", "rule", "agent"),
		addedLatency:   m.Histogram("proxy", "added_latency_seconds", "Latency scrim adds per request, by stage.", nil, "provider", "stage"),
		chunkLatency:   m.Histogram("proxy", "chunk_added_latency_seconds", "Latency scrim adds per streamed chunk, by stage.", nil, "provider", "stage"),
		storeUp:        m.Gauge("store", "up", "1 when the store answered its last check.", "store"),
		storeRefreshed: m.Gauge("store", "last_refresh_timestamp_seconds", "Unix time of the store's last successful refresh.", "store"),
		storeValues:    m.Gauge("store", "values_loaded", "Values loaded from the store.", "store"),
		storeDegraded:  m.Gauge("store", "degraded", "1 when the store is past its staleness limit.", "store"),
		approvals:      m.Counter("approval", "outcomes_total", "Approvals requested, approved, denied and timed out.", "rule", "notifier", "outcome"),
		approvalWait: m.Histogram("approval", "wait_seconds", "Time an approval waited for a decision.",
			[]float64{1, 5, 15, 30, 60, 120, 300, 600, 1800}, "rule", "notifier"),
		auditDelivered: m.Counter("audit", "delivered_total", "Audit entries delivered, by sink.", "sink"),
		auditDropped:   m.Counter("audit", "dropped_total", "Audit entries dropped under the drop policy, by sink.", "sink"),
		stateUp:        m.Gauge("state", "up", "1 when the state backend answered its last health check.", "backend"),
		stateTx:        m.Histogram("state", "transaction_seconds", "State transaction duration.", prometheus.DefBuckets, "backend", "kind"),
		weakened:       m.Gauge("config", "weakened_settings", "1 for each weakening setting in effect.", "setting"),
	}
}

func (in *Instruments) labels(vals ...string) []string {
	for i, v := range vals {
		vals[i] = in.sc.Scrub(v)
	}
	return vals
}

// Redaction counts n values replaced in one request.
func (in *Instruments) Redaction(provider, rule, agent string, n int) {
	in.redactions.WithLabelValues(in.labels(provider, rule, agent)...).Add(float64(n))
}

// GuardRepair counts a request the guard repaired.
func (in *Instruments) GuardRepair(provider, rule, agent string) {
	in.guardRepairs.WithLabelValues(in.labels(provider, rule, agent)...).Inc()
}

// GuardRefusal counts a request the guard refused.
func (in *Instruments) GuardRefusal(provider, agent string) {
	in.guardRefusals.WithLabelValues(in.labels(provider, agent)...).Inc()
}

// FallbackHit counts a fallback detector match.
func (in *Instruments) FallbackHit(provider, rule, agent string) {
	in.fallbackHits.WithLabelValues(in.labels(provider, rule, agent)...).Inc()
}

// AddedLatency records the latency scrim added to one request in stage.
func (in *Instruments) AddedLatency(provider, stage string, d time.Duration) {
	in.addedLatency.WithLabelValues(in.labels(provider, stage)...).Observe(d.Seconds())
}

// ChunkLatency records the latency scrim added to one streamed chunk.
func (in *Instruments) ChunkLatency(provider, stage string, d time.Duration) {
	in.chunkLatency.WithLabelValues(in.labels(provider, stage)...).Observe(d.Seconds())
}

// StoreHealth records one store's reachability, freshness and size.
func (in *Instruments) StoreHealth(store string, up bool, lastRefresh time.Time, values int, degraded bool) {
	l := in.labels(store)
	in.storeUp.WithLabelValues(l...).Set(b2f(up))
	if !lastRefresh.IsZero() {
		in.storeRefreshed.WithLabelValues(l...).Set(float64(lastRefresh.Unix()))
	}
	in.storeValues.WithLabelValues(l...).Set(float64(values))
	in.storeDegraded.WithLabelValues(l...).Set(b2f(degraded))
}

// Approval counts one approval outcome.
func (in *Instruments) Approval(rule, notifier, outcome string) {
	in.approvals.WithLabelValues(in.labels(rule, notifier, outcome)...).Inc()
}

// ApprovalWait records how long an approval waited for its decision.
func (in *Instruments) ApprovalWait(rule, notifier string, d time.Duration) {
	in.approvalWait.WithLabelValues(in.labels(rule, notifier)...).Observe(d.Seconds())
}

// AuditDelivered counts n entries delivered to sink.
func (in *Instruments) AuditDelivered(sink string, n int) {
	in.auditDelivered.WithLabelValues(in.labels(sink)...).Add(float64(n))
}

// AuditDropped counts n entries dropped by sink; it fits audit.Fanout.OnDrop.
func (in *Instruments) AuditDropped(sink string, n int) {
	in.auditDropped.WithLabelValues(in.labels(sink)...).Add(float64(n))
}

// StateUp records the state backend's health.
func (in *Instruments) StateUp(backend string, up bool) {
	in.stateUp.WithLabelValues(in.labels(backend)...).Set(b2f(up))
}

// StateTransaction records one state transaction; it fits the backends'
// Observe option once bound to a backend name.
func (in *Instruments) StateTransaction(backend, kind string, d time.Duration) {
	in.stateTx.WithLabelValues(in.labels(backend, kind)...).Observe(d.Seconds())
}

// Weakened records which weakening settings are in effect.
func (in *Instruments) Weakened(keys []string) {
	in.weakened.Reset()
	for _, k := range keys {
		in.weakened.WithLabelValues(in.labels(k)...).Set(1)
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
