// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Instruments are the control-plane metrics specs/observability names,
// registered once on a [Metrics] registry and shared by every package that
// records them. Label values are configured names (provider, rule, agent,
// store, sink, setting); each still passes the scrubber before it becomes a
// series.
//
// Instruments made with [DisabledInstruments] (metrics.enabled false) record
// nothing: every method returns at once, so no label is scrubbed and no
// series is touched. A nil *Instruments behaves the same.
//
// The data plane's latency histograms (redaction, guard, restore per chunk)
// are measured where the work happens, in the data plane, and reach the
// registry through the daemon's data plane collector.
type Instruments struct {
	sc  Scrubber
	off bool

	redactions     *prometheus.CounterVec
	guardRepairs   *prometheus.CounterVec
	guardRefusals  *prometheus.CounterVec
	fallbackHits   *prometheus.CounterVec
	storeUp        *prometheus.GaugeVec
	storeRefreshed *prometheus.GaugeVec
	storeValues    *prometheus.GaugeVec
	storeDegraded  *prometheus.GaugeVec
	storeRefresh   *prometheus.HistogramVec
	storeErrors    *prometheus.CounterVec
	staleness      *stalenessCollector
	auditDelivered *prometheus.CounterVec
	auditDropped   *prometheus.CounterVec
	stateTx        *prometheus.HistogramVec
	weakened       *prometheus.GaugeVec

	sinkDelivered *prometheus.CounterVec
	sinkDropped   *prometheus.CounterVec
	sinkRefused   *prometheus.CounterVec
	sinkErrors    *prometheus.CounterVec
	sinkWrite     *prometheus.HistogramVec
	sinkQueued    *prometheus.GaugeVec
	sinkCapacity  *prometheus.GaugeVec
	sinkUp        *prometheus.GaugeVec
	rateLimits    *prometheus.CounterVec
}

// DisabledInstruments returns instruments that record nothing.
func DisabledInstruments() *Instruments { return &Instruments{off: true} }

// NewInstruments registers every instrument on m. sc may be nil.
func NewInstruments(m *Metrics, sc Scrubber) *Instruments {
	if sc == nil {
		sc = noScrub{}
	}
	stale := &stalenessCollector{last: map[string]time.Time{}, now: time.Now,
		desc: prometheus.NewDesc(Namespace+"_store_staleness_seconds", "Seconds since the store's last successful refresh, at scrape time.", []string{"store"}, nil)}
	m.Registry.MustRegister(stale)
	return &Instruments{
		sc:             sc,
		redactions:     m.Counter("redaction", "replacements_total", "Known values replaced by placeholders.", "provider", "rule", "agent"),
		guardRepairs:   m.Counter("guard", "repairs_total", "Outbound requests the guard repaired.", "provider", "rule", "agent"),
		guardRefusals:  m.Counter("guard", "refusals_total", "Outbound requests the guard refused.", "provider", "agent"),
		fallbackHits:   m.Counter("detector", "fallback_hits_total", "Fallback detector matches.", "provider", "rule", "agent"),
		storeUp:        m.Gauge("store", "up", "1 when the store is loaded, not locked and refreshed successfully within its refresh.staleness; set on each refresh attempt.", "store"),
		storeRefreshed: m.Gauge("store", "last_refresh_timestamp_seconds", "Unix time of the store's last successful refresh.", "store"),
		storeValues:    m.Gauge("store", "values_loaded", "Values loaded from the store.", "store"),
		storeDegraded:  m.Gauge("store", "degraded", "1 when the store's last refresh failed (the last known values stay redacted) or a redact target holds no value.", "store"),
		storeRefresh: m.Histogram("store", "refresh_duration_seconds", "Duration of one full store refresh.",
			[]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}, "store"),
		storeErrors:    m.Counter("store", "refresh_errors_total", "Store refreshes that failed; the previous values stay in force.", "store"),
		staleness:      stale,
		auditDelivered: m.Counter("audit", "delivered_total", "Data plane audit events written to the audit log, by sink (state).", "sink"),
		auditDropped:   m.Counter("audit", "dropped_total", "Data plane audit events lost, by sink: dataplane (dropped before the control plane read them) or state (the state backend could not write them).", "sink"),
		stateTx:        m.Histogram("state", "transaction_seconds", "State transaction duration.", prometheus.DefBuckets, "backend", "kind"),
		weakened:       m.Gauge("config", "weakened_settings", "1 for each weakening setting in effect.", "setting"),

		sinkDelivered: m.Counter("audit_sink", "delivered_total", "Audit entries an external sink (otlp, loki, kafka) accepted.", "sink"),
		sinkDropped: m.Counter("audit_sink", "dropped_total", "Audit entries an external sink never received: queue_full under the drop policy, "+
			"or shutdown before delivery. Every entry is still in the database audit log.", "sink", "reason"),
		sinkRefused: m.Counter("audit_sink", "refused_total", "Audit entries whose operation was refused because a block-policy sink had no queue room within its timeout.", "sink"),
		sinkErrors:  m.Counter("audit_sink", "write_errors_total", "Failed writes to an external audit sink; the batch is retried.", "sink"),
		sinkWrite: m.Histogram("audit_sink", "write_duration_seconds", "Duration of one write to an external audit sink, successful or not.",
			[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}, "sink"),
		sinkQueued:   m.Gauge("audit_sink", "queue_entries", "Audit entries waiting for an external sink.", "sink"),
		sinkCapacity: m.Gauge("audit_sink", "queue_capacity", "Queue size of an external audit sink (audit.<sink>.queue-size).", "sink"),
		sinkUp:       m.Gauge("audit_sink", "up", "1 when the external audit sink accepted its last write, 0 while writes fail.", "sink"),
		rateLimits:   m.Counter("ratelimit", "decisions_total", "Rate-limit decisions by backend, class and result (allowed, limited, error; error refuses).", "backend", "class", "result"),
	}
}

// On reports whether the instruments record.
func (in *Instruments) On() bool { return in != nil && !in.off }

func (in *Instruments) labels(vals ...string) []string {
	for i, v := range vals {
		vals[i] = in.sc.Scrub(v)
	}
	return vals
}

// Redaction counts n values replaced in one request.
func (in *Instruments) Redaction(provider, rule, agent string, n int) {
	if !in.On() {
		return
	}
	in.redactions.WithLabelValues(in.labels(provider, rule, agent)...).Add(float64(n))
}

// GuardRepair counts a request the guard repaired.
func (in *Instruments) GuardRepair(provider, rule, agent string) {
	if !in.On() {
		return
	}
	in.guardRepairs.WithLabelValues(in.labels(provider, rule, agent)...).Inc()
}

// GuardRefusal counts a request the guard refused.
func (in *Instruments) GuardRefusal(provider, agent string) {
	if !in.On() {
		return
	}
	in.guardRefusals.WithLabelValues(in.labels(provider, agent)...).Inc()
}

// FallbackHit counts a fallback detector match.
func (in *Instruments) FallbackHit(provider, rule, agent string) {
	if !in.On() {
		return
	}
	in.fallbackHits.WithLabelValues(in.labels(provider, rule, agent)...).Inc()
}

// StoreHealth records one store's reachability, freshness and size.
func (in *Instruments) StoreHealth(store string, up bool, lastRefresh time.Time, values int, degraded bool) {
	if !in.On() {
		return
	}
	l := in.labels(store)
	in.storeUp.WithLabelValues(l...).Set(b2f(up))
	if !lastRefresh.IsZero() {
		in.storeRefreshed.WithLabelValues(l...).Set(float64(lastRefresh.Unix()))
	}
	in.storeValues.WithLabelValues(l...).Set(float64(values))
	in.storeDegraded.WithLabelValues(l...).Set(b2f(degraded))
	if !lastRefresh.IsZero() {
		in.staleness.set(l[0], lastRefresh)
	}
}

// StoreRefresh records one refresh attempt of store: how long it took and
// whether it failed.
func (in *Instruments) StoreRefresh(store string, took time.Duration, failed bool) {
	if !in.On() {
		return
	}
	l := in.labels(store)
	if took > 0 {
		in.storeRefresh.WithLabelValues(l...).Observe(took.Seconds())
	}
	if failed {
		in.storeErrors.WithLabelValues(l...).Inc()
	}
}

// AuditDelivered counts n entries delivered to sink.
func (in *Instruments) AuditDelivered(sink string, n int) {
	if !in.On() {
		return
	}
	in.auditDelivered.WithLabelValues(in.labels(sink)...).Add(float64(n))
}

// AuditDropped counts n entries dropped by sink; it fits audit.Fanout.OnDrop.
func (in *Instruments) AuditDropped(sink string, n int) {
	if !in.On() {
		return
	}
	in.auditDropped.WithLabelValues(in.labels(sink)...).Add(float64(n))
}

// AuditSinkDelivered implements audit.Observer.
func (in *Instruments) AuditSinkDelivered(sink string, n int, took time.Duration) {
	if !in.On() {
		return
	}
	l := in.labels(sink)
	in.sinkDelivered.WithLabelValues(l...).Add(float64(n))
	in.sinkWrite.WithLabelValues(l...).Observe(took.Seconds())
}

// AuditSinkWriteFailed implements audit.Observer.
func (in *Instruments) AuditSinkWriteFailed(sink string, took time.Duration) {
	if !in.On() {
		return
	}
	l := in.labels(sink)
	in.sinkErrors.WithLabelValues(l...).Inc()
	in.sinkWrite.WithLabelValues(l...).Observe(took.Seconds())
}

// AuditSinkDropped implements audit.Observer.
func (in *Instruments) AuditSinkDropped(sink, reason string, n int) {
	if !in.On() {
		return
	}
	in.sinkDropped.WithLabelValues(in.labels(sink, reason)...).Add(float64(n))
}

// AuditSinkRefused implements audit.Observer.
func (in *Instruments) AuditSinkRefused(sink string, n int) {
	if !in.On() {
		return
	}
	in.sinkRefused.WithLabelValues(in.labels(sink)...).Add(float64(n))
}

// AuditSinkQueue implements audit.Observer.
func (in *Instruments) AuditSinkQueue(sink string, queued, capacity int) {
	if !in.On() {
		return
	}
	l := in.labels(sink)
	in.sinkQueued.WithLabelValues(l...).Set(float64(queued))
	in.sinkCapacity.WithLabelValues(l...).Set(float64(capacity))
}

// AuditSinkUp implements audit.Observer.
func (in *Instruments) AuditSinkUp(sink string, up bool) {
	if !in.On() {
		return
	}
	in.sinkUp.WithLabelValues(in.labels(sink)...).Set(b2f(up))
}

// RateLimit implements ratelimit.Observer.
func (in *Instruments) RateLimit(backend, class, result string) {
	if !in.On() {
		return
	}
	in.rateLimits.WithLabelValues(in.labels(backend, class, result)...).Inc()
}

// StateTransaction records one state transaction; it fits the backends'
// Observe option once bound to a backend name.
func (in *Instruments) StateTransaction(backend, kind string, d time.Duration) {
	if !in.On() {
		return
	}
	in.stateTx.WithLabelValues(in.labels(backend, kind)...).Observe(d.Seconds())
}

// Weakened records which weakening settings are in effect.
func (in *Instruments) Weakened(keys []string) {
	if !in.On() {
		return
	}
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

// stalenessCollector reports each store's time since its last successful
// refresh, computed when scraped so it grows while a store is unreachable.
type stalenessCollector struct {
	mu   sync.Mutex
	last map[string]time.Time
	now  func() time.Time
	desc *prometheus.Desc
}

func (c *stalenessCollector) set(store string, t time.Time) {
	c.mu.Lock()
	c.last[store] = t
	c.mu.Unlock()
}

func (c *stalenessCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *stalenessCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for store, t := range c.last {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, max(now.Sub(t).Seconds(), 0), store)
	}
}
