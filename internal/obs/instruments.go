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
		storeUp:        m.Gauge("store", "up", "1 when the store answered its last check.", "store"),
		storeRefreshed: m.Gauge("store", "last_refresh_timestamp_seconds", "Unix time of the store's last successful refresh.", "store"),
		storeValues:    m.Gauge("store", "values_loaded", "Values loaded from the store.", "store"),
		storeDegraded:  m.Gauge("store", "degraded", "1 when the store is past its staleness limit.", "store"),
		storeRefresh: m.Histogram("store", "refresh_duration_seconds", "Duration of one full store refresh.",
			[]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}, "store"),
		storeErrors:    m.Counter("store", "refresh_errors_total", "Store refreshes that failed; the previous values stay in force.", "store"),
		staleness:      stale,
		auditDelivered: m.Counter("audit", "delivered_total", "Audit entries delivered, by sink.", "sink"),
		auditDropped:   m.Counter("audit", "dropped_total", "Audit entries dropped under the drop policy, by sink.", "sink"),
		stateTx:        m.Histogram("state", "transaction_seconds", "State transaction duration.", prometheus.DefBuckets, "backend", "kind"),
		weakened:       m.Gauge("config", "weakened_settings", "1 for each weakening setting in effect.", "setting"),
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
