// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/heliopsy/scrim/internal/config"
)

// Namespace prefixes every scrim metric.
const Namespace = "scrim"

// MetricsListen is where the metrics and health endpoints listen.
var MetricsListen = config.Register(config.Spec[string]{
	Key:             "metrics.listen",
	Default:         "",
	Description:     "Address of the metrics and health endpoint (Prometheus format at /metrics, /livez, /readyz). Empty disables it; bind to loopback unless scraped remotely.",
	Flag:            true,
	RestartRequired: true,
})

// Metrics is the process metrics registry. Packages create their collectors
// through it so tests can use a fresh one.
//
// Label values must be configured names (provider, store, rule, agent ID,
// sink), never a reference path, request content or a value.
type Metrics struct {
	Registry *prometheus.Registry
}

// NewMetrics returns a registry with the Go runtime and process collectors.
func NewMetrics() *Metrics {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return &Metrics{Registry: r}
}

// Counter registers a counter vector named scrim_<subsystem>_<name>.
func (m *Metrics) Counter(subsystem, name, help string, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: Namespace, Subsystem: subsystem, Name: name, Help: help}, labels)
	m.Registry.MustRegister(c)
	return c
}

// Gauge registers a gauge vector.
func (m *Metrics) Gauge(subsystem, name, help string, labels ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: Namespace, Subsystem: subsystem, Name: name, Help: help}, labels)
	m.Registry.MustRegister(g)
	return g
}

// Histogram registers a histogram vector. Nil buckets use latency buckets
// from 50µs to 5s, suited to added latency.
func (m *Metrics) Histogram(subsystem, name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	if buckets == nil {
		buckets = prometheus.ExponentialBucketsRange(0.00005, 5, 16)
	}
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: Namespace, Subsystem: subsystem, Name: name, Help: help, Buckets: buckets}, labels)
	m.Registry.MustRegister(h)
	return h
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry})
}
