// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// Namespace prefixes every scrim metric.
const Namespace = "scrim"

// MetricsEnabled is the feature flag for Prometheus-style monitoring.
var MetricsEnabled = config.Register(config.Spec[bool]{
	Key:             "metrics.enabled",
	Default:         false,
	Description:     "Serve Prometheus metrics (control plane and data plane) at metrics.path on metrics.listen. Off: nothing is measured on the request path and no metrics listener is bound.",
	Flag:            true,
	RestartRequired: true,
})

// DefaultMetricsListen is metrics.listen's default.
const DefaultMetricsListen = "127.0.0.1:9792"

// MetricsListen is where the metrics and health endpoints listen.
var MetricsListen = config.Register(config.Spec[string]{
	Key:             "metrics.listen",
	Default:         DefaultMetricsListen,
	Description:     "Address of the metrics and health endpoint (/healthz or /livez, /readyz, and metrics.path while metrics.enabled). Used when metrics.enabled is true; set explicitly with metrics.enabled false it serves the health endpoints only. Bind to loopback unless scraped remotely.",
	Flag:            true,
	RestartRequired: true,
})

// MetricsPath is the path of the Prometheus endpoint.
var MetricsPath = config.Register(config.Spec[string]{
	Key:             "metrics.path",
	Default:         "/metrics",
	Description:     "Path of the Prometheus endpoint on metrics.listen.",
	RestartRequired: true,
	Validate: func(p string) error {
		switch {
		case !strings.HasPrefix(p, "/") || strings.ContainsAny(p, " ?#{}"):
			return errors.New("must be an absolute path such as /metrics")
		case p == "/healthz" || p == "/livez" || p == "/readyz":
			return errors.New("is a health endpoint")
		}
		return nil
	},
})

// MetricsToken is the bearer token a scraper presents.
var MetricsToken = config.Register(config.Spec[config.SecretRef]{
	Key:             "metrics.auth.token",
	Description:     "Reference to a bearer token (at least 16 bytes) a scraper must present on metrics.path. Required when metrics.listen is not a loopback address, unless metrics.allow-unauthenticated-remote is set. The health endpoints never need it.",
	RestartRequired: true,
})

// MetricsAllowUnauthenticatedRemote lets the metrics endpoint listen beyond
// loopback without a token.
var MetricsAllowUnauthenticatedRemote = config.Register(config.Spec[bool]{
	Key:             "metrics.allow-unauthenticated-remote",
	Default:         false,
	Weakening:       true,
	RestartRequired: true,
	Description:     "Serve metrics.path on a non-loopback metrics.listen without metrics.auth.token, for a network policy or mesh that already restricts who connects. Anyone who can reach the port reads the metrics.",
})

// MinMetricsTokenLen is the shortest accepted metrics.auth.token.
const MinMetricsTokenLen = 16

// IsLoopback reports whether a host:port listen address binds loopback only.
// An empty host binds every interface.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// CheckMetricsAuth refuses a metrics endpoint that would be served beyond
// loopback without a token, unless the weakening setting allows it.
func CheckMetricsAuth(addr string, token secret.Value, allowRemote bool) error {
	if !token.IsZero() && token.Len() < MinMetricsTokenLen {
		return fmt.Errorf("metrics.auth.token: the token must be at least %d bytes", MinMetricsTokenLen)
	}
	if token.IsZero() && !IsLoopback(addr) && !allowRemote {
		return fmt.Errorf("metrics.listen %q is not a loopback address: set metrics.auth.token, or metrics.allow-unauthenticated-remote to serve metrics to anyone who can connect", addr)
	}
	return nil
}

// Metrics is the process metrics registry. Packages create their collectors
// through it so tests can use a fresh one.
//
// Label values must be configured names (provider, store, rule, agent ID,
// sink), never a reference path, request content or a value.
type Metrics struct {
	Registry *prometheus.Registry
	// Scrubber filters the whole metrics page before it is served; nil
	// means none. Label values should already be safe; this is the second
	// line.
	Scrubber Scrubber
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

// RequireBearer wraps h so that only requests carrying token as a bearer
// token reach it; a zero token returns h unchanged. Failures get 401 with no
// detail.
func RequireBearer(h http.Handler, token secret.Value) http.Handler {
	if token.IsZero() {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		match := false
		if ok {
			_ = token.Expose(func(b []byte) error {
				match = subtle.ConstantTimeCompare([]byte(got), b) == 1
				return nil
			})
		}
		if !match {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scrim metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Handler serves the registry in the Prometheus exposition format. With a
// Scrubber the page is buffered, uncompressed, and scrubbed as a whole.
func (m *Metrics) Handler() http.Handler {
	if m.Scrubber == nil {
		return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry})
	}
	inner := promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry, DisableCompression: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &bufferedResponse{header: http.Header{}, code: http.StatusOK}
		inner.ServeHTTP(rec, r)
		body := m.Scrubber.Scrub(rec.buf.String())
		for k, v := range rec.header {
			w.Header()[k] = v
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(rec.code)
		_, _ = io.WriteString(w, body)
	})
}

// bufferedResponse collects a response so it can be scrubbed before it is
// sent.
type bufferedResponse struct {
	header http.Header
	code   int
	buf    bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) WriteHeader(code int)        { b.code = code }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.buf.Write(p) }
