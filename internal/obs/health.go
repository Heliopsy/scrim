// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Check reports one component's health. A nil error is healthy. The error
// text is shown on the health endpoint after scrubbing, so it must name the
// component and the problem, never a value.
type Check func(ctx context.Context) error

// Health aggregates liveness and readiness checks (specs/observability
// "Liveness and readiness"). Liveness reflects only whether the process
// works; readiness fails while scrim cannot redact safely.
type Health struct {
	mu        sync.RWMutex
	liveness  map[string]Check
	readiness map[string]Check
	// Scrubber filters check errors; nil means none.
	Scrubber Scrubber
	// Timeout bounds each check; default 2s.
	Timeout time.Duration
}

// NewHealth returns an empty Health.
func NewHealth() *Health {
	return &Health{liveness: map[string]Check{}, readiness: map[string]Check{}}
}

// Live adds a liveness check under name, replacing any with that name.
func (h *Health) Live(name string, c Check) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.liveness[name] = c
}

// Ready adds a readiness check under name, replacing any with that name.
func (h *Health) Ready(name string, c Check) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.readiness[name] = c
}

// Report is the JSON body of a health endpoint.
type Report struct {
	Status string            `json:"status"` // "ok" or "fail"
	Checks map[string]string `json:"checks"` // name -> "ok" or the problem
}

// Run evaluates the liveness (ready=false) or readiness checks.
func (h *Health) Run(ctx context.Context, ready bool) Report {
	h.mu.RLock()
	set := h.liveness
	if ready {
		set = h.readiness
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	checks := make(map[string]Check, len(set))
	for n, c := range set {
		checks[n] = c
	}
	h.mu.RUnlock()
	sort.Strings(names)

	timeout := h.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	rep := Report{Status: "ok", Checks: map[string]string{}}
	for _, n := range names {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		err := checks[n](cctx)
		cancel()
		if err == nil {
			rep.Checks[n] = "ok"
			continue
		}
		rep.Status = "fail"
		msg := err.Error()
		if h.Scrubber != nil {
			msg = h.Scrubber.Scrub(msg)
		}
		rep.Checks[n] = msg
	}
	return rep
}

// Handler serves /healthz (and its alias /livez) and /readyz; other paths
// are 404.
func (h *Health) Handler() http.Handler {
	mux := http.NewServeMux()
	serve := func(ready bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			rep := h.Run(r.Context(), ready)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			if rep.Status != "ok" {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			_ = json.NewEncoder(w).Encode(rep)
		}
	}
	mux.HandleFunc("GET /healthz", serve(false))
	mux.HandleFunc("GET /livez", serve(false))
	mux.HandleFunc("GET /readyz", serve(true))
	return mux
}

// Mux serves the health endpoints of h and, when m is not nil, /metrics:
// everything metrics.listen exposes.
func Mux(h *Health, m *Metrics) *http.ServeMux {
	mux := http.NewServeMux()
	hh := h.Handler()
	for _, p := range []string{"/healthz", "/livez", "/readyz"} {
		mux.Handle("GET "+p, hh)
	}
	if m != nil {
		mux.Handle("GET /metrics", m.Handler())
	}
	return mux
}
