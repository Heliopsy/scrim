// SPDX-License-Identifier: AGPL-3.0-only

//! The LLM proxy's own metrics, aggregated in process with [`scrim_metrics`] primitives.
//!
//! A proxy built without [`Proxy::with_metrics`](crate::Proxy::with_metrics) records nothing and
//! takes no timestamps: every hook is behind one `Option` check. With metrics, a request looks
//! up its route's series once ([`LlmMetrics::route`]) and then only touches atomics.
//!
//! Labels are the route name (operator configuration), the provider codec (`anthropic`,
//! `openai`), refusal codes and fixed enumerations. Never a reference, a placeholder, a header
//! or any part of a request.

use std::sync::Arc;
use std::time::Duration;

use scrim_metrics::{
    BODY_BYTES, CHUNK_LATENCY, Counter, Family, Gauge, GaugeGuard, Histogram, Labelled,
    REQUEST_LATENCY, UPSTREAM_LATENCY,
};

use crate::audit::RefusalReason;

/// Most routes tracked; more share the overflow series.
const MAX_ROUTES: usize = 256;
/// Most refusal codes per route (the codes are a closed set; this is a backstop).
const MAX_CODES: usize = 64;
/// Separates route and provider in a series key. Not a character a route name can hold in
/// configuration that matters here: a name containing it only shares a series.
const SEP: char = '\u{1f}';

/// Stages of the added-latency histogram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The redactor over the body.
    Redaction,
    /// The guard over the exact outgoing body.
    Guard,
    /// Everything scrim adds before the request leaves: body redaction and guard, the request
    /// target and headers, policy admission excluded.
    Total,
}

const STAGES: [(Stage, &str); 3] = [
    (Stage::Redaction, "redaction"),
    (Stage::Guard, "guard"),
    (Stage::Total, "total"),
];

/// Why an upstream call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamError {
    /// No connection could be made.
    Connect,
    /// The connection failed after the request may have left.
    Failed,
    /// The chained upstream could not be reached and the route refuses.
    ChainUnavailable,
}

const UPSTREAM_ERRORS: [(UpstreamError, &str); 3] = [
    (UpstreamError::Connect, "connect"),
    (UpstreamError::Failed, "failed"),
    (UpstreamError::ChainUnavailable, "chain_unavailable"),
];

/// Listener kinds the LLM proxy serves directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// TCP base URL.
    BaseUrl,
    /// Unix socket base URL.
    Unix,
}

/// The series of one route.
#[derive(Debug)]
pub struct RouteMetrics {
    forwarded: Counter,
    refused: Counter,
    added: [Histogram; 3],
    body: Histogram,
    hits_value: Counter,
    hits_detector: Counter,
    guard_repaired: Counter,
    guard_withheld: Counter,
    refusals: Labelled<Counter>,
    chunk: Histogram,
    resolved: Counter,
    kept: Counter,
    upstream: Histogram,
    status: [Counter; 5],
    upstream_errors: [Counter; 3],
}

impl RouteMetrics {
    fn new() -> Self {
        Self {
            forwarded: Counter::new(),
            refused: Counter::new(),
            added: [
                Histogram::new(&REQUEST_LATENCY),
                Histogram::new(&REQUEST_LATENCY),
                Histogram::new(&REQUEST_LATENCY),
            ],
            body: Histogram::new(&BODY_BYTES),
            hits_value: Counter::new(),
            hits_detector: Counter::new(),
            guard_repaired: Counter::new(),
            guard_withheld: Counter::new(),
            refusals: Labelled::new(MAX_CODES, Counter::new),
            chunk: Histogram::new(&CHUNK_LATENCY),
            resolved: Counter::new(),
            kept: Counter::new(),
            upstream: Histogram::new(&UPSTREAM_LATENCY),
            status: Default::default(),
            upstream_errors: Default::default(),
        }
    }

    /// Records the time one stage added.
    pub fn stage(&self, stage: Stage, d: Duration) {
        let i = STAGES.iter().position(|(s, _)| *s == stage).unwrap_or(2);
        self.added[i].observe_duration(d);
    }

    /// Records the size of a request body as received.
    pub fn body_bytes(&self, n: usize) {
        self.body.observe(u64::try_from(n).unwrap_or(u64::MAX));
    }

    /// Counts a forwarded request and what redaction and the guard did to it.
    pub fn forwarded(&self, replacements: usize, detectors: usize, guard_repaired: bool) {
        self.forwarded.inc();
        self.hits_value
            .add(u64::try_from(replacements).unwrap_or(u64::MAX));
        self.hits_detector
            .add(u64::try_from(detectors).unwrap_or(u64::MAX));
        if guard_repaired {
            self.guard_repaired.inc();
        }
    }

    /// Counts a refused request by its code.
    pub fn refused(&self, reason: RefusalReason) {
        self.refused.inc();
        self.refusals.get(reason.code()).inc();
        if reason == RefusalReason::GuardRefused {
            self.guard_withheld.inc();
        }
    }

    /// Records the time restore added to one streamed chunk.
    pub fn chunk(&self, d: Duration) {
        self.chunk.observe_duration(d);
    }

    /// Counts placeholders resolved and kept in one response.
    pub fn restored(&self, resolved: u64, kept: u64) {
        self.resolved.add(resolved);
        self.kept.add(kept);
    }

    /// Records an upstream response: time to headers and the status class.
    pub fn upstream(&self, d: Duration, status: http::StatusCode) {
        self.upstream.observe_duration(d);
        let class = usize::from(status.as_u16() / 100).clamp(1, 5) - 1;
        self.status[class].inc();
    }

    /// Counts an upstream failure.
    pub fn upstream_error(&self, e: UpstreamError) {
        let i = UPSTREAM_ERRORS
            .iter()
            .position(|(k, _)| *k == e)
            .unwrap_or(1);
        self.upstream_errors[i].inc();
    }
}

/// The LLM proxy's metrics. Share one per process behind an [`Arc`].
#[derive(Debug)]
pub struct LlmMetrics {
    routes: Labelled<RouteMetrics>,
    connections: [Counter; 2],
    active: [Arc<Gauge>; 2],
}

impl Default for LlmMetrics {
    fn default() -> Self {
        Self {
            routes: Labelled::new(MAX_ROUTES, RouteMetrics::new),
            connections: Default::default(),
            active: Default::default(),
        }
    }
}

impl LlmMetrics {
    /// The series of `route` served by the `provider` codec. An empty route is a request no
    /// route matched.
    pub fn route(&self, route: &str, provider: &str) -> Arc<RouteMetrics> {
        let mut key = String::with_capacity(route.len() + provider.len() + 1);
        key.push_str(route);
        key.push(SEP);
        key.push_str(provider);
        self.routes.get(&key)
    }

    /// Counts an accepted connection; the guard keeps it in the active count until dropped.
    pub fn connection(&self, l: Listener) -> GaugeGuard {
        let i = usize::from(l == Listener::Unix);
        self.connections[i].inc();
        self.active[i].track()
    }

    /// Appends every family to `out`. Families another component also fills (refusals, guard
    /// actions, redaction hits) carry a `source` label of `llm`; merge by name.
    #[allow(clippy::too_many_lines)] // one block per family, read top to bottom
    pub fn export(&self, out: &mut Vec<Family>) {
        const RP: &[&str] = &["route", "provider"];
        let mut requests = Family::counter(
            "scrim_dataplane_requests_total",
            "LLM proxy requests, by route, provider and outcome (forwarded, refused).",
            &["route", "provider", "outcome"],
        );
        let mut added = Family::histogram(
            "scrim_dataplane_request_added_seconds",
            "Latency scrim adds to a request before it leaves, by stage (redaction, guard, total). Excludes reading the body and the upstream.",
            &["route", "provider", "stage"],
            &REQUEST_LATENCY,
        );
        let mut body = Family::histogram(
            "scrim_dataplane_request_body_bytes",
            "Size of request bodies as received from the agent.",
            RP,
            &BODY_BYTES,
        );
        let mut hits = Family::counter(
            "scrim_dataplane_redaction_hits_total",
            "Values replaced by placeholders, by source and class (value: a known value, detector: a fallback detector match).",
            &["source", "route", "provider", "class"],
        );
        let mut guard = Family::counter(
            "scrim_dataplane_guard_actions_total",
            "Requests or responses the guard repaired or withheld.",
            &["source", "route", "provider", "action"],
        );
        let mut refusals = Family::counter(
            "scrim_dataplane_refusals_total",
            "Requests scrim refused, by source and the x-scrim-error code.",
            &["source", "route", "provider", "code"],
        );
        let mut chunk = Family::histogram(
            "scrim_dataplane_restore_chunk_seconds",
            "Latency placeholder restore adds per streamed response chunk.",
            RP,
            &CHUNK_LATENCY,
        );
        let mut restored = Family::counter(
            "scrim_dataplane_restored_total",
            "Placeholders in responses, resolved to their value or kept, by route.",
            &["route", "provider", "result"],
        );
        let mut upstream = Family::histogram(
            "scrim_dataplane_upstream_seconds",
            "Time from sending a request upstream to its response headers.",
            RP,
            &UPSTREAM_LATENCY,
        );
        let mut status = Family::counter(
            "scrim_dataplane_upstream_responses_total",
            "Upstream responses by status class.",
            &["route", "provider", "status_class"],
        );
        let mut errors = Family::counter(
            "scrim_dataplane_upstream_errors_total",
            "Upstream calls that failed, by kind (connect, failed, chain_unavailable).",
            &["route", "provider", "kind"],
        );
        self.routes.each(|key, m| {
            let (route, provider) = key.split_once(SEP).unwrap_or((key, ""));
            requests
                .count(&[route, provider, "forwarded"], &m.forwarded)
                .count(&[route, provider, "refused"], &m.refused);
            for (i, (_, name)) in STAGES.iter().enumerate() {
                added.observed(&[route, provider, name], &m.added[i]);
            }
            body.observed(&[route, provider], &m.body);
            hits.count(&["llm", route, provider, "value"], &m.hits_value)
                .count(&["llm", route, provider, "detector"], &m.hits_detector);
            guard
                .count(&["llm", route, provider, "repaired"], &m.guard_repaired)
                .count(&["llm", route, provider, "withheld"], &m.guard_withheld);
            m.refusals.each(|code, c| {
                refusals.count(&["llm", route, provider, code], c);
            });
            chunk.observed(&[route, provider], &m.chunk);
            restored
                .count(&[route, provider, "resolved"], &m.resolved)
                .count(&[route, provider, "kept"], &m.kept);
            upstream.observed(&[route, provider], &m.upstream);
            for (i, c) in m.status.iter().enumerate() {
                if c.get() > 0 {
                    let class = ["1xx", "2xx", "3xx", "4xx", "5xx"][i];
                    status.count(&[route, provider, class], c);
                }
            }
            for (i, (_, kind)) in UPSTREAM_ERRORS.iter().enumerate() {
                errors.count(&[route, provider, kind], &m.upstream_errors[i]);
            }
        });
        let mut conns = Family::counter(
            "scrim_dataplane_connections_total",
            "Connections accepted, by listener kind.",
            &["listener"],
        );
        let mut active = Family::gauge(
            "scrim_dataplane_connections_active",
            "Connections open now, by listener kind.",
            &["listener"],
        );
        for (i, name) in ["base_url", "unix"].iter().enumerate() {
            conns.count(&[name], &self.connections[i]);
            #[allow(clippy::cast_precision_loss)] // a connection count fits
            active.value(&[name], self.active[i].get() as f64);
        }
        out.extend([
            requests, added, body, hits, guard, refusals, chunk, restored, upstream, status,
            errors, conns, active,
        ]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn family<'a>(fams: &'a [Family], name: &str) -> &'a Family {
        fams.iter().find(|f| f.name == name).unwrap()
    }

    #[test]
    fn records_and_exports_per_route() {
        let m = LlmMetrics::default();
        let r = m.route("claude", "anthropic");
        r.stage(Stage::Redaction, Duration::from_micros(300));
        r.stage(Stage::Total, Duration::from_millis(1));
        r.body_bytes(2048);
        r.forwarded(3, 1, true);
        r.refused(RefusalReason::GuardRefused);
        r.chunk(Duration::from_micros(4));
        r.restored(2, 1);
        r.upstream(Duration::from_millis(120), http::StatusCode::OK);
        r.upstream_error(UpstreamError::Connect);
        let _g = m.connection(Listener::BaseUrl);
        let mut fams = Vec::new();
        m.export(&mut fams);

        let req = family(&fams, "scrim_dataplane_requests_total");
        assert_eq!(req.samples.len(), 2);
        assert_eq!(req.samples[0].labels, ["claude", "anthropic", "forwarded"]);
        assert!((req.samples[0].value - 1.0).abs() < f64::EPSILON);
        let added = family(&fams, "scrim_dataplane_request_added_seconds");
        assert_eq!(added.samples.len(), 2, "guard stage had no observation");
        let refusals = family(&fams, "scrim_dataplane_refusals_total");
        assert_eq!(
            refusals.samples[0].labels,
            ["llm", "claude", "anthropic", "guard_refused"]
        );
        let guard = family(&fams, "scrim_dataplane_guard_actions_total");
        assert!(
            guard
                .samples
                .iter()
                .all(|s| (s.value - 1.0).abs() < f64::EPSILON)
        );
        let status = family(&fams, "scrim_dataplane_upstream_responses_total");
        assert_eq!(status.samples[0].labels[2], "2xx");
        let active = family(&fams, "scrim_dataplane_connections_active");
        assert!((active.samples[0].value - 1.0).abs() < f64::EPSILON);
    }
}
