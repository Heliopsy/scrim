// SPDX-License-Identifier: AGPL-3.0-only

//! The data plane's metrics (specs/observability "Data plane metrics", design D12).
//!
//! Off unless the control plane starts the data plane with `SCRIM_DP_METRICS=1` (it does when
//! `metrics.enabled` is true). Then the request path aggregates into atomics and fixed-bucket
//! histograms ([`scrim_metrics`]) and nothing is formatted or sent until the control plane asks:
//! it calls the `Metrics` RPC once per Prometheus scrape and serves the families on its own
//! metrics endpoint, scrubbed with everything else. The data plane opens no listener for it.
//!
//! Sources:
//!
//! - the LLM proxy records its own series ([`scrim_llm::metrics`]);
//! - tool-proxy audit events are counted here as they pass to the event bus
//!   ([`DataPlaneMetrics::tool_event`]);
//! - tool-proxy listeners count their connections ([`DataPlaneMetrics::connection`]);
//! - snapshot applies are timed by [`crate::engine::Shared::apply`].
//!
//! Every label value is a route name, a codec name, a refusal code or another fixed
//! enumeration. References, placeholders, hosts and paths are never labels.

use std::sync::Arc;
use std::time::Duration;

use scrim_llm::LlmMetrics;
use scrim_metrics::{
    APPLY_LATENCY, Counter, Family, Gauge, GaugeGuard, Histogram, Kind, Labelled, to_f64,
};
use scrim_proto::v1;
use scrim_toolproxy::{AuditEvent, ErrorCode};

/// Tool-proxy listener kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyListener {
    /// `TOOL_PROXY`.
    ToolProxy,
    /// `FORWARD_PROXY`.
    ForwardProxy,
}

/// Most distinct tool-proxy refusal codes (a closed set; this is a backstop).
const MAX_CODES: usize = 64;

/// Every metric the data plane keeps.
#[derive(Debug)]
pub struct DataPlaneMetrics {
    /// The LLM proxy's series.
    pub llm: Arc<LlmMetrics>,
    injections: [Counter; 3],
    captures: [Counter; 2],
    tool_refusals: Labelled<Counter>,
    tool_withheld: Counter,
    tool_hits: Counter,
    connections: [Counter; 2],
    active: [Arc<Gauge>; 2],
    applies: [Counter; 2],
    apply_seconds: Histogram,
    version: Gauge,
    values: Gauge,
}

impl Default for DataPlaneMetrics {
    fn default() -> Self {
        Self {
            llm: Arc::default(),
            injections: Default::default(),
            captures: Default::default(),
            tool_refusals: Labelled::new(MAX_CODES, Counter::new),
            tool_withheld: Counter::new(),
            tool_hits: Counter::new(),
            connections: Default::default(),
            active: Default::default(),
            applies: Default::default(),
            apply_seconds: Histogram::new(&APPLY_LATENCY),
            version: Gauge::new(),
            values: Gauge::new(),
        }
    }
}

const INJECTIONS: [&str; 3] = ["allowed", "denied", "unbound"];

impl DataPlaneMetrics {
    /// Counts one tool-proxy audit event.
    pub fn tool_event(&self, e: &AuditEvent) {
        match e {
            AuditEvent::RequestRefused { code, .. } => {
                self.tool_refusals.get(code.as_str()).inc();
                match code {
                    ErrorCode::UnboundCredential
                    | ErrorCode::UnboundDestination
                    | ErrorCode::UndeclaredLocation => self.injections[2].inc(),
                    ErrorCode::PolicyDenied => self.injections[1].inc(),
                    _ => {}
                }
            }
            AuditEvent::CredentialInjected { .. } => self.injections[0].inc(),
            AuditEvent::ResponseRedacted { replacements, .. } => self.tool_hits.add(*replacements),
            AuditEvent::ResponseWithheld { code, .. } => {
                self.tool_withheld.inc();
                self.tool_refusals.get(code.as_str()).inc();
            }
            AuditEvent::ValueCaptured { .. } => self.captures[0].inc(),
            AuditEvent::CaptureFailed { .. } => self.captures[1].inc(),
            AuditEvent::InterceptionRefused { .. } => {
                self.tool_refusals.get("interception_refused").inc();
            }
            _ => {}
        }
    }

    /// Counts an accepted tool-proxy connection; the guard keeps it active until dropped.
    pub fn connection(&self, l: ProxyListener) -> GaugeGuard {
        let i = usize::from(l == ProxyListener::ForwardProxy);
        self.connections[i].inc();
        self.active[i].track()
    }

    /// Records one snapshot apply: how long it took, and on success the version and value
    /// count now in force.
    pub fn applied(&self, took: Duration, result: Option<(u64, u32)>) {
        self.apply_seconds.observe_duration(took);
        match result {
            Some((version, values)) => {
                self.applies[0].inc();
                self.version.set(i64::try_from(version).unwrap_or(i64::MAX));
                self.values.set(i64::from(values));
            }
            None => self.applies[1].inc(),
        }
    }

    /// Every family, merged by name, in boundary form.
    pub fn export(&self, events_dropped: u64) -> v1::MetricsResponse {
        let mut fams = Vec::new();
        self.llm.export(&mut fams);

        let mut hits = Family::counter(
            "scrim_dataplane_redaction_hits_total",
            "",
            &["source", "route", "provider", "class"],
        );
        hits.count(&["toolproxy", "", "", "value"], &self.tool_hits);
        let mut guard = Family::counter(
            "scrim_dataplane_guard_actions_total",
            "",
            &["source", "route", "provider", "action"],
        );
        guard.count(&["toolproxy", "", "", "withheld"], &self.tool_withheld);
        let mut refusals = Family::counter(
            "scrim_dataplane_refusals_total",
            "",
            &["source", "route", "provider", "code"],
        );
        self.tool_refusals.each(|code, c| {
            refusals.count(&["toolproxy", "", "", code], c);
        });
        let mut injections = Family::counter(
            "scrim_dataplane_injections_total",
            "Tool-proxy credential injections: allowed, denied by policy, or refused because the credential is not bound to the destination or location.",
            &["outcome"],
        );
        for (i, o) in INJECTIONS.iter().enumerate() {
            injections.count(&[o], &self.injections[i]);
        }
        let mut captures = Family::counter(
            "scrim_dataplane_captures_total",
            "Values tool-proxy capture rules took from responses, stored or failed.",
            &["outcome"],
        );
        captures
            .count(&["stored"], &self.captures[0])
            .count(&["failed"], &self.captures[1]);
        let mut conns = Family::counter("scrim_dataplane_connections_total", "", &["listener"]);
        let mut active = Family::gauge("scrim_dataplane_connections_active", "", &["listener"]);
        for (i, name) in ["tool_proxy", "forward_proxy"].iter().enumerate() {
            conns.count(&[name], &self.connections[i]);
            active.value(&[name], gauge(&self.active[i]));
        }
        let mut applies = Family::counter(
            "scrim_dataplane_snapshot_applies_total",
            "Snapshots the data plane applied or rejected.",
            &["result"],
        );
        applies
            .count(&["applied"], &self.applies[0])
            .count(&["rejected"], &self.applies[1]);
        let mut apply = Family::histogram(
            "scrim_dataplane_snapshot_apply_seconds",
            "Time to validate, build and publish a snapshot, off the request path.",
            &[],
            &APPLY_LATENCY,
        );
        apply.observed(&[], &self.apply_seconds);
        let mut version = Family::gauge(
            "scrim_dataplane_snapshot_version",
            "Version of the snapshot in force, 0 before the first.",
            &[],
        );
        version.value(&[], gauge(&self.version));
        let mut values = Family::gauge(
            "scrim_dataplane_values",
            "Values in the redaction dictionary in force.",
            &[],
        );
        values.value(&[], gauge(&self.values));
        let mut dropped = Family::counter(
            "scrim_dataplane_events_dropped_total",
            "Audit events dropped because the control plane did not read them fast enough.",
            &[],
        );
        dropped.value(&[], to_f64(events_dropped));
        fams.extend([
            hits, guard, refusals, injections, captures, conns, active, applies, apply, version,
            values, dropped,
        ]);
        v1::MetricsResponse {
            protocol: v1::PROTOCOL,
            enabled: true,
            families: merge(fams).into_iter().map(to_proto).collect(),
        }
    }
}

#[allow(clippy::cast_precision_loss)] // gauges here are counts far below 2^53
fn gauge(g: &Gauge) -> f64 {
    g.get() as f64
}

/// Merges families of the same name: samples are concatenated, the first non-empty help wins.
/// Families keep the order of their first appearance.
fn merge(fams: Vec<Family>) -> Vec<Family> {
    let mut out: Vec<Family> = Vec::with_capacity(fams.len());
    for f in fams {
        match out.iter_mut().find(|o| o.name == f.name) {
            Some(o) => {
                debug_assert!(o.kind == f.kind && o.labels == f.labels, "{}", f.name);
                if o.help.is_empty() {
                    o.help = f.help;
                }
                o.samples.extend(f.samples);
            }
            None => out.push(f),
        }
    }
    out
}

fn to_proto(f: Family) -> v1::MetricFamily {
    let kind = match f.kind {
        Kind::Counter => v1::MetricType::Counter,
        Kind::Gauge => v1::MetricType::Gauge,
        Kind::Histogram => v1::MetricType::Histogram,
    };
    v1::MetricFamily {
        name: f.name.to_owned(),
        help: f.help.to_owned(),
        r#type: kind.into(),
        label_names: f.labels.iter().map(|&l| l.to_owned()).collect(),
        bucket_bounds: f.bounds,
        samples: f
            .samples
            .into_iter()
            .map(|s| v1::MetricSample {
                label_values: s.labels,
                value: s.value,
                bucket_counts: s.buckets,
                count: s.count,
                sum: s.sum,
            })
            .collect(),
    }
}

/// The answer of a data plane started without metrics.
pub fn disabled() -> v1::MetricsResponse {
    v1::MetricsResponse {
        protocol: v1::PROTOCOL,
        enabled: false,
        families: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::float_cmp)]
    use super::*;

    #[test]
    fn tool_events_and_merge() {
        let m = DataPlaneMetrics::default();
        m.tool_event(&AuditEvent::CredentialInjected {
            credentials: vec!["acme".into()],
            destination: "https://api.acme.example:443".into(),
            method: "GET".into(),
            path: "/v1".into(),
        });
        m.tool_event(&AuditEvent::RequestRefused {
            code: ErrorCode::UnboundDestination,
            credentials: vec!["acme".into()],
            destination: "https://evil.example:443".into(),
            method: "GET".into(),
            path: "/".into(),
            message: "not bound".into(),
        });
        m.llm
            .route("claude", "anthropic")
            .refused(scrim_llm::RefusalReason::GuardRefused);
        m.applied(Duration::from_millis(3), Some((7, 12)));
        let r = m.export(2);
        assert!(r.enabled);
        let names: Vec<_> = r.families.iter().map(|f| f.name.as_str()).collect();
        let mut dedup = names.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(names.len(), dedup.len(), "families are merged by name");
        let refusals = r
            .families
            .iter()
            .find(|f| f.name == "scrim_dataplane_refusals_total")
            .unwrap();
        assert_eq!(refusals.samples.len(), 2);
        assert_ne!(refusals.help, "");
        let inj = r
            .families
            .iter()
            .find(|f| f.name == "scrim_dataplane_injections_total")
            .unwrap();
        let by: Vec<_> = inj
            .samples
            .iter()
            .map(|s| (s.label_values[0].as_str(), s.value))
            .collect();
        assert_eq!(by, [("allowed", 1.0), ("denied", 0.0), ("unbound", 1.0)]);
        // No label anywhere carries the destination, method, path or credential name.
        for f in &r.families {
            for s in &f.samples {
                for v in &s.label_values {
                    assert!(!v.contains("example") && !v.contains("acme"), "{v}");
                }
            }
        }
    }
}
