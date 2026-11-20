// SPDX-License-Identifier: AGPL-3.0-only

//! Turns tool-proxy and LLM-proxy audit events into boundary events for the control plane.
//! Both proxies emit metadata only (references, routes, destinations, counts); so do these
//! conversions.

use std::collections::HashMap;
use std::sync::Arc;

use scrim_llm::RefusalReason;
use scrim_proto::v1;
use scrim_toolproxy::{AuditEvent, AuditSink};

use crate::events::Bus;

/// The LLM proxy's audit sink: every event becomes one or more boundary events on the bus.
#[derive(Clone, Debug)]
pub struct LlmSink(pub Arc<Bus>);

impl scrim_llm::AuditSink for LlmSink {
    fn record(&self, event: scrim_llm::AuditEvent) {
        for ev in convert_llm(event) {
            self.0.emit(ev);
        }
    }
}

fn llm_attrs(pairs: &[(&str, String)]) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    m.insert("source".into(), "llm".into());
    m
}

fn join(refs: &[scrim_llm::SecretRef]) -> String {
    refs.iter()
        .map(scrim_llm::SecretRef::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

/// The single reference of a list, for `Event.ref`; several go to the `refs` attribute only.
fn only(refs: &[scrim_llm::SecretRef]) -> String {
    match refs {
        [one] => one.as_str().to_owned(),
        _ => String::new(),
    }
}

/// Maps one LLM proxy event. A forwarded request yields a redaction event (with its count,
/// zero included, so every provider request is accounted for), plus a guard-repair event and a
/// detector event when those fired.
pub fn convert_llm(event: scrim_llm::AuditEvent) -> Vec<v1::Event> {
    match event {
        scrim_llm::AuditEvent::Forwarded {
            route,
            snapshot,
            replacements,
            refs,
            detectors,
            guard_repaired,
            unscanned,
            chain_skipped,
        } => {
            let mut out = Vec::with_capacity(3);
            out.push(v1::Event {
                kind: v1::EventKind::Redaction.into(),
                effect: v1::Effect::Allow.into(),
                target: route.clone(),
                r#ref: only(&refs),
                count: u32::try_from(replacements).unwrap_or(u32::MAX),
                snapshot_version: snapshot,
                attrs: llm_attrs(&[
                    ("direction", "request".to_owned()),
                    ("refs", join(&refs)),
                    ("unscanned", unscanned.join(",")),
                    (
                        "chain_skipped",
                        if chain_skipped {
                            "true".into()
                        } else {
                            String::new()
                        },
                    ),
                ]),
                ..Default::default()
            });
            if !guard_repaired.is_empty() {
                out.push(v1::Event {
                    kind: v1::EventKind::GuardRepair.into(),
                    target: route.clone(),
                    r#ref: only(&guard_repaired),
                    count: u32::try_from(guard_repaired.len()).unwrap_or(u32::MAX),
                    snapshot_version: snapshot,
                    attrs: llm_attrs(&[("refs", join(&guard_repaired))]),
                    ..Default::default()
                });
            }
            if !detectors.is_empty() {
                out.push(v1::Event {
                    kind: v1::EventKind::DetectorHit.into(),
                    target: route,
                    count: u32::try_from(detectors.len()).unwrap_or(u32::MAX),
                    snapshot_version: snapshot,
                    attrs: llm_attrs(&[("detectors", detectors.join(","))]),
                    ..Default::default()
                });
            }
            out
        }
        scrim_llm::AuditEvent::Refused {
            route,
            reason,
            refs,
        } => {
            let kind = if reason == RefusalReason::GuardRefused {
                v1::EventKind::GuardRefusal
            } else {
                v1::EventKind::Error
            };
            vec![v1::Event {
                kind: kind.into(),
                effect: v1::Effect::Deny.into(),
                target: route.unwrap_or_default(),
                r#ref: only(&refs),
                reason: reason.code().to_owned(),
                attrs: llm_attrs(&[("code", reason.code().to_owned()), ("refs", join(&refs))]),
                ..Default::default()
            }]
        }
        scrim_llm::AuditEvent::Restored {
            route,
            resolved,
            kept,
        } => vec![v1::Event {
            kind: v1::EventKind::Restore.into(),
            target: route,
            count: u32::try_from(resolved).unwrap_or(u32::MAX),
            attrs: llm_attrs(&[("kept", kept.to_string())]),
            ..Default::default()
        }],
    }
}

/// The tool proxy's audit sink: every event goes onto the event bus.
#[derive(Clone, Debug)]
pub struct Sink(pub Arc<Bus>);

impl AuditSink for Sink {
    fn record(&self, event: AuditEvent) {
        self.0.emit(convert(event));
    }
}

fn attrs(pairs: &[(&str, String)]) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    m.insert("source".into(), "toolproxy".into());
    m
}

/// Maps one event. Every field the tool proxy emits is metadata; values
/// never appear in `AuditEvent`.
pub fn convert(event: AuditEvent) -> v1::Event {
    let mut ev = v1::Event::default();
    match event {
        AuditEvent::RequestRefused {
            code,
            credentials,
            destination,
            method,
            path,
            message,
        } => {
            ev.kind = v1::EventKind::Error.into();
            ev.effect = v1::Effect::Deny.into();
            ev.target = destination;
            ev.reason = message;
            ev.attrs = attrs(&[
                ("code", code.as_str().to_owned()),
                ("credentials", credentials.join(",")),
                ("method", method),
                ("path", path),
            ]);
        }
        AuditEvent::CredentialInjected {
            credentials,
            destination,
            method,
            path,
        } => {
            ev.kind = v1::EventKind::Injection.into();
            ev.effect = v1::Effect::Allow.into();
            ev.target = destination;
            ev.count = u32::try_from(credentials.len()).unwrap_or(u32::MAX);
            ev.attrs = attrs(&[
                ("credentials", credentials.join(",")),
                ("method", method),
                ("path", path),
            ]);
        }
        AuditEvent::ResponseRedacted {
            destination,
            replacements,
        } => {
            ev.kind = v1::EventKind::Redaction.into();
            ev.target = destination;
            ev.count = u32::try_from(replacements).unwrap_or(u32::MAX);
            ev.attrs = attrs(&[("direction", "response".to_owned())]);
        }
        AuditEvent::ResponseWithheld {
            code,
            destination,
            message,
        } => {
            ev.kind = v1::EventKind::GuardRefusal.into();
            ev.target = destination;
            ev.reason = message;
            ev.attrs = attrs(&[("code", code.as_str().to_owned())]);
        }
        AuditEvent::ValueCaptured {
            rule,
            reference,
            destination,
        } => {
            ev.kind = v1::EventKind::Capture.into();
            ev.rule = rule;
            ev.r#ref = reference;
            ev.target = destination;
            ev.attrs = attrs(&[]);
        }
        AuditEvent::CaptureFailed {
            rule,
            reference,
            destination,
            message,
        } => {
            ev.kind = v1::EventKind::Error.into();
            ev.rule = rule;
            ev.r#ref = reference;
            ev.target = destination;
            ev.reason = message;
            ev.attrs = attrs(&[("stage", "capture".to_owned())]);
        }
        AuditEvent::InterceptionRefused {
            destination,
            reason,
        } => {
            ev.kind = v1::EventKind::InterceptionRefused.into();
            ev.target = destination;
            ev.reason = reason;
            ev.attrs = attrs(&[]);
        }
        _ => {
            ev.kind = v1::EventKind::Unspecified.into();
            ev.reason = "tool proxy event this data plane does not map yet".into();
            ev.attrs = attrs(&[]);
        }
    }
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_injection_and_capture() {
        let ev = convert(AuditEvent::CredentialInjected {
            credentials: vec!["acme".into()],
            destination: "https://api.acme.example:443".into(),
            method: "GET".into(),
            path: "/v1/items".into(),
        });
        assert_eq!(ev.kind(), v1::EventKind::Injection);
        assert_eq!(
            ev.attrs.get("credentials").map(String::as_str),
            Some("acme")
        );
        let ev = convert(AuditEvent::ValueCaptured {
            rule: "r".into(),
            reference: "bao://kv/new#token".into(),
            destination: "https://x:443".into(),
        });
        assert_eq!(ev.kind(), v1::EventKind::Capture);
        assert_eq!(ev.r#ref, "bao://kv/new#token");
    }

    #[test]
    fn maps_llm_events() {
        use scrim_llm::{AuditEvent as E, SecretRef};
        let evs = convert_llm(E::Forwarded {
            route: "anthropic".into(),
            snapshot: 4,
            replacements: 3,
            refs: vec![SecretRef::new("bao://kv/a#b")],
            detectors: vec!["aws-access-key-id".into()],
            guard_repaired: vec![SecretRef::new("bao://kv/c#d")],
            unscanned: vec![],
            chain_skipped: false,
        });
        let kinds: Vec<_> = evs.iter().map(v1::Event::kind).collect();
        assert_eq!(
            kinds,
            [
                v1::EventKind::Redaction,
                v1::EventKind::GuardRepair,
                v1::EventKind::DetectorHit
            ]
        );
        assert_eq!((evs[0].count, evs[0].snapshot_version), (3, 4));
        assert_eq!(evs[0].r#ref, "bao://kv/a#b");
        assert_eq!(evs[1].r#ref, "bao://kv/c#d");
        assert_eq!(evs[0].attrs.get("source").map(String::as_str), Some("llm"));

        let evs = convert_llm(E::Refused {
            route: Some("openai".into()),
            reason: RefusalReason::GuardRefused,
            refs: vec![],
        });
        assert_eq!(evs[0].kind(), v1::EventKind::GuardRefusal);
        assert_eq!(evs[0].effect(), v1::Effect::Deny);
        assert_eq!(evs[0].reason, "guard_refused");
        let evs = convert_llm(E::Refused {
            route: None,
            reason: RefusalReason::NotReady,
            refs: vec![],
        });
        assert_eq!(evs[0].kind(), v1::EventKind::Error);
        let evs = convert_llm(E::Restored {
            route: "anthropic".into(),
            resolved: 2,
            kept: 1,
        });
        assert_eq!(evs[0].kind(), v1::EventKind::Restore);
        assert_eq!(evs[0].attrs.get("kept").map(String::as_str), Some("1"));
    }
}
