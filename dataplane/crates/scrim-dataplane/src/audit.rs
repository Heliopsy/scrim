// SPDX-License-Identifier: AGPL-3.0-only

//! Turns tool-proxy audit events into boundary events for the control plane.

use std::collections::HashMap;
use std::sync::Arc;

use scrim_proto::v1;
use scrim_toolproxy::{AuditEvent, AuditSink};

use crate::events::Bus;

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
}
