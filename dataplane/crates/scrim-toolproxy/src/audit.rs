//! Audit events emitted by the tool proxy.
//!
//! Events carry metadata only: credential aliases, store references, rule names, destinations,
//! methods, paths without query strings, counts and error codes. They never carry a value. The data
//! plane forwards them to the control plane in batches (design D12); [`AuditSink::record`] must not
//! block.

use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::error::ErrorCode;

/// One audit event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditEvent {
    /// A request was refused before anything was sent upstream.
    RequestRefused {
        /// Why.
        code: ErrorCode,
        /// Credentials whose placeholders the request carried.
        credentials: Vec<String>,
        /// `scheme://host:port`.
        destination: String,
        /// HTTP method.
        method: String,
        /// URL path, query removed.
        path: String,
        /// Explanation, free of values.
        message: String,
    },
    /// Credentials were injected into a request that was then sent upstream.
    CredentialInjected {
        /// Injected credentials.
        credentials: Vec<String>,
        /// `scheme://host:port`.
        destination: String,
        /// HTTP method.
        method: String,
        /// URL path, query removed.
        path: String,
    },
    /// Known values were replaced with placeholders in a response.
    ResponseRedacted {
        /// `scheme://host:port`.
        destination: String,
        /// Number of replacements.
        replacements: u64,
    },
    /// A response was withheld or cut off because it could not be scanned.
    ResponseWithheld {
        /// Why.
        code: ErrorCode,
        /// `scheme://host:port`.
        destination: String,
        /// Explanation, free of values.
        message: String,
    },
    /// A capture rule stored a value from a response.
    ValueCaptured {
        /// Rule name.
        rule: String,
        /// Store reference written.
        reference: String,
        /// `scheme://host:port`.
        destination: String,
    },
    /// A capture rule matched but storing failed; the field was withheld.
    CaptureFailed {
        /// Rule name.
        rule: String,
        /// Store reference that could not be written.
        reference: String,
        /// `scheme://host:port`.
        destination: String,
        /// Explanation, free of values.
        message: String,
    },
    /// A client refused the interception certificate (certificate pinning or missing trust) or
    /// did not speak TLS inside a CONNECT tunnel. The connection was closed, never passed through.
    InterceptionRefused {
        /// `host:port` of the CONNECT target.
        destination: String,
        /// TLS failure as reported by rustls.
        reason: String,
    },
}

/// Receives audit events. Implementations must be cheap and non-blocking.
pub trait AuditSink: Send + Sync + 'static {
    /// Records one event.
    fn record(&self, event: AuditEvent);
}

/// Writes events to `tracing` at INFO (refusals at WARN).
#[derive(Clone, Copy, Debug, Default)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, event: AuditEvent) {
        let json = serde_json::to_string(&event).unwrap_or_default();
        match event {
            AuditEvent::RequestRefused { .. }
            | AuditEvent::ResponseWithheld { .. }
            | AuditEvent::CaptureFailed { .. }
            | AuditEvent::InterceptionRefused { .. } => {
                tracing::warn!(target: "scrim::audit", "{json}");
            }
            _ => tracing::info!(target: "scrim::audit", "{json}"),
        }
    }
}

/// Keeps events in memory. For tests and `scrim proxy --capture` style inspection.
#[derive(Clone, Debug, Default)]
pub struct MemoryAuditSink(Arc<Mutex<Vec<AuditEvent>>>);

impl MemoryAuditSink {
    /// A new, empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of every event so far.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: AuditEvent) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event);
    }
}

/// Sends events into a Tokio channel, dropping none: the channel is unbounded and the control
/// plane connection drains it in batches.
#[derive(Clone, Debug)]
pub struct ChannelAuditSink(pub tokio::sync::mpsc::UnboundedSender<AuditEvent>);

impl AuditSink for ChannelAuditSink {
    fn record(&self, event: AuditEvent) {
        if self.0.send(event).is_err() {
            tracing::error!(target: "scrim::audit", "audit channel closed, event lost");
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}
