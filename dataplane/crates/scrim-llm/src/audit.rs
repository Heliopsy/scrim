// SPDX-License-Identifier: AGPL-3.0-only

//! Audit events the proxy emits. Metadata only: never a value, a header value or body content.

use crate::engine::SecretRef;

/// Why a request was refused. Stable identifiers, also used as the `code` in error bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    /// No snapshot (value dictionary) loaded yet.
    NotReady,
    /// The path matched no route.
    NoRoute,
    /// The body could not be parsed well enough to redact it.
    MalformedBody,
    /// The body uses a content encoding the proxy cannot scan.
    UnsupportedEncoding,
    /// The body exceeded the configured limit.
    BodyTooLarge,
    /// The redactor returned an error.
    RedactorFailed,
    /// The guard returned an error.
    GuardFailed,
    /// The guard found a known value it could not repair.
    GuardRefused,
    /// Unscannable content under the `block` binary policy.
    UnscannableContent,
    /// Capture mode could not record the outgoing request.
    CaptureFailed,
    /// A configured chained upstream could not be reached and `on_unavailable` is `fail`.
    ChainUnavailable,
    /// The provider could not be reached.
    UpstreamUnavailable,
    /// The request gate ([`crate::RequestGate`]) refused it: a rule denied it, or an approval
    /// was denied or did not come in time.
    PolicyDenied,
    /// A protocol upgrade (WebSocket): the upgraded stream cannot be redacted.
    UpgradeUnsupported,
}

impl RefusalReason {
    /// Stable machine-readable code.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotReady => "not_ready",
            Self::NoRoute => "no_route",
            Self::MalformedBody => "malformed_body",
            Self::UnsupportedEncoding => "unsupported_encoding",
            Self::BodyTooLarge => "body_too_large",
            Self::RedactorFailed => "redactor_failed",
            Self::GuardFailed => "guard_failed",
            Self::GuardRefused => "guard_refused",
            Self::UnscannableContent => "unscannable_content",
            Self::CaptureFailed => "capture_failed",
            Self::ChainUnavailable => "chain_unavailable",
            Self::UpstreamUnavailable => "upstream_unavailable",
            Self::PolicyDenied => "policy_denied",
            Self::UpgradeUnsupported => "upgrade_unsupported",
        }
    }
}

/// One audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// A request was redacted and sent upstream.
    Forwarded {
        /// Route name.
        route: String,
        /// Snapshot version used.
        snapshot: u64,
        /// Replacements made by the redactor.
        replacements: usize,
        /// References the redactor replaced.
        refs: Vec<SecretRef>,
        /// Fallback detectors that fired.
        detectors: Vec<String>,
        /// The guard repaired something the redactor missed; references involved.
        guard_repaired: Vec<SecretRef>,
        /// Media types of unscannable parts forwarded under the `pass` policy.
        unscanned: Vec<String>,
        /// The chained upstream was skipped (`on_unavailable: direct`).
        chain_skipped: bool,
    },
    /// A request was refused; nothing was sent upstream.
    Refused {
        /// Route name, when one matched.
        route: Option<String>,
        /// Why.
        reason: RefusalReason,
        /// Secret references involved, for guard refusals.
        refs: Vec<SecretRef>,
    },
    /// A response finished; placeholder resolution counters.
    Restored {
        /// Route name.
        route: String,
        /// Placeholders resolved to values.
        resolved: u64,
        /// Placeholders kept (policy, credential class or unknown).
        kept: u64,
    },
}

/// Receives audit events. Must not block: implementations queue and batch (design D12).
pub trait AuditSink: Send + Sync {
    /// Records one event.
    fn record(&self, event: AuditEvent);
}

/// Drops every event. For tools and tests that do not audit.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAudit;

impl AuditSink for NoAudit {
    fn record(&self, _: AuditEvent) {}
}
