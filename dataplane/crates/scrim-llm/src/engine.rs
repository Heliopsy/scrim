// SPDX-License-Identifier: AGPL-3.0-only

//! Contracts between the LLM proxy and the redaction core.
//!
//! The proxy never matches secrets itself. It hands raw request bytes to a [`Redactor`], the
//! result to an independent [`Guard`], and uses [`Placeholders`] plus a [`RestorePolicy`] to
//! resolve placeholders in responses. All four come from one [`Snapshot`], which the control
//! plane replaces atomically; a request loads the snapshot once and uses it from start to end.
//!
//! The redaction core (`scrim-redact`) provides the production implementations. The
//! `test-util` feature ships fakes for tests and benches.

use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use zeroize::Zeroizing;

/// Name of a secret reference, such as `github-token` or `prod/db/password`.
///
/// This is metadata, never a value, and is safe to log and audit.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretRef(Arc<str>);

impl SecretRef {
    /// Wraps a reference name.
    pub fn new(name: impl Into<Arc<str>>) -> Self {
        Self(name.into())
    }

    /// The reference name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretRef({})", self.0)
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a secret value may be used once a placeholder resolves to it (design D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueClass {
    /// A credential. Never restored into text, commands, files or tool arguments; it reaches its
    /// destination only through credential injection. The proxy enforces this regardless of the
    /// restore policy.
    Credential,
    /// Display data the agent may need to read or keep, restored under the tool policy.
    Display,
}

/// A secret value in memory. Wiped on drop, and printed as `[redacted]`.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Takes ownership of the bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The raw value. Callers must not log, print or persist it.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([redacted])")
    }
}

/// Error from the redactor, guard or placeholder layer.
///
/// The message is chosen by the implementation and must never contain a secret value or the
/// bytes being redacted. The proxy maps every engine error to the fail-closed refusal.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct EngineError {
    message: String,
}

impl EngineError {
    /// Creates an error. `message` must not contain secret values or request content.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The (value-free) message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// What the redactor did to one input.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RedactReport {
    /// Number of replacements made.
    pub replacements: usize,
    /// Secret references whose values were replaced, without duplicates.
    pub refs: Vec<SecretRef>,
    /// Fallback detectors that fired, by name.
    pub detectors: Vec<String>,
}

impl RedactReport {
    /// Merges another report into this one.
    pub fn merge(&mut self, other: RedactReport) {
        self.replacements += other.replacements;
        for r in other.refs {
            if !self.refs.contains(&r) {
                self.refs.push(r);
            }
        }
        for d in other.detectors {
            if !self.detectors.contains(&d) {
                self.detectors.push(d);
            }
        }
    }
}

/// Replaces known secret values (and their encoded variants) with placeholders in raw bytes.
pub trait Redactor: Send + Sync {
    /// Appends the redacted form of `input` to `out`. On error nothing may be forwarded.
    ///
    /// The output must be deterministic for a given snapshot so that an unchanged conversation
    /// prefix redacts to the same bytes on every request (prompt-cache stability).
    fn redact(&self, input: &[u8], out: &mut Vec<u8>) -> Result<RedactReport, EngineError>;
}

/// The guard's verdict over the exact outgoing bytes.
#[derive(Debug)]
pub enum GuardVerdict {
    /// No known value found.
    Clean,
    /// Known values were found and replaced; forward `bytes` instead.
    Repaired {
        /// The repaired outgoing bytes.
        bytes: Vec<u8>,
        /// References involved.
        refs: Vec<SecretRef>,
    },
    /// Known values were found and could not be repaired. The request must be refused.
    Refused {
        /// References involved.
        refs: Vec<SecretRef>,
    },
}

/// Independent second check over the exact bytes that would leave (design D4). It must not share
/// matching code with the [`Redactor`].
pub trait Guard: Send + Sync {
    /// Scans `outgoing`.
    fn check(&self, outgoing: &[u8]) -> Result<GuardVerdict, EngineError>;
}

/// Where a placeholder sits in a piece of text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderMatch {
    /// A complete, well-formed placeholder at `start..end`.
    Complete {
        /// Byte offset of the first placeholder byte.
        start: usize,
        /// Byte offset just past the placeholder.
        end: usize,
    },
    /// The text ends with `text[start..]`, which could still become a placeholder once more
    /// bytes arrive. `text.len() - start` is less than [`Placeholders::max_len`].
    Partial {
        /// Byte offset where the possible placeholder starts.
        start: usize,
    },
}

/// A placeholder that resolved to a value.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The secret reference.
    pub reference: SecretRef,
    /// The value's class.
    pub class: ValueClass,
    /// The value.
    pub value: Arc<SecretValue>,
}

/// Placeholder syntax and resolution (design D3).
pub trait Placeholders: Send + Sync {
    /// Length in bytes of the longest placeholder. Streams hold back at most `max_len() - 1`
    /// bytes per content block.
    fn max_len(&self) -> usize;

    /// Finds the first complete or trailing partial placeholder in `text`. Must be a char
    /// boundary-respecting byte offset (placeholders start with a non-continuation byte).
    fn find(&self, text: &str) -> Option<PlaceholderMatch>;

    /// Resolves a complete placeholder. `None` when it is unknown (for example made with a
    /// retired key or by another deployment); the proxy then emits it unchanged.
    fn resolve(&self, placeholder: &str) -> Option<Resolved>;
}

/// The place in a response where a placeholder would be resolved.
#[derive(Debug, Clone, Copy)]
pub enum RestoreSite<'a> {
    /// Text the agent displays to the user (assistant text, refusals).
    Text,
    /// Arguments of a tool call the model makes.
    ToolInput {
        /// The tool name as the model called it.
        tool: &'a str,
        /// The complete arguments (JSON text, or free-form input for custom tools) when known.
        /// `None` while arguments stream in, unless the policy asked for
        /// [`ToolMode::Buffered`].
        arguments: Option<&'a str>,
    },
}

/// The policy's answer for one placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreDecision {
    /// Replace the placeholder with the value, escaped for where it lands.
    Resolve,
    /// Leave the placeholder as is.
    Keep,
}

/// How the proxy feeds a tool call's arguments to the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolMode {
    /// Decide per placeholder while arguments stream; [`RestoreSite::ToolInput::arguments`] is
    /// `None` for streamed responses.
    Stream,
    /// Hold the tool call's argument deltas until the call is complete, then decide with the
    /// full arguments. Needed for rules such as "write tools only restore values already in
    /// the target file". Bounded by `limits.max_buffered_tool_input`; past it, every
    /// placeholder of that call is kept.
    Buffered,
}

/// Per-tool restore policy (design D5, redaction spec "Resolution follows tool policy").
///
/// Thinking, reasoning and signature content is never offered to the policy: it stays
/// byte-identical. Values of class [`ValueClass::Credential`] are never offered either.
pub trait RestorePolicy: Send + Sync {
    /// Decides one placeholder.
    fn decide(
        &self,
        site: &RestoreSite<'_>,
        reference: &SecretRef,
        class: ValueClass,
    ) -> RestoreDecision;

    /// How to feed `tool`'s arguments. Defaults to [`ToolMode::Stream`].
    fn tool_mode(&self, tool: &str) -> ToolMode {
        let _ = tool;
        ToolMode::Stream
    }

    /// Restores one tool call's complete arguments itself, each value escaped for where it
    /// lands (a shell word, a heredoc, an interpreter string), instead of the proxy inserting
    /// raw values where [`RestorePolicy::decide`] allows.
    ///
    /// Called with the complete arguments: buffered calls ([`ToolMode::Buffered`]) at their
    /// end, and tool calls of complete (non-streamed) responses. `arguments` is the JSON text of
    /// the arguments, or the free-form input of a custom tool, as the agent will receive it.
    /// `values` resolves display values only: credentials never resolve through it. `None`
    /// (the default) leaves the call to [`RestorePolicy::decide`].
    fn restore_tool_input(
        &self,
        tool: &str,
        arguments: &str,
        values: &dyn Placeholders,
    ) -> Option<ToolInputRestore> {
        let _ = (tool, arguments, values);
        None
    }
}

/// What [`RestorePolicy::restore_tool_input`] did to one tool call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolInputRestore {
    /// The rewritten arguments; `None` when nothing was resolved.
    pub text: Option<String>,
    /// Placeholders resolved.
    pub resolved: u64,
    /// Placeholders kept.
    pub kept: u64,
}

/// What the proxy knows about one request before anything is forwarded, for a [`RequestGate`].
#[derive(Debug, Clone, Copy)]
pub struct RequestInfo<'a> {
    /// The route that matched.
    pub route: &'a str,
    /// The route's provider (`anthropic`, `openai`).
    pub provider: &'a str,
    /// The request headers as the agent sent them (before scrim strips its own).
    pub headers: &'a http::HeaderMap,
    /// The request extensions: what the listener knows about the connection, such as
    /// [`crate::server::UnixPeer`] or the tool proxy's client information.
    pub extensions: &'a http::Extensions,
}

/// A narrower redactor and guard for one caller, built from the dictionary minus the values that
/// caller's own store identity cannot read (agent-identity spec, "Redaction coverage is separate
/// from use", only with the weakening setting `redaction.limit-to-agent-identity`). The two stay
/// independent: each comes from the same narrowed dictionary, as the snapshot-wide pair comes
/// from the whole one.
#[derive(Clone)]
pub struct ScopedRedaction {
    /// Request-side redactor for this caller.
    pub redactor: Arc<dyn Redactor>,
    /// Guard over this caller's outgoing bytes.
    pub guard: Arc<dyn Guard>,
}

impl fmt::Debug for ScopedRedaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopedRedaction(..)")
    }
}

/// A [`RequestGate`]'s answer.
pub enum Admission {
    /// Forward the request; restore its response under `policy` (the snapshot's restore policy
    /// bound to this request's caller).
    Forward {
        /// Restore policy for this request.
        policy: Arc<dyn RestorePolicy>,
        /// Redactor and guard for this request in place of the snapshot's, `None` for the
        /// snapshot's (the whole dictionary).
        redaction: Option<ScopedRedaction>,
    },
    /// Refuse with `policy_denied`. `detail` names the rule and never contains a value.
    Deny {
        /// Value-free explanation (rule name, why).
        detail: String,
    },
}

impl fmt::Debug for Admission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forward { .. } => f.write_str("Forward"),
            Self::Deny { detail } => f.debug_struct("Deny").field("detail", detail).finish(),
        }
    }
}

/// Decides, per request, whether it may go to the provider and with which restore policy
/// (design D7: policy decisions in the data plane, asking the control plane only when a rule
/// says so). Runs before the body is read; may wait (an approval), bounded by the gate.
pub trait RequestGate: Send + Sync {
    /// Decides one request.
    fn admit<'a>(
        &'a self,
        req: RequestInfo<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Admission> + Send + 'a>>;
}

/// Keeps every placeholder. The safe default until a policy snapshot arrives.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeepAll;

impl RestorePolicy for KeepAll {
    fn decide(&self, _: &RestoreSite<'_>, _: &SecretRef, _: ValueClass) -> RestoreDecision {
        RestoreDecision::Keep
    }
}

/// What to do with binary content parts (images, documents, audio) (`redaction.binary`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BinaryPolicy {
    /// Decode each part and scan it and the text it carries (metadata, document text) with the
    /// redactor and the guard. A secret found there, or a part that cannot be decoded within the
    /// bounds, refuses the request: a binary part cannot be redacted in place.
    #[default]
    Scan,
    /// Refuse every request that carries a binary part, naming the content type.
    Block,
    /// Forward unscanned and mark the request as containing unscanned content in the audit log.
    /// Weakening.
    Pass,
}

/// What to do with attachments a request only references: a URL the provider would fetch, a
/// provider file ID, a cloud storage location (`redaction.remote-attachments`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RemoteMode {
    /// Fetch each URL, scan the content under the binary policy and send it inline instead of
    /// the reference. File IDs pass only when scrim scanned their upload; anything else scrim
    /// cannot fetch refuses the request.
    #[default]
    Inline,
    /// Refuse every request with a reference, except file IDs whose upload scrim scanned.
    Refuse,
    /// Forward references unfetched; the provider fetches content scrim never sees. Weakening.
    Pass,
}

/// The remote attachment policy of a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemotePolicy {
    /// What to do with references.
    pub mode: RemoteMode,
    /// Networks a fetch may reach although they are private, loopback, link-local or otherwise
    /// not public (`redaction.remote-attachments-allowed-networks`). Empty: public addresses
    /// only.
    pub allowed_networks: Vec<crate::remote::Network>,
}

/// Everything a request needs from the control plane, swapped atomically.
#[derive(Clone)]
pub struct Snapshot {
    /// Version acknowledged back to the control plane.
    pub version: u64,
    /// Request-side redactor.
    pub redactor: Arc<dyn Redactor>,
    /// Independent guard.
    pub guard: Arc<dyn Guard>,
    /// Placeholder syntax and resolution.
    pub placeholders: Arc<dyn Placeholders>,
    /// Tool restore policy.
    pub policy: Arc<dyn RestorePolicy>,
    /// Policy for unscannable content.
    pub binary: BinaryPolicy,
    /// Policy for attachments referenced by URL or file ID.
    pub remote: RemotePolicy,
    /// Routes that come with this snapshot (the control plane's), so a request picks its route
    /// and its value dictionary from one version. `None` uses the routes the proxy was built
    /// with.
    pub routes: Option<Arc<crate::route::RouteTable>>,
    /// Per-request admission and restore policy. `None` forwards every request and restores
    /// under [`Snapshot::policy`].
    pub gate: Option<Arc<dyn RequestGate>>,
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("version", &self.version)
            .field("binary", &self.binary)
            .field("remote", &self.remote)
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

/// Where a cell built with [`SnapshotCell::from_source`] reads the snapshot in force, for an
/// embedder that publishes one bundle for several engines and swaps it once.
pub trait SnapshotSource: Send + Sync {
    /// The snapshot in force, if any.
    fn load(&self) -> Option<Arc<Snapshot>>;
}

/// Holds the current [`Snapshot`]. Empty until the first one is applied; requests are refused
/// with "redaction not ready" while it is empty.
#[derive(Default)]
pub struct SnapshotCell {
    inner: ArcSwapOption<Snapshot>,
    source: Option<Arc<dyn SnapshotSource>>,
}

impl SnapshotCell {
    /// An empty cell.
    pub fn new() -> Self {
        Self::default()
    }

    /// A cell that reads every snapshot from `source`. [`SnapshotCell::store`] and
    /// [`SnapshotCell::clear`] do nothing on it: the source decides what is in force.
    pub fn from_source(source: Arc<dyn SnapshotSource>) -> Self {
        Self {
            inner: ArcSwapOption::empty(),
            source: Some(source),
        }
    }

    /// A cell holding `snapshot`.
    pub fn with(snapshot: Snapshot) -> Self {
        let cell = Self::new();
        cell.store(snapshot);
        cell
    }

    /// Replaces the snapshot. In-flight requests keep the one they loaded.
    pub fn store(&self, snapshot: Snapshot) {
        self.inner.store(Some(Arc::new(snapshot)));
    }

    /// Empties the cell, for example when the control plane connection is lost.
    pub fn clear(&self) {
        self.inner.store(None);
    }

    /// The current snapshot, if any.
    pub fn load(&self) -> Option<Arc<Snapshot>> {
        match &self.source {
            Some(s) => s.load(),
            None => self.inner.load_full(),
        }
    }
}

impl fmt::Debug for SnapshotCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotCell")
            .field("version", &self.load().map(|s| s.version))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_debug_is_redacted() {
        let v = SecretValue::new(b"hunter2-hunter2".to_vec());
        assert_eq!(format!("{v:?}"), "SecretValue([redacted])");
        assert_eq!(v.expose(), b"hunter2-hunter2");
    }

    #[test]
    fn report_merge_dedups() {
        let mut a = RedactReport {
            replacements: 1,
            refs: vec![SecretRef::new("a")],
            detectors: vec!["x".into()],
        };
        a.merge(RedactReport {
            replacements: 2,
            refs: vec![SecretRef::new("a"), SecretRef::new("b")],
            detectors: vec!["x".into(), "y".into()],
        });
        assert_eq!(a.replacements, 3);
        assert_eq!(a.refs, vec![SecretRef::new("a"), SecretRef::new("b")]);
        assert_eq!(a.detectors, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn keep_all_keeps() {
        let d = KeepAll.decide(
            &RestoreSite::Text,
            &SecretRef::new("a"),
            ValueClass::Display,
        );
        assert_eq!(d, RestoreDecision::Keep);
        assert_eq!(KeepAll.tool_mode("bash"), ToolMode::Stream);
    }
}
