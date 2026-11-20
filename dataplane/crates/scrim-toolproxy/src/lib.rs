//! The scrim HTTPS tool proxy.
//!
//! Agents keep placeholders in their commands, files and configuration: generated ones
//! (`⟦scrim:acme:…⟧`), user-declared ones (`SCRIM_ACME_KEY`) and reference placeholders
//! (`{{scrim:bao://kv/agents/acme#key}}`). This crate is the forward proxy their tools talk to. It
//! terminates TLS with scrim's own CA, swaps each placeholder for the real credential only on
//! requests toward the hosts, methods, paths and request locations that credential is bound to,
//! and redacts known values out of every response so the agent sees placeholders back.
//!
//! The guarantees, all fail-closed:
//!
//! - A placeholder toward a destination its credential is not bound to is refused with
//!   [`ErrorCode::UnboundDestination`] and audited. Nothing is sent upstream.
//! - A placeholder in an undeclared location (a header-only credential in a body) is refused.
//! - Substitution covers the URL, headers (Basic credentials decoded and re-encoded), cookies,
//!   JSON, form, XML and multipart bodies, through gzip, deflate, br and zstd, with
//!   `Content-Length` and digest headers recomputed. A body that cannot be rewritten safely is
//!   refused, never sent half substituted.
//! - Responses are redacted in headers, trailers and bodies, buffered or streamed, compressed or
//!   not. A response that cannot be scanned is withheld.
//! - Capture rules store a token an API returns and hand the agent its placeholder; if storing
//!   fails the field is withheld.
//!
//! # Wiring
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use scrim_toolproxy::{Snapshot, ToolProxy, ToolProxyConfig, SecretValue};
//!
//! let proxy = ToolProxy::builder().build()?;
//! let config: ToolProxyConfig = serde_json::from_str(r#"{"credentials": [{
//!     "name": "acme", "reference": "env://ACME_KEY",
//!     "placeholders": ["SCRIM_ACME_KEY"],
//!     "binding": {"hosts": ["api.acme.example"]}}]}"#)?;
//! let snapshot = Snapshot::from_config(1, &config, |_reference| Some(SecretValue::new("from the store")), |_, _| vec![])?;
//! proxy.apply(snapshot);
//! std::fs::write("/run/scrim/ca.pem", proxy.ca().trust_bundle_pem())?;
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:8899").await?;
//! proxy.serve(listener, std::future::pending()).await?;
//! # Ok(()) }
//! ```
//!
//! The redaction core plugs in through [`Redactor`] ([`Snapshot::redactor`]), the control plane
//! through [`AuditSink`] and [`CaptureSink`], the LLM proxy through [`InterceptHandler`], and
//! request re-signing (AWS `SigV4`, task 10a.2) through [`RequestSigner`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod audit;
mod body;
mod ca;
mod capture;
mod codec;
mod credential;
mod digest;
mod engine;
mod error;
mod host;
mod inject;
mod multipart;
mod proto;
mod proxy;
mod redactor;
mod request;
mod response;
mod secret;
mod upstream;

pub use audit::{AuditEvent, AuditSink, ChannelAuditSink, MemoryAuditSink, TracingAuditSink};
pub use body::{BoxError, ProxyBody, empty, full};
pub use ca::{CaError, CaOptions, CaRing, CertificateAuthority, LeafSettings};
pub use capture::{
    CaptureError, CaptureFuture, CaptureRequest, CaptureRule, CaptureRuleSpec, CaptureSink,
    CaptureSource, RefusingCaptureSink, WITHHELD_MARKER,
};
pub use codec::Coding;
pub use credential::{
    Binding, BindingSpec, Credential, CredentialSet, CredentialSetBuilder, CredentialSpec,
    Location, Locations, MIN_DECLARED_PLACEHOLDER_LEN, Placeholder, PlaceholderKind,
    ValidationError,
};
pub use engine::{RequestSigner, Snapshot, ToolProxyConfig};
pub use error::{ErrorCode, Refusal};
pub use host::{Destination, HostPattern, HostPatternError, Scheme};
pub use proxy::{
    BuildError, InterceptHandler, ProxyStatus, ToolProxy, ToolProxyBuilder, ToolProxySettings,
};
pub use redactor::{
    CoreRedactor, RedactError, RedactMatch, Redactor, RedactorChain, StreamRedactor, ValueRedactor,
    redact_all,
};
pub use secret::SecretValue;
pub use upstream::{UpstreamSettings, UpstreamSetupError};
