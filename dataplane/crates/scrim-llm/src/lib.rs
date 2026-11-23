// SPDX-License-Identifier: AGPL-3.0-only

//! scrim LLM proxy.
//!
//! Sits between agents and model providers on a local base URL. Every request body is redacted
//! on its raw bytes and checked by an independent guard before it leaves; responses, streamed or
//! not, have their placeholders resolved where the restore policy allows. Anything that cannot
//! be made safe is refused with a documented error and nothing reaches the provider.
//!
//! ```text
//! agent ──▶ listener (TCP or Unix, HTTP/1.1 or h2c)
//!             │ route by path prefix
//!             ▼
//!           codec plan ─▶ redactor over raw bytes ─▶ guard over exact bytes ─▶ capture
//!           (body; the request target and headers get the same two checks in [`head`])
//!             │                                                     (refuse on any error)
//!             ▼
//!           [chained upstream] ─▶ provider (rustls, pooled, HTTP/1.1 or HTTP/2)
//!             │
//!             ▼
//!           response: SSE restore per content block, or JSON restore ─▶ agent
//! ```
//!
//! The redaction engine is behind the traits in [`engine`]; the control plane supplies them in a
//! [`Snapshot`] that is swapped atomically. Start with [`Proxy::new`] and one of the `serve_*`
//! functions in [`server`].
//!
//! Supported APIs: Anthropic Messages, `OpenAI` Chat Completions, `OpenAI` Responses and Gemini
//! `generateContent`, streaming and not, and Amazon Bedrock (Anthropic bodies on `InvokeModel`,
//! Converse, both with the binary event stream). Routes for cloud providers authenticate the redacted request themselves
//! ([`auth`]). Other paths on a provider route are forwarded with the whole body redacted and the
//! response passed through.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod audit;
pub mod auth;
mod body;
pub mod capture;
pub mod codec;
pub mod config;
#[cfg(feature = "redact")]
pub mod core;
pub mod engine;
pub mod error;
pub mod eventstream;
pub mod head;
#[cfg(feature = "intercept")]
pub mod intercept;
pub mod json;
mod jsonarray;
pub mod metrics;
pub mod outgoing;
pub mod proxy;
mod restore;
pub mod route;
pub mod server;
mod sse;
pub mod stream;
pub mod token;
pub mod upstream;

#[cfg(feature = "test-util")]
pub mod testing;

pub use audit::{AuditEvent, AuditSink, NoAudit, RefusalReason};
pub use body::{BoxError, ProxyBody};
pub use codec::Api;
pub use config::{ChainConfig, OnUnavailable, Provider, ProxyConfig, RouteConfig};
pub use engine::{
    Admission, BinaryPolicy, EngineError, Guard, GuardVerdict, KeepAll, PlaceholderMatch,
    Placeholders, RedactReport, Redactor, RequestGate, RequestInfo, Resolved, RestoreDecision,
    RestorePolicy, RestoreSite, SecretRef, SecretValue, Snapshot, SnapshotCell, SnapshotSource,
    ToolInputRestore, ToolMode, ValueClass,
};
pub use error::{ERROR_HEADER, Refusal};
pub use metrics::LlmMetrics;
pub use proxy::{BuildError, Proxy, SESSION_HEADER};
pub use stream::{ChunkRestore, SseRestorer, restore_json};
