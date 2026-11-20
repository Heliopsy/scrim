// SPDX-License-Identifier: AGPL-3.0-only

//! The scrim data plane (design D1, D11, D12).
//!
//! The control plane starts this binary as a child and hands it one end of a
//! socketpair. Over that socket the data plane serves the gRPC service in
//! `proto/scrim/dataplane/v1`: it takes versioned snapshots (value
//! dictionary, placeholder keys, compiled policy, routes, listeners), streams
//! events back, and asks the control plane only when a rule says "ask".
//!
//! Module seams for the feature work:
//!
//! - [`snapshot`]: one control-plane snapshot becomes the redaction core
//!   (`scrim-redact`), the LLM proxy's engine and routes (`scrim-llm`) and the
//!   tool proxy's credentials (`scrim-toolproxy`), built off the request path
//!   and published together by [`engine::Shared::apply`].
//! - [`engine`]: the engines and the state they share; the traffic path reads
//!   the snapshot in force through [`engine::Engine`].
//! - [`listeners`]: base-URL listeners (TCP and Unix socket) serve the LLM
//!   proxy; tool-proxy and forward-proxy listeners serve the HTTPS tool proxy,
//!   which hands provider hosts to the LLM proxy. Transparent listeners are
//!   still to come.
//! - [`policy`]: restore and injection decisions (a conservative stand-in
//!   until the decision-table evaluator lands).
//! - [`audit`] and [`captures`]: audit events of both proxies and tool-proxy
//!   captures reach the control plane over the Events and Captures streams.
//!
//! The process exits when the control plane's end of the socket closes, so a
//! dead control plane never leaves a data plane serving traffic.

pub mod asks;
pub mod audit;
pub mod captures;
pub mod engine;
pub mod events;
pub mod harden;
pub mod inherit;
pub mod listeners;
pub mod policy;
pub mod server;
pub mod settings;
pub mod snapshot;

/// The data plane build version reported in Hello, Status and `--version`.
/// Release builds set `SCRIM_BUILD_VERSION`; other builds report the crate
/// version.
pub const VERSION: &str = match option_env!("SCRIM_BUILD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};
