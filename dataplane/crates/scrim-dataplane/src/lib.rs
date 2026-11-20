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
//! - [`engine`]: redactor, guard, restorer and injector read the current
//!   snapshot through [`engine::Engine`].
//! - [`listeners`]: the listeners bound from the snapshot's listener list.
//!   Tool-proxy and forward-proxy listeners serve `scrim-toolproxy`; its audit
//!   events and captures reach the control plane through [`audit`] and
//!   [`captures`]. Base-URL and transparent listeners are still to come.
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
pub mod server;
pub mod snapshot;

/// The data plane build version reported in Hello, Status and `--version`.
/// Release builds set `SCRIM_BUILD_VERSION`; other builds report the crate
/// version.
pub const VERSION: &str = match option_env!("SCRIM_BUILD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};
