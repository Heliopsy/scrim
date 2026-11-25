// SPDX-License-Identifier: AGPL-3.0-only

//! Generated types for the boundary between the scrim control plane and data
//! plane (design D12), from `proto/scrim/dataplane/v1/dataplane.proto`.
//!
//! The generated code under `src/gen` is committed and regenerated with
//! `just proto` (see `dataplane/tools/protogen`), so building the data plane
//! needs no protoc. CI fails if the committed output is stale.
//!
//! [`v1::ValueEntry`], [`v1::PlaceholderKey`], [`v1::UpstreamProxy`] and the
//! other messages listed in `secret_fields` carry secret material. Their
//! `Debug` output is redacted and their bytes are zeroed on drop. The
//! generated clients and servers use [`wipe::WipingCodec`], and the data
//! plane wraps its service in [`wipe::WipeBodies`], so the encoded copies are
//! zeroed as well.

/// Protocol version 1 of the boundary.
pub mod v1 {
    #![allow(
        missing_docs,
        unreachable_pub,
        clippy::all,
        clippy::pedantic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )]
    include!("gen/scrim.dataplane.v1.rs");

    /// The protocol version this build speaks.
    pub const PROTOCOL: u32 = ProtocolVersion::Current as u32;
}

mod secret_fields;
pub mod wipe;

pub use secret_fields::REDACTED;
