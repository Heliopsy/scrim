// SPDX-License-Identifier: AGPL-3.0-only

//! Regenerates the Rust boundary types from `proto/` into
//! `dataplane/crates/scrim-proto/src/gen`.
//!
//! The output is committed (design D12) so a data plane build needs neither
//! protoc nor this generator. protox compiles the schema in pure Rust, so the
//! output does not depend on which protoc is installed. CI runs `just proto`
//! and fails when the committed files differ.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let proto_dir = root.join("proto");
    let out_dir = root.join("dataplane/crates/scrim-proto/src/gen");

    let fds = protox::compile(["scrim/dataplane/v1/dataplane.proto"], [&proto_dir])?;

    let mut config = prost_build::Config::new();
    // These messages hold secret material; scrim-proto implements a
    // redacting Debug for them by hand.
    config.skip_debug([
        ".scrim.dataplane.v1.ValueEntry",
        ".scrim.dataplane.v1.PlaceholderKey",
        ".scrim.dataplane.v1.CaptureRequest",
        ".scrim.dataplane.v1.CaCertificate",
        ".scrim.dataplane.v1.AskCaller",
        ".scrim.dataplane.v1.RedactRequest",
        ".scrim.dataplane.v1.UpstreamProxy",
    ]);

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .build_transport(false)
        .out_dir(&out_dir)
        .compile_fds_with_config(fds, config)?;
    Ok(())
}
