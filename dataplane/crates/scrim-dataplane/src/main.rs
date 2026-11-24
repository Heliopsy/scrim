// SPDX-License-Identifier: AGPL-3.0-only

//! `scrim-dataplane`: run by the scrim control plane, never by hand.
//!
//! The control plane connection is an inherited socket named by `--fd <n>` or
//! `SCRIM_DP_FD=<n>` (Unix; the control plane passes 3), or stdin and stdout
//! with `--stdio` or `SCRIM_DP_STDIO=1` (Windows, accepted on Unix too); see
//! [`scrim_dataplane::transport`]. `SCRIM_DP_MLOCK` is `auto` (lock memory when the
//! memlock limit allows, warn otherwise), `require` (refuse to start without
//! it) or `off`. Logs go to stderr as JSON lines, filtered by `SCRIM_DP_LOG`
//! (default `info`). `--version` prints the version and exits.

use std::io::Write;
use std::process::ExitCode;

use scrim_dataplane::transport::{self, Transport};
use scrim_dataplane::{harden, server};
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    if std::env::args().skip(1).any(|a| a == "--version") {
        let mut out = std::io::stdout().lock();
        return match writeln!(out, "scrim-dataplane {}", scrim_dataplane::VERSION) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_env("SCRIM_DP_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Harden before anything that could hold a secret is allocated.
    let mode = match std::env::var("SCRIM_DP_MLOCK").as_deref() {
        Ok("require") => harden::MlockMode::Require,
        Ok("off") => harden::MlockMode::Off,
        Ok("auto" | "") | Err(_) => harden::MlockMode::Auto,
        Ok(other) => {
            tracing::error!(value = other, "SCRIM_DP_MLOCK must be auto, require or off");
            return ExitCode::from(2);
        }
    };
    let hardening = match harden::apply(mode) {
        Ok(h) => h,
        Err(err) => {
            tracing::error!(%err, "refusing to start");
            return ExitCode::from(3);
        }
    };

    let transport = match transport::from(
        std::env::args().skip(1),
        std::env::var("SCRIM_DP_FD").ok(),
        std::env::var("SCRIM_DP_STDIO").ok().as_deref(),
    ) {
        Ok(t) => t,
        Err(err) => {
            tracing::error!(%err, "no control plane connection");
            return ExitCode::from(2);
        }
    };
    #[cfg(unix)]
    let socket = match transport {
        Transport::Fd(fd) => match scrim_dataplane::inherit::adopt(fd) {
            Ok(s) => Some(s),
            Err(err) => {
                tracing::error!(%err, fd, "cannot use the inherited socket");
                return ExitCode::from(2);
            }
        },
        Transport::Stdio => None,
    };
    #[cfg(not(unix))]
    if let Transport::Fd(fd) = transport {
        tracing::error!(
            fd,
            "descriptor inheritance is not supported on Windows; pass --stdio"
        );
        return ExitCode::from(2);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!(%err, "cannot start the runtime");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(unix)]
    let result = match socket {
        Some(socket) => runtime.block_on(server::run_socket(socket, hardening)),
        None => run_stdio(runtime, hardening),
    };
    #[cfg(not(unix))]
    let result = run_stdio(runtime, hardening);
    match result {
        Ok(()) => {
            tracing::info!("control plane closed the connection; exiting");
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(%err, "serving the control plane failed");
            ExitCode::FAILURE
        }
    }
}

/// Serves over stdin and stdout. The runtime is shut down with a timeout: tokio reads stdin on a
/// blocking thread, and a read still pending would otherwise keep the process alive.
fn run_stdio(
    runtime: tokio::runtime::Runtime,
    hardening: harden::Hardening,
) -> std::io::Result<()> {
    let result = runtime.block_on(server::run_stdio(hardening));
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    result
}
