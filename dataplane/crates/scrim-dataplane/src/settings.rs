// SPDX-License-Identifier: AGPL-3.0-only

//! Process settings the control plane passes in the environment, for what the snapshot does not
//! carry.
//!
//! - `SCRIM_DP_EXTRA_CA_FILE`: a PEM bundle of extra roots trusted for upstream TLS, by the LLM
//!   proxy and the tool proxy alike (corporate TLS inspection, private API hosts, tests). The
//!   system and Mozilla roots stay trusted.
//! - `SCRIM_DP_CAPTURE_DIR` and `SCRIM_DP_CAPTURE_RETENTION_SECS`: capture mode (leak-assurance
//!   "Capture mode"); every provider request as it left and the response as received are written
//!   to the directory, which must not be accessible to group or others. Off when unset.
//! - `SCRIM_DP_METRICS`: `1` aggregates metrics for the control plane's Metrics call
//!   (`metrics.enabled`). Off otherwise: nothing is measured.

use std::path::PathBuf;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use scrim_llm::config::CaptureConfig;

/// Environment variable naming the extra CA bundle.
pub const EXTRA_CA_FILE: &str = "SCRIM_DP_EXTRA_CA_FILE";
/// Environment variable naming the capture directory.
pub const CAPTURE_DIR: &str = "SCRIM_DP_CAPTURE_DIR";
/// Environment variable with the capture retention in seconds.
pub const CAPTURE_RETENTION: &str = "SCRIM_DP_CAPTURE_RETENTION_SECS";
/// Environment variable that turns metrics on.
pub const METRICS: &str = "SCRIM_DP_METRICS";

/// Settings read once at start-up.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// Extra PEM roots for upstream TLS.
    pub extra_ca_file: Option<PathBuf>,
    /// Capture mode, off when `None`.
    pub capture: Option<CaptureConfig>,
    /// Aggregate metrics for the control plane.
    pub metrics: bool,
}

impl Settings {
    /// Reads the settings from the environment.
    pub fn from_env() -> Self {
        Self {
            extra_ca_file: std::env::var_os(EXTRA_CA_FILE)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            capture: std::env::var_os(CAPTURE_DIR)
                .filter(|v| !v.is_empty())
                .map(|dir| CaptureConfig {
                    dir: PathBuf::from(dir),
                    retention_secs: std::env::var(CAPTURE_RETENTION)
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .filter(|&n| n > 0)
                        .unwrap_or(7 * 24 * 3600),
                }),
            metrics: std::env::var(METRICS).is_ok_and(|v| v == "1" || v == "true"),
        }
    }

    /// The certificates in the extra CA file, none when it is not set. A file that is set but
    /// unreadable, or holds no certificate, is an error: the operator asked for trust that would
    /// silently be missing.
    pub fn extra_roots(&self) -> Result<Vec<CertificateDer<'static>>, String> {
        let Some(path) = &self.extra_ca_file else {
            return Ok(Vec::new());
        };
        let pem = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let certs = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if certs.is_empty() {
            return Err(format!("{}: no certificate found", path.display()));
        }
        Ok(certs)
    }
}
