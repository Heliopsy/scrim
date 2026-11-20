// SPDX-License-Identifier: AGPL-3.0-only

//! Process settings the control plane passes in the environment, for what the snapshot does not
//! carry.
//!
//! - `SCRIM_DP_EXTRA_CA_FILE`: a PEM bundle of extra roots trusted for upstream TLS, by the LLM
//!   proxy and the tool proxy alike (corporate TLS inspection, private API hosts, tests). The
//!   system and Mozilla roots stay trusted.

use std::path::PathBuf;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

/// Environment variable naming the extra CA bundle.
pub const EXTRA_CA_FILE: &str = "SCRIM_DP_EXTRA_CA_FILE";

/// Settings read once at start-up.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// Extra PEM roots for upstream TLS.
    pub extra_ca_file: Option<PathBuf>,
}

impl Settings {
    /// Reads the settings from the environment.
    pub fn from_env() -> Self {
        Self {
            extra_ca_file: std::env::var_os(EXTRA_CA_FILE)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
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
