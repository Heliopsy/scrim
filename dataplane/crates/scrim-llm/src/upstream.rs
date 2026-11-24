// SPDX-License-Identifier: AGPL-3.0-only

//! Upstream HTTP client: pooled connections, HTTP/1.1 and HTTP/2 (ALPN), rustls with webpki
//! and/or native roots, through the upstream proxy in force when one is set
//! ([`scrim_upstream_proxy`]).

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use scrim_upstream_proxy::ProxyConnector;

use crate::config::{ProxyConfig, Roots};

/// The client type used for every upstream.
///
/// Names resolve through [`scrim_dns::LoopSafeResolver`], which never answers with scrim's own SNI
/// listener (DNS override mode points provider names at it). Destinations the upstream proxy in
/// force applies to are tunnelled through it instead and resolved by the proxy; TLS to the
/// destination runs inside the tunnel and is verified against the destination's name.
pub type UpstreamClient =
    Client<HttpsConnector<ProxyConnector<HttpConnector<scrim_dns::LoopSafeResolver>>>, Full<Bytes>>;

/// Upstream TLS setup failed.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The extra CA file could not be read or parsed.
    #[error("extra CA file: {0}")]
    ExtraCa(String),
    /// No trust roots at all.
    #[error("no TLS trust roots available")]
    NoRoots,
}

fn root_store(cfg: &ProxyConfig) -> Result<rustls::RootCertStore, TlsError> {
    let mut roots = rustls::RootCertStore::empty();
    if matches!(cfg.tls.roots, Roots::Webpki | Roots::Both) {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if matches!(cfg.tls.roots, Roots::Native | Roots::Both) {
        let native = rustls_native_certs::load_native_certs();
        if !native.errors.is_empty() {
            tracing::debug!(
                errors = native.errors.len(),
                "some native certificates could not be loaded"
            );
        }
        let (added, ignored) = roots.add_parsable_certificates(native.certs);
        tracing::debug!(added, ignored, "native trust roots");
    }
    if let Some(path) = &cfg.tls.extra_ca_file {
        let pem = std::fs::read(path)
            .map_err(|e| TlsError::ExtraCa(format!("{}: {e}", path.display())))?;
        let mut rd = std::io::Cursor::new(pem);
        let mut n = 0;
        for c in rustls_pemfile::certs(&mut rd) {
            let c = c.map_err(|e| TlsError::ExtraCa(format!("{}: {e}", path.display())))?;
            roots
                .add(c)
                .map_err(|e| TlsError::ExtraCa(format!("{}: {e}", path.display())))?;
            n += 1;
        }
        if n == 0 {
            return Err(TlsError::ExtraCa(format!(
                "{}: no certificates found",
                path.display()
            )));
        }
    }
    if roots.is_empty() {
        return Err(TlsError::NoRoots);
    }
    Ok(roots)
}

/// Builds the pooled upstream client.
pub fn build_client(cfg: &ProxyConfig) -> Result<UpstreamClient, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::NoRoots)?
        .with_root_certificates(root_store(cfg)?)
        .with_no_client_auth();
    let mut http = HttpConnector::new_with_resolver(scrim_dns::LoopSafeResolver);
    http.enforce_http(false);
    http.set_connect_timeout(Some(cfg.connect_timeout()));
    http.set_nodelay(true);
    // An https:// upstream proxy is verified with the same roots as the providers.
    let http = ProxyConnector::new(
        http,
        cfg.upstream_proxy.clone(),
        Arc::new(tls.clone()),
        cfg.connect_timeout(),
    );
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Ok(Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(cfg.pool_max_idle_per_host)
        .build(https))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_with_each_root_choice() {
        for roots in [Roots::Webpki, Roots::Both] {
            let mut cfg = ProxyConfig::default();
            cfg.tls.roots = roots;
            assert!(root_store(&cfg).unwrap().len() > 10);
        }
    }

    #[test]
    fn bad_extra_ca_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ca.pem");
        std::fs::write(&p, "not a certificate").unwrap();
        let mut cfg = ProxyConfig::default();
        cfg.tls.extra_ca_file = Some(p);
        assert!(matches!(root_store(&cfg), Err(TlsError::ExtraCa(_))));
    }
}
