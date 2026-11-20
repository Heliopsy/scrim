//! The client side: connections from scrim to upstream servers.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use hyper_util::rt::TokioExecutor;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use tower_service::Service;

use crate::body::ProxyBody;

/// How scrim verifies upstream servers and resolves their names.
#[derive(Clone, Debug)]
pub struct UpstreamSettings {
    /// Trust the operating system's root store.
    pub native_roots: bool,
    /// Additional trusted roots (DER), for private CAs and tests.
    pub extra_roots: Vec<CertificateDer<'static>>,
    /// Fixed addresses for host names, checked before DNS. For tests and pinned internal hosts.
    pub resolve_overrides: HashMap<String, Vec<SocketAddr>>,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Idle pooled connections are closed after this long.
    pub pool_idle_timeout: Duration,
}

impl Default for UpstreamSettings {
    fn default() -> Self {
        Self {
            native_roots: true,
            extra_roots: Vec::new(),
            resolve_overrides: HashMap::new(),
            connect_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(90),
        }
    }
}

/// DNS with fixed overrides.
#[derive(Clone)]
pub(crate) struct OverrideResolver {
    overrides: Arc<HashMap<String, Vec<SocketAddr>>>,
    gai: GaiResolver,
}

type Addrs = std::vec::IntoIter<SocketAddr>;

impl Service<Name> for OverrideResolver {
    type Response = Addrs;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Addrs, std::io::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        if let Some(addrs) = self.overrides.get(&name.as_str().to_ascii_lowercase()) {
            let addrs = addrs.clone();
            return Box::pin(async move { Ok(addrs.into_iter()) });
        }
        let mut gai = self.gai.clone();
        Box::pin(async move {
            let it = gai.call(name).await?;
            Ok(it.collect::<Vec<_>>().into_iter())
        })
    }
}

pub(crate) type HttpsClient =
    Client<hyper_rustls::HttpsConnector<HttpConnector<OverrideResolver>>, ProxyBody>;

/// Upstream client errors.
#[derive(Debug, thiserror::Error)]
#[error("upstream TLS setup failed: {0}")]
pub struct UpstreamSetupError(pub String);

pub(crate) fn build_client(s: &UpstreamSettings) -> Result<HttpsClient, UpstreamSetupError> {
    let mut roots = RootCertStore::empty();
    if s.native_roots {
        let native = rustls_native_certs::load_native_certs();
        for c in native.certs {
            let _ = roots.add(c);
        }
    }
    for c in &s.extra_roots {
        roots
            .add(c.clone())
            .map_err(|e| UpstreamSetupError(e.to_string()))?;
    }
    if roots.is_empty() {
        tracing::warn!("no trusted upstream roots: every HTTPS upstream will fail verification");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| UpstreamSetupError(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let resolver = OverrideResolver {
        overrides: Arc::new(s.resolve_overrides.clone()),
        gai: GaiResolver::new(),
    };
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    http.set_connect_timeout(Some(s.connect_timeout));
    http.set_nodelay(true);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http);
    Ok(Client::builder(TokioExecutor::new())
        .pool_idle_timeout(s.pool_idle_timeout)
        .build(https))
}
