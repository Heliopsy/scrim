//! The forward proxy listener: HTTP CONNECT with TLS interception and plain HTTP proxying.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http::{Method, Request, Response};
use http_body::Body;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

use crate::audit::{AuditEvent, AuditSink, TracingAuditSink};
use crate::body::{BoxError, ProxyBody, empty, full};
use crate::ca::{CaOptions, CaRing, CertificateAuthority, LeafSettings};
use crate::capture::{CaptureSink, CapturedValues, RefusingCaptureSink};
use crate::credential::ValidationError;
use crate::decide::ClientInfo;
use crate::engine::{Engine, RequestSigner, Snapshot};
use crate::error::{ErrorCode, Refusal};
use crate::host::{Destination, Scheme};
use crate::upstream::{HttpsClient, UpstreamSettings, UpstreamSetupError, build_client};

/// Limits of the tool proxy.
#[derive(Clone, Debug)]
pub struct ToolProxySettings {
    /// Bodies up to this size are buffered and rewritten. Larger request bodies are streamed and
    /// refused if a placeholder shows up in them; larger responses are streamed through the
    /// redactor. Config key `toolproxy.max_buffered_body_bytes`, default 32 MiB.
    pub max_buffered_body: usize,
    /// Limit on a decoded (decompressed) buffered body. Config key
    /// `toolproxy.max_decoded_body_bytes`, default 128 MiB.
    pub max_decoded_body: u64,
    /// How many captured values are kept for redaction until the control plane's snapshot
    /// includes them. Config key `toolproxy.captured_values_capacity`, default 1024.
    pub captured_values_capacity: usize,
}

impl Default for ToolProxySettings {
    fn default() -> Self {
        Self {
            max_buffered_body: 32 << 20,
            max_decoded_body: 128 << 20,
            captured_values_capacity: 1024,
        }
    }
}

/// Hands decrypted requests for some destinations to another engine (the LLM proxy for model
/// provider hosts), so one forward-proxy listener serves both.
pub trait InterceptHandler: Send + Sync + 'static {
    /// Whether requests toward `dest` belong to this handler.
    fn claims(&self, dest: &Destination) -> bool;
    /// Handles one decrypted request.
    fn handle(
        &self,
        dest: Destination,
        req: Request<ProxyBody>,
    ) -> Pin<Box<dyn Future<Output = Response<ProxyBody>> + Send>>;
}

/// A snapshot compiled by [`ToolProxy::compile`], ready to be put in force. Cheap to clone.
#[derive(Clone)]
pub struct CompiledSnapshot(Arc<Engine>);

impl CompiledSnapshot {
    /// The snapshot version.
    pub fn version(&self) -> u64 {
        self.0.version
    }
}

impl std::fmt::Debug for CompiledSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledSnapshot")
            .field("version", &self.0.version)
            .finish_non_exhaustive()
    }
}

/// Where a proxy built with [`ToolProxyBuilder::snapshot_source`] reads the snapshot in force,
/// for an embedder that publishes one bundle for several engines and swaps it once. Each
/// request reads it once and keeps what it got to the end.
pub trait SnapshotSource: Send + Sync + 'static {
    /// The compiled snapshot in force, if any.
    fn current(&self) -> Option<CompiledSnapshot>;
}

/// State shared by every connection.
pub(crate) struct Shared {
    pub(crate) engine: ArcSwapOption<Engine>,
    source: Option<Arc<dyn SnapshotSource>>,
    pub(crate) ca: CaRing,
    pub(crate) client: HttpsClient,
    pub(crate) audit: Arc<dyn AuditSink>,
    pub(crate) capture_sink: Arc<dyn CaptureSink>,
    pub(crate) captured: Arc<CapturedValues>,
    pub(crate) intercept: Option<Arc<dyn InterceptHandler>>,
    pub(crate) signers: Vec<Arc<dyn RequestSigner>>,
    pub(crate) settings: ToolProxySettings,
    unsupported: Mutex<BTreeMap<String, String>>,
}

/// Builder for [`ToolProxy`].
pub struct ToolProxyBuilder {
    settings: ToolProxySettings,
    upstream: UpstreamSettings,
    ca: Option<CertificateAuthority>,
    leaf: LeafSettings,
    audit: Arc<dyn AuditSink>,
    capture_sink: Arc<dyn CaptureSink>,
    intercept: Option<Arc<dyn InterceptHandler>>,
    signers: Vec<Arc<dyn RequestSigner>>,
    source: Option<Arc<dyn SnapshotSource>>,
}

impl Shared {
    /// The engine in force: from the source when there is one, else the last applied.
    pub(crate) fn current(&self) -> Option<Arc<Engine>> {
        match &self.source {
            Some(s) => s.current().map(|c| c.0),
            None => self.engine.load_full(),
        }
    }
}

impl ToolProxyBuilder {
    /// Limits.
    #[must_use]
    pub fn settings(mut self, s: ToolProxySettings) -> Self {
        self.settings = s;
        self
    }
    /// Upstream trust, DNS overrides and timeouts.
    #[must_use]
    pub fn upstream(mut self, u: UpstreamSettings) -> Self {
        self.upstream = u;
        self
    }
    /// The interception CA. A fresh one is generated when none is given.
    #[must_use]
    pub fn ca(mut self, ca: CertificateAuthority) -> Self {
        self.ca = Some(ca);
        self
    }
    /// Leaf certificate validity and cache size.
    #[must_use]
    pub fn leaf_settings(mut self, l: LeafSettings) -> Self {
        self.leaf = l;
        self
    }
    /// Where audit events go. Default: `tracing`.
    #[must_use]
    pub fn audit(mut self, a: Arc<dyn AuditSink>) -> Self {
        self.audit = a;
        self
    }
    /// Where captured values are stored. Default: nowhere, captured fields are withheld.
    #[must_use]
    pub fn capture_sink(mut self, c: Arc<dyn CaptureSink>) -> Self {
        self.capture_sink = c;
        self
    }
    /// Handler for destinations another engine owns (model providers).
    #[must_use]
    pub fn intercept(mut self, h: Arc<dyn InterceptHandler>) -> Self {
        self.intercept = Some(h);
        self
    }
    /// Reads the snapshot in force from `source` instead of [`ToolProxy::apply`]; compile
    /// snapshots with [`ToolProxy::compile`] and publish them through the source.
    #[must_use]
    pub fn snapshot_source(mut self, source: Arc<dyn SnapshotSource>) -> Self {
        self.source = Some(source);
        self
    }
    /// Adds a request re-signer.
    #[must_use]
    pub fn signer(mut self, s: Arc<dyn RequestSigner>) -> Self {
        self.signers.push(s);
        self
    }

    /// Builds the proxy. It refuses traffic until [`ToolProxy::apply`] is called.
    pub fn build(self) -> Result<ToolProxy, BuildError> {
        let ca = match self.ca {
            Some(c) => c,
            None => CertificateAuthority::generate(&CaOptions::default())
                .map_err(|e| BuildError(e.to_string()))?,
        };
        let client = build_client(&self.upstream).map_err(|UpstreamSetupError(e)| BuildError(e))?;
        Ok(ToolProxy {
            shared: Arc::new(Shared {
                engine: ArcSwapOption::empty(),
                source: self.source,
                ca: CaRing::new(ca, self.leaf),
                client,
                audit: self.audit,
                capture_sink: self.capture_sink,
                captured: Arc::new(CapturedValues::new(self.settings.captured_values_capacity)),
                intercept: self.intercept,
                signers: self.signers,
                settings: self.settings,
                unsupported: Mutex::new(BTreeMap::new()),
            }),
        })
    }
}

/// Building the proxy failed.
#[derive(Debug, thiserror::Error)]
#[error("tool proxy setup failed: {0}")]
pub struct BuildError(pub String);

/// Health of the tool proxy, for `scrim status`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProxyStatus {
    /// A snapshot is applied and the redactor is ready.
    pub ready: bool,
    /// Version of the applied snapshot.
    pub snapshot_version: Option<u64>,
    /// Destinations whose clients refused the interception certificate, with the TLS error.
    pub unsupported_destinations: BTreeMap<String, String>,
    /// Leaf certificates in the cache.
    pub cached_leaves: usize,
}

/// The HTTPS tool proxy. Cheap to clone.
#[derive(Clone)]
pub struct ToolProxy {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for ToolProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolProxy")
            .field("status", &self.status())
            .finish()
    }
}

fn refusal_response(r: &Refusal) -> Response<ProxyBody> {
    r.to_response().map(full)
}

impl ToolProxy {
    /// Starts a builder with defaults.
    pub fn builder() -> ToolProxyBuilder {
        ToolProxyBuilder {
            settings: ToolProxySettings::default(),
            upstream: UpstreamSettings::default(),
            ca: None,
            leaf: LeafSettings::default(),
            audit: Arc::new(TracingAuditSink),
            capture_sink: Arc::new(RefusingCaptureSink),
            intercept: None,
            signers: Vec::new(),
            source: None,
        }
    }

    /// Applies a snapshot atomically. Requests in flight finish with the snapshot they started
    /// with. Returns the applied version, to acknowledge to the control plane.
    ///
    /// A snapshot that fails to compile is rejected and the previous one stays in force.
    ///
    /// A proxy built with a [`SnapshotSource`] ignores applied snapshots; publish through the
    /// source instead.
    pub fn apply(&self, snapshot: Snapshot) -> Result<u64, ValidationError> {
        let compiled = self.compile(snapshot)?;
        let v = compiled.version();
        self.shared.engine.store(Some(compiled.0));
        Ok(v)
    }

    /// Compiles a snapshot without putting it in force, for a [`SnapshotSource`]. Fails like
    /// [`ToolProxy::apply`].
    pub fn compile(&self, snapshot: Snapshot) -> Result<CompiledSnapshot, ValidationError> {
        Engine::compile(snapshot, self.shared.captured.clone())
            .map(|e| CompiledSnapshot(Arc::new(e)))
    }

    /// The interception CA ring: export the trust bundle, rotate.
    pub fn ca(&self) -> &CaRing {
        &self.shared.ca
    }

    /// Current status.
    pub fn status(&self) -> ProxyStatus {
        let engine = self.shared.current();
        ProxyStatus {
            ready: engine.as_ref().is_some_and(|e| e.redactors.is_ready()),
            snapshot_version: engine.as_ref().map(|e| e.version),
            unsupported_destinations: self
                .shared
                .unsupported
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            cached_leaves: self.shared.ca.cached_leaves(),
        }
    }

    /// Accepts connections until `shutdown` resolves. Connections already accepted run to
    /// completion on their own tasks.
    pub async fn serve(
        &self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()>,
    ) -> std::io::Result<()> {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(x) => x,
                        Err(e) => {
                            tracing::warn!(error = %e, "accept failed");
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);
                    let this = self.clone();
                    tokio::spawn(async move { this.serve_connection(stream, Some(peer)).await });
                }
            }
        }
    }

    /// Serves one proxy client connection (TCP, Unix socket or anything else).
    pub async fn serve_connection<IO>(&self, io: IO, peer: Option<SocketAddr>)
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let this = self.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let this = this.clone();
            async move { Ok::<_, Infallible>(this.proxy_request(req, peer).await) }
        });
        if let Err(e) = hyper::server::conn::http1::Builder::new()
            .preserve_header_case(false)
            .serve_connection(TokioIo::new(io), svc)
            .with_upgrades()
            .await
        {
            tracing::debug!(error = %e, ?peer, "proxy connection ended with an error");
        }
    }

    async fn proxy_request(
        &self,
        mut req: Request<Incoming>,
        peer: Option<SocketAddr>,
    ) -> Response<ProxyBody> {
        let client = ClientInfo {
            peer,
            session: ClientInfo::session_from(req.headers()),
        };
        if req.method() == Method::CONNECT {
            let Some(dest) = req
                .uri()
                .authority()
                .and_then(|a| Destination::from_authority(Scheme::Https, a.as_str()))
            else {
                return refusal_response(&Refusal::new(
                    ErrorCode::BadRequest,
                    "CONNECT needs a host:port target",
                ));
            };
            if self.shared.current().is_none() {
                return refusal_response(&not_ready());
            }
            let this = self.clone();
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(up) => this.tunnel(dest, TokioIo::new(up), client).await,
                    Err(e) => tracing::debug!(error = %e, "CONNECT upgrade failed"),
                }
            });
            return Response::new(empty());
        }
        let scheme = match req.uri().scheme_str() {
            Some("http") => Scheme::Http,
            Some("https") => Scheme::Https,
            _ => {
                return refusal_response(&Refusal::new(
                    ErrorCode::BadRequest,
                    "this is a forward proxy: send absolute-form requests or CONNECT",
                ));
            }
        };
        let Some(dest) = req
            .uri()
            .authority()
            .and_then(|a| Destination::from_authority(scheme, a.as_str()))
        else {
            return refusal_response(&Refusal::new(
                ErrorCode::BadRequest,
                "request URI has no host",
            ));
        };
        req.extensions_mut().insert(client);
        self.route(dest, req, false).await
    }

    /// Terminates TLS inside a CONNECT tunnel with a leaf for the CONNECT host and serves HTTP/1.1
    /// or HTTP/2 over it. Every request in the tunnel carries the CONNECT's [`ClientInfo`].
    async fn tunnel<IO>(&self, dest: Destination, io: IO, client: ClientInfo)
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let start = match LazyConfigAcceptor::new(Acceptor::default(), io).await {
            Ok(s) => s,
            Err(e) => {
                self.interception_refused(&dest, format!("no TLS client hello: {e}"), false);
                return;
            }
        };
        let sni = start
            .client_hello()
            .server_name()
            .map(str::to_ascii_lowercase);
        let misdirected = sni
            .as_deref()
            .is_some_and(|s| s.trim_end_matches('.') != dest.host);
        let leaf = match self.shared.ca.leaf_for(&dest.host) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, destination = %dest, "issuing a leaf certificate failed");
                return;
            }
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = match rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
        {
            Ok(b) => b
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(FixedCert(leaf))),
            Err(e) => {
                tracing::error!(error = %e, "TLS server config failed");
                return;
            }
        };
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let tls = match start.into_stream(Arc::new(cfg)).await {
            Ok(t) => t,
            Err(e) => {
                let alert = e
                    .get_ref()
                    .and_then(|i| i.downcast_ref::<rustls::Error>())
                    .is_some_and(|r| matches!(r, rustls::Error::AlertReceived(_)));
                self.interception_refused(&dest, e.to_string(), alert);
                return;
            }
        };
        let this = self.clone();
        let svc = service_fn(move |mut req: Request<Incoming>| {
            let this = this.clone();
            let dest = dest.clone();
            req.extensions_mut().insert(client.clone());
            async move { Ok::<_, Infallible>(this.route(dest, req, misdirected).await) }
        });
        if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(tls), svc)
            .await
        {
            tracing::debug!(error = %e, "intercepted connection ended with an error");
        }
    }

    fn interception_refused(
        &self,
        dest: &Destination,
        reason: String,
        client_rejected_certificate: bool,
    ) {
        if client_rejected_certificate {
            self.shared
                .unsupported
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(dest.authority(), reason.clone());
        }
        self.shared.audit.record(AuditEvent::InterceptionRefused {
            destination: dest.authority(),
            reason,
        });
    }

    async fn route<B>(
        &self,
        dest: Destination,
        req: Request<B>,
        misdirected: bool,
    ) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError>,
    {
        if misdirected {
            return refusal_response(&Refusal::new(
                ErrorCode::MisdirectedRequest,
                format!("TLS server name does not match the CONNECT target {dest}"),
            ));
        }
        if let Some(h) = &self.shared.intercept
            && h.claims(&dest)
        {
            let req = req.map(|b| b.map_err(Into::into).boxed_unsync());
            return h.handle(dest, req).await;
        }
        self.handle(dest, req).await
    }

    /// Runs one request toward `dest` through injection, the upstream and response redaction.
    /// This is the engine entry point other listeners (transparent mode) call directly.
    pub async fn handle<B>(&self, dest: Destination, req: Request<B>) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError>,
    {
        let Some(engine) = self.shared.current() else {
            return refusal_response(&not_ready());
        };
        if !engine.redactors.is_ready() {
            return refusal_response(&not_ready());
        }
        let shared = &*self.shared;
        let prepared = match engine.prepare_request(shared, &dest, req).await {
            Ok(p) => p,
            Err(r) => return refusal_response(&r),
        };
        let sent = shared.client.request(prepared.req).await;
        if prepared
            .meta
            .aborted
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return refusal_response(&Refusal::new(
                ErrorCode::BodyTooLarge,
                "a placeholder appeared in a request body too large to rewrite; the request was cut off",
            ));
        }
        let resp = match sent {
            Ok(r) => r,
            Err(e) => {
                let r = Refusal::new(
                    ErrorCode::UpstreamUnavailable,
                    format!("could not reach {dest}: {}", error_chain(&e)),
                );
                shared.audit.record(AuditEvent::ResponseWithheld {
                    code: r.code,
                    destination: dest.to_string(),
                    message: r.message.clone(),
                });
                return refusal_response(&r);
            }
        };
        match engine.rewrite_response(shared, &prepared.meta, resp).await {
            Ok(r) => r,
            Err(r) => refusal_response(&r),
        }
    }
}

fn not_ready() -> Refusal {
    Refusal::new(
        ErrorCode::NotReady,
        "scrim has not loaded its credentials and known values yet",
    )
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}
