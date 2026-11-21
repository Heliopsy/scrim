//! Test harness: fake upstream servers, a running proxy and a proxy-aware client.
#![allow(
    clippy::pedantic,
    clippy::type_complexity,
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unreachable_pub
)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use scrim_toolproxy::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The real values used in tests. Generated-looking, never real secrets.
pub const ACME_VALUE: &str = "acme-live-7f3c9a1e5b2d4c6f8a0b";
pub const GIT_VALUE: &str = "ghx_test_0c1d2e3f4a5b6c7d8e9f0a1b";
pub const WEIRD_VALUE: &str = "we\"ird&va=lue+/x";
pub const GENERATED_ACME: &str = "⟦scrim:acme:5f2a9c0d1e7b⟧";

/// A request the fake upstream received.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub uri: String,
    pub version: Version,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

pub type Handler = Arc<dyn Fn(&Seen) -> Response<ResponseBody> + Send + Sync>;

/// Bodies the fake upstream can return: complete, or chunks with delays.
pub enum ResponseBody {
    Full(Bytes),
    Chunks(Vec<Bytes>),
}

pub fn ok_json(v: serde_json::Value) -> Response<ResponseBody> {
    Response::builder()
        .header("content-type", "application/json")
        .body(ResponseBody::Full(Bytes::from(v.to_string())))
        .unwrap()
}

/// Echoes the request: method, path, every header and the body as text.
pub fn echo_handler() -> Handler {
    Arc::new(|s: &Seen| {
        let headers: serde_json::Map<String, serde_json::Value> = s
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    serde_json::Value::String(String::from_utf8_lossy(v.as_bytes()).into()),
                )
            })
            .collect();
        ok_json(serde_json::json!({
            "method": s.method,
            "uri": s.uri,
            "headers": headers,
            "body": String::from_utf8_lossy(&s.body),
        }))
    })
}

/// A test CA for upstream servers, plus leaf issuance.
pub struct UpstreamCa {
    pub issuer: CertifiedIssuer<'static, KeyPair>,
}

impl UpstreamCa {
    pub fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name
            .push(DnType::CommonName, "test upstream CA");
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        Self {
            issuer: CertifiedIssuer::self_signed(p, key).unwrap(),
        }
    }

    pub fn der(&self) -> CertificateDer<'static> {
        self.issuer.der().clone()
    }

    pub fn server_config(&self, hosts: &[&str]) -> rustls::ServerConfig {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>())
            .unwrap();
        p.subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        cfg
    }
}

/// A fake upstream on 127.0.0.1 recording every request.
pub struct Upstream {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Upstream {
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

async fn serve_upstream_conn<IO>(io: IO, handler: Handler, seen: Arc<Mutex<Vec<Seen>>>)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let svc = service_fn(move |req: Request<Incoming>| {
        let handler = handler.clone();
        let seen = seen.clone();
        async move {
            let (parts, body) = req.into_parts();
            let body = body
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            let s = Seen {
                method: parts.method.to_string(),
                uri: parts
                    .uri
                    .path_and_query()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                version: parts.version,
                headers: parts.headers,
                body,
            };
            seen.lock().unwrap().push(s.clone());
            let resp = handler(&s);
            let (p, b) = resp.into_parts();
            let body: http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible> = match b {
                ResponseBody::Full(b) => Full::new(b).boxed_unsync(),
                ResponseBody::Chunks(chunks) => {
                    let stream = futures_util::stream::iter(
                        chunks
                            .into_iter()
                            .map(|c| Ok::<_, Infallible>(hyper::body::Frame::data(c))),
                    );
                    let delayed = DelayedStream {
                        inner: Box::pin(stream),
                        sleep: None,
                    };
                    http_body_util::StreamBody::new(delayed).boxed_unsync()
                }
            };
            Ok::<_, Infallible>(Response::from_parts(p, body))
        }
    });
    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), svc)
        .await;
}

/// Yields stream items with a short pause between them, so the proxy sees separate chunks.
struct DelayedStream<S> {
    inner: Pin<Box<S>>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S: futures_util::Stream + Send> futures_util::Stream for DelayedStream<S> {
    type Item = S::Item;
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<S::Item>> {
        if let Some(s) = self.sleep.as_mut() {
            if s.as_mut().poll(cx).is_pending() {
                return std::task::Poll::Pending;
            }
            self.sleep = None;
        }
        let r = self.inner.as_mut().poll_next(cx);
        if r.is_ready() {
            self.sleep = Some(Box::pin(tokio::time::sleep(
                std::time::Duration::from_millis(15),
            )));
        }
        r
    }
}

/// Starts a TLS upstream serving `hosts`.
pub async fn tls_upstream(ca: &UpstreamCa, hosts: &[&str], handler: Handler) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(ca.server_config(hosts)));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let handler = handler.clone();
            let seen = seen2.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve_upstream_conn(tls, handler, seen).await;
                }
            });
        }
    });
    Upstream { addr, seen }
}

/// Starts a plain HTTP upstream.
pub async fn plain_upstream(handler: Handler) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(serve_upstream_conn(tcp, handler.clone(), seen2.clone()));
        }
    });
    Upstream { addr, seen }
}

/// Records captures and answers with a fixed placeholder, or fails.
#[derive(Clone, Default)]
pub struct TestCaptureSink {
    pub stored: Arc<Mutex<Vec<(String, String, Vec<u8>)>>>,
    pub fail: bool,
}

impl CaptureSink for TestCaptureSink {
    fn store(&self, req: CaptureRequest) -> CaptureFuture {
        let me = self.clone();
        Box::pin(async move {
            if me.fail {
                return Err(CaptureError("store unreachable".into()));
            }
            me.stored.lock().unwrap().push((
                req.rule.clone(),
                req.reference.clone(),
                req.value.expose().to_vec(),
            ));
            Ok(format!("⟦scrim:captured:{}⟧", req.rule))
        })
    }
}

/// A running proxy.
pub struct Proxy {
    pub proxy: ToolProxy,
    pub addr: SocketAddr,
    pub audit: MemoryAuditSink,
    pub capture: TestCaptureSink,
}

#[derive(Default)]
pub struct ProxyOptions {
    pub hosts: Vec<(String, SocketAddr)>,
    pub roots: Vec<CertificateDer<'static>>,
    pub settings: ToolProxySettings,
    pub capture_fail: bool,
    pub intercept: Option<Arc<dyn InterceptHandler>>,
}

pub async fn start_proxy(opts: ProxyOptions) -> Proxy {
    let audit = MemoryAuditSink::new();
    let capture = TestCaptureSink {
        fail: opts.capture_fail,
        ..Default::default()
    };
    let mut overrides: HashMap<String, Vec<SocketAddr>> = HashMap::new();
    for (h, a) in opts.hosts {
        overrides.entry(h).or_default().push(a);
    }
    let mut b = ToolProxy::builder()
        .settings(opts.settings)
        .upstream(UpstreamSettings {
            native_roots: false,
            extra_roots: opts.roots,
            resolve_overrides: overrides,
            ..Default::default()
        })
        .audit(Arc::new(audit.clone()))
        .capture_sink(Arc::new(capture.clone()));
    if let Some(i) = opts.intercept {
        b = b.intercept(i);
    }
    let proxy = b.build().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let p2 = proxy.clone();
    tokio::spawn(async move { p2.serve(listener, std::future::pending()).await });
    Proxy {
        proxy,
        addr,
        audit,
        capture,
    }
}

/// Builds a snapshot from YAML, values by reference from `values`.
pub fn snapshot(yaml: &str, values: &[(&str, &str)]) -> Snapshot {
    let cfg: ToolProxyConfig = serde_yaml::from_str(yaml).unwrap();
    let values: HashMap<String, String> = values
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Snapshot::from_config(
        1,
        &cfg,
        |r| {
            values
                .get(r)
                .map(|v| SecretValue::new(v.as_bytes().to_vec()))
        },
        |r, _| {
            if r == "env://ACME" {
                vec![GENERATED_ACME.to_string()]
            } else {
                vec![]
            }
        },
    )
    .unwrap()
}

/// A client that talks through the proxy: CONNECT, TLS trusting `trust`, then HTTP/1.1 or 2.
pub struct Client {
    pub proxy: SocketAddr,
    pub trust: Vec<CertificateDer<'static>>,
    pub h2: bool,
}

#[derive(Debug)]
pub struct Got {
    pub status: StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
    pub version: Version,
}

impl Got {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.text()))
    }
    pub fn error_code(&self) -> Option<String> {
        self.headers
            .get("x-scrim-error")
            .map(|v| v.to_str().unwrap().to_owned())
    }
}

#[derive(Debug)]
pub enum ClientError {
    Connect(String),
    Tls(String),
    Http(String),
}

impl Client {
    pub fn new(proxy: &Proxy) -> Self {
        let trust = pem_certs(&proxy.proxy.ca().trust_bundle_pem());
        Self {
            proxy: proxy.addr,
            trust,
            h2: false,
        }
    }

    pub async fn send<B>(&self, host: &str, port: u16, req: Request<B>) -> Result<Got, ClientError>
    where
        B: hyper::body::Body<Data = Bytes> + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut tcp = TcpStream::connect(self.proxy)
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        let connect = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
        tcp.write_all(connect.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            let n = tcp
                .read(&mut byte)
                .await
                .map_err(|e| ClientError::Connect(e.to_string()))?;
            if n == 0 {
                return Err(ClientError::Connect("proxy closed during CONNECT".into()));
            }
            buf.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        if !head.starts_with("HTTP/1.1 200") {
            return Err(ClientError::Connect(head));
        }
        let mut roots = rustls::RootCertStore::empty();
        for c in &self.trust {
            roots.add(c.clone()).unwrap();
        }
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        cfg.alpn_protocols = if self.h2 {
            vec![b"h2".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let name = ServerName::try_from(host.to_string()).unwrap();
        let tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| ClientError::Tls(e.to_string()))?;
        let io = TokioIo::new(tls);
        let resp = if self.h2 {
            let (mut send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                .await
                .map_err(|e| ClientError::Http(e.to_string()))?;
            tokio::spawn(conn);
            send.send_request(req)
                .await
                .map_err(|e| ClientError::Http(e.to_string()))?
        } else {
            let (mut send, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| ClientError::Http(e.to_string()))?;
            tokio::spawn(conn);
            send.send_request(req)
                .await
                .map_err(|e| ClientError::Http(e.to_string()))?
        };
        let (parts, body) = resp.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?
            .to_bytes();
        Ok(Got {
            status: parts.status,
            headers: parts.headers,
            body,
            version: parts.version,
        })
    }

    /// Plain-HTTP proxy request in absolute form.
    pub async fn send_plain(&self, req: Request<Full<Bytes>>) -> Got {
        let tcp = TcpStream::connect(self.proxy).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(conn);
        let resp = send.send_request(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        Got {
            status: parts.status,
            headers: parts.headers,
            body,
            version: parts.version,
        }
    }
}

pub fn pem_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .map(|c| c.unwrap())
        .collect()
}

pub fn body(b: impl Into<Bytes>) -> Full<Bytes> {
    Full::new(b.into())
}

/// Request to `https://host:port{path}`.
pub fn req(method: &str, host: &str, port: u16, path: &str) -> http::request::Builder {
    Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("{host}:{port}"))
}

/// Request for HTTP/2 (absolute URI, no Host header).
pub fn req_h2(method: &str, host: &str, port: u16, path: &str) -> http::request::Builder {
    Request::builder()
        .method(method)
        .uri(format!("https://{host}:{port}{path}"))
        .version(Version::HTTP_2)
}

/// Asserts no audit event, error or response text contains a real value.
pub fn assert_no_values(texts: &[String]) {
    for t in texts {
        for v in [ACME_VALUE, GIT_VALUE, WEIRD_VALUE] {
            assert!(!t.contains(v), "a real value leaked: {t}");
        }
    }
}

pub fn audit_texts(p: &Proxy) -> Vec<String> {
    p.audit
        .events()
        .iter()
        .map(|e| format!("{e:?} {}", serde_json::to_string(e).unwrap()))
        .collect()
}
