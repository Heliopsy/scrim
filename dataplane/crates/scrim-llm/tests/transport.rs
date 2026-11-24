// SPDX-License-Identifier: AGPL-3.0-only

//! Listeners and upstream transport: HTTP/2 prior knowledge inbound, Unix socket, upstream TLS
//! with a private CA over HTTP/2 and HTTP/1.1, and upstream connection reuse.

#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unreachable_pub,
    dead_code,
    reason = "test code"
)]

mod common;

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use common::*;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use scrim_llm::testing::{FakeUpstream, Scripted};

const H: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("authorization", "Bearer t"),
];

#[tokio::test(flavor = "multi_thread")]
async fn h2c_prior_knowledge_inbound() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, r#"{"type":"message","content":[]}"#)).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let body = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"{}"}}]}}"#,
        fx.value("s0")
    );
    let r = send(&h, "/anthropic/v1/messages", H, body, true).await;
    assert_eq!(r.status, 200);
    assert!(fx.leaks(&h.upstream.received()[0].body).is_empty());
}

// Unix socket listeners and file modes exist on Unix only.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn unix_socket_listener() {
    use scrim_llm::{Proxy, ProxyConfig, SnapshotCell};
    use std::os::unix::fs::PermissionsExt;
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let cfg = ProxyConfig {
        routes: routes_to(&up.url()),
        ..ProxyConfig::default()
    };
    let proxy = Arc::new(
        Proxy::new(
            cfg,
            Arc::new(SnapshotCell::with(fx.snapshot())),
            Arc::new(scrim_llm::NoAudit),
        )
        .unwrap(),
    );
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("scrim.sock");
    std::fs::write(&path, b"not a socket").unwrap();
    assert!(
        scrim_llm::server::bind_unix(&path).is_err(),
        "refuses to replace a regular file"
    );
    std::fs::remove_file(&path).unwrap();
    let listener = scrim_llm::server::bind_unix(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(scrim_llm::server::serve_unix(listener, proxy, async {
        let _ = rx.await;
    }));

    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    let body = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"{}"}}]}}"#,
        fx.value("s0")
    );
    let req = http::Request::post("/anthropic/v1/messages")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(fx.leaks(&up.received()[0].body).is_empty());
    drop(sender);
    tx.send(()).unwrap();
    server.await.unwrap();
    // A second bind replaces the stale socket file.
    drop(scrim_llm::server::bind_unix(&path).unwrap());
}

struct TlsUpstream {
    port: u16,
    connections: Arc<AtomicUsize>,
    versions: Arc<std::sync::Mutex<Vec<http::Version>>>,
    ca_pem: String,
}

async fn tls_upstream(alpn: Vec<Vec<u8>>) -> TlsUpstream {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut sc = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        )
        .unwrap();
    sc.alpn_protocols = alpn;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(sc));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let versions = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (c2, v2) = (connections.clone(), versions.clone());
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            c2.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let v = v2.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let v = v.clone();
                    async move {
                        v.lock().unwrap().push(req.version());
                        let _ = req.into_body().collect().await;
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                .await;
            });
        }
    });
    TlsUpstream {
        port,
        connections,
        versions,
        ca_pem: ca.pem(),
    }
}

async fn through_tls(alpn: Vec<Vec<u8>>) -> (TlsUpstream, Vec<u16>) {
    let fx = fixture();
    let tls = tls_upstream(alpn).await;
    let tmp = tempfile::tempdir().unwrap();
    let ca_file = tmp.path().join("ca.pem");
    std::fs::write(&ca_file, &tls.ca_pem).unwrap();
    let url = format!("https://localhost:{}", tls.port);
    let dummy = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), dummy, move |c| {
        c.routes = routes_to(&url);
        c.tls.roots = scrim_llm::config::Roots::Webpki;
        c.tls.extra_ca_file = Some(ca_file);
    })
    .await;
    let mut statuses = Vec::new();
    for _ in 0..3 {
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"{}"}}]}}"#,
            fx.value("s0")
        );
        statuses.push(
            send(&h, "/anthropic/v1/messages", H, body, false)
                .await
                .status,
        );
    }
    (tls, statuses)
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_tls_http2_with_reuse() {
    let (tls, statuses) = through_tls(vec![b"h2".to_vec(), b"http/1.1".to_vec()]).await;
    assert_eq!(statuses, vec![200, 200, 200]);
    assert_eq!(
        tls.connections.load(Ordering::SeqCst),
        1,
        "one pooled upstream connection"
    );
    assert!(
        tls.versions
            .lock()
            .unwrap()
            .iter()
            .all(|v| *v == http::Version::HTTP_2)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_tls_http1_with_reuse() {
    let (tls, statuses) = through_tls(vec![b"http/1.1".to_vec()]).await;
    assert_eq!(statuses, vec![200, 200, 200]);
    assert_eq!(tls.connections.load(Ordering::SeqCst), 1);
    assert!(
        tls.versions
            .lock()
            .unwrap()
            .iter()
            .all(|v| *v == http::Version::HTTP_11)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_tls_untrusted_ca_is_refused() {
    let fx = fixture();
    let tls = tls_upstream(vec![b"http/1.1".to_vec()]).await;
    let url = format!("https://localhost:{}", tls.port);
    let dummy = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), dummy, move |c| {
        c.routes = routes_to(&url);
        c.tls.roots = scrim_llm::config::Roots::Webpki;
    })
    .await;
    let r = send(&h, "/anthropic/v1/messages", H, r#"{"messages":[]}"#, false).await;
    assert_eq!(r.status, 502);
    assert!(
        tls.versions.lock().unwrap().is_empty(),
        "no request reached an untrusted server"
    );
}
