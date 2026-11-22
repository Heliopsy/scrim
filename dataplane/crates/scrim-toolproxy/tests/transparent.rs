//! Transparent and SNI listener connections (tasks 13.3, 15.2): no CONNECT, the destination comes
//! from the TLS server name or the Host header.
#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unreachable_pub
)]

mod common;

use std::net::SocketAddr;

use bytes::Bytes;
use common::*;
use http::StatusCode;
use scrim_toolproxy::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HOSTS: &[&str] = &["api.acme.test", "other.test"];

fn config(port: u16) -> String {
    format!(
        r"
credentials:
  - name: acme
    reference: env://ACME
    placeholders: [SCRIM_ACME_KEY]
    binding: {{ hosts: ['api.acme.test:{port}'] }}
"
    )
}

struct World {
    proxy: Proxy,
    up: Upstream,
    listener: SocketAddr,
}

/// A tool proxy with a transparent-style listener whose connections claim `port` as their
/// original destination port.
async fn world(block_unrouted: bool, tls_only: bool) -> World {
    let ca = UpstreamCa::new();
    let up = tls_upstream(&ca, HOSTS, echo_handler()).await;
    let mut opts = ProxyOptions::default();
    opts.roots.push(ca.der());
    for h in HOSTS {
        opts.hosts.push(((*h).to_owned(), up.addr));
    }
    let proxy = start_proxy(opts).await;
    proxy
        .proxy
        .apply(snapshot(&config(up.port()), &[("env://ACME", ACME_VALUE)]))
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = l.local_addr().unwrap();
    let p = proxy.proxy.clone();
    let port = up.port();
    tokio::spawn(async move {
        loop {
            let (s, peer) = l.accept().await.unwrap();
            let conn = TransparentConn {
                peer: Some(peer),
                port,
                dialled: Some(SocketAddr::from(([192, 0, 2, 1], port))),
                block_unrouted,
                tls_only,
            };
            let p = p.clone();
            tokio::spawn(async move { p.serve_transparent(s, conn).await });
        }
    });
    World {
        proxy,
        up,
        listener,
    }
}

impl World {
    fn client(&self) -> Client {
        Client {
            proxy: self.listener,
            trust: pem_certs(&self.proxy.proxy.ca().trust_bundle_pem()),
            h2: false,
            direct: true,
            identity: None,
        }
    }

    fn refusals(&self) -> Vec<String> {
        self.proxy
            .audit
            .events()
            .into_iter()
            .filter_map(|e| match e {
                AuditEvent::InterceptionRefused {
                    destination,
                    reason,
                } => Some(format!("{destination} {reason}")),
                _ => None,
            })
            .collect()
    }
}

#[tokio::test]
async fn routed_host_is_intercepted_by_server_name() {
    let w = world(false, false).await;
    let r = req("GET", "api.acme.test", w.up.port(), "/v1/me")
        .header("authorization", "Bearer SCRIM_ACME_KEY")
        .body(body(Bytes::new()))
        .unwrap();
    let got = w
        .client()
        .send("api.acme.test", w.up.port(), r)
        .await
        .unwrap();
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    let seen = w.up.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].headers["authorization"],
        format!("Bearer {ACME_VALUE}").as_str(),
        "the credential is injected toward its bound host"
    );
    assert_eq!(
        got.json()["headers"]["authorization"],
        "Bearer SCRIM_ACME_KEY",
        "the response is redacted"
    );
    assert!(w.proxy.proxy.routes(&Destination::new(
        Scheme::Https,
        "api.acme.test",
        w.up.port()
    )));
}

#[tokio::test]
async fn connection_by_address_without_server_name_is_closed() {
    let w = world(false, false).await;
    let r = req("GET", "127.0.0.1", w.up.port(), "/")
        .body(body(Bytes::new()))
        .unwrap();
    assert!(w.client().send("127.0.0.1", w.up.port(), r).await.is_err());
    assert!(w.up.seen().is_empty());
    let refused = w.refusals();
    assert!(
        refused
            .iter()
            .any(|r| r.contains("192.0.2.1") && r.contains("without a server name")),
        "{refused:?}"
    );
}

#[tokio::test]
async fn unrouted_host_is_blocked_when_asked() {
    let w = world(true, false).await;
    let r = req("GET", "other.test", w.up.port(), "/")
        .body(body(Bytes::new()))
        .unwrap();
    assert!(w.client().send("other.test", w.up.port(), r).await.is_err());
    assert!(w.up.seen().is_empty());
    assert!(
        w.refusals()
            .iter()
            .any(|r| r.starts_with("other.test:") && r.contains("blocks unrouted"))
    );
}

#[tokio::test]
async fn unrouted_host_resolving_to_this_host_is_not_passed_through() {
    // Passed through by name; a name that resolves to loopback would come back to scrim.
    let w = world(false, false).await;
    let r = req("GET", "localhost", w.up.port(), "/")
        .body(body(Bytes::new()))
        .unwrap();
    assert!(w.client().send("localhost", w.up.port(), r).await.is_err());
    assert!(
        w.refusals()
            .iter()
            .any(|r| r.starts_with("localhost:") && r.contains("resolves to this host")),
        "{:?}",
        w.refusals()
    );
}

#[tokio::test]
async fn plain_http_to_unrouted_host_is_refused_when_blocking() {
    let w = world(true, false).await;
    let mut s = TcpStream::connect(w.listener).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    assert!(w.up.seen().is_empty());
}

#[tokio::test]
async fn sni_listener_closes_plain_http() {
    let w = world(false, true).await;
    let mut s = TcpStream::connect(w.listener).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: api.acme.test\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    assert!(out.is_empty());
    assert!(w.refusals().iter().any(|r| r.contains("TLS only")));
}

#[tokio::test]
async fn plain_http_to_a_name_resolving_here_is_refused() {
    let w = world(false, false).await;
    let mut s = TcpStream::connect(w.listener).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 403"), "{text}");
    assert!(
        w.refusals()
            .iter()
            .any(|r| r.contains("resolves to this host"))
    );
}
