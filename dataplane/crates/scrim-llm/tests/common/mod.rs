// SPDX-License-Identifier: AGPL-3.0-only

//! Shared harness: a proxy on 127.0.0.1 in front of a recording fake upstream.

#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    unreachable_pub,
    dead_code,
    reason = "test code"
)]

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use scrim_llm::testing::{FakeUpstream, Fixture, RecordingAudit};
use scrim_llm::{Provider, Proxy, ProxyConfig, RouteConfig, SnapshotCell, ValueClass};

/// Generated secrets used by the recorded fixtures: `s0` database password (display), `s1`
/// payment API key (credential), `s2` user name (display).
pub fn fixture() -> Fixture {
    let mut fx = Fixture::new(&[]);
    fx.add(
        "s0",
        &scrim_llm::testing::random_value("pw_"),
        ValueClass::Display,
    );
    fx.add(
        "s1",
        &scrim_llm::testing::random_value("sk_live_"),
        ValueClass::Credential,
    );
    fx.add(
        "s2",
        &scrim_llm::testing::random_value("user"),
        ValueClass::Display,
    );
    fx
}

/// Fills `{{Sn}}` with values and `{{Pn}}` with placeholders.
pub fn fill(template: &str, fx: &Fixture) -> String {
    let mut s = template.to_string();
    for i in 0..3 {
        s = s.replace(&format!("{{{{S{i}}}}}"), &fx.value(&format!("s{i}")));
        s = s.replace(&format!("{{{{P{i}}}}}"), &fx.placeholder(&format!("s{i}")));
    }
    s
}

/// Fills `{{Sn}}` with placeholders: what the provider should receive.
pub fn fill_redacted(template: &str, fx: &Fixture) -> String {
    let mut s = template.to_string();
    for i in 0..3 {
        s = s.replace(&format!("{{{{S{i}}}}}"), &fx.placeholder(&format!("s{i}")));
    }
    s
}

pub fn read_fixture(name: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

pub fn routes_to(url: &str) -> Vec<RouteConfig> {
    vec![
        RouteConfig {
            name: "anthropic".into(),
            prefix: "/anthropic".into(),
            upstream: url.into(),
            provider: Provider::Anthropic,
            strip_prefix: true,
            chain: None,
            hosts: vec!["api.anthropic.com".into()],
            auth: None,
        },
        RouteConfig {
            name: "openai".into(),
            prefix: "/openai".into(),
            upstream: url.into(),
            provider: Provider::Openai,
            strip_prefix: true,
            chain: None,
            hosts: vec!["api.openai.com".into()],
            auth: None,
        },
        RouteConfig {
            name: "gemini".into(),
            prefix: "/gemini".into(),
            upstream: url.into(),
            provider: Provider::Gemini,
            strip_prefix: true,
            chain: None,
            hosts: vec!["generativelanguage.googleapis.com".into()],
            auth: None,
        },
    ]
}

/// A loopback address that refuses connections for as long as the returned socket lives.
///
/// The socket is bound but never listens, so a connect gets a reset (connection refused) and the
/// port stays taken: no listener started by a test running in parallel can be given it. Binding
/// a listener, reading its address and dropping it frees the port, and the kernel can hand it to
/// the next `bind(":0")` before the request is sent.
pub fn refusing_addr() -> (tokio::net::TcpSocket, SocketAddr) {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = sock.local_addr().unwrap();
    (sock, addr)
}

pub struct Harness {
    pub addr: SocketAddr,
    pub upstream: FakeUpstream,
    pub audit: RecordingAudit,
    pub cell: Arc<SnapshotCell>,
    pub proxy: Arc<Proxy>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

pub async fn start(
    fx: Option<&Fixture>,
    upstream: FakeUpstream,
    tweak: impl FnOnce(&mut ProxyConfig),
) -> Harness {
    let mut cfg = ProxyConfig {
        routes: routes_to(&upstream.url()),
        ..ProxyConfig::default()
    };
    tweak(&mut cfg);
    let cell = Arc::new(match fx {
        Some(fx) => SnapshotCell::with(fx.snapshot()),
        None => SnapshotCell::new(),
    });
    let audit = RecordingAudit::default();
    let proxy = Arc::new(Proxy::new(cfg, cell.clone(), Arc::new(audit.clone())).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(scrim_llm::server::serve_tcp(
        listener,
        proxy.clone(),
        async {
            let _ = rx.await;
        },
    ));
    Harness {
        addr,
        upstream,
        audit,
        cell,
        proxy,
        stop: Some(tx),
    }
}

pub struct Reply {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8(self.body.to_vec()).unwrap()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// Sends a request to the harness over HTTP/1.1 (or HTTP/2 prior knowledge with `h2`).
pub async fn send(
    h: &Harness,
    path: &str,
    headers: &[(&str, &str)],
    body: impl Into<Bytes>,
    h2: bool,
) -> Reply {
    let client = Client::builder(TokioExecutor::new())
        .http2_only(h2)
        .build_http::<Full<Bytes>>();
    let mut req = http::Request::builder()
        .method("POST")
        .uri(format!("http://{}{path}", h.addr));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = client
        .request(req.body(Full::new(body.into())).unwrap())
        .await
        .unwrap();
    let (parts, body) = resp.into_parts();
    Reply {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body: body.collect().await.unwrap().to_bytes(),
    }
}

/// Splits `s` into chunks with sizes cycling through `sizes`.
pub fn chunked(s: &str, sizes: &[usize]) -> Vec<Bytes> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut pos = 0;
    let mut i = 0;
    while pos < b.len() {
        let n = sizes[i % sizes.len()].max(1).min(b.len() - pos);
        out.push(Bytes::copy_from_slice(&b[pos..pos + n]));
        pos += n;
        i += 1;
    }
    out
}

/// Parses an SSE body into (event name, data JSON) pairs; `[DONE]` becomes `Value::Null`.
pub fn events(body: &str) -> Vec<(Option<String>, serde_json::Value)> {
    body.split("\n\n")
        .filter(|e| !e.trim().is_empty())
        .map(|e| {
            let mut name = None;
            let mut data = String::new();
            for line in e.lines() {
                if let Some(v) = line.strip_prefix("event: ") {
                    name = Some(v.to_string());
                } else if let Some(v) = line.strip_prefix("data: ") {
                    data.push_str(v);
                }
            }
            let v = if data == "[DONE]" {
                serde_json::Value::Null
            } else {
                serde_json::from_str(&data).unwrap()
            };
            (name, v)
        })
        .collect()
}
