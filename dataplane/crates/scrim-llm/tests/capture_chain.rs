// SPDX-License-Identifier: AGPL-3.0-only

//! Task 3.4 (capture mode) and 3.5 (upstream chaining with redaction first).

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
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use common::*;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use scrim_llm::config::CaptureConfig;
use scrim_llm::testing::{FakeUpstream, Scripted};
use scrim_llm::{AuditEvent, ChainConfig, OnUnavailable};

const AUTH: &[(&str, &str)] = &[
    (
        "authorization",
        "Bearer agent-oauth-token-must-not-be-captured",
    ),
    ("x-api-key", "agent-api-key-must-not-be-captured"),
    ("content-type", "application/json"),
    ("anthropic-version", "2023-06-01"),
];

fn files(dir: &std::path::Path, suffix: &str) -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(suffix))
        .collect();
    v.sort();
    v
}

#[tokio::test(flavor = "multi_thread")]
async fn captured_request_is_byte_identical_to_what_upstream_received() {
    let fx = fixture();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("capture");
    let stream = fill(&read_fixture("anthropic/stream_tool_use.sse"), &fx);
    let up = FakeUpstream::start(Scripted::sse(chunked(&stream, &[13]))).await;
    let d = dir.clone();
    let h = start(Some(&fx), up, move |c| {
        c.capture = Some(CaptureConfig {
            dir: d,
            retention_secs: 3600,
        })
    })
    .await;
    let tpl = read_fixture("anthropic/claude_code_request.json");
    let r = send(&h, "/anthropic/v1/messages", AUTH, fill(&tpl, &fx), false).await;
    assert_eq!(r.status, 200);
    assert!(
        r.text().contains(&fx.value("s0")),
        "agent got the restored stream"
    );

    let received = &h.upstream.received()[0];
    let bodies = files(&dir, ".request.body");
    assert_eq!(bodies.len(), 1);
    assert_eq!(std::fs::read(&bodies[0]).unwrap(), received.body.to_vec());
    // The response is captured as received: placeholders, never values.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let resp = std::fs::read(&files(&dir, ".response.body")[0]).unwrap();
    assert_eq!(resp, stream.as_bytes());
    for f in std::fs::read_dir(&dir).unwrap() {
        let bytes = std::fs::read(f.unwrap().path()).unwrap();
        assert!(fx.leaks(&bytes).is_empty());
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            !s.contains("must-not-be-captured"),
            "agent credentials are masked"
        );
    }
    let meta = std::fs::read_to_string(&files(&dir, ".request.json")[0]).unwrap();
    assert!(meta.contains("2023-06-01") && meta.contains("[masked]"));
}

// The permission check reads Unix mode bits.
#[cfg(unix)]
#[tokio::test]
async fn capture_refuses_a_world_readable_directory() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let cfg = scrim_llm::ProxyConfig {
        capture: Some(CaptureConfig {
            dir: tmp.path().to_path_buf(),
            retention_secs: 1,
        }),
        ..Default::default()
    };
    let err = scrim_llm::Proxy::new(
        cfg,
        Arc::new(scrim_llm::SnapshotCell::new()),
        Arc::new(scrim_llm::NoAudit),
    );
    assert!(matches!(err, Err(scrim_llm::BuildError::Capture(_))));
}

/// A stand-in for a context-compression proxy such as caveman: records what it receives,
/// "compresses" the body (collapses runs of spaces) and forwards to the provider.
struct Compressor {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Bytes>>>,
}

async fn compressor(provider: String) -> Compressor {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let seen = s2.clone();
            let provider = provider.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let seen = seen.clone();
                    let provider = provider.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body.collect().await.unwrap().to_bytes();
                        seen.lock().unwrap().push(body.clone());
                        let mut s = String::from_utf8(body.to_vec()).unwrap();
                        while s.contains("  ") {
                            s = s.replace("  ", " ");
                        }
                        let client = hyper_util::client::legacy::Client::builder(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .build_http::<Full<Bytes>>();
                        let mut up = hyper::Request::new(Full::new(Bytes::from(s)));
                        *up.method_mut() = parts.method;
                        *up.uri_mut() = format!("{provider}{}", parts.uri.path()).parse().unwrap();
                        *up.headers_mut() = parts.headers;
                        up.headers_mut().remove("content-length");
                        let resp = client.request(up).await.unwrap();
                        let (p, b) = resp.into_parts();
                        let b = b.collect().await.unwrap().to_bytes();
                        Ok::<_, Infallible>(hyper::Response::from_parts(p, Full::new(b)))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Compressor { addr, seen }
}

#[tokio::test(flavor = "multi_thread")]
async fn chained_compressor_sees_only_placeholders_and_they_survive() {
    let fx = fixture();
    let stream = fill(&read_fixture("anthropic/stream_tool_use.sse"), &fx);
    let up = FakeUpstream::start(Scripted::sse(chunked(&stream, &[29]))).await;
    let comp = compressor(up.url()).await;
    let chain_url = format!("http://{}", comp.addr);
    let h = start(Some(&fx), up, move |c| {
        c.routes[0].chain = Some(ChainConfig {
            url: chain_url,
            on_unavailable: OnUnavailable::Fail,
        });
    })
    .await;
    let body = format!(
        r#"{{"model":"m","stream":true,"messages":[{{"role":"user","content":"pw    is   {}   and key    {}"}}]}}"#,
        fx.value("s0"),
        fx.value("s1")
    );
    let r = send(&h, "/anthropic/v1/messages", AUTH, body, false).await;
    assert_eq!(r.status, 200);
    let seen = comp.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert!(
        fx.leaks(&seen[0]).is_empty(),
        "the chained proxy holds placeholders only"
    );
    let provider = &h.upstream.received()[0];
    let ptext = String::from_utf8(provider.body.to_vec()).unwrap();
    assert!(ptext.contains(&format!(
        "pw is {} and key {}",
        fx.placeholder("s0"),
        fx.placeholder("s1")
    )));
    assert!(
        r.text().contains(&fx.value("s0")),
        "placeholders from the provider resolve after the chain"
    );
    assert!(matches!(
        &h.audit.events()[0],
        AuditEvent::Forwarded {
            chain_skipped: false,
            ..
        }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn chain_unavailable_fail_and_direct() {
    let fx = fixture();
    // Held until the end of the test so the port cannot be reused by a parallel test's listener,
    // or by this test's own upstream and proxy.
    let (_dead, dead_addr) = refusing_addr();
    let dead_url = format!("http://{dead_addr}");
    let b = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"{}"}}]}}"#,
        fx.value("s0")
    );

    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let u = dead_url.clone();
    let h = start(Some(&fx), up, move |c| {
        c.routes[0].chain = Some(ChainConfig {
            url: u,
            on_unavailable: OnUnavailable::Fail,
        });
    })
    .await;
    let r = send(&h, "/anthropic/v1/messages", AUTH, b.clone(), false).await;
    assert_eq!(r.status, 502, "{}", r.text());
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "chain_unavailable");
    assert!(
        h.upstream.received().is_empty(),
        "fail sends nothing to the provider"
    );

    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), up, move |c| {
        c.routes[0].chain = Some(ChainConfig {
            url: dead_url,
            on_unavailable: OnUnavailable::Direct,
        });
    })
    .await;
    let r = send(&h, "/anthropic/v1/messages", AUTH, b, false).await;
    assert_eq!(r.status, 200);
    let got = h.upstream.received();
    assert_eq!(got.len(), 1);
    assert!(
        fx.leaks(&got[0].body).is_empty(),
        "direct sends the already-redacted request"
    );
    assert!(matches!(
        &h.audit.events()[0],
        AuditEvent::Forwarded {
            chain_skipped: true,
            ..
        }
    ));
}
