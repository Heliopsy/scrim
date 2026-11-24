// SPDX-License-Identifier: AGPL-3.0-only

//! Forward-proxy mode (interception spec, task 13.2): an agent with `HTTPS_PROXY` pointing at the
//! tool proxy reaches a provider host, the tool proxy hands it to the LLM engine through
//! `LlmIntercept`, and the request is redacted like any base-URL request.

#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    unreachable_pub,
    dead_code,
    reason = "test code"
)]

mod common;

use std::sync::Arc;

use bytes::Bytes;
use common::*;
use http_body_util::{BodyExt, Full};
use scrim_llm::intercept::LlmIntercept;
use scrim_llm::testing::{FakeUpstream, Scripted};
use scrim_llm::{Proxy, ProxyConfig, SnapshotCell};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct World {
    proxy_addr: std::net::SocketAddr,
    ca_pem: String,
    upstream: FakeUpstream,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn world(fx: &scrim_llm::testing::Fixture, response: Scripted) -> World {
    world_with(fx, response, routes_to).await
}

/// The default routes (every provider host scrim claims), each sent to the fake provider.
fn default_routes_to(url: &str) -> Vec<scrim_llm::RouteConfig> {
    scrim_llm::config::default_routes()
        .into_iter()
        .map(|mut r| {
            r.upstream = url.into();
            r
        })
        .collect()
}

async fn world_with(
    fx: &scrim_llm::testing::Fixture,
    response: Scripted,
    routes: impl FnOnce(&str) -> Vec<scrim_llm::RouteConfig>,
) -> World {
    let upstream = FakeUpstream::start(response).await;
    // Provider hosts are claimed by host name; the route's upstream is the fake provider.
    let cfg = ProxyConfig {
        routes: routes(&upstream.url()),
        ..ProxyConfig::default()
    };
    let llm = Arc::new(
        Proxy::new(
            cfg,
            Arc::new(SnapshotCell::with(fx.snapshot())),
            Arc::new(scrim_llm::NoAudit),
        )
        .unwrap(),
    );
    let tools = scrim_toolproxy::ToolProxy::builder()
        .intercept(Arc::new(LlmIntercept::new(llm)))
        .build()
        .unwrap();
    // The tool proxy refuses CONNECT until it has a snapshot; an empty one has no credentials.
    let empty = scrim_toolproxy::Snapshot::from_config(
        1,
        &scrim_toolproxy::ToolProxyConfig::default(),
        |_| None,
        |_, _| vec![],
    )
    .unwrap();
    tools.apply(empty).unwrap();
    let ca_pem = tools.ca().trust_bundle_pem();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = tools
            .serve(listener, async {
                let _ = rx.await;
            })
            .await;
    });
    World {
        proxy_addr,
        ca_pem,
        upstream,
        _stop: tx,
    }
}

async fn via_connect(w: &World, host: &str, path: &str, body: String) -> (u16, Bytes) {
    let req = http::Request::post(path)
        .header("host", host)
        .header("content-type", "application/json")
        .header("x-api-key", "agent-own-key")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    let (status, _, body, _) = send_via_connect(w, host, req).await;
    (status, body)
}

/// Opens a CONNECT tunnel to `host`, speaks TLS with the interception CA and sends `req`.
/// Also returns how long the request took to answer, tunnel and handshake excluded.
async fn send_via_connect(
    w: &World,
    host: &str,
    req: http::Request<Full<Bytes>>,
) -> (u16, http::HeaderMap, Bytes, std::time::Duration) {
    let tls = tunnel(w, host).await;
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let t = std::time::Instant::now();
    let resp = send.send_request(req).await.unwrap();
    let took = t.elapsed();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    (
        status,
        headers,
        resp.into_body().collect().await.unwrap().to_bytes(),
        took,
    )
}

/// Opens a CONNECT tunnel to `host` and speaks TLS (HTTP/1.1 by ALPN) with the interception CA.
async fn tunnel(w: &World, host: &str) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut tcp = tokio::net::TcpStream::connect(w.proxy_addr).await.unwrap();
    tcp.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(tcp.read(&mut b).await.unwrap(), 1);
        head.push(b[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    let mut roots = rustls::RootCertStore::empty();
    let mut rd = std::io::Cursor::new(w.ca_pem.as_bytes());
    for c in rustls_pemfile::certs(&mut rd) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(
            rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(),
            tcp,
        )
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn provider_host_through_connect_is_redacted_and_restored() {
    let fx = fixture();
    let p0 = fx.placeholder("s0");
    let reply = format!(r#"{{"type":"message","content":[{{"type":"text","text":"pw {p0}"}}]}}"#);
    let w = world(&fx, Scripted::json(200, reply)).await;
    let body = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"pw {}"}}]}}"#,
        fx.value("s0")
    );
    let (status, resp) = via_connect(&w, "api.anthropic.com", "/v1/messages", body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    let got = w.upstream.received();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].uri, "/v1/messages");
    assert!(fx.leaks(&got[0].body).is_empty());
    assert!(String::from_utf8_lossy(&got[0].body).contains(&p0));
    assert_eq!(got[0].headers["x-api-key"], "agent-own-key");
    let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    assert_eq!(v["content"][0]["text"], format!("pw {}", fx.value("s0")));
}

#[tokio::test(flavor = "multi_thread")]
async fn chatgpt_hosts_through_connect_get_the_llm_pipeline() {
    let fx = fixture();
    let w = world_with(
        &fx,
        Scripted::json(200, r#"{"ok":true}"#),
        default_routes_to,
    )
    .await;
    // Codex signed in with ChatGPT: the Responses API on chatgpt.com.
    let body = format!(
        r#"{{"model":"gpt-5-codex","instructions":"x","input":[{{"type":"message","role":"user","content":[{{"type":"input_text","text":"pw {}"}}]}}],"stream":false}}"#,
        fx.value("s0")
    );
    let (status, resp) = via_connect(&w, "chatgpt.com", "/backend-api/codex/responses", body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    // ab.chatgpt.com: no documented shape, redacted as generic JSON.
    let body = format!(
        r#"{{"events":[{{"name":"x","metadata":{{"note":"user {}"}}}}]}}"#,
        fx.value("s2")
    );
    let (status, resp) = via_connect(&w, "ab.chatgpt.com", "/v1/rgstr", body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    let got = w.upstream.received();
    assert_eq!(got.len(), 2, "both went to the LLM routes' upstream");
    assert_eq!(got[0].uri, "/backend-api/codex/responses");
    assert_eq!(got[1].uri, "/v1/rgstr");
    for (r, s) in got.iter().zip(["s0", "s2"]) {
        assert!(fx.leaks(&r.body).is_empty(), "{}", r.uri);
        assert!(
            String::from_utf8_lossy(&r.body).contains(&fx.placeholder(s)),
            "{}",
            r.uri
        );
        assert_eq!(r.headers["x-api-key"], "agent-own-key");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_to_a_provider_host_is_served_and_redacted() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let fx = fixture();
    let p0 = fx.placeholder("s0");
    let reply = format!(
        r#"{{"type":"response.output_text.done","item_id":"i1","content_index":0,"text":"pw {p0}"}}"#
    );
    let up = scrim_llm::testing::FakeWsUpstream::start(vec![], move |_| vec![reply.clone()]).await;
    let w = world_with(&fx, Scripted::json(200, "{}"), |_| routes_to(&up.url())).await;
    let tls = tunnel(&w, "api.openai.com").await;
    let mut req = "wss://api.openai.com/v1/realtime?model=gpt-realtime"
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("authorization", "Bearer agent-own-key".parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::client_async(req, tls).await.unwrap();
    let msg = format!(
        r#"{{"type":"conversation.item.create","item":{{"type":"message","role":"user","content":[{{"type":"input_text","text":"pw {}"}}]}}}}"#,
        fx.value("s0")
    );
    ws.send(Message::text(msg)).await.unwrap();
    let got = loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => break t.to_string(),
            _ => continue,
        }
    };
    assert!(got.contains(&format!("pw {}", fx.value("s0"))), "{got}");
    let sent = up.texts();
    assert_eq!(sent.len(), 1);
    assert!(fx.leaks(sent[0].as_bytes()).is_empty(), "{}", sent[0]);
    assert!(sent[0].contains(&p0));
    assert_eq!(up.handshakes()[0].uri, "/v1/realtime?model=gpt-realtime");
    assert!(w.upstream.received().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn other_upgrades_on_a_provider_host_are_refused_at_once() {
    let fx = fixture();
    let w = world(&fx, Scripted::json(200, "{}")).await;
    let req = http::Request::get("/v1/responses")
        .header("host", "api.openai.com")
        .header("connection", "Upgrade")
        .header("upgrade", "h2c")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, headers, _, took) = send_via_connect(&w, "api.openai.com", req).await;
    assert_eq!(status, 501);
    assert_eq!(headers[scrim_llm::ERROR_HEADER], "upgrade_unsupported");
    assert!(
        took < std::time::Duration::from_millis(100),
        "refused after {took:?}"
    );
    assert!(w.upstream.received().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_on_intercepted_hosts_are_closed() {
    let mut fx = fixture();
    fx.redactor_fault = scrim_llm::testing::Fault::Error;
    let w = world(&fx, Scripted::json(200, "{}")).await;
    let body = format!(
        r#"{{"messages":[{{"role":"user","content":"{}"}}]}}"#,
        fx.value("s0")
    );
    let (status, _) = via_connect(&w, "api.openai.com", "/v1/responses", body).await;
    assert_eq!(status, 422);
    assert!(w.upstream.received().is_empty());
}

// Windows curl uses Schannel, which wants a revocation check the test CA cannot answer.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn curl_with_https_proxy_is_redacted() {
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("curl not installed, skipping");
        return;
    }
    let fx = fixture();
    let w = world(&fx, Scripted::json(200, r#"{"ok":true}"#)).await;
    let tmp = tempfile::tempdir().unwrap();
    let ca = tmp.path().join("ca.pem");
    std::fs::write(&ca, &w.ca_pem).unwrap();
    let body = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"{}"}}]}}"#,
        fx.value("s0")
    );
    let out = tokio::process::Command::new("curl")
        .args(["-sS", "--fail-with-body", "--cacert"])
        .arg(&ca)
        .args([
            "-H",
            "content-type: application/json",
            "--data-binary",
            "@-",
        ])
        .arg("https://api.anthropic.com/v1/messages")
        .env("HTTPS_PROXY", format!("http://{}", w.proxy_addr))
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = out;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .await
        .unwrap();
    let res = child.wait_with_output().await.unwrap();
    assert!(
        res.status.success(),
        "curl: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert_eq!(res.stdout, br#"{"ok":true}"#);
    let got = w.upstream.received();
    assert!(fx.leaks(&got[0].body).is_empty());
}
