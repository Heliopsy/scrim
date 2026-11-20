// SPDX-License-Identifier: AGPL-3.0-only

//! WebSocket upgrades are refused at once (llm-proxy spec "Protocol upgrades are refused"):
//! Codex tries the Responses API over WebSocket first and falls back to HTTPS only when the
//! handshake fails, so the refusal must be immediate and nothing may reach the provider.

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

use std::time::{Duration, Instant};

use common::*;
use scrim_llm::testing::{FakeUpstream, Scripted};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Sends a raw HTTP/1.1 request and returns the response head and how long it took.
async fn raw(addr: std::net::SocketAddr, req: &str) -> (String, Duration) {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let t = Instant::now();
    tcp.write_all(req.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut b))
            .await
            .expect("response head in time")
            .unwrap();
        assert_eq!(
            n,
            1,
            "connection closed: {}",
            String::from_utf8_lossy(&head)
        );
        head.push(b[0]);
    }
    (String::from_utf8(head).unwrap(), t.elapsed())
}

fn handshake(path: &str, connection: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: {connection}\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Authorization: Bearer agent-own-key\r\nOpenAI-Beta: responses_websockets=2026-02-06\r\n\r\n"
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_upgrade_is_refused_at_once_and_nothing_reaches_the_provider() {
    let fx = fixture();
    // A provider that would accept anything, slowly: a forwarded handshake would show up here
    // and take at least this long.
    let mut slow = Scripted::json(200, "{}");
    slow.delay = Duration::from_secs(2);
    let up = FakeUpstream::start(slow).await;
    let h = start(Some(&fx), up, |_| {}).await;
    for (path, conn) in [
        ("/openai/v1/responses", "Upgrade"),
        ("/openai/v1/responses", "keep-alive, upgrade"),
        ("/anthropic/v1/messages", "Upgrade"),
    ] {
        let (head, took) = raw(h.addr, &handshake(path, conn)).await;
        assert!(head.starts_with("HTTP/1.1 501"), "{path}: {head}");
        assert!(
            head.to_ascii_lowercase()
                .contains("x-scrim-error: upgrade_unsupported"),
            "{head}"
        );
        assert!(
            took < Duration::from_millis(100),
            "{path}: refused after {took:?}"
        );
    }
    assert!(
        h.upstream.received().is_empty(),
        "the provider saw a handshake"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_is_refused_even_before_the_values_load() {
    // Not ready would answer 503 with Retry-After, which a client may retry; an upgrade gets the
    // definitive answer so the client falls back.
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(None, up, |_| {}).await;
    let (head, took) = raw(h.addr, &handshake("/openai/v1/responses", "Upgrade")).await;
    assert!(head.starts_with("HTTP/1.1 501"), "{head}");
    assert!(took < Duration::from_millis(100), "refused after {took:?}");
    assert!(h.upstream.received().is_empty());
}
