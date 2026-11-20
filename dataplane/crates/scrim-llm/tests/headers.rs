// SPDX-License-Identifier: AGPL-3.0-only

//! Header values leave as visible ASCII (llm-proxy spec "Request target and headers are
//! redacted", redaction spec "Placeholder format"): a placeholder in a header is sent in its
//! percent form, which a strict provider front end accepts and which still resolves.

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

use bytes::Bytes;
use common::*;
use http_body_util::Full;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use scrim_llm::testing::{FakeUpstream, Scripted, is_strict_field_value};

#[tokio::test(flavor = "multi_thread")]
async fn redacted_header_is_visible_ascii_and_the_strict_upstream_accepts_it() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, r#"{"type":"message","content":[]}"#)).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let ctx = format!("db=\"{}\"; user={}", fx.value("s0"), fx.value("s2"));
    let r = send(
        &h,
        "/anthropic/v1/messages",
        &[
            ("content-type", "application/json"),
            ("x-debug-context", &ctx),
        ],
        r#"{"model":"m","messages":[]}"#,
        false,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let got = h.upstream.received();
    assert_eq!(got.len(), 1);
    let v = got[0].headers["x-debug-context"].as_bytes();
    assert!(is_strict_field_value(v), "{}", String::from_utf8_lossy(v));
    assert!(fx.leaks(v).is_empty());
    let (p0, p2) = (fx.placeholder_ascii("s0"), fx.placeholder_ascii("s2"));
    assert_eq!(v, format!("db=\"{p0}\"; user={p2}").as_bytes());
    let snap = fx.snapshot();
    for (p, s) in [(&p0, "s0"), (&p2, "s2")] {
        let r = snap.placeholders.resolve(p).expect("resolves");
        assert_eq!(r.value.expose(), fx.value(s).as_bytes());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_fake_upstream_rejects_raw_placeholders_in_headers() {
    // What the proxy sent before: the placeholder's UTF-8 brackets as obs-text.
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let raw = format!("db=\"{}\"", fx.placeholder("s0"));
    let req = http::Request::post(format!("{}/v1/messages", up.url()))
        .header(
            "x-debug-context",
            http::HeaderValue::from_bytes(raw.as_bytes()).unwrap(),
        )
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap();
    let resp = Client::builder(TokioExecutor::new())
        .build_http::<Full<Bytes>>()
        .request(req)
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.headers()["x-fake-upstream"], "obs-text");
    assert!(up.received().is_empty());
}
