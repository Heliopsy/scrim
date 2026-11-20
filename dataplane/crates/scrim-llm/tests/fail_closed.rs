// SPDX-License-Identifier: AGPL-3.0-only

//! Task 3.3: every redaction or guard failure returns the documented error and nothing reaches
//! the upstream.

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

use common::*;
use scrim_llm::testing::{FakeUpstream, Fault, GuardMode, Scripted};
use scrim_llm::{AuditEvent, BinaryPolicy, RefusalReason, SecretRef};

const H: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("x-api-key", "agent-key-for-tests"),
];

fn body(fx: &scrim_llm::testing::Fixture) -> String {
    format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"pw {}"}}]}}"#,
        fx.value("s0")
    )
}

async fn expect_refused(
    fx: Option<&scrim_llm::testing::Fixture>,
    path: &str,
    headers: &[(&str, &str)],
    req: String,
    status: u16,
    code: &str,
    tweak: impl FnOnce(&mut scrim_llm::ProxyConfig),
) -> (Reply, Vec<AuditEvent>) {
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(fx, up, tweak).await;
    let r = send(&h, path, headers, req, false).await;
    assert_eq!(r.status, status, "{}", r.text());
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], code);
    assert!(
        h.upstream.received().is_empty(),
        "nothing may reach the upstream"
    );
    if let Some(fx) = fx {
        assert!(fx.leaks(&r.body).is_empty(), "error bodies carry no values");
    }
    (r, h.audit.events())
}

#[tokio::test(flavor = "multi_thread")]
async fn redactor_error() {
    let mut fx = fixture();
    let b = body(&fx);
    fx.redactor_fault = Fault::Error;
    let (r, ev) = expect_refused(
        Some(&fx),
        "/anthropic/v1/messages",
        H,
        b,
        422,
        "redactor_failed",
        |_| {},
    )
    .await;
    assert_eq!(r.json()["type"], "error");
    assert_eq!(r.json()["error"]["code"], "redactor_failed");
    assert!(matches!(
        ev[0],
        AuditEvent::Refused {
            reason: RefusalReason::RedactorFailed,
            ..
        }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_error_and_guard_refusal() {
    let mut fx = fixture();
    let b = body(&fx);
    fx.guard_fault = Fault::Error;
    expect_refused(
        Some(&fx),
        "/openai/v1/responses",
        H,
        b.clone(),
        422,
        "guard_failed",
        |_| {},
    )
    .await;

    let mut fx = fixture();
    let b = body(&fx);
    fx.redactor_misses = vec!["s0".into()];
    fx.guard_mode = GuardMode::Refuse;
    let (r, ev) = expect_refused(
        Some(&fx),
        "/openai/v1/chat/completions",
        H,
        b,
        422,
        "guard_refused",
        |_| {},
    )
    .await;
    assert_eq!(
        r.json()["error"]["code"],
        "guard_refused",
        "OpenAI error shape"
    );
    match &ev[0] {
        AuditEvent::Refused { reason, refs, .. } => {
            assert_eq!(*reason, RefusalReason::GuardRefused);
            assert_eq!(refs, &vec![SecretRef::new("s0")]);
        }
        e => panic!("unexpected {e:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_repair_is_forwarded_and_audited() {
    let mut fx = fixture();
    let b = body(&fx);
    fx.redactor_misses = vec!["s0".into()];
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), up, |_| {}).await;
    assert_eq!(
        send(&h, "/anthropic/v1/messages", H, b, false).await.status,
        200
    );
    assert!(fx.leaks(&h.upstream.received()[0].body).is_empty());
    assert!(
        matches!(&h.audit.events()[0], AuditEvent::Forwarded { guard_repaired, .. } if guard_repaired == &vec![SecretRef::new("s0")])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_bodies() {
    let fx = fixture();
    let v = fx.value("s0");
    for bad in [
        format!("{{\"model\":\"m\",\"messages\":[{{\"content\":\"{v}\"}}"),
        format!("{{\"messages\":\"{v}\",}}"),
        "[1,2]".to_string(),
        format!(
            "{{\"messages\":[{{\"content\":[{{\"type\":\"thinking\",\"type\":\"text\",\"thinking\":\"{v}\"}}]}}]}}"
        ),
        String::from_utf8_lossy(b"{\"a\":\"\xff\"}")
            .into_owned()
            .replace('\u{fffd}', "\u{1}"),
    ] {
        let (r, _) = expect_refused(
            Some(&fx),
            "/anthropic/v1/messages",
            H,
            bad,
            422,
            "malformed_body",
            |_| {},
        )
        .await;
        assert!(!r.text().contains(&v));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn not_ready_until_snapshot_and_then_served() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(None, up, |_| {}).await;
    let r = send(&h, "/anthropic/v1/messages", H, body(&fx), false).await;
    assert_eq!(r.status, 503);
    assert_eq!(r.headers["retry-after"], "1");
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "not_ready");
    assert!(h.upstream.received().is_empty());
    h.cell.store(fx.snapshot());
    assert_eq!(
        send(&h, "/anthropic/v1/messages", H, body(&fx), false)
            .await
            .status,
        200
    );
    h.cell.clear();
    assert_eq!(
        send(&h, "/anthropic/v1/messages", H, body(&fx), false)
            .await
            .status,
        503
    );
    assert_eq!(h.upstream.received().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_route() {
    let fx = fixture();
    expect_refused(
        Some(&fx),
        "/v1/messages",
        H,
        body(&fx),
        404,
        "no_route",
        |_| {},
    )
    .await;
    expect_refused(
        Some(&fx),
        "/anthropicx/v1/messages",
        H,
        body(&fx),
        404,
        "no_route",
        |_| {},
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn binary_block_policy_names_content_type() {
    let mut fx = fixture();
    fx.binary = BinaryPolicy::Block;
    let b = read_fixture("anthropic/claude_code_request.json");
    let (r, _) = expect_refused(
        Some(&fx),
        "/anthropic/v1/messages",
        H,
        fill(&b, &fx),
        422,
        "unscannable_content",
        |_| {},
    )
    .await;
    assert!(
        r.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("image/png")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn compressed_and_oversized_bodies() {
    let fx = fixture();
    let gz = [
        ("content-type", "application/json"),
        ("content-encoding", "gzip"),
    ];
    expect_refused(
        Some(&fx),
        "/anthropic/v1/messages",
        &gz,
        body(&fx),
        415,
        "unsupported_encoding",
        |_| {},
    )
    .await;
    expect_refused(
        Some(&fx),
        "/anthropic/v1/messages",
        H,
        body(&fx),
        413,
        "body_too_large",
        |c| {
            c.limits.max_request_body = 16;
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn large_bodies_offloaded_still_fail_closed() {
    let mut fx = fixture();
    let filler = "x".repeat(2 << 20);
    let b = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"{filler} {}"}}]}}"#,
        fx.value("s0")
    );
    fx.redactor_fault = Fault::Error;
    expect_refused(
        Some(&fx),
        "/anthropic/v1/messages",
        H,
        b.clone(),
        422,
        "redactor_failed",
        |_| {},
    )
    .await;
    fx.redactor_fault = Fault::None;
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), up, |_| {}).await;
    assert_eq!(
        send(&h, "/anthropic/v1/messages", H, b, false).await.status,
        200
    );
    assert!(fx.leaks(&h.upstream.received()[0].body).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_down_is_a_documented_error() {
    let fx = fixture();
    // Held until the end of the test so the port cannot be reused by a parallel test's listener.
    let (_dead, addr) = refusing_addr();
    let url = format!("http://{addr}");
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), up, |c| c.routes = routes_to(&url)).await;
    let r = send(&h, "/anthropic/v1/messages", H, body(&fx), false).await;
    assert_eq!(r.status, 502, "{}", r.text());
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "upstream_unavailable");
    assert!(fx.leaks(&r.body).is_empty(), "error bodies carry no values");
}
