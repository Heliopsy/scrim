// SPDX-License-Identifier: AGPL-3.0-only

//! Anthropic Messages through the proxy, end to end against a recording fake upstream.

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
use scrim_llm::testing::{FakePolicy, FakeUpstream, Scripted};
use scrim_llm::{AuditEvent, SecretRef};

const AUTH: &[(&str, &str)] = &[
    (
        "authorization",
        "Bearer sk-ant-oat01-agent-own-oauth-token-for-tests",
    ),
    ("x-api-key", "agent-own-api-key-for-tests"),
    ("anthropic-version", "2023-06-01"),
    (
        "anthropic-beta",
        "claude-code-20250219,interleaved-thinking-2025-05-14",
    ),
    ("content-type", "application/json"),
    ("user-agent", "claude-cli/2.0.0 (external, cli)"),
];

#[tokio::test(flavor = "multi_thread")]
async fn recorded_request_redacted_byte_exact_with_auth_untouched() {
    let fx = fixture();
    let tpl = read_fixture("anthropic/claude_code_request.json");
    let up = FakeUpstream::start(Scripted::json(200, r#"{"type":"message","content":[]}"#)).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let r = send(
        &h,
        "/anthropic/v1/messages?beta=true",
        AUTH,
        fill(&tpl, &fx),
        false,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());

    let got = h.upstream.received();
    assert_eq!(got.len(), 1);
    let req = &got[0];
    assert_eq!(req.uri, "/v1/messages?beta=true");
    // Every value became its placeholder and nothing else changed: allowlisted configuration,
    // the thinking block and its signature, redacted thinking and the image stay byte-identical,
    // and the unknown `undocumented_safeguards` member was redacted like content.
    assert_eq!(
        std::str::from_utf8(&req.body).unwrap(),
        fill_redacted(&tpl, &fx)
    );
    assert!(fx.leaks(&req.body).is_empty());
    for (k, v) in AUTH.iter().filter(|(k, _)| *k != "content-length") {
        assert_eq!(req.headers.get(*k).unwrap(), v, "header {k}");
    }
    assert_eq!(req.headers.get("accept-encoding").unwrap(), "identity");

    let ev = h.audit.events();
    match &ev[0] {
        AuditEvent::Forwarded {
            route,
            refs,
            unscanned,
            guard_repaired,
            chain_skipped,
            ..
        } => {
            assert_eq!(route, "anthropic");
            let mut refs = refs.clone();
            refs.sort();
            assert_eq!(
                refs,
                vec![
                    SecretRef::new("s0"),
                    SecretRef::new("s1"),
                    SecretRef::new("s2")
                ]
            );
            assert!(
                unscanned.is_empty(),
                "the scan policy scanned the image: {unscanned:?}"
            );
            assert!(guard_repaired.is_empty());
            assert!(!chain_skipped);
        }
        e => panic!("unexpected {e:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn identical_prefix_redacts_identically_across_requests() {
    let fx = fixture();
    let tpl = read_fixture("anthropic/claude_code_request.json");
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), up, |_| {}).await;
    for _ in 0..3 {
        send(&h, "/anthropic/v1/messages", AUTH, fill(&tpl, &fx), false).await;
    }
    let got = h.upstream.received();
    assert!(got.windows(2).all(|w| w[0].body == w[1].body));
}

/// Concatenated text per content block index, plus the event type sequence.
fn collect(body: &str) -> (Vec<String>, std::collections::BTreeMap<u64, String>, String) {
    let mut kinds = Vec::new();
    let mut blocks = std::collections::BTreeMap::<u64, String>::new();
    let mut sig = String::new();
    for (name, v) in events(body) {
        let name = name.unwrap();
        if name != "content_block_delta" {
            kinds.push(name.clone());
        }
        if name == "content_block_delta" {
            let i = v["index"].as_u64().unwrap();
            let d = &v["delta"];
            let t = match d["type"].as_str().unwrap() {
                "text_delta" => d["text"].as_str().unwrap(),
                "thinking_delta" => d["thinking"].as_str().unwrap(),
                "input_json_delta" => d["partial_json"].as_str().unwrap(),
                "signature_delta" => {
                    sig.push_str(d["signature"].as_str().unwrap());
                    continue;
                }
                other => panic!("delta {other}"),
            };
            blocks.entry(i).or_default().push_str(t);
        }
    }
    (kinds, blocks, sig)
}

#[tokio::test(flavor = "multi_thread")]
async fn recorded_stream_restored_under_policy_for_every_chunking() {
    let fx = fixture();
    let stream = fill(&read_fixture("anthropic/stream_tool_use.sse"), &fx);
    let v0 = fx.value("s0");
    let p0 = fx.placeholder("s0");
    let p1 = fx.placeholder("s1");
    let (want_kinds, upstream_blocks, want_sig) = collect(&stream);

    for sizes in [
        vec![1],
        vec![2, 3, 5, 7],
        vec![17],
        vec![64, 1, 128],
        vec![1 << 20],
    ] {
        let chunks = chunked(&stream, &sizes);
        let up = FakeUpstream::start(Scripted::sse(chunks)).await;
        let h = start(Some(&fx), up, |_| {}).await;
        let r = send(
            &h,
            "/anthropic/v1/messages",
            AUTH,
            r#"{"model":"m","stream":true,"messages":[]}"#,
            false,
        )
        .await;
        assert_eq!(r.status, 200);
        assert_eq!(r.headers["content-type"], "text/event-stream");
        let body = r.text();
        let (kinds, blocks, sig) = collect(&body);
        assert_eq!(kinds, want_kinds, "non-delta events keep type and order");
        // Thinking and its signature are byte-identical: never restored.
        assert_eq!(blocks[&0], upstream_blocks[&0]);
        assert!(blocks[&0].contains(&p0));
        assert_eq!(sig, want_sig);
        assert!(body.contains(&format!(r#""signature":"{want_sig}""#)));
        // Text resolves display values; the credential stays a placeholder.
        assert_eq!(
            blocks[&1],
            format!(
                "The connection string uses {v0} as the password and the Stripe key {p1} is a credential. Ünïcode ✓."
            )
        );
        // Tool input resolves inside the JSON string and stays valid JSON.
        let input: serde_json::Value = serde_json::from_str(&blocks[&2]).unwrap();
        assert_eq!(
            input["command"],
            format!("psql 'postgres://app:{v0}@db.internal/app' -c 'select 1'")
        );
        assert!(!body.contains(&fx.value("s1")), "credential never restored");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn keep_policy_streams_byte_identical() {
    let mut fx = fixture();
    fx.policy = FakePolicy::keep_all();
    let stream = fill(&read_fixture("anthropic/stream_tool_use.sse"), &fx);
    let up = FakeUpstream::start(Scripted::sse(chunked(&stream, &[3, 11]))).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let r = send(&h, "/anthropic/v1/messages", AUTH, "{}", false).await;
    // Held bytes are re-emitted as their own deltas, so compare the decoded content.
    let (k1, b1, s1) = collect(&r.text());
    let (k2, b2, s2) = collect(&stream);
    assert_eq!((k1, b1, s1), (k2, b2, s2));
}

#[tokio::test(flavor = "multi_thread")]
async fn buffered_tool_mode_sees_full_arguments() {
    let mut fx = fixture();
    fx.policy = FakePolicy {
        buffered: vec!["Bash".into()],
        ..FakePolicy::resolve_all()
    };
    let seen = fx.policy.seen.clone();
    let stream = fill(&read_fixture("anthropic/stream_tool_use.sse"), &fx);
    let up = FakeUpstream::start(Scripted::sse(chunked(&stream, &[9]))).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let r = send(&h, "/anthropic/v1/messages", AUTH, "{}", false).await;
    let (_, blocks, _) = collect(&r.text());
    let input: serde_json::Value = serde_json::from_str(&blocks[&2]).unwrap();
    assert!(input["command"].as_str().unwrap().contains(&fx.value("s0")));
    let seen = seen.lock().unwrap();
    let bash: Vec<_> = seen.iter().filter(|(t, _)| t == "Bash").collect();
    assert!(!bash.is_empty());
    assert!(
        bash.iter()
            .all(|(_, args)| args.as_deref().is_some_and(|a| a.contains("description")))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn non_streaming_response_restored_and_errors_pass_through() {
    let fx = fixture();
    let p0 = fx.placeholder("s0");
    let body = format!(
        r#"{{"id":"msg_1","type":"message","role":"assistant","content":[{{"type":"thinking","thinking":"{p0}","signature":"c2ln"}},{{"type":"text","text":"pw {p0}"}},{{"type":"tool_use","id":"t","name":"Bash","input":{{"command":"echo {p0}"}}}}],"stop_reason":"tool_use"}}"#
    );
    let up = FakeUpstream::start(Scripted::json(200, body)).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let r = send(&h, "/anthropic/v1/messages", AUTH, "{}", false).await;
    let v = r.json();
    assert_eq!(v["content"][0]["thinking"], p0.as_str());
    assert_eq!(v["content"][1]["text"], format!("pw {}", fx.value("s0")));
    assert_eq!(
        v["content"][2]["input"]["command"],
        format!("echo {}", fx.value("s0"))
    );
    assert_eq!(r.headers["content-length"], r.body.len().to_string());

    let err = r#"{"type":"error","error":{"type":"rate_limit_error","message":"Number of request tokens has exceeded your per-minute rate limit"}}"#;
    let up = FakeUpstream::start(Scripted {
        status: 429,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("retry-after".into(), "17".into()),
            ("anthropic-ratelimit-tokens-remaining".into(), "0".into()),
        ],
        chunks: vec![err.into()],
        delay: std::time::Duration::ZERO,
    })
    .await;
    let h = start(Some(&fx), up, |_| {}).await;
    let r = send(&h, "/anthropic/v1/messages", AUTH, "{}", false).await;
    assert_eq!(r.status, 429);
    assert_eq!(r.headers["retry-after"], "17");
    assert_eq!(r.headers["anthropic-ratelimit-tokens-remaining"], "0");
    assert_eq!(r.text(), err);
}

#[tokio::test(flavor = "multi_thread")]
async fn count_tokens_and_get_requests_are_routed() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, r#"{"input_tokens":3}"#)).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let body = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"{}"}}]}}"#,
        fx.value("s0")
    );
    let r = send(&h, "/anthropic/v1/messages/count_tokens", AUTH, body, false).await;
    assert_eq!(r.status, 200);
    assert!(fx.leaks(&h.upstream.received()[0].body).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn fallback_detectors_never_touch_signed_or_opaque_content() {
    let mut fx = fixture();
    // A detector that fires on a fragment present in the thinking signature, the redacted
    // thinking blob, the base64 image and (as a control) in an ordinary user message.
    let marker = "EqQBCkgI";
    fx.detector = Some(marker.into());
    let tpl = read_fixture("anthropic/claude_code_request.json");
    let tpl = tpl.replace("fix it", &format!("fix it {marker}"));
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), up, |_| {}).await;
    send(&h, "/anthropic/v1/messages", AUTH, fill(&tpl, &fx), false).await;
    let sent = String::from_utf8(h.upstream.received()[0].body.to_vec()).unwrap();
    let want = fill_redacted(&tpl, &fx).replace(
        &format!("fix it {marker}"),
        &format!("fix it {}", scrim_llm::testing::DETECTED),
    );
    assert_eq!(sent, want);
    match &h.audit.events()[0] {
        AuditEvent::Forwarded { detectors, .. } => {
            assert_eq!(detectors, &vec!["fake-pattern".to_string()])
        }
        e => panic!("unexpected {e:?}"),
    }
}
