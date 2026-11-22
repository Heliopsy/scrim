// SPDX-License-Identifier: AGPL-3.0-only

//! Cloud provider routes end to end (llm-proxy spec, "Cloud provider routes"): Bedrock
//! `InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, `ConverseStream` and
//! `count-tokens` through the proxy, signed after redaction with credentials from the snapshot,
//! against a fake upstream whose requests are checked with an independent `SigV4` verifier.

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

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use common::*;
use scrim_llm::auth::AuthConfig;
use scrim_llm::eventstream::{self, HeaderValue, Message};
use scrim_llm::route::RouteTable;
use scrim_llm::testing::{FakeUpstream, Fixture, RecordingAudit, Scripted};
use scrim_llm::{AuditEvent, Provider, Proxy, ProxyConfig, RouteConfig, SecretValue, SnapshotCell};
use scrim_toolproxy::sigv4_testing as sig;

const AKID_REF: &str = "bao://kv/aws#access_key_id";
const SECRET_REF: &str = "bao://kv/aws#secret_access_key";
const TOKEN_REF: &str = "bao://kv/aws#session_token";
const KEY_REF: &str = "bao://kv/foundry#api_key";

struct Creds {
    akid: String,
    secret: String,
    token: String,
    key: String,
}

fn creds() -> Creds {
    Creds {
        akid: format!(
            "AKIA{}",
            scrim_llm::testing::random_value("").to_uppercase()[..16].to_owned()
        ),
        secret: scrim_llm::testing::random_value("aws-secret-"),
        token: scrim_llm::testing::random_value("aws-token-"),
        key: scrim_llm::testing::random_value("foundry-key-"),
    }
}

fn bedrock_route(url: &str, session_token: bool) -> RouteConfig {
    RouteConfig {
        name: "bedrock".into(),
        prefix: "/bedrock".into(),
        upstream: url.into(),
        provider: Provider::Bedrock,
        strip_prefix: true,
        chain: None,
        hosts: vec!["bedrock-runtime.us-east-1.amazonaws.com".into()],
        auth: Some(AuthConfig::AwsSigv4 {
            region: "us-east-1".into(),
            service: "bedrock".into(),
            access_key_id: AKID_REF.into(),
            secret_access_key: SECRET_REF.into(),
            session_token: session_token.then(|| TOKEN_REF.into()),
        }),
    }
}

fn key_route(url: &str) -> RouteConfig {
    RouteConfig {
        name: "foundry".into(),
        prefix: "/foundry".into(),
        upstream: format!("{url}/anthropic"),
        provider: Provider::Anthropic,
        strip_prefix: true,
        chain: None,
        hosts: vec![],
        auth: Some(AuthConfig::Header {
            name: "api-key".into(),
            prefix: String::new(),
            value: KEY_REF.into(),
        }),
    }
}

struct Cloud {
    h: Harness2,
    c: Creds,
}

struct Harness2 {
    addr: std::net::SocketAddr,
    upstream: FakeUpstream,
    audit: RecordingAudit,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Harness2 {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

/// A proxy whose snapshot carries the cloud routes, their credentials looked up from `have`.
async fn cloud(fx: &Fixture, upstream: FakeUpstream, have: &[&str], session_token: bool) -> Cloud {
    let c = creds();
    let routes = vec![
        bedrock_route(&upstream.url(), session_token),
        key_route(&upstream.url()),
    ];
    let values = [
        (AKID_REF, c.akid.clone()),
        (SECRET_REF, c.secret.clone()),
        (TOKEN_REF, c.token.clone()),
        (KEY_REF, c.key.clone()),
    ];
    let table = RouteTable::with_credentials(&routes, &|r| {
        values
            .iter()
            .find(|(k, _)| *k == r && have.contains(k))
            .map(|(_, v)| SecretValue::new(v.as_bytes().to_vec()))
    })
    .unwrap();
    let mut snap = fx.snapshot();
    snap.routes = Some(Arc::new(table));
    let cell = Arc::new(SnapshotCell::with(snap));
    let audit = RecordingAudit::default();
    let cfg = ProxyConfig {
        routes,
        ..ProxyConfig::default()
    };
    let proxy = Arc::new(Proxy::new(cfg, cell, Arc::new(audit.clone())).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(scrim_llm::server::serve_tcp(listener, proxy, async {
        let _ = rx.await;
    }));
    Cloud {
        h: Harness2 {
            addr,
            upstream,
            audit,
            stop: Some(tx),
        },
        c,
    }
}

const ALL: &[&str] = &[AKID_REF, SECRET_REF, TOKEN_REF, KEY_REF];

async fn post(cl: &Cloud, path: &str, headers: &[(&str, &str)], body: impl Into<Bytes>) -> Reply {
    use http_body_util::{BodyExt, Full};
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http::<Full<Bytes>>();
    let mut req = http::Request::builder()
        .method("POST")
        .uri(format!("http://{}{path}", cl.h.addr));
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

/// The agent's own (dummy) AWS signature, which must never reach the provider.
const AGENT: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    (
        "authorization",
        "AWS4-HMAC-SHA256 Credential=AKIDAGENTDUMMY/20260101/us-east-1/bedrock/aws4_request, SignedHeaders=host, Signature=00",
    ),
    ("x-amz-date", "20260101T000000Z"),
    ("x-amz-security-token", "agent-dummy-token"),
    ("x-api-key", "agent-dummy-key"),
];

/// Checks the request the provider got was signed with the real secret over its exact bytes.
fn assert_signed(cl: &Cloud, r: &scrim_llm::testing::Recorded, with_token: bool) {
    let uri: http::Uri = r.uri.parse().unwrap();
    let akid = sig::verify(
        &r.method,
        &uri,
        &r.headers,
        Some(&r.body),
        cl.c.secret.as_bytes(),
    );
    assert_eq!(
        akid.as_deref(),
        Some(cl.c.akid.as_str()),
        "signature over the forwarded bytes"
    );
    assert!(
        sig::verify(
            &r.method,
            &uri,
            &r.headers,
            Some(b"{}"),
            cl.c.secret.as_bytes()
        )
        .is_none(),
        "the signature covers the body"
    );
    let token = r
        .headers
        .get("x-amz-security-token")
        .map(|v| v.to_str().unwrap().to_owned());
    if with_token {
        assert_eq!(token.as_deref(), Some(cl.c.token.as_str()));
    } else {
        assert!(token.is_none());
    }
    assert!(r.headers.get("x-api-key").is_none());
    let auth = r.headers["authorization"].to_str().unwrap();
    assert!(!auth.contains("AKIDAGENTDUMMY"));
}

fn anthropic_body(fx: &Fixture) -> String {
    format!(
        r#"{{"anthropic_version":"bedrock-2023-05-31","max_tokens":64,"messages":[{{"role":"user","content":"deploy with {}"}}]}}"#,
        fx.value("s0")
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn invoke_model_is_redacted_then_signed() {
    let fx = fixture();
    let reply = format!(
        r#"{{"id":"msg_1","type":"message","role":"assistant","content":[{{"type":"text","text":"used {}"}}],"stop_reason":"end_turn"}}"#,
        fx.placeholder("s0")
    );
    let up = FakeUpstream::start(Scripted::json(200, reply)).await;
    let cl = cloud(&fx, up, ALL, true).await;
    let path = "/bedrock/model/us.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke";
    let r = post(&cl, path, AGENT, anthropic_body(&fx)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.json()["content"][0]["text"],
        format!("used {}", fx.value("s0"))
    );
    let got = cl.h.upstream.received();
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].uri,
        "/model/us.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke"
    );
    assert!(fx.leaks(&got[0].body).is_empty());
    assert!(
        std::str::from_utf8(&got[0].body)
            .unwrap()
            .contains(&fx.placeholder("s0"))
    );
    assert_signed(&cl, &got[0], true);
    assert!(
        matches!(&cl.h.audit.events()[0], AuditEvent::Forwarded { route, .. } if route == "bedrock")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_credentials_refuse_without_sending() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let cl = cloud(&fx, up, &[AKID_REF, KEY_REF], false).await;
    let r = post(&cl, "/bedrock/model/m/invoke", AGENT, anthropic_body(&fx)).await;
    assert_eq!(r.status, 503);
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "credential_unavailable");
    assert!(r.text().contains(SECRET_REF), "{}", r.text());
    assert!(cl.h.upstream.received().is_empty());
    assert!(matches!(
        &cl.h.audit.events()[0],
        AuditEvent::Refused {
            reason: scrim_llm::RefusalReason::CredentialUnavailable,
            ..
        }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn long_term_keys_sign_without_a_session_token() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, r#"{"content":[]}"#)).await;
    let cl = cloud(&fx, up, ALL, false).await;
    let r = post(&cl, "/bedrock/model/m/invoke", AGENT, anthropic_body(&fx)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_signed(&cl, &cl.h.upstream.received()[0], false);
}

fn chunk(event: &serde_json::Value) -> Vec<u8> {
    let data = serde_json::to_vec(event).unwrap();
    Message {
        headers: vec![
            (":event-type".into(), HeaderValue::String("chunk".into())),
            (
                ":content-type".into(),
                HeaderValue::String("application/json".into()),
            ),
            (":message-type".into(), HeaderValue::String("event".into())),
        ],
        payload: format!(r#"{{"bytes":"{}","p":"abcdefgh"}}"#, B64.encode(data)).into_bytes(),
    }
    .encode()
}

fn event_stream(frames: &[Vec<u8>], sizes: &[usize]) -> Scripted {
    let all: Vec<u8> = frames.concat();
    let mut chunks = Vec::new();
    let (mut pos, mut i) = (0, 0);
    while pos < all.len() {
        let n = sizes[i % sizes.len()].min(all.len() - pos);
        chunks.push(Bytes::copy_from_slice(&all[pos..pos + n]));
        pos += n;
        i += 1;
    }
    Scripted {
        status: 200,
        headers: vec![("content-type".into(), eventstream::CONTENT_TYPE.into())],
        chunks,
        delay: std::time::Duration::ZERO,
    }
}

/// Decodes every frame of a body, failing on a bad CRC.
fn frames(body: &[u8]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let total = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        out.push(eventstream::decode(&rest[..total]).expect("valid frame"));
        rest = &rest[total..];
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn invoke_stream_restores_inside_frames_split_anywhere() {
    let fx = fixture();
    let ph = fx.placeholder("s0");
    let cut = ph.char_indices().nth(5).unwrap().0;
    let up_frames = vec![
        chunk(
            &serde_json::json!({"type":"message_start","message":{"id":"m","type":"message","role":"assistant","content":[]}}),
        ),
        chunk(
            &serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        ),
        chunk(
            &serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":format!("pw is {}", &ph[..cut])}}),
        ),
        chunk(
            &serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":format!("{} ok", &ph[cut..])}}),
        ),
        chunk(&serde_json::json!({"type":"content_block_stop","index":0})),
        chunk(
            &serde_json::json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}),
        ),
        chunk(
            &serde_json::json!({"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":1}}),
        ),
    ];
    for sizes in [&[7usize, 3, 50][..], &[1], &[100_000]] {
        let up = FakeUpstream::start(event_stream(&up_frames, sizes)).await;
        let cl = cloud(&fx, up, ALL, true).await;
        let r = post(
            &cl,
            "/bedrock/model/m/invoke-with-response-stream",
            AGENT,
            anthropic_body(&fx),
        )
        .await;
        assert_eq!(r.status, 200);
        assert_eq!(r.headers["content-type"], eventstream::CONTENT_TYPE);
        let got = frames(&r.body);
        let mut text = String::new();
        let mut types = Vec::new();
        for m in &got {
            assert_eq!(m.header_str(":event-type"), Some("chunk"));
            let p: serde_json::Value = serde_json::from_slice(&m.payload).unwrap();
            let ev: serde_json::Value =
                serde_json::from_slice(&B64.decode(p["bytes"].as_str().unwrap()).unwrap()).unwrap();
            types.push(ev["type"].as_str().unwrap().to_owned());
            if let Some(t) = ev["delta"]["text"].as_str() {
                text.push_str(t);
            }
        }
        assert_eq!(
            text,
            format!("pw is {} ok", fx.value("s0")),
            "sizes {sizes:?}"
        );
        types.dedup();
        assert_eq!(
            types,
            [
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop"
            ]
        );
        // Frames without a placeholder leave byte for byte, padding included.
        assert!(r.body.starts_with(&up_frames[0]));
        assert!(r.body.ends_with(&up_frames[6]));
        assert_signed(&cl, &cl.h.upstream.received()[0], true);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_event_stream_passes_through_untouched() {
    let fx = fixture();
    let mut f = chunk(
        &serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":fx.placeholder("s0")}}),
    );
    let n = f.len();
    f[n - 1] ^= 0xff;
    let up = FakeUpstream::start(event_stream(&[f.clone()], &[5])).await;
    let cl = cloud(&fx, up, ALL, true).await;
    let r = post(
        &cl,
        "/bedrock/model/m/invoke-with-response-stream",
        AGENT,
        anthropic_body(&fx),
    )
    .await;
    assert_eq!(&r.body[..], &f[..], "kept as received, placeholder and all");
}

fn converse_frame(event: &str, payload: serde_json::Value) -> Vec<u8> {
    Message {
        headers: vec![
            (":event-type".into(), HeaderValue::String(event.into())),
            (
                ":content-type".into(),
                HeaderValue::String("application/json".into()),
            ),
            (":message-type".into(), HeaderValue::String("event".into())),
        ],
        payload: serde_json::to_vec(&payload).unwrap(),
    }
    .encode()
}

#[tokio::test(flavor = "multi_thread")]
async fn converse_and_converse_stream() {
    let fx = fixture();
    let body = format!(
        r#"{{"messages":[{{"role":"user","content":[{{"text":"use {}"}}]}}],"inferenceConfig":{{"maxTokens":64}}}}"#,
        fx.value("s0")
    );
    // Non-streaming.
    let reply = format!(
        r#"{{"output":{{"message":{{"role":"assistant","content":[{{"text":"ok {}"}}]}}}},"stopReason":"end_turn","usage":{{"inputTokens":1,"outputTokens":1,"totalTokens":2}}}}"#,
        fx.placeholder("s0")
    );
    let up = FakeUpstream::start(Scripted::json(200, reply)).await;
    let cl = cloud(&fx, up, ALL, true).await;
    let r = post(&cl, "/bedrock/model/m/converse", AGENT, body.clone()).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.json()["output"]["message"]["content"][0]["text"],
        format!("ok {}", fx.value("s0"))
    );
    let got = cl.h.upstream.received();
    assert!(fx.leaks(&got[0].body).is_empty());
    assert!(
        std::str::from_utf8(&got[0].body)
            .unwrap()
            .contains(r#""inferenceConfig":{"maxTokens":64}"#)
    );
    assert_signed(&cl, &got[0], true);

    // Streaming, the placeholder split across two deltas.
    let ph = fx.placeholder("s0");
    let cut = ph.char_indices().nth(4).unwrap().0;
    let up_frames = vec![
        converse_frame("messageStart", serde_json::json!({"role":"assistant"})),
        converse_frame(
            "contentBlockDelta",
            serde_json::json!({"contentBlockIndex":0,"delta":{"text":format!("pw {}", &ph[..cut])}}),
        ),
        converse_frame(
            "contentBlockDelta",
            serde_json::json!({"contentBlockIndex":0,"delta":{"text":format!("{}.", &ph[cut..])}}),
        ),
        converse_frame(
            "contentBlockStop",
            serde_json::json!({"contentBlockIndex":0}),
        ),
        converse_frame("messageStop", serde_json::json!({"stopReason":"end_turn"})),
        converse_frame(
            "metadata",
            serde_json::json!({"usage":{"inputTokens":1,"outputTokens":2,"totalTokens":3},"metrics":{"latencyMs":1}}),
        ),
    ];
    let up = FakeUpstream::start(event_stream(&up_frames, &[9, 2])).await;
    let cl = cloud(&fx, up, ALL, true).await;
    let r = post(&cl, "/bedrock/model/m/converse-stream", AGENT, body).await;
    assert_eq!(r.status, 200);
    let mut text = String::new();
    let mut kinds = Vec::new();
    for m in frames(&r.body) {
        kinds.push(m.header_str(":event-type").unwrap().to_owned());
        let p: serde_json::Value = serde_json::from_slice(&m.payload).unwrap();
        if let Some(t) = p["delta"]["text"].as_str() {
            text.push_str(t);
        }
    }
    assert_eq!(text, format!("pw {}.", fx.value("s0")));
    kinds.dedup();
    assert_eq!(
        kinds,
        [
            "messageStart",
            "contentBlockDelta",
            "contentBlockStop",
            "messageStop",
            "metadata"
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn count_tokens_redacts_the_embedded_body() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, r#"{"inputTokens":12}"#)).await;
    let cl = cloud(&fx, up, ALL, true).await;
    let body = format!(
        r#"{{"input":{{"invokeModel":{{"body":"{}"}}}}}}"#,
        B64.encode(anthropic_body(&fx))
    );
    let r = post(&cl, "/bedrock/model/m/count-tokens", AGENT, body).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let got = cl.h.upstream.received();
    let v: serde_json::Value = serde_json::from_slice(&got[0].body).unwrap();
    let inner = B64
        .decode(v["input"]["invokeModel"]["body"].as_str().unwrap())
        .unwrap();
    assert!(fx.leaks(&inner).is_empty());
    assert!(
        std::str::from_utf8(&inner)
            .unwrap()
            .contains(&fx.placeholder("s0"))
    );
    assert_signed(&cl, &got[0], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn header_auth_replaces_the_agents_key() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, r#"{"type":"message","content":[]}"#)).await;
    let cl = cloud(&fx, up, ALL, true).await;
    let body = format!(
        r#"{{"model":"claude-x","max_tokens":5,"messages":[{{"role":"user","content":"{}"}}]}}"#,
        fx.value("s0")
    );
    let r = post(
        &cl,
        "/foundry/v1/messages",
        &[
            ("content-type", "application/json"),
            ("api-key", "agent-dummy"),
            ("authorization", "Bearer agent-dummy"),
            ("anthropic-version", "2023-06-01"),
        ],
        body,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let got = cl.h.upstream.received();
    assert_eq!(got[0].uri, "/anthropic/v1/messages");
    assert_eq!(got[0].headers["api-key"], cl.c.key.as_str());
    assert!(got[0].headers.get("authorization").is_none());
    assert_eq!(got[0].headers["anthropic-version"], "2023-06-01");
    assert!(fx.leaks(&got[0].body).is_empty());
}
