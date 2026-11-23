// SPDX-License-Identifier: AGPL-3.0-only

//! Gemini generateContent through the proxy, against recorded fixtures: the request redacted
//! byte for byte, the agent's key passed through, and placeholders restored in the SSE stream,
//! the JSON-array stream and the non-streaming response.

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
use scrim_llm::config::CaptureConfig;
use scrim_llm::testing::{FakeUpstream, Fixture, Scripted};
use scrim_llm::{AuditEvent, ValueClass};

const KEY: &str = "AIzaSyAgentOwnKeyForTests-0123456789";

const AUTH: &[(&str, &str)] = &[
    ("x-goog-api-key", KEY),
    (
        "x-goog-api-client",
        "google-genai-sdk/1.30.0 gl-node/v22.19.0",
    ),
    ("user-agent", "GeminiCLI/0.17.1 (linux; x64)"),
    ("content-type", "application/json"),
];

const STREAM_PATH: &str = "/gemini/v1beta/models/gemini-2.5-pro:streamGenerateContent";

/// The stream template with `{{P0a}}{{P0b}}` cut inside s0's placeholder, then filled.
fn stream_fixture(name: &str, fx: &Fixture) -> String {
    let ph = fx.placeholder("s0");
    let cut = ph.char_indices().nth(5).unwrap().0;
    let tpl = read_fixture(name)
        .replace("{{P0a}}", &ph[..cut])
        .replace("{{P0b}}", &ph[cut..]);
    fill(&tpl, fx)
}

/// What the agent's client reassembles from the chunks: visible text, thought text and the
/// function calls, checking that no text follows a finish reason.
struct Seen {
    text: String,
    thoughts: String,
    calls: Vec<serde_json::Value>,
    signatures: Vec<String>,
    chunks: usize,
}

fn reassemble(chunks: &[serde_json::Value]) -> Seen {
    let mut s = Seen {
        text: String::new(),
        thoughts: String::new(),
        calls: Vec::new(),
        signatures: Vec::new(),
        chunks: chunks.len(),
    };
    let mut finished = false;
    for c in chunks {
        let cand = &c["candidates"][0];
        for p in cand["content"]["parts"].as_array().unwrap() {
            if let Some(t) = p["text"].as_str() {
                assert!(!finished, "text after finishReason");
                if p["thought"] == true {
                    s.thoughts.push_str(t);
                } else {
                    s.text.push_str(t);
                }
            }
            if p.get("functionCall").is_some() {
                s.calls.push(p["functionCall"].clone());
            }
            if let Some(sig) = p["thoughtSignature"].as_str() {
                s.signatures.push(sig.to_string());
            }
        }
        if cand["finishReason"].is_string() {
            finished = true;
        }
        assert_eq!(c["responseId"], "k8kgaZ2dMbSGkdUPo4LZ8Ac", "envelope kept");
    }
    s
}

fn check_stream(fx: &Fixture, seen: &Seen, upstream: &str) {
    let (v0, v2) = (fx.value("s0"), fx.value("s2"));
    let (p0, p1) = (fx.placeholder("s0"), fx.placeholder("s1"));
    assert_eq!(
        seen.text,
        format!(
            "The database password is {v0} and it works for `{v2}`; the Stripe key {p1} stays hidden. I'll update the connection string."
        )
    );
    assert!(seen.thoughts.contains(&p0), "thoughts are not restored");
    assert_eq!(seen.calls.len(), 1);
    assert_eq!(seen.calls[0]["name"], "run_shell_command");
    assert_eq!(
        seen.calls[0]["args"]["command"],
        format!(
            "sed -i 's|^DATABASE_URL=.*|DATABASE_URL=postgres://{v2}:{v0}@db.internal/billing|' .env"
        )
    );
    // The signature carries a placeholder-looking text and is never touched.
    let up_sig = upstream
        .split("\"thoughtSignature\"")
        .nth(1)
        .unwrap()
        .split('"')
        .nth(1)
        .unwrap();
    assert_eq!(seen.signatures, vec![up_sig.to_string()]);
    assert!(!seen.text.contains(&fx.value("s1")));
}

#[tokio::test(flavor = "multi_thread")]
async fn request_redacted_byte_exact_with_key_and_signatures_kept() {
    let mut fx = fixture();
    // A detector hit inside the thought signature must not touch it.
    fx.detector = Some("CiQB0e2Kb7Hj".into());
    // The agent's own key is known to scrim too: it still leaves as sent, in the header and in
    // the query.
    fx.add("gemini-key", KEY, ValueClass::Credential);
    let tpl = read_fixture("gemini/request.json");
    let up = FakeUpstream::start(Scripted::sse(vec![Bytes::from_static(b"")])).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let path = format!("{STREAM_PATH}?alt=sse&key={KEY}");
    let r = send(&h, &path, AUTH, fill(&tpl, &fx), false).await;
    assert_eq!(r.status, 200);
    let req = &h.upstream.received()[0];
    assert_eq!(
        req.uri,
        format!("/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse&key={KEY}"),
        "the key query parameter is the agent's credential and passes through"
    );
    assert_eq!(
        std::str::from_utf8(&req.body).unwrap(),
        fill_redacted(&tpl, &fx)
    );
    for (k, v) in AUTH {
        assert_eq!(req.headers.get(*k).unwrap(), v);
    }
    match &h.audit.events()[0] {
        AuditEvent::Forwarded {
            unscanned,
            replacements,
            ..
        } => {
            assert_eq!(unscanned, &vec!["image/png".to_string()]);
            assert_eq!(*replacements, tpl.matches("{{S").count());
        }
        e => panic!("{e:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sse_stream_restored_for_every_chunking() {
    let fx = fixture();
    let stream = stream_fixture("gemini/stream.sse", &fx);
    for sizes in [vec![1], vec![5, 3], vec![31], vec![1 << 20]] {
        let up = FakeUpstream::start(Scripted::sse(chunked(&stream, &sizes))).await;
        let h = start(Some(&fx), up, |_| {}).await;
        let r = send(&h, &format!("{STREAM_PATH}?alt=sse"), AUTH, "{}", false).await;
        assert_eq!(r.status, 200);
        let chunks: Vec<serde_json::Value> = r
            .text()
            .split("\r\n\r\n")
            .flat_map(|e| e.split("\n\n"))
            .filter(|e| !e.trim().is_empty())
            .map(|e| serde_json::from_str(e.trim().strip_prefix("data: ").unwrap()).unwrap())
            .collect();
        let seen = reassemble(&chunks);
        check_stream(&fx, &seen, &stream);
        assert_eq!(seen.chunks, 5, "no chunk added or lost");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn json_array_stream_restored_incrementally_for_every_chunking() {
    let fx = fixture();
    let stream = stream_fixture("gemini/stream.json", &fx);
    for sizes in [vec![1], vec![7, 2], vec![64], vec![1 << 20]] {
        let up = FakeUpstream::start(Scripted {
            status: 200,
            headers: vec![(
                "content-type".into(),
                "application/json; charset=UTF-8".into(),
            )],
            chunks: chunked(&stream, &sizes),
            delay: std::time::Duration::ZERO,
        })
        .await;
        let h = start(Some(&fx), up, |_| {}).await;
        let r = send(&h, STREAM_PATH, AUTH, "{}", false).await;
        assert_eq!(r.status, 200);
        let chunks: Vec<serde_json::Value> = serde_json::from_slice(&r.body).unwrap();
        let seen = reassemble(&chunks);
        check_stream(&fx, &seen, &stream);
        assert_eq!(seen.chunks, 5);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn json_array_stream_is_not_buffered_whole() {
    // A stream larger than max-response-body still restores: it is framed element by element.
    let fx = fixture();
    let stream = stream_fixture("gemini/stream.json", &fx);
    let up = FakeUpstream::start(Scripted {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        chunks: chunked(&stream, &[100]),
        delay: std::time::Duration::ZERO,
    })
    .await;
    let h = start(Some(&fx), up, |c| c.limits.max_response_body = 600).await;
    let r = send(&h, STREAM_PATH, AUTH, "{}", false).await;
    let chunks: Vec<serde_json::Value> = serde_json::from_slice(&r.body).unwrap();
    check_stream(&fx, &reassemble(&chunks), &stream);
}

#[tokio::test(flavor = "multi_thread")]
async fn non_streaming_response_restored() {
    let fx = fixture();
    let body = fill(&read_fixture("gemini/response.json"), &fx);
    let up = FakeUpstream::start(Scripted::json(200, body)).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let v = send(
        &h,
        "/gemini/v1beta/models/gemini-2.5-pro:generateContent",
        AUTH,
        "{}",
        false,
    )
    .await
    .json();
    let (v0, v2, p0, p1) = (
        fx.value("s0"),
        fx.value("s2"),
        fx.placeholder("s0"),
        fx.placeholder("s1"),
    );
    let parts = &v["candidates"][0]["content"]["parts"];
    assert!(parts[0]["text"].as_str().unwrap().contains(&p0));
    assert_eq!(
        parts[1]["text"],
        format!(
            "The service reads `DB_PASSWORD={v0}` for user `{v2}`. The Stripe key {p1} is unused here."
        )
    );
    assert_eq!(
        parts[2]["functionCall"]["args"]["command"],
        format!("PGPASSWORD='{v0}' psql -h db.internal -U {v2} -c 'select 1'")
    );
    assert_eq!(
        parts[2]["thoughtSignature"],
        "CiQB0e2Kb3NpZ25hdHVyZUZvclRlc3RzT25seVt7e1AwfX1d"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_and_ambiguous_requests_refused_in_gemini_shape() {
    let fx = fixture();
    let v = fx.value("s0");
    for bad in [
        format!("{{\"contents\":[{{\"parts\":[{{\"text\":\"{v}\"}}]}}"),
        format!("{{\"contents\":{{\"parts\":[{{\"text\":\"{v}\"}}]}}}}"),
        format!(
            "{{\"contents\":[{{\"parts\":[{{\"text\":\"{v}\",\"thought\":true,\"thought\":false}}]}}]}}"
        ),
        format!(
            "{{\"contents\":[{{\"parts\":[{{\"inlineData\":{{\"data\":\"{v}\"}},\"inline_data\":{{\"data\":\"x\"}}}}]}}]}}"
        ),
        "[]".to_string(),
    ] {
        let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
        let h = start(Some(&fx), up, |_| {}).await;
        let r = send(
            &h,
            "/gemini/v1beta/models/gemini-2.5-pro:generateContent",
            AUTH,
            bad.clone(),
            false,
        )
        .await;
        assert_eq!(r.status, 422, "{bad}");
        assert_eq!(r.headers["x-scrim-error"], "malformed_body");
        let e = r.json();
        assert_eq!(e["error"]["code"], 422);
        assert_eq!(e["error"]["status"], "INVALID_ARGUMENT");
        assert!(!r.text().contains(&v));
        assert!(h.upstream.received().is_empty(), "nothing forwarded");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn count_tokens_and_other_methods_redacted() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, r#"{"totalTokens":31}"#)).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let (v0, p0) = (fx.value("s0"), fx.placeholder("s0"));
    let body = format!(
        r#"{{"generateContentRequest":{{"model":"models/gemini-2.5-pro","contents":[{{"role":"user","parts":[{{"text":"pw {v0}"}}]}}]}}}}"#
    );
    let r = send(
        &h,
        "/gemini/v1beta/models/gemini-2.5-pro:countTokens",
        AUTH,
        body,
        false,
    )
    .await;
    assert_eq!(r.status, 200);
    let body = format!(
        r#"{{"model":"models/text-embedding-004","content":{{"parts":[{{"text":"{v0}"}}]}}}}"#
    );
    let r = send(
        &h,
        "/gemini/v1beta/models/text-embedding-004:embedContent",
        AUTH,
        body,
        false,
    )
    .await;
    assert_eq!(r.status, 200);
    let got = h.upstream.received();
    for req in &got {
        assert!(fx.leaks(&req.body).is_empty());
        assert!(std::str::from_utf8(&req.body).unwrap().contains(&p0));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn capture_masks_the_key_query_parameter_and_header() {
    let fx = fixture();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("capture");
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let d = dir.clone();
    let h = start(Some(&fx), up, move |c| {
        c.capture = Some(CaptureConfig {
            dir: d,
            retention_secs: 3600,
        })
    })
    .await;
    let r = send(
        &h,
        &format!("/gemini/v1beta/models/gemini-2.5-pro:generateContent?key={KEY}"),
        AUTH,
        r#"{"contents":[]}"#,
        false,
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(h.upstream.received()[0].uri.ends_with(KEY));
    let mut metas = 0;
    for f in std::fs::read_dir(&dir).unwrap() {
        let p = f.unwrap().path();
        let s = String::from_utf8_lossy(&std::fs::read(&p).unwrap()).into_owned();
        assert!(!s.contains(KEY), "{}", p.display());
        if p.to_string_lossy().ends_with(".request.json") {
            assert!(s.contains("key=masked"));
            metas += 1;
        }
    }
    assert_eq!(metas, 1);
}
