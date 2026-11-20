// SPDX-License-Identifier: AGPL-3.0-only

//! OpenAI Chat Completions and Responses through the proxy.

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
use scrim_llm::testing::{FakeUpstream, Scripted};

const AUTH: &[(&str, &str)] = &[
    ("authorization", "Bearer agent-own-chatgpt-session-token"),
    ("chatgpt-account-id", "acct-for-tests"),
    ("openai-beta", "responses=experimental"),
    ("originator", "codex_cli_rs"),
    ("content-type", "application/json"),
];

#[tokio::test(flavor = "multi_thread")]
async fn chat_request_redacted_byte_exact() {
    let fx = fixture();
    let tpl = read_fixture("openai/chat_request.json");
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let r = send(
        &h,
        "/openai/v1/chat/completions",
        AUTH,
        fill(&tpl, &fx),
        false,
    )
    .await;
    assert_eq!(r.status, 200);
    let req = &h.upstream.received()[0];
    assert_eq!(req.uri, "/v1/chat/completions");
    assert_eq!(
        std::str::from_utf8(&req.body).unwrap(),
        fill_redacted(&tpl, &fx)
    );
    for (k, v) in AUTH {
        assert_eq!(req.headers.get(*k).unwrap(), v);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn responses_request_redacted_byte_exact_with_encrypted_reasoning_kept() {
    let mut fx = fixture();
    // Detector hit inside the encrypted reasoning blob: it must not be touched.
    fx.detector = Some("gAAAAABor0Aw".into());
    let tpl = read_fixture("openai/responses_request.json");
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let r = send(&h, "/openai/v1/responses", AUTH, fill(&tpl, &fx), false).await;
    assert_eq!(r.status, 200);
    let req = &h.upstream.received()[0];
    assert_eq!(req.uri, "/v1/responses");
    assert_eq!(
        std::str::from_utf8(&req.body).unwrap(),
        fill_redacted(&tpl, &fx)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn chat_stream_restored_for_every_chunking() {
    let fx = fixture();
    let stream = fill(&read_fixture("openai/chat_stream.sse"), &fx);
    let (v0, p1) = (fx.value("s0"), fx.placeholder("s1"));
    for sizes in [vec![1], vec![5, 3], vec![31], vec![1 << 20]] {
        let up = FakeUpstream::start(Scripted::sse(chunked(&stream, &sizes))).await;
        let h = start(Some(&fx), up, |_| {}).await;
        let r = send(&h, "/openai/v1/chat/completions", AUTH, "{}", false).await;
        let evs = events(&r.text());
        let mut content = String::new();
        let mut args = String::new();
        let mut finish_seen = false;
        for (_, v) in &evs {
            if v.is_null() {
                continue;
            }
            for c in v["choices"].as_array().unwrap() {
                let d = &c["delta"];
                if let Some(s) = d["content"].as_str() {
                    assert!(!finish_seen, "content after finish_reason");
                    content.push_str(s);
                }
                if let Some(calls) = d["tool_calls"].as_array() {
                    for t in calls {
                        if let Some(a) = t["function"]["arguments"].as_str() {
                            assert!(!finish_seen, "arguments after finish_reason");
                            args.push_str(a);
                        }
                    }
                }
                if c["finish_reason"].is_string() {
                    finish_seen = true;
                }
            }
        }
        assert_eq!(
            content,
            format!("The password {v0} is fine; rotate {p1} instead.")
        );
        let a: serde_json::Value = serde_json::from_str(&args).unwrap();
        assert_eq!(a["cmd"][1], v0.as_str());
        assert!(evs.last().unwrap().1.is_null(), "[DONE] stays last");
        assert!(!r.text().contains(&fx.value("s1")));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn responses_stream_deltas_done_and_completed_agree() {
    let fx = fixture();
    let stream = fill(&read_fixture("openai/responses_stream.sse"), &fx);
    let (v0, p0, p1) = (fx.value("s0"), fx.placeholder("s0"), fx.placeholder("s1"));
    let want_text = format!("DB password is {v0}; key {p1} stays hidden.");
    for sizes in [vec![1], vec![7, 2], vec![50], vec![1 << 20]] {
        let up = FakeUpstream::start(Scripted::sse(chunked(&stream, &sizes))).await;
        let h = start(Some(&fx), up, |_| {}).await;
        let r = send(&h, "/openai/v1/responses", AUTH, "{}", false).await;
        let evs = events(&r.text());
        let mut text = String::new();
        let mut args = String::new();
        let mut patch = String::new();
        let mut kinds = Vec::new();
        for (name, v) in &evs {
            let ty = v["type"].as_str().unwrap();
            assert_eq!(name.as_deref(), Some(ty));
            if !ty.ends_with(".delta") {
                kinds.push(ty.to_string());
            }
            match ty {
                "response.output_text.delta" => text.push_str(v["delta"].as_str().unwrap()),
                "response.function_call_arguments.delta" => {
                    args.push_str(v["delta"].as_str().unwrap())
                }
                "response.custom_tool_call_input.delta" => {
                    patch.push_str(v["delta"].as_str().unwrap())
                }
                "response.reasoning_summary_text.delta" => {
                    assert!(v["delta"].as_str().unwrap().contains(&p0))
                }
                "response.output_text.done" => assert_eq!(v["text"], want_text.as_str()),
                "response.function_call_arguments.done" => {
                    assert_eq!(v["arguments"].as_str().unwrap(), args)
                }
                "response.custom_tool_call_input.done" => {
                    assert_eq!(v["input"].as_str().unwrap(), patch)
                }
                "response.completed" => {
                    let out = &v["response"]["output"];
                    assert!(
                        out[0]["summary"][0]["text"].as_str().unwrap().contains(&p0),
                        "reasoning untouched"
                    );
                    assert_eq!(out[1]["content"][0]["text"], want_text.as_str());
                    assert_eq!(out[2]["arguments"].as_str().unwrap(), args);
                    assert_eq!(out[3]["input"].as_str().unwrap(), patch);
                }
                _ => {}
            }
        }
        assert_eq!(text, want_text);
        let a: serde_json::Value = serde_json::from_str(&args).unwrap();
        assert_eq!(a["command"][2], format!("echo {v0}"));
        assert!(patch.contains(&format!("-DB_PASSWORD={v0}\n")));
        let (_, up_kinds): (Vec<_>, Vec<_>) = events(&stream).into_iter().unzip();
        let up_kinds: Vec<String> = up_kinds
            .iter()
            .map(|v| v["type"].as_str().unwrap().to_string())
            .filter(|t| !t.ends_with(".delta"))
            .collect();
        assert_eq!(kinds, up_kinds);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn non_streaming_responses_and_chat_restored() {
    let fx = fixture();
    let (v0, p0) = (fx.value("s0"), fx.placeholder("s0"));
    let body = format!(
        r#"{{"id":"resp_1","object":"response","status":"completed","output":[{{"type":"reasoning","id":"rs","summary":[],"encrypted_content":"enc{p0}"}},{{"type":"message","role":"assistant","content":[{{"type":"output_text","text":"is {p0}","annotations":[]}}]}},{{"type":"function_call","name":"shell","call_id":"c","arguments":"{{\"command\":[\"echo\",\"{p0}\"]}}"}}]}}"#
    );
    let up = FakeUpstream::start(Scripted::json(200, body)).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let v = send(&h, "/openai/v1/responses", AUTH, "{}", false)
        .await
        .json();
    assert_eq!(v["output"][0]["encrypted_content"], format!("enc{p0}"));
    assert_eq!(v["output"][1]["content"][0]["text"], format!("is {v0}"));
    let args: serde_json::Value =
        serde_json::from_str(v["output"][2]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(args["command"][1], v0.as_str());

    let body = format!(
        r#"{{"id":"c1","object":"chat.completion","choices":[{{"index":0,"message":{{"role":"assistant","content":"pw {p0}","tool_calls":[{{"id":"t","type":"function","function":{{"name":"shell","arguments":"{{\"cmd\":\"{p0}\"}}"}}}}]}},"finish_reason":"tool_calls"}}]}}"#
    );
    let up = FakeUpstream::start(Scripted::json(200, body)).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let v = send(&h, "/openai/v1/chat/completions", AUTH, "{}", false)
        .await
        .json();
    assert_eq!(v["choices"][0]["message"]["content"], format!("pw {v0}"));
    let args: serde_json::Value = serde_json::from_str(
        v["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(args["cmd"], v0.as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn other_paths_redact_whole_body() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(Some(&fx), up, |_| {}).await;
    let body = format!("input={}&model=text-embedding-3-small", fx.value("s0"));
    let r = send(&h, "/openai/v1/embeddings", AUTH, body, false).await;
    assert_eq!(r.status, 200);
    let req = &h.upstream.received()[0];
    assert!(fx.leaks(&req.body).is_empty());
    assert!(
        std::str::from_utf8(&req.body)
            .unwrap()
            .contains(&fx.placeholder("s0"))
    );
}
