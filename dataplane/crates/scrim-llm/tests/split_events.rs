// SPDX-License-Identifier: AGPL-3.0-only

//! Placeholders split across delta events, for every cut point and every API, and the
//! `restore(redact(x)) == x` property over generated streams.

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

use common::events;
use proptest::prelude::*;
use scrim_llm::config::Limits;
use scrim_llm::testing::{FakePolicy, Fixture};
use scrim_llm::{Api, SseRestorer};

fn q(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

fn anthropic(deltas: &[&str]) -> String {
    let mut s = String::from(
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
    );
    for d in deltas {
        s.push_str(&format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":{}}}}}\n\n",
            q(d)
        ));
    }
    s.push_str(
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
    );
    s.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
    s
}

fn anthropic_text(out: &str) -> String {
    let mut t = String::new();
    let mut stopped = false;
    for (name, v) in events(out) {
        match name.as_deref() {
            Some("content_block_delta") => {
                assert!(!stopped, "delta after stop");
                t.push_str(v["delta"]["text"].as_str().unwrap());
            }
            Some("content_block_stop") => stopped = true,
            _ => {}
        }
    }
    t
}

fn chat(deltas: &[&str], finish_with_content: bool) -> String {
    let env = r#""id":"c","object":"chat.completion.chunk","created":1,"model":"m""#;
    let mut s = String::new();
    let n = deltas.len();
    for (i, d) in deltas.iter().enumerate() {
        let fin = if finish_with_content && i == n - 1 {
            "\"stop\""
        } else {
            "null"
        };
        s.push_str(&format!(
            "data: {{{env},\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{}}},\"finish_reason\":{fin}}}]}}\n\n",
            q(d)
        ));
    }
    if !finish_with_content {
        s.push_str(&format!("data: {{{env},\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n"));
    }
    s.push_str("data: [DONE]\n\n");
    s
}

fn chat_text(out: &str) -> String {
    let mut t = String::new();
    let mut finished = false;
    for (_, v) in events(out) {
        if v.is_null() {
            continue;
        }
        for c in v["choices"].as_array().unwrap() {
            if let Some(s) = c["delta"]["content"].as_str() {
                assert!(
                    !finished || s.is_empty(),
                    "content after finish_reason: {out}"
                );
                t.push_str(s);
            }
            if c["finish_reason"].is_string() {
                finished = true;
            }
        }
    }
    t
}

fn responses(deltas: &[&str], full: &str) -> String {
    let mut s = String::new();
    for (i, d) in deltas.iter().enumerate() {
        s.push_str(&format!(
            "event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"sequence_number\":{i},\"item_id\":\"m\",\"output_index\":0,\"content_index\":0,\"delta\":{}}}\n\n",
            q(d)
        ));
    }
    s.push_str(&format!(
        "event: response.output_text.done\ndata: {{\"type\":\"response.output_text.done\",\"item_id\":\"m\",\"output_index\":0,\"content_index\":0,\"text\":{}}}\n\n",
        q(full)
    ));
    s
}

fn responses_text(out: &str) -> (String, String) {
    let mut t = String::new();
    let mut done = String::new();
    for (_, v) in events(out) {
        match v["type"].as_str().unwrap() {
            "response.output_text.delta" => {
                assert!(done.is_empty(), "delta after done");
                t.push_str(v["delta"].as_str().unwrap());
            }
            "response.output_text.done" => done = v["text"].as_str().unwrap().to_string(),
            _ => {}
        }
    }
    (t, done)
}

/// Gemini chunks, one text delta each, the last with `finishReason` (and the delta when
/// `finish_with_text`); as SSE or as a JSON array.
fn gemini(deltas: &[&str], finish_with_text: bool, sse: bool) -> String {
    let chunk = |t: Option<&str>, fin: bool| {
        let parts = t.map_or(String::new(), |t| format!("{{\"text\":{}}}", q(t)));
        let fin = if fin {
            ",\"finishReason\":\"STOP\""
        } else {
            ""
        };
        format!(
            "{{\"candidates\":[{{\"content\":{{\"parts\":[{parts}],\"role\":\"model\"}}{fin},\"index\":0}}],\"modelVersion\":\"gemini-2.5-flash\",\"responseId\":\"r\"}}"
        )
    };
    let n = deltas.len();
    let mut chunks: Vec<String> = deltas
        .iter()
        .enumerate()
        .map(|(i, d)| chunk(Some(d), finish_with_text && i == n - 1))
        .collect();
    if !finish_with_text {
        chunks.push(chunk(None, true));
    }
    if sse {
        chunks
            .iter()
            .map(|c| format!("data: {c}\r\n\r\n"))
            .collect()
    } else {
        format!("[{}]", chunks.join("\r\n,"))
    }
}

fn gemini_text(out: &str, sse: bool) -> String {
    let chunks: Vec<serde_json::Value> = if sse {
        events(&out.replace("\r\n", "\n"))
            .into_iter()
            .map(|(_, v)| v)
            .collect()
    } else {
        serde_json::from_str(out).unwrap()
    };
    let mut t = String::new();
    let mut finished = false;
    for c in chunks {
        let cand = &c["candidates"][0];
        for p in cand["content"]["parts"].as_array().unwrap() {
            let s = p["text"].as_str().unwrap();
            assert!(!finished || s.is_empty(), "text after finishReason: {out}");
            t.push_str(s);
        }
        if cand["finishReason"].is_string() {
            finished = true;
        }
    }
    t
}

fn run_array(fx: &Fixture, stream: &str) -> String {
    let mut r =
        SseRestorer::json_array(Api::Gemini, Arc::new(fx.snapshot()), &Limits::default()).unwrap();
    let mut out = Vec::new();
    r.push(stream.as_bytes(), &mut out);
    r.finish(&mut out);
    String::from_utf8(out).unwrap()
}

fn run(api: Api, fx: &Fixture, stream: &str) -> String {
    let mut r = SseRestorer::new(api, Arc::new(fx.snapshot()), &Limits::default()).unwrap();
    let mut out = Vec::new();
    r.push(stream.as_bytes(), &mut out);
    r.finish(&mut out);
    String::from_utf8(out).unwrap()
}

#[test]
fn every_cut_point_every_api() {
    let fx = Fixture::new(&[("db", "pw-0123456789abcdef")]);
    let ph = fx.placeholder("db");
    // The second case ends in a dangling placeholder prefix, which is held until the block ends
    // and must then be released before the end-of-block event.
    let dangling = &ph[..12];
    for (full, want) in [
        (format!("a {ph} b"), "a pw-0123456789abcdef b".to_string()),
        (
            format!("a {ph} b {dangling}"),
            format!("a pw-0123456789abcdef b {dangling}"),
        ),
    ] {
        let cuts: Vec<usize> = (0..=full.len())
            .filter(|c| full.is_char_boundary(*c))
            .collect();
        for &i in &cuts {
            for &j in cuts.iter().filter(|j| **j >= i) {
                let parts = [&full[..i], &full[i..j], &full[j..]];
                let a = anthropic_text(&run(Api::AnthropicMessages, &fx, &anthropic(&parts)));
                assert_eq!(a, want, "cut {i} {j}");
                for fin in [false, true] {
                    let c = chat_text(&run(Api::OpenAiChat, &fx, &chat(&parts, fin)));
                    assert_eq!(c, want, "cut {i} {j} {fin}");
                    let g = gemini_text(&run(Api::Gemini, &fx, &gemini(&parts, fin, true)), true);
                    assert_eq!(g, want, "gemini sse cut {i} {j} {fin}");
                    let g = gemini_text(&run_array(&fx, &gemini(&parts, fin, false)), false);
                    assert_eq!(g, want, "gemini array cut {i} {j} {fin}");
                }
                let (t, done) =
                    responses_text(&run(Api::OpenAiResponses, &fx, &responses(&parts, &full)));
                assert_eq!(
                    (t.as_str(), done.as_str()),
                    (want.as_str(), want.as_str()),
                    "cut {i} {j}"
                );
            }
        }
    }
}

#[test]
fn holdback_is_bounded_and_plain_text_is_not_delayed() {
    let fx = Fixture::new(&[("db", "pw-0123456789abcdef")]);
    let ph = fx.placeholder("db");
    let snap = Arc::new(fx.snapshot());
    let mut r = SseRestorer::new(Api::AnthropicMessages, snap, &Limits::default()).unwrap();
    let mut out = Vec::new();
    let head = anthropic(&[]);
    let start = &head.as_bytes()[..head.find("event: content_block_stop").unwrap()];
    r.push(start, &mut out);
    out.clear();
    // Plain text goes out with its own event.
    let ev = |t: &str| {
        format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":{}}}}}\n\n",
            q(t)
        )
    };
    r.push(ev("hello world").as_bytes(), &mut out);
    assert_eq!(String::from_utf8(out.clone()).unwrap(), ev("hello world"));
    out.clear();
    // A partial placeholder is held, at most max_len - 1 bytes, the rest goes out.
    let partial = &ph[..ph.len() - 3];
    r.push(ev(&format!("x{partial}")).as_bytes(), &mut out);
    let got = String::from_utf8(out.clone()).unwrap();
    assert_eq!(got, ev("x"));
    assert!(partial.len() < fx.placeholders_max_len());
}

#[test]
fn keep_policy_changes_nothing_but_event_boundaries() {
    let mut fx = Fixture::new(&[("db", "pw-0123456789abcdef")]);
    fx.policy = FakePolicy::keep_all();
    let ph = fx.placeholder("db");
    let full = format!("a {ph} b");
    let (a, b) = full.split_at(5);
    assert_eq!(
        anthropic_text(&run(Api::AnthropicMessages, &fx, &anthropic(&[a, b]))),
        full
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Redact a text containing secrets, stream the redacted text as deltas cut anywhere, restore:
    /// the agent sees the original text.
    #[test]
    fn restore_of_redact_is_identity(
        words in prop::collection::vec(prop_oneof![
            "[a-zA-Z0-9 .,é✓\n\"\\\\]{0,12}".prop_map(|s| (s, None)),
            (0usize..3).prop_map(|i| (String::new(), Some(i))),
        ], 1..12),
        cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..6),
    ) {
        let fx = Fixture::new(&[("a", "alpha-0000-secret"), ("b", "bravo/1111+secret"), ("c", "charlie\u{e9}2222secret")]);
        let names = ["a", "b", "c"];
        let original: String = words.iter().map(|(s, i)| match i { Some(i) => fx.value(names[*i]), None => s.clone() }).collect();
        let snap = fx.snapshot();
        let mut redacted = Vec::new();
        snap.redactor.redact(original.as_bytes(), &mut redacted).unwrap();
        let redacted = String::from_utf8(redacted).unwrap();
        prop_assert!(fx.leaks(redacted.as_bytes()).is_empty());
        let mut points: Vec<usize> = cuts.iter().map(|c| c.index(redacted.len() + 1)).filter(|p| redacted.is_char_boundary(*p)).collect();
        points.sort_unstable();
        points.dedup();
        let mut parts = Vec::new();
        let mut last = 0;
        for p in points {
            parts.push(&redacted[last..p]);
            last = p;
        }
        parts.push(&redacted[last..]);
        let out = run(Api::AnthropicMessages, &fx, &anthropic(&parts));
        prop_assert_eq!(anthropic_text(&out), original);
    }
}
