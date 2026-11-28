// SPDX-License-Identifier: AGPL-3.0-only

//! The plan cache (`plan_cache.rs`) against planning without it: on an agent's next turn, and on
//! bodies that change, break or duplicate what the cache knows, the plan (or the error) is the
//! same with and without the cache.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use proptest::prelude::*;
use serde_json::{Value as J, json};

use super::plan_cache::{MIN_ELEMENT, PlanCache};
use super::{Api, Plan, PlanError, plan, plan_cached, plan_counted};
use crate::remote::Reference;

/// What planning gave, comparable.
/// Verbatim spans, binary media types and attachment references, or the error.
type Outcome = Result<(Vec<(usize, usize)>, Vec<String>, Vec<Reference>), String>;

fn outcome(r: Result<Plan, PlanError>) -> Outcome {
    r.map(|p| (p.verbatim, p.binary, p.remote))
        .map_err(|e| e.to_string())
}

fn agree(cache: &PlanCache, body: &[u8]) -> Outcome {
    let a = outcome(plan_cached(Api::AnthropicMessages, body, Some(cache)));
    let b = outcome(plan(Api::AnthropicMessages, body));
    assert_eq!(a, b, "cached and uncached plans disagree");
    a
}

fn text(seed: u64, n: usize) -> String {
    let words = [
        "alpha",
        "beta",
        "gamma",
        "delta",
        "\"quoted\"",
        "line\nbreak",
        "tab\t",
        "é",
    ];
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut s = String::new();
    while s.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.push_str(words[(x % words.len() as u64) as usize]);
        s.push(' ');
    }
    s
}

/// A message of about `n` bytes; `kind` picks plain text, a thinking block, a tool result or
/// an image.
fn message(i: u64, n: usize, kind: u8) -> J {
    match kind % 4 {
        0 => json!({"role": "user", "content": [{"type": "text", "text": text(i, n)}]}),
        1 => json!({"role": "assistant", "content": [
            {"type": "thinking", "thinking": text(i, n / 2), "signature": "sig".repeat(20)},
            {"type": "text", "text": text(i + 1, n / 2)},
            {"type": "redacted_thinking", "data": "opaque"},
        ]}),
        2 => {
            json!({"role": "user", "content": [{"type": "tool_result", "tool_use_id": format!("toolu_{i}"),
            "content": [{"type": "text", "text": text(i, n)},
                        {"type": "thinking", "thinking": "nested", "signature": "s"}]}]})
        }
        _ => json!({"role": "user", "content": [{"type": "image", "source": {"type": "base64",
            "media_type": "image/png", "data": "iVBORw0KGgo".repeat(n / 11 + 1)}}]}),
    }
}

fn body(messages: &[J], system: bool) -> Vec<u8> {
    let mut doc = json!({"model": "m", "max_tokens": 10, "messages": messages});
    if system {
        doc["system"] = json!([{"type": "text", "text": text(7, 3000)},
                               {"type": "thinking", "thinking": text(8, 2000), "signature": "x"}]);
        doc["tools"] = json!([{"name": "Read", "description": text(9, 2000), "input_schema": {}}]);
    }
    serde_json::to_vec(&doc).unwrap()
}

#[test]
fn next_turn_skips_known_messages_with_the_same_plan() {
    let cache = PlanCache::new(1024);
    let mut msgs: Vec<J> = (0..30)
        .map(|i| message(i, 1500 + 100 * i as usize, i as u8))
        .collect();
    let first = body(&msgs, true);
    agree(&cache, &first).unwrap();
    assert!(!cache.is_empty());
    msgs.push(message(99, 2000, 1));
    let next = body(&msgs, true);
    let (_, skipped) = plan_counted(Api::AnthropicMessages, &next, Some(&cache)).unwrap();
    // All but the runs around images and the last run of each array.
    assert!(
        skipped * 10 > next.len() * 6,
        "{skipped} of {} bytes skipped",
        next.len()
    );
    agree(&cache, &next).unwrap();
    // The same body again plans the same, with more of it known.
    let (_, again) = plan_counted(Api::AnthropicMessages, &next, Some(&cache)).unwrap();
    assert!(again >= skipped);
    agree(&cache, &next).unwrap();
}

#[test]
fn known_bytes_elsewhere_are_not_skipped() {
    let cache = PlanCache::new(1024);
    let m = message(1, 3000, 1);
    agree(&cache, &body(&[m.clone(), message(2, 2000, 0)], false)).unwrap();
    // The same message bytes as an element of an array the plan reads differently, and nested.
    let s = serde_json::to_string(&m).unwrap();
    for b in [
        format!(r#"{{"model":"m","metadata":[{s},{s}],"messages":[]}}"#),
        format!(r#"{{"model":"m","messages":[{{"role":"user","content":[{s}]}}]}}"#),
        format!(r#"{{"model":"m","system":[{s}],"messages":[{s}]}}"#),
        format!(r#"[{s}]"#),
    ] {
        agree(&cache, b.as_bytes()).ok();
    }
}

#[test]
fn errors_stay_the_same() {
    let cache = PlanCache::new(1024);
    let msgs: Vec<J> = (0..6).map(|i| message(i, 2000, i as u8)).collect();
    let good = body(&msgs, true);
    agree(&cache, &good).unwrap();
    let s = String::from_utf8(good.clone()).unwrap();
    for bad in [
        // Truncated after known elements, a second `messages`, a broken tail.
        s[..s.len() - 3].to_string(),
        s.replacen(r#""messages":"#, r#""messages":[],"messages":"#, 1),
        s.replace(r#"]}"#, "],}"),
        format!("{s}x"),
    ] {
        assert!(agree(&cache, bad.as_bytes()).is_err());
    }
}

#[test]
fn small_and_binary_elements_are_not_remembered() {
    let cache = PlanCache::new(1024);
    agree(
        &cache,
        &body(&[message(1, 10, 0), message(2, 4000, 3)], false),
    )
    .unwrap();
    assert_eq!(cache.len(), 0);
    const { assert!(MIN_ELEMENT > 10) };
}

#[test]
fn referenced_attachments_are_planned_on_every_turn() {
    let cache = PlanCache::new(1024);
    let refs = |i: u64| {
        json!({"role": "user", "content": [
            {"type": "text", "text": text(i, 3000)},
            {"type": "image", "source": {"type": "url", "url": format!("https://example.com/{i}.png")}},
            {"type": "container_upload", "file_id": format!("file_{i}")},
        ]})
    };
    let mut msgs = vec![refs(1), message(2, 3000, 0), refs(3)];
    let first = agree(&cache, &body(&msgs, false)).unwrap();
    assert_eq!(first.2.len(), 4);
    msgs.push(message(4, 2000, 0));
    let next = agree(&cache, &body(&msgs, false)).unwrap();
    assert_eq!(next.2.len(), 4);
}

#[test]
fn eviction_keeps_the_cap() {
    let cache = PlanCache::new(16);
    for k in 0..10 {
        let msgs: Vec<J> = (0..8).map(|i| message(k * 100 + i, 1200, 0)).collect();
        agree(&cache, &body(&msgs, false)).unwrap();
        assert!(cache.len() <= 16);
    }
    cache.clear();
    assert!(cache.is_empty());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// A conversation planned turn after turn, with messages edited, dropped or reordered on
    /// the way: every plan agrees with planning without the cache.
    #[test]
    fn turns_agree(
        sizes in prop::collection::vec((500usize..4000, 0u8..4), 2..10),
        edits in prop::collection::vec((0usize..16, 0u8..4), 0..6),
    ) {
        let cache = PlanCache::new(256);
        let mut msgs: Vec<J> = Vec::new();
        for (i, (n, kind)) in sizes.iter().enumerate() {
            msgs.push(message(i as u64, *n, *kind));
            agree(&cache, &body(&msgs, i % 2 == 0)).unwrap();
        }
        for (k, (at, op)) in edits.into_iter().enumerate() {
            let at = at % msgs.len();
            match op {
                0 => { msgs.remove(at); }
                1 => {
                    let last = msgs.len() - 1;
                    msgs.swap(at, last);
                }
                2 => msgs[at] = message(1000 + k as u64, 1500, k as u8),
                _ => {
                    let m = msgs[at].clone();
                    msgs.insert(at, m);
                }
            }
            if msgs.is_empty() {
                msgs.push(message(5, 1500, 0));
            }
            agree(&cache, &body(&msgs, k % 2 == 1)).unwrap();
        }
    }
}
