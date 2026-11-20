// SPDX-License-Identifier: AGPL-3.0-only

//! Values with quotes and backslashes in JSON nested in JSON strings, through the proxy with the
//! production engine (scrim-redact): OpenAI Chat tool-call `arguments` on the way out, restore
//! into `arguments` on the way back.

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

use common::*;
use scrim_llm::core::CoreEngine;
use scrim_llm::testing::{FakePolicy, FakeUpstream, Scripted, random_value};
use scrim_llm::{AuditEvent, BinaryPolicy, SecretRef};
use scrim_redact as rc;
use serde_json::{Value, json};

const AUTH: &[(&str, &str)] = &[
    ("authorization", "Bearer agent-own-session-token"),
    ("content-type", "application/json"),
];

struct Values {
    /// Display value with quotes, backslashes and characters Go and Python escape.
    display: String,
    credential: String,
}

fn values() -> Values {
    Values {
        display: format!("{}\"q\\<b>&\u{e9}'", random_value("pw_")),
        credential: format!("{}\"\\cred", random_value("sk_live_")),
    }
}

fn engine(v: &Values) -> (CoreEngine, Arc<rc::Snapshot>) {
    let keyring = Arc::new(rc::Keyring::new(
        rc::PlaceholderKey::new(1, &[9u8; 32]).unwrap(),
    ));
    let entries = vec![
        rc::Entry::new(
            0,
            rc::RefSlug::new("db").unwrap(),
            rc::ValueClass::Display,
            rc::SecretValue::from_slice(v.display.as_bytes()),
        ),
        rc::Entry::new(
            1,
            rc::RefSlug::new("pay").unwrap(),
            rc::ValueClass::Credential,
            rc::SecretValue::from_slice(v.credential.as_bytes()),
        ),
    ];
    let snap = Arc::new(rc::Snapshot::build(entries, keyring, &rc::Config::default()).unwrap());
    let engine = CoreEngine::new(
        Arc::clone(&snap),
        [
            (rc::EntryId(0), SecretRef::new("bao://kv/db#password")),
            (rc::EntryId(1), SecretRef::new("bao://kv/pay#key")),
        ],
    );
    (engine, snap)
}

fn placeholder(snap: &rc::Snapshot, value: &str) -> String {
    let mut out = Vec::new();
    snap.redactor().redact(value.as_bytes(), &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

async fn harness(engine: &CoreEngine, up: FakeUpstream) -> Harness {
    let h = start(None, up, |_| {}).await;
    h.cell
        .store(engine.snapshot(1, Arc::new(FakePolicy::resolve_all()), BinaryPolicy::Pass));
    h
}

/// Every string in `v`, and the strings of every string that is itself JSON, at any depth.
fn strings_deep(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            out.push(s.clone());
            if let Ok(inner) = serde_json::from_str::<Value>(s)
                && (inner.is_object() || inner.is_array())
            {
                strings_deep(&inner, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| strings_deep(x, out)),
        Value::Object(m) => m.values().for_each(|x| strings_deep(x, out)),
        _ => {}
    }
}

fn deep_strings(body: &[u8]) -> Vec<String> {
    let mut all = Vec::new();
    strings_deep(
        &serde_json::from_slice(body).expect("body is JSON"),
        &mut all,
    );
    all
}

/// A Codex-style request after a tool call: the call's `arguments` hold the values (two levels),
/// and the tool result is JSON whose `output` is the tool's own JSON (three levels).
fn chat_request(v: &Values) -> String {
    let cmd = format!(
        "printf '%s' '{}' > .env && curl -H 'x-key: {}' localhost",
        v.display, v.credential
    );
    let arguments = serde_json::to_string(&json!({ "command": cmd })).unwrap();
    let tool_json = serde_json::to_string(&json!({ "stdout": v.display, "exit_code": 0 })).unwrap();
    let result = serde_json::to_string(&json!({ "output": tool_json })).unwrap();
    serde_json::to_string(&json!({
        "model": "gpt-test",
        "messages": [
            { "role": "user", "content": "Write the password to .env." },
            { "role": "assistant", "content": null, "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": { "name": "shell", "arguments": arguments },
            }]},
            { "role": "tool", "tool_call_id": "call_1", "content": result },
        ],
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn chat_tool_call_arguments_redacted_at_every_level() {
    let v = values();
    let (engine, snap) = engine(&v);
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = harness(&engine, up).await;
    let body = chat_request(&v);
    assert!(
        deep_strings(body.as_bytes())
            .iter()
            .any(|s| s.contains(&v.display))
    );
    let r = send(&h, "/openai/v1/chat/completions", AUTH, body, false).await;
    assert_eq!(r.status, 200);
    let sent = &h.upstream.received()[0].body;
    let strings = deep_strings(sent);
    for s in &strings {
        assert!(!s.contains(&v.display) && !s.contains(&v.credential));
    }
    let (pd, pc) = (
        placeholder(&snap, &v.display),
        placeholder(&snap, &v.credential),
    );
    assert!(strings.iter().any(|s| s.contains(&pd)));
    assert!(strings.iter().any(|s| s.contains(&pc)));
    // The redactor got all three; the guard had nothing to repair.
    let fwd = h
        .audit
        .events()
        .into_iter()
        .find_map(|e| match e {
            AuditEvent::Forwarded {
                replacements,
                guard_repaired,
                ..
            } => Some((replacements, guard_repaired)),
            _ => None,
        })
        .unwrap();
    assert_eq!(fwd, (3, vec![]));
}

/// The value restored into `arguments` is escaped for both levels: the arguments JSON and the
/// response JSON around it.
#[tokio::test(flavor = "multi_thread")]
async fn display_value_restored_into_arguments_escaped_for_both_levels() {
    let v = values();
    let (engine, snap) = engine(&v);
    let (pd, pc) = (
        placeholder(&snap, &v.display),
        placeholder(&snap, &v.credential),
    );
    let arguments =
        serde_json::to_string(&json!({ "cmd": format!("echo {pd}; use {pc}") })).unwrap();
    let body = serde_json::to_string(&json!({
        "id": "c1", "object": "chat.completion",
        "choices": [{ "index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": null,
            "tool_calls": [{ "id": "t", "type": "function",
                "function": { "name": "shell", "arguments": arguments } }],
        }}],
    }))
    .unwrap();
    let up = FakeUpstream::start(Scripted::json(200, body)).await;
    let h = harness(&engine, up).await;
    let out = send(&h, "/openai/v1/chat/completions", AUTH, "{}", false)
        .await
        .json();
    let args: Value = serde_json::from_str(
        out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    // Credentials are never restored, whatever the policy says.
    assert_eq!(
        args["cmd"].as_str().unwrap(),
        format!("echo {}; use {pc}", v.display)
    );
}

/// The same through a stream cut at every size, and a placeholder inside JSON nested in
/// `arguments` (one escape too few there) is kept rather than restored.
#[tokio::test(flavor = "multi_thread")]
async fn streamed_arguments_restored_and_nested_strings_kept() {
    let v = values();
    let (engine, snap) = engine(&v);
    let pd = placeholder(&snap, &v.display);
    let nested = serde_json::to_string(&json!({ "pw": pd })).unwrap();
    let arguments =
        serde_json::to_string(&json!({ "cmd": format!("echo {pd}"), "input": nested })).unwrap();
    let chunk = |delta: Value| {
        let ev = json!({ "id": "c", "object": "chat.completion.chunk", "choices": [{
            "index": 0, "delta": delta, "finish_reason": null }] });
        format!("data: {ev}\n\n")
    };
    let mut sse = chunk(
        json!({ "role": "assistant", "tool_calls": [{ "index": 0, "id": "t",
        "type": "function", "function": { "name": "shell", "arguments": "" } }] }),
    );
    let mut at = 0;
    while at < arguments.len() {
        let mut end = (at + 7).min(arguments.len());
        while !arguments.is_char_boundary(end) {
            end += 1;
        }
        sse.push_str(&chunk(json!({ "tool_calls": [{ "index": 0,
            "function": { "arguments": &arguments[at..end] } }] })));
        at = end;
    }
    sse.push_str("data: [DONE]\n\n");
    for sizes in [vec![1], vec![5, 3], vec![1 << 20]] {
        let up = FakeUpstream::start(Scripted::sse(chunked(&sse, &sizes))).await;
        let h = harness(&engine, up).await;
        let r = send(&h, "/openai/v1/chat/completions", AUTH, "{}", false).await;
        let mut args = String::new();
        for (_, ev) in events(&r.text()) {
            if let Some(a) =
                ev["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"].as_str()
            {
                args.push_str(a);
            }
        }
        let a: Value = serde_json::from_str(&args).unwrap();
        assert_eq!(a["cmd"].as_str().unwrap(), format!("echo {}", v.display));
        let inner: Value = serde_json::from_str(a["input"].as_str().unwrap()).unwrap();
        assert_eq!(inner["pw"].as_str().unwrap(), pd);
    }
}
