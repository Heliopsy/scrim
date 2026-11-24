// SPDX-License-Identifier: AGPL-3.0-only

//! WebSocket connections (llm-proxy spec, "WebSocket connections" and the requirements after
//! it): every client message is redacted and guarded before it reaches the fake provider, a
//! message that cannot be made safe closes the connection without being forwarded, and provider
//! events have their placeholders restored.

#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    unreachable_pub,
    dead_code,
    reason = "test code"
)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::*;
use futures_util::{SinkExt, StreamExt};
use scrim_llm::testing::{FakeWsUpstream, Fixture, GuardMode, RecordingAudit, WsReceived};
use scrim_llm::{AuditEvent, Proxy, ProxyConfig, RefusalReason, SnapshotCell};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};
use tokio_tungstenite::tungstenite::protocol::frame::{CloseFrame, Frame};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

struct Ws {
    addr: SocketAddr,
    audit: RecordingAudit,
    cell: Arc<SnapshotCell>,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn start(
    fx: Option<&Fixture>,
    up: &FakeWsUpstream,
    tweak: impl FnOnce(&mut ProxyConfig),
) -> Ws {
    let mut cfg = ProxyConfig {
        routes: routes_to(&up.url()),
        ..ProxyConfig::default()
    };
    tweak(&mut cfg);
    let cell = Arc::new(match fx {
        Some(fx) => SnapshotCell::with(fx.snapshot()),
        None => SnapshotCell::new(),
    });
    let audit = RecordingAudit::default();
    let proxy = Arc::new(Proxy::new(cfg, cell.clone(), Arc::new(audit.clone())).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(scrim_llm::server::serve_tcp(listener, proxy, async {
        let _ = rx.await;
    }));
    Ws {
        addr,
        audit,
        cell,
        _stop: tx,
    }
}

type Client = WebSocketStream<tokio::net::TcpStream>;

async fn connect(ws: &Ws, path: &str, headers: &[(&str, &str)]) -> Result<Client, WsError> {
    let mut req = format!("ws://{}{path}", ws.addr)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("authorization", "Bearer agent-own-key".parse().unwrap());
    for (k, v) in headers {
        req.headers_mut().insert(
            http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    let tcp = tokio::net::TcpStream::connect(ws.addr).await.unwrap();
    tokio_tungstenite::client_async(req, tcp)
        .await
        .map(|(s, _)| s)
}

/// Reads until `until` matches a text message, the connection closes or 10 s pass. Returns the
/// text messages and the close frame, if one came.
async fn read_until(
    c: &mut Client,
    until: &dyn Fn(&str) -> bool,
) -> (Vec<String>, Option<CloseFrame>) {
    let mut texts = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, c.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                let done = until(&t);
                texts.push(t.to_string());
                if done {
                    return (texts, None);
                }
            }
            Ok(Some(Ok(Message::Close(f)))) => return (texts, f),
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_)) | None) | Err(_) => return (texts, None),
        }
    }
}

/// Every text and binary message the provider received.
fn data(up: &FakeWsUpstream) -> Vec<WsReceived> {
    up.received()
        .into_iter()
        .filter(|m| matches!(m, WsReceived::Text(_) | WsReceived::Binary(_)))
        .collect()
}

fn ty(t: &str) -> String {
    serde_json::from_str::<serde_json::Value>(t)
        .ok()
        .and_then(|v| v["type"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Splits `s` into pieces of at most `n` characters.
fn pieces(s: &str, n: usize) -> Vec<String> {
    let cs: Vec<char> = s.chars().collect();
    cs.chunks(n).map(|c| c.iter().collect()).collect()
}

/// A fake Realtime provider that answers `response.create` with an assistant message saying
/// `text` in small deltas, a function call with `args`, and `response.done`.
async fn realtime(text: String, args: String) -> FakeWsUpstream {
    let greeting = vec![
        r#"{"type":"session.created","event_id":"ev0","session":{"id":"sess_1"}}"#.to_string(),
    ];
    FakeWsUpstream::start(greeting, move |m| {
        let v: serde_json::Value = match serde_json::from_str(m) {
            Ok(v) => v,
            Err(_) => return vec![r#"{"type":"error","error":{"message":"not json"}}"#.into()],
        };
        if v["type"] != "response.create" {
            return vec![];
        }
        let mut out = vec![
            r#"{"type":"response.created","response":{"id":"resp_1"}}"#.to_string(),
            r#"{"type":"response.output_item.added","response_id":"resp_1","output_index":0,"item":{"id":"item_1","type":"message","role":"assistant","content":[]}}"#.to_string(),
        ];
        for p in pieces(&text, 5) {
            out.push(serde_json::json!({"type":"response.output_text.delta","response_id":"resp_1","item_id":"item_1","output_index":0,"content_index":0,"delta":p}).to_string());
        }
        out.push(serde_json::json!({"type":"response.output_text.done","item_id":"item_1","output_index":0,"content_index":0,"text":text}).to_string());
        out.push(r#"{"type":"response.output_item.added","response_id":"resp_1","output_index":1,"item":{"id":"fc_1","type":"function_call","name":"Bash","call_id":"call_1","arguments":""}}"#.to_string());
        for p in pieces(&args, 4) {
            out.push(serde_json::json!({"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"call_id":"call_1","delta":p}).to_string());
        }
        out.push(serde_json::json!({"type":"response.function_call_arguments.done","item_id":"fc_1","output_index":1,"call_id":"call_1","name":"Bash","arguments":args}).to_string());
        out.push(serde_json::json!({"type":"response.done","response":{"id":"resp_1","output":[
            {"id":"item_1","type":"message","role":"assistant","content":[{"type":"output_text","text":text}]},
            {"id":"fc_1","type":"function_call","name":"Bash","call_id":"call_1","arguments":args}
        ]}}).to_string());
        out
    })
    .await
}

fn deltas(texts: &[String], t: &str) -> String {
    texts
        .iter()
        .filter_map(|m| serde_json::from_str::<serde_json::Value>(m).ok())
        .filter(|v| v["type"] == t)
        .map(|v| v["delta"].as_str().unwrap().to_string())
        .collect()
}

fn item_create(fx: &Fixture) -> String {
    serde_json::json!({
        "type": "conversation.item.create",
        "event_id": "evt_1",
        "item": {"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": format!("the db password is {}", fx.value("s0"))},
        ]},
    })
    .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn realtime_seeds_never_reach_the_provider_and_replies_are_restored() {
    let fx = fixture();
    let (p0, p1) = (fx.placeholder("s0"), fx.placeholder("s1"));
    let up = realtime(
        format!("Your password is {p0} and the key {p1}."),
        format!(r#"{{"command":"psql -p '{p0}'"}}"#),
    )
    .await;
    let ws = start(Some(&fx), &up, |_| {}).await;
    let mut c = connect(
        &ws,
        "/openai/v1/realtime?model=gpt-realtime",
        &[
            ("x-trace", &format!("t-{}", fx.value("s2"))),
            (
                "sec-websocket-extensions",
                "permessage-deflate; client_max_window_bits",
            ),
        ],
    )
    .await
    .unwrap();
    let (hello, _) = read_until(&mut c, &|t| ty(t) == "session.created").await;
    assert_eq!(hello.len(), 1);
    let messages = [
        serde_json::json!({"type":"session.update","session":{"type":"realtime","instructions":format!("user is {}", fx.value("s2")),"tools":[{"type":"function","name":"Bash","description":"run","parameters":{}}]}}).to_string(),
        item_create(&fx),
        serde_json::json!({"type":"conversation.item.create","item":{"type":"function_call_output","call_id":"call_0","output":format!("API_KEY={}\n", fx.value("s1"))}}).to_string(),
        serde_json::json!({"type":"input_audio_buffer.append","audio":"UklGRiQAAABXQVZFZm10IBAAAAAB"}).to_string(),
        r#"{"type":"response.create","response":{"output_modalities":["text"]}}"#.to_string(),
    ];
    for m in &messages {
        c.send(Message::text(m.clone())).await.unwrap();
    }
    let (texts, close) = read_until(&mut c, &|t| ty(t) == "response.done").await;
    assert!(close.is_none(), "closed: {close:?}");

    // What the provider received: every message, each with placeholders and no value.
    let got = up.texts();
    assert_eq!(got.len(), messages.len());
    for m in &got {
        assert!(fx.leaks(m.as_bytes()).is_empty(), "leak in {m}");
    }
    assert!(got[0].contains(&fx.placeholder("s2")));
    assert!(got[1].contains(&p0));
    assert!(got[2].contains(&p1));
    // The audio is binary content and leaves untouched.
    assert_eq!(got[3], messages[3]);
    // The handshake: the agent's credential unchanged, other headers redacted, no extension.
    let hs = &up.handshakes()[0];
    assert_eq!(hs.uri, "/v1/realtime?model=gpt-realtime");
    assert_eq!(hs.headers["authorization"], "Bearer agent-own-key");
    assert_eq!(
        hs.headers["x-trace"].to_str().unwrap(),
        format!("t-{}", fx.placeholder_ascii("s2"))
    );
    assert!(!hs.headers.contains_key("sec-websocket-extensions"));
    assert!(fx.leaks(format!("{:?}", hs.headers).as_bytes()).is_empty());

    // What the agent received: display values restored in the deltas, done events and the
    // final response; the credential stays a placeholder.
    let v0 = fx.value("s0");
    assert_eq!(
        deltas(&texts, "response.output_text.delta"),
        format!("Your password is {v0} and the key {p1}.")
    );
    assert_eq!(
        deltas(&texts, "response.function_call_arguments.delta"),
        format!(r#"{{"command":"psql -p '{v0}'"}}"#)
    );
    let done: serde_json::Value = serde_json::from_str(texts.last().unwrap()).unwrap();
    assert_eq!(
        done["response"]["output"][0]["content"][0]["text"],
        format!("Your password is {v0} and the key {p1}.")
    );
    assert!(texts.iter().all(|t| !t.contains(&fx.value("s1"))));
    assert!(texts.iter().all(|t| !t.contains(&p0)));

    // Audit: the handshake, the messages that had something replaced and the unscanned audio
    // once, then the restore counters when the connection closes.
    c.close(None).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ws
        .audit
        .events()
        .iter()
        .any(|e| matches!(e, AuditEvent::Restored { .. }))
    {
        assert!(Instant::now() < deadline, "no restore audit");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let events = ws.audit.events();
    let forwarded = events
        .iter()
        .filter(|e| matches!(e, AuditEvent::Forwarded { .. }))
        .count();
    assert_eq!(forwarded, 1 + 3 + 1, "{events:?}");
    assert!(events.iter().any(
        |e| matches!(e, AuditEvent::Forwarded { unscanned, .. } if unscanned == &["audio/unknown"])
    ));
    // The close code reached the provider without a reason.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !up
        .received()
        .iter()
        .any(|m| matches!(m, WsReceived::Close(_)))
    {
        assert!(Instant::now() < deadline, "no close at the provider");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn expect_refusal(c: &mut Client, code: u16, reason: &str) {
    let (texts, close) = read_until(c, &|_| false).await;
    let ev: serde_json::Value =
        serde_json::from_str(texts.last().expect("an error event")).unwrap();
    assert_eq!(ev["type"], "error");
    assert_eq!(ev["error"]["code"], reason);
    let close = close.expect("a close frame");
    assert_eq!(u16::from(close.code), code);
    assert_eq!(close.reason.as_str(), reason);
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_refusal_closes_with_policy_violation_and_forwards_nothing() {
    let mut fx = fixture();
    fx.redactor_misses = vec!["s0".into()];
    fx.guard_mode = GuardMode::Refuse;
    let up = realtime("ok".into(), "{}".into()).await;
    let ws = start(Some(&fx), &up, |_| {}).await;
    let mut c = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    read_until(&mut c, &|t| ty(t) == "session.created").await;
    c.send(Message::text(r#"{"type":"session.update","session":{}}"#))
        .await
        .unwrap();
    c.send(Message::text(item_create(&fx))).await.unwrap();
    c.send(Message::text(r#"{"type":"response.create"}"#))
        .await
        .unwrap();
    expect_refusal(&mut c, 1008, "guard_refused").await;
    // Only the clean message before the refused one left.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        data(&up),
        [WsReceived::Text(
            r#"{"type":"session.update","session":{}}"#.into()
        )]
    );
    assert!(ws.audit.events().iter().any(|e| matches!(
        e,
        AuditEvent::Refused {
            reason: RefusalReason::GuardRefused,
            ..
        }
    )));
}

#[tokio::test(flavor = "multi_thread")]
async fn redactor_failure_and_malformed_events_close_the_connection() {
    let fx = fixture();
    let up = realtime("ok".into(), "{}".into()).await;
    let ws = start(Some(&fx), &up, |_| {}).await;
    // A redactor that fails on the handshake refuses it over HTTP, before anything leaves.
    let mut broken = fx.clone();
    broken.redactor_fault = scrim_llm::testing::Fault::Error;
    ws.cell.store(broken.snapshot());
    match connect(&ws, "/openai/v1/realtime", &[]).await {
        Err(WsError::Http(r)) => assert_eq!(r.status(), 422),
        other => panic!("{:?}", other.map(|_| ())),
    }
    assert!(up.handshakes().is_empty());
    // One that starts failing during a session closes it at the next message.
    ws.cell.store(fx.snapshot());
    let mut c = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    ws.cell.store(broken.snapshot());
    c.send(Message::text(item_create(&fx))).await.unwrap();
    expect_refusal(&mut c, 1008, "redactor_failed").await;

    ws.cell.store(fx.snapshot());
    let mut c = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    c.send(Message::text(format!("not json {}", fx.value("s0"))))
        .await
        .unwrap();
    expect_refusal(&mut c, 1008, "malformed_body").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(data(&up).is_empty(), "{:?}", up.received());
}

#[tokio::test(flavor = "multi_thread")]
async fn fragmented_message_is_reassembled_before_redaction() {
    let fx = fixture();
    let up = realtime("ok".into(), "{}".into()).await;
    let ws = start(Some(&fx), &up, |_| {}).await;
    let mut c = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    let msg = item_create(&fx);
    let v = fx.value("s0");
    // Cut inside the value, and once more inside its first half.
    let at = msg.find(&v).unwrap() + v.len() / 2;
    let parts = [&msg[..at - 3], &msg[at - 3..at], &msg[at..]];
    c.send(Message::Frame(Frame::message(
        Bytes::from(parts[0].to_string()),
        OpCode::Data(Data::Text),
        false,
    )))
    .await
    .unwrap();
    c.send(Message::Frame(Frame::message(
        Bytes::from(parts[1].to_string()),
        OpCode::Data(Data::Continue),
        false,
    )))
    .await
    .unwrap();
    c.send(Message::Frame(Frame::message(
        Bytes::from(parts[2].to_string()),
        OpCode::Data(Data::Continue),
        true,
    )))
    .await
    .unwrap();
    c.send(Message::text(r#"{"type":"response.create"}"#))
        .await
        .unwrap();
    read_until(&mut c, &|t| ty(t) == "response.done").await;
    let got = up.texts();
    assert_eq!(got.len(), 2);
    assert!(fx.leaks(got[0].as_bytes()).is_empty(), "{}", got[0]);
    assert!(got[0].contains(&fx.placeholder("s0")));
    // Each fragment alone holds only part of the value: nothing was sent before the whole
    // message was there.
    assert_eq!(got[0], msg.replace(&v, &fx.placeholder("s0")));
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_messages_close_with_1009_whole_or_fragmented() {
    let fx = fixture();
    let up = realtime("ok".into(), "{}".into()).await;
    let ws = start(Some(&fx), &up, |c| c.limits.max_request_body = 2048).await;
    let big = serde_json::json!({"type":"conversation.item.create","item":{"type":"message","role":"user","content":[{"type":"input_text","text":format!("{} {}", fx.value("s0"), "x".repeat(4096))}]}}).to_string();

    let mut c = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    c.send(Message::text(big.clone())).await.unwrap();
    expect_refusal(&mut c, 1009, "body_too_large").await;

    let mut c = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    let chunks: Vec<&str> = {
        let b = big.as_bytes();
        b.chunks(1000)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect()
    };
    for (i, ch) in chunks.iter().enumerate() {
        let op = if i == 0 { Data::Text } else { Data::Continue };
        let _ = c
            .send(Message::Frame(Frame::message(
                Bytes::from(ch.to_string()),
                OpCode::Data(op),
                i + 1 == chunks.len(),
            )))
            .await;
    }
    expect_refusal(&mut c, 1009, "body_too_large").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(data(&up).is_empty(), "{:?}", up.received());
    let messages_under_limit = serde_json::json!({"type":"session.update"}).to_string();
    let mut c = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    c.send(Message::text(messages_under_limit.clone()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(up.texts(), [messages_under_limit]);
}

#[tokio::test(flavor = "multi_thread")]
async fn binary_messages_are_redacted_when_text_and_refused_otherwise() {
    let fx = fixture();
    let up = realtime("ok".into(), "{}".into()).await;
    let ws = start(Some(&fx), &up, |_| {}).await;
    let mut c = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    c.send(Message::binary(
        format!("raw {}", fx.value("s0")).into_bytes(),
    ))
    .await
    .unwrap();
    c.send(Message::Ping(Bytes::from(fx.value("s2"))))
        .await
        .unwrap();
    c.send(Message::binary(vec![0xff, 0xfe, 0x00, 0x01]))
        .await
        .unwrap();
    expect_refusal(&mut c, 1008, "unscannable_content").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let got = up.received();
    assert_eq!(
        data(&up),
        [WsReceived::Binary(Bytes::from(format!(
            "raw {}",
            fx.placeholder("s0")
        )))]
    );
    // The ping was answered by scrim, never forwarded, and nothing after the refused frame.
    assert!(
        got.iter()
            .all(|m| !matches!(m, WsReceived::Ping(_) | WsReceived::Text(_))),
        "{got:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_refusals_answer_over_http_and_send_nothing() {
    let fx = fixture();
    // Values not loaded.
    let up = realtime("ok".into(), "{}".into()).await;
    let ws = start(None, &up, |_| {}).await;
    match connect(&ws, "/openai/v1/realtime", &[]).await {
        Err(WsError::Http(r)) => {
            assert_eq!(r.status(), 503);
            assert_eq!(r.headers()[scrim_llm::ERROR_HEADER], "not_ready");
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
    assert!(up.handshakes().is_empty());

    // The provider refuses: its answer is the agent's answer.
    let refusing = FakeWsUpstream::refusing(401).await;
    let ws = start(Some(&fx), &refusing, |_| {}).await;
    match connect(&ws, "/openai/v1/realtime", &[]).await {
        Err(WsError::Http(r)) => {
            assert_eq!(r.status(), 401);
            let body = String::from_utf8(r.body().clone().unwrap_or_default()).unwrap();
            assert!(body.contains("refused by the fake provider"), "{body}");
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
    assert_eq!(refusing.handshakes().len(), 1);

    // The provider is not there.
    let (_sock, dead) = refusing_addr();
    let mut cfg_up = None;
    let ws = {
        let fx = fx.clone();
        let mut cfg = ProxyConfig {
            routes: routes_to(&format!("http://{dead}")),
            ..ProxyConfig::default()
        };
        cfg.connect_timeout_ms = 2000;
        cfg_up.replace(cfg.clone());
        let cell = Arc::new(SnapshotCell::with(fx.snapshot()));
        let proxy = Arc::new(Proxy::new(cfg, cell.clone(), Arc::new(scrim_llm::NoAudit)).unwrap());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(scrim_llm::server::serve_tcp(l, proxy, async {
            let _ = rx.await;
        }));
        Ws {
            addr,
            audit: RecordingAudit::default(),
            cell,
            _stop: tx,
        }
    };
    match connect(&ws, "/openai/v1/realtime", &[]).await {
        Err(WsError::Http(r)) => {
            assert_eq!(r.status(), 502);
            assert_eq!(r.headers()[scrim_llm::ERROR_HEADER], "upstream_unavailable");
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_added_during_a_session_is_redacted_from_the_next_message() {
    let fx = fixture();
    let up = realtime("ok".into(), "{}".into()).await;
    let ws = start(Some(&fx), &up, |_| {}).await;
    let mut c = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    let mut fx2 = fx.clone();
    fx2.add(
        "s3",
        &scrim_llm::testing::random_value("new_"),
        scrim_llm::ValueClass::Display,
    );
    fx2.version = 2;
    let msg = serde_json::json!({"type":"conversation.item.create","item":{"type":"message","role":"user","content":[{"type":"input_text","text":fx2.value("s3")}]}}).to_string();
    c.send(Message::text(msg.clone())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    ws.cell.store(fx2.snapshot());
    c.send(Message::text(msg.clone())).await.unwrap();
    c.send(Message::text(r#"{"type":"response.create"}"#))
        .await
        .unwrap();
    read_until(&mut c, &|t| ty(t) == "response.done").await;
    let got = up.texts();
    // Before the update the value was unknown; after it, the same message is redacted.
    assert_eq!(got[0], msg);
    assert!(fx2.leaks(got[1].as_bytes()).is_empty(), "{}", got[1]);
    assert!(got[1].contains(&fx2.placeholder("s3")));
}

#[tokio::test(flavor = "multi_thread")]
async fn responses_websocket_mode_is_redacted_and_restored() {
    let fx = fixture();
    let p0 = fx.placeholder("s0");
    let text = format!("found {p0} in .env");
    let greeting = vec![];
    let t2 = text.clone();
    let up = FakeWsUpstream::start(greeting, move |m| {
        let v: serde_json::Value = serde_json::from_str(m).unwrap();
        assert_eq!(v["type"], "response.create");
        let mut out = vec![
            r#"{"type":"response.created","sequence_number":0,"response":{"id":"resp_1","status":"in_progress","output":[]}}"#.to_string(),
            r#"{"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}"#.to_string(),
        ];
        for (i, p) in pieces(&t2, 3).into_iter().enumerate() {
            out.push(serde_json::json!({"type":"response.output_text.delta","sequence_number":2+i,"item_id":"msg_1","output_index":0,"content_index":0,"delta":p}).to_string());
        }
        out.push(serde_json::json!({"type":"response.output_text.done","item_id":"msg_1","output_index":0,"content_index":0,"text":t2}).to_string());
        out.push(serde_json::json!({"type":"response.completed","response":{"id":"resp_1","status":"completed","output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":t2}]}]}}).to_string());
        out
    })
    .await;
    let ws = start(Some(&fx), &up, |_| {}).await;
    let mut c = connect(
        &ws,
        "/openai/v1/responses",
        &[("openai-beta", "responses_websockets=2026-02-06")],
    )
    .await
    .unwrap();
    let enc = "gAAAAABencrypted-reasoning-blob";
    let create = serde_json::json!({
        "type": "response.create",
        "model": "gpt-5.2-codex",
        "store": false,
        "instructions": format!("never print {}", fx.value("s2")),
        "input": [
            {"type": "reasoning", "summary": [], "encrypted_content": enc},
            {"type": "function_call_output", "call_id": "call_1", "output": format!("DB_PASSWORD={}", fx.value("s0"))},
        ],
    })
    .to_string();
    for _ in 0..2 {
        c.send(Message::text(create.clone())).await.unwrap();
        let (texts, close) = read_until(&mut c, &|t| ty(t) == "response.completed").await;
        assert!(close.is_none());
        let v0 = fx.value("s0");
        assert_eq!(
            deltas(&texts, "response.output_text.delta"),
            format!("found {v0} in .env")
        );
        let done: serde_json::Value = serde_json::from_str(texts.last().unwrap()).unwrap();
        assert_eq!(
            done["response"]["output"][0]["content"][0]["text"],
            format!("found {v0} in .env")
        );
    }
    let got = up.texts();
    assert_eq!(got.len(), 2);
    assert!(fx.leaks(got[0].as_bytes()).is_empty());
    assert!(got[0].contains(enc));
    assert!(got[0].contains(&p0));
    // Deterministic: the second turn is byte-identical, so prompt caching works.
    assert_eq!(got[0], got[1]);
    assert_eq!(
        up.handshakes()[0].headers["openai-beta"],
        "responses_websockets=2026-02-06"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn route_authentication_replaces_the_agents_on_the_handshake() {
    use scrim_llm::auth::AuthConfig;
    let fx = fixture();
    let key = scrim_llm::testing::random_value("route_key_");
    let up = realtime("ok".into(), "{}".into()).await;
    let mut routes = routes_to(&up.url());
    routes[1].auth = Some(AuthConfig::Header {
        name: "api-key".into(),
        prefix: String::new(),
        value: "openai/key".into(),
    });
    let mut cfg = ProxyConfig {
        routes,
        ..ProxyConfig::default()
    };
    cfg.connect_timeout_ms = 2000;
    // Routes with credentials come with the snapshot.
    let mut snap = fx.snapshot();
    let k = key.clone();
    snap.routes = Some(Arc::new(
        scrim_llm::route::RouteTable::with_credentials(&cfg.routes, &|r| {
            (r == "openai/key").then(|| scrim_llm::SecretValue::new(k.as_bytes().to_vec()))
        })
        .unwrap(),
    ));
    let cell = Arc::new(SnapshotCell::with(snap));
    let proxy = Arc::new(Proxy::new(cfg, cell.clone(), Arc::new(scrim_llm::NoAudit)).unwrap());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(scrim_llm::server::serve_tcp(l, proxy, async {
        let _ = rx.await;
    }));
    let ws = Ws {
        addr,
        audit: RecordingAudit::default(),
        cell,
        _stop: tx,
    };
    let _c = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    let hs = &up.handshakes()[0];
    assert_eq!(hs.headers["api-key"].to_str().unwrap(), key);
    assert!(!hs.headers.contains_key("authorization"));
}

#[tokio::test(flavor = "multi_thread")]
async fn added_latency_per_message_is_small() {
    // Round trip of one event through the proxy against the same round trip direct to the
    // fake provider. The budget is enforced by the latency gate on a quiet machine; this
    // only catches a relay that waits on something it should not (a timer, a flush).
    let fx = Fixture::generated(100);
    let up = FakeWsUpstream::start(vec![], |m| {
        vec![m.replace("conversation.item.create", "conversation.item.done")]
    })
    .await;
    let ws = start(Some(&fx), &up, |_| {}).await;
    let msg = serde_json::json!({"type":"conversation.item.create","item":{"type":"message","role":"user","content":[{"type":"input_text","text":"x".repeat(4000)}]}}).to_string();
    async fn rtt(c: &mut Client, msg: &str, n: usize) -> Vec<Duration> {
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let t = Instant::now();
            c.send(Message::text(msg.to_string())).await.unwrap();
            loop {
                if let Some(Ok(Message::Text(_))) = c.next().await {
                    break;
                }
            }
            v.push(t.elapsed());
        }
        v.sort();
        v
    }
    let mut via = connect(&ws, "/openai/v1/realtime", &[]).await.unwrap();
    let direct_req = format!("ws://{}/v1/realtime", up.addr)
        .into_client_request()
        .unwrap();
    let (mut direct, _) = tokio_tungstenite::client_async(
        direct_req,
        tokio::net::TcpStream::connect(up.addr).await.unwrap(),
    )
    .await
    .unwrap();
    rtt(&mut via, &msg, 50).await;
    rtt(&mut direct, &msg, 50).await;
    let a = rtt(&mut via, &msg, 500).await;
    let b = rtt(&mut direct, &msg, 500).await;
    let p = |v: &[Duration], q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)];
    let added50 = p(&a, 0.5).saturating_sub(p(&b, 0.5));
    let added99 = p(&a, 0.99).saturating_sub(p(&b, 0.99));
    eprintln!(
        "websocket message added latency: p50 {added50:?}, p99 {added99:?} (proxy p50 {:?}, direct p50 {:?})",
        p(&a, 0.5),
        p(&b, 0.5)
    );
    assert!(added50 < Duration::from_millis(5), "p50 added {added50:?}");
}
