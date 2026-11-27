// SPDX-License-Identifier: AGPL-3.0-only

//! The per-request gate (`Snapshot::gate`) and policies that restore tool arguments themselves
//! (`RestorePolicy::restore_tool_input`).

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

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use common::*;
use scrim_llm::testing::{FakePolicy, FakeUpstream, Scripted};
use scrim_llm::{
    Admission, EngineError, Guard, GuardVerdict, Placeholders, RequestGate, RequestInfo,
    RestoreDecision, RestorePolicy, RestoreSite, SecretRef, SessionKey, ToolInputRestore,
    ValueClass,
};

const H: &[(&str, &str)] = &[
    ("content-type", "application/json"),
    ("x-api-key", "agent-key-for-tests"),
    ("x-scrim-session", "sess-7"),
];

/// Records what it was shown and answers with a fixed admission.
struct Gate {
    deny: bool,
    policy: Arc<dyn RestorePolicy>,
    seen: Mutex<Vec<(String, String, Option<String>)>>,
}

impl RequestGate for Gate {
    fn admit<'a>(
        &'a self,
        req: RequestInfo<'a>,
    ) -> Pin<Box<dyn Future<Output = Admission> + Send + 'a>> {
        self.seen.lock().unwrap().push((
            req.route.to_owned(),
            req.provider.to_owned(),
            req.headers
                .get(scrim_llm::SESSION_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        ));
        Box::pin(async move {
            if self.deny {
                Admission::Deny {
                    detail: "rule `no-model`".into(),
                }
            } else {
                Admission::Forward {
                    policy: Arc::clone(&self.policy),
                    redaction: None,
                    session: None,
                }
            }
        })
    }
}

fn messages(fx: &scrim_llm::testing::Fixture) -> String {
    format!(
        r#"{{"model":"m","max_tokens":8,"messages":[{{"role":"user","content":"pw {}"}}]}}"#,
        fx.value("s0")
    )
}

/// A complete Messages response with the display placeholder in text and in a tool call, and
/// the credential placeholder in the tool call.
fn response(fx: &scrim_llm::testing::Fixture) -> String {
    let input = serde_json::json!({"command": format!("echo {} {}", fx.placeholder("s0"), fx.placeholder("s1"))});
    serde_json::json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "m",
        "content": [
            {"type": "text", "text": format!("pw is {}", fx.placeholder("s0"))},
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": input}
        ],
        "stop_reason": "tool_use", "usage": {"input_tokens": 1, "output_tokens": 1}
    })
    .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denying_gate_refuses_before_anything_leaves() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(None, up, |_| {}).await;
    let gate = Arc::new(Gate {
        deny: true,
        policy: Arc::new(FakePolicy::keep_all()),
        seen: Mutex::default(),
    });
    let mut snap = fx.snapshot();
    snap.gate = Some(gate.clone());
    h.cell.store(snap);
    let r = send(&h, "/anthropic/v1/messages", H, messages(&fx), false).await;
    assert_eq!(r.status, 403, "{}", r.text());
    assert_eq!(r.headers[scrim_llm::ERROR_HEADER], "policy_denied");
    assert!(r.text().contains("no-model"), "{}", r.text());
    assert!(fx.leaks(&r.body).is_empty());
    assert!(
        h.upstream.received().is_empty(),
        "nothing reached the provider"
    );
    assert_eq!(
        gate.seen.lock().unwrap().as_slice(),
        &[(
            "anthropic".into(),
            "anthropic".into(),
            Some("sess-7".into())
        )]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gate_picks_the_restore_policy_and_the_session_header_stays_local() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, response(&fx))).await;
    let h = start(None, up, |_| {}).await;
    // The snapshot's own policy keeps everything; the gate's restores text.
    let mut snap = fx.snapshot();
    snap.policy = Arc::new(FakePolicy::keep_all());
    snap.gate = Some(Arc::new(Gate {
        deny: false,
        policy: Arc::new(FakePolicy::text_only()),
        seen: Mutex::default(),
    }));
    h.cell.store(snap);
    let r = send(&h, "/anthropic/v1/messages", H, messages(&fx), false).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!(v["content"][0]["text"], format!("pw is {}", fx.value("s0")));
    let got = h.upstream.received();
    assert_eq!(got.len(), 1);
    assert!(got[0].headers.get("x-scrim-session").is_none(), "forwarded");
}

/// Restores tool arguments itself and records which placeholders resolved through `values`.
#[derive(Default)]
struct OwnRestore {
    resolved: Mutex<Vec<(String, bool)>>,
}

impl RestorePolicy for OwnRestore {
    fn decide(&self, _: &RestoreSite<'_>, _: &SecretRef, _: ValueClass) -> RestoreDecision {
        RestoreDecision::Keep
    }

    fn restore_tool_input(
        &self,
        tool: &str,
        arguments: &str,
        values: &dyn Placeholders,
    ) -> Option<ToolInputRestore> {
        let v: serde_json::Value = serde_json::from_str(arguments).unwrap();
        let cmd = v["command"].as_str().unwrap();
        let mut out = cmd.to_owned();
        let mut resolved = 0;
        let mut kept = 0;
        for word in cmd.split(' ').skip(1) {
            let r = values.resolve(word);
            self.resolved
                .lock()
                .unwrap()
                .push((word.to_owned(), r.is_some()));
            match r {
                Some(r) => {
                    let val = std::str::from_utf8(r.value.expose()).unwrap().to_owned();
                    out = out.replace(word, &format!("'{val}'"));
                    resolved += 1;
                }
                None => kept += 1,
            }
        }
        assert_eq!(tool, "Bash");
        Some(ToolInputRestore {
            text: Some(serde_json::json!({ "command": out }).to_string()),
            resolved,
            kept,
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_restores_complete_tool_input_itself_and_never_sees_credentials() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, response(&fx))).await;
    let h = start(None, up, |_| {}).await;
    let policy = Arc::new(OwnRestore::default());
    let mut snap = fx.snapshot();
    snap.policy = policy.clone();
    h.cell.store(snap);
    let r = send(&h, "/anthropic/v1/messages", H, messages(&fx), false).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!(
        v["content"][1]["input"]["command"],
        format!("echo '{}' {}", fx.value("s0"), fx.placeholder("s1"))
    );
    assert_eq!(
        policy.resolved.lock().unwrap().as_slice(),
        &[(fx.placeholder("s0"), true), (fx.placeholder("s1"), false)],
        "a credential never resolves for the policy"
    );
    assert!(!r.text().contains(&fx.value("s1")));
}

/// Forwards every request with the session named in `x-scrim-session`, if any.
struct SessionGate;

impl RequestGate for SessionGate {
    fn admit<'a>(
        &'a self,
        req: RequestInfo<'a>,
    ) -> Pin<Box<dyn Future<Output = Admission> + Send + 'a>> {
        let session = req
            .headers
            .get(scrim_llm::SESSION_HEADER)
            .map(|v| SessionKey::new("session", v.as_bytes()));
        Box::pin(async move {
            Admission::Forward {
                policy: Arc::new(FakePolicy::keep_all()),
                redaction: None,
                session,
            }
        })
    }
}

/// Records the session of every check, then defers to the fixture's guard.
struct Sessions {
    inner: Arc<dyn Guard>,
    seen: Mutex<Vec<Option<SessionKey>>>,
}

impl Guard for Sessions {
    fn check(&self, outgoing: &[u8]) -> Result<GuardVerdict, EngineError> {
        self.seen.lock().unwrap().push(None);
        self.inner.check(outgoing)
    }

    fn check_in(&self, outgoing: &[u8], s: &SessionKey) -> Result<GuardVerdict, EngineError> {
        self.seen.lock().unwrap().push(Some(*s));
        self.inner.check(outgoing)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_guard_checks_each_request_in_its_callers_session() {
    let fx = fixture();
    let up = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let h = start(None, up, |_| {}).await;
    let mut snap = fx.snapshot();
    let guard = Arc::new(Sessions {
        inner: snap.guard.clone(),
        seen: Mutex::default(),
    });
    snap.guard = guard.clone();
    snap.gate = Some(Arc::new(SessionGate));
    h.cell.store(snap);
    let body = r#"{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#;
    let other = &[
        ("content-type", "application/json"),
        ("x-api-key", "agent-key-for-tests"),
        ("x-scrim-session", "sess-8"),
    ];
    let none = &[
        ("content-type", "application/json"),
        ("x-api-key", "agent-key-for-tests"),
    ];
    for hs in [H, other, none] {
        let r = send(&h, "/anthropic/v1/messages", hs, body.to_owned(), false).await;
        assert_eq!(r.status, 200, "{}", r.text());
    }
    let seen: Vec<Option<SessionKey>> = guard.seen.lock().unwrap().clone();
    let (s7, s8) = (
        SessionKey::new("session", b"sess-7"),
        SessionKey::new("session", b"sess-8"),
    );
    // The body and the request head are checked in the request's session; a gate that names
    // no session leaves the plain check.
    assert!(
        seen.contains(&Some(s7)) && seen.contains(&Some(s8)),
        "{seen:?}"
    );
    assert!(seen.contains(&None), "{seen:?}");
    assert!(!format!("{s7:?}").contains("sess"));
}
