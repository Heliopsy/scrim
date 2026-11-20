// SPDX-License-Identifier: AGPL-3.0-only

//! The ask broker: the one place the data plane waits on the control plane
//! (design D7, D12). Anything other than an explicit allow answer before the
//! deadline is a deny: no control plane attached, the call ended, a timeout,
//! or an answer with any other effect.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac as _};
use scrim_proto::v1;
use scrim_toolproxy::SessionVerifier;
use tokio::sync::{mpsc, oneshot};

/// The proof that an ask's caller holds the token of `session_id` (`AskCaller.session_proof`,
/// design D14): `HMAC-SHA256(key = verifier, "scrim session proof v1\0" || session_id || "\0" ||
/// ask id (big-endian) || deadline (big-endian))`. Bound to one ask; reveals neither the token
/// nor the verifier.
pub fn session_proof(
    verifier: &SessionVerifier,
    session_id: &str,
    ask_id: u64,
    deadline_unix_nano: i64,
) -> [u8; 32] {
    let Ok(mut mac) = Hmac::<sha2::Sha256>::new_from_slice(verifier.as_bytes()) else {
        return [0; 32]; // unreachable: HMAC takes any key length
    };
    mac.update(b"scrim session proof v1\0");
    mac.update(session_id.as_bytes());
    mac.update(b"\0");
    mac.update(&ask_id.to_be_bytes());
    mac.update(&deadline_unix_nano.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// The outcome of an ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Whether the operation may proceed.
    pub allowed: bool,
    /// Why, for audit.
    pub reason: String,
    /// The grant an approval created, if any, for audit. Never cached: the
    /// control plane reads grants on every use.
    pub grant_id: String,
    /// When that grant expires (Unix nanoseconds).
    pub grant_expires_unix_nano: i64,
}

impl Answer {
    fn deny(reason: &str) -> Self {
        Self {
            allowed: false,
            reason: reason.to_owned(),
            grant_id: String::new(),
            grant_expires_unix_nano: 0,
        }
    }
}

/// The ask broker.
#[derive(Debug, Default)]
pub struct Broker {
    next: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<v1::AskAnswer>>>,
    out: Mutex<Option<mpsc::Sender<v1::AskRequest>>>,
}

impl Broker {
    /// Attaches the control plane's `Asks` call. Returns `None` if one is
    /// already attached.
    pub fn attach(&self) -> Option<mpsc::Receiver<v1::AskRequest>> {
        let mut out = self.out.lock().ok()?;
        if out.as_ref().is_some_and(|tx| !tx.is_closed()) {
            return None;
        }
        let (tx, rx) = mpsc::channel(256);
        *out = Some(tx);
        Some(rx)
    }

    /// Detaches the control plane; every pending ask is denied.
    pub fn detach(&self) {
        if let Ok(mut out) = self.out.lock() {
            *out = None;
        }
        if let Ok(mut p) = self.pending.lock() {
            p.clear(); // dropping the senders denies the waiters
        }
    }

    /// Delivers the control plane's answer to the waiting ask.
    pub fn answer(&self, a: v1::AskAnswer) {
        let waiter = self.pending.lock().ok().and_then(|mut p| p.remove(&a.id));
        if let Some(w) = waiter {
            let _ = w.send(a);
        }
    }

    /// Asks the control plane about `request` and waits up to `timeout`.
    pub async fn ask(
        &self,
        request: v1::PolicyRequest,
        rule: &str,
        reason: &str,
        timeout: Duration,
    ) -> Answer {
        self.ask_as(request, None, rule, reason, timeout).await
    }

    /// Asks the control plane about `request` from `caller` (what the transport said about the
    /// sender, for the control plane to resolve) and waits up to `timeout`.
    pub async fn ask_as(
        &self,
        request: v1::PolicyRequest,
        caller: Option<v1::AskCaller>,
        rule: &str,
        reason: &str,
        timeout: Duration,
    ) -> Answer {
        self.ask_proven(request, caller, None, rule, reason, timeout)
            .await
    }

    /// [`Broker::ask_as`], and when `verifier` is set (the request carried the token of
    /// `caller.session_id`) the ask carries the session proof bound to this ask
    /// ([`session_proof`]).
    pub async fn ask_proven(
        &self,
        request: v1::PolicyRequest,
        mut caller: Option<v1::AskCaller>,
        verifier: Option<&SessionVerifier>,
        rule: &str,
        reason: &str,
        timeout: Duration,
    ) -> Answer {
        let Some(out) = self.out.lock().ok().and_then(|o| o.clone()) else {
            return Answer::deny("control plane not connected");
        };
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id, tx);
        }
        let deadline = SystemTime::now() + timeout;
        let deadline_unix_nano = deadline
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
        if let (Some(c), Some(v)) = (caller.as_mut(), verifier)
            && !c.session_id.is_empty()
        {
            c.session_proof = session_proof(v, &c.session_id, id, deadline_unix_nano).to_vec();
        }
        let msg = v1::AskRequest {
            protocol: v1::PROTOCOL,
            id,
            request: Some(request),
            rule: rule.to_owned(),
            reason: reason.to_owned(),
            deadline_unix_nano,
            caller,
        };
        if out.send(msg).await.is_err() {
            self.forget(id);
            return Answer::deny("control plane not connected");
        }
        let answer = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(a)) => a,
            Ok(Err(_)) => {
                return Answer::deny("control plane went away");
            }
            Err(_) => {
                self.forget(id);
                return Answer::deny("approval timed out");
            }
        };
        if answer.protocol != v1::PROTOCOL {
            return Answer::deny("answer carries a different protocol version");
        }
        Answer {
            allowed: answer.effect() == v1::Effect::Allow,
            reason: answer.reason,
            grant_id: answer.grant_id,
            grant_expires_unix_nano: answer.grant_expires_unix_nano,
        }
    }

    fn forget(&self, id: u64) {
        if let Ok(mut p) = self.pending.lock() {
            p.remove(&id);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write as _;
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    }

    /// The same vector as `internal/identity` `TestSessionProofVector`: both halves derive the
    /// verifier and the proof identically.
    #[test]
    fn session_proof_matches_the_control_plane() {
        let token = format!("scrim_st_abcdefghijklmn23_{}", "A".repeat(43));
        let (id, v) = scrim_toolproxy::parse_session_token(token.as_bytes()).unwrap();
        assert_eq!(id, "abcdefghijklmn23");
        assert_eq!(
            hex(v.as_bytes()),
            "7cabb63bcae2fbcaef12849c770d685680ecb7a8f7286a7a8791e91cba662b8a"
        );
        assert_eq!(
            hex(&session_proof(&v, &id, 7, 1_700_000_000_000_000_000)),
            "2f9e6c617d495d092f9b5bd93420f5735cb4d84a70ca3c068d3dfe822bbad3a7"
        );
    }

    #[tokio::test]
    async fn ask_carries_the_proof_only_with_a_verifier() {
        let b = Arc::new(Broker::default());
        let mut rx = b.attach().unwrap();
        let token = format!("scrim_st_abcdefghijklmn23_{}", "A".repeat(43));
        let (id, v) = scrim_toolproxy::parse_session_token(token.as_bytes()).unwrap();
        let mut caller = v1::AskCaller::default();
        caller.session_id.clone_from(&id);
        let b2 = Arc::clone(&b);
        let c2 = caller.clone();
        let h = tokio::spawn(async move {
            b2.ask_proven(
                v1::PolicyRequest::default(),
                Some(c2),
                Some(&v),
                "r",
                "",
                Duration::from_secs(5),
            )
            .await
        });
        let msg = rx.recv().await.unwrap();
        let c = msg.caller.clone().unwrap();
        let (_, v) = scrim_toolproxy::parse_session_token(token.as_bytes()).unwrap();
        assert_eq!(
            c.session_proof,
            session_proof(&v, &id, msg.id, msg.deadline_unix_nano).to_vec()
        );
        assert!(!format!("{msg:?}").contains(&token[26..]));
        b.answer(v1::AskAnswer {
            protocol: v1::PROTOCOL,
            id: msg.id,
            ..Default::default()
        });
        assert!(!h.await.unwrap().allowed);
        let b2 = Arc::clone(&b);
        let h = tokio::spawn(async move {
            b2.ask_as(
                v1::PolicyRequest::default(),
                Some(caller),
                "r",
                "",
                Duration::from_secs(5),
            )
            .await
        });
        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.caller.unwrap().session_proof, Vec::<u8>::new());
        b.answer(v1::AskAnswer {
            protocol: v1::PROTOCOL,
            id: msg.id,
            ..Default::default()
        });
        let _ = h.await;
    }

    #[tokio::test]
    async fn denies_without_control_plane() {
        let b = Broker::default();
        let a = b
            .ask(
                v1::PolicyRequest::default(),
                "r",
                "why",
                Duration::from_secs(1),
            )
            .await;
        assert!(!a.allowed);
    }

    #[tokio::test]
    async fn allow_answer_and_timeout() {
        let b = Arc::new(Broker::default());
        let mut rx = b.attach();
        assert!(b.attach().is_none());
        let b2 = Arc::clone(&b);
        let answerer = tokio::spawn(async move {
            let req = match rx.as_mut() {
                Some(rx) => rx.recv().await,
                None => None,
            };
            if let Some(req) = req {
                b2.answer(v1::AskAnswer {
                    protocol: v1::PROTOCOL,
                    id: req.id,
                    effect: v1::Effect::Allow.into(),
                    ..Default::default()
                });
            }
            rx
        });
        let a = b
            .ask(
                v1::PolicyRequest::default(),
                "r",
                "why",
                Duration::from_secs(5),
            )
            .await;
        assert!(a.allowed);
        let _rx = answerer.await;
        let a = b
            .ask(
                v1::PolicyRequest::default(),
                "r",
                "why",
                Duration::from_millis(20),
            )
            .await;
        assert!(!a.allowed);
        assert_eq!(a.reason, "approval timed out");
    }
}
