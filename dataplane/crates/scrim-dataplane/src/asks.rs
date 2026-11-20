// SPDX-License-Identifier: AGPL-3.0-only

//! The ask broker: the one place the data plane waits on the control plane
//! (design D7, D12). Anything other than an explicit allow answer before the
//! deadline is a deny: no control plane attached, the call ended, a timeout,
//! or an answer with any other effect.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scrim_proto::v1;
use tokio::sync::{mpsc, oneshot};

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
        let Some(out) = self.out.lock().ok().and_then(|o| o.clone()) else {
            return Answer::deny("control plane not connected");
        };
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id, tx);
        }
        let deadline = SystemTime::now() + timeout;
        let msg = v1::AskRequest {
            protocol: v1::PROTOCOL,
            id,
            request: Some(request),
            rule: rule.to_owned(),
            reason: reason.to_owned(),
            deadline_unix_nano: deadline
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)),
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
mod tests {
    use std::sync::Arc;

    use super::*;

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
