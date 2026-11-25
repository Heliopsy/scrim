// SPDX-License-Identifier: AGPL-3.0-only

//! The certificate check broker: while OCSP is on (`ClientCertificateTrust.ocsp`), a TLS
//! listener sends every client chain it accepted in the handshake to the control plane, which
//! applies the CRLs and OCSP, and serves the connection only when the answer accepts it
//! (agent-identity spec, "Revocation checks of client certificates"). Anything else refuses: no
//! control plane attached, the call ended, a timeout, or a refusal.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::CertificateDer;
use scrim_proto::v1;
use tokio::sync::{mpsc, oneshot};

/// How long a connection waits for its check. The control plane bounds each OCSP request to at
/// most ten seconds and runs a chain's requests in parallel, so it answers well before this.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// The refusal reason when no answer could be had from the control plane.
pub const UNAVAILABLE: &str = "ocsp unavailable";

/// The certificate check broker.
#[derive(Debug, Default)]
pub struct Broker {
    next: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<v1::CertificateCheckResult>>>,
    out: Mutex<Option<mpsc::Sender<v1::CertificateCheckRequest>>>,
}

impl Broker {
    /// Attaches the control plane's `CertificateChecks` call; `None` if one is already attached.
    pub fn attach(&self) -> Option<mpsc::Receiver<v1::CertificateCheckRequest>> {
        let mut out = self.out.lock().ok()?;
        if out.as_ref().is_some_and(|tx| !tx.is_closed()) {
            return None;
        }
        let (tx, rx) = mpsc::channel(256);
        *out = Some(tx);
        Some(rx)
    }

    /// Detaches the control plane; pending checks refuse.
    pub fn detach(&self) {
        if let Ok(mut out) = self.out.lock() {
            *out = None;
        }
        if let Ok(mut p) = self.pending.lock() {
            p.clear();
        }
    }

    /// Delivers the control plane's result.
    pub fn result(&self, r: v1::CertificateCheckResult) {
        let waiter = self.pending.lock().ok().and_then(|mut p| p.remove(&r.id));
        if let Some(w) = waiter {
            let _ = w.send(r);
        }
    }

    /// Sends `chain` (leaf first) for checking and waits up to `timeout`. `Ok(())` serves the
    /// connection; `Err` carries the refusal reason.
    pub async fn check(
        &self,
        listener: &str,
        chain: &[CertificateDer<'static>],
        timeout: Duration,
    ) -> Result<(), String> {
        let Some(out) = self.out.lock().ok().and_then(|o| o.clone()) else {
            return Err(UNAVAILABLE.to_owned());
        };
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id, tx);
        }
        let deadline = SystemTime::now() + timeout;
        let msg = v1::CertificateCheckRequest {
            protocol: v1::PROTOCOL,
            id,
            listener: listener.to_owned(),
            chain: chain.iter().map(|c| c.to_vec()).collect(),
            deadline_unix_nano: deadline
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)),
        };
        if out.send(msg).await.is_err() {
            self.forget(id);
            return Err(UNAVAILABLE.to_owned());
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(r)) if r.protocol == v1::PROTOCOL && r.accepted => Ok(()),
            Ok(Ok(r)) if !r.reason.is_empty() && !r.accepted => Err(r.reason),
            Ok(_) => Err(UNAVAILABLE.to_owned()),
            Err(_) => {
                self.forget(id);
                Err(UNAVAILABLE.to_owned())
            }
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

    fn chain() -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(b"leaf-in-test".to_vec())]
    }

    #[tokio::test]
    async fn refuses_without_control_plane() {
        let b = Broker::default();
        assert_eq!(
            b.check("tls", &chain(), Duration::from_secs(1)).await,
            Err(UNAVAILABLE.to_owned())
        );
    }

    #[tokio::test]
    async fn round_trip_refusal_and_timeout() {
        let b = Arc::new(Broker::default());
        let mut rx = b.attach().unwrap();
        assert!(b.attach().is_none(), "a second attach while one is live");
        let b2 = Arc::clone(&b);
        tokio::spawn(async move {
            let mut n = 0;
            while let Some(m) = rx.recv().await {
                n += 1;
                assert_eq!(m.chain, vec![b"leaf-in-test".to_vec()]);
                assert_eq!(m.listener, "tls");
                match n {
                    1 => b2.result(v1::CertificateCheckResult {
                        protocol: v1::PROTOCOL,
                        id: m.id,
                        accepted: true,
                        reason: String::new(),
                    }),
                    2 => b2.result(v1::CertificateCheckResult {
                        protocol: v1::PROTOCOL,
                        id: m.id,
                        accepted: false,
                        reason: "revoked".into(),
                    }),
                    3 => b2.result(v1::CertificateCheckResult {
                        protocol: v1::PROTOCOL + 1,
                        id: m.id,
                        accepted: true,
                        reason: String::new(),
                    }),
                    _ => {} // no answer: times out
                }
            }
        });
        let t = Duration::from_secs(5);
        assert_eq!(b.check("tls", &chain(), t).await, Ok(()));
        assert_eq!(b.check("tls", &chain(), t).await, Err("revoked".to_owned()));
        assert_eq!(
            b.check("tls", &chain(), t).await,
            Err(UNAVAILABLE.to_owned()),
            "an answer in another protocol accepts nothing"
        );
        assert_eq!(
            b.check("tls", &chain(), Duration::from_millis(20)).await,
            Err(UNAVAILABLE.to_owned())
        );
    }
}
