// SPDX-License-Identifier: AGPL-3.0-only

//! The capture broker: hands values a tool-proxy capture rule took from a
//! response to the control plane, which stores them and answers with the
//! placeholder the agent sees. Anything but a placeholder before the
//! deadline withholds the field.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scrim_proto::v1;
use scrim_toolproxy::{CaptureError, CaptureFuture, CaptureRequest, CaptureSink};
use tokio::sync::{mpsc, oneshot};

/// How long a capture may wait for the control plane.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// The capture broker.
#[derive(Debug, Default)]
pub struct Broker {
    next: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<v1::CaptureResult>>>,
    out: Mutex<Option<mpsc::Sender<v1::CaptureRequest>>>,
}

impl Broker {
    /// Attaches the control plane's `Captures` call; `None` if one is
    /// already attached.
    pub fn attach(&self) -> Option<mpsc::Receiver<v1::CaptureRequest>> {
        let mut out = self.out.lock().ok()?;
        if out.as_ref().is_some_and(|tx| !tx.is_closed()) {
            return None;
        }
        let (tx, rx) = mpsc::channel(64);
        *out = Some(tx);
        Some(rx)
    }

    /// Detaches the control plane; pending captures are withheld.
    pub fn detach(&self) {
        if let Ok(mut out) = self.out.lock() {
            *out = None;
        }
        if let Ok(mut p) = self.pending.lock() {
            p.clear();
        }
    }

    /// Delivers the control plane's result.
    pub fn result(&self, r: v1::CaptureResult) {
        let waiter = self.pending.lock().ok().and_then(|mut p| p.remove(&r.id));
        if let Some(w) = waiter {
            let _ = w.send(r);
        }
    }

    /// Sends one capture and waits for its placeholder.
    pub async fn capture(
        &self,
        req: CaptureRequest,
        timeout: Duration,
    ) -> Result<String, CaptureError> {
        let Some(out) = self.out.lock().ok().and_then(|o| o.clone()) else {
            return Err(CaptureError("control plane not connected".into()));
        };
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id, tx);
        }
        let deadline = SystemTime::now() + timeout;
        let mut msg = v1::CaptureRequest::default();
        msg.protocol = v1::PROTOCOL;
        msg.id = id;
        msg.rule = req.rule;
        msg.r#ref = req.reference;
        msg.destination = req.destination;
        msg.value = req.value.expose().to_vec();
        msg.deadline_unix_nano = deadline
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
        if out.send(msg).await.is_err() {
            self.forget(id);
            return Err(CaptureError("control plane not connected".into()));
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(r))
                if r.protocol == v1::PROTOCOL
                    && r.error.is_empty()
                    && !r.placeholder.is_empty() =>
            {
                Ok(r.placeholder)
            }
            Ok(Ok(r)) if !r.error.is_empty() => Err(CaptureError(r.error)),
            Ok(Ok(_)) => Err(CaptureError("control plane returned no placeholder".into())),
            Ok(Err(_)) => Err(CaptureError("control plane went away".into())),
            Err(_) => {
                self.forget(id);
                Err(CaptureError("capture timed out".into()))
            }
        }
    }

    fn forget(&self, id: u64) {
        if let Ok(mut p) = self.pending.lock() {
            p.remove(&id);
        }
    }
}

/// The tool proxy's capture sink, backed by the broker.
#[derive(Clone, Debug)]
pub struct Sink(pub Arc<Broker>);

impl CaptureSink for Sink {
    fn store(&self, req: CaptureRequest) -> CaptureFuture {
        let broker = Arc::clone(&self.0);
        Box::pin(async move { broker.capture(req, TIMEOUT).await })
    }
}

#[cfg(test)]
mod tests {
    use scrim_toolproxy::SecretValue;

    use super::*;

    fn req() -> CaptureRequest {
        CaptureRequest {
            rule: "new-token".into(),
            reference: "mem://captured#token".into(),
            destination: "https://api.example:443".into(),
            value: SecretValue::new("issued-in-test"),
        }
    }

    #[tokio::test]
    async fn withholds_without_control_plane() {
        let b = Broker::default();
        assert!(b.capture(req(), Duration::from_secs(1)).await.is_err());
    }

    #[tokio::test]
    async fn round_trip_and_timeout() {
        let b = Arc::new(Broker::default());
        let mut rx = b.attach();
        let b2 = Arc::clone(&b);
        tokio::spawn(async move {
            if let Some(r) = rx.as_mut() {
                if let Some(m) = r.recv().await {
                    assert_eq!(m.value, b"issued-in-test");
                    b2.result(v1::CaptureResult {
                        protocol: v1::PROTOCOL,
                        id: m.id,
                        placeholder: "SCRIM_CAPTURED".into(),
                        error: String::new(),
                    });
                }
                let _ = r.recv().await;
            }
        });
        assert_eq!(
            b.capture(req(), Duration::from_secs(5))
                .await
                .ok()
                .as_deref(),
            Some("SCRIM_CAPTURED")
        );
        assert!(b.capture(req(), Duration::from_millis(20)).await.is_err());
    }
}
