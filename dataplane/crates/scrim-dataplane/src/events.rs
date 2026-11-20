// SPDX-License-Identifier: AGPL-3.0-only

//! The event bus: the engine emits audit-relevant events without waiting;
//! the control plane drains them in batches over `Events`. When the control
//! plane falls behind, events are dropped and counted, never silently lost.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use scrim_proto::v1;
use tokio::sync::mpsc;

/// Capacity of the queue between the engine and the control plane.
pub const CAPACITY: usize = 4096;
/// Largest batch sent in one message.
pub const MAX_BATCH: usize = 256;

/// The event bus.
#[derive(Debug)]
pub struct Bus {
    tx: mpsc::Sender<v1::Event>,
    rx: Mutex<Option<mpsc::Receiver<v1::Event>>>,
    seq: AtomicU64,
    dropped: Arc<AtomicU64>,
    dropped_total: AtomicU64,
}

impl Default for Bus {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel(CAPACITY);
        Self {
            tx,
            rx: Mutex::new(Some(rx)),
            seq: AtomicU64::new(0),
            dropped: Arc::default(),
            dropped_total: AtomicU64::new(0),
        }
    }
}

impl Bus {
    /// Queues `ev`, filling in its sequence number and time. Never blocks.
    /// The event must not contain a value.
    pub fn emit(&self, mut ev: v1::Event) {
        ev.seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        if ev.time_unix_nano == 0 {
            ev.time_unix_nano = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
        }
        if self.tx.try_send(ev).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            self.dropped_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Takes the receiving end. Only the first caller gets it: there is one
    /// subscriber per process.
    pub fn subscribe(&self) -> Option<Subscriber> {
        let rx = self.rx.lock().ok()?.take()?;
        Some(Subscriber {
            dropped: Arc::clone(&self.dropped),
            rx,
        })
    }

    /// Events dropped and not yet reported.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Events dropped since the process started, for metrics.
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total.load(Ordering::Relaxed)
    }
}

/// The receiving end of the bus.
#[derive(Debug)]
pub struct Subscriber {
    dropped: Arc<AtomicU64>,
    rx: mpsc::Receiver<v1::Event>,
}

impl Subscriber {
    /// Waits for at least one event and returns up to [`MAX_BATCH`], with
    /// the drop count since the last batch. `None` once the bus is gone.
    pub async fn next_batch(&mut self) -> Option<v1::EventBatch> {
        let mut events = Vec::with_capacity(16);
        if self.rx.recv_many(&mut events, MAX_BATCH).await == 0 {
            return None;
        }
        Some(v1::EventBatch {
            protocol: scrim_proto::v1::PROTOCOL,
            events,
            dropped: self.dropped.swap(0, Ordering::Relaxed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn batches_and_counts_drops() {
        let bus = Bus::default();
        for _ in 0..CAPACITY + 5 {
            bus.emit(v1::Event {
                kind: v1::EventKind::Redaction.into(),
                ..Default::default()
            });
        }
        let mut sub = bus.subscribe();
        assert!(
            bus.subscribe().is_none(),
            "a second subscriber must be refused"
        );
        let first = match sub.as_mut() {
            Some(s) => s.next_batch().await,
            None => None,
        };
        assert_eq!(first.as_ref().map(|b| b.events.len()), Some(MAX_BATCH));
        assert_eq!(first.as_ref().map(|b| b.dropped), Some(5));
        assert_eq!(first.as_ref().map(|b| b.events[0].seq), Some(1));
    }
}
