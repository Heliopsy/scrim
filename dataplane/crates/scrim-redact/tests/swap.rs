//! Atomic rebuild and swap: readers never block and never miss a value present before and after.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    unreachable_pub,
    missing_docs
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::*;
use scrim_redact::*;

fn build(generation: usize) -> Snapshot {
    // A stable value present in every generation, plus values that change per generation, and
    // enough of them that the auto engine switches between Aho-Corasick and hash-window.
    let mut vals: Vec<Vec<u8>> = vec![b"stable-value-present-always".to_vec()];
    let n = if generation.is_multiple_of(2) {
        3
    } else {
        1500
    };
    vals.extend((0..n).map(|i| format!("gen{generation}-value-{i:05}-xyz").into_bytes()));
    let refs: Vec<&[u8]> = vals.iter().map(Vec::as_slice).collect();
    snapshot_with(&refs, ValueClass::Credential, &Config::default())
}

#[test]
fn concurrent_redactions_during_rebuilds() {
    let handle = Arc::new(SnapshotHandle::new());
    handle.store(Arc::new(build(0)));
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicUsize::new(0));
    let worst = Arc::new(AtomicUsize::new(0));
    let body = b"{\"t\":\"x stable-value-present-always y\"}".repeat(200);

    let readers: Vec<_> = (0..4)
        .map(|_| {
            let (handle, stop, done, worst, body) = (
                handle.clone(),
                stop.clone(),
                done.clone(),
                worst.clone(),
                body.clone(),
            );
            std::thread::spawn(move || {
                let mut ws = Workspace::new();
                while !stop.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    let snap = handle.load().unwrap();
                    worst.fetch_max(t.elapsed().as_micros() as usize, Ordering::Relaxed);
                    let p = snap.protect(&body, &mut ws).unwrap();
                    assert!(!contains(p.bytes, b"stable-value-present-always"));
                    assert_eq!(p.stats.credential, 200);
                    done.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();

    // Rebuild off the request path and swap, repeatedly.
    for g in 1..=8 {
        let snap = Arc::new(build(g));
        handle.store(snap);
    }
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
    assert!(done.load(Ordering::Relaxed) > 0);
    // Loading is a lock-free pointer read; even on a loaded CI machine it never waits for a
    // rebuild (which takes tens of milliseconds here).
    assert!(
        Duration::from_micros(worst.load(Ordering::Relaxed) as u64) < Duration::from_millis(20)
    );
}

#[test]
fn in_flight_request_keeps_its_snapshot() {
    let handle = SnapshotHandle::new();
    handle.store(Arc::new(build(0)));
    let held = handle.load().unwrap();
    handle.store(Arc::new(build(1)));
    // The old snapshot still knows generation 0's values; the new one does not.
    assert!(!contains(
        &redact(&held, b"gen0-value-00001-xyz"),
        b"gen0-value"
    ));
    let now = handle.load().unwrap();
    assert_eq!(
        redact(&now, b"gen0-value-00001-xyz"),
        b"gen0-value-00001-xyz"
    );
    assert_eq!(held.report().engine, EngineKind::AhoCorasick);
    assert_eq!(now.report().engine, EngineKind::HashWindow);
}
