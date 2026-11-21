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

/// Whether `snap` knows generation `g`'s values (redacts its first per-generation value).
fn knows(snap: &Snapshot, g: usize) -> bool {
    let probe = format!("gen{g}-value-00000-xyz");
    !contains(&redact(snap, probe.as_bytes()), probe.as_bytes())
}

/// Waits until every reader has completed `n` more redactions than `from`, or fails after a
/// liveness bound far beyond any scheduling delay. A reader stuck in `load` never gets there.
fn wait_for_progress(
    readers: &[std::thread::JoinHandle<()>],
    counts: &[Arc<AtomicUsize>],
    from: &[usize],
    n: usize,
    what: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while counts
        .iter()
        .zip(from)
        .any(|(c, &f)| c.load(Ordering::Acquire) < f + n)
    {
        // A reader that panicked (wrong redaction) stops counting; say so instead of timing out.
        assert!(
            !readers.iter().any(std::thread::JoinHandle::is_finished),
            "a reader failed while {what}"
        );
        assert!(
            Instant::now() < deadline,
            "readers made no progress while {what}"
        );
        std::thread::yield_now();
    }
}

#[test]
fn concurrent_redactions_during_rebuilds() {
    const READERS: usize = 4;
    const GENERATIONS: usize = 8;
    // Redactions every reader completes while a rebuild is held open.
    const DURING: usize = 20;

    let handle = Arc::new(SnapshotHandle::new());
    handle.store(Arc::new(build(0)));
    let stop = Arc::new(AtomicBool::new(false));
    let counts: Vec<_> = (0..READERS)
        .map(|_| Arc::new(AtomicUsize::new(0)))
        .collect();
    let body = b"{\"t\":\"x stable-value-present-always y\"}".repeat(200);

    let readers: Vec<_> = counts
        .iter()
        .map(|count| {
            let (handle, stop, count, body) =
                (handle.clone(), stop.clone(), count.clone(), body.clone());
            std::thread::spawn(move || {
                let mut ws = Workspace::new();
                while !stop.load(Ordering::Relaxed) {
                    let snap = handle.load().unwrap();
                    let p = snap.protect(&body, &mut ws).unwrap();
                    assert!(!contains(p.bytes, b"stable-value-present-always"));
                    assert_eq!(p.stats.credential, 200);
                    count.fetch_add(1, Ordering::Release);
                }
            })
        })
        .collect();

    // The builder rebuilds off the request path and stops twice per generation until released:
    // once with the rebuild started and once with the new snapshot built but not yet published.
    // Each stop is a rendezvous, so while main runs between two of them the builder is
    // provably inside the rebuild.
    let (to_main, from_builder) = std::sync::mpsc::sync_channel::<()>(0);
    let (to_builder, from_main) = std::sync::mpsc::sync_channel::<()>(0);
    let builder = {
        let handle = handle.clone();
        std::thread::spawn(move || {
            for g in 1..=GENERATIONS {
                to_main.send(()).unwrap();
                from_main.recv().unwrap();
                let snap = Arc::new(build(g));
                to_main.send(()).unwrap();
                from_main.recv().unwrap();
                handle.store(snap);
            }
        })
    };

    let snapshot = || -> Vec<usize> { counts.iter().map(|c| c.load(Ordering::Acquire)).collect() };
    for g in 1..=GENERATIONS {
        // Rebuild started, nothing built yet.
        from_builder.recv().unwrap();
        wait_for_progress(
            &readers,
            &counts,
            &snapshot(),
            DURING,
            "a rebuild had started",
        );
        to_builder.send(()).unwrap();
        // New snapshot built and held unpublished: readers keep loading and redacting with the
        // previous one.
        from_builder.recv().unwrap();
        let held = handle.load().unwrap();
        assert!(knows(&held, g - 1), "generation {g} published early");
        assert!(!knows(&held, g));
        wait_for_progress(
            &readers,
            &counts,
            &snapshot(),
            DURING,
            "a rebuild was held open",
        );
        to_builder.send(()).unwrap();
    }
    builder.join().unwrap();

    // The last swap reached the handle and readers keep making progress on it.
    let now = handle.load().unwrap();
    assert!(knows(&now, GENERATIONS));
    assert!(!knows(&now, GENERATIONS - 1));
    wait_for_progress(
        &readers,
        &counts,
        &snapshot(),
        DURING,
        "after the last swap",
    );

    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
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
