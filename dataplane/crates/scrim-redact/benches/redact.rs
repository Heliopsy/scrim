//! Benchmarks mirroring `bench/redact-bench`: secret sets of 10, 1,000 and 10,000 values with all
//! variants, request bodies of 100 KB, 1 MB and 4 MB with and without hits, and streamed
//! restoration per chunk.
//!
//! Fixtures come from `testdata/fixtures.rs` (a port of the Go generator). Set
//! `SCRIM_REDACT_GOFIX=<dir>` to load the Go generator's output instead (`secrets-N.json`,
//! `body-*.json`) for a byte-identical comparison with the redact-bench results.
//!
//! Besides criterion's throughput numbers, the `latency` group prints p50/p99/max of redact plus
//! guard per request, and the `restore` group prints p99 per chunk, the two budgets of the
//! performance spec.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::pedantic,
    // The latency report is the point of this bench.
    clippy::print_stderr
)]

#[path = "../testdata/fixtures.rs"]
mod fixtures;

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use scrim_redact::*;

const SETS: [usize; 3] = [10, 1000, 10_000];
const SIZES: [(&str, usize); 3] = [("100k", 100_000), ("1m", 1_000_000), ("4m", 4_000_000)];

fn gofix() -> Option<String> {
    std::env::var("SCRIM_REDACT_GOFIX").ok()
}

fn secrets(n: usize) -> Vec<String> {
    match gofix() {
        Some(d) => {
            let v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(format!("{d}/secrets-{n}.json")).unwrap())
                    .unwrap();
            v["secrets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect()
        }
        None => fixtures::gen_secrets(20_261_120 + n as u64, n),
    }
}

fn body(size: (&str, usize), set: &[String], hits: bool, n: usize) -> Vec<u8> {
    match gofix() {
        Some(d) if hits => std::fs::read(format!("{d}/body-{}-s{n}.json", size.0)).unwrap(),
        Some(d) => std::fs::read(format!("{d}/body-{}-clean.json", size.0)).unwrap(),
        None if hits => fixtures::gen_body(size.1 as u64 + n as u64, size.1, set).0,
        None => fixtures::gen_body(size.1 as u64, size.1, &[]).0,
    }
}

/// `SCRIM_REDACT_THREADS` overrides `Config::parallel_threads` (1: single core).
fn parallel_threads() -> usize {
    std::env::var("SCRIM_REDACT_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Config::default().parallel_threads)
}

fn snapshot(set: &[String], engine: EngineChoice, class: ValueClass) -> Snapshot {
    let kr = Arc::new(Keyring::new(PlaceholderKey::new(1, &[0x5a; 32]).unwrap()));
    let entries = set
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Entry::new(
                i as u64,
                RefSlug::new("secret").unwrap(),
                class,
                SecretValue::from_slice(s.as_bytes()),
            )
        })
        .collect();
    Snapshot::build(
        entries,
        kr,
        &Config {
            engine,
            parallel_threads: parallel_threads(),
            ..Config::default()
        },
    )
    .unwrap()
}

fn engines(n: usize) -> Vec<(&'static str, EngineChoice)> {
    let mut v = vec![("auto", EngineChoice::Auto)];
    if n <= 1000 {
        v.push(("ac", EngineChoice::Fixed(EngineKind::AhoCorasick)));
        v.push(("hw", EngineChoice::Fixed(EngineKind::HashWindow)));
    }
    v
}

fn bench_redact(c: &mut Criterion) {
    let mut g = c.benchmark_group("redact");
    g.warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20);
    for n in SETS {
        let set = secrets(n);
        for (ename, e) in engines(n) {
            let snap = snapshot(&set, e, ValueClass::Credential);
            for size in SIZES {
                for hits in [true, false] {
                    let b = body(size, &set, hits, n);
                    let mut out = Vec::with_capacity(b.len() * 2);
                    g.throughput(Throughput::Bytes(b.len() as u64));
                    let id = format!(
                        "engine={ename}/set={n}/size={}/{}",
                        size.0,
                        if hits { "hits" } else { "clean" }
                    );
                    g.bench_function(BenchmarkId::from_parameter(id), |bn| {
                        bn.iter(|| {
                            black_box(snap.redactor().redact(black_box(&b), &mut out).unwrap())
                        });
                    });
                }
            }
        }
    }
    g.finish();
}

fn bench_protect(c: &mut Criterion) {
    let mut g = c.benchmark_group("protect");
    g.warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20);
    for n in SETS {
        let set = secrets(n);
        let snap = snapshot(&set, EngineChoice::Auto, ValueClass::Credential);
        for size in SIZES {
            for hits in [true, false] {
                let b = body(size, &set, hits, n);
                let mut ws = Workspace::new();
                g.throughput(Throughput::Bytes(b.len() as u64));
                let id = format!(
                    "set={n}/size={}/{}",
                    size.0,
                    if hits { "hits" } else { "clean" }
                );
                g.bench_function(BenchmarkId::from_parameter(id), |bn| {
                    bn.iter(|| {
                        black_box(snap.protect(black_box(&b), &mut ws).unwrap().bytes.len())
                    });
                });
            }
        }
    }
    g.finish();
}

fn percentiles(mut v: Vec<Duration>) -> (Duration, Duration, Duration) {
    v.sort_unstable();
    let at = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)];
    (at(0.5), at(0.99), *v.last().unwrap())
}

/// The latency budget: redact + guard per request, p50/p99 over many requests, and the two
/// halves on their own. 1 MB bodies by default; `SCRIM_REDACT_LATENCY_SIZES=100k,1m,4m` for the
/// full matrix. The guard is timed on the redactor's output, as `protect` runs it.
fn latency(_c: &mut Criterion) {
    let runs: usize = std::env::var("SCRIM_REDACT_LATENCY_RUNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    if runs == 0 {
        return;
    }
    let sizes: Vec<(&str, usize)> = match std::env::var("SCRIM_REDACT_LATENCY_SIZES") {
        Ok(v) => SIZES
            .iter()
            .copied()
            .filter(|(n, _)| v.split(',').any(|x| x == *n))
            .collect(),
        Err(_) => vec![SIZES[1]],
    };
    eprintln!(
        "\nlatency: {runs} runs each, p50 / p99 (redact, guard on redacted bytes, redact = Redactor::redact on one thread, guard = Guard::check, protect = both as protect runs them), parallel threads {}",
        parallel_threads()
    );
    for n in SETS {
        let set = secrets(n);
        let snap = snapshot(&set, EngineChoice::Auto, ValueClass::Credential);
        for &size in &sizes {
            for hits in [true, false] {
                let b = body(size, &set, hits, n);
                let mut ws = Workspace::new();
                let mut out = Vec::new();
                let mut gs = GuardScratch::new();
                for _ in 0..10 {
                    snap.protect(&b, &mut ws).unwrap();
                }
                snap.redactor().redact(&b, &mut out).unwrap();
                let red = out.clone();
                let (mut t, mut tr, mut tg) = (
                    Vec::with_capacity(runs),
                    Vec::with_capacity(runs),
                    Vec::with_capacity(runs),
                );
                for _ in 0..runs {
                    let s = Instant::now();
                    black_box(snap.protect(black_box(&b), &mut ws).unwrap().bytes.len());
                    t.push(s.elapsed());
                    let s = Instant::now();
                    black_box(snap.redactor().redact(black_box(&b), &mut out).unwrap());
                    tr.push(s.elapsed());
                    let s = Instant::now();
                    black_box(matches!(
                        snap.guard().check(black_box(&red), &mut gs),
                        Verdict::Clean
                    ));
                    tg.push(s.elapsed());
                }
                let (p50, p99, _) = percentiles(t);
                let (r50, r99, _) = percentiles(tr);
                let (g50, g99, _) = percentiles(tg);
                eprintln!(
                    "  set={n:>5} size={:<4} {:<5} engine={:?}: redact {r50:>9.2?} / {r99:>9.2?}   guard {g50:>9.2?} / {g99:>9.2?}   protect {p50:>9.2?} / {p99:>9.2?}",
                    size.0,
                    if hits { "hits" } else { "clean" },
                    snap.report().engine
                );
            }
        }
    }
}

/// The fallback detectors alone (no known values): agent request bodies and source code with no
/// secret in them, the cost every request pays for the pattern rules, and with each detector
/// setting changed from its default (`default`: the pattern rules; `encoded`:
/// `redaction.detectors.encoded`; `entropy-key-name` and `entropy-any`: the entropy detector in
/// each context).
fn detect(c: &mut Criterion) {
    let kr = Arc::new(Keyring::new(PlaceholderKey::new(1, &[0x5a; 32]).unwrap()));
    let det = |d: DetectorConfig| {
        Snapshot::build(
            vec![],
            kr.clone(),
            &Config {
                detectors: d,
                ..Config::default()
            },
        )
        .unwrap()
    };
    let snaps = [
        ("default", det(DetectorConfig::default())),
        (
            "encoded",
            det(DetectorConfig {
                encoded: true,
                ..Default::default()
            }),
        ),
        (
            "entropy-key-name",
            det(DetectorConfig {
                entropy: Some(EntropyConfig::default()),
                ..Default::default()
            }),
        ),
        (
            "entropy-any",
            det(DetectorConfig {
                entropy: Some(EntropyConfig::any_context()),
                ..Default::default()
            }),
        ),
    ];
    let src = [
        include_str!("../src/redactor.rs"),
        include_str!("../src/guard.rs"),
        include_str!("../src/detect.rs"),
        include_str!("../src/matcher.rs"),
        include_str!("../README.md"),
    ]
    .concat();
    let mut code = String::with_capacity(1 << 20);
    while code.len() < 1_000_000 {
        code.push_str(&src);
    }
    let mut g = c.benchmark_group("detect");
    g.warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20);
    let inputs = [
        ("body-1m", body(SIZES[1], &[], false, 0)),
        ("body-4m", body(SIZES[2], &[], false, 0)),
        ("code-1m", code.into_bytes()),
    ];
    for (cfg, snap) in &snaps {
        for (name, b) in &inputs {
            let mut out = Vec::with_capacity(b.len() * 2);
            g.throughput(Throughput::Bytes(b.len() as u64));
            let id = if *cfg == "default" {
                (*name).to_string()
            } else {
                format!("{name}/{cfg}")
            };
            g.bench_function(BenchmarkId::from_parameter(id), |bn| {
                bn.iter(|| black_box(snap.redactor().redact(black_box(b), &mut out).unwrap()));
            });
        }
    }
    g.finish();
}

/// Snapshot build time per set size.
fn build(c: &mut Criterion) {
    let mut g = c.benchmark_group("build");
    g.warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    for n in SETS {
        let set = secrets(n);
        g.bench_function(BenchmarkId::from_parameter(format!("set={n}")), |bn| {
            bn.iter(|| {
                black_box(
                    snapshot(&set, EngineChoice::Auto, ValueClass::Credential)
                        .report()
                        .patterns,
                )
            });
        });
    }
    g.finish();
}

/// Restoring a stream: decoded text deltas of realistic chunk sizes with placeholders every
/// ~600 bytes, secret set of 1,000.
fn restore(c: &mut Criterion) {
    let set = secrets(1000);
    let kr = Arc::new(Keyring::new(PlaceholderKey::new(1, &[0x5a; 32]).unwrap()));
    let snap = snapshot(&set, EngineChoice::Auto, ValueClass::Display);
    let slug = RefSlug::new("secret").unwrap();
    let phs: Vec<String> = set
        .iter()
        .take(200)
        .map(|s| placeholder_for(kr.current(), &slug, s.as_bytes()))
        .collect();
    let mut g = c.benchmark_group("restore");
    g.warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(3))
        .sample_size(20);
    for (name, size) in [("2k", 40_000usize), ("20k", 400_000)] {
        let text = fixtures::gen_stream_text(5, size, &phs, 600);
        let mut chunks = Vec::new();
        let mut at = 0;
        for n in fixtures::gen_chunks(6, text.len()) {
            if at >= text.len() {
                break;
            }
            let mut end = (at + n).min(text.len());
            while !text.is_char_boundary(end) {
                end += 1;
            }
            chunks.push(&text[at..end]);
            at = end;
        }
        let mut out = String::with_capacity(text.len() * 2);
        g.throughput(Throughput::Bytes(text.len() as u64));
        g.bench_function(
            BenchmarkId::from_parameter(format!("stream={name}/chunks={}", chunks.len())),
            |bn| {
                bn.iter(|| {
                    out.clear();
                    let mut b = BlockRestorer::new();
                    for ch in &chunks {
                        b.push(snap.resolver(), &RestoreDisplay, ch, &mut out);
                    }
                    b.finish(&mut out);
                    black_box(out.len())
                });
            },
        );
        let mut t = Vec::with_capacity(chunks.len() * 5);
        for _ in 0..5 {
            out.clear();
            let mut b = BlockRestorer::new();
            for ch in &chunks {
                let s = Instant::now();
                b.push(snap.resolver(), &RestoreDisplay, ch, &mut out);
                t.push(s.elapsed());
            }
        }
        let (p50, p99, max) = percentiles(t);
        eprintln!(
            "restore stream={name}: per chunk p50 {p50:.2?} p99 {p99:.2?} max {max:.2?} ({} chunks)",
            chunks.len()
        );
    }
    g.finish();
}

criterion_group!(
    benches,
    latency,
    bench_redact,
    bench_protect,
    restore,
    build,
    detect
);
criterion_main!(benches);
