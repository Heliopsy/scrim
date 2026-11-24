// SPDX-License-Identifier: AGPL-3.0-only

//! Latency budget gate (performance spec), with the production engine (`scrim-redact`).
//!
//! Measures, on generated reference fixtures:
//!
//! - proxy overhead per request: codec plan, segmenting and guard hand-off for Anthropic
//!   Messages bodies of about 100 KB, 1 MB and 4 MB, once with a pass-through engine and once
//!   with the production engine wired in (the engine's own time subtracted), so the number is
//!   what this crate adds on its own;
//! - added request latency through the proxy (`outgoing::prepare`) with the production engine,
//!   for 10, 1,000 and 10,000 secrets, with and without hits, on the redaction benchmark's
//!   request bodies (`scrim-redact/testdata/fixtures.rs`, the conditions of
//!   `bench/redact-bench`);
//! - the redaction core on its own, as the `scrim-redact` benchmarks measure it:
//!   `Snapshot::protect` per request, single-thread redaction throughput, and restore per
//!   streamed chunk;
//! - time added per streamed chunk while the proxy restores a 20,000-event stream with the
//!   production placeholders, chunked at event and mid-event boundaries;
//! - the request and chunk paths with metrics off and on (`metrics.enabled`).
//!
//! # Method
//!
//! Every measurement runs in rounds (`SCRIM_PERF_ROUNDS`, default 5). A round takes a fixed
//! number of samples and computes nearest-rank p50 and p99; the reported value is the median of
//! the rounds. On Linux, a sample during which the measuring thread waited for a CPU for more
//! than 50 µs (its run-queue delay in `/proc/thread-self/schedstat`: another process held the
//! CPU, or the cgroup's CPU quota was used up) measures the machine, not scrim, and is dropped
//! and counted.
//! A round where more than half the samples were dropped keeps all of them and is reported as
//! busy, so a saturated machine shows up in the report instead of passing on a handful of
//! samples. A regression is in every round; load from other processes is in some.
//!
//! Each gated value is compared with `benches/budget.json` (or the file in
//! `SCRIM_LLM_BUDGET`). The process exits non-zero, naming the measurement, when a budget is
//! missed. `SCRIM_PERF_JSON=<file>` also writes every measurement, its rounds and the machine
//! as JSON, which `scripts/perfgate` compares with the previous release's.
//!
//! Run with `cargo bench -p scrim-llm --bench latency_gate`; `SCRIM_LLM_BENCH_QUICK=1`
//! shortens it (fewer rounds and samples, no 4 MB bodies).

#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::pedantic,
    reason = "benchmark binary: prints its report and fails loudly"
)]

#[path = "../../scrim-redact/testdata/fixtures.rs"]
mod fixtures;

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use scrim_llm::config::Limits;
use scrim_llm::core::CoreEngine;
use scrim_llm::engine::{
    BinaryPolicy, EngineError, Guard, GuardVerdict, RedactReport, Redactor, RestoreDecision,
    RestorePolicy, RestoreSite, SecretRef, Snapshot, ValueClass,
};
use scrim_llm::metrics::{LlmMetrics, Stage};
use scrim_llm::outgoing;
use scrim_llm::testing::Fixture;
use scrim_llm::{Api, SseRestorer};
use scrim_redact as rc;
use serde_json::{Value, json};

/// Deterministic xorshift, so fixtures have the same shape on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const WORDS: &[&str] = &[
    "const", "let", "return", "error", "config", "deploy", "func", "value", "the", "user", "file",
    "path", "read", "write", "test", "build", "server", "client", "token", "request", "fn", "impl",
    "match", "string", "result",
];

fn prose(rng: &mut Rng, bytes: usize) -> String {
    let mut s = String::with_capacity(bytes + 16);
    while s.len() < bytes {
        s.push_str(WORDS[rng.below(WORDS.len())]);
        s.push(if rng.below(12) == 0 { '\n' } else { ' ' });
    }
    s
}

/// A Claude Code style conversation of about `size` bytes, with a thinking block (a verbatim
/// span) per turn. With `values`, one of them is embedded in every ~4 KB tool result.
fn anthropic_body(values: &[String], rng: &mut Rng, size: usize) -> Vec<u8> {
    let mut messages = Vec::new();
    let mut total = 0;
    let mut turn = 0;
    while total < size {
        let mut out = prose(rng, 4096.min(size - total + 64));
        if !values.is_empty() {
            out.push_str(&values[rng.below(values.len())]);
        }
        total += out.len() + 200;
        let id = format!("toolu_{turn:08}");
        messages.push(json!({"role": "assistant", "content": [
            {"type": "thinking", "thinking": "Let me look at the file.", "signature": "EqQBCkgIARABGAIiQKsfY2s0bWVzaWduYXR1cmU="},
            {"type": "tool_use", "id": id, "name": "Read", "input": {"file_path": format!("/src/f{turn}.rs")}}
        ]}));
        messages.push(json!({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": id, "content": out}
        ]}));
        turn += 1;
    }
    serde_json::to_vec(&json!({
        "model": "claude-sonnet-4-5", "max_tokens": 32000, "stream": true,
        "system": [{"type": "text", "text": "You are Claude Code."}],
        "messages": messages,
    }))
    .unwrap()
}

/// An Anthropic stream of `events` events with one of `phs` in about one delta in five, split
/// into chunks at event boundaries and, for one event in four, inside the event.
fn stream_chunks(phs: &[String], rng: &mut Rng, events: usize) -> Vec<Vec<u8>> {
    let mut s = String::new();
    let mut n = 0;
    let mut index = 0;
    while n < events {
        let (start, dtype, field) = match rng.below(10) {
            0 => (
                r#"{"type":"thinking","thinking":"","signature":""}"#,
                "thinking_delta",
                "thinking",
            ),
            1 => (
                r#"{"type":"tool_use","id":"t","name":"Bash","input":{}}"#,
                "input_json_delta",
                "partial_json",
            ),
            _ => (r#"{"type":"text","text":""}"#, "text_delta", "text"),
        };
        let _ = write!(
            s,
            "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":{index},\"content_block\":{start}}}\n\n"
        );
        n += 1;
        let deltas = 20 + rng.below(80);
        for d in 0..deltas {
            let len = 10 + rng.below(40);
            let mut t = prose(rng, len);
            if field == "partial_json" && d == 0 {
                t = format!("{{\"command\": \"{t}");
            }
            if rng.below(5) == 0 && !phs.is_empty() {
                t.push_str(&phs[rng.below(phs.len())]);
            }
            let v = serde_json::to_string(&t).unwrap();
            let _ = write!(
                s,
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":{index},\"delta\":{{\"type\":\"{dtype}\",\"{field}\":{v}}}}}\n\n"
            );
            n += 1;
        }
        let _ = write!(
            s,
            "event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":{index}}}\n\n"
        );
        n += 1;
        index += 1;
    }
    let b = s.into_bytes();
    let mut chunks = Vec::new();
    let mut pos = 0;
    while pos < b.len() {
        let end = b[pos..]
            .windows(2)
            .position(|w| w == b"\n\n")
            .map_or(b.len(), |p| pos + p + 2);
        if rng.below(4) == 0 && end - pos > 8 {
            let mid = pos + 1 + rng.below(end - pos - 1);
            chunks.push(b[pos..mid].to_vec());
            chunks.push(b[mid..end].to_vec());
        } else {
            chunks.push(b[pos..end].to_vec());
        }
        pos = end;
    }
    chunks
}

// ---------------------------------------------------------------------------------------------
// The production engine.

/// The redaction benchmark's secret set of `n` values (same seeds as `scrim-redact`'s bench).
fn secrets(n: usize) -> Vec<String> {
    fixtures::gen_secrets(20_261_120 + n as u64, n)
}

/// A core snapshot over `set`, built with the data plane's default configuration.
fn core(set: &[String], class: rc::ValueClass) -> Arc<rc::Snapshot> {
    let kr = Arc::new(rc::Keyring::new(
        rc::PlaceholderKey::new(1, &[0x5a; 32]).unwrap(),
    ));
    let entries = set
        .iter()
        .enumerate()
        .map(|(i, s)| {
            rc::Entry::new(
                i as u64,
                rc::RefSlug::new("secret").unwrap(),
                class,
                rc::SecretValue::from_slice(s.as_bytes()),
            )
        })
        .collect();
    Arc::new(rc::Snapshot::build(entries, kr, &rc::Config::default()).unwrap())
}

/// Resolves every placeholder the proxy offers, without recording anything.
struct ResolveAll;

impl RestorePolicy for ResolveAll {
    fn decide(&self, _: &RestoreSite<'_>, _: &SecretRef, _: ValueClass) -> RestoreDecision {
        RestoreDecision::Resolve
    }
}

/// The proxy's engine snapshot over `core`, as the data plane builds it.
fn engine(core: &Arc<rc::Snapshot>, n: usize) -> Snapshot {
    let refs = (0..n as u64).map(|i| (rc::EntryId(i), SecretRef::new(format!("bench#s{i}"))));
    CoreEngine::new(Arc::clone(core), refs).snapshot(1, Arc::new(ResolveAll), BinaryPolicy::Pass)
}

/// Adds the time spent in the wrapped redactor to a shared counter.
struct TimedRedactor(Arc<dyn Redactor>, Arc<AtomicU64>);

impl Redactor for TimedRedactor {
    fn redact(&self, input: &[u8], out: &mut Vec<u8>) -> Result<RedactReport, EngineError> {
        let t = Instant::now();
        let r = self.0.redact(input, out);
        self.1
            .fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
        r
    }
}

/// Adds the time spent in the wrapped guard to a shared counter.
struct TimedGuard(Arc<dyn Guard>, Arc<AtomicU64>);

impl Guard for TimedGuard {
    fn check(&self, outgoing: &[u8]) -> Result<GuardVerdict, EngineError> {
        let t = Instant::now();
        let r = self.0.check(outgoing);
        self.1
            .fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
        r
    }
}

/// `snap` with its redactor and guard timed into the returned counter.
fn timed(snap: &Snapshot) -> (Snapshot, Arc<AtomicU64>) {
    let spent = Arc::new(AtomicU64::new(0));
    let mut s = snap.clone();
    s.redactor = Arc::new(TimedRedactor(snap.redactor.clone(), spent.clone()));
    s.guard = Arc::new(TimedGuard(snap.guard.clone(), spent.clone()));
    (s, spent)
}

// ---------------------------------------------------------------------------------------------
// Sampling.

/// The calling thread's total run-queue delay in nanoseconds (Linux schedstat), or `None` where
/// the kernel does not expose it.
fn run_delay() -> Option<u64> {
    std::fs::read_to_string("/proc/thread-self/schedstat")
        .ok()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Run-queue delay during one sample above which the sample is dropped. Waking up after the
/// engine's worker threads join takes microseconds and is part of the latency; a thread that
/// another process preempted, or that its cgroup's CPU quota throttled, waits milliseconds.
const DISTURBED_NS: u64 = 50_000;

fn nearest_rank(sorted: &[f64], q: f64) -> f64 {
    let i = ((sorted.len() as f64) * q).ceil() as usize;
    sorted[i.saturating_sub(1).min(sorted.len() - 1)]
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_unstable_by(f64::total_cmp);
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

/// The rounds of one measurement, in the measurement's unit.
#[derive(Default)]
struct Rounds {
    p50: Vec<f64>,
    p99: Vec<f64>,
    samples: usize,
    dropped: usize,
    busy: usize,
}

impl Rounds {
    fn p50(&self) -> f64 {
        median(&self.p50)
    }

    fn p99(&self) -> f64 {
        median(&self.p99)
    }
}

struct Sampler {
    rounds: usize,
    filter: bool,
}

impl Sampler {
    /// Runs `rounds` rounds of `per_round` samples of `f`, which returns the duration to record
    /// (it may subtract time that is not part of the measurement). `scale` converts seconds to
    /// the unit reported.
    fn run(&self, per_round: usize, scale: f64, mut f: impl FnMut() -> Duration) -> Rounds {
        let mut r = Rounds::default();
        let mut all = Vec::with_capacity(per_round);
        let mut kept = Vec::with_capacity(per_round);
        for _ in 0..self.rounds {
            all.clear();
            kept.clear();
            for _ in 0..per_round {
                let before = if self.filter { run_delay() } else { None };
                let d = f().as_secs_f64() * scale;
                let after = if self.filter { run_delay() } else { None };
                all.push(d);
                match (before, after) {
                    (Some(b), Some(a)) if a.saturating_sub(b) > DISTURBED_NS => {}
                    _ => kept.push(d),
                }
            }
            r.samples += all.len();
            let use_all = kept.len() * 2 < all.len();
            if use_all {
                r.busy += 1;
            } else {
                r.dropped += all.len() - kept.len();
            }
            let v = if use_all { &mut all } else { &mut kept };
            v.sort_unstable_by(f64::total_cmp);
            r.p50.push(nearest_rank(v, 0.5));
            r.p99.push(nearest_rank(v, 0.99));
        }
        r
    }
}

// ---------------------------------------------------------------------------------------------
// Report.

struct Report {
    measurements: Vec<Value>,
    failures: Vec<String>,
}

impl Report {
    /// Records a latency measurement; `budget` is the p99 limit, when gated.
    fn latency(
        &mut self,
        id: &str,
        unit: &str,
        r: &Rounds,
        budget: Option<f64>,
        conditions: Value,
    ) {
        let p99 = r.p99();
        if let Some(b) = budget
            && p99 > b
        {
            self.failures
                .push(format!("{id}: p99 {p99:.3} {unit} > budget {b} {unit}"));
        }
        let r3 = |v: &[f64]| v.iter().copied().map(round3).collect::<Vec<_>>();
        self.measurements.push(json!({
            "id": id,
            "unit": unit,
            "better": "lower",
            "gated": budget.is_some(),
            "budget": budget.map(|b| json!({"p99": {"max": b}})),
            "p50": round3(r.p50()),
            "p99": round3(p99),
            "rounds": {"p50": r3(&r.p50), "p99": r3(&r.p99)},
            "samples": r.samples,
            "dropped": r.dropped,
            "busy_rounds": r.busy,
            "conditions": conditions,
        }));
    }

    /// Records a throughput measurement (higher is better); `min` is the floor, when gated.
    fn throughput(&mut self, id: &str, rounds: &[f64], min: Option<f64>, conditions: Value) {
        let v = median(rounds);
        if let Some(m) = min
            && v < m
        {
            self.failures
                .push(format!("{id}: {v:.1} MB/s < minimum {m} MB/s"));
        }
        self.measurements.push(json!({
            "id": id,
            "unit": "MB/s",
            "better": "higher",
            "gated": min.is_some(),
            "budget": min.map(|m| json!({"mbps": {"min": m}})),
            "mbps": round3(v),
            "rounds": {"mbps": rounds.iter().copied().map(round3).collect::<Vec<_>>()},
            "conditions": conditions,
        }));
    }
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn shown(b: Option<f64>, unit: &str) -> String {
    b.map_or_else(|| "-".to_string(), |b| format!("{b} {unit}"))
}

fn dropped(r: &Rounds) -> String {
    let mut s = format!("{}/{}", r.dropped, r.samples);
    if r.busy > 0 {
        let _ = write!(s, ", {} busy", r.busy);
    }
    s
}

fn machine() -> (String, usize) {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|c| {
            c.lines()
                .find(|l| l.starts_with("model name"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    (cpu, cpus)
}

fn budget_at(budget: &Value, path: &[&str]) -> Option<f64> {
    let mut v = budget;
    for p in path {
        v = v.get(p)?;
    }
    v.as_f64()
}

fn size_name(size: usize) -> &'static str {
    match size {
        s if s >= 4 << 20 => "4MB",
        s if s >= 1 << 20 => "1MB",
        _ => "100KB",
    }
}

fn redact_bench_body(size: usize, n: usize, set: &[String], hits: bool) -> Vec<u8> {
    if hits {
        fixtures::gen_body(size as u64 + n as u64, size, set).0
    } else {
        fixtures::gen_body(size as u64, size, &[]).0
    }
}

fn main() {
    let quick = std::env::var_os("SCRIM_LLM_BENCH_QUICK").is_some();
    let budget_path = std::env::var("SCRIM_LLM_BUDGET").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/benches/budget.json").to_string()
    });
    let budget: Value = serde_json::from_slice(&std::fs::read(&budget_path).unwrap()).unwrap();
    let rounds = std::env::var("SCRIM_PERF_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(if quick { 2 } else { 5 })
        .max(1);
    let filter = run_delay().is_some() && std::env::var_os("SCRIM_PERF_NO_FILTER").is_none();
    let sampler = Sampler { rounds, filter };
    let runner = std::env::var("SCRIM_PERF_RUNNER").unwrap_or_else(|_| "local".into());
    let (cpu, cpus) = machine();
    let mut report = Report {
        measurements: Vec::new(),
        failures: Vec::new(),
    };
    let mut rng = Rng(0x5c41_1d00_c0ff_ee01);
    let ms = 1e3;
    let us = 1e6;

    println!("# scrim latency gate\n");
    println!(
        "- machine: {cpu}, {cpus} logical CPUs, {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("- runner: {runner}");
    println!(
        "- crate: scrim-llm {}, profile: {}",
        env!("CARGO_PKG_VERSION"),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!("- budget: {budget_path}");
    println!(
        "- method: {rounds} rounds per measurement; each value is the median of the rounds' nearest-rank p50 or p99. {}",
        if filter {
            "Samples during which the measuring thread waited more than 50 µs for a CPU are dropped (column \"dropped\"); a round with more than half dropped keeps them all and counts as busy."
        } else {
            "No run-queue filter on this platform."
        }
    );
    println!();

    let sizes: &[usize] = if quick {
        &[100 << 10, 1 << 20]
    } else {
        &[100 << 10, 1 << 20, 4 << 20]
    };
    // Samples per round: `light` for the pass-through path (about 1 ms per MB), otherwise for
    // the production engine (tens of ms per MB).
    let per_round = |size: usize, light: bool| -> usize {
        let n = if light {
            ((400 << 20) / size / 5).clamp(30, 400)
        } else if size >= 4 << 20 {
            20
        } else if size >= 1 << 20 {
            60
        } else {
            200
        };
        if quick { n.min(30) } else { n }
    };

    // `SCRIM_PERF_ONLY=passthrough,overhead,request,core,chunk,metrics` runs some sections.
    let only = std::env::var("SCRIM_PERF_ONLY").ok();
    let want = |section: &str| {
        only.as_deref()
            .is_none_or(|o| o.split(',').any(|x| x.trim() == section))
    };
    let counts: &[usize] = &[10, 1000, 10_000];
    let cores: Vec<(usize, Vec<String>, Arc<rc::Snapshot>)> = counts
        .iter()
        .map(|&n| {
            let set = secrets(n);
            let c = core(&set, rc::ValueClass::Credential);
            (n, set, c)
        })
        .collect();
    let (set1k, core1k) = (&cores[1].1, &cores[1].2);
    // Display values resolve in responses; the stream fixtures carry their placeholders.
    let display = core(set1k, rc::ValueClass::Display);
    let phs: Vec<String> = set1k
        .iter()
        .take(200)
        .map(|s| {
            let mut o = Vec::new();
            display.redactor().redact(s.as_bytes(), &mut o).unwrap();
            String::from_utf8(o).unwrap()
        })
        .collect();
    let events = if quick { 5000 } else { 20000 };
    let chunks = stream_chunks(&phs, &mut rng, events);
    let stream_snap = Arc::new(engine(&display, 1000));
    let new_restorer = || {
        SseRestorer::new(
            Api::AnthropicMessages,
            stream_snap.clone(),
            &Limits::default(),
        )
    };
    let mut out = Vec::with_capacity(1 << 16);
    let limit = budget_at(&budget, &["chunk_p99_us"]);

    // ---- Proxy overhead, pass-through engine.
    if want("passthrough") {
        println!(
            "## Proxy overhead, pass-through engine\n\nWhat the LLM proxy adds on its own: codec plan, segmenting at verbatim spans, copying, guard hand-off.\n\n| body | p50 | p99 | budget (p99) | dropped |\n|---|---|---|---|---|"
        );
        let mut empty = Fixture::new(&[]);
        empty.fast_guard = true;
        let empty_snap = empty.snapshot();
        for &size in sizes {
            let name = size_name(size);
            let body = anthropic_body(&[], &mut rng, size);
            for _ in 0..3 {
                outgoing::prepare(&empty_snap, Api::AnthropicMessages, &body).unwrap();
            }
            let r = sampler.run(per_round(size, true), ms, || {
                let t = Instant::now();
                let o = outgoing::prepare(&empty_snap, Api::AnthropicMessages, &body).unwrap();
                let d = t.elapsed();
                std::hint::black_box(o);
                d
            });
            let b = budget_at(&budget, &["proxy_overhead_p99_ms", name]);
            println!(
                "| {name} ({} B) | {:.3} ms | {:.3} ms | {} | {} |",
                body.len(),
                r.p50(),
                r.p99(),
                shown(b, "ms"),
                dropped(&r)
            );
            report.latency(
                &format!("proxy_overhead/passthrough/{name}"),
                "ms",
                &r,
                b,
                json!({"body_bytes": body.len(), "secrets": 0, "body": "anthropic-claude-code"}),
            );
        }
    }

    // ---- Proxy overhead with the production engine.
    if want("overhead") {
        println!(
            "\n## Proxy overhead, production engine\n\nThe same with the production engine wired in (1,000 secrets, one hit per ~4 KB tool result), less the time spent inside its redactor and guard.\n\n| body | p50 | p99 | budget (p99) | dropped |\n|---|---|---|---|---|"
        );
        let (eng1k_timed, spent) = timed(&engine(core1k, 1000));
        for &size in sizes {
            let name = size_name(size);
            let body = anthropic_body(set1k, &mut rng, size);
            for _ in 0..3 {
                outgoing::prepare(&eng1k_timed, Api::AnthropicMessages, &body).unwrap();
            }
            let r = sampler.run(per_round(size, false), ms, || {
                spent.store(0, Ordering::Relaxed);
                let t = Instant::now();
                let o = outgoing::prepare(&eng1k_timed, Api::AnthropicMessages, &body).unwrap();
                let d = t.elapsed();
                std::hint::black_box(o);
                d.saturating_sub(Duration::from_nanos(spent.load(Ordering::Relaxed)))
            });
            let b = budget_at(&budget, &["proxy_overhead_p99_ms", name]);
            println!(
                "| {name} ({} B) | {:.3} ms | {:.3} ms | {} | {} |",
                body.len(),
                r.p50(),
                r.p99(),
                shown(b, "ms"),
                dropped(&r)
            );
            report.latency(
            &format!("proxy_overhead/engine/{name}"),
            "ms",
            &r,
            b,
            json!({"body_bytes": body.len(), "secrets": 1000, "hits": true, "body": "anthropic-claude-code"}),
        );
        }
    }

    // ---- Added request latency through the proxy, production engine.
    if want("request") {
        println!(
            "\n## Added request latency, production engine\n\n`outgoing::prepare` with the `scrim-redact` redactor and guard, on the redaction benchmark's request bodies (prose, code, logs, env files, base64 blobs; one hit per 4 KiB).\n\n| secrets | body | hits | p50 | p99 | budget (p99) | dropped |\n|---|---|---|---|---|---|---|"
        );
        for (n, set, c) in &cores {
            let (n, set) = (*n, set.as_slice());
            let snap = engine(c, n);
            for &size in sizes {
                let name = size_name(size);
                for hits in [false, true] {
                    let body = redact_bench_body(size, n, set, hits);
                    for _ in 0..2 {
                        outgoing::prepare(&snap, Api::AnthropicMessages, &body).unwrap();
                    }
                    let r = sampler.run(per_round(size, false), ms, || {
                        let t = Instant::now();
                        let o = outgoing::prepare(&snap, Api::AnthropicMessages, &body).unwrap();
                        let d = t.elapsed();
                        std::hint::black_box(o);
                        d
                    });
                    let b = budget_at(&budget, &["engine", "request_p99_ms", name, &n.to_string()]);
                    println!(
                        "| {n} | {name} | {hits} | {:.3} ms | {:.3} ms | {} | {} |",
                        r.p50(),
                        r.p99(),
                        shown(b, "ms"),
                        dropped(&r)
                    );
                    report.latency(
                    &format!(
                        "request/{n}/{name}/{}",
                        if hits { "hits" } else { "clean" }
                    ),
                    "ms",
                    &r,
                    b,
                    json!({"body_bytes": body.len(), "secrets": n, "hits": hits, "body": "redact-bench", "engine": format!("{:?}", c.report().engine)}),
                );
                }
            }
        }
    }

    // ---- The redaction core on its own.
    if want("core") {
        println!(
            "\n## Redaction core (`scrim-redact`)\n\n`Snapshot::protect` per 1 MB request (redaction and guard, both split over threads for large bodies, as the tool proxy runs them), `Redactor::redact` throughput on one core, and `BlockRestorer` per streamed text chunk.\n\n| measurement | secrets | p50 | p99 | budget | dropped |\n|---|---|---|---|---|---|"
        );
        for (n, set, c) in &cores {
            let size = 1 << 20;
            for hits in [false, true] {
                let body = redact_bench_body(size, *n, set, hits);
                let mut ws = rc::Workspace::new();
                for _ in 0..2 {
                    c.protect(&body, &mut ws).unwrap();
                }
                let r = sampler.run(per_round(size, false), ms, || {
                    let t = Instant::now();
                    let len = c.protect(&body, &mut ws).unwrap().bytes.len();
                    let d = t.elapsed();
                    std::hint::black_box(len);
                    d
                });
                let b = budget_at(&budget, &["core", "protect_p99_ms", "1MB", &n.to_string()]);
                let h = if hits { "hits" } else { "clean" };
                println!(
                    "| protect 1MB {h} | {n} | {:.3} ms | {:.3} ms | {} | {} |",
                    r.p50(),
                    r.p99(),
                    shown(b, "ms"),
                    dropped(&r)
                );
                report.latency(
                &format!("core/protect/{n}/1MB/{h}"),
                "ms",
                &r,
                b,
                json!({"body_bytes": body.len(), "secrets": n, "hits": hits, "body": "redact-bench", "parallel_threads": rc::Config::default().parallel_threads}),
            );
            }
            // Throughput per core: the body over the median single-thread redaction time.
            let body = redact_bench_body(size, *n, set, true);
            let mut out = Vec::with_capacity(body.len() * 2);
            let r = sampler.run(per_round(size, true).min(100), 1.0, || {
                let t = Instant::now();
                c.redactor().redact(&body, &mut out).unwrap();
                t.elapsed()
            });
            let mbps: Vec<f64> = r.p50.iter().map(|s| body.len() as f64 / 1e6 / s).collect();
            let min = budget_at(&budget, &["core", "redact_min_mbps", "1MB", &n.to_string()]);
            println!(
                "| redact throughput 1MB hits, one core | {n} | {:.0} MB/s | - | {} | {} |",
                median(&mbps),
                min.map_or_else(|| "-".to_string(), |m| format!(">= {m} MB/s")),
                dropped(&r)
            );
            report.throughput(
            &format!("core/redact_throughput/{n}/1MB"),
            &mbps,
            min,
            json!({"body_bytes": body.len(), "secrets": n, "hits": true, "body": "redact-bench", "threads": 1}),
        );
        }

        // Restore per chunk in the core: text deltas with a placeholder every ~600 bytes.
        let text = fixtures::gen_stream_text(5, 400_000, &phs, 600);
        let mut text_chunks = Vec::new();
        let mut at = 0;
        for n in fixtures::gen_chunks(6, text.len()) {
            if at >= text.len() {
                break;
            }
            let mut end = (at + n).min(text.len());
            while !text.is_char_boundary(end) {
                end += 1;
            }
            text_chunks.push(&text[at..end]);
            at = end;
        }
        let mut restored = String::with_capacity(text.len() * 2);
        let mut br = rc::BlockRestorer::new();
        let mut i = 0;
        let r = sampler.run(text_chunks.len(), us, || {
            if i == text_chunks.len() {
                i = 0;
                restored.clear();
                br = rc::BlockRestorer::new();
            }
            let t = Instant::now();
            br.push(
                display.resolver(),
                &rc::RestoreDisplay,
                text_chunks[i],
                &mut restored,
            );
            let d = t.elapsed();
            i += 1;
            d
        });
        let b = budget_at(&budget, &["chunk_p99_us"]);
        println!(
            "| restore per chunk | 1000 | {:.2} µs | {:.2} µs | {} | {} |",
            r.p50(),
            r.p99(),
            shown(b, "µs"),
            dropped(&r)
        );
        report.latency(
        "core/restore_chunk",
        "us",
        &r,
        b,
        json!({"chunks": text_chunks.len(), "text_bytes": text.len(), "secrets": 1000, "placeholder_every": 600}),
    );
    }

    // ---- Streamed chunks through the proxy, production placeholders.
    if want("chunk") {
        println!("\n## Streamed chunks, production engine\n");
        let mut bytes = 0usize;
        let mut sse = new_restorer().unwrap();
        let mut i = 0;
        let r = sampler.run(chunks.len(), us, || {
            if i == chunks.len() {
                i = 0;
                sse.finish(&mut out);
                sse = new_restorer().unwrap();
            }
            out.clear();
            let t = Instant::now();
            sse.push(&chunks[i], &mut out);
            let d = t.elapsed();
            bytes += out.len();
            i += 1;
            d
        });
        println!(
            "| events | chunks | output bytes | p50 per chunk | p99 per chunk | budget (p99) | dropped |\n|---|---|---|---|---|---|---|"
        );
        println!(
            "| {events} | {} | {bytes} | {:.2} µs | {:.2} µs | {} | {} |",
            chunks.len(),
            r.p50(),
            r.p99(),
            shown(limit, "µs"),
            dropped(&r)
        );
        report.latency(
            "chunk/engine",
            "us",
            &r,
            limit,
            json!({"events": events, "chunks": chunks.len(), "secrets": 1000}),
        );
    }

    // ---- Metrics on and off.
    if want("metrics") {
        println!(
            "\n## Metrics overhead (production engine, 1,000 secrets, hits, metrics off vs on)\n\n| path | off p50 | off p99 | on p50 | on p99 | p50 delta | budget (p99) |\n|---|---|---|---|---|---|---|"
        );
        let metrics = LlmMetrics::default();
        let snap1k = engine(core1k, 1000);
        {
            let size = 1 << 20;
            let body = redact_bench_body(size, 1000, set1k, true);
            let n = per_round(size, false);
            let off = sampler.run(n, ms, || {
                let t = Instant::now();
                let o = outgoing::prepare(&snap1k, Api::AnthropicMessages, &body).unwrap();
                let d = t.elapsed();
                std::hint::black_box(o);
                d
            });
            let on = sampler.run(n, ms, || {
                let t = Instant::now();
                let rm = metrics.route("anthropic", "anthropic");
                rm.body_bytes(body.len());
                let began = Instant::now();
                let o =
                    outgoing::prepare_timed(&snap1k, Api::AnthropicMessages, &body, true).unwrap();
                rm.stage(Stage::Redaction, o.stages.redaction);
                rm.stage(Stage::Guard, o.stages.guard);
                rm.stage(Stage::Total, began.elapsed());
                rm.forwarded(o.report.replacements, o.report.detectors.len(), false);
                let d = t.elapsed();
                std::hint::black_box(o);
                d
            });
            let b = budget_at(&budget, &["engine", "request_p99_ms", "1MB", "1000"]);
            println!(
                "| request 1MB | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:+.1} µs | {} |",
                off.p50(),
                off.p99(),
                on.p50(),
                on.p99(),
                (on.p50() - off.p50()) * 1e3,
                shown(b, "ms"),
            );
            report.latency(
            "request/1000/1MB/hits/metrics",
            "ms",
            &on,
            b,
            json!({"body_bytes": body.len(), "secrets": 1000, "hits": true, "body": "redact-bench", "metrics": true}),
        );
        }
        {
            let rm = metrics.route("anthropic", "anthropic");
            let mut sse = new_restorer().unwrap();
            let mut i = 0;
            let mut step = |metered: bool| {
                if i == chunks.len() {
                    i = 0;
                    sse.finish(&mut out);
                    sse = new_restorer().unwrap();
                }
                out.clear();
                let t = Instant::now();
                if metered {
                    let m = Instant::now();
                    sse.push(&chunks[i], &mut out);
                    rm.chunk(m.elapsed());
                } else {
                    sse.push(&chunks[i], &mut out);
                }
                let d = t.elapsed();
                i += 1;
                d
            };
            let off = sampler.run(chunks.len(), us, || step(false));
            let on = sampler.run(chunks.len(), us, || step(true));
            println!(
                "| chunk | {:.2} µs | {:.2} µs | {:.2} µs | {:.2} µs | {:+.3} µs | {} |",
                off.p50(),
                off.p99(),
                on.p50(),
                on.p99(),
                on.p50() - off.p50(),
                shown(limit, "µs"),
            );
            report.latency(
                "chunk/engine/metrics",
                "us",
                &on,
                limit,
                json!({"events": events, "chunks": chunks.len(), "secrets": 1000, "metrics": true}),
            );
        }
    }

    println!();
    let pass = report.failures.is_empty();
    if let Ok(path) = std::env::var("SCRIM_PERF_JSON") {
        let doc = json!({
            "schema": 1,
            "gate": "scrim-llm latency_gate",
            "version": env!("CARGO_PKG_VERSION"),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "runner": runner,
            "machine": {"cpu": cpu, "logical_cpus": cpus, "os": std::env::consts::OS, "arch": std::env::consts::ARCH},
            "method": {"rounds": rounds, "statistic": "median over rounds of nearest-rank p50 and p99", "run_queue_filter": filter, "quick": quick},
            "budget_file": budget_path,
            "pass": pass,
            "failures": report.failures,
            "measurements": report.measurements,
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        println!("Results written to {path}.\n");
    }
    if pass {
        println!("All budgets met.");
    } else {
        for f in &report.failures {
            println!("BUDGET EXCEEDED: {f}");
        }
        std::process::exit(1);
    }
}
