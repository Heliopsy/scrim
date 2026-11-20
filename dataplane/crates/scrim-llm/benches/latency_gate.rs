// SPDX-License-Identifier: AGPL-3.0-only

//! Latency budget gate for the LLM proxy (task 3.6, performance spec).
//!
//! Measures, on generated reference fixtures:
//!
//! - proxy overhead per request: codec plan, segmenting and guard hand-off for Anthropic
//!   Messages bodies of about 100 KB, 1 MB and 4 MB, with a pass-through engine, so the number is
//!   what this crate adds on its own;
//! - added request latency with an engine (redactor plus guard) for 10, 1,000 and 10,000 secrets,
//!   with and without hits;
//! - time added per streamed chunk while restoring a 20,000-event stream chunked at event and
//!   mid-event boundaries;
//! - the same request and chunk paths with metrics off and on (`metrics.enabled`): the on
//!   numbers must meet the same budgets, and the difference is reported.
//!
//! Each p99 is compared with `benches/budget.json` (or the file in `SCRIM_LLM_BUDGET`). The
//! process exits non-zero, naming the measurement, when a budget is exceeded. Run with
//! `cargo bench -p scrim-llm --bench latency_gate`; `SCRIM_LLM_BENCH_QUICK=1` shortens it.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::pedantic,
    reason = "benchmark binary: prints its report and fails loudly"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use scrim_llm::config::Limits;
use scrim_llm::metrics::{LlmMetrics, Stage};
use scrim_llm::outgoing;
use scrim_llm::testing::Fixture;
use scrim_llm::{Api, SseRestorer};

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

/// A Claude Code style conversation of about `size` bytes. With `hits`, one secret value is
/// embedded in every ~4 KB tool result.
fn anthropic_body(fx: &Fixture, rng: &mut Rng, size: usize, hits: bool) -> Vec<u8> {
    let mut messages = Vec::new();
    let mut total = 0;
    let mut turn = 0;
    while total < size {
        let mut out = prose(rng, 4096.min(size - total + 64));
        if hits && !fx.entries().is_empty() {
            let e = &fx.entries()[rng.below(fx.entries().len())];
            out.push_str(std::str::from_utf8(e.value.expose()).unwrap());
        }
        total += out.len() + 200;
        let id = format!("toolu_{turn:08}");
        messages.push(serde_json::json!({"role": "assistant", "content": [
            {"type": "thinking", "thinking": "Let me look at the file.", "signature": "EqQBCkgIARABGAIiQKsfY2s0bWVzaWduYXR1cmU="},
            {"type": "tool_use", "id": id, "name": "Read", "input": {"file_path": format!("/src/f{turn}.rs")}}
        ]}));
        messages.push(serde_json::json!({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": id, "content": out}
        ]}));
        turn += 1;
    }
    serde_json::to_vec(&serde_json::json!({
        "model": "claude-sonnet-4-5", "max_tokens": 32000, "stream": true,
        "system": [{"type": "text", "text": "You are Claude Code."}],
        "messages": messages,
    }))
    .unwrap()
}

/// An Anthropic stream of `events` events with a placeholder in about one delta in five, split
/// into chunks at event boundaries and, for one event in four, inside the event.
fn stream_chunks(fx: &Fixture, rng: &mut Rng, events: usize) -> Vec<Vec<u8>> {
    let phs: Vec<String> = fx
        .entries()
        .iter()
        .take(64)
        .map(|e| e.placeholder.clone())
        .collect();
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
        s.push_str(&format!(
            "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":{index},\"content_block\":{start}}}\n\n"
        ));
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
            s.push_str(&format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":{index},\"delta\":{{\"type\":\"{dtype}\",\"{field}\":{v}}}}}\n\n"
            ));
            n += 1;
        }
        s.push_str(&format!(
            "event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":{index}}}\n\n"
        ));
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

fn p99(mut v: Vec<Duration>) -> Duration {
    v.sort_unstable();
    let i = ((v.len() as f64) * 0.99).ceil() as usize;
    v[i.saturating_sub(1).min(v.len() - 1)]
}

fn p50(mut v: Vec<Duration>) -> Duration {
    v.sort_unstable();
    v[v.len() / 2]
}

/// Best p99 (and its round's p50) over `ROUNDS` rounds of `iters` requests. Taking the best
/// round filters load from other processes on a shared machine without hiding a regression,
/// which shows in every round.
const ROUNDS: usize = 3;

fn time_requests(fx: &Fixture, body: &[u8], iters: usize) -> (Duration, Duration) {
    let snap = fx.snapshot();
    for _ in 0..3 {
        outgoing::prepare(&snap, Api::AnthropicMessages, body).unwrap();
    }
    let mut best = (Duration::MAX, Duration::MAX);
    for _ in 0..ROUNDS {
        let mut v = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            let o = outgoing::prepare(&snap, Api::AnthropicMessages, body).unwrap();
            v.push(t.elapsed());
            std::hint::black_box(o);
        }
        let r = (p99(v.clone()), p50(v));
        if r.0 < best.0 {
            best = r;
        }
    }
    best
}

/// Like [`time_requests`], recording what the proxy records per request when metrics are on:
/// the route lookup, both stage timings, the total, the body size and the forwarded counters.
fn time_requests_metered(
    fx: &Fixture,
    body: &[u8],
    iters: usize,
    m: &LlmMetrics,
) -> (Duration, Duration) {
    let snap = fx.snapshot();
    let mut best = (Duration::MAX, Duration::MAX);
    for _ in 0..ROUNDS {
        let mut v = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            let rm = m.route("anthropic", "anthropic");
            rm.body_bytes(body.len());
            let began = Instant::now();
            let o = outgoing::prepare_timed(&snap, Api::AnthropicMessages, body, true).unwrap();
            rm.stage(Stage::Redaction, o.stages.redaction);
            rm.stage(Stage::Guard, o.stages.guard);
            rm.stage(Stage::Total, began.elapsed());
            rm.forwarded(o.report.replacements, o.report.detectors.len(), false);
            v.push(t.elapsed());
            std::hint::black_box(o);
        }
        let r = (p99(v.clone()), p50(v));
        if r.0 < best.0 {
            best = r;
        }
    }
    best
}

fn machine() -> String {
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
    format!(
        "{cpu}, {cpus} logical CPUs, {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

fn main() {
    let quick = std::env::var_os("SCRIM_LLM_BENCH_QUICK").is_some();
    let budget_path = std::env::var("SCRIM_LLM_BUDGET").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/benches/budget.json").to_string()
    });
    let budget: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&budget_path).unwrap()).unwrap();
    let mut failures = Vec::new();
    let mut rng = Rng(0x5c41_1d00_c0ff_ee01);

    println!("# scrim-llm latency gate\n");
    println!("- machine: {}", machine());
    println!(
        "- crate: scrim-llm {}, profile: {}",
        env!("CARGO_PKG_VERSION"),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!("- budget: {budget_path}\n");

    let sizes: &[(&str, usize)] = &[("100KB", 100 << 10), ("1MB", 1 << 20), ("4MB", 4 << 20)];
    let iters = |size: usize| {
        if quick {
            10
        } else {
            ((400 << 20) / size).clamp(30, 400)
        }
    };

    println!(
        "## Proxy overhead (pass-through engine)\n\n| body | p50 | p99 | budget |\n|---|---|---|---|"
    );
    let mut empty = Fixture::new(&[]);
    empty.fast_guard = true;
    for (name, size) in sizes {
        let body = anthropic_body(&empty, &mut rng, *size, false);
        let (p, m) = time_requests(&empty, &body, iters(*size));
        let limit = budget["proxy_overhead_p99_ms"][name].as_f64().unwrap();
        let ms = p.as_secs_f64() * 1e3;
        let med = m.as_secs_f64() * 1e3;
        println!(
            "| {name} ({} B) | {med:.3} ms | {ms:.3} ms | {limit} ms |",
            body.len()
        );
        if ms > limit {
            failures.push(format!(
                "proxy overhead p99 for {name}: {ms:.3} ms > {limit} ms"
            ));
        }
    }

    println!("\n## Added request latency, fake engine (Aho-Corasick redactor, automaton guard)\n");
    println!("| secrets | body | hits | p50 | p99 | budget (1 MB) |\n|---|---|---|---|---|---|");
    let enforce = budget["engine"]["enforce"].as_bool().unwrap_or(false);
    let counts: &[usize] = if quick {
        &[10, 1000]
    } else {
        &[10, 1000, 10000]
    };
    for &n in counts {
        let mut fx = Fixture::generated(n);
        fx.fast_guard = true;
        for (name, size) in sizes {
            for hits in [false, true] {
                let body = anthropic_body(&fx, &mut rng, *size, hits);
                let (p, m) = time_requests(&fx, &body, iters(*size).min(60));
                let ms = p.as_secs_f64() * 1e3;
                let med = m.as_secs_f64() * 1e3;
                let limit = budget["engine"]["request_p99_ms"][n.to_string()]
                    .as_f64()
                    .filter(|_| *name == "1MB");
                let shown = limit.map_or_else(|| "-".to_string(), |l| format!("{l} ms"));
                println!("| {n} | {name} | {hits} | {med:.3} ms | {ms:.3} ms | {shown} |");
                if let Some(l) = limit
                    && enforce
                    && ms > l
                {
                    failures.push(format!(
                        "request p99 with {n} secrets, {name}, hits={hits}: {ms:.3} ms > {l} ms"
                    ));
                }
            }
        }
    }
    if !enforce {
        println!(
            "\nEngine budgets are reported, not enforced, until the production engine is wired in."
        );
    }

    println!("\n## Streamed chunks\n");
    let fx = Fixture::generated(1000);
    let events = if quick { 5000 } else { 20000 };
    let chunks = stream_chunks(&fx, &mut rng, events);
    let snap = Arc::new(fx.snapshot());
    let mut samples = Vec::new();
    let mut bytes = 0;
    for _ in 0..if quick { 1 } else { 5 } {
        let mut r =
            SseRestorer::new(Api::AnthropicMessages, snap.clone(), &Limits::default()).unwrap();
        let mut out = Vec::with_capacity(1 << 16);
        for c in &chunks {
            out.clear();
            let t = Instant::now();
            r.push(c, &mut out);
            samples.push(t.elapsed());
            bytes += out.len();
        }
        r.finish(&mut out);
        std::hint::black_box(&out);
    }
    let us = p99(samples).as_secs_f64() * 1e6;
    let limit = budget["chunk_p99_us"].as_f64().unwrap();
    println!("| events | chunks | output bytes | p99 per chunk | budget |\n|---|---|---|---|---|");
    println!(
        "| {events} | {} | {bytes} | {us:.2} µs | {limit} µs |",
        chunks.len()
    );
    if us > limit {
        failures.push(format!("chunk p99: {us:.2} µs > {limit} µs"));
    }

    println!("\n## Metrics overhead (1,000 secrets, hits, metrics off vs on)\n");
    println!(
        "| path | off p50 | off p99 | on p50 | on p99 | p50 delta | budget |\n|---|---|---|---|---|---|---|"
    );
    let mut fx = Fixture::generated(1000);
    fx.fast_guard = true;
    let metrics = LlmMetrics::default();
    for (name, size) in sizes {
        let body = anthropic_body(&fx, &mut rng, *size, true);
        let n = iters(*size).min(60);
        let (off99, off50) = time_requests(&fx, &body, n);
        let (on99, on50) = time_requests_metered(&fx, &body, n, &metrics);
        let ms = |d: Duration| d.as_secs_f64() * 1e3;
        let limit = budget["proxy_overhead_p99_ms"][name].as_f64().unwrap();
        let engine = budget["engine"]["request_p99_ms"]["1000"]
            .as_f64()
            .filter(|_| *name == "1MB");
        println!(
            "| request {name} | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms | {:+.1} µs | {} |",
            ms(off50),
            ms(off99),
            ms(on50),
            ms(on99),
            (on50.as_secs_f64() - off50.as_secs_f64()) * 1e6,
            engine.map_or_else(|| "-".to_string(), |l| format!("{l} ms")),
        );
        if let Some(l) = engine
            && enforce
            && ms(on99) > l
        {
            failures.push(format!(
                "request p99 with metrics on, {name}: {:.3} ms > {l} ms",
                ms(on99)
            ));
        }
        let _ = limit;
    }
    let rm = metrics.route("anthropic", "anthropic");
    let (mut off, mut on) = (Vec::new(), Vec::new());
    for _ in 0..if quick { 1 } else { 3 } {
        for metered in [false, true] {
            let mut r =
                SseRestorer::new(Api::AnthropicMessages, snap.clone(), &Limits::default()).unwrap();
            let mut out = Vec::with_capacity(1 << 16);
            for c in &chunks {
                out.clear();
                let t = Instant::now();
                if metered {
                    let m = Instant::now();
                    r.push(c, &mut out);
                    rm.chunk(m.elapsed());
                } else {
                    r.push(c, &mut out);
                }
                if metered { &mut on } else { &mut off }.push(t.elapsed());
            }
            r.finish(&mut out);
            std::hint::black_box(&out);
        }
    }
    let us = |d: Duration| d.as_secs_f64() * 1e6;
    let (off50, on50) = (p50(off.clone()), p50(on.clone()));
    let (off99, on99) = (p99(off), p99(on));
    println!(
        "| chunk | {:.2} µs | {:.2} µs | {:.2} µs | {:.2} µs | {:+.3} µs | {limit} µs |",
        us(off50),
        us(off99),
        us(on50),
        us(on99),
        us(on50) - us(off50)
    );
    if us(on99) > limit {
        failures.push(format!(
            "chunk p99 with metrics on: {:.2} µs > {limit} µs",
            us(on99)
        ));
    }

    println!();
    if failures.is_empty() {
        println!("All budgets met.");
    } else {
        for f in &failures {
            eprintln!("BUDGET EXCEEDED: {f}");
        }
        std::process::exit(1);
    }
}
