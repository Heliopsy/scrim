use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use redactbench::*;
use std::time::Duration;

fn fixtures() -> String {
    std::env::var("RB_FIXTURES").unwrap_or_else(|_| "../fixtures/data".into())
}

fn engines_for(n: usize) -> Vec<String> {
    let e: Vec<String> = std::env::var("RB_RUST_ENGINES")
        .unwrap_or_else(|_| "ac-auto ac-dfa".into())
        .split_whitespace()
        .map(String::from)
        .collect();
    if n >= 10000 { e.into_iter().filter(|x| x != "ac-dfa").collect() } else { e }
}

fn bench_redact(c: &mut Criterion) {
    let d = fixtures();
    let mut g = c.benchmark_group("redact");
    g.warm_up_time(Duration::from_millis(500)).measurement_time(Duration::from_secs(2)).sample_size(20);
    for n in [10usize, 1000, 10000] {
        let (secrets, key) = load_secrets(&format!("{d}/secrets-{n}.json"));
        for eng in engines_for(n) {
            let r = Redactor::new(&secrets, &key, &eng);
            for size in ["100k", "1m", "4m"] {
                for kind in ["hits", "clean"] {
                    let name = if kind == "hits" { format!("body-{size}-s{n}.json") } else { format!("body-{size}-clean.json") };
                    let body = std::fs::read(format!("{d}/{name}")).unwrap();
                    let mut buf = Vec::with_capacity(body.len() * 2);
                    g.throughput(Throughput::Bytes(body.len() as u64));
                    g.bench_function(BenchmarkId::from_parameter(format!("engine={eng}/set={n}/size={size}/{kind}")), |b| {
                        b.iter(|| {
                            let (o, k) = r.redact(&body, &mut buf);
                            std::hint::black_box((o.len(), k));
                        })
                    });
                }
            }
        }
    }
    g.finish();
}

fn bench_restore(c: &mut Criterion) {
    let d = fixtures();
    let (secrets, key) = load_secrets(&format!("{d}/secrets-1000.json"));
    let t = std::sync::Arc::new(Table::new(&secrets, &key));
    let mut g = c.benchmark_group("restore");
    g.warm_up_time(Duration::from_millis(500)).measurement_time(Duration::from_secs(3)).sample_size(20);
    for st in ["2k", "20k"] {
        let data = std::fs::read(format!("{d}/stream-{st}.sse")).unwrap();
        let sizes = load_chunks(&format!("{d}/stream-{st}.chunks"));
        let chunks = split_chunks(&data, &sizes);
        let mut r = Restorer::new(t.clone());
        let mut out = Vec::with_capacity(64 << 10);
        g.throughput(Throughput::Bytes(data.len() as u64));
        g.bench_function(BenchmarkId::from_parameter(format!("stream={st}/chunks={}", chunks.len())), |b| {
            b.iter(|| {
                r.reset();
                for ch in &chunks {
                    out.clear(); // a proxy writes each output chunk and reuses the buffer
                    r.feed(&mut out, ch);
                }
                out.clear();
                r.finish(&mut out);
                std::hint::black_box(out.len());
            })
        });
    }
    g.finish();
}

fn bench_build(c: &mut Criterion) {
    let d = fixtures();
    let mut g = c.benchmark_group("build");
    g.warm_up_time(Duration::from_millis(100)).measurement_time(Duration::from_secs(3)).sample_size(10);
    for n in [10usize, 1000, 10000] {
        let (secrets, key) = load_secrets(&format!("{d}/secrets-{n}.json"));
        for eng in engines_for(n) {
            g.bench_function(BenchmarkId::from_parameter(format!("engine={eng}/set={n}")), |b| {
                b.iter(|| std::hint::black_box(Redactor::new(&secrets, &key, &eng)))
            });
        }
    }
    g.finish();
}

criterion_group!(benches, bench_redact, bench_restore, bench_build);
criterion_main!(benches);
