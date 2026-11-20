//! rbcli: run the Rust implementation over fixtures (same flags as the Go CLI).
use redactbench::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

/// Counting allocator: live bytes and allocation count (for build memory and allocs/op).
struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Relaxed);
        COUNT.fetch_add(1, Relaxed);
        BYTES.fetch_add(l.size(), Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n.wrapping_sub(l.size()), Relaxed);
        COUNT.fetch_add(1, Relaxed);
        BYTES.fetch_add(n, Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static A: Counting = Counting;

fn peak_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).expect("usage: rbcli patterns|redact|restore ...").clone();
    let mut flags = std::collections::HashMap::new();
    let mut i = 2;
    while i + 1 < args.len() {
        flags.insert(args[i].trim_start_matches('-').to_string(), args[i + 1].clone());
        i += 2;
    }
    let get = |k: &str| flags.get(k).cloned().unwrap_or_default();
    let (secrets, key) = load_secrets(&get("secrets"));
    match cmd.as_str() {
        "patterns" => {
            let (pats, owner) = patterns(&secrets);
            let mut w = std::io::BufWriter::new(std::io::stdout());
            for (p, o) in pats.iter().zip(owner) {
                writeln!(w, "{}\t{}", o, hex::encode(p)).unwrap();
            }
        }
        "redact" => {
            let engine = flags.get("engine").cloned().unwrap_or_else(|| "ac-auto".into());
            let r = Redactor::new(&secrets, &key, &engine);
            for f in get("in").split(',') {
                let body = std::fs::read(f).expect(f);
                let mut buf = Vec::new();
                let (o, n) = r.redact(&body, &mut buf);
                let name = std::path::Path::new(f).file_name().unwrap().to_str().unwrap();
                let base = format!("{}/{}", get("out"), name);
                std::fs::write(&base, o).unwrap();
                let meta = format!(
                    "{{\"matches\":{},\"remaining\":{},\"in_bytes\":{},\"out_bytes\":{}}}\n",
                    n,
                    r.count(o),
                    body.len(),
                    o.len()
                );
                std::fs::write(format!("{}.meta.json", base.trim_end_matches(".json")), meta).unwrap();
            }
        }
        "restore" => {
            let t = std::sync::Arc::new(Table::new(&secrets, &key));
            let data = std::fs::read(get("in")).unwrap();
            let sizes = load_chunks(&get("chunks"));
            let mut r = Restorer::new(t.clone());
            let mut out = Vec::new();
            for c in split_chunks(&data, &sizes) {
                r.feed(&mut out, c);
            }
            r.finish(&mut out);
            std::fs::write(get("out"), &out).unwrap();
            println!("{{\"in_bytes\":{},\"out_bytes\":{},\"chunks\":{}}}", data.len(), out.len(), sizes.len());
        }
        "buildmem" => {
            let engine = flags.get("engine").cloned().unwrap_or_else(|| "ac-auto".into());
            let before = LIVE.load(Relaxed);
            let t0 = Instant::now();
            let r = Redactor::new(&secrets, &key, &engine);
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            let live = LIVE.load(Relaxed) - before;
            println!(
                "{{\"lang\":\"rust\",\"engine\":\"{}\",\"secrets\":{},\"build_ms\":{:.1},\"retained_bytes\":{},\"automaton_bytes\":{},\"ac_kind\":\"{:?}\",\"peak_rss_kb\":{}}}",
                engine, secrets.len(), ms, live, r.ac.memory_usage(), r.ac.kind(), peak_rss_kb()
            );
        }
        "allocs" => {
            // allocations for one redact per body (after warm-up) and one restore per stream
            let engine = flags.get("engine").cloned().unwrap_or_else(|| "ac-auto".into());
            let r = Redactor::new(&secrets, &key, &engine);
            let mut buf = Vec::new();
            for f in get("in").split(',').filter(|x| !x.is_empty()) {
                let body = std::fs::read(f).unwrap();
                r.redact(&body, &mut buf);
                let (c0, b0) = (COUNT.load(Relaxed), BYTES.load(Relaxed));
                let n = r.redact(&body, &mut buf).1;
                println!("{{\"op\":\"redact\",\"file\":\"{}\",\"matches\":{},\"allocs\":{},\"bytes\":{}}}",
                    f.rsplit('/').next().unwrap(), n, COUNT.load(Relaxed) - c0, BYTES.load(Relaxed) - b0);
            }
            let t = std::sync::Arc::new(Table::new(&secrets, &key));
            for st in get("streams").split(',').filter(|x| !x.is_empty()) {
                let data = std::fs::read(format!("{st}.sse")).unwrap();
                let sizes = load_chunks(&format!("{st}.chunks"));
                let chunks = split_chunks(&data, &sizes);
                let mut rs = Restorer::new(t.clone());
                let mut out = Vec::with_capacity(64 << 10);
                let run = |rs: &mut Restorer, out: &mut Vec<u8>| {
                    rs.reset();
                    for c in &chunks { out.clear(); rs.feed(out, c); }
                    out.clear();
                    rs.finish(out);
                };
                run(&mut rs, &mut out);
                let (c0, b0) = (COUNT.load(Relaxed), BYTES.load(Relaxed));
                run(&mut rs, &mut out);
                println!("{{\"op\":\"restore\",\"file\":\"{}\",\"allocs\":{},\"bytes\":{}}}",
                    st.rsplit('/').next().unwrap(), COUNT.load(Relaxed) - c0, BYTES.load(Relaxed) - b0);
            }
        }
        c => panic!("unknown command {c}"),
    }
}
