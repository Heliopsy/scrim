// SPDX-License-Identifier: AGPL-3.0-only

//! What the `scan` binary policy adds to a request with a large attachment.
//!
//! Builds Anthropic Messages bodies carrying one image or PDF part of 1, 5 and 20 MiB, runs
//! `outgoing::prepare` over each with the production engine (`scrim-redact`, 1,000 values) under
//! `BinaryPolicy::Pass` and `BinaryPolicy::Scan`, and prints p50 and p99 of both and the
//! difference. Fixtures: a PNG of noise pixels with a text chunk (photos and screenshots compress
//! poorly, and the pixels are not inflated), a JPEG with EXIF and XMP segments and noise entropy
//! data, and a PDF of Flate-compressed text pages (every stream is inflated and its strings
//! extracted, the expensive case). A part the scan refuses for its bounds is timed until the
//! refusal and marked. Report only, no budget: run with
//! `cargo bench -p scrim-llm --features test-util,redact --bench binary_scan`.

#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::pedantic,
    reason = "benchmark binary: prints its report and fails loudly"
)]

use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use scrim_llm::core::CoreEngine;
use scrim_llm::outgoing;
use scrim_llm::{Api, BinaryPolicy, KeepAll, SecretRef};
use scrim_redact as rc;

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

    fn fill(&mut self, out: &mut Vec<u8>, n: usize) {
        out.reserve(n);
        for _ in 0..n / 8 {
            out.extend_from_slice(&self.next().to_le_bytes());
        }
        out.resize(out.len() + n % 8, 0x5a);
    }
}

fn chunk(out: &mut Vec<u8>, typ: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(typ);
    out.extend_from_slice(data);
    let mut h = crc32fast::Hasher::new();
    h.update(typ);
    h.update(data);
    out.extend_from_slice(&h.finalize().to_be_bytes());
}

/// A PNG of about `size` bytes: noise image data in 64 KiB IDAT chunks and a text chunk.
fn png(size: usize, rng: &mut Rng) -> Vec<u8> {
    let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut p, b"IHDR", &[0, 0, 4, 0, 0, 0, 4, 0, 8, 2, 0, 0, 0]);
    chunk(&mut p, b"tEXt", b"Software\0screenshot tool 4.2");
    let mut data = Vec::new();
    while p.len() < size {
        data.clear();
        rng.fill(&mut data, 65536);
        chunk(&mut p, b"IDAT", &data);
    }
    chunk(&mut p, b"IEND", &[]);
    p
}

/// A JPEG of about `size` bytes: EXIF and XMP APP1 segments, then noise entropy-coded data.
fn jpeg(size: usize, rng: &mut Rng) -> Vec<u8> {
    let mut j = vec![0xff, 0xd8];
    let seg = |j: &mut Vec<u8>, marker: u8, payload: &[u8]| {
        j.extend_from_slice(&[0xff, marker]);
        j.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        j.extend_from_slice(payload);
    };
    seg(&mut j, 0xe0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
    let mut exif = b"Exif\0\0MM\0\x2a\0\0\0\x08".to_vec();
    exif.resize(4096, b' ');
    seg(&mut j, 0xe1, &exif);
    let mut xmp = b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">".to_vec();
    xmp.resize(8192, b' ');
    xmp.extend_from_slice(b"</x:xmpmeta>");
    seg(&mut j, 0xe1, &xmp);
    seg(&mut j, 0xdb, &[0u8; 65]);
    seg(&mut j, 0xc0, &[8, 4, 0, 4, 0, 1, 1, 0x11, 0]);
    seg(&mut j, 0xda, &[1, 1, 0, 0, 63, 0]);
    let mut data = Vec::new();
    rng.fill(&mut data, size.saturating_sub(j.len() + 2));
    // Entropy-coded data never holds a bare 0xFF.
    for b in &mut data {
        if *b == 0xff {
            *b = 0xfe;
        }
    }
    j.extend_from_slice(&data);
    j.extend_from_slice(&[0xff, 0xd9]);
    j
}

/// A PDF of about `size` bytes: pages whose Flate content streams show lines of text.
fn pdf(size: usize, rng: &mut Rng) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    let mut p = b"%PDF-1.7\n".to_vec();
    let mut n = 1;
    while p.len() < size {
        let mut content = Vec::new();
        for line in 0..60 {
            let w = rng.next();
            writeln!(
                content,
                "BT /F1 10 Tf 72 {} Td (Line {line} of the build log: step {w:x} finished in {} ms) Tj ET",
                760 - line * 12,
                w % 997
            )
            .unwrap();
        }
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(&content).unwrap();
        let z = z.finish().unwrap();
        write!(
            p,
            "{n} 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
            z.len()
        )
        .unwrap();
        p.extend_from_slice(&z);
        p.extend_from_slice(b"\nendstream\nendobj\n");
        n += 1;
    }
    p.extend_from_slice(b"trailer\n<< /Size 1 >>\n%%EOF\n");
    p
}

fn body(kind: &str, media_type: &str, data: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"model":"claude-x","max_tokens":1024,"messages":[{{"role":"user","content":[{{"type":"{kind}","source":{{"type":"base64","media_type":"{media_type}","data":"{}"}}}},{{"type":"text","text":"What does this show?"}}]}}]}}"#,
        B64.encode(data)
    )
    .into_bytes()
}

fn engine(values: usize) -> CoreEngine {
    let keyring = Arc::new(rc::Keyring::new(
        rc::PlaceholderKey::new(1, &[5u8; 32]).unwrap(),
    ));
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut entries = Vec::new();
    let mut refs = Vec::new();
    for i in 0..values {
        let v = format!("bench-value-{:016x}{:08x}", rng.next(), i);
        entries.push(rc::Entry::new(
            i as u64,
            rc::RefSlug::new(&format!("v{i}")).unwrap(),
            rc::ValueClass::Display,
            rc::SecretValue::from_slice(v.as_bytes()),
        ));
        refs.push((rc::EntryId(i as u64), SecretRef::new(format!("bench/v{i}"))));
    }
    let snap = rc::Snapshot::build(entries, keyring, &rc::Config::default()).unwrap();
    CoreEngine::new(Arc::new(snap), refs)
}

fn percentile(v: &mut [Duration], p: f64) -> Duration {
    v.sort_unstable();
    v[((v.len() - 1) as f64 * p).round() as usize]
}

fn main() {
    let quick = std::env::var_os("SCRIM_LLM_BENCH_QUICK").is_some();
    let iters = if quick { 5 } else { 21 };
    let engine = engine(1000);
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    println!(
        "{:<6} {:>6} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "part", "MiB", "pass p50", "pass p99", "scan p50", "scan p99", "added p50"
    );
    for mib in [1usize, 5, 20] {
        let size = mib << 20;
        for (name, kind, mt, data) in [
            ("png", "image", "image/png", png(size, &mut rng)),
            ("jpeg", "image", "image/jpeg", jpeg(size, &mut rng)),
            ("pdf", "document", "application/pdf", pdf(size, &mut rng)),
        ] {
            let b = body(kind, mt, &data);
            let mut results = Vec::new();
            let mut refused = None;
            for policy in [BinaryPolicy::Pass, BinaryPolicy::Scan] {
                let snap = engine.snapshot(1, Arc::new(KeepAll), policy);
                // A part past the scan bounds is refused; the time to refuse is what it costs.
                if let Err(e) = outgoing::prepare(&snap, Api::AnthropicMessages, &b) {
                    assert_eq!(policy, BinaryPolicy::Scan, "pass forwards everything");
                    refused = Some(e.detail);
                }
                let mut t = Vec::with_capacity(iters);
                for _ in 0..iters {
                    let s = Instant::now();
                    let o = outgoing::prepare(&snap, Api::AnthropicMessages, &b);
                    t.push(s.elapsed());
                    std::hint::black_box(o).ok();
                }
                results.push((percentile(&mut t, 0.5), percentile(&mut t, 0.99)));
            }
            let ms = |d: Duration| format!("{:.1} ms", d.as_secs_f64() * 1000.0);
            println!(
                "{:<6} {:>6} {:>10} {:>10} {:>10} {:>10} {:>10}",
                name,
                mib,
                ms(results[0].0),
                ms(results[0].1),
                ms(results[1].0),
                ms(results[1].1),
                ms(results[1].0.saturating_sub(results[0].0)),
            );
            if let Some(detail) = refused {
                println!("       refused under scan: {detail}");
            }
        }
    }
}
