//! A value inside a longer value: the shorter one's replacement must not break the longer one.
//!
//! LocalStack's default credentials are `test`/`test`. With them in the redaction set next to an
//! API key `sk-test-...`, the redactor replaced the `test` (raw, or its hex form) inside a dump of
//! the key that only the guard decodes (wrapped hex, `xxd`, `hexdump -C`). The rest of the key no
//! longer formed the whole value, so the guard found nothing and 41 of its 48 bytes went out.
//!
//! Every case here sends one encoded form of the longer value and checks, with decoders of its
//! own, that no eight-byte window of that value survives in what `protect` returns.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::chunks_exact_to_as_chunks,
    unreachable_pub,
    missing_docs
)]

mod common;

use common::fixtures::{Rng, b64, hex, json_escape};
use common::*;
use scrim_redact::*;

const URLSAFE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A generated API key shaped like the leak suite's: a public prefix and 40 random characters.
fn api_key(seed: u64) -> String {
    format!("sk-test-{}", Rng::new(seed).string(URLSAFE, 40))
}

/// The nested setups: (name, inner value, longer value, length of the longer value's public
/// prefix).
fn setups(seed: u64) -> Vec<(&'static str, Vec<u8>, Vec<u8>, usize)> {
    let long = api_key(seed);
    let inner_mid = long[20..32].to_owned();
    let inner_prefix = long[..12].to_owned();
    vec![
        (
            "short-inside",
            b"test".to_vec(),
            long.clone().into_bytes(),
            8,
        ),
        (
            "long-inside",
            inner_mid.into_bytes(),
            long.clone().into_bytes(),
            8,
        ),
        (
            "long-prefix",
            inner_prefix.into_bytes(),
            long.clone().into_bytes(),
            8,
        ),
        // A value of hex digits (a PIN, a hex token) that is part of the longer value's hex form.
        (
            "digits-inside-hex",
            hex(&long.as_bytes()[12..16]).into_bytes(),
            long.into_bytes(),
            8,
        ),
    ]
}

fn xxd(v: &[u8]) -> String {
    let mut o = String::new();
    for (n, line) in v.chunks(16).enumerate() {
        o += &format!("{:08x}: ", n * 16);
        for i in 0..16 {
            match line.get(i) {
                Some(b) => o += &format!("{b:02x}"),
                None => o += "  ",
            }
            if i % 2 == 1 {
                o.push(' ');
            }
        }
        o.push(' ');
        o.extend(line.iter().map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '.'
            }
        }));
        o.push('\n');
    }
    o
}

fn hexdump_c(v: &[u8]) -> String {
    let mut o = String::new();
    for (n, line) in v.chunks(16).enumerate() {
        o += &format!("{:08x}  ", n * 16);
        for i in 0..16 {
            match line.get(i) {
                Some(b) => o += &format!("{b:02x} "),
                None => o += "   ",
            }
            if i == 7 {
                o.push(' ');
            }
        }
        o += " |";
        o.extend(line.iter().map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '.'
            }
        }));
        o += "|\n";
    }
    o
}

fn od_x1(v: &[u8]) -> String {
    v.chunks(16)
        .map(|l| l.iter().map(|b| format!(" {b:02x}")).collect::<String>() + "\n")
        .collect()
}

fn wrap(s: &str, n: usize) -> String {
    s.as_bytes()
        .chunks(n)
        .map(|c| std::str::from_utf8(c).unwrap().to_owned() + "\n")
        .collect()
}

fn base32(v: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut o = String::new();
    for ch in v.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..ch.len()].copy_from_slice(ch);
        let x = buf.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
        let chars = (ch.len() * 8).div_ceil(5);
        for q in 0..8 {
            o.push(if q < chars {
                A[((x >> (35 - 5 * q)) & 31) as usize] as char
            } else {
                '='
            });
        }
    }
    o
}

/// The forms an agent's tools produce, each written into a JSON string as a client would.
fn forms(v: &[u8]) -> Vec<(&'static str, String)> {
    let s = std::str::from_utf8(v).unwrap();
    let doc = format!("API_KEY={s}\nREGION=eu-west-1\n");
    vec![
        ("raw", s.to_owned()),
        ("hex", hex(v)),
        ("hex-upper", hex(v).to_uppercase()),
        ("hex-wrapped", wrap(&hex(v), 60)),
        ("xxd", xxd(v)),
        ("xxd-doc", xxd(doc.as_bytes())),
        ("hexdump-c", hexdump_c(v)),
        ("od-x1", od_x1(v)),
        (
            "c-hex-escapes",
            v.iter().map(|b| format!("\\x{b:02x}")).collect(),
        ),
        (
            "spaced",
            v.iter().map(|&b| format!("{} ", b as char)).collect(),
        ),
        ("base64", b64(v, false, true)),
        ("base64url", b64(v, true, false)),
        (
            "base64-doc-wrapped",
            wrap(&b64(doc.as_bytes(), false, true), 76),
        ),
        (
            "percent-all",
            v.iter().map(|b| format!("%{b:02X}")).collect(),
        ),
        ("reversed", s.chars().rev().collect()),
        // Truncated where the inner value of the long-inside setup ends or starts: the guard's
        // fragment rule (at least half the value) catches these.
        ("truncated-head", format!("{}...", &s[..32])),
        ("truncated-tail", format!("...{}", &s[20..])),
        ("base32", base32(v)),
    ]
}

fn body(form: &str) -> Vec<u8> {
    format!(
        r#"{{"messages":[{{"role":"user","content":"output:\n{}\ndone, test passed"}}]}}"#,
        json_escape(form, false, false)
    )
    .into_bytes()
}

/// Decoded readings of `out`, independent of the crate: as is, reversed, percent-decoded, its hex
/// digits joined and decoded at both alignments, its base64 characters joined and decoded at all
/// four. Joining every digit of the body over-approximates (other text adds junk between them),
/// which can only add findings, never hide one: a dump keeps each line's bytes contiguous.
fn readings(out: &[u8]) -> Vec<Vec<u8>> {
    // JSON escapes first: `\n` between dump lines would otherwise add an `n`.
    let text = String::from_utf8_lossy(out)
        .replace("\\n", "\n")
        .replace("\\\\", "\\");
    let t = text.as_bytes();
    let mut r = vec![t.to_vec(), t.iter().rev().copied().collect()];
    let mut pct = Vec::new();
    let mut i = 0;
    while i < t.len() {
        if t[i] == b'%'
            && i + 2 < t.len()
            && let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&t[i + 1..i + 3]).unwrap_or("zz"), 16)
        {
            pct.push(b);
            i += 3;
            continue;
        }
        pct.push(t[i]);
        i += 1;
    }
    r.push(pct);
    let digits: Vec<u8> = t.iter().copied().filter(u8::is_ascii_hexdigit).collect();
    for a in 0..2 {
        r.push(
            digits[a.min(digits.len())..]
                .chunks_exact(2)
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect(),
        );
    }
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    };
    let sextets: Vec<u8> = t.iter().filter_map(|&c| val(c)).collect();
    for a in 0..4 {
        let mut dec = Vec::new();
        for q in sextets[a.min(sextets.len())..].chunks_exact(4) {
            let x = q.iter().fold(0u32, |acc, &s| (acc << 6) | u32::from(s));
            dec.extend_from_slice(&[(x >> 16) as u8, (x >> 8) as u8, x as u8]);
        }
        r.push(dec);
    }
    // Spaced letters.
    r.push(t.iter().copied().filter(|&c| c != b' ').collect());
    r
}

/// The first eight-byte window of `v` (past its public prefix) readable in `out`, if any.
fn leaked_window(out: &[u8], v: &[u8], public: usize) -> Option<usize> {
    let rs: Vec<Vec<u8>> = readings(out)
        .into_iter()
        .map(|r| r.to_ascii_lowercase())
        .collect();
    let v = v.to_ascii_lowercase();
    (1.max(public.saturating_sub(7))..=v.len() - 8)
        .find(|&i| rs.iter().any(|r| contains(r, &v[i..i + 8])))
}

fn check(kind: EngineKind, seed: u64) -> Vec<String> {
    let mut failures = Vec::new();
    for (setup, inner, long, public) in setups(seed) {
        let s = snapshot_with(&[&inner, &long], ValueClass::Credential, &engine(kind));
        for (name, form) in forms(&long) {
            let input = body(&form);
            let mut ws = Workspace::new();
            match s.protect(&input, &mut ws) {
                Ok(p) => {
                    if let Some(at) = leaked_window(p.bytes, &long, public) {
                        failures.push(format!("{kind:?} {setup} {name}: window at {at} leaked"));
                    }
                }
                Err(e) => failures.push(format!("{kind:?} {setup} {name}: refused ({e:?})")),
            }
        }
    }
    failures
}

#[test]
fn nested_value_is_redacted_in_every_form() {
    let mut failures = Vec::new();
    for seed in 1..=8 {
        for kind in [EngineKind::AhoCorasick, EngineKind::HashWindow] {
            failures.extend(check(kind, seed));
        }
    }
    failures.dedup();
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The leak-suite shape exactly: LocalStack's `test`, an `sk-test-` key, a wrapped hex dump.
#[test]
fn localstack_test_credential_and_wrapped_hex() {
    let long = api_key(42);
    let s = snapshot(&[b"test", long.as_bytes()]);
    let input = body(&wrap(&hex(long.as_bytes()), 60));
    let mut ws = Workspace::new();
    let p = s.protect(&input, &mut ws).unwrap();
    assert_eq!(leaked_window(p.bytes, long.as_bytes(), 8), None);
    // The value on its own is still replaced by its own placeholder, the short one by its own.
    assert!(contains(p.bytes, &ph(&s, long.as_bytes())));
    assert!(
        contains(p.bytes, &ph(&s, b"test")),
        "the trailing `test` keeps its placeholder"
    );
}

/// The redactor alone, as the LLM proxy calls it (the guard runs on its output separately), and
/// `find_matches`, which the HTTPS tool proxy applies itself, give the same bytes.
#[test]
fn redactor_alone_widens_and_find_matches_agrees() {
    let long = api_key(7);
    let s = snapshot_with(
        &[b"test", long.as_bytes()],
        ValueClass::Credential,
        &no_detectors(),
    );
    for (name, form) in forms(long.as_bytes()) {
        let input = body(&form);
        let out = redact(&s, &input);
        let mut rebuilt = Vec::new();
        let mut at = 0;
        s.redactor()
            .find_matches(&input, &mut |a, b, ph| {
                rebuilt.extend_from_slice(&input[at..a]);
                rebuilt.extend_from_slice(ph);
                at = b;
            })
            .unwrap();
        rebuilt.extend_from_slice(&input[at..]);
        assert_eq!(rebuilt, out, "{name}: find_matches disagrees with redact");
        let mut gs = GuardScratch::new();
        let sent = match s.guard().check(&out, &mut gs) {
            Verdict::Clean => out.clone(),
            Verdict::Repaired { bytes, .. } => bytes.to_vec(),
            Verdict::Withhold(r) => panic!("{name}: withheld {r:?}"),
        };
        assert_eq!(
            leaked_window(&sent, long.as_bytes(), 8),
            None,
            "{name}: leaked"
        );
    }
}
