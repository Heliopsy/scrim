//! The optimised guard against the pre-optimisation guard (`guard_oracle.rs`): the same verdict,
//! repaired bytes and findings on every input.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

#[path = "../testdata/fixtures.rs"]
mod fixtures;

use std::sync::Arc;

use proptest::prelude::*;

use crate::*;

fn snap(values: &[Vec<u8>], min_len: usize, max_repairs: usize) -> Option<Snapshot> {
    snap_par(values, min_len, max_repairs, 1, usize::MAX)
}

/// With `threads` workers on bodies of at least `min` bytes.
fn snap_par(
    values: &[Vec<u8>],
    min_len: usize,
    max_repairs: usize,
    threads: usize,
    min: usize,
) -> Option<Snapshot> {
    snap_depth(
        values,
        min_len,
        max_repairs,
        threads,
        min,
        Config::default().json_depth,
    )
}

/// With JSON unescaping to `depth` rounds.
fn snap_depth(
    values: &[Vec<u8>],
    min_len: usize,
    max_repairs: usize,
    threads: usize,
    min: usize,
    depth: usize,
) -> Option<Snapshot> {
    let kr = Arc::new(Keyring::new(PlaceholderKey::new(1, &[9; 32]).unwrap()));
    let entries = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            Entry::new(
                i as u64 + 1,
                RefSlug::new(&format!("v{i}")).unwrap(),
                ValueClass::Credential,
                SecretValue::from_slice(v),
            )
        })
        .collect();
    let cfg = Config {
        min_len,
        guard_max_repairs: max_repairs,
        parallel_threads: threads,
        parallel_min_bytes: min,
        json_depth: depth,
        detectors: DetectorConfig {
            rules_enabled: false,
            ..Default::default()
        },
        ..Config::default()
    };
    Snapshot::build(entries, kr, &cfg).ok()
}

fn assert_agrees(s: &Snapshot, body: &[u8]) {
    assert!(
        s.guard().agrees_with_oracle(body),
        "guard and oracle disagree on a {}-byte body",
        body.len()
    );
}

/// Bytes values are drawn from: base64 and hex characters, JSON and URL specials, case pairs,
/// line breaks and non-ASCII.
fn value_byte() -> impl Strategy<Value = u8> {
    prop_oneof![
        8 => prop::sample::select(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_".to_vec()
        ),
        2 => prop::sample::select(b"\\\"%=&?:. \n\t\r{}[]'@`^~".to_vec()),
        1 => prop::sample::select(vec![0u8, 0x08, 0x0c, 0x1f, 0x7f, 0x80, 0xc3, 0xa9, 0xe2, 0xff]),
        1 => any::<u8>(),
    ]
}

fn value() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => prop::collection::vec(value_byte(), 8..40),
        1 => prop::collection::vec(value_byte(), 4..8),
        1 => prop::collection::vec(any::<u8>(), 4..24),
    ]
}

fn b64(data: &[u8], url: bool) -> Vec<u8> {
    fixtures::b64(data, url, false).into_bytes()
}

fn hex(data: &[u8], upper: bool) -> Vec<u8> {
    let h = fixtures::hex(data);
    if upper { h.to_ascii_uppercase() } else { h }.into_bytes()
}

fn json_escape(v: &[u8], slash: bool, uni: bool) -> Vec<u8> {
    fixtures::json_escape(&String::from_utf8_lossy(v), slash, uni).into_bytes()
}

fn percent(v: &[u8], lower: bool) -> Vec<u8> {
    let mut o = Vec::new();
    for &c in v {
        if c.is_ascii_alphanumeric() {
            o.push(c);
        } else if lower {
            o.extend_from_slice(format!("%{c:02x}").as_bytes());
        } else {
            o.extend_from_slice(format!("%{c:02X}").as_bytes());
        }
    }
    o
}

fn wrap(v: &[u8], every: usize, crlf: bool) -> Vec<u8> {
    let mut o = Vec::new();
    for (i, c) in v.chunks(every.max(1)).enumerate() {
        if i > 0 {
            o.extend_from_slice(if crlf { b"\r\n" } else { b"\n" });
        }
        o.extend_from_slice(c);
    }
    o
}

/// One piece of a body: a value in some form, or filler.
fn piece(values: Vec<Vec<u8>>) -> impl Strategy<Value = Vec<u8>> {
    let n = values.len();
    (
        0..n,
        0..18u8,
        prop::collection::vec(value_byte(), 0..6),
        prop::collection::vec(value_byte(), 0..6),
        1..80usize,
        any::<bool>(),
    )
        .prop_map(move |(vi, form, pre, post, every, flag)| {
            let v = &values[vi];
            let mut x = pre.clone();
            x.extend_from_slice(v);
            x.extend_from_slice(&post);
            match form {
                0 => v.clone(),
                1 => v.to_ascii_uppercase(),
                2 => json_escape(v, flag, false),
                3 => json_escape(v, false, true),
                4 => json_escape(&json_escape(v, flag, false), false, false),
                5 => percent(v, flag),
                6 => b64(&x, flag),
                7 => wrap(&b64(&x, flag), every, !flag),
                8 => hex(&x, flag),
                9 => json_escape(&wrap(&b64(&x, false), every, false), true, false),
                10 => json_escape(&percent(v, flag), false, false),
                11 => {
                    // A value cut in two by an escape or a line break.
                    let k = every % v.len();
                    let mut o = v[..k].to_vec();
                    o.extend_from_slice(if flag { b"\\n" } else { b"\n" });
                    o.extend_from_slice(&v[k..]);
                    o
                }
                12 => pre,
                13 => b64(&x, flag)[every % 4..].to_vec(),
                14 => hex(&x, flag)[1..].to_vec(),
                // JSON in a JSON string in a JSON string, mixed styles.
                15 => json_escape(
                    &json_escape(&json_escape(v, flag, !flag), false, false),
                    !flag,
                    false,
                ),
                16 => json_escape(
                    &json_escape(
                        &json_escape(&json_escape(v, false, flag), flag, false),
                        false,
                        false,
                    ),
                    false,
                    false,
                ),
                _ => post,
            }
        })
}

fn body(values: Vec<Vec<u8>>) -> impl Strategy<Value = Vec<u8>> {
    let filler = prop::collection::vec(value_byte(), 0..24);
    prop::collection::vec((piece(values), filler), 1..10).prop_map(|parts| {
        let mut b = Vec::new();
        for (p, f) in parts {
            b.extend_from_slice(&p);
            b.extend_from_slice(&f);
        }
        b
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    #[test]
    fn optimised_guard_matches_oracle(
        (values, body) in prop::collection::vec(value(), 1..8)
            .prop_flat_map(|vs| (Just(vs.clone()), body(vs)))
    ) {
        for (min_len, repairs, threads) in [(8usize, 64usize, 1usize), (4, 64, 1), (12, 2, 1), (8, 64, 4), (4, 1000, 3)] {
            // Several workers on tiny regions: every boundary case of the split is exercised.
            if let Some(s) = snap_par(&values, min_len, repairs, threads, 8) {
                prop_assert!(s.guard().agrees_with_oracle(&body));
            }
        }
        for (depth, threads) in [(2usize, 1usize), (4, 1), (4, 3)] {
            if let Some(s) = snap_depth(&values, 8, 64, threads, 8, depth) {
                prop_assert!(s.guard().agrees_with_oracle(&body));
            }
        }
    }

    #[test]
    fn optimised_guard_matches_oracle_on_noise(
        values in prop::collection::vec(value(), 1..6),
        body in prop::collection::vec(value_byte(), 0..600),
    ) {
        for threads in [1, 2, 8] {
            if let Some(s) = snap_par(&values, 8, 64, threads, 16) {
                prop_assert!(s.guard().agrees_with_oracle(&body));
            }
        }
    }
}

/// The benchmark bodies, before and after redaction, with the benchmark secret kinds.
#[test]
fn optimised_guard_matches_oracle_on_fixtures() {
    for n in [10usize, 300] {
        let secrets = fixtures::gen_secrets(77 + n as u64, n);
        let values: Vec<Vec<u8>> = secrets.iter().map(|s| s.as_bytes().to_vec()).collect();
        for (threads, min) in [(1, usize::MAX), (4, 1 << 12), (8, 1 << 16)] {
            let s = snap_par(&values, 8, 100_000, threads, min).unwrap();
            for seed in 0..3u64 {
                let (b, _) = fixtures::gen_body(seed, 120_000, &secrets);
                assert_agrees(&s, &b);
                let mut out = Vec::new();
                s.redactor().redact(&b, &mut out).unwrap();
                assert_agrees(&s, &out);
                let (clean, _) = fixtures::gen_body(seed + 100, 60_000, &[]);
                assert_agrees(&s, &clean);
            }
        }
    }
}

/// Values with backslashes, occurring overlapped and back to back, in the raw bytes of a body
/// that has JSON escapes elsewhere.
#[test]
fn backslash_values_overlapping() {
    let values = vec![
        b"ab\\ab\\ab".to_vec(),
        b"\\x\\x\\x\\x".to_vec(),
        b"tail-ends\\".to_vec(),
        b"q\\q".to_vec(),
    ];
    let s = snap_par(&values, 8, 1000, 4, 4).unwrap();
    for body in [
        &b"\\n ab\\ab\\ab\\ab\\ab x"[..],
        b"\\\"\\x\\x\\x\\x\\x\\x\\x y",
        b"tail-ends\\tail-ends\\\\n",
        b"\\nq\\q\\q\\q",
        b"ab\\ab\\ab",
    ] {
        assert_agrees(&s, body);
    }
}

/// A value whose hex form has no digit: hex spans without digits must be decoded as well.
#[test]
fn digit_free_hex_value() {
    let v = vec![0xab, 0xcd, 0xef, 0xfa, 0xbc, 0xde, 0xaf, 0xbe, 0xca, 0xfe];
    let s = snap(&[v.clone(), b"other-value-1".to_vec()], 8, 64).unwrap();
    for body in [
        hex(&v, false),
        hex(&v, true),
        [b"x".to_vec(), hex(&v, false)].concat(),
    ] {
        assert_agrees(&s, &body);
        let mut gs = GuardScratch::new();
        assert!(matches!(
            s.guard().check(&body, &mut gs),
            Verdict::Repaired { .. }
        ));
    }
}
