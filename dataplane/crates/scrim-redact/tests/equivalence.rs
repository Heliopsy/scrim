//! The Aho-Corasick and hash-window engines produce byte-identical output.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    unreachable_pub,
    missing_docs
)]

mod common;

use common::fixtures::{gen_body, gen_secrets};
use common::*;
use proptest::prelude::*;
use scrim_redact::*;

fn pair(values: &[&[u8]], config: &Config) -> (Snapshot, Snapshot) {
    let ac = Config {
        engine: EngineChoice::Fixed(EngineKind::AhoCorasick),
        ..config.clone()
    };
    let hw = Config {
        engine: EngineChoice::Fixed(EngineKind::HashWindow),
        ..config.clone()
    };
    (
        snapshot_with(values, ValueClass::Display, &ac),
        snapshot_with(values, ValueClass::Display, &hw),
    )
}

fn hits(s: &Snapshot, input: &[u8]) -> (Vec<u8>, Vec<(u64, usize, usize)>) {
    let mut out = Vec::new();
    let mut v = Vec::new();
    s.redactor()
        .redact_with(input, &mut out, &mut |h| {
            if let Hit::Known {
                meta, start, end, ..
            } = h
            {
                v.push((meta.id.0, start, end));
            }
        })
        .unwrap();
    (out, v)
}

#[test]
fn fixtures_identical() {
    for n in [10usize, 300] {
        let secrets = gen_secrets(20_261_120 + n as u64, n);
        let refs: Vec<&[u8]> = secrets.iter().map(|s| s.as_bytes()).collect();
        let (a, h) = pair(&refs, &Config::default());
        for (seed, sec) in [(1u64, &secrets[..]), (2, &[][..])] {
            let (body, inserted) = gen_body(seed + n as u64, 300_000, sec);
            let (oa, ha) = hits(&a, &body);
            let (oh, hh) = hits(&h, &body);
            assert_eq!(ha, hh, "set {n} seed {seed}");
            assert_eq!(oa, oh, "set {n} seed {seed}");
            if inserted > 0 {
                assert!(
                    ha.len() >= inserted,
                    "set {n}: {} hits for {inserted} inserted",
                    ha.len()
                );
                // No inserted value survives in any form the redactor knows.
                for s in &secrets {
                    assert!(!contains(&oa, s.as_bytes()));
                }
            }
        }
    }
}

/// Values drawn from a small alphabet so they overlap, nest and share prefixes often.
fn value() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(prop::sample::select(b"ab".to_vec()), 4..20),
        prop::collection::vec(prop::sample::select(b"abc/+\"\\ =%".to_vec()), 4..14),
        prop::collection::vec(any::<u8>(), 4..24),
    ]
}

fn haystack(values: Vec<Vec<u8>>) -> impl Strategy<Value = Vec<u8>> {
    let pieces = prop::collection::vec(
        prop_oneof![
            3 => prop::collection::vec(prop::sample::select(b"abc/+\"\\ =%AB".to_vec()), 0..12),
            2 => prop::sample::select(values.clone()),
            1 => (prop::sample::select(values.clone()), 0..6usize).prop_map(|(v, cut)| v[..v.len().saturating_sub(cut)].to_vec()),
            1 => prop::sample::select(values).prop_map(|v| {
                let mut s = b"=".to_vec();
                s.extend(common::fixtures::b64(&[b"xy".as_slice(), &v, b"z"].concat(), false, false).into_bytes());
                s
            }),
        ],
        0..30,
    );
    pieces.prop_map(|p| p.concat())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn engines_agree(
        (values, hay) in prop::collection::vec(value(), 1..12)
            .prop_flat_map(|vs| (Just(vs.clone()), haystack(vs)))
    ) {
        let refs: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();
        for min_len in [8usize, 4, 12] {
            let cfg = Config { min_len, ..no_detectors() };
            let (a, h) = pair(&refs, &cfg);
            let (oa, ha) = hits(&a, &hay);
            let (oh, hh) = hits(&h, &hay);
            prop_assert_eq!(&ha, &hh);
            prop_assert_eq!(&oa, &oh);
        }
    }

    #[test]
    fn whole_values_never_survive(
        (values, hay) in prop::collection::vec(value(), 1..8)
            .prop_flat_map(|vs| (Just(vs.clone()), haystack(vs)))
    ) {
        let refs: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();
        let s = snapshot_with(&refs, ValueClass::Display, &no_detectors());
        let mut ws = Workspace::new();
        let out = s.protect(&hay, &mut ws);
        // Either refused, or no value remains verbatim.
        if let Ok(p) = out {
            for v in &values {
                prop_assert!(!contains(p.bytes, v));
            }
        }
    }
}
