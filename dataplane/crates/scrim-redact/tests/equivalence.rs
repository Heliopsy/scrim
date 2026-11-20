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

/// What `protect` returned, owned, for comparing two snapshots.
type Outcome = Result<(Vec<u8>, Stats, GuardOutcome, Vec<GuardFinding>), Error>;

fn protect_owned(s: &Snapshot, input: &[u8]) -> Outcome {
    let mut ws = Workspace::new();
    s.protect(input, &mut ws)
        .map(|p| (p.bytes.to_vec(), p.stats, p.guard, p.findings.to_vec()))
}

/// `input` with genuine placeholders of the values inserted at `cuts`, so the redactor's
/// copy-and-skip path (a seek past matches) runs too.
fn with_placeholders(values: &[Vec<u8>], input: &[u8], cuts: &[(usize, usize)]) -> Vec<u8> {
    let kr = keyring();
    let mut points: Vec<(usize, usize)> = cuts
        .iter()
        .map(|&(at, v)| (at % (input.len() + 1), v % values.len()))
        .collect();
    points.sort_unstable();
    let mut out = Vec::new();
    let mut last = 0;
    for (at, v) in points {
        out.extend_from_slice(&input[last..at]);
        let slug = RefSlug::new(&format!("s{}", v + 1)).unwrap();
        out.extend_from_slice(placeholder_for(kr.current(), &slug, &values[v]).as_bytes());
        last = at;
    }
    out.extend_from_slice(&input[last..]);
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// Splitting a body over threads (matching and guard) changes nothing: same bytes, counts,
    /// guard outcome and findings as on one thread, with tiny regions so that matches straddle
    /// region ends all the time.
    #[test]
    fn parallel_protect_matches_sequential(
        (values, hay) in prop::collection::vec(value(), 1..10)
            .prop_flat_map(|vs| (Just(vs.clone()), haystack(vs))),
        cuts in prop::collection::vec((any::<usize>(), any::<usize>()), 0..4),
    ) {
        let refs: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();
        let hay = with_placeholders(&values, &hay, &cuts);
        for kind in [EngineKind::AhoCorasick, EngineKind::HashWindow] {
            let one = Config { parallel_threads: 1, ..engine(kind) };
            let s1 = snapshot_with(&refs, ValueClass::Display, &one);
            let want = protect_owned(&s1, &hay);
            for (threads, min) in [(2usize, 4usize), (3, 16), (8, 8)] {
                let cfg = Config { parallel_threads: threads, parallel_min_bytes: min, ..one.clone() };
                let s = snapshot_with(&refs, ValueClass::Display, &cfg);
                prop_assert_eq!(&protect_owned(&s, &hay), &want);
            }
        }
    }
}

#[test]
fn parallel_protect_matches_sequential_on_fixtures() {
    for n in [10usize, 300] {
        let secrets = gen_secrets(31 + n as u64, n);
        let refs: Vec<&[u8]> = secrets.iter().map(|s| s.as_bytes()).collect();
        let one = Config {
            parallel_threads: 1,
            ..Config::default()
        };
        let s1 = snapshot_with(&refs, ValueClass::Credential, &one);
        let s4 = snapshot_with(
            &refs,
            ValueClass::Credential,
            &Config {
                parallel_threads: 4,
                parallel_min_bytes: 1 << 12,
                ..Config::default()
            },
        );
        for seed in 0..3u64 {
            let (body, _) = gen_body(seed, 200_000, &secrets);
            assert_eq!(protect_owned(&s4, &body), protect_owned(&s1, &body));
        }
    }
}
