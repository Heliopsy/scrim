//! The redactor's segment cache (`redact_cache.rs`) against whole redaction: every segment of a
//! body redacts on its own to what the body redacts to there, so cached and whole redaction
//! produce the same bytes and report the same hits, whatever sits next to a cut.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use std::sync::Arc;

use proptest::prelude::*;

use crate::detect::Detectors;
use crate::guard_tests::fixtures;
use crate::*;

fn snapshot_with(values: &[Vec<u8>], entries: usize, detectors: DetectorConfig) -> Snapshot {
    snapshot_threads(
        values,
        entries,
        detectors,
        Config::default().parallel_min_bytes,
    )
}

/// With `parallel_min` low, segment runs are redacted on several threads in small bodies too.
fn snapshot_threads(
    values: &[Vec<u8>],
    entries: usize,
    detectors: DetectorConfig,
    parallel_min: usize,
) -> Snapshot {
    let kr = Arc::new(Keyring::new(PlaceholderKey::new(1, &[7; 32]).unwrap()));
    let list = values
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
        redact_cache_entries: entries,
        detectors,
        parallel_min_bytes: parallel_min,
        ..Config::default()
    };
    Snapshot::build(list, kr, &cfg).unwrap()
}

/// Every rule on, default and opt-in, without entropy and encoded forms (which keep the cache
/// off).
fn all_rules() -> DetectorConfig {
    DetectorConfig {
        enabled_rules: crate::detect::default_off_rule_names()
            .into_iter()
            .map(String::from)
            .collect(),
        ..Default::default()
    }
}

fn snapshot(values: &[Vec<u8>]) -> Snapshot {
    snapshot_with(values, 1 << 16, all_rules())
}

fn detectors() -> Detectors {
    Detectors::build(&all_rules()).unwrap()
}

/// What a redaction produced, comparable: output bytes, stats, and each hit as (start, end,
/// entry id or rule).
type Outcome = (Vec<u8>, Stats, Vec<(usize, usize, String)>);

fn run(f: impl FnOnce(&mut Vec<u8>, &mut dyn FnMut(Hit<'_>)) -> Result<Stats, Error>) -> Outcome {
    let mut out = Vec::new();
    let mut hits = Vec::new();
    let st = f(&mut out, &mut |h| {
        let (s, e) = h.span();
        let who = match h {
            Hit::Known { meta, .. } => format!("{:?}", meta.id),
            Hit::Detected { rule, .. } => rule.to_string(),
        };
        hits.push((s, e, who));
    })
    .unwrap();
    (out, st, hits)
}

fn cached(s: &Snapshot, b: &[u8]) -> Outcome {
    run(|out, f| s.redactor().redact_with(b, out, f))
}

fn whole(s: &Snapshot, b: &[u8]) -> Outcome {
    run(|out, f| s.redactor().redact_whole_with(b, out, f))
}

fn cuts(b: &[u8]) -> Vec<usize> {
    let mut c = Vec::new();
    redact_cache::cuts(b, &detectors(), &mut Vec::new(), &mut c);
    c
}

/// Each segment redacted on its own and the results joined, hits moved to body offsets.
fn by_segment(s: &Snapshot, b: &[u8]) -> Outcome {
    let mut bounds = vec![0];
    bounds.extend(cuts(b));
    bounds.push(b.len());
    let mut all: Outcome = (Vec::new(), Stats::default(), Vec::new());
    for w in bounds.windows(2) {
        let (out, st, hits) = whole(s, &b[w[0]..w[1]]);
        all.0.extend(out);
        all.1.credential += st.credential;
        all.1.display += st.display;
        all.1.detected += st.detected;
        all.2.extend(
            hits.into_iter()
                .map(|(x, y, who)| (x + w[0], y + w[0], who)),
        );
    }
    all
}

/// The segments, the cache cold and warm, and the whole redaction agree on `b`.
fn agree(s: &Snapshot, b: &[u8]) {
    assert!(s.redactor().caches());
    s.redactor().clear_cache();
    let w = whole(s, b);
    assert_eq!(by_segment(s, b), w, "segments and whole body disagree");
    assert_eq!(cached(s, b), w, "cold cache and whole body disagree");
    assert_eq!(cached(s, b), w, "warm cache and whole body disagree");
}

fn esc(t: &str) -> String {
    fixtures::json_escape(t, false, false)
}

/// Content blocks joined the way the codecs see them: `{"type":"text","text":"..."},{...}`.
fn blocks(texts: &[String]) -> Vec<u8> {
    let mut b = br#"{"model":"m","messages":[{"role":"user","content":["#.to_vec();
    for (i, t) in texts.iter().enumerate() {
        if i > 0 {
            b.push(b',');
        }
        b.extend_from_slice(format!(r#"{{"type":"text","text":"{}"}}"#, esc(t)).as_bytes());
    }
    b.extend_from_slice(b"]}]}");
    b
}

/// Prose of about `n` bytes.
fn prose(seed: u64, n: usize) -> String {
    let mut r = fixtures::Rng::new(seed);
    let words = [
        "const", "let", "return", "error", "config", "deploy", "func", "value", "the", "user",
    ];
    let mut s = String::new();
    while s.len() < n {
        s.push_str(r.pick(&words));
        s.push(if r.below(12) == 0 { '\n' } else { ' ' });
    }
    s
}

const VALUE: &[u8] = b"redact-cache-value-Hq7Lr2Wm5Tx9";
// Token-shaped test values, put together at run time so no file holds one whole.
const AWS_ID: &str = concat!("AK", "IAQWERTYUIOPASDFGH");
const AWS_SECRET: &str = concat!("wJalrXUtnFEMI2K7", "MDENGbPxRfiCYEXAMPLEKEYa");
const GHP: &str = concat!("gh", "p_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5");
const PG: &str = concat!("post", "gres://");
const BEGIN: &str = concat!("-----BEG", "IN ");
const END: &str = concat!("-----EN", "D ");

#[test]
fn next_turn_remembers_segments_without_replacements() {
    let s = snapshot(&[VALUE.to_vec()]);
    let mut texts: Vec<String> = (0..40).map(|i| prose(i, 2000)).collect();
    texts[7].push_str(std::str::from_utf8(VALUE).unwrap());
    let old = blocks(&texts);
    texts.push(format!("{} {}", prose(99, 1500), GHP));
    let new = blocks(&texts);
    s.redactor().clear_cache();
    assert_eq!(cached(&s, &old), whole(&s, &old));
    let n = cuts(&old).len() + 1;
    assert!(n >= 40, "{n} segments");
    // Every segment but the one with the value.
    assert_eq!(s.redactor().cache_len(), n - 1);
    let b = cached(&s, &new);
    assert_eq!(b, whole(&s, &new));
    assert!(b.1.detected == 1 && b.1.credential == 1);
    // The old last block is a new segment now (a cut follows it); the new block has a token.
    assert_eq!(s.redactor().cache_len(), n);
}

#[test]
fn values_and_tokens_next_to_cuts() {
    let s = snapshot(&[VALUE.to_vec(), b"x}]-value,1234{".to_vec()]);
    let v = std::str::from_utf8(VALUE).unwrap();
    let filler = prose(5, 40_000);
    let cases: Vec<Vec<String>> = vec![
        // Values and tokens right before and right after a cut.
        vec![
            filler.clone(),
            format!("x {v}"),
            format!("{v} y"),
            GHP.into(),
        ],
        // An access key id before a cut, its secret in the next block.
        vec![
            filler.clone(),
            format!("id {AWS_ID}"),
            format!("{AWS_SECRET} rest"),
        ],
        // A database URL whose password runs into the next block.
        vec![
            filler.clone(),
            format!("{PG}user:pa]"),
            "}@db.example.com".into(),
        ],
        // ... and one whose password holds `]},{}`, which reads as a cut.
        vec![
            filler.clone(),
            format!("{PG}user:pa]}},{{}}@db.example.com"),
        ],
        // A private key block with its end in a later block.
        vec![
            filler.clone(),
            format!("{BEGIN}RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn"),
            format!("MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n{END}RSA PRIVATE KEY-----"),
        ],
        // A placeholder from an earlier turn next to a cut.
        vec![
            filler.clone(),
            "⟦scrim:v0:01abcdef0123456789⟧".into(),
            v.into(),
        ],
    ];
    for texts in cases {
        agree(&s, &blocks(&texts));
    }
}

#[test]
fn windows_rule_out_cuts() {
    let pad = "a ".repeat(400);
    let plain = format!(r#"[{{"t":"{pad}"}},{{"t":"x"}}]"#);
    assert_eq!(cuts(plain.as_bytes()).len(), 1);
    for before in [
        format!("{AWS_ID} "),
        format!("{PG}u:p"),
        format!("{BEGIN}RSA PRIVATE KEY-----"),
    ] {
        let b = format!(r#"[{{"t":"{pad}{before}"}},{{"t":"x"}}]"#);
        assert_eq!(cuts(b.as_bytes()).len(), 0, "{before}");
        // Far enough back, the anchor does not rule the cut out.
        let far = format!(r#"[{{"t":"{before}{}"}},{{"t":"x"}}]"#, "b ".repeat(9000));
        assert_eq!(cuts(far.as_bytes()).len(), 1, "{before} far back");
    }
    // A URL scheme right after the cut is within the rule's reach too.
    let after = format!(
        r#"[{{"t":"{pad}"}},{{"t":"my{}u:p@h"}}]"#,
        concat!("sql", "://")
    );
    assert_eq!(cuts(after.as_bytes()).len(), 0);
}

#[test]
fn only_the_url_password_rule_can_match_a_comma_or_brace() {
    // The rules whose pattern can match `,` or `{` get a window around cuts (`cut_ok`). Today
    // that is the URL password; a new one is handled the same way without a change here, but
    // this test says when the list grows.
    assert_eq!(
        crate::detect::crossing_rule_names(),
        vec!["database-url-password"]
    );
}

#[test]
fn snapshots_that_cannot_segment_do_not_cache() {
    let value = || vec![VALUE.to_vec()];
    let entropy = DetectorConfig {
        entropy: Some(EntropyConfig::default()),
        ..Default::default()
    };
    assert!(
        !snapshot_with(&value(), 1 << 16, entropy)
            .redactor()
            .caches()
    );
    let encoded = DetectorConfig {
        encoded: true,
        ..Default::default()
    };
    assert!(
        !snapshot_with(&value(), 1 << 16, encoded)
            .redactor()
            .caches()
    );
    // A value whose compiled forms contain `,{`.
    assert!(
        !snapshot_with(&[b"abc,{def-1234".to_vec()], 1 << 16, all_rules())
            .redactor()
            .caches()
    );
    // A value inside another value.
    assert!(
        !snapshot_with(
            &[b"test-1234".to_vec(), b"sk-test-1234-abcdefgh".to_vec()],
            1 << 16,
            all_rules()
        )
        .redactor()
        .caches()
    );
    assert!(!snapshot_with(&value(), 0, all_rules()).redactor().caches());
    assert!(
        snapshot_with(&value(), 1 << 16, all_rules())
            .redactor()
            .caches()
    );
}

/// Snippets that put values, tokens, encodings and anchors next to cuts.
fn snippet() -> impl Strategy<Value = String> {
    let v = std::str::from_utf8(VALUE).unwrap().to_string();
    prop_oneof![
        Just(v.clone()),
        Just(v[..12].to_string()),
        Just(v[12..].to_string()),
        Just(GHP.to_string()),
        Just(AWS_ID.to_string()),
        Just(AWS_SECRET.to_string()),
        Just(format!("{PG}admin:")),
        Just("s3cr3t]".to_string()),
        Just("}@db.internal".to_string()),
        Just(format!("{BEGIN}EC PRIVATE KEY-----\n")),
        Just(format!("\n{END}EC PRIVATE KEY-----")),
        Just("MHcCAQEEIBkg4LVWM9nuwNSk".to_string()),
        Just(concat!("ey", "JhbGciOiJIUzI1NiJ9.ey", "JzdWIiOiIxMjM0NTY3ODkwIn0.").to_string()),
        Just("dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U".to_string()),
        Just("aws_secret_access_key = ".to_string()),
        Just("password: ".to_string()),
        Just("Zx9!kQ2#mW7$pL4^".to_string()),
        Just("⟦scrim:v0:01abcdef0123456789⟧".to_string()),
        Just("\\".to_string()),
        Just("\"},{\"".to_string()),
        Just("]},{}".to_string()),
        "[ -~]{0,40}",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Blocks of prose with snippets at their ends: segments, cache and whole agree.
    #[test]
    fn segments_agree_with_the_whole_body(
        parts in prop::collection::vec(
            (
                prop::collection::vec(snippet(), 0..3),
                0usize..600,
                prop::collection::vec(snippet(), 0..3),
            ),
            2..12,
        ),
        seed in 0u64..1000,
    ) {
        let s = snapshot(&[VALUE.to_vec(), b"admin-pass-1234".to_vec()]);
        let mut texts = vec![prose(seed, 33_000)];
        for (k, (head, n, tail)) in parts.into_iter().enumerate() {
            let mut t = head.concat();
            t.push_str(&prose(seed + k as u64 + 1, n));
            t.push_str(&tail.concat());
            texts.push(t);
        }
        agree(&s, &blocks(&texts));
    }
}
