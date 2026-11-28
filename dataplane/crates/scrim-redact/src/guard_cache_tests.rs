//! The guard's verdict cache (`guard_cache.rs`) against the whole check: on an agent's next turn,
//! which resends the previous turn's bytes and adds new ones, the cached check reaches the
//! verdict the whole check reaches, whatever the new bytes hold and wherever they hold it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use std::sync::Arc;

use proptest::prelude::*;

use crate::guard_tests::fixtures;
use crate::*;

fn snapshot(values: &[Vec<u8>], cache: bool) -> Snapshot {
    let kr = Arc::new(Keyring::new(PlaceholderKey::new(1, &[3; 32]).unwrap()));
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
        guard_cache_entries: if cache { 1 << 16 } else { 0 },
        detectors: DetectorConfig {
            rules_enabled: false,
            ..Default::default()
        },
        ..Config::default()
    };
    Snapshot::build(entries, kr, &cfg).unwrap()
}

/// One Anthropic Messages body from message texts (JSON-escaped here).
fn body(texts: &[Vec<u8>]) -> Vec<u8> {
    let mut b = br#"{"model":"m","max_tokens":1024,"messages":["#.to_vec();
    for (i, t) in texts.iter().enumerate() {
        if i > 0 {
            b.push(b',');
        }
        let role = if i % 2 == 0 { "user" } else { "assistant" };
        b.extend_from_slice(
            format!(r#"{{"role":"{role}","content":[{{"type":"text","text":""#).as_bytes(),
        );
        b.extend_from_slice(&escape(t));
        b.extend_from_slice(br#""}]}"#);
    }
    b.extend_from_slice(b"]}");
    b
}

fn escape(t: &[u8]) -> Vec<u8> {
    fixtures::json_escape(&String::from_utf8_lossy(t), false, false).into_bytes()
}

/// Ordinary conversation text of about `n` bytes: prose, code, logs (the redaction benchmark's
/// generator, without values).
fn text(seed: u64, n: usize) -> Vec<u8> {
    let doc: serde_json::Value =
        serde_json::from_slice(&fixtures::gen_body(seed, n + 4096, &[]).0).unwrap();
    let mut out = String::new();
    strings(&doc, &mut out);
    let mut end = n.min(out.len());
    while !out.is_char_boundary(end) {
        end -= 1;
    }
    out.truncate(end);
    out.into_bytes()
}

fn strings(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        serde_json::Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

/// What `check` decided, comparable: `None` when clean.
fn outcome(v: Verdict<'_>) -> Option<(Vec<u8>, Vec<GuardFinding>)> {
    match v {
        Verdict::Clean => None,
        Verdict::Repaired { bytes, findings } => Some((bytes.to_vec(), findings.to_vec())),
        Verdict::Withhold(_) => Some((b"withheld".to_vec(), Vec::new())),
    }
}

/// Checks `turns` in order with the cache, and each one with the whole check on its own; the
/// verdicts must agree. Returns the last turn's verdict.
fn agree(s: &Snapshot, turns: &[Vec<u8>]) -> Option<(Vec<u8>, Vec<GuardFinding>)> {
    assert!(s.guard().caches());
    let mut cached = GuardScratch::new();
    let mut last = None;
    for (k, t) in turns.iter().enumerate() {
        let a = outcome(s.guard().check(t, &mut cached));
        let b = outcome(s.guard().check_whole(t, &mut GuardScratch::new()));
        assert_eq!(
            a,
            b,
            "turn {k} of {}: cached and whole checks disagree",
            turns.len()
        );
        last = a;
    }
    last
}

/// Old turn and new turn: the new one repeats the old texts and adds `new`.
fn turns(old: &[Vec<u8>], new: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut all = old.to_vec();
    all.extend_from_slice(new);
    vec![body(old), body(&all)]
}

fn history(seed: u64) -> Vec<Vec<u8>> {
    (0..12)
        .map(|i| text(seed + i, 3000 + 500 * i as usize))
        .collect()
}

const VALUE: &[u8] = b"cache-test-value-Zq8Lr2Wm5Tx9Hy3P";

#[test]
fn second_turn_uses_the_cache() {
    let s = snapshot(&[VALUE.to_vec()], true);
    let old = history(1);
    let t = turns(&old, &[text(99, 2000)]);
    assert_eq!(agree(&s, &t), None);
    // The first turn's segments are all known: the second adds only its own.
    let mut sc = GuardScratch::new();
    let n = t[1].len();
    assert!(n > guard_cache_len_min());
    assert!(matches!(s.guard().check(&t[1], &mut sc), Verdict::Clean));
    assert!(
        sc_known_all(&sc),
        "a repeated body has every segment cached"
    );
}

fn guard_cache_len_min() -> usize {
    crate::guard_cache::MIN_BYTES
}

fn sc_known_all(sc: &GuardScratch) -> bool {
    sc.segments_known().iter().all(|&k| k) && sc.segments_known().len() > 10
}

#[test]
fn value_in_a_new_turn_is_repaired() {
    let s = snapshot(&[VALUE.to_vec()], true);
    let old = history(2);
    let mut leak = text(50, 1500);
    leak.extend_from_slice(b"\nexport TOKEN=");
    leak.extend_from_slice(VALUE);
    leak.extend_from_slice(b"\nmore text after it\n");
    let r = agree(&s, &turns(&old, &[leak])).expect("the new value is found");
    assert!(memchr::memmem::find(&r.0, VALUE).is_none());
}

#[test]
fn value_split_across_cached_and_new_segments_is_repaired() {
    let s = snapshot(&[VALUE.to_vec()], true);
    let mut old = history(3);
    // The old turn ends with less than half the value: no fragment, so it is clean and cached.
    let cut = VALUE.len() / 2 - 3;
    old.last_mut().unwrap().extend_from_slice(&VALUE[..cut]);
    let mut new = VALUE[cut..].to_vec();
    new.extend_from_slice(b" and the rest of the message");
    let r = agree(&s, &turns(&old, &[new])).expect("the fragment in the new turn is found");
    assert!(!r.1.is_empty());
}

#[test]
fn value_with_a_cut_pattern_turns_the_cache_off() {
    // A value written as JSON that the body carries across two content blocks.
    let v = br#"tok-1234"}]},{"role":"user","content":[{"type":"text","text":"tok-5678"#.to_vec();
    let s = snapshot(std::slice::from_ref(&v), true);
    assert!(!s.guard().caches());
    let mut old = history(4);
    old.last_mut().unwrap().extend_from_slice(b"tok-1234");
    let mut all = old.clone();
    all.push(b"tok-5678 rest".to_vec());
    let mut sc = GuardScratch::new();
    s.guard().check(&body(&old), &mut sc);
    assert!(matches!(
        s.guard().check(&body(&all), &mut sc),
        Verdict::Repaired { .. }
    ));
}

/// A `hexdump -C` line in the old turn whose ASCII column runs over the message boundary into
/// the new turn, followed there by the next dump line: the dump joins them, so the value spread
/// over both lines is found by the whole check, and must be by the cached one.
#[test]
fn dump_column_across_a_boundary_is_followed() {
    // Short enough that neither half is a fragment: only the joined dump shows it.
    let value = b"Zq8Lr2Wm5Tx9";
    let s = snapshot(&[value.to_vec()], true);
    let mut old = history(5);
    // The bytes between the old turn's last text and the new one's first (message 12 is the
    // user's).
    let junk = br#""}]},{"role":"user","content":[{"type":"text","text":""#;
    // Line 1 decodes `nb` bytes ending with the value's first part; its column holds exactly
    // `nb` bytes: the old text after `|`, the boundary, and the new text up to the closing `|`.
    let first = &value[..6];
    let nb = 64usize;
    let mut data = vec![b'.'; nb - first.len()];
    data.extend_from_slice(first);
    let mut line1 = b"00000000  ".to_vec();
    for (i, c) in data.iter().enumerate() {
        line1.extend_from_slice(format!("{c:02x} ").as_bytes());
        if i == 7 {
            line1.push(b' ');
        }
    }
    line1.extend_from_slice(b" |");
    let col_old = 4usize;
    line1.extend_from_slice(&vec![b'a'; col_old]);
    old.last_mut().unwrap().push(b'\n');
    old.last_mut().unwrap().extend_from_slice(&line1);
    let col_new = nb - col_old - junk.len();
    let mut new = vec![b'b'; col_new];
    new.extend_from_slice(b"|\n00000040  ");
    for c in &value[6..] {
        new.extend_from_slice(format!("{c:02x} ").as_bytes());
    }
    new.extend_from_slice(b"\n");
    // The old turn had another message after the dump line, so the message holding it is
    // cached and the next one is new.
    let mut first = old.clone();
    first.push(text(77, 2000));
    first.push(text(78, 500));
    let mut second = old;
    second.push(new);
    second.push(text(78, 500));
    let t = vec![body(&first), body(&second)];
    // The construction is what the test says: the whole check joins the two lines.
    let whole = outcome(s.guard().check_whole(&t[1], &mut GuardScratch::new()));
    assert!(
        whole.is_some(),
        "the whole check must find the value in the joined dump"
    );
    assert!(agree(&s, &t).is_some());
}

fn encodings(v: &[u8], k: u8) -> Vec<u8> {
    match k % 8 {
        0 => v.to_vec(),
        1 => fixtures::b64(v, false, true).into_bytes(),
        2 => fixtures::hex(v).into_bytes(),
        3 => v.iter().flat_map(|&c| [c, b' ']).collect(),
        4 => fixtures::json_escape(&String::from_utf8_lossy(v), true, true).into_bytes(),
        5 => fixtures::url_encode(&String::from_utf8_lossy(v)).into_bytes(),
        6 => v.iter().rev().copied().collect(),
        _ => v
            .iter()
            .map(|c| format!("\\x{c:02x}"))
            .collect::<String>()
            .into_bytes(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Values hidden in the new turn in many encodings, split over its messages, or straddling
    /// the end of the old turn: the cached check and the whole check agree on every turn.
    #[test]
    fn cached_and_whole_checks_agree_on_next_turns(
        seed in 0u64..1000,
        n_old in 3usize..10,
        enc in any::<u8>(),
        split in 0usize..30,
        place in 0usize..3,
    ) {
        let set = fixtures::gen_secrets(seed, 20);
        let values: Vec<Vec<u8>> = set.iter().map(|s| s.as_bytes().to_vec()).collect();
        let s = snapshot(&values, true);
        prop_assume!(s.guard().caches());
        let v = &values[seed as usize % values.len()];
        let mut old: Vec<Vec<u8>> = (0..n_old as u64).map(|i| text(seed * 31 + i, 4000)).collect();
        let e = encodings(v, enc);
        let at = split.min(e.len());
        let mut new = vec![text(seed + 7, 1200), text(seed + 8, 900)];
        match place {
            // Straddling the old turn's end.
            0 => {
                old.last_mut().unwrap().extend_from_slice(&e[..at]);
                new[0].splice(0..0, e[at..].iter().copied());
            }
            // Split over two new messages.
            1 => {
                new[0].extend_from_slice(&e[..at]);
                new[1].splice(0..0, e[at..].iter().copied());
            }
            // Whole, inside a new message.
            _ => {
                let mid = new[0].len() / 2;
                new[0].splice(mid..mid, e.iter().copied());
            }
        }
        let mut all = old.clone();
        all.extend(new);
        // The old turn ended with another message, which the new turn replaces (as when an agent
        // moves a cache marker): the old messages are cached, the boundary after them is new.
        let mut first = old.clone();
        first.push(text(seed + 9, 700));
        // Three turns: the old one, the new one, and the new one again (all cached).
        let t = vec![body(&first), body(&all), body(&all)];
        let _ = agree(&s, &t);
    }
}
