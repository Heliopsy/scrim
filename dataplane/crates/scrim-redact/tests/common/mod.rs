#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    unreachable_pub,
    missing_docs,
    dead_code
)]

#[path = "../../testdata/fixtures.rs"]
pub mod fixtures;

use std::sync::Arc;

use scrim_redact::*;

pub fn keyring() -> Arc<Keyring> {
    Arc::new(Keyring::new(PlaceholderKey::new(1, &[0x42; 32]).unwrap()))
}

pub fn entries(values: &[&[u8]], class: ValueClass) -> Vec<Entry> {
    values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            Entry::new(
                i as u64 + 1,
                RefSlug::new(&format!("s{}", i + 1)).unwrap(),
                class,
                SecretValue::from_slice(v),
            )
        })
        .collect()
}

pub fn snapshot_with(values: &[&[u8]], class: ValueClass, config: &Config) -> Snapshot {
    Snapshot::build(entries(values, class), keyring(), config).unwrap()
}

pub fn snapshot(values: &[&[u8]]) -> Snapshot {
    snapshot_with(values, ValueClass::Display, &Config::default())
}

pub fn no_detectors() -> Config {
    Config {
        detectors: DetectorConfig {
            rules_enabled: false,
            ..Default::default()
        },
        ..Config::default()
    }
}

pub fn engine(kind: EngineKind) -> Config {
    Config {
        engine: EngineChoice::Fixed(kind),
        ..no_detectors()
    }
}

pub fn redact(s: &Snapshot, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    s.redactor().redact(input, &mut out).unwrap();
    out
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && memchr::memmem::find(hay, needle).is_some()
}

/// Whether `needle` occurs in `out` outside the placeholders of `values` (as [`entries`] names
/// them, under [`keyring`]). A placeholder's slug and tag can contain a value's bytes by
/// coincidence (a short value of hex digits inside the tag, a value that is part of a slug); the
/// redactor and the guard keep genuine placeholders byte for byte, so only an occurrence outside
/// one is a surviving value. The placeholders are computed here rather than parsed by the crate,
/// so a resolver that accepted too much would not hide a leak from this check.
pub fn exposed(values: &[&[u8]], out: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    let kr = keyring();
    let mut spans = Vec::new();
    for (i, v) in values.iter().enumerate() {
        let slug = RefSlug::new(&format!("s{}", i + 1)).unwrap();
        let p = placeholder_for(kr.current(), &slug, v);
        let pct = p
            .replace('\u{27e6}', "%E2%9F%A6")
            .replace('\u{27e7}', "%E2%9F%A7");
        for form in [p.as_bytes(), pct.as_bytes()] {
            spans.extend(memchr::memmem::find_iter(out, form).map(|at| (at, at + form.len())));
        }
    }
    memchr::memmem::find_iter(out, needle).any(|at| {
        !spans
            .iter()
            .any(|&(a, b)| a <= at && at + needle.len() <= b)
    })
}

pub fn ph(s: &Snapshot, value: &[u8]) -> Vec<u8> {
    let out = redact(s, value);
    assert!(
        out.starts_with("\u{27e6}".as_bytes()),
        "value is not replaced whole"
    );
    out
}
