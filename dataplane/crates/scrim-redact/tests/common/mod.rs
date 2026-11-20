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

pub fn ph(s: &Snapshot, value: &[u8]) -> Vec<u8> {
    let out = redact(s, value);
    assert!(
        out.starts_with("\u{27e6}".as_bytes()),
        "value is not replaced whole"
    );
    out
}
