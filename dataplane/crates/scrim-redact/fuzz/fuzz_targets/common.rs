//! Shared input decoding for the fuzz targets.
#![allow(dead_code)]

use std::sync::Arc;

use scrim_redact::*;

/// Splits `data` at the first `0xFF 0xFE` into a value list (separated by `0xFF`) and the rest.
pub fn split(data: &[u8]) -> (Vec<Vec<u8>>, &[u8]) {
    let cut = data
        .windows(2)
        .position(|w| w == [0xFF, 0xFE])
        .unwrap_or(data.len());
    let head = &data[..cut];
    let rest = if cut + 2 <= data.len() {
        &data[cut + 2..]
    } else {
        &[][..]
    };
    let mut vals: Vec<Vec<u8>> = head
        .split(|&b| b == 0xFF)
        .filter(|v| v.len() >= 4 && v.len() <= 64)
        .map(<[u8]>::to_vec)
        .take(16)
        .collect();
    vals.sort();
    vals.dedup();
    (vals, rest)
}

pub fn snapshot(
    vals: &[Vec<u8>],
    min_len: usize,
    engine: EngineChoice,
    class: ValueClass,
) -> Option<Snapshot> {
    let kr = Arc::new(Keyring::new(PlaceholderKey::new(1, &[7; 32]).ok()?));
    let entries = vals
        .iter()
        .enumerate()
        .map(|(i, v)| {
            Entry::new(
                i as u64,
                RefSlug::new(&format!("v{i}"))
                    .ok()
                    .unwrap_or_else(|| RefSlug::from_alias("v")),
                class,
                SecretValue::from_slice(v),
            )
        })
        .collect();
    let cfg = Config {
        min_len,
        engine,
        detectors: DetectorConfig {
            rules_enabled: false,
            ..Default::default()
        },
        guard_max_repairs: 10_000,
        ..Config::default()
    };
    Snapshot::build(entries, kr, &cfg).ok()
}

pub fn contains(h: &[u8], n: &[u8]) -> bool {
    !n.is_empty() && h.windows(n.len()).any(|w| w == n)
}

/// `b` split at every genuine placeholder (one that resolves), so assertions about leftover values
/// ignore text inside our own placeholders. Segments are checked one by one: joining them with
/// any separator byte could itself form a value.
pub fn outside_placeholders<'a>(s: &Snapshot, b: &'a [u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut pos = 0;
    for (at, p) in find_placeholders(b) {
        if s.resolver().resolve(&b[at..at + p.len]).is_none() {
            continue;
        }
        out.push(&b[pos..at]);
        pos = at + p.len;
    }
    out.push(&b[pos..]);
    out
}

pub fn contains_outside(s: &Snapshot, b: &[u8], n: &[u8]) -> bool {
    outside_placeholders(s, b)
        .iter()
        .any(|seg| contains(seg, n))
}
