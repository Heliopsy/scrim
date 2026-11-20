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

/// JSON string escaping of one level, in one of five styles: 0 minimal, 1 Go (`<>&`), 2 Python
/// (non-ASCII), 3 escaped slash, 4 every character. Invalid UTF-8 is copied as is.
pub fn json_level(s: &[u8], style: u8) -> Vec<u8> {
    fn u4(o: &mut Vec<u8>, x: u32) {
        o.extend_from_slice(format!("\\u{x:04x}").as_bytes());
    }
    let mut o = Vec::with_capacity(s.len() * 2);
    let text = std::str::from_utf8(s).ok();
    let one = |o: &mut Vec<u8>, c: char, bytes: &[u8]| {
        let mut b16 = [0u16; 2];
        match (style % 5, c) {
            (4, c) => c
                .encode_utf16(&mut b16)
                .iter()
                .for_each(|&x| u4(o, u32::from(x))),
            (_, '"') => o.extend_from_slice(b"\\\""),
            (_, '\\') => o.extend_from_slice(b"\\\\"),
            (3, '/') => o.extend_from_slice(b"\\/"),
            (1, '<' | '>' | '&' | '\u{2028}' | '\u{2029}') => u4(o, c as u32),
            (2, c) if !c.is_ascii() => c
                .encode_utf16(&mut b16)
                .iter()
                .for_each(|&x| u4(o, u32::from(x))),
            (_, c) if (c as u32) < 0x20 => u4(o, c as u32),
            _ => o.extend_from_slice(bytes),
        }
    };
    match text {
        Some(t) => {
            for c in t.chars() {
                let mut buf = [0u8; 4];
                let b = c.encode_utf8(&mut buf).as_bytes().to_vec();
                one(&mut o, c, &b);
            }
        }
        None => {
            for &b in s {
                if b < 0x80 {
                    one(&mut o, char::from(b), &[b]);
                } else {
                    o.push(b);
                }
            }
        }
    }
    o
}

/// `v` escaped once per entry of `styles`, innermost first.
pub fn json_nested(v: &[u8], styles: &[u8]) -> Vec<u8> {
    styles
        .iter()
        .fold(v.to_vec(), |acc, &st| json_level(&acc, st))
}
