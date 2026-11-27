//! The redactor's segment cache across requests (performance spec, "Redactor segment cache").
//!
//! An agent's next turn resends the conversation, so most of a request body is bytes the
//! redactor saw one request earlier. Like the guard's verdict cache ([`crate::guard_cache`]), the
//! redactor cuts a body into segments and keeps the BLAKE3 hash of every segment in which it
//! replaced nothing; a later body has only the other segments redacted, and a segment known to
//! hold nothing is copied as it is. A segment with a replacement is never remembered: it is
//! redacted again on every request. Only hashes are kept, never bytes, values or positions, and
//! the cache lives in the [`Redactor`](crate::Redactor), so a new snapshot starts empty.
//!
//! # Why the segments of a body redact as the body does
//!
//! A cut sits at `p` where the body reads `X},{Y` with `{` at `p`, `X` one of `"`, `]`, `}` and
//! `Y` one of `"`, `}`, the guard's cuts without its dump-column rule. Redacting the two sides
//! on their own gives the same output as redacting the body whole when:
//!
//! * no compiled pattern contains `,{`, so no match of a value crosses `p`. Matches are
//!   leftmost-longest and non-overlapping; with none crossing, the matches left of `p` are the
//!   same whether the matcher sees the rest or not, and the first match at or after `p` is the
//!   first match of the right side. The snapshot does not cache otherwise;
//! * a genuine placeholder already in the body, which is copied as it is, holds neither `,` nor
//!   `{`, so it lies on one side;
//! * the detectors find the same matches on each side (`Detectors::cut_ok` gives the argument
//!   per rule and the windows that rule a cut out). The entropy detector and the encoded forms
//!   read unanchored runs and turn the cache off, as do format-preserving placeholders, which
//!   the detectors must step over, and values inside other values, whose replacement asks the
//!   guard about a window around the match.
//!
//! A segment in which the redactor replaced nothing, under this snapshot, is therefore copied
//! unchanged wherever it appears again. The property tests in `redact_cache_tests.rs` check
//! that cached and whole redaction agree byte for byte.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Mutex;

use crate::detect::{Detectors, PEM_BEGIN};
use crate::guard_cache::Key;

/// Bodies shorter than this are redacted whole: hashing and lookups would cost more than they
/// save.
pub(crate) const MIN_BYTES: usize = 32 << 10;

/// Appends to `out` the cut positions of `b`, ascending: segments are `0..out[0]`,
/// `out[0]..out[1]`, ... `out[last]..b.len()`. `pem` is scratch for the private key headers.
pub(crate) fn cuts(b: &[u8], det: &Detectors, pem: &mut Vec<usize>, out: &mut Vec<usize>) {
    pem.clear();
    if det.pem() {
        pem.extend(memchr::memmem::find_iter(b, PEM_BEGIN.as_bytes()));
    }
    for m in memchr::memmem::find_iter(b, b"},{") {
        let p = m + 2;
        if m == 0 || p + 1 >= b.len() {
            continue;
        }
        if !matches!(b[m - 1], b'"' | b']' | b'}') || !matches!(b[p + 1], b'"' | b'}') {
            continue;
        }
        if det.cut_ok(b, p, pem) {
            out.push(p);
        }
    }
}

/// A segment's probe: its length and its first and last 32 bytes, mixed. Cheap, so segments the
/// cache has never held (new ones, and ones with a replacement, which it never holds) cost no
/// BLAKE3 hash; a probe that matches is confirmed by the hash.
pub(crate) fn probe(b: &[u8]) -> u64 {
    let mut x = 0x9e37_79b9_7f4a_7c15_u64 ^ b.len() as u64;
    let head = &b[..b.len().min(32)];
    let tail = &b[b.len().saturating_sub(32)..];
    for c in head.chunks(8).chain(tail.chunks(8)) {
        let mut w = [0u8; 8];
        w[..c.len()].copy_from_slice(c);
        x = (x.rotate_left(23) ^ u64::from_le_bytes(w)).wrapping_mul(0x5172_7a3c_9d1b_4e4b);
    }
    x ^ (x >> 29)
}

struct Map {
    /// Probe to the hashes held under it, each with the clock value of its last use.
    by_probe: HashMap<u64, Vec<(Key, u64)>, BuildHasherDefault<ProbeHasher>>,
    len: usize,
    clock: u64,
}

/// Probes are mixed already.
#[derive(Default)]
struct ProbeHasher(u64);

impl Hasher for ProbeHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 << 8) | u64::from(b);
        }
    }
    fn write_u64(&mut self, x: u64) {
        self.0 = x;
    }
}

/// Hashes of segments without replacements, found by probe: at most `cap` of them, the least
/// recently used out.
pub(crate) struct ProbeCache {
    cap: usize,
    map: Mutex<Map>,
}

impl ProbeCache {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            map: Mutex::new(Map {
                by_probe: HashMap::default(),
                len: 0,
                clock: 0,
            }),
        }
    }

    /// Marks in `maybe` which of `probes` the cache holds something under.
    pub(crate) fn candidates(&self, probes: &[u64], maybe: &mut Vec<bool>) {
        maybe.clear();
        let Ok(m) = self.map.lock() else {
            maybe.resize(probes.len(), false);
            return;
        };
        maybe.extend(probes.iter().map(|p| m.by_probe.contains_key(p)));
    }

    /// For each `i` with `maybe[i]`, whether `keys[i]` is held under `probes[i]`, into `known`
    /// (same length as `probes`), refreshing their use.
    pub(crate) fn confirm(
        &self,
        probes: &[u64],
        keys: &[Key],
        maybe: &[bool],
        known: &mut Vec<bool>,
    ) {
        known.clear();
        known.resize(probes.len(), false);
        let Ok(mut m) = self.map.lock() else {
            return;
        };
        m.clock += 1;
        let now = m.clock;
        for i in (0..probes.len()).filter(|&i| maybe[i]) {
            if let Some(list) = m.by_probe.get_mut(&probes[i])
                && let Some(e) = list.iter_mut().find(|e| e.0 == keys[i])
            {
                e.1 = now;
                known[i] = true;
            }
        }
    }

    /// Records `(probe, key)` pairs, evicting the least recently used beyond the cap.
    pub(crate) fn insert(&self, items: impl Iterator<Item = (u64, Key)>) {
        let Ok(mut m) = self.map.lock() else {
            return;
        };
        m.clock += 1;
        let now = m.clock;
        let mut added = 0;
        for (p, k) in items {
            let list = m.by_probe.entry(p).or_default();
            if let Some(e) = list.iter_mut().find(|e| e.0 == k) {
                e.1 = now;
            } else {
                list.push((k, now));
                added += 1;
            }
        }
        m.len += added;
        if m.len > self.cap {
            // Down to seven eighths, so eviction runs once per cap/8 insertions. Entries used
            // together share a stamp: all of the oldest stamps go.
            let keep = self.cap - self.cap / 8;
            let mut stamps: Vec<u64> = m.by_probe.values().flatten().map(|e| e.1).collect();
            let drop = stamps.len() - keep;
            let (_, &mut cut, _) = stamps.select_nth_unstable(drop - 1);
            m.by_probe.retain(|_, list| {
                list.retain(|e| e.1 > cut);
                !list.is_empty()
            });
            m.len = m.by_probe.values().map(Vec::len).sum();
        }
    }

    pub(crate) fn clear(&self) {
        if let Ok(mut m) = self.map.lock() {
            m.by_probe.clear();
            m.len = 0;
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.lock().map_or(0, |m| m.len)
    }
}
