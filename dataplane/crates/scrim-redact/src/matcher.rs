//! Multi-pattern matching over raw request bytes (design D2, D13).
//!
//! Two engines implement [`Engine`] with identical semantics: non-overlapping, leftmost-longest
//! matches over one fixed pattern set. That is, scanning from a position, the match that starts
//! first wins, among those the longest, and scanning resumes at its end.
//!
//! * [`AcEngine`]: Aho-Corasick (`aho-corasick` crate). Its SIMD prefilter makes it the fastest
//!   choice for small sets; it is also the reference implementation in tests.
//! * [`HashWindowEngine`]: every pattern of at least [`WINDOW`] bytes is indexed by its first
//!   eight bytes. Each eight-byte window of the input is hashed and tested against a blocked
//!   Bloom filter (one cache line word per window, two bits), so the per-byte cost does not grow
//!   with the set. A filter hit is looked up exactly in a prefix table that points into the
//!   lexicographically sorted patterns sharing that prefix; the longest pattern that is a prefix
//!   of the input there is found by binary search for the predecessor plus a walk up precomputed
//!   "longest proper prefix" links. Patterns shorter than [`WINDOW`] (short values) go to a small
//!   Aho-Corasick tier, and the two tiers are merged with the same leftmost-longest rule.

use aho_corasick::{AhoCorasick, Input, MatchKind};
use zeroize::Zeroizing;

use crate::error::BuildError;
use crate::variants::Variant;

/// Window width of the hash-window engine, in bytes.
pub(crate) const WINDOW: usize = 8;

const NONE: u32 = u32::MAX;

/// Metadata of one compiled pattern.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PatInfo {
    off: u32,
    len: u32,
    /// Index of the owning entry in the snapshot.
    pub owner: u32,
    /// Which encoded form this pattern is.
    pub variant: Variant,
}

/// The deduplicated pattern set. Pattern bytes are secret-equivalent and wiped on drop.
pub(crate) struct PatternSet {
    arena: Zeroizing<Vec<u8>>,
    pub info: Vec<PatInfo>,
}

impl PatternSet {
    pub(crate) fn new() -> Self {
        Self {
            arena: Zeroizing::new(Vec::new()),
            info: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8], owner: u32, variant: Variant) {
        let off = self.arena.len() as u32;
        self.arena.extend_from_slice(bytes);
        self.info.push(PatInfo {
            off,
            len: bytes.len() as u32,
            owner,
            variant,
        });
    }

    #[inline]
    pub(crate) fn get(&self, i: u32) -> &[u8] {
        let p = &self.info[i as usize];
        &self.arena[p.off as usize..(p.off + p.len) as usize]
    }

    pub(crate) fn len(&self) -> usize {
        self.info.len()
    }
}

/// One match: `[start, end)` in the haystack and the pattern index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Match {
    pub start: usize,
    pub end: usize,
    pub pattern: u32,
}

/// Per-search state. Lives on the caller's stack; no allocation.
#[derive(Debug, Default)]
pub(crate) struct Cursor {
    pos: usize,
    /// Cached next short-tier match (hash-window engine only). `Some(None)` means "none left".
    #[allow(clippy::option_option)]
    short: Option<Option<Match>>,
}

impl Cursor {
    /// Moves the search position forward to `pos`.
    pub(crate) fn seek(&mut self, pos: usize) {
        self.pos = self.pos.max(pos);
    }
}

/// A matching engine over a [`PatternSet`]. Implementations must return the same matches.
pub(crate) trait Engine: Send + Sync {
    /// Next non-overlapping leftmost-longest match at or after the cursor; advances the cursor.
    fn next(&self, set: &PatternSet, hay: &[u8], cur: &mut Cursor) -> Option<Match>;
}

fn build_ac<'a>(pats: impl IntoIterator<Item = &'a [u8]>) -> Result<AhoCorasick, BuildError> {
    AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(pats)
        .map_err(|_| BuildError::Automaton)
}

/// Aho-Corasick engine over the whole set.
pub(crate) struct AcEngine {
    ac: AhoCorasick,
}

impl AcEngine {
    pub(crate) fn build(set: &PatternSet) -> Result<Self, BuildError> {
        let ac = build_ac((0..set.len() as u32).map(|i| set.get(i)))?;
        Ok(Self { ac })
    }
}

impl Engine for AcEngine {
    fn next(&self, _set: &PatternSet, hay: &[u8], cur: &mut Cursor) -> Option<Match> {
        if cur.pos >= hay.len() {
            return None;
        }
        let m = self.ac.find(Input::new(hay).span(cur.pos..hay.len()))?;
        cur.pos = m.end();
        Some(Match {
            start: m.start(),
            end: m.end(),
            pattern: m.pattern().as_u32(),
        })
    }
}

/// Hash-window engine (design D13).
pub(crate) struct HashWindowEngine {
    bloom: Vec<u64>,
    word_shift: u32,
    table: PrefixTable,
    /// Pattern indices of long patterns in lexicographic order.
    sorted: Vec<u32>,
    /// For `sorted[i]`, the index in `sorted` of its longest proper prefix pattern, or `NONE`.
    parent: Vec<u32>,
    /// Short tier: patterns shorter than [`WINDOW`], with their pattern indices.
    short: Option<(AhoCorasick, Vec<u32>)>,
}

const K1: u64 = 0x9E37_79B9_7F4A_7C15;

#[inline]
fn mix(x: u64) -> u64 {
    x.wrapping_mul(K1)
}

#[inline]
fn load8(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

impl HashWindowEngine {
    pub(crate) fn build(set: &PatternSet) -> Result<Self, BuildError> {
        let mut long: Vec<u32> = Vec::new();
        let mut short: Vec<u32> = Vec::new();
        for i in 0..set.len() as u32 {
            if set.get(i).len() >= WINDOW {
                long.push(i);
            } else {
                short.push(i);
            }
        }
        long.sort_unstable_by(|&a, &b| set.get(a).cmp(set.get(b)));

        // Longest-proper-prefix links via a stack over the sorted order.
        let mut parent = vec![NONE; long.len()];
        let mut stack: Vec<u32> = Vec::new();
        for (i, &p) in long.iter().enumerate() {
            let pb = set.get(p);
            while let Some(&top) = stack.last() {
                if pb.starts_with(set.get(long[top as usize])) {
                    break;
                }
                stack.pop();
            }
            if let Some(&top) = stack.last() {
                parent[i] = top;
            }
            stack.push(i as u32);
        }

        // Prefix ranges over the sorted order.
        let mut ranges: Vec<(u64, u32, u32)> = Vec::new();
        for (i, &p) in long.iter().enumerate() {
            let k = load8(set.get(p));
            match ranges.last_mut() {
                Some(r) if r.0 == k => r.2 = i as u32 + 1,
                _ => ranges.push((k, i as u32, i as u32 + 1)),
            }
        }

        // Blocked Bloom filter: ~32 bits per distinct prefix, at least 64 words.
        let words = (ranges.len() * 32 / 64).next_power_of_two().max(64);
        let wbits = words.trailing_zeros();
        let word_shift = 64 - wbits;
        let mut bloom = vec![0u64; words];
        for &(k, _, _) in &ranges {
            let h = mix(k);
            bloom[(h >> word_shift) as usize] |= bloom_mask(h);
        }

        let table = PrefixTable::build(&ranges);
        let short = if short.is_empty() {
            None
        } else {
            let ac = build_ac(short.iter().map(|&i| set.get(i)))?;
            Some((ac, short))
        };
        Ok(Self {
            bloom,
            word_shift,
            table,
            sorted: long,
            parent,
            short,
        })
    }

    /// Longest long pattern that is a prefix of `text`, given its first eight bytes `key`.
    #[inline(never)]
    fn verify(&self, set: &PatternSet, key: u64, text: &[u8]) -> Option<u32> {
        let (lo, hi) = self.table.get(key)?;
        let bucket = &self.sorted[lo as usize..hi as usize];
        // Predecessor: last pattern <= text.
        let pp = bucket.partition_point(|&p| {
            let pb = set.get(p);
            let n = pb.len().min(text.len());
            match pb[..n].cmp(&text[..n]) {
                std::cmp::Ordering::Less => true,
                std::cmp::Ordering::Greater => false,
                std::cmp::Ordering::Equal => pb.len() <= text.len(),
            }
        });
        if pp == 0 {
            return None;
        }
        let mut c = lo + pp as u32 - 1;
        while c != NONE {
            let p = self.sorted[c as usize];
            if text.starts_with(set.get(p)) {
                return Some(p);
            }
            c = self.parent[c as usize];
        }
        None
    }

    /// First position in `[from, last]` (inclusive) where a long pattern starts.
    #[inline]
    fn scan_long(&self, set: &PatternSet, hay: &[u8], from: usize, last: usize) -> Option<Match> {
        if hay.len() < WINDOW || from > last {
            return None;
        }
        let stop = last.min(hay.len() - WINDOW);
        if from > stop {
            return None;
        }
        let region = &hay[from..stop + WINDOW];
        for (j, w) in region.windows(WINDOW).enumerate() {
            let x = u64::from_le_bytes(w.try_into().unwrap_or([0; 8]));
            let h = mix(x);
            let m = bloom_mask(h);
            if self.bloom[(h >> self.word_shift) as usize] & m == m {
                let i = from + j;
                if let Some(p) = self.verify(set, x, &hay[i..]) {
                    return Some(Match {
                        start: i,
                        end: i + set.get(p).len(),
                        pattern: p,
                    });
                }
            }
        }
        None
    }
}

#[inline]
fn bloom_mask(h: u64) -> u64 {
    (1u64 << ((h >> 20) & 63)) | (1u64 << ((h >> 26) & 63))
}

impl Engine for HashWindowEngine {
    fn next(&self, set: &PatternSet, hay: &[u8], cur: &mut Cursor) -> Option<Match> {
        if cur.pos >= hay.len() {
            return None;
        }
        let short = match &self.short {
            None => None,
            Some((ac, ids)) => match cur.short {
                Some(Some(m)) if m.start >= cur.pos => Some(m),
                Some(None) => None,
                _ => {
                    let m = ac
                        .find(Input::new(hay).span(cur.pos..hay.len()))
                        .map(|m| Match {
                            start: m.start(),
                            end: m.end(),
                            pattern: ids[m.pattern().as_usize()],
                        });
                    cur.short = Some(m);
                    m
                }
            },
        };
        let last = short.map_or(usize::MAX, |s| s.start);
        let long = self.scan_long(set, hay, cur.pos, last);
        let m = match (long, short) {
            (Some(l), Some(s)) => {
                if l.start < s.start || (l.start == s.start && l.end >= s.end) {
                    l
                } else {
                    s
                }
            }
            (Some(l), None) => l,
            (None, Some(s)) => s,
            (None, None) => {
                cur.pos = hay.len();
                return None;
            }
        };
        cur.pos = m.end;
        Some(m)
    }
}

/// Open-addressing map from an eight-byte prefix to a range of `sorted`.
struct PrefixTable {
    keys: Vec<u64>,
    lo: Vec<u32>,
    hi: Vec<u32>,
    mask: usize,
}

impl PrefixTable {
    fn build(ranges: &[(u64, u32, u32)]) -> Self {
        let cap = (ranges.len() * 2).next_power_of_two().max(16);
        let mut t = Self {
            keys: vec![0; cap],
            lo: vec![0; cap],
            hi: vec![0; cap],
            mask: cap - 1,
        };
        for &(k, lo, hi) in ranges {
            let mut s = Self::slot(k) & t.mask;
            while t.hi[s] != 0 {
                s = (s + 1) & t.mask;
            }
            t.keys[s] = k;
            t.lo[s] = lo;
            t.hi[s] = hi;
        }
        t
    }

    #[inline]
    fn slot(k: u64) -> usize {
        // Different bits from the Bloom filter's, so filter false positives spread out here.
        (k.wrapping_mul(0xD6E8_FEB8_6659_FD93) >> 32) as usize
    }

    #[inline]
    fn get(&self, k: u64) -> Option<(u32, u32)> {
        let mut s = Self::slot(k) & self.mask;
        loop {
            if self.hi[s] == 0 {
                return None;
            }
            if self.keys[s] == k {
                return Some((self.lo[s], self.hi[s]));
            }
            s = (s + 1) & self.mask;
        }
    }
}

/// Which engine a snapshot uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineKind {
    /// Aho-Corasick over all patterns.
    AhoCorasick,
    /// Hash-window prefilter with exact verification.
    HashWindow,
}

/// Engine selection in [`crate::Config`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineChoice {
    /// Aho-Corasick up to [`crate::Config::engine_threshold`] patterns, hash-window above.
    Auto,
    /// Always this engine.
    Fixed(EngineKind),
}

pub(crate) fn build_engine(
    set: &PatternSet,
    kind: EngineKind,
) -> Result<Box<dyn Engine>, BuildError> {
    Ok(match kind {
        EngineKind::AhoCorasick => Box::new(AcEngine::build(set)?),
        EngineKind::HashWindow => Box::new(HashWindowEngine::build(set)?),
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
mod tests {
    use super::*;

    fn set(pats: &[&[u8]]) -> PatternSet {
        let mut s = PatternSet::new();
        for (i, p) in pats.iter().enumerate() {
            s.push(p, i as u32, Variant::Raw);
        }
        s
    }

    fn all(e: &dyn Engine, s: &PatternSet, hay: &[u8]) -> Vec<(usize, usize, u32)> {
        let mut c = Cursor::default();
        let mut v = Vec::new();
        while let Some(m) = e.next(s, hay, &mut c) {
            v.push((m.start, m.end, m.pattern));
        }
        v
    }

    fn both(pats: &[&[u8]], hay: &[u8]) -> Vec<(usize, usize, u32)> {
        let s = set(pats);
        let a = all(&AcEngine::build(&s).unwrap(), &s, hay);
        let h = all(&HashWindowEngine::build(&s).unwrap(), &s, hay);
        assert_eq!(a, h, "engines disagree");
        a
    }

    #[test]
    fn leftmost_longest_nested_prefixes() {
        let pats: &[&[u8]] = &[b"abcdefgh", b"abcdefghij", b"abcdefghijkl", b"abcdefghxx"];
        assert_eq!(both(pats, b"..abcdefghijk.."), vec![(2, 12, 1)]);
        assert_eq!(both(pats, b"abcdefghijkl"), vec![(0, 12, 2)]);
        assert_eq!(
            both(pats, b"abcdefghxxabcdefgh"),
            vec![(0, 10, 3), (10, 18, 0)]
        );
        assert_eq!(both(pats, b"abcdefg"), vec![]);
    }

    #[test]
    fn short_tier_merges() {
        let pats: &[&[u8]] = &[b"pw12", b"pw1234567890", b"zz", b"xyzzzzzzzzzz"];
        assert_eq!(both(pats, b"pw1234567890"), vec![(0, 12, 1)]);
        assert_eq!(both(pats, b"pw123"), vec![(0, 4, 0)]);
        assert_eq!(both(pats, b"xyzzzzzzzzzz"), vec![(0, 12, 3)]);
        assert_eq!(
            both(pats, b"axyzzzzzzzzz"),
            vec![(3, 5, 2), (5, 7, 2), (7, 9, 2), (9, 11, 2)]
        );
    }

    #[test]
    fn overlap_resumes_after_end() {
        let pats: &[&[u8]] = &[b"aaaaaaaa"];
        assert_eq!(both(pats, &[b'a'; 20]), vec![(0, 8, 0), (8, 16, 0)]);
    }

    #[test]
    fn predecessor_not_prefix() {
        // The predecessor of the text is a non-prefix; the answer is up its parent chain.
        let pats: &[&[u8]] = &[b"abcdefgh", b"abcdefghm", b"abcdefghmz"];
        assert_eq!(both(pats, b"abcdefghmq"), vec![(0, 9, 1)]);
        assert_eq!(both(pats, b"abcdefghq"), vec![(0, 8, 0)]);
    }
}
