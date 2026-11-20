//! Multi-pattern matching over raw request bytes (design D2, D13).
//!
//! Two engines implement [`Engine`] with identical semantics: non-overlapping, leftmost-longest
//! matches over one fixed pattern set. That is, scanning from a position, the match that starts
//! first wins, among those the longest, and scanning resumes at its end.
//!
//! * [`AcEngine`]: Aho-Corasick (`aho-corasick` crate). Its SIMD prefilter makes it the fastest
//!   choice for small sets, but only up to 64 patterns per automaton. Sets of up to
//!   [`PACKED_MAX`] patterns use the packed Teddy searcher directly; larger ones up to
//!   [`AC_PART`]` * `[`AC_MAX_PARTS`] patterns are split and merged. With one automaton it is the
//!   reference implementation in tests.
//! * [`HashWindowEngine`]: every pattern of at least [`WINDOW`] bytes is indexed by its first
//!   eight bytes. A gram filter over the five-byte grams at offsets 0 to 3 of every pattern is
//!   probed at every fourth input position; each gram hit tests the eight-byte windows it can
//!   belong to against a blocked Bloom filter (one word per window, two bits), so the per-byte
//!   cost does not grow with the set. A filter hit is looked up exactly in a prefix table that points into the
//!   lexicographically sorted patterns sharing that prefix; the longest pattern that is a prefix
//!   of the input there is found by binary search for the predecessor plus a walk up precomputed
//!   "longest proper prefix" links. Patterns shorter than [`WINDOW`] (short values) go to a small
//!   Aho-Corasick tier, and the two tiers are merged with the same leftmost-longest rule.

use aho_corasick::{AhoCorasick, Input, MatchKind, Span, packed};
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
    /// Cached next match per Aho-Corasick part (split engine only), same encoding.
    #[allow(clippy::option_option)]
    parts: [Option<Option<Match>>; AC_MAX_PARTS],
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

/// Patterns per Aho-Corasick automaton when the set is split. The crate's SIMD (Teddy)
/// prefilter only applies up to 64 patterns; past that throughput drops by an order of
/// magnitude, so small sets are split into several automata of at most 64 patterns each and
/// their matches merged.
pub(crate) const AC_PART: usize = 64;
/// Most parts a split engine uses; larger sets get one automaton.
pub(crate) const AC_MAX_PARTS: usize = 4;

/// Most patterns searched with one packed (Teddy) searcher instead of split automata. The
/// `aho-corasick` crate's packed searcher takes up to 128 patterns; its automata only use Teddy
/// up to 64, a heuristic limit that the packed builder lets us lift. Measured on the benchmark's
/// 10-secret set (73 patterns, see the crate README): one Teddy pass beats two split automata.
pub(crate) const PACKED_MAX: usize = 128;

/// Aho-Corasick engine: one packed (Teddy) searcher for up to [`PACKED_MAX`] patterns where the
/// CPU supports it, else one automaton over the whole set, or up to [`AC_MAX_PARTS`] automata of
/// [`AC_PART`] patterns whose leftmost-longest matches are merged.
pub(crate) struct AcEngine {
    packed: Option<packed::Searcher>,
    parts: Vec<(AhoCorasick, Vec<u32>)>,
}

impl AcEngine {
    pub(crate) fn build(set: &PatternSet) -> Result<Self, BuildError> {
        let ids: Vec<u32> = (0..set.len() as u32).collect();
        if set.len() <= PACKED_MAX {
            let mut b = packed::Config::new()
                .match_kind(packed::MatchKind::LeftmostLongest)
                .heuristic_pattern_limits(false)
                .builder();
            b.extend(ids.iter().map(|&i| set.get(i)));
            if let Some(p) = b.build() {
                return Ok(Self {
                    packed: Some(p),
                    parts: Vec::new(),
                });
            }
        }
        let chunk = if set.len() <= AC_PART * AC_MAX_PARTS {
            AC_PART
        } else {
            set.len().max(1)
        };
        let parts = ids
            .chunks(chunk)
            .map(|c| Ok((build_ac(c.iter().map(|&i| set.get(i)))?, c.to_vec())))
            .collect::<Result<Vec<_>, BuildError>>()?;
        Ok(Self {
            packed: None,
            parts,
        })
    }
}

impl Engine for AcEngine {
    fn next(&self, _set: &PatternSet, hay: &[u8], cur: &mut Cursor) -> Option<Match> {
        if cur.pos >= hay.len() {
            return None;
        }
        if let Some(p) = &self.packed {
            // Pattern ids are the set's indices: the builder got them in order.
            let m = p.find_in(hay, Span::from(cur.pos..hay.len()))?;
            cur.pos = m.end();
            return Some(Match {
                start: m.start(),
                end: m.end(),
                pattern: m.pattern().as_u32(),
            });
        }
        let find = |ac: &AhoCorasick, ids: &[u32], from: usize| {
            ac.find(Input::new(hay).span(from..hay.len()))
                .map(|m| Match {
                    start: m.start(),
                    end: m.end(),
                    pattern: ids[m.pattern().as_usize()],
                })
        };
        if let [(ac, ids)] = self.parts.as_slice() {
            let m = find(ac, ids, cur.pos)?;
            cur.pos = m.end;
            return Some(m);
        }
        // Merge: the leftmost start wins, then the longest. Each part's next match stays valid
        // while it starts at or after the cursor.
        let mut best: Option<Match> = None;
        for (k, (ac, ids)) in self.parts.iter().enumerate() {
            let m = match cur.parts[k] {
                Some(Some(m)) if m.start >= cur.pos => Some(m),
                Some(None) => None,
                _ => {
                    let m = find(ac, ids, cur.pos);
                    cur.parts[k] = Some(m);
                    m
                }
            };
            if let Some(m) = m
                && best.is_none_or(|b| m.start < b.start || (m.start == b.start && m.end > b.end))
            {
                best = Some(m);
            }
        }
        let m = best?;
        cur.pos = m.end;
        Some(m)
    }
}

/// Hash-window engine (design D13).
pub(crate) struct HashWindowEngine {
    /// Filter over the five-byte grams at offsets 0 to 3 of every long pattern: probed at every
    /// fourth input position only, it says where a window check can succeed.
    gram_bloom: Vec<u64>,
    gram_shift: u32,
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

/// Probe stride and gram length of the hash-window engine's gram filter: a pattern of
/// [`WINDOW`] bytes holds a gram at each of the offsets `0..GRAM_STRIDE`.
const GRAM_STRIDE: usize = 4;
const GRAM_LEN: usize = WINDOW - GRAM_STRIDE + 1;

/// The five bytes of `b` at `p`, little-endian.
#[inline]
fn load_gram(b: &[u8], p: usize) -> u64 {
    if let Some(&[a, b, c, d, e, ..]) = b.get(p..p + 8) {
        u64::from_le_bytes([a, b, c, d, e, 0, 0, 0])
    } else {
        let mut w = [0u8; 8];
        w[..GRAM_LEN].copy_from_slice(&b[p..p + GRAM_LEN]);
        u64::from_le_bytes(w)
    }
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

        // Gram filter: ~16 bits per distinct gram, at least 64 words.
        let mut grams: Vec<u64> = long
            .iter()
            .flat_map(|&p| {
                let b = set.get(p);
                (0..GRAM_STRIDE).map(move |o| load_gram(b, o))
            })
            .collect();
        grams.sort_unstable();
        grams.dedup();
        let gwords = (grams.len() / 4).next_power_of_two().max(64);
        let gram_shift = 64 - gwords.trailing_zeros();
        let mut gram_bloom = vec![0u64; gwords];
        for &g in &grams {
            let h = mix(g);
            gram_bloom[(h >> gram_shift) as usize] |= bloom_mask(h);
        }

        let table = PrefixTable::build(&ranges);
        let short = if short.is_empty() {
            None
        } else {
            let ac = build_ac(short.iter().map(|&i| set.get(i)))?;
            Some((ac, short))
        };
        Ok(Self {
            gram_bloom,
            gram_shift,
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
        // A long pattern starting at `i` holds, at offset `(4 - i % 4) % 4`, a gram that starts
        // at a multiple of four. So grams are probed at those positions only, and each filter hit
        // checks the (up to) four windows it can belong to, in order. Probes go in order and
        // each start belongs to exactly one probe, so the first window that verifies is the
        // leftmost match.
        let mut q = from.next_multiple_of(GRAM_STRIDE);
        let q_last = stop.next_multiple_of(GRAM_STRIDE);
        while q <= q_last && q + GRAM_LEN <= hay.len() {
            let g = load_gram(hay, q);
            let h = mix(g);
            let m = bloom_mask(h);
            if self.gram_bloom[(h >> self.gram_shift) as usize] & m == m
                && let Some(found) = self.windows_at(set, hay, q, from, stop)
            {
                return Some(found);
            }
            q += GRAM_STRIDE;
        }
        None
    }

    /// The leftmost match starting in `[max(from, q - 3), min(q, stop)]`.
    #[inline(never)]
    fn windows_at(
        &self,
        set: &PatternSet,
        hay: &[u8],
        q: usize,
        from: usize,
        stop: usize,
    ) -> Option<Match> {
        for i in q.saturating_sub(GRAM_STRIDE - 1).max(from)..=q.min(stop) {
            let x = load8(&hay[i..]);
            let h = mix(x);
            let m = bloom_mask(h);
            if self.bloom[(h >> self.word_shift) as usize] & m == m
                && let Some(p) = self.verify(set, x, &hay[i..])
            {
                return Some(Match {
                    start: i,
                    end: i + set.get(p).len(),
                    pattern: p,
                });
            }
        }
        None
    }
}

/// The two filter bits of `h`. Looked up rather than shifted: a variable shift is three
/// micro-ops on x86-64 without BMI2, and this runs once per input byte.
#[inline]
fn bloom_mask(h: u64) -> u64 {
    BIT[((h >> 20) & 63) as usize] | BIT[((h >> 26) & 63) as usize]
}

static BIT: [u64; 64] = {
    let mut t = [0u64; 64];
    let mut i = 0;
    while i < 64 {
        t[i] = 1 << i;
        i += 1;
    }
    t
};

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

    /// The three Aho-Corasick forms (packed, split, one automaton) and the hash-window engine
    /// agree on sets around the packed and split limits.
    #[test]
    fn ac_forms_agree_around_limits() {
        let mut x = 0x1234_5678u64;
        let mut rnd = |n: usize| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (x >> 33) as usize % n
        };
        for count in [60usize, 64, 65, 100, 128, 129, 200, 256, 257] {
            let pats: Vec<Vec<u8>> = (0..count)
                .map(|_| (0..4 + rnd(10)).map(|_| b"abc"[rnd(3)]).collect())
                .collect();
            let refs: Vec<&[u8]> = pats.iter().map(Vec::as_slice).collect();
            let s = set(&refs);
            let hay: Vec<u8> = (0..4000).map(|_| b"abcd"[rnd(4)]).collect();
            let ac = AcEngine::build(&s).unwrap();
            let want = all(&HashWindowEngine::build(&s).unwrap(), &s, &hay);
            assert_eq!(all(&ac, &s, &hay), want, "{count} patterns");
            let ids: Vec<u32> = (0..count as u32).collect();
            let split = AcEngine {
                packed: None,
                parts: ids
                    .chunks(AC_PART)
                    .map(|c| (build_ac(c.iter().map(|&i| s.get(i))).unwrap(), c.to_vec()))
                    .collect(),
            };
            if count <= AC_PART * AC_MAX_PARTS {
                assert_eq!(all(&split, &s, &hay), want, "split, {count} patterns");
            }
            let one = AcEngine {
                packed: None,
                parts: vec![(
                    build_ac(refs.iter().copied()).unwrap(),
                    (0..count as u32).collect(),
                )],
            };
            assert_eq!(all(&one, &s, &hay), want, "one automaton, {count} patterns");
        }
    }

    #[test]
    fn predecessor_not_prefix() {
        // The predecessor of the text is a non-prefix; the answer is up its parent chain.
        let pats: &[&[u8]] = &[b"abcdefgh", b"abcdefghm", b"abcdefghmz"];
        assert_eq!(both(pats, b"abcdefghmq"), vec![(0, 9, 1)]);
        assert_eq!(both(pats, b"abcdefghq"), vec![(0, 8, 0)]);
    }
}
