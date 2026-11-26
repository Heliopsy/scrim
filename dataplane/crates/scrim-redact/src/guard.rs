//! The independent guard (design D4).
//!
//! The guard re-checks the exact bytes about to leave and shares no matching code with the
//! redactor. Where the redactor compiles encoded forms of every value and matches them in the raw
//! bytes, the guard does the opposite: it decodes the bytes into views and looks for the raw values
//! in each view, case-insensitively, with its own index.
//!
//! Views:
//!
//! * the bytes as they are;
//! * JSON-unescaped, once, twice and more, up to `redaction.json_depth` rounds (`\"`, `\\`, `\/`,
//!   `\n`..., `\uXXXX` with surrogate pairs), so JSON text nested in JSON strings is read the way
//!   its innermost consumer reads it;
//! * percent-decoded (`%XX`, either case);
//! * every run of base64 characters (both alphabets at once, runs may continue across line
//!   breaks), decoded at all four character alignments;
//! * every run of hex digits (any case), decoded at both alignments.
//!
//! The encoding views are derived from the once-unescaped JSON view, so `\/` inside base64 and
//! `\n` line wrapping are seen through. Matching is case-insensitive for values of at least the
//! minimum length, which also covers upper-cased and mixed-case transforms. Short values are
//! matched exactly, and only in the raw and JSON views, never as fragments.
//!
//! Index: values of at least eight bytes are sampled with five-byte grams. Any occurrence of such
//! a value contains, at one of its first four offsets, a gram that starts at a position divisible
//! by four, so the guard only probes every fourth position of a view. A probe folds bit 5 of each
//! byte (so both cases of a letter meet) and tests a blocked Bloom filter of about sixteen bits per
//! gram; a hit is verified in full, case-insensitively. Short values (four to seven bytes) are
//! indexed by their first four bytes and probed at every position.
//!
//! Cost: one class bitmap pass (base64 characters, hex digits) finds the runs and spans worth
//! decoding without touching other text byte by byte. Each base64 run is decoded once, into its
//! bit stream; the other three alignments are the same stream read from bit 6, 12 and 18, so they
//! are probed in place instead of decoded again. Values containing a backslash, which only the raw
//! bytes can show, are found from the backslashes the JSON pass records rather than by one search
//! per value. Bodies of at least [`Config::parallel_min_bytes`](crate::Config) bytes are split
//! into regions checked on scoped threads; region ends are placed where no run can cross them,
//! and the result is the same as on one thread.
//!
//! Every finding is mapped back to a byte range of the outgoing bytes and replaced with the
//! value's placeholder. The repaired bytes are checked again; a value still present means the
//! request is withheld.

use std::collections::HashMap;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::error::WithholdReason;
use crate::guard_cache::{self, Key, SegmentCache};
use crate::guard_tx::{TransformConfig, Transforms, TxScratch, derived_forms};
use crate::restore::Resolver;
use crate::secret::EntryId;

const GRAM: usize = 5;
/// Most workers one check uses.
const MAX_THREADS: usize = 8;
const STRIDE: usize = 4;
const SHORT_KEY: usize = 4;
/// Shortest base64 run worth decoding: an eight-byte value needs at least eleven characters.
const MIN_B64_RUN: usize = 11;
/// Shortest hex run worth decoding: an eight-byte value is sixteen digits.
const MIN_HEX_RUN: usize = 16;

/// In which view the guard found a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuardView {
    /// The bytes as sent.
    Raw,
    /// After one round of JSON unescaping.
    Json,
    /// After two rounds of JSON unescaping.
    JsonTwice,
    /// After three or more rounds of JSON unescaping (up to `redaction.json_depth`).
    JsonDeep,
    /// After percent-decoding.
    Url,
    /// Inside a decoded base64 run.
    Base64,
    /// Inside a decoded hex run.
    Hex,
    /// Written one unit at a time: spaced or separated characters, character and byte lists,
    /// runs of `\xNN`, `\NNN`, `&#NN;` or `%25NN` escapes.
    Separated,
    /// Inside a byte dump (`xxd`, `hexdump -C`, `od`).
    Dump,
    /// Inside a decoded base32 run.
    Base32,
    /// A fragment of a value or of its reversal: at least half of it, at least the minimum length,
    /// or shorter fragments that together cover the value.
    Fragment,
    /// After folding look-alike Unicode to its ASCII skeleton and dropping invisible characters.
    Confusable,
    /// Spelled out in words (NATO alphabet, digit and symbol words).
    Spelled,
    /// Inside a compressed document in a base64 run.
    Compressed,
}

impl GuardView {
    /// Fixed order of views, for deterministic tie-breaking.
    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::Raw => 0,
            Self::Json => 1,
            Self::JsonTwice => 2,
            Self::JsonDeep => 3,
            Self::Url => 4,
            Self::Base64 => 5,
            Self::Hex => 6,
            Self::Separated => 7,
            Self::Dump => 8,
            Self::Base32 => 9,
            Self::Fragment => 10,
            Self::Confusable => 11,
            Self::Spelled => 12,
            Self::Compressed => 13,
        }
    }
}

/// One value found by the guard. Carries the entry id, never the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardFinding {
    /// The entry whose value was found.
    pub entry: EntryId,
    /// Where it was found.
    pub view: GuardView,
}

/// What the guard decided about a request body.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict<'s> {
    /// No known value present. Send the bytes as they are.
    Clean,
    /// Known values were present and have been replaced. Send `bytes` instead, and record an audit
    /// entry per finding.
    Repaired {
        /// The repaired body.
        bytes: &'s [u8],
        /// What was found.
        findings: &'s [GuardFinding],
    },
    /// Known values are present and could not be removed. Refuse the request.
    Withhold(WithholdReason),
}

struct GValue {
    value: Zeroizing<Vec<u8>>,
    owner: u32,
}

/// Input to [`Guard::build`]: one known value with its placeholder.
pub(crate) struct GuardInput<'a> {
    pub value: &'a [u8],
    pub entry: EntryId,
    pub placeholder: &'a [u8],
}

/// The guard. Immutable after build, shared between threads.
pub struct Guard {
    /// Per byte, the longest value containing it (both cases for letters of long values).
    byte_width: Vec<u32>,
    /// First two bytes of every value (both cases for long values).
    starts: PairSet,
    long: Vec<GValue>,
    short: Vec<GValue>,
    grams: GramIndex,
    short_bits: Vec<u64>,
    short_keys: HashMap<u32, (u32, u32)>,
    short_cands: Vec<u32>,
    placeholders: Vec<Box<[u8]>>,
    entry_ids: Vec<EntryId>,
    max_repairs: usize,
    /// Rounds of JSON unescaping, at least 2.
    json_depth: usize,
    resolver: Arc<Resolver>,
    /// Values containing a backslash, bucketed by the byte after their first backslash, or for
    /// values ending in it, 256 plus the byte before. `bs_index[k]..bs_index[k + 1]` indexes
    /// `bs_cands`.
    bs_index: Vec<u32>,
    bs_cands: Vec<BsCand>,
    /// Workers per check at most (1: never parallel), and the shortest view checked in parallel.
    threads: usize,
    parallel_min: usize,
    /// Per class set of a run (`CLASS_MASK` bits): whether it contains the classes of some
    /// value's inner base64 form. A run for which this is false cannot carry any value.
    b64_mask_ok: [bool; 64],
    /// Some value's hex form has no digit, so hex runs without digits must be decoded too.
    hex_needs_digit_free: bool,
    /// Transform decoders and the fragment index.
    tx: Transforms,
    /// Segments found clean in earlier checks (`None`: off, or a value contains `,{`).
    cache: Option<SegmentCache>,
    /// The guard as it was before the single-decode rewrite, built from the same inputs.
    #[cfg(any(test, feature = "oracle"))]
    oracle: crate::guard_oracle::OracleGuard,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("long_values", &self.long.len())
            .field("short_values", &self.short.len())
            .finish_non_exhaustive()
    }
}

/// Reusable buffers for [`Guard::check`]. One per thread or request; never shared.
#[derive(Default)]
pub struct GuardScratch {
    json1: View,
    json2: View,
    /// Views after three and more rounds of JSON unescaping.
    deeper: Vec<View>,
    url: View,
    /// One per worker; the first is used by the calling thread.
    parts: Vec<Part>,
    regions: Vec<Region>,
    bs_all: Vec<(usize, usize, u32)>,
    view_hits: Vec<(usize, usize, u32)>,
    hits: Vec<RawHit>,
    findings: Vec<GuardFinding>,
    repaired: Vec<u8>,
    recheck: Vec<RawHit>,
    tx: TxScratch,
    /// Hits of the transform views, before the fragment rule.
    tx_hits: Vec<RawHit>,
    /// Segment cuts, keys and cache answers of the body being checked.
    seg_cuts: Vec<usize>,
    seg_keys: Vec<Key>,
    seg_known: Vec<bool>,
}

/// Buffers of one worker, which checks one region of the body.
#[derive(Default)]
struct Part {
    run_pos: Vec<u32>,
    run_chars: Vec<u8>,
    runs: Vec<RunRec>,
    hex_spans: Vec<(u32, u32)>,
    b64m: Vec<u64>,
    hexm: Vec<u64>,
    decoded: Vec<u8>,
    view_hits: Vec<(usize, usize, u32)>,
    /// Hits in raw coordinates.
    hits: Vec<RawHit>,
    /// Every occurrence of a value containing a backslash (start, end, value index), before the
    /// non-overlap rule.
    bs_hits: Vec<(usize, usize, u32)>,
    /// This part's piece of the JSON view, while unescaping in parallel.
    json: View,
}

/// What one worker checks. Ranges are half-open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Region {
    /// Start positions of occurrences in the scanned view; `.0` is a multiple of `STRIDE`.
    scan: (usize, usize),
    /// Bytes of the scanned view searched for base64 runs and hex spans. Both ends are at a byte
    /// that is no base64 character and no line break (or at the ends), so no run crosses them.
    runs: (usize, usize),
    /// Indices into the JSON view's backslash list.
    bs: (usize, usize),
    /// Indices into the JSON view's unit list.
    units: (usize, usize),
}

impl std::fmt::Debug for GuardScratch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuardScratch(<redacted>)")
    }
}

impl GuardScratch {
    /// Empty scratch space.
    pub fn new() -> Self {
        Self::default()
    }

    /// Per segment of the last body checked with the cache, whether it was known clean.
    #[cfg(test)]
    pub(crate) fn segments_known(&self) -> &[bool] {
        &self.seg_known
    }

    /// Wipes every buffer that may have held request bytes. Capacity is kept.
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.json1.bytes.zeroize();
        self.json2.bytes.zeroize();
        for v in &mut self.deeper {
            v.bytes.zeroize();
        }
        self.url.bytes.zeroize();
        for p in &mut self.parts {
            p.run_chars.zeroize();
            p.decoded.zeroize();
            p.json.bytes.zeroize();
        }
        self.repaired.zeroize();
        self.tx.wipe();
    }
}

#[derive(Clone, Copy)]
struct RawHit {
    start: usize,
    end: usize,
    owner: u32,
    view: GuardView,
}

/// A decoded view and its map back to the parent bytes.
#[derive(Default)]
struct View {
    bytes: Vec<u8>,
    /// Decoded units, sorted by `view` position.
    units: Vec<Unit>,
    /// Positions of every backslash in the parent, ascending (JSON views only).
    backslashes: Vec<u32>,
}

#[derive(Clone, Copy)]
struct Unit {
    view: u32,
    vlen: u32,
    parent: u32,
    plen: u32,
}

impl View {
    fn clear(&mut self) {
        self.bytes.clear();
        self.units.clear();
        self.backslashes.clear();
    }

    fn map_start(&self, a: usize) -> usize {
        let k = self.units.partition_point(|u| u.view as usize <= a);
        if k == 0 {
            return a;
        }
        let u = self.units[k - 1];
        let (uv, ul) = (u.view as usize, u.vlen as usize);
        if a < uv + ul {
            u.parent as usize
        } else {
            u.parent as usize + u.plen as usize + (a - uv - ul)
        }
    }

    fn map_end(&self, b: usize) -> usize {
        if b == 0 {
            return 0;
        }
        let q = b - 1;
        let k = self.units.partition_point(|u| u.view as usize <= q);
        if k > 0 {
            let u = self.units[k - 1];
            if q < u.view as usize + u.vlen as usize {
                return u.parent as usize + u.plen as usize;
            }
        }
        self.map_start(q) + 1
    }

    fn map(&self, a: usize, b: usize) -> (usize, usize) {
        (self.map_start(a), self.map_end(b))
    }
}

/// A gram's index key: five bytes, little-endian, with bit 5 of every byte set. ASCII letters of
/// either case get the same key. So do a few other byte pairs that differ only in bit 5, which
/// costs a candidate now and then and nothing else: candidates are verified in full.
#[inline]
fn gram_key(x: u64) -> u64 {
    (x | 0x20_2020_2020) & 0xFF_FFFF_FFFF
}

/// Eight bytes of `b` from `p`, little-endian, zero-filled past the end.
#[inline]
fn load_le(b: &[u8], p: usize) -> u64 {
    if let Some(w) = b.get(p..).and_then(<[u8]>::first_chunk::<8>) {
        u64::from_le_bytes(*w)
    } else {
        let mut w = [0u8; 8];
        let rest = b.get(p..).unwrap_or(&[]);
        w[..rest.len()].copy_from_slice(rest);
        u64::from_le_bytes(w)
    }
}

/// The gram index of the long values: a blocked Bloom filter (one word, two bits, about
/// sixteen bits per key) in front of an open-addressing table of keys and candidates.
struct GramIndex {
    bloom: Vec<u64>,
    /// `64 - log2(bloom.len())`.
    bloom_shift: u32,
    /// (key, candidates start, candidates end); `u64::MAX` marks an empty slot (keys have 40 bits).
    slots: Vec<(u64, u32, u32)>,
    /// `64 - log2(slots.len())`.
    slot_shift: u32,
    /// (long value index, offset of the gram in the value).
    cands: Vec<(u32, u8)>,
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

impl GramIndex {
    const EMPTY: u64 = u64::MAX;

    fn build(mut pairs: Vec<(u64, u32, u8)>) -> Self {
        pairs.sort_unstable();
        pairs.dedup();
        let mut keys = Vec::new();
        let mut cands = Vec::with_capacity(pairs.len());
        let mut i = 0;
        while i < pairs.len() {
            let k = pairs[i].0;
            let lo = cands.len() as u32;
            while i < pairs.len() && pairs[i].0 == k {
                cands.push((pairs[i].1, pairs[i].2));
                i += 1;
            }
            keys.push((k, lo, cands.len() as u32));
        }
        let words = (keys.len() / 4).next_power_of_two().max(64);
        let bloom_shift = 64 - words.trailing_zeros();
        let nslots = (keys.len() * 2).next_power_of_two().max(64);
        let slot_shift = 64 - nslots.trailing_zeros();
        let mut g = Self {
            bloom: vec![0; words],
            bloom_shift,
            slots: vec![(Self::EMPTY, 0, 0); nslots],
            slot_shift,
            cands,
        };
        for &(k, lo, hi) in &keys {
            let h = Self::hash(k);
            g.bloom[(h >> g.bloom_shift) as usize] |= g.bits(h);
            let mask = g.slots.len() - 1;
            let mut at = (h >> g.slot_shift) as usize;
            while g.slots[at].0 != Self::EMPTY {
                at = (at + 1) & mask;
            }
            g.slots[at] = (k, lo, hi);
        }
        g
    }

    #[inline]
    fn hash(k: u64) -> u64 {
        k.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    }

    /// The two filter bits of `h`, taken from just below the word index (`bloom_shift >= 44`).
    /// Looked up in a table: variable shifts cost three micro-ops each on x86-64 without BMI2.
    #[inline]
    fn bits(&self, h: u64) -> u64 {
        BIT[((h >> (self.bloom_shift - 6)) & 63) as usize]
            | BIT[((h >> (self.bloom_shift - 12)) & 63) as usize]
    }

    /// Whether `k` may be a key. Never false for a key.
    #[inline]
    fn maybe(&self, k: u64) -> bool {
        let h = Self::hash(k);
        let m = self.bits(h);
        self.bloom[(h >> self.bloom_shift) as usize] & m == m
    }

    /// The candidates of `k`.
    fn get(&self, k: u64) -> &[(u32, u8)] {
        let mask = self.slots.len() - 1;
        let mut at = (Self::hash(k) >> self.slot_shift) as usize;
        loop {
            let (key, lo, hi) = self.slots[at];
            if key == k {
                return &self.cands[lo as usize..hi as usize];
            }
            if key == Self::EMPTY {
                return &[];
            }
            at = (at + 1) & mask;
        }
    }
}

#[inline]
fn short_key(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}

#[inline]
fn short_bit(k: u32) -> usize {
    (k.wrapping_mul(0x9E37_79B1) >> 16) as usize
}

impl Guard {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build(
        inputs: &[GuardInput<'_>],
        min_len: usize,
        max_repairs: usize,
        json_depth: usize,
        (threads, parallel_min): (usize, usize),
        cache_entries: usize,
        resolver: Arc<Resolver>,
        tx_cfg: &TransformConfig,
    ) -> Self {
        let mut long = Vec::new();
        let mut short = Vec::new();
        let mut placeholders = Vec::with_capacity(inputs.len());
        let entry_ids = inputs.iter().map(|i| i.entry).collect();
        for (i, inp) in inputs.iter().enumerate() {
            placeholders.push(inp.placeholder.into());
            let gv = GValue {
                value: Zeroizing::new(inp.value.to_vec()),
                owner: i as u32,
            };
            if inp.value.len() >= min_len.max(8) {
                long.push(gv);
                derived_forms(inp.value, tx_cfg, |f| {
                    long.push(GValue {
                        value: f,
                        owner: i as u32,
                    });
                });
            } else if inp.value.len() >= SHORT_KEY {
                short.push(gv);
            }
        }

        // Gram index over long values.
        let mut pairs: Vec<(u64, u32, u8)> = Vec::with_capacity(long.len() * STRIDE);
        for (vi, v) in long.iter().enumerate() {
            for off in 0..STRIDE {
                pairs.push((gram_key(load_le(&v.value, off)), vi as u32, off as u8));
            }
        }
        let grams = GramIndex::build(pairs);

        // Exact four-byte index over short values.
        let mut sp: Vec<(u32, u32)> = short
            .iter()
            .enumerate()
            .map(|(i, v)| (short_key(&v.value, 0), i as u32))
            .collect();
        sp.sort_unstable();
        let mut short_keys = HashMap::new();
        let mut short_cands = Vec::with_capacity(sp.len());
        let mut short_bits = vec![0u64; 1 << 10];
        let mut i = 0;
        while i < sp.len() {
            let k = sp[i].0;
            let lo = short_cands.len() as u32;
            while i < sp.len() && sp[i].0 == k {
                short_cands.push(sp[i].1);
                i += 1;
            }
            short_keys.insert(k, (lo, short_cands.len() as u32));
            let b = short_bit(k);
            short_bits[b >> 6] |= 1 << (b & 63);
        }

        // Values containing a backslash, keyed by the byte after the first one.
        let mut bs: Vec<(usize, BsCand)> = Vec::new();
        for (i, v) in long.iter().chain(short.iter()).enumerate() {
            if let Some(j) = memchr::memchr(b'\\', &v.value) {
                // Values are at least four bytes long, so one of the neighbours exists.
                let key = match v.value.get(j + 1) {
                    Some(&c) => usize::from(c),
                    None => 256 + usize::from(v.value[j - 1]),
                };
                let l = v.value.len();
                let cand = BsCand {
                    value: i as u32,
                    first_bs: j as u32,
                    len: l as u32,
                    ends: [v.value[0], v.value[l - 1]],
                };
                bs.push((key, cand));
            }
        }
        bs.sort_by_key(|&(key, _)| key);
        let mut bs_index = vec![0u32; 513];
        for &(key, ..) in &bs {
            bs_index[key + 1] += 1;
        }
        for k in 1..bs_index.len() {
            bs_index[k] += bs_index[k - 1];
        }
        let bs_cands = bs.iter().map(|&(_, c)| c).collect();
        let mut masks: Vec<u8> = long
            .iter()
            .flat_map(|v| (0..3).map(|k| b64_inner_mask(&v.value, k)))
            .collect();
        // Both alphabets share the class of their two symbols, so one mask covers both.
        masks.sort_unstable();
        masks.dedup();
        let b64_masks: Vec<u8> = masks
            .iter()
            .copied()
            .filter(|&m| !masks.iter().any(|&o| o != m && o & m == o))
            .collect();
        let hex_needs_digit_free = long
            .iter()
            .any(|v| v.value.iter().all(|&b| b >> 4 >= 10 && b & 15 >= 10));
        let tx = Transforms::build(
            inputs
                .iter()
                .enumerate()
                .filter(|(_, inp)| inp.value.len() >= min_len.max(8))
                .map(|(i, inp)| (inp.value, i as u32)),
            min_len,
            tx_cfg,
        );
        let mut byte_width = vec![0u32; 256];
        let mut starts = PairSet::new();
        for (v, fold) in long
            .iter()
            .map(|v| (v, true))
            .chain(short.iter().map(|v| (v, false)))
        {
            for &c in v.value.iter() {
                let l = v.value.len() as u32;
                for c in [
                    c,
                    if fold { c.to_ascii_lowercase() } else { c },
                    if fold { c.to_ascii_uppercase() } else { c },
                ] {
                    let w = &mut byte_width[usize::from(c)];
                    *w = (*w).max(l);
                }
            }
            let (a, b) = (v.value[0], v.value[1]);
            if fold {
                for x in [a.to_ascii_lowercase(), a.to_ascii_uppercase()] {
                    for y in [b.to_ascii_lowercase(), b.to_ascii_uppercase()] {
                        starts.insert(x, y);
                    }
                }
            } else {
                starts.insert(a, b);
            }
        }
        // A value with `,{` could cross a segment cut (see guard_cache).
        let cache = (cache_entries > 0
            && !long
                .iter()
                .chain(short.iter())
                .any(|v| memchr::memmem::find(&v.value, b",{").is_some()))
        .then(|| SegmentCache::new(cache_entries));
        Self {
            #[cfg(any(test, feature = "oracle"))]
            oracle: crate::guard_oracle::OracleGuard::build(
                inputs,
                min_len,
                max_repairs,
                json_depth,
                resolver.clone(),
                tx_cfg,
            ),
            byte_width,
            starts,
            long,
            short,
            grams,
            short_bits,
            short_keys,
            short_cands,
            placeholders,
            entry_ids,
            max_repairs,
            json_depth: json_depth.max(2),
            resolver,
            bs_index,
            bs_cands,
            threads: threads.clamp(1, MAX_THREADS),
            parallel_min,
            b64_mask_ok: std::array::from_fn(|mask| b64_masks.iter().any(|&m| m & mask as u8 == m)),
            hex_needs_digit_free,
            tx,
            cache,
        }
    }

    /// Whether the verdict cache is in use for this guard.
    pub fn caches(&self) -> bool {
        self.cache.is_some()
    }

    /// Forgets every segment found clean, so the next check sees every body for the first time
    /// (benchmarks of the first request of a conversation).
    pub fn clear_cache(&self) {
        if let Some(c) = &self.cache {
            c.clear();
        }
    }

    /// With the verdict cache: whether `bytes` is clean, checking only the segments not found
    /// clean before, and remembering the new ones when the body is clean. `false` means "not
    /// shown clean": the caller runs the whole check, which decides.
    fn clean_by_segments(&self, cache: &SegmentCache, bytes: &[u8], s: &mut GuardScratch) -> bool {
        let mut cuts = std::mem::take(&mut s.seg_cuts);
        let mut keys = std::mem::take(&mut s.seg_keys);
        let mut known = std::mem::take(&mut s.seg_known);
        cuts.clear();
        keys.clear();
        guard_cache::cuts(bytes, &mut cuts);
        let seg = |i: usize| {
            let a = if i == 0 { 0 } else { cuts[i - 1] };
            let b = cuts.get(i).copied().unwrap_or(bytes.len());
            (a, b)
        };
        let n = cuts.len() + 1;
        keys.extend((0..n).map(|i| {
            let (a, b) = seg(i);
            *blake3::hash(&bytes[a..b]).as_bytes()
        }));
        cache.lookup(&keys, &mut known);
        let mut clean = true;
        let mut hits = std::mem::take(&mut s.recheck);
        let mut i = 0;
        while clean && i < n {
            if known[i] {
                i += 1;
                continue;
            }
            // A run of segments not seen before, checked as one piece.
            let a = seg(i).0;
            while i < n && !known[i] {
                i += 1;
            }
            let b = seg(i - 1).1;
            hits.clear();
            self.collect(&bytes[a..b], s, &mut hits);
            // Short fragments of a value may be completed by pieces in cached parts: only the
            // whole check sees them together, and no part holding one is cached.
            clean = hits.is_empty() && !s.tx.saw_short();
        }
        s.recheck = hits;
        if clean && known.iter().any(|k| !k) {
            cache.insert(
                keys.iter()
                    .zip(&known)
                    .filter(|(_, k)| !**k)
                    .map(|(k, _)| *k),
            );
        }
        s.seg_cuts = cuts;
        s.seg_keys = keys;
        s.seg_known = known;
        clean
    }

    /// Checks `bytes`, the exact body about to be sent.
    ///
    /// Returns [`Verdict::Clean`], or [`Verdict::Repaired`] with the repaired body in `scratch`,
    /// or [`Verdict::Withhold`]. Never allocates once `scratch` has grown to the body size.
    pub fn check<'s>(&self, bytes: &[u8], scratch: &'s mut GuardScratch) -> Verdict<'s> {
        if let Some(cache) = &self.cache
            && bytes.len() >= guard_cache::MIN_BYTES
            && self.clean_by_segments(cache, bytes, scratch)
        {
            return Verdict::Clean;
        }
        self.check_whole(bytes, scratch)
    }

    /// [`Guard::check`] without the verdict cache: every byte is checked.
    pub fn check_whole<'s>(&self, bytes: &[u8], scratch: &'s mut GuardScratch) -> Verdict<'s> {
        let mut hits = std::mem::take(&mut scratch.hits);
        hits.clear();
        self.collect(bytes, scratch, &mut hits);
        if hits.is_empty() {
            scratch.hits = hits;
            return Verdict::Clean;
        }
        // The view breaks ties, so the finding reported for a range does not depend on the
        // order hits were collected in.
        hits.sort_unstable_by_key(|h| (h.start, std::cmp::Reverse(h.end), h.owner, h.view.rank()));
        hits.dedup_by(|b, a| a.start == b.start && a.end == b.end && a.owner == b.owner);
        scratch.findings.clear();
        let mut repaired = std::mem::take(&mut scratch.repaired);
        repaired.clear();
        repaired.reserve(bytes.len());
        let mut pos = 0;
        let mut i = 0;
        let mut merged = 0usize;
        while i < hits.len() {
            let h = hits[i];
            let mut end = h.end;
            scratch.findings.push(GuardFinding {
                entry: self.entry_of(h.owner),
                view: h.view,
            });
            i += 1;
            while i < hits.len() && hits[i].start < end {
                end = end.max(hits[i].end);
                scratch.findings.push(GuardFinding {
                    entry: self.entry_of(hits[i].owner),
                    view: hits[i].view,
                });
                i += 1;
            }
            let start = h.start.max(pos);
            repaired.extend_from_slice(&bytes[pos..start]);
            repaired.extend_from_slice(&self.placeholders[h.owner as usize]);
            pos = end.max(pos);
            merged += 1;
        }
        repaired.extend_from_slice(&bytes[pos..]);
        scratch.hits = hits;
        if merged > self.max_repairs {
            scratch.repaired = repaired;
            return Verdict::Withhold(WithholdReason::TooManyInterventions);
        }
        // The repair must leave nothing behind.
        let mut again = std::mem::take(&mut scratch.recheck);
        again.clear();
        self.collect(&repaired, scratch, &mut again);
        let still = !again.is_empty();
        scratch.recheck = again;
        scratch.repaired = repaired;
        if still {
            return Verdict::Withhold(WithholdReason::RepairIncomplete);
        }
        Verdict::Repaired {
            bytes: &scratch.repaired,
            findings: &scratch.findings,
        }
    }

    /// Whether [`Guard::check`] and the guard as it was before the single-decode rewrite reach
    /// the same verdict on `bytes`: same outcome, same repaired bytes, same findings. Only with
    /// the `oracle` feature (tests and fuzzing).
    #[cfg(any(test, feature = "oracle"))]
    #[doc(hidden)]
    pub fn agrees_with_oracle(&self, bytes: &[u8]) -> bool {
        let mut a = GuardScratch::new();
        let mut b = crate::guard_oracle::OracleScratch::new();
        self.check(bytes, &mut a) == self.oracle.check(bytes, &mut b)
    }

    /// Every occurrence the guard finds in `bytes`, as `(start, end, owner)` over `bytes`, before
    /// any repair; `owner` is the index of the value in the inputs [`Guard::build`] was given.
    /// The redactor asks this around a nested value's match (`Redactor::widen`); it reads the
    /// input there, never the outgoing bytes, which [`Guard::check`] still checks on its own.
    pub(crate) fn spans(
        &self,
        bytes: &[u8],
        scratch: &mut GuardScratch,
        out: &mut Vec<(usize, usize, u32)>,
    ) {
        let mut hits = std::mem::take(&mut scratch.hits);
        hits.clear();
        self.collect(bytes, scratch, &mut hits);
        out.extend(hits.iter().map(|h| (h.start, h.end, h.owner)));
        scratch.hits = hits;
    }

    fn entry_of(&self, owner: u32) -> EntryId {
        self.entry_ids[owner as usize]
    }

    /// All hits in every view, in raw coordinates, minus those inside genuine placeholders.
    fn collect(&self, bytes: &[u8], s: &mut GuardScratch, out: &mut Vec<RawHit>) {
        let from = out.len();
        self.collect_views(bytes, s, out);
        if out.len() > from {
            let mut k = from;
            while k < out.len() {
                if self
                    .resolver
                    .covering(bytes, out[k].start, out[k].end)
                    .is_some()
                {
                    out.swap_remove(k);
                } else {
                    k += 1;
                }
            }
        }
    }

    fn collect_views(&self, bytes: &[u8], s: &mut GuardScratch, out: &mut Vec<RawHit>) {
        if self.long.is_empty() && self.short.is_empty() {
            return;
        }
        let GuardScratch {
            json1,
            json2,
            deeper,
            url,
            parts,
            regions,
            bs_all,
            view_hits: vh,
            tx,
            tx_hits,
            ..
        } = s;
        let has_json1 = has_json_escape(bytes);
        if has_json1 {
            // The unescaped view is what the provider reads. It is scanned fully, and the raw-only
            // occurrences are covered precisely: values containing a backslash, and values
            // starting inside an escape sequence (`\token` reads as TAB + `oken` once unescaped).
            self.unescape(bytes, json1, parts);
        } else {
            json1.clear();
        }
        // The encoding views are taken over the once-unescaped bytes.
        let base: &[u8] = if has_json1 { &json1.bytes } else { bytes };
        let json1: &View = json1;

        self.split(base, json1, regions);
        if parts.len() < regions.len() {
            parts.resize_with(regions.len(), Part::default);
        }
        let work =
            |part: &mut Part, r: Region| self.check_region(bytes, base, has_json1, json1, r, part);
        // The transform views take the whole once-unescaped view on the calling thread (their
        // decoders on threads of their own when the body is split), so no region cut can split
        // a reversed, spaced or dumped value.
        let parallel = regions.len() > 1;
        let transforms = |tx: &mut TxScratch, tx_hits: &mut Vec<RawHit>| {
            tx_hits.clear();
            if self.long.is_empty() {
                return;
            }
            self.tx.collect(
                base,
                tx,
                &|v, o| self.scan(v, false, o),
                &mut |a, b, owner, view| {
                    let (start, end) = if has_json1 { json1.map(a, b) } else { (a, b) };
                    tx_hits.push(RawHit {
                        start,
                        end,
                        owner,
                        view,
                    });
                },
                parallel,
            );
        };
        if regions.len() == 1 {
            work(&mut parts[0], regions[0]);
            self.second_views(has_json1, base, json1, json2, deeper, url, vh, out);
            transforms(tx, tx_hits);
        } else {
            // Every region on a worker; the calling thread takes the transform views, the
            // longest single piece of work.
            std::thread::scope(|sc| {
                for (part, &r) in parts.iter_mut().zip(regions.iter()) {
                    sc.spawn(move || work(part, r));
                }
                transforms(tx, tx_hits);
                self.second_views(has_json1, base, json1, json2, deeper, url, vh, out);
            });
        }

        // Backslash values: leftmost occurrences first, without overlap, per value.
        bs_all.clear();
        for part in &parts[..regions.len()] {
            out.extend_from_slice(&part.hits);
            bs_all.extend_from_slice(&part.bs_hits);
        }
        bs_all.sort_unstable_by_key(|&(a, _, o)| (o, a));
        let mut last: Option<(u32, usize)> = None;
        for &(a, b, o) in bs_all.iter() {
            if let Some((lo, le)) = last
                && lo == o
                && a < le
            {
                continue;
            }
            last = Some((o, b));
            out.push(RawHit {
                start: a,
                end: b,
                owner: self.value(o).owner,
                view: GuardView::Raw,
            });
        }

        // Transform hits; a fragment inside a hit already found adds nothing.
        let found = out.len();
        for h in tx_hits.iter() {
            if h.view == GuardView::Fragment
                && out[..found]
                    .iter()
                    .any(|o| o.start <= h.start && h.end <= o.end)
            {
                continue;
            }
            out.push(*h);
        }
    }

    /// [`json_unescape`] of `src` into `out`, on several threads for a large body: the body is
    /// cut where no backslash is within the eleven bytes before the cut, so no escape sequence
    /// (at most twelve bytes) and none of its look-ahead crosses it, each piece is unescaped on
    /// its own and the pieces are joined.
    fn unescape(&self, src: &[u8], out: &mut View, parts: &mut Vec<Part>) {
        let n = src.len();
        let k = self.workers(n);
        let mut cuts = [0usize; MAX_THREADS + 1];
        let mut m = 1;
        for r in 1..k {
            let from = (r * n / k).max(cuts[m - 1] + 12);
            let to = ((r + 1) * n / k).min(n);
            let mut q = from;
            while q < to {
                match memchr::memrchr(b'\\', &src[q - 11..q]) {
                    // The next candidate is just past that backslash's reach.
                    Some(at) => q = q - 11 + at + 12,
                    None => break,
                }
            }
            if q < to {
                cuts[m] = q;
                m += 1;
            }
        }
        cuts[m] = n;
        if m == 1 {
            json_unescape(src, out);
            return;
        }
        if parts.len() < m {
            parts.resize_with(m, Part::default);
        }
        std::thread::scope(|sc| {
            let (first, rest) = parts.split_at_mut(1);
            for (r, part) in rest[..m - 1].iter_mut().enumerate() {
                let piece = &src[cuts[r + 1]..cuts[r + 2]];
                sc.spawn(move || json_unescape(piece, &mut part.json));
            }
            json_unescape(&src[..cuts[1]], &mut first[0].json);
        });
        out.clear();
        for (r, part) in parts[..m].iter().enumerate() {
            let (view0, parent0) = (out.bytes.len() as u32, cuts[r] as u32);
            let v = &part.json;
            out.bytes.extend_from_slice(&v.bytes);
            out.units.extend(v.units.iter().map(|u| Unit {
                view: u.view + view0,
                parent: u.parent + parent0,
                ..*u
            }));
            out.backslashes
                .extend(v.backslashes.iter().map(|&b| b + parent0));
        }
    }

    /// The views derived from the JSON view near its units: JSON unescaped twice, and
    /// percent-decoded. Both are small unless the body is full of escapes.
    #[allow(clippy::too_many_arguments)]
    fn second_views(
        &self,
        has_json1: bool,
        base: &[u8],
        json1: &View,
        json2: &mut View,
        deeper: &mut Vec<View>,
        url: &mut View,
        vh: &mut Vec<(usize, usize, u32)>,
        out: &mut Vec<RawHit>,
    ) {
        // json2 is round two; more follow when the depth goes past it.
        if has_json1 && self.json_escapes_matter(&json1.bytes, self.json_depth > 2) {
            json_unescape(&json1.bytes, json2);
            vh.clear();
            self.scan_near_units(json2, true, vh);
            push_mapped(out, vh, GuardView::JsonTwice, |a, b| {
                let (a, b) = json2.map(a, b);
                json1.map(a, b)
            });
            if self.json_depth > 2 {
                self.scan_deeper(json1, json2, deeper, vh, out);
            }
        }
        if !self.long.is_empty() && has_percent_escape(base) {
            url_decode(base, url);
            vh.clear();
            self.scan_near_units(url, false, vh);
            push_mapped(out, vh, GuardView::Url, |a, b| {
                let (a, b) = url.map(a, b);
                if has_json1 { json1.map(a, b) } else { (a, b) }
            });
        }
    }

    /// Workers for a view of `n` bytes: one below `parallel_min`, else up to `threads`, each
    /// with at least `parallel_min / threads` bytes.
    fn workers(&self, n: usize) -> usize {
        if self.threads <= 1 || n < self.parallel_min {
            1
        } else {
            let chunk = (self.parallel_min / self.threads).max(1);
            self.threads.min(n / chunk).max(1)
        }
    }

    /// Splits the work on `base` into regions, one per worker.
    fn split(&self, base: &[u8], json1: &View, out: &mut Vec<Region>) {
        out.clear();
        let n = base.len();
        let k = self.workers(n);
        // Run boundaries: the first byte at or after each target that no run can cross.
        let mut cuts = [0usize; MAX_THREADS + 1];
        let mut m = 1;
        for r in 1..k {
            let from = (r * n / k).max(cuts[m - 1] + 1);
            let to = ((r + 1) * n / k).min(n);
            if let Some(q) = (from..to).find(|&q| {
                let c = base[q];
                is_b64_char(c) == 0 && c != b'\n' && c != b'\r'
            }) {
                cuts[m] = q;
                m += 1;
            }
        }
        cuts[m] = n;
        let (nb, nu) = (json1.backslashes.len(), json1.units.len());
        for r in 0..m {
            let scan0 = cuts[r] / STRIDE * STRIDE;
            let scan1 = if r + 1 == m {
                n
            } else {
                cuts[r + 1] / STRIDE * STRIDE
            };
            out.push(Region {
                scan: (scan0, scan1),
                runs: (cuts[r], cuts[r + 1]),
                bs: (r * nb / m, (r + 1) * nb / m),
                units: (r * nu / m, (r + 1) * nu / m),
            });
        }
    }

    /// Everything one worker checks: occurrences starting in its part of the scanned view, the
    /// raw-only occurrences at its share of escapes, and its base64 runs and hex spans.
    fn check_region(
        &self,
        bytes: &[u8],
        base: &[u8],
        has_json1: bool,
        json1: &View,
        r: Region,
        part: &mut Part,
    ) {
        part.hits.clear();
        part.bs_hits.clear();
        let to_raw = |a: usize, b: usize| if has_json1 { json1.map(a, b) } else { (a, b) };
        let view = if has_json1 {
            GuardView::Json
        } else {
            GuardView::Raw
        };
        part.view_hits.clear();
        self.scan_range(base, r.scan.0, r.scan.1, true, &mut part.view_hits);
        push_mapped(&mut part.hits, &part.view_hits, view, to_raw);
        if has_json1 {
            part.view_hits.clear();
            self.raw_only(bytes, json1, r, &mut part.bs_hits, &mut part.view_hits);
            push_mapped(&mut part.hits, &part.view_hits, GuardView::Raw, |a, b| {
                (a, b)
            });
        }
        if !self.long.is_empty() {
            let (a, b) = r.runs;
            let sub = &base[a..b];
            self.find_runs(sub, part);
            self.decode_runs(sub, part, &|x, y| to_raw(x + a, y + a));
        }
    }

    /// Collects the base64 runs and hex spans of `base` worth decoding.
    ///
    /// A run is a maximal sequence of at least `MIN_B64_RUN` base64 characters, extended across
    /// single line breaks that are followed by another base64 character. A hex span is a maximal
    /// sequence of at least `MIN_HEX_RUN` hex digits. Both come from per-byte class bitmaps built
    /// in one pass, so text without long runs costs a few instructions per 64 bytes.
    fn find_runs(&self, base: &[u8], s: &mut Part) {
        s.runs.clear();
        s.run_pos.clear();
        s.run_chars.clear();
        s.hex_spans.clear();
        let n = base.len();
        class_bitmaps(base, &mut s.b64m, &mut s.hexm);
        let b64m = &s.b64m;
        let is_b64 = |p: usize| b64m[p / 64] >> (p % 64) & 1 != 0;

        // Base64 runs.
        let mut i = 0;
        let mut starts = RunStarts::new(b64m, MIN_B64_RUN);
        while let Some(p) = starts.next_from(i) {
            // One run, allowing single line breaks between characters. Characters and positions
            // are copied only once a break makes them non-contiguous.
            let start = p;
            i = p;
            let mut mask = 0u8;
            let mut broken = false;
            let chars_off = s.run_chars.len();
            loop {
                let seg = i;
                i = ones_end(b64m, i, n);
                mask |= class_mask(&base[seg..i]);
                if broken {
                    s.run_pos.extend(seg as u32..i as u32);
                    s.run_chars.extend_from_slice(&base[seg..i]);
                }
                let brk = if base[i..].starts_with(b"\r\n") {
                    2
                } else {
                    usize::from(base[i..].starts_with(b"\n"))
                };
                if brk > 0 && i + brk < n && is_b64(i + brk) {
                    if !broken {
                        broken = true;
                        s.run_pos.extend(start as u32..i as u32);
                        s.run_chars.extend_from_slice(&base[start..i]);
                    }
                    i += brk;
                } else {
                    break;
                }
            }
            let len = if broken {
                s.run_chars.len() - chars_off
            } else {
                i - start
            };
            if len >= MIN_B64_RUN && self.b64_mask_ok[usize::from(mask & CLASS_MASK)] {
                s.runs.push(RunRec {
                    start: start as u32,
                    len: len as u32,
                    copied: if broken { chars_off as u32 } else { u32::MAX },
                });
            } else if broken {
                s.run_pos.truncate(chars_off);
                s.run_chars.truncate(chars_off);
            }
        }

        // Hex spans.
        let hexm = &s.hexm;
        let mut i = 0;
        let mut starts = RunStarts::new(hexm, MIN_HEX_RUN);
        while let Some(st) = starts.next_from(i) {
            let en = ones_end(hexm, st, n);
            if self.hex_needs_digit_free || base[st..en].iter().any(u8::is_ascii_digit) {
                s.hex_spans.push((st as u32, en as u32));
            }
            i = en;
        }
    }

    /// Decodes and scans what [`Guard::find_runs`] collected.
    fn decode_runs(
        &self,
        base: &[u8],
        s: &mut Part,
        to_raw: &dyn Fn(usize, usize) -> (usize, usize),
    ) {
        let vh = &mut s.view_hits;
        let out = &mut s.hits;

        // Each run is decoded once, at character alignment 0, into a bit stream. Decoding at
        // alignment `a` gives the same stream from bit 6a on, so the other alignments are read
        // from it at a bit offset instead of being decoded again. Hex spans likewise: alignment 1
        // is the nibble stream from bit 4.
        for r in &s.runs {
            let chars: &[u8] = if r.copied == u32::MAX {
                &base[r.start as usize..(r.start + r.len) as usize]
            } else {
                &s.run_chars[r.copied as usize..(r.copied + r.len) as usize]
            };
            s.decoded.clear();
            decode_b64_bits(chars, &mut s.decoded);
            let l = chars.len();
            for align in 0..4usize {
                if l - align < MIN_B64_RUN {
                    break;
                }
                let bits = BitView {
                    d: &s.decoded,
                    at: 6 * align / 8,
                    shift: (6 * align % 8) as u32,
                    len: 6 * (l - align) / 8,
                };
                vh.clear();
                self.scan_bits(&bits, vh);
                for &(x, y, o) in vh.iter() {
                    let at = |c: usize| {
                        if r.copied == u32::MAX {
                            r.start as usize + c
                        } else {
                            s.run_pos[r.copied as usize + c] as usize
                        }
                    };
                    let c0 = align + (8 * x) / 6;
                    let c1 = (align + (8 * y).div_ceil(6)).min(l);
                    let (a, b) = to_raw(at(c0), at(c1 - 1) + 1);
                    out.push(RawHit {
                        start: a,
                        end: b,
                        owner: o,
                        view: GuardView::Base64,
                    });
                }
            }
        }
        for &(st, en) in &s.hex_spans {
            let (st, en) = (st as usize, en as usize);
            s.decoded.clear();
            decode_hex_bits(&base[st..en], &mut s.decoded);
            for align in 0..2usize {
                let bits = BitView {
                    d: &s.decoded,
                    at: 0,
                    shift: 4 * align as u32,
                    len: (en - st - align) / 2,
                };
                vh.clear();
                self.scan_bits(&bits, vh);
                for &(x, y, o) in vh.iter() {
                    let (a, b) = to_raw(st + align + 2 * x, st + align + 2 * y);
                    out.push(RawHit {
                        start: a,
                        end: b,
                        owner: o,
                        view: GuardView::Hex,
                    });
                }
            }
        }
    }

    /// Finds long values in a decoded bit stream view, like [`Guard::scan`] does in bytes.
    fn scan_bits(&self, v: &BitView<'_>, out: &mut Vec<(usize, usize, u32)>) {
        let mut j = 0;
        while j + GRAM <= v.len {
            let g = v.gram(j);
            if self.grams.maybe(g) {
                self.verify_bits(v, j, g, out);
            }
            j += STRIDE;
        }
    }

    #[inline(never)]
    fn verify_bits(&self, v: &BitView<'_>, j: usize, g: u64, out: &mut Vec<(usize, usize, u32)>) {
        for &(vi, off) in self.grams.get(g) {
            let off = usize::from(off);
            if j < off {
                continue;
            }
            let st = j - off;
            let gv = &self.long[vi as usize];
            let l = gv.value.len();
            if st + l <= v.len
                && gv
                    .value
                    .iter()
                    .enumerate()
                    .all(|(m, &c)| v.byte(st + m).eq_ignore_ascii_case(&c))
            {
                out.push((st, st + l, gv.owner));
            }
        }
    }

    /// Rounds three to `json_depth` of JSON unescaping, each derived from the previous one and
    /// scanned near its decoded units: an occurrence that differs from the previous view must
    /// contain a byte one of its units produced, and the previous view is covered the same way down
    /// to the fully scanned first one. Stops at the first view whose escapes cannot matter.
    fn scan_deeper(
        &self,
        json1: &View,
        json2: &View,
        deeper: &mut Vec<View>,
        vh: &mut Vec<(usize, usize, u32)>,
        out: &mut Vec<RawHit>,
    ) {
        let extra = self.json_depth - 2;
        if deeper.len() < extra {
            deeper.resize_with(extra, View::default);
        }
        for k in 0..extra {
            let (done, rest) = deeper.split_at_mut(k);
            let parent = done.last().unwrap_or(json2);
            // This view is round 3 + k.
            if !self.json_escapes_matter(&parent.bytes, 3 + k < self.json_depth) {
                break;
            }
            let view = &mut rest[0];
            json_unescape(&parent.bytes, view);
            vh.clear();
            self.scan_near_units(view, true, vh);
            push_mapped(out, vh, GuardView::JsonDeep, |a, b| {
                let (mut a, mut b) = view.map(a, b);
                for v in done.iter().rev() {
                    (a, b) = v.map(a, b);
                }
                let (a, b) = json2.map(a, b);
                json1.map(a, b)
            });
        }
    }

    /// Occurrences in the raw bytes that the unescaped view cannot show.
    /// `bs_out` gets every occurrence of a value containing a backslash, overlapping or not;
    /// the caller applies the leftmost non-overlapping rule across regions.
    fn raw_only(
        &self,
        raw: &[u8],
        json1: &View,
        r: Region,
        bs_out: &mut Vec<(usize, usize, u32)>,
        out: &mut Vec<(usize, usize, u32)>,
    ) {
        if !self.bs_cands.is_empty() {
            // Every occurrence of a value with a backslash has the value's first backslash at a
            // backslash of `raw`, so one pass over the backslashes finds them all.
            let bucket =
                |k: usize| &self.bs_cands[self.bs_index[k] as usize..self.bs_index[k + 1] as usize];
            for &p in &json1.backslashes[r.bs.0..r.bs.1] {
                let p = p as usize;
                let next = raw.get(p + 1).map_or(&[][..], |&c| bucket(usize::from(c)));
                let prev = match p.checked_sub(1) {
                    Some(q) => bucket(256 + usize::from(raw[q])),
                    None => &[],
                };
                for c in next.iter().chain(prev) {
                    let (j, l) = (c.first_bs as usize, c.len as usize);
                    if p < j || p - j + l > raw.len() {
                        continue;
                    }
                    let st = p - j;
                    // First and last byte are kept inline, so most candidates are rejected
                    // without touching the value.
                    if [raw[st], raw[st + l - 1]] != c.ends {
                        continue;
                    }
                    let gv = self.value(c.value);
                    if raw[st..st + l] == gv.value[..] {
                        // By value, not owner: a value and its derived forms share an owner but
                        // are searched separately.
                        bs_out.push((st, st + l, c.value));
                    }
                }
            }
        }
        for u in &json1.units[r.units.0..r.units.1] {
            for p in u.parent as usize + 1..(u.parent + u.plen) as usize {
                if p + 1 < raw.len() && self.starts.contains(raw[p], raw[p + 1]) {
                    self.point(raw, p, out);
                }
            }
        }
    }

    /// Values starting exactly at `p`.
    fn point(&self, v: &[u8], p: usize, out: &mut Vec<(usize, usize, u32)>) {
        if p + GRAM <= v.len() {
            let g = gram_key(load_le(v, p));
            for &(vi, off) in self.grams.get(g) {
                let gv = &self.long[vi as usize];
                let l = gv.value.len();
                if off == 0 && p + l <= v.len() && v[p..p + l].eq_ignore_ascii_case(&gv.value) {
                    out.push((p, p + l, gv.owner));
                }
            }
        }
        if !self.short.is_empty()
            && p + SHORT_KEY <= v.len()
            && let k = short_key(v, p)
            && self.short_bits[short_bit(k) >> 6] & (1 << (short_bit(k) & 63)) != 0
            && let Some(&(lo, hi)) = self.short_keys.get(&k)
        {
            for &si in &self.short_cands[lo as usize..hi as usize] {
                let gv = &self.short[si as usize];
                let l = gv.value.len();
                if p + l <= v.len() && v[p..p + l] == gv.value[..] {
                    out.push((p, p + l, gv.owner));
                }
            }
        }
    }

    fn value(&self, vi: u32) -> &GValue {
        let vi = vi as usize;
        if vi < self.long.len() {
            &self.long[vi]
        } else {
            &self.short[vi - self.long.len()]
        }
    }

    /// Width of the window a decoded unit needs: the longest value containing one of the bytes
    /// it decoded to (0 when no value contains any of them, so the unit cannot matter).
    #[inline]
    fn unit_width(&self, view: &View, u: &Unit) -> usize {
        view.bytes[u.view as usize..(u.view + u.vlen) as usize]
            .iter()
            .map(|&c| self.byte_width[usize::from(c)] as usize)
            .max()
            .unwrap_or(0)
    }

    /// Scans only the parts of a decoded view where an occurrence can differ from its parent:
    /// an occurrence only in this view must contain a byte some unit decoded to, so windows of
    /// the longest value containing that byte around each unit suffice. Falls back to a full scan
    /// when the windows would cover most of the view.
    fn scan_near_units(&self, view: &View, with_short: bool, out: &mut Vec<(usize, usize, u32)>) {
        let len = view.bytes.len();
        let windows = || {
            view.units.iter().filter_map(move |u| {
                let w = self.unit_width(view, u);
                (w > 0).then(|| {
                    (
                        (u.view as usize).saturating_sub(w - 1),
                        (u.view as usize + u.vlen as usize + w - 1).min(len),
                    )
                })
            })
        };
        let merged = |f: &mut dyn FnMut(usize, usize)| {
            let mut cur: Option<(usize, usize)> = None;
            for (a, b) in windows() {
                cur = match cur {
                    Some((ca, cb)) if a <= cb => Some((ca, cb.max(b))),
                    Some((ca, cb)) => {
                        f(ca, cb);
                        Some((a, b))
                    }
                    None => Some((a, b)),
                };
            }
            if let Some((ca, cb)) = cur {
                f(ca, cb);
            }
        };
        let mut covered = 0usize;
        merged(&mut |a, b| covered += b - a);
        if covered == 0 {
            return;
        }
        if covered * 2 > len {
            self.scan(&view.bytes, with_short, out);
            return;
        }
        merged(&mut |a, b| {
            let from = out.len();
            self.scan(&view.bytes[a..b], with_short, out);
            for h in &mut out[from..] {
                h.0 += a;
                h.1 += a;
            }
        });
    }

    /// Whether unescaping `b` once more can show a value: some escape in `b` decodes to a byte a
    /// value contains, or, when `more` rounds follow, the unescaped view can hold an escape `b`
    /// does not have. A decoded backslash starts one (`\` `u` `0`... spells
    /// `\u0000`, every byte of it outside the value), and so does a `\u` that is not an escape
    /// yet because escapes stand where its hex digits go.
    fn json_escapes_matter(&self, b: &[u8], more: bool) -> bool {
        let w = |c: u8| self.byte_width[usize::from(c)] != 0;
        memchr::memchr_iter(b'\\', b).any(|i| match b.get(i + 1) {
            Some(b'"') => w(b'"'),
            Some(b'\\') => more || w(b'\\'),
            Some(b'u') if more && builds_escape(&b[i + 2..]) => true,
            Some(b'/') => w(b'/'),
            Some(b'n') => w(b'\n'),
            Some(b'r') => w(b'\r'),
            Some(b't') => w(b'\t'),
            Some(b'b') => w(0x08),
            Some(b'f') => w(0x0c),
            Some(b'u') => match hex4(&b[i + 2..]) {
                Some(cp @ 0..0x80) => w(cp as u8),
                // Non-ASCII: any value with a non-ASCII byte may need it.
                Some(_) => self.byte_width[0x80..].iter().any(|&x| x != 0),
                None => false,
            },
            _ => false,
        })
    }

    /// Finds known values in one view. `with_short` enables exact short-value matching.
    fn scan(&self, v: &[u8], with_short: bool, out: &mut Vec<(usize, usize, u32)>) {
        self.scan_range(v, 0, v.len(), with_short, out);
    }

    /// Finds the occurrences in `v` that start in `[from, to)`; `from` is a multiple of
    /// `STRIDE`, and so is `to` unless it is `v.len()`.
    fn scan_range(
        &self,
        v: &[u8],
        from: usize,
        to: usize,
        with_short: bool,
        out: &mut Vec<(usize, usize, u32)>,
    ) {
        if !self.long.is_empty() && v.len() >= 8 {
            // An occurrence starting at `st` is seen by the probe in `st..st + STRIDE`, so the
            // probes run up to `to` itself, and the hits are filtered by start.
            let last = if to >= v.len() { usize::MAX } else { to };
            let mut p = from;
            // Main loop over full eight-byte loads; the last few probes load zero-filled.
            while p <= last
                && let Some(w) = v.get(p..).and_then(<[u8]>::first_chunk::<8>)
            {
                let g = gram_key(u64::from_le_bytes(*w));
                if self.grams.maybe(g) {
                    self.verify_gram(v, p, g, (from, to), out);
                }
                p += STRIDE;
            }
            while p <= last && p + GRAM <= v.len() {
                let g = gram_key(load_le(v, p));
                if self.grams.maybe(g) {
                    self.verify_gram(v, p, g, (from, to), out);
                }
                p += STRIDE;
            }
        }
        if with_short && !self.short.is_empty() && v.len() >= SHORT_KEY {
            let end = to.min(v.len() - SHORT_KEY + 1);
            for p in from..end {
                let k = short_key(v, p);
                let b = short_bit(k);
                if self.short_bits[b >> 6] & (1 << (b & 63)) != 0 {
                    self.verify_short(v, p, k, out);
                }
            }
        }
    }

    #[inline(never)]
    fn verify_gram(
        &self,
        v: &[u8],
        p: usize,
        g: u64,
        (from, to): (usize, usize),
        out: &mut Vec<(usize, usize, u32)>,
    ) {
        for &(vi, off) in self.grams.get(g) {
            let off = usize::from(off);
            if p < off + from || p - off >= to {
                continue;
            }
            let st = p - off;
            let gv = &self.long[vi as usize];
            let l = gv.value.len();
            if st + l <= v.len() && v[st..st + l].eq_ignore_ascii_case(&gv.value) {
                out.push((st, st + l, gv.owner));
            }
        }
    }

    #[inline(never)]
    fn verify_short(&self, v: &[u8], p: usize, k: u32, out: &mut Vec<(usize, usize, u32)>) {
        let Some(&(lo, hi)) = self.short_keys.get(&k) else {
            return;
        };
        for &si in &self.short_cands[lo as usize..hi as usize] {
            let gv = &self.short[si as usize];
            let l = gv.value.len();
            if p + l <= v.len() && v[p..p + l] == gv.value[..] {
                out.push((p, p + l, gv.owner));
            }
        }
    }
}

// Non-short-circuit operators on purpose: branch-free, so the class tests vectorise.
#[allow(clippy::needless_bitwise_bool)]
#[inline]
fn is_b64_char(c: u8) -> u8 {
    let letter = (c | 0x20).wrapping_sub(b'a') < 26;
    let digit = c.wrapping_sub(b'0') < 10;
    let sym = (c == b'+') | (c == b'/') | (c == b'-') | (c == b'_');
    u8::from(letter | digit | sym)
}

#[inline]
fn is_hex_char(c: u8) -> u8 {
    u8::from(((c | 0x20).wrapping_sub(b'a') < 6) | (c.wrapping_sub(b'0') < 10))
}

/// Eight 0/1 bytes to eight bits, byte `k` to bit `k`.
#[inline]
pub(crate) fn pack8(b: &[u8]) -> u64 {
    let x = match b {
        &[a, b, c, d, e, f, g, h] => u64::from_le_bytes([a, b, c, d, e, f, g, h]),
        _ => 0,
    };
    x.wrapping_mul(0x0102_0408_1020_4080) >> 56
}

/// Per-byte bitmaps of `b`: base64 characters (either alphabet) and hex digits, bit `k % 64` of
/// word `k / 64` for byte `k`, plus one zero word. Written so the compiler vectorises the class
/// tests; the table lookup it replaces cost several times more per byte.
fn class_bitmaps(b: &[u8], b64: &mut Vec<u64>, hex: &mut Vec<u64>) {
    b64.clear();
    hex.clear();
    let mut block = |blk: &[u8; 64]| {
        let mut cb = [0u8; 64];
        let mut ch = [0u8; 64];
        for k in 0..64 {
            cb[k] = is_b64_char(blk[k]);
            ch[k] = is_hex_char(blk[k]);
        }
        let (mut mb, mut mh) = (0u64, 0u64);
        for q in 0..8 {
            mb |= pack8(&cb[8 * q..8 * q + 8]) << (8 * q);
            mh |= pack8(&ch[8 * q..8 * q + 8]) << (8 * q);
        }
        b64.push(mb);
        hex.push(mh);
    };
    let mut blocks = b.chunks_exact(64);
    for blk in &mut blocks {
        if let Ok(blk) = <&[u8; 64]>::try_from(blk) {
            block(blk);
        }
    }
    let rest = blocks.remainder();
    if !rest.is_empty() {
        let mut last = [0u8; 64];
        last[..rest.len()].copy_from_slice(rest);
        block(&last);
    }
    b64.push(0);
    hex.push(0);
}

/// End of the run of set bits starting at `p`: the first clear bit at or after `p`, at most
/// `n`. The bitmap must end with a zero word.
#[inline]
pub(crate) fn ones_end(m: &[u64], p: usize, n: usize) -> usize {
    let mut at = p;
    while at < n {
        let sh = at % 64;
        // Bits shifted in at the top are clear, so `t` stops at the end of the word.
        let t = (!(m[at / 64] >> sh)).trailing_zeros() as usize;
        at += t;
        if t < 64 - sh {
            break;
        }
    }
    at.min(n)
}

/// Character classes (`CLASS_MASK` bits) present in `b`: a table lookup per byte for short
/// slices, comparisons the compiler vectorises for long ones.
#[allow(clippy::needless_bitwise_bool)]
#[inline]
fn class_mask(b: &[u8]) -> u8 {
    if b.len() < 48 {
        return b
            .iter()
            .fold(0u8, |m, &c| m | (CLASS[usize::from(c)] & CLASS_MASK));
    }
    b.iter().fold(0u8, |m, &c| {
        let sym = (c == b'+') | (c == b'/') | (c == b'-') | (c == b'_');
        m | u8::from(c.wrapping_sub(b'A') < 13)
            | (u8::from(c.wrapping_sub(b'N') < 13) << 1)
            | (u8::from(c.wrapping_sub(b'a') < 13) << 2)
            | (u8::from(c.wrapping_sub(b'n') < 13) << 3)
            | (u8::from(c.wrapping_sub(b'0') < 10) << 4)
            | (u8::from(sym) << 5)
    })
}

/// Starts of maximal runs of at least `min` set bits in a bitmap, found word by word.
pub(crate) struct RunStarts<'a> {
    m: &'a [u64],
    min: usize,
    /// Word the cached starts belong to, `usize::MAX` before the first.
    w: usize,
    starts: u64,
}

impl<'a> RunStarts<'a> {
    pub(crate) fn new(m: &'a [u64], min: usize) -> Self {
        Self {
            m,
            min,
            w: usize::MAX,
            starts: 0,
        }
    }

    fn word(&mut self, w: usize) {
        let cur = self.m[w];
        let next = self.m.get(w + 1).copied().unwrap_or(0);
        let prev = if w == 0 { 0 } else { self.m[w - 1] };
        let x = u128::from(cur) | (u128::from(next) << 64);
        // Positions where `min` set bits follow: shift-and by doubling.
        let mut r = x;
        let mut have = 1;
        while have * 2 <= self.min {
            r &= r >> have;
            have *= 2;
        }
        if have < self.min {
            r &= r >> (self.min - have);
        }
        // Only maximal starts: the bit before is clear.
        let before = (cur << 1) | (prev >> 63);
        self.w = w;
        self.starts = (r as u64) & !before;
    }

    /// First maximal run start at or after `from`.
    pub(crate) fn next_from(&mut self, from: usize) -> Option<usize> {
        let mut w = from / 64;
        let mut off = from % 64;
        while w + 1 < self.m.len() {
            if self.w != w {
                self.word(w);
            }
            let s = self.starts & (u64::MAX << off);
            if s != 0 {
                return Some(w * 64 + s.trailing_zeros() as usize);
            }
            w += 1;
            off = 0;
        }
        None
    }
}

/// A value containing a backslash, as indexed for the raw-only pass.
#[derive(Clone, Copy)]
struct BsCand {
    /// Value index, long values first, then short.
    value: u32,
    /// Offset of the value's first backslash.
    first_bs: u32,
    len: u32,
    /// First and last byte.
    ends: [u8; 2],
}

/// A set of byte pairs, 8 KiB.
struct PairSet(Vec<u64>);

impl PairSet {
    fn new() -> Self {
        Self(vec![0; 1024])
    }
    fn insert(&mut self, a: u8, b: u8) {
        let i = (usize::from(a) << 8) | usize::from(b);
        self.0[i >> 6] |= 1 << (i & 63);
    }
    #[inline]
    fn contains(&self, a: u8, b: u8) -> bool {
        let i = (usize::from(a) << 8) | usize::from(b);
        self.0[i >> 6] & (1 << (i & 63)) != 0
    }
}

/// A base64 run selected for decoding.
#[derive(Clone, Copy)]
struct RunRec {
    /// First character in the base bytes.
    start: u32,
    /// Characters in the run.
    len: u32,
    /// Offset in `run_chars`/`run_pos` when the run spans line breaks, else `u32::MAX`.
    copied: u32,
}

/// A view of a decoded bit stream: `len` bytes starting `shift` bits into `d[at]`. `d` carries
/// at least eight bytes after the last one a view reads.
struct BitView<'a> {
    d: &'a [u8],
    at: usize,
    shift: u32,
    len: usize,
}

impl BitView<'_> {
    /// Eight stream bytes from byte `i` of `d`, big-endian.
    #[inline]
    fn be8(&self, i: usize) -> u64 {
        match self.d.get(i..i + 8) {
            Some(&[a, b, c, d, e, f, g, h]) => u64::from_be_bytes([a, b, c, d, e, f, g, h]),
            _ => 0,
        }
    }

    /// The gram key at view byte `j`.
    #[inline]
    fn gram(&self, j: usize) -> u64 {
        let x = self.be8(self.at + j) << self.shift;
        gram_key(x.swap_bytes())
    }

    /// View byte `m`.
    #[inline]
    fn byte(&self, m: usize) -> u8 {
        let i = self.at + m;
        let hi = u16::from(self.d[i]) << 8 | u16::from(self.d[i + 1]);
        (hi >> (8 - self.shift)) as u8
    }
}

/// Appends the bit stream of `chars` (base64, either alphabet): three bytes per four characters,
/// the last partial byte zero-filled, then eight zero bytes.
fn decode_b64_bits(chars: &[u8], out: &mut Vec<u8>) {
    let mut quads = chars.chunks_exact(4);
    for q in &mut quads {
        let acc = (u32::from(B64[usize::from(q[0])]) << 18)
            | (u32::from(B64[usize::from(q[1])]) << 12)
            | (u32::from(B64[usize::from(q[2])]) << 6)
            | u32::from(B64[usize::from(q[3])]);
        out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
    }
    let rest = quads.remainder();
    let mut acc = 0u32;
    for (k, &c) in rest.iter().enumerate() {
        acc |= u32::from(B64[usize::from(c)]) << (18 - 6 * k);
    }
    for k in 0..(rest.len() * 6).div_ceil(8) {
        out.push((acc >> (16 - 8 * k)) as u8);
    }
    out.extend_from_slice(&[0; 8]);
}

/// Appends the nibble stream of `digits` (hex, any case), the last partial byte zero-filled,
/// then eight zero bytes.
fn decode_hex_bits(digits: &[u8], out: &mut Vec<u8>) {
    let mut pairs = digits.chunks_exact(2);
    for pair in &mut pairs {
        out.push((HEXV[usize::from(pair[0])] << 4) | HEXV[usize::from(pair[1])]);
    }
    if let [c] = pairs.remainder() {
        out.push(HEXV[usize::from(*c)] << 4);
    }
    out.extend_from_slice(&[0; 8]);
}

fn push_mapped(
    out: &mut Vec<RawHit>,
    vh: &[(usize, usize, u32)],
    view: GuardView,
    map: impl Fn(usize, usize) -> (usize, usize),
) {
    for &(a, b, o) in vh {
        let (a, b) = map(a, b);
        out.push(RawHit {
            start: a,
            end: b,
            owner: o,
            view,
        });
    }
}

// Character classes of base64 characters, fine enough that an inner encoding of ten or more
// random characters rarely fits in a run of identifier or timestamp text.
const CLASS_UPPER_AM: u8 = 1;
const CLASS_UPPER_NZ: u8 = 2;
const CLASS_LOWER_AM: u8 = 4;
const CLASS_LOWER_NZ: u8 = 8;
const CLASS_DIGIT: u8 = 16;
const CLASS_SYM: u8 = 32;
const CLASS_MASK: u8 = 63;
const CLASS_B64: u8 = 64;
const CLASS_HEX: u8 = 128;

const fn class_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let c = i as u8;
        let class = match c {
            b'A'..=b'M' => CLASS_UPPER_AM,
            b'N'..=b'Z' => CLASS_UPPER_NZ,
            b'a'..=b'm' => CLASS_LOWER_AM,
            b'n'..=b'z' => CLASS_LOWER_NZ,
            b'0'..=b'9' => CLASS_DIGIT,
            b'+' | b'/' | b'-' | b'_' => CLASS_SYM,
            _ => 0,
        };
        let b64 = if class != 0 { CLASS_B64 } else { 0 };
        let hex = if c.is_ascii_hexdigit() { CLASS_HEX } else { 0 };
        t[i] = class | b64 | hex;
        i += 1;
    }
    t
}
static CLASS: [u8; 256] = class_table();

/// Character classes of the base64 characters that encode only `v`'s bits, for `v` placed at
/// byte offset `k` of a stream (the part any run carrying the value must contain).
fn b64_inner_mask(v: &[u8], k: usize) -> u8 {
    let total = k + v.len();
    let first = (8 * k).div_ceil(6);
    let last = (8 * total) / 6;
    let mut mask = 0;
    for c in first..last {
        // Six bits starting at bit 6c of the stream.
        let mut x = 0u32;
        for bit in 0..6 {
            let pos = 6 * c + bit;
            let byte = pos / 8;
            let b = if byte < k { 0 } else { v[byte - k] };
            x = (x << 1) | u32::from((b >> (7 - pos % 8)) & 1);
        }
        let ch = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[x as usize];
        mask |= CLASS[usize::from(ch)] & CLASS_MASK;
    }
    mask
}

/// Whether `\u` followed by `rest` can become an escape after one more round of unescaping: it
/// decodes to a backslash, or its hex digits are cut short by a backslash that may start an
/// escape decoding to one.
fn builds_escape(rest: &[u8]) -> bool {
    match hex4(rest) {
        Some(cp) => cp == u32::from(b'\\'),
        None => rest
            .iter()
            .take(4)
            .find(|&&c| HEXV[usize::from(c)] == 0xFF)
            .is_some_and(|&c| c == b'\\'),
    }
}

fn has_json_escape(b: &[u8]) -> bool {
    memchr::memchr_iter(b'\\', b).any(|i| {
        i + 1 < b.len()
            && matches!(
                b[i + 1],
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' | b'u'
            )
    })
}

const fn b64_table() -> [u8; 256] {
    let mut t = [0xFFu8; 256];
    let a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut i = 0;
    while i < 62 {
        t[a[i] as usize] = i as u8;
        i += 1;
    }
    t[b'+' as usize] = 62;
    t[b'-' as usize] = 62;
    t[b'/' as usize] = 63;
    t[b'_' as usize] = 63;
    t
}
static B64: [u8; 256] = b64_table();

const fn hex_table() -> [u8; 256] {
    let mut t = [0xFFu8; 256];
    let a = b"0123456789abcdef";
    let mut i = 0;
    while i < 16 {
        t[a[i] as usize] = i as u8;
        t[a[i].to_ascii_uppercase() as usize] = i as u8;
        i += 1;
    }
    t
}
static HEXV: [u8; 256] = hex_table();

fn hex4(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    let mut x = 0u32;
    for &c in &b[..4] {
        let v = HEXV[usize::from(c)];
        if v == 0xFF {
            return None;
        }
        x = (x << 4) | u32::from(v);
    }
    Some(x)
}

/// JSON-unescapes all of `src` (strings or not; unknown escapes are kept verbatim).
fn json_unescape(src: &[u8], v: &mut View) {
    v.clear();
    v.bytes.reserve(src.len());
    let mut i = 0;
    let mut copied = 0;
    while let Some(off) = memchr::memchr(b'\\', &src[i..]) {
        let at = i + off;
        v.bytes.extend_from_slice(&src[copied..at]);
        v.backslashes.push(at as u32);
        let rest = &src[at + 1..];
        let view = v.bytes.len() as u32;
        let (plen, ok) = match rest.first() {
            Some(b'"') => (2, push1(&mut v.bytes, b'"')),
            Some(b'\\') => (2, push1(&mut v.bytes, b'\\')),
            Some(b'/') => (2, push1(&mut v.bytes, b'/')),
            Some(b'n') => (2, push1(&mut v.bytes, b'\n')),
            Some(b'r') => (2, push1(&mut v.bytes, b'\r')),
            Some(b't') => (2, push1(&mut v.bytes, b'\t')),
            Some(b'b') => (2, push1(&mut v.bytes, 0x08)),
            Some(b'f') => (2, push1(&mut v.bytes, 0x0c)),
            Some(b'u') => match hex4(&rest[1..]) {
                Some(hi @ 0xD800..=0xDBFF) => {
                    let lo = if rest.len() >= 11 && rest[5] == b'\\' && rest[6] == b'u' {
                        hex4(&rest[7..])
                    } else {
                        None
                    };
                    match lo {
                        Some(lo @ 0xDC00..=0xDFFF) => {
                            let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                            (12, push_char(&mut v.bytes, cp))
                        }
                        _ => (0, false),
                    }
                }
                Some(0xDC00..=0xDFFF) | None => (0, false),
                Some(cp) => (6, push_char(&mut v.bytes, cp)),
            },
            _ => (0, false),
        };
        if ok {
            // Backslashes the escape consumed: `\\` and the second half of a surrogate pair.
            match plen {
                2 if rest[0] == b'\\' => v.backslashes.push(at as u32 + 1),
                12 => v.backslashes.push(at as u32 + 6),
                _ => {}
            }
            let vlen = v.bytes.len() as u32 - view;
            v.units.push(Unit {
                view,
                vlen,
                parent: at as u32,
                plen,
            });
            i = at + plen as usize;
        } else {
            v.bytes.push(b'\\');
            i = at + 1;
        }
        copied = i;
    }
    v.bytes.extend_from_slice(&src[copied..]);
}

fn push1(b: &mut Vec<u8>, c: u8) -> bool {
    b.push(c);
    true
}

fn push_char(b: &mut Vec<u8>, cp: u32) -> bool {
    match char::from_u32(cp) {
        Some(c) => {
            let mut buf = [0u8; 4];
            b.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            true
        }
        None => false,
    }
}

fn has_percent_escape(b: &[u8]) -> bool {
    memchr::memchr_iter(b'%', b).any(|i| {
        i + 2 < b.len()
            && HEXV[usize::from(b[i + 1])] != 0xFF
            && HEXV[usize::from(b[i + 2])] != 0xFF
    })
}

fn url_decode(src: &[u8], v: &mut View) {
    v.clear();
    v.bytes.reserve(src.len());
    let mut i = 0;
    let mut copied = 0;
    while let Some(off) = memchr::memchr(b'%', &src[i..]) {
        let at = i + off;
        if at + 2 < src.len()
            && HEXV[usize::from(src[at + 1])] != 0xFF
            && HEXV[usize::from(src[at + 2])] != 0xFF
        {
            v.bytes.extend_from_slice(&src[copied..at]);
            let view = v.bytes.len() as u32;
            v.bytes
                .push((HEXV[usize::from(src[at + 1])] << 4) | HEXV[usize::from(src[at + 2])]);
            v.units.push(Unit {
                view,
                vlen: 1,
                parent: at as u32,
                plen: 3,
            });
            i = at + 3;
            copied = i;
        } else {
            i = at + 1;
        }
    }
    v.bytes.extend_from_slice(&src[copied..]);
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

    fn empty_resolver() -> Arc<Resolver> {
        Arc::new(Resolver::new(
            HashMap::new(),
            Arc::from(Vec::new()),
            Default::default(),
        ))
    }

    #[test]
    fn repair_that_leaves_a_value_withholds() {
        // A replacement that is not a genuine placeholder and itself carries another value: the
        // recheck must catch it.
        let inputs = [
            GuardInput {
                value: b"first-value-123",
                entry: EntryId(1),
                placeholder: b"[second-value-456]",
            },
            GuardInput {
                value: b"second-value-456",
                entry: EntryId(2),
                placeholder: b"[x]",
            },
        ];
        let g = Guard::build(
            &inputs,
            8,
            64,
            3,
            (1, usize::MAX),
            0,
            empty_resolver(),
            &TransformConfig::default(),
        );
        let mut s = GuardScratch::new();
        assert_eq!(
            g.check(b"a first-value-123 b", &mut s),
            Verdict::Withhold(WithholdReason::RepairIncomplete)
        );
        assert!(matches!(
            g.check(b"a second-value-456 b", &mut s),
            Verdict::Repaired { .. }
        ));
        assert_eq!(g.check(b"a b", &mut s), Verdict::Clean);
    }

    #[test]
    fn view_mapping() {
        let mut v = View::default();
        json_unescape(b"ab\\\"cd\\u00e9ef\\ud83d\\ude00g\\q", &mut v);
        assert_eq!(v.bytes, "ab\"cdéef😀g\\q".as_bytes());
        // "cd" in the view is raw 4..6.
        assert_eq!(v.map(3, 5), (4, 6));
        // The quote maps to its whole escape.
        assert_eq!(v.map(2, 3), (2, 4));
        // é (two view bytes) maps to the six-byte escape, even when only half is covered.
        assert_eq!(v.map(5, 6), (6, 12));
        assert_eq!(v.map(6, 7), (6, 12));
        let emoji = "ab\"cdéef".len();
        assert_eq!(v.map(emoji, emoji + 4), (14, 26));
        let mut u = View::default();
        url_decode(b"a%2Fb%zz%2f", &mut u);
        assert_eq!(u.bytes, b"a/b%zz/");
        assert_eq!(u.map(1, 3), (1, 5));
    }
}
