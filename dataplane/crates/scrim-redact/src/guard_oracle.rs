//! The guard as it was before the single-decode rewrite, kept as a test oracle: the optimised
//! guard in `guard.rs` must reach exactly the same verdict on every input. Compiled for unit
//! tests and fuzzing only.
#![allow(dead_code, unreachable_pub, clippy::pedantic, missing_docs)]

use std::collections::HashMap;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::error::WithholdReason;
use crate::guard::{GuardFinding, GuardInput, GuardView, Verdict};
use crate::guard_tx::{TransformConfig, Transforms, TxScratch, derived_forms};
use crate::restore::Resolver;
use crate::secret::EntryId;

const GRAM: usize = 5;
const STRIDE: usize = 4;
const SHORT_KEY: usize = 4;
/// Shortest base64 run worth decoding: an eight-byte value needs at least eleven characters.
const MIN_B64_RUN: usize = 11;
/// Shortest hex run worth decoding: an eight-byte value is sixteen digits.
const MIN_HEX_RUN: usize = 16;

struct GValue {
    value: Zeroizing<Vec<u8>>,
    owner: u32,
}

/// The guard. Immutable after build, shared between threads.
pub(crate) struct OracleGuard {
    /// Per byte, the longest value containing it (both cases for letters of long values).
    byte_width: Vec<u32>,
    /// First two bytes of every value (both cases for long values).
    starts: PairSet,
    long: Vec<GValue>,
    short: Vec<GValue>,
    gram_bits: Vec<u64>,
    gram_shift: u32,
    grams: HashMap<u64, (u32, u32)>,
    gram_cands: Vec<(u32, u8)>,
    short_bits: Vec<u64>,
    short_keys: HashMap<u32, (u32, u32)>,
    short_cands: Vec<u32>,
    placeholders: Vec<Box<[u8]>>,
    entry_ids: Vec<EntryId>,
    max_repairs: usize,
    /// Rounds of JSON unescaping, at least 2.
    json_depth: usize,
    resolver: Arc<Resolver>,
    /// Indices (long first, then short) of values containing a backslash.
    backslash_values: Vec<u32>,
    /// Minimal character-class masks of every value's inner base64 forms; a run whose classes
    /// contain none of them cannot carry any value.
    b64_masks: Vec<u8>,
    /// Some value's hex form has no digit, so hex runs without digits must be decoded too.
    hex_needs_digit_free: bool,
    /// The same transform decoders as the guard (shared code: the oracle checks the rewrite of
    /// the guard's own views, and both must feed the transforms the same view).
    tx: Transforms,
}

impl std::fmt::Debug for OracleGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleGuard")
            .field("long_values", &self.long.len())
            .field("short_values", &self.short.len())
            .finish_non_exhaustive()
    }
}

/// Reusable buffers for [`OracleGuard::check`]. One per thread or request; never shared.
#[derive(Default)]
pub(crate) struct OracleScratch {
    json1: View,
    json2: View,
    /// Views after three and more rounds of JSON unescaping.
    deeper: Vec<View>,
    url: View,
    run_pos: Vec<u32>,
    run_chars: Vec<u8>,
    runs: Vec<RunRec>,
    hex_spans: Vec<(u32, u32)>,
    segs: Vec<DecSeg>,
    decoded: Vec<u8>,
    hits: Vec<RawHit>,
    view_hits: Vec<(usize, usize, u32)>,
    findings: Vec<GuardFinding>,
    repaired: Vec<u8>,
    recheck: Vec<RawHit>,
    tx: TxScratch,
}

impl std::fmt::Debug for OracleScratch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OracleScratch(<redacted>)")
    }
}

impl OracleScratch {
    /// Empty scratch space.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Wipes every buffer that may have held request bytes. Capacity is kept.
    pub(crate) fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.json1.bytes.zeroize();
        self.json2.bytes.zeroize();
        for v in &mut self.deeper {
            v.bytes.zeroize();
        }
        self.url.bytes.zeroize();
        self.run_chars.zeroize();
        self.decoded.zeroize();
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

const fn lower_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = (i as u8).to_ascii_lowercase();
        i += 1;
    }
    t
}
static LOWER: [u8; 256] = lower_table();

#[inline]
fn gram_at(b: &[u8], p: usize) -> u64 {
    let mut g = 0u64;
    for k in 0..GRAM {
        g |= u64::from(LOWER[usize::from(b[p + k])]) << (8 * k);
    }
    g
}

#[inline]
fn gram_hash(g: u64) -> u64 {
    let mut h = g ^ (g >> 31);
    h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    h ^ (h >> 29)
}

#[inline]
fn short_key(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}

#[inline]
fn short_bit(k: u32) -> usize {
    (k.wrapping_mul(0x9E37_79B1) >> 16) as usize
}

impl OracleGuard {
    pub(crate) fn build(
        inputs: &[GuardInput<'_>],
        min_len: usize,
        max_repairs: usize,
        json_depth: usize,
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
                pairs.push((gram_at(&v.value, off), vi as u32, off as u8));
            }
        }
        pairs.sort_unstable();
        pairs.dedup();
        let mut grams = HashMap::new();
        let mut gram_cands = Vec::with_capacity(pairs.len());
        let mut i = 0;
        while i < pairs.len() {
            let g = pairs[i].0;
            let lo = gram_cands.len() as u32;
            while i < pairs.len() && pairs[i].0 == g {
                gram_cands.push((pairs[i].1, pairs[i].2));
                i += 1;
            }
            grams.insert(g, (lo, gram_cands.len() as u32));
        }
        let bits = (grams.len() * 64).next_power_of_two().max(1 << 12);
        let gram_shift = 64 - bits.trailing_zeros();
        let mut gram_bits = vec![0u64; bits / 64];
        for &g in grams.keys() {
            let h = (gram_hash(g) >> gram_shift) as usize;
            gram_bits[h >> 6] |= 1 << (h & 63);
        }

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

        let backslash_values = long
            .iter()
            .chain(short.iter())
            .enumerate()
            .filter(|(_, v)| v.value.contains(&b'\\'))
            .map(|(i, _)| i as u32)
            .collect();
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
        Self {
            byte_width,
            starts,
            long,
            short,
            gram_bits,
            gram_shift,
            grams,
            gram_cands,
            short_bits,
            short_keys,
            short_cands,
            placeholders,
            entry_ids,
            max_repairs,
            json_depth: json_depth.max(2),
            resolver,
            backslash_values,
            b64_masks,
            hex_needs_digit_free,
            tx,
        }
    }

    /// Checks `bytes`, the exact body about to be sent.
    ///
    /// Returns [`Verdict::Clean`], or [`Verdict::Repaired`] with the repaired body in `scratch`,
    /// or [`Verdict::Withhold`]. Never allocates once `scratch` has grown to the body size.
    pub(crate) fn check<'s>(&self, bytes: &[u8], scratch: &'s mut OracleScratch) -> Verdict<'s> {
        let mut hits = std::mem::take(&mut scratch.hits);
        hits.clear();
        self.collect(bytes, scratch, &mut hits);
        if hits.is_empty() {
            scratch.hits = hits;
            return Verdict::Clean;
        }
        // Deviation from the original: the view breaks ties, so the reported view does not
        // depend on the order hits were collected in (the optimised guard collects differently).
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

    fn entry_of(&self, owner: u32) -> EntryId {
        self.entry_ids[owner as usize]
    }

    /// All hits in every view, in raw coordinates, minus those inside genuine placeholders.
    fn collect(&self, bytes: &[u8], s: &mut OracleScratch, out: &mut Vec<RawHit>) {
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

    fn collect_views(&self, bytes: &[u8], s: &mut OracleScratch, out: &mut Vec<RawHit>) {
        if self.long.is_empty() && self.short.is_empty() {
            return;
        }
        let mut vh = std::mem::take(&mut s.view_hits);
        let mut json1 = std::mem::take(&mut s.json1);
        let has_json1 = has_json_escape(bytes);

        if has_json1 {
            // The unescaped view is what the provider reads. Scan it fully, and cover the raw-only
            // occurrences precisely: values containing a backslash, and values starting inside
            // an escape sequence (`\token` reads as TAB + `oken` once unescaped).
            json_unescape(bytes, &mut json1);
            vh.clear();
            self.scan(&json1.bytes, true, &mut vh);
            push_mapped(out, &vh, GuardView::Json, |a, b| json1.map(a, b));
            vh.clear();
            self.raw_only(bytes, &json1, &mut vh);
            push_mapped(out, &vh, GuardView::Raw, |a, b| (a, b));

            // Every round up to the depth while escapes remain: no guess about which escapes
            // can matter, so the optimised guard's pruning is checked against all of them.
            if has_json_escape(&json1.bytes) {
                let mut json2 = std::mem::take(&mut s.json2);
                json_unescape(&json1.bytes, &mut json2);
                vh.clear();
                self.scan_near_units(&json2, true, &mut vh);
                push_mapped(out, &vh, GuardView::JsonTwice, |a, b| {
                    let (a, b) = json2.map(a, b);
                    json1.map(a, b)
                });
                if self.json_depth > 2 {
                    let mut deeper = std::mem::take(&mut s.deeper);
                    self.scan_deeper(&json1, &json2, &mut deeper, &mut vh, out);
                    s.deeper = deeper;
                }
                s.json2 = json2;
            }
        } else {
            vh.clear();
            self.scan(bytes, true, &mut vh);
            push_mapped(out, &vh, GuardView::Raw, |a, b| (a, b));
        }

        if !self.long.is_empty() {
            // Encoding views over the once-unescaped bytes.
            let base: &[u8] = if has_json1 { &json1.bytes } else { bytes };
            let to_raw = |a: usize, b: usize| if has_json1 { json1.map(a, b) } else { (a, b) };

            if has_percent_escape(base) {
                let mut url = std::mem::take(&mut s.url);
                url_decode(base, &mut url);
                vh.clear();
                self.scan_near_units(&url, false, &mut vh);
                push_mapped(out, &vh, GuardView::Url, |a, b| {
                    let (a, b) = url.map(a, b);
                    to_raw(a, b)
                });
                s.url = url;
            }
            self.scan_runs(base, s, &mut vh, out, &to_raw);
            let found = out.len();
            self.tx.collect(
                base,
                &mut s.tx,
                &|v, o| self.scan(v, false, o),
                &mut |a, b, owner, view| {
                    let (start, end) = to_raw(a, b);
                    if view == GuardView::Fragment
                        && out[..found]
                            .iter()
                            .any(|h| h.start <= start && end <= h.end)
                    {
                        return;
                    }
                    out.push(RawHit {
                        start,
                        end,
                        owner,
                        view,
                    });
                },
                false,
            );
        }
        s.json1 = json1;
        s.view_hits = vh;
    }

    /// Base64 and hex runs of `base`: collected in one pass, decoded into one buffer (every
    /// alignment of every run, back to back), scanned once.
    fn scan_runs(
        &self,
        base: &[u8],
        s: &mut OracleScratch,
        vh: &mut Vec<(usize, usize, u32)>,
        out: &mut Vec<RawHit>,
        to_raw: &dyn Fn(usize, usize) -> (usize, usize),
    ) {
        s.runs.clear();
        s.run_pos.clear();
        s.run_chars.clear();
        s.hex_spans.clear();
        let n = base.len();
        let mut i = 0;
        let mut finder = RunFinder::new();
        while i < n {
            // Skip 64-byte blocks in which no run of MIN_B64_RUN characters starts. Prose and
            // most code have none, and skipping them avoids a branch per word.
            match finder.next(base, i) {
                Some(p) => i = p,
                None => break,
            }
            // One run, allowing single line breaks between characters. Characters and positions
            // are copied only once a break makes them non-contiguous.
            let start = i;
            let mut mask = 0u8;
            let mut broken = false;
            let chars_off = s.run_chars.len();
            loop {
                let seg = i;
                let mut hex_len = 0usize;
                let mut hex_max = 0usize;
                while i < n {
                    let c = CLASS[usize::from(base[i])];
                    if c & CLASS_B64 == 0 {
                        break;
                    }
                    mask |= c & CLASS_MASK;
                    hex_len = (hex_len + 1) * usize::from(c >> 7);
                    hex_max = hex_max.max(hex_len);
                    i += 1;
                }
                if hex_max >= MIN_HEX_RUN {
                    let mut k = seg;
                    while k < i {
                        let st = k;
                        while k < i && CLASS[usize::from(base[k])] & CLASS_HEX != 0 {
                            k += 1;
                        }
                        if k - st >= MIN_HEX_RUN
                            && (self.hex_needs_digit_free
                                || base[st..k].iter().any(u8::is_ascii_digit))
                        {
                            s.hex_spans.push((st as u32, k as u32));
                        }
                        k = k.max(st + 1);
                    }
                }
                if broken {
                    s.run_pos.extend(seg as u32..i as u32);
                    s.run_chars.extend_from_slice(&base[seg..i]);
                }
                let brk = if base[i..].starts_with(b"\r\n") {
                    2
                } else {
                    usize::from(base[i..].starts_with(b"\n"))
                };
                if brk > 0 && i + brk < n && CLASS[usize::from(base[i + brk])] & CLASS_B64 != 0 {
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
            if len >= MIN_B64_RUN && self.b64_masks.iter().any(|&m| m & mask == m) {
                s.runs.push(RunRec {
                    start: start as u32,
                    len: len as u32,
                    copied: if broken { chars_off as u32 } else { u32::MAX },
                });
            } else if broken {
                s.run_pos.truncate(chars_off);
                s.run_chars.truncate(chars_off);
            }
            i = i.max(start + 1);
        }
        if s.runs.is_empty() && s.hex_spans.is_empty() {
            return;
        }

        // Decode everything into one buffer, remembering where each piece came from.
        s.decoded.clear();
        s.segs.clear();
        for (ri, r) in s.runs.iter().enumerate() {
            let chars: &[u8] = if r.copied == u32::MAX {
                &base[r.start as usize..(r.start + r.len) as usize]
            } else {
                &s.run_chars[r.copied as usize..(r.copied + r.len) as usize]
            };
            for align in 0..4usize {
                if chars.len() - align < MIN_B64_RUN {
                    break;
                }
                let at = s.decoded.len();
                decode_b64_into(&chars[align..], &mut s.decoded);
                s.segs.push(DecSeg {
                    at: at as u32,
                    len: (s.decoded.len() - at) as u32,
                    src: ri as u32,
                    align: align as u8,
                    hex: false,
                });
            }
        }
        for (hi, &(st, en)) in s.hex_spans.iter().enumerate() {
            for align in 0..2usize {
                let at = s.decoded.len();
                for pair in base[st as usize + align..en as usize].chunks_exact(2) {
                    s.decoded
                        .push((HEXV[usize::from(pair[0])] << 4) | HEXV[usize::from(pair[1])]);
                }
                s.segs.push(DecSeg {
                    at: at as u32,
                    len: (s.decoded.len() - at) as u32,
                    src: hi as u32,
                    align: align as u8,
                    hex: true,
                });
            }
        }

        vh.clear();
        self.scan(&s.decoded, false, vh);
        for &(x, y, o) in vh.iter() {
            let k = s.segs.partition_point(|g| g.at as usize <= x);
            let g = s.segs[k - 1];
            let (gx, gy) = (x - g.at as usize, y - g.at as usize);
            if gy > g.len as usize {
                // Straddles two pieces: not a real occurrence.
                continue;
            }
            let align = usize::from(g.align);
            let (a, b, view) = if g.hex {
                let st = s.hex_spans[g.src as usize].0 as usize;
                (st + align + 2 * gx, st + align + 2 * gy, GuardView::Hex)
            } else {
                let r = s.runs[g.src as usize];
                let at = |c: usize| {
                    if r.copied == u32::MAX {
                        r.start as usize + c
                    } else {
                        s.run_pos[r.copied as usize + c] as usize
                    }
                };
                let c0 = align + (8 * gx) / 6;
                let c1 = (align + (8 * gy).div_ceil(6)).min(r.len as usize);
                (at(c0), at(c1 - 1) + 1, GuardView::Base64)
            };
            let (a, b) = to_raw(a, b);
            out.push(RawHit {
                start: a,
                end: b,
                owner: o,
                view,
            });
        }
    }

    /// Rounds three to `json_depth` of JSON unescaping, each derived from the previous one and
    /// scanned near its decoded units: an occurrence that differs from the previous view must
    /// contain a byte one of its units produced, and the previous view is covered the same way down
    /// to the fully scanned first one. Stops at the first view without escapes.
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
            if !has_json_escape(&parent.bytes) {
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
    fn raw_only(&self, raw: &[u8], json1: &View, out: &mut Vec<(usize, usize, u32)>) {
        for &vi in &self.backslash_values {
            let gv = self.value(vi);
            for at in memchr::memmem::find_iter(raw, &gv.value[..]) {
                out.push((at, at + gv.value.len(), gv.owner));
            }
        }
        for u in &json1.units {
            for p in u.parent as usize + 1..(u.parent + u.plen) as usize {
                if p + 1 < raw.len() && self.starts.contains(raw[p], raw[p + 1]) {
                    self.point(raw, p, out);
                }
            }
        }
    }

    /// Values starting exactly at `p`.
    fn point(&self, v: &[u8], p: usize, out: &mut Vec<(usize, usize, u32)>) {
        let g = if p + GRAM <= v.len() {
            lower_gram(v, p)
        } else {
            u64::MAX
        };
        let h = (gram_hash(g) >> self.gram_shift) as usize;
        if g != u64::MAX
            && self.gram_bits[h >> 6] & (1 << (h & 63)) != 0
            && let Some(&(lo, hi)) = self.grams.get(&g)
        {
            for &(vi, off) in &self.gram_cands[lo as usize..hi as usize] {
                let gv = &self.long[vi as usize];
                let l = gv.value.len();
                if off == 0 && p + l <= v.len() && v[p..p + l].eq_ignore_ascii_case(&gv.value) {
                    out.push((p, p + l, gv.owner));
                }
            }
        }
        if !self.short.is_empty()
            && p + SHORT_KEY <= v.len()
            && let Some(&(lo, hi)) = self.short_keys.get(&short_key(v, p))
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

    /// Finds known values in one view. `with_short` enables exact short-value matching.
    fn scan(&self, v: &[u8], with_short: bool, out: &mut Vec<(usize, usize, u32)>) {
        if !self.long.is_empty() && v.len() >= 8 {
            // Main loop over full eight-byte loads; the last few probes use the byte-wise gram.
            let mut p = 0;
            for w in v.chunks_exact(STRIDE).zip(v[STRIDE..].chunks(STRIDE)) {
                let (a, b) = w;
                if b.len() < STRIDE {
                    break;
                }
                let x = u64::from_le_bytes([a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]);
                let g = swar_lower(x) & 0xFF_FFFF_FFFF;
                let h = (gram_hash(g) >> self.gram_shift) as usize;
                if self.gram_bits[h >> 6] & (1 << (h & 63)) != 0 {
                    self.verify_gram(v, p, g, out);
                }
                p += STRIDE;
            }
            while p + GRAM <= v.len() {
                let g = gram_at(v, p);
                let h = (gram_hash(g) >> self.gram_shift) as usize;
                if self.gram_bits[h >> 6] & (1 << (h & 63)) != 0 {
                    self.verify_gram(v, p, g, out);
                }
                p += STRIDE;
            }
        }
        if with_short && !self.short.is_empty() && v.len() >= SHORT_KEY {
            for (p, w) in v.windows(SHORT_KEY).enumerate() {
                let k = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                let b = short_bit(k);
                if self.short_bits[b >> 6] & (1 << (b & 63)) != 0 {
                    self.verify_short(v, p, k, out);
                }
            }
        }
    }

    #[inline(never)]
    fn verify_gram(&self, v: &[u8], p: usize, g: u64, out: &mut Vec<(usize, usize, u32)>) {
        let Some(&(lo, hi)) = self.grams.get(&g) else {
            return;
        };
        for &(vi, off) in &self.gram_cands[lo as usize..hi as usize] {
            let off = usize::from(off);
            if p < off {
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

/// Bit `k` set when `b[k]` is a base64 character (`b.len() <= 64`).
#[inline]
fn b64_bits(b: &[u8]) -> u64 {
    let mut m = 0u64;
    for (k, &c) in b.iter().enumerate() {
        m |= u64::from((CLASS[usize::from(c)] >> 6) & 1) << k;
    }
    m
}

/// Finds positions where at least `MIN_B64_RUN` base64 characters follow, 64-byte block by
/// block, caching the current block so consecutive queries cost nothing.
struct RunFinder {
    /// Index of the cached block, `usize::MAX` before the first.
    blk: usize,
    /// Run starts in the cached block.
    starts: u64,
    /// Character bits of the block after it.
    next_bits: u64,
}

impl RunFinder {
    fn new() -> Self {
        Self {
            blk: usize::MAX,
            starts: 0,
            next_bits: 0,
        }
    }

    fn block(&mut self, b: &[u8], blk: usize) {
        let n = b.len();
        let lo = blk * 64;
        let cur = if self.blk != usize::MAX && blk == self.blk + 1 {
            self.next_bits
        } else {
            b64_bits(&b[lo..n.min(lo + 64)])
        };
        let mid = n.min(lo + 64);
        let next = b64_bits(&b[mid..n.min(mid + 64)]);
        let m = u128::from(cur) | (u128::from(next) << 64);
        let mut r = m;
        for k in 1..MIN_B64_RUN {
            r &= m >> k;
        }
        self.blk = blk;
        self.starts = r as u64;
        self.next_bits = next;
    }

    /// First run start at or after `from`.
    fn next(&mut self, b: &[u8], from: usize) -> Option<usize> {
        let mut blk = from / 64;
        let mut off = from % 64;
        while blk * 64 < b.len() {
            if self.blk != blk {
                self.block(b, blk);
            }
            let m = self.starts & (u64::MAX << off);
            if m != 0 {
                return Some(blk * 64 + m.trailing_zeros() as usize);
            }
            blk += 1;
            off = 0;
        }
        None
    }
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

/// A piece of the decoded buffer: which run or hex span at which alignment.
#[derive(Clone, Copy)]
struct DecSeg {
    at: u32,
    len: u32,
    src: u32,
    align: u8,
    hex: bool,
}

/// Appends the bytes `chars` (base64, either alphabet) decode to.
fn decode_b64_into(chars: &[u8], out: &mut Vec<u8>) {
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
    for k in 0..(rest.len() * 6) / 8 {
        out.push((acc >> (16 - 8 * k)) as u8);
    }
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

#[inline]
fn lower_gram(b: &[u8], p: usize) -> u64 {
    if p + 8 <= b.len() {
        let x = u64::from_le_bytes([
            b[p],
            b[p + 1],
            b[p + 2],
            b[p + 3],
            b[p + 4],
            b[p + 5],
            b[p + 6],
            b[p + 7],
        ]);
        swar_lower(x) & 0xFF_FFFF_FFFF
    } else {
        gram_at(b, p)
    }
}

/// ASCII lower-casing of eight bytes at once.
#[inline]
fn swar_lower(x: u64) -> u64 {
    const H: u64 = 0x8080_8080_8080_8080;
    let a = x & !H;
    let ge_a = a.wrapping_add(0x3F3F_3F3F_3F3F_3F3F);
    let gt_z = a.wrapping_add(0x2525_2525_2525_2525);
    let upper = ge_a & !gt_z & !x & H;
    x | (upper >> 2)
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
