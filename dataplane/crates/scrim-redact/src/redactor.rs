//! The redactor, the snapshot that bundles it with the guard and resolver, and the swap holder.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use zeroize::Zeroizing;

use crate::detect::{DetectorConfig, Detectors};
use crate::error::{BuildError, Error};
use crate::guard::{Guard, GuardFinding, GuardInput, GuardScratch, Verdict};
use crate::matcher::{Cursor, Engine, EngineChoice, EngineKind, Match, PatternSet, build_engine};
use crate::placeholder::{Keyring, MAX_PLACEHOLDER_LEN, write_placeholder};
use crate::restore::{Resolver, ResolverEntry, Shaped};
use crate::secret::{Entry, EntryId, EntryMeta, RefSlug, ValueClass};
use crate::shape::shaped_placeholder_for;
use crate::variants::{DEFAULT_JSON_DEPTH, MAX_JSON_DEPTH, Variant, variants};

/// Redaction settings. Canonical configuration keys are given per field.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// `redaction.min_length` (default 8): values shorter than this are short values, matched
    /// only verbatim and in whole encodings, never as base64 fragments, and listed by status.
    pub min_len: usize,
    /// `redaction.short_floor` (default 4, at least 4): values shorter than this cannot be matched
    /// without wrecking traffic; they are rejected at build and listed in the
    /// [`BuildReport::rejected`] ids.
    pub short_floor: usize,
    /// `redaction.engine` (default `auto`).
    pub engine: EngineChoice,
    /// `redaction.engine_threshold` (default 256 patterns): with `auto`, sets with more compiled
    /// patterns use the hash-window engine. Aho-Corasick is only faster while its SIMD (Teddy)
    /// prefilter applies, which is up to 64 patterns per automaton; the engine splits sets of up
    /// to 256 patterns into such automata. Above that the hash-window engine wins (measured, see
    /// the crate README).
    pub engine_threshold: usize,
    /// `redaction.max_body_bytes` (default 64 MiB): larger inputs are refused.
    pub max_input: usize,
    /// `redaction.guard.max_repairs` (default 64): more guard interventions than this in one
    /// body withhold the request instead of repairing it.
    pub guard_max_repairs: usize,
    /// `redaction.json_depth` (default 3, 2 to [`MAX_JSON_DEPTH`]): how many levels of JSON
    /// text inside JSON strings are covered. The redactor compiles each value escaped up to this
    /// many times and the guard unescapes the bytes as often. Two is a tool call's `arguments`
    /// (JSON in a JSON string); three is JSON inside those, such as a tool result holding
    /// `JSON.stringify` output that itself carries a JSON string.
    pub json_depth: usize,
    /// `redaction.detectors.*`.
    pub detectors: DetectorConfig,
    /// `redaction.parallel.threads` (default 4, at most 8): most threads [`Snapshot::protect`]
    /// uses on one large body, for matching and for the guard. Each takes a region of the body;
    /// the output is byte for byte what one thread produces. 1 keeps all work on the calling
    /// thread.
    pub parallel_threads: usize,
    /// `redaction.parallel.min_bytes` (default 512 KiB): bodies shorter than this are handled on
    /// the calling thread only. Below it, starting threads costs more than it saves, and warm
    /// buffers mean no allocation at all; a parallel pass starts scoped threads.
    pub parallel_min_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_len: 8,
            short_floor: 4,
            engine: EngineChoice::Auto,
            engine_threshold: 256,
            max_input: 64 << 20,
            guard_max_repairs: 64,
            json_depth: DEFAULT_JSON_DEPTH,
            detectors: DetectorConfig::default(),
            parallel_threads: 4,
            parallel_min_bytes: 512 << 10,
        }
    }
}

/// What a build produced. Contains counts and ids only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildReport {
    /// Distinct values compiled.
    pub values: usize,
    /// Entries dropped because another entry with a lower id holds the same value.
    pub duplicates: usize,
    /// Values below [`Config::min_len`] (matched only whole).
    pub short: usize,
    /// Entries rejected for being below [`Config::short_floor`]. These values are NOT protected.
    pub rejected: Vec<EntryId>,
    /// Compiled patterns (values times distinct encoded variants).
    pub patterns: usize,
    /// Engine in use.
    pub engine: EngineKind,
    /// Entries that asked for a format-preserving placeholder but have no shape (or are display
    /// values): they use the bracket form.
    pub shape_fallback: Vec<EntryId>,
}

/// Hit counts of one redaction. No values, no positions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Known credential values replaced.
    pub credential: u32,
    /// Known display values replaced.
    pub display: u32,
    /// Fallback detector matches replaced.
    pub detected: u32,
}

impl Stats {
    /// Total replacements.
    pub fn total(&self) -> u32 {
        self.credential + self.display + self.detected
    }
}

/// One replacement, reported through [`Redactor::redact_with`]. Positions refer to the input.
#[derive(Clone, Copy, Debug)]
pub enum Hit<'a> {
    /// A known value in one of its encoded forms.
    Known {
        /// Entry metadata.
        meta: &'a EntryMeta,
        /// Which encoding matched.
        variant: Variant,
        /// Start offset in the input.
        start: usize,
        /// End offset in the input.
        end: usize,
    },
    /// A fallback detector match.
    Detected {
        /// Rule name (`aws-access-key-id`, `high-entropy`, ...).
        rule: &'static str,
        /// Start offset in the input.
        start: usize,
        /// End offset in the input.
        end: usize,
    },
}

pub(crate) struct CompiledEntry {
    pub meta: EntryMeta,
    pub placeholder: Box<[u8]>,
}

/// Replaces known values and detector matches with placeholders. Immutable, `Send + Sync`.
pub struct Redactor {
    entries: Vec<CompiledEntry>,
    set: PatternSet,
    engine: Box<dyn Engine>,
    kind: EngineKind,
    detectors: Detectors,
    keyring: Arc<Keyring>,
    det_slugs: Vec<(&'static str, RefSlug)>,
    resolver: Arc<Resolver>,
    max_input: usize,
    /// Longest compiled pattern.
    max_pattern: usize,
    /// Most threads matching one body uses, and the shortest body matched in parallel.
    threads: usize,
    parallel_min: usize,
    /// Set when some value lies inside a longer one (see [`Nested`]).
    nested: Option<Nested>,
}

/// Values that lie inside longer values (`test` inside `sk-test-...`, ASCII case ignored).
///
/// The redactor finds the longer value only in the forms it compiles. In a form it does not
/// compile but the guard decodes (a hex dump wrapped at 60 columns, `xxd`, `hexdump -C`), it would
/// still find the shorter value, raw in the dump's text column or as a hex form inside a line, and
/// replacing that cuts the longer value apart: the guard then finds no whole value in the outgoing
/// bytes and the rest of it goes out. So around every match of a nested value the redactor asks
/// the guard's decoders what they read in the input, and a value found there that overlaps the
/// match and reaches past it is replaced whole instead ([`Variant::Enclosing`]).
struct Nested {
    /// Per entry, how far around one of its matches a longer value containing it can reach in the
    /// input (0 when no longer value contains it).
    reach: Vec<u32>,
    /// Per entry, the bytes that can sit right before and right after its raw or JSON form when
    /// that lies inside a longer value's encoding ([`Enclosure`]). Inside one, at least one side
    /// of the match touches the longer value (one of its bytes, an escape of one, a line or
    /// column end of a dump or wrapped text); a match with other bytes on both sides is not
    /// inside one, and the guard is not asked.
    sides: Vec<Option<Box<(ByteSet, ByteSet)>>>,
    guard: Arc<Guard>,
}

/// A set of bytes. It says which bytes border a value inside another, so it has no `Debug`.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct ByteSet([u64; 4]);

impl ByteSet {
    const ALL: Self = Self([u64::MAX; 4]);

    fn of(bytes: &[u8]) -> Self {
        let mut s = Self::default();
        for &b in bytes {
            s.add(b);
        }
        s
    }

    fn add(&mut self, b: u8) {
        self.0[usize::from(b >> 6)] |= 1 << (b & 63);
    }

    /// Adds a longer value's byte next to a nested one: in both cases, as rot13 and rot47 (the
    /// guard reads those forms too), as `.` when unprintable (a dump's text column), as `+` when
    /// a space (form encoding) and as the letter of its JSON escape when a control character.
    /// The other escapes of it end in a hex digit or `;` and start with `\\`, `%` or `&`, which
    /// [`BEFORE`] and [`AFTER`] hold.
    fn add_neighbour(&mut self, b: u8) {
        for c in [b, rot13(b), rot47(b)] {
            self.add(c.to_ascii_lowercase());
            self.add(c.to_ascii_uppercase());
        }
        if !(0x20..0x7f).contains(&b) {
            self.add(b'.');
        }
        match b {
            b' ' => self.add(b'+'),
            0x08 => self.add(b'b'),
            0x0c => self.add(b'f'),
            b'\n' => self.add(b'n'),
            b'\r' => self.add(b'r'),
            b'\t' => self.add(b't'),
            _ => {}
        }
    }

    fn has(&self, b: u8) -> bool {
        self.0[usize::from(b >> 6)] & (1 << (b & 63)) != 0
    }

    fn union(&mut self, o: &Self) {
        for (a, b) in self.0.iter_mut().zip(o.0) {
            *a |= b;
        }
    }
}

fn rot13(c: u8) -> u8 {
    match c {
        b'a'..=b'z' => (c - b'a' + 13) % 26 + b'a',
        b'A'..=b'Z' => (c - b'A' + 13) % 26 + b'A',
        _ => c,
    }
}

fn rot47(c: u8) -> u8 {
    if (33..=126).contains(&c) {
        33 + (c - 33 + 47) % 94
    } else {
        c
    }
}

/// What can sit right before a nested value's characters inside a longer value's encoding
/// besides the longer value's own bytes: a line break, raw or as the end of a JSON `\\n` or
/// `\\r`, and the end of an escape of any character (`\\uXXXX`, `%XX` and `\\xNN` end in a
/// hex digit, `&#NN;` in a semicolon).
const BEFORE: &[u8] = b"\n\rnr;0123456789abcdefABCDEF";
/// What can sit right after them: a line break, the end of a `hexdump -C` text column, and the
/// start of an escape. The space and `|` that open a dump's text column only ever come before,
/// with one of these or a byte of the longer value after.
const AFTER: &[u8] = b"\n\r\\|%&";

/// How many input bytes one value byte can take in a form the guard decodes, at most: a `\xNN`
/// escape under three levels of JSON escaping plus a separator is about 17.
const ENCODED_SPREAD: usize = 24;
/// Bytes a dump line adds around its data (offset column, padding).
const ENCODED_SLACK: usize = 256;

thread_local! {
    /// Guard buffers for [`Redactor::widen`], reused per thread and wiped after every use.
    static WIDEN_SCRATCH: std::cell::RefCell<GuardScratch> =
        std::cell::RefCell::new(GuardScratch::new());
}

/// A replacement decided by [`Redactor::widen`]: input range and entry index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Widen {
    start: usize,
    end: usize,
    owner: u32,
}

/// How a value lies inside longer ones, from [`enclosures`]. No `Debug`, like [`ByteSet`].
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Enclosure {
    /// Length of the longest value containing it (0: none does).
    len: usize,
    /// Bytes next to it in those values (both sides, as reversal swaps them; [`ByteSet::ALL`]
    /// where it starts or ends one, or lies inside one's hex form).
    before: ByteSet,
    after: ByteSet,
}

/// For each value, how it lies inside other values, ASCII case ignored: raw inside a longer
/// value, raw inside another value's hex form (a PIN of digits inside a hex dump), or in hex
/// form inside another value (a hex token). Base64 and the other forms are not compared: a value
/// of four or more characters matching inside one by chance is about as likely as any other
/// coincidence of that length.
///
/// Needles are indexed by a hash of their first four bytes (every value has at least four),
/// every position of every haystack is probed and candidates are compared in full. Linear in
/// the total length of the values for sets without shared prefixes.
fn enclosures(values: &[&[u8]]) -> Vec<Enclosure> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hex = |v: &[u8]| {
        let mut h = Zeroizing::new(Vec::with_capacity(v.len() * 2));
        for &b in v {
            h.extend_from_slice(&[HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
        }
        h
    };
    let key = |b: &[u8]| {
        let x = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) | 0x2020_2020;
        x.wrapping_mul(0x9E37_79B1).rotate_left(13)
    };
    let hexes: Vec<Zeroizing<Vec<u8>>> = values.iter().map(|v| hex(v)).collect();
    // (form, owner, raw?) for needles and haystacks alike.
    let forms: Vec<(&[u8], u32, bool)> = values
        .iter()
        .enumerate()
        .map(|(i, v)| (*v, i as u32, true))
        .chain(
            hexes
                .iter()
                .enumerate()
                .map(|(i, h)| (h.as_slice(), i as u32, false)),
        )
        .collect();
    let mut index: Vec<(u32, u32)> = forms
        .iter()
        .enumerate()
        .filter(|(_, (f, _, _))| f.len() >= 4)
        .map(|(n, (f, _, _))| (key(f), n as u32))
        .collect();
    index.sort_unstable();
    let mut out = vec![Enclosure::default(); values.len()];
    for &(hay, hay_owner, hay_raw) in &forms {
        for p in 0..hay.len().saturating_sub(3) {
            let k = key(&hay[p..]);
            let from = index.partition_point(|&(h, _)| h < k);
            for &(h, n) in &index[from..] {
                if h != k {
                    break;
                }
                let (needle, owner, needle_raw) = forms[n as usize];
                // Hex inside hex is the raw case again.
                if owner == hay_owner || !(needle_raw || hay_raw) {
                    continue;
                }
                let long = values[hay_owner as usize].len();
                let q = p + needle.len();
                if (needle_raw && hay_raw && needle.len() >= long)
                    || q > hay.len()
                    || !hay[p..q].eq_ignore_ascii_case(needle)
                {
                    continue;
                }
                let e = &mut out[owner as usize];
                e.len = e.len.max(long);
                match (p.checked_sub(1).map(|i| hay[i]), hay.get(q)) {
                    (Some(l), Some(&r)) if needle_raw && hay_raw => {
                        for side in [&mut e.before, &mut e.after] {
                            side.add_neighbour(l);
                            side.add_neighbour(r);
                        }
                    }
                    _ => {
                        e.before = ByteSet::ALL;
                        e.after = ByteSet::ALL;
                    }
                }
            }
        }
    }
    zeroize::Zeroize::zeroize(&mut index);
    let (before, after) = (ByteSet::of(BEFORE), ByteSet::of(AFTER));
    for e in &mut out {
        e.before.union(&before);
        e.after.union(&after);
    }
    out
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("values", &self.entries.len())
            .field("patterns", &self.set.len())
            .field("engine", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Redactor {
    /// Writes `input` with every known value and detector match replaced into `out` (cleared
    /// first). Output is a pure function of the input and the snapshot, so an unchanged prefix
    /// redacts to identical bytes on every request.
    ///
    /// Does not allocate when `out` already has enough capacity.
    pub fn redact(&self, input: &[u8], out: &mut Vec<u8>) -> Result<Stats, Error> {
        self.redact_with(input, out, &mut |_| {})
    }

    /// Like [`Redactor::redact`], and reports each replacement to `on_hit` (for the audit log).
    pub fn redact_with(
        &self,
        input: &[u8],
        out: &mut Vec<u8>,
        on_hit: &mut dyn FnMut(Hit<'_>),
    ) -> Result<Stats, Error> {
        self.redact_core(input, out, &mut |h| on_hit(h), None)
    }

    /// [`Redactor::redact`] for [`Snapshot::protect`]: on bodies of at least
    /// `parallel_min_bytes`, the matches are found on several threads first (`ms` holds them).
    fn redact_par(
        &self,
        input: &[u8],
        out: &mut Vec<u8>,
        ms: &mut MatchScratch,
    ) -> Result<Stats, Error> {
        self.redact_core(input, out, &mut |_| {}, Some(ms))
    }

    fn redact_core<'r>(
        &'r self,
        input: &[u8],
        out: &mut Vec<u8>,
        on_hit: &mut dyn FnMut(Hit<'r>),
        mut ms: Option<&mut MatchScratch>,
    ) -> Result<Stats, Error> {
        if self.nested.is_none() {
            return self.redact_pass(input, out, on_hit, ms, &[], None);
        }
        // Hits are held back until it is known whether a second pass replaces them.
        let mut hits: Vec<Hit<'r>> = Vec::new();
        let mut inner = Vec::new();
        let st = self.redact_pass(
            input,
            out,
            &mut |h| hits.push(h),
            ms.as_deref_mut(),
            &[],
            Some(&mut inner),
        )?;
        let widen = if inner.is_empty() {
            Vec::new()
        } else {
            self.widen(input, &inner)
        };
        if widen.is_empty() {
            for h in hits {
                on_hit(h);
            }
            return Ok(st);
        }
        // The first output cut a longer value apart; it never leaves this function.
        zeroize::Zeroize::zeroize(out);
        self.redact_pass(input, out, on_hit, ms, &widen, None)
    }

    /// Asks the guard what it reads around each match of a nested value (`inner`, input ranges)
    /// and returns the values it finds there that overlap such a match and reach past it, merged
    /// where they overlap, in input order. Windows around matches are joined where they meet, so
    /// the guard reads each input byte at most once.
    fn widen(&self, input: &[u8], inner: &[(usize, usize, u32)]) -> Vec<Widen> {
        let Some(nested) = &self.nested else {
            return Vec::new();
        };
        let mut found: Vec<(usize, usize, u32)> = Vec::new();
        let mut spans: Vec<(usize, usize, u32)> = Vec::new();
        let mut run = |scratch: &mut GuardScratch| {
            let mut i = 0;
            while i < inner.len() {
                let reach = |&(a, b, r): &(usize, usize, u32)| {
                    (
                        a.saturating_sub(r as usize),
                        (b + r as usize).min(input.len()),
                    )
                };
                let (mut w0, mut w1) = reach(&inner[i]);
                let first = i;
                i += 1;
                while i < inner.len() && reach(&inner[i]).0 <= w1 {
                    let (a, b) = reach(&inner[i]);
                    w0 = w0.min(a);
                    w1 = w1.max(b);
                    i += 1;
                }
                spans.clear();
                nested.guard.spans(&input[w0..w1], scratch, &mut spans);
                for &(a, b, owner) in &spans {
                    let (a, b) = (a + w0, b + w0);
                    if inner[first..i]
                        .iter()
                        .any(|&(s, e, _)| a < e && s < b && (a < s || e < b))
                    {
                        found.push((a, b, owner));
                    }
                }
            }
            scratch.wipe();
        };
        WIDEN_SCRATCH.with(|cell| match cell.try_borrow_mut() {
            Ok(mut scratch) => run(&mut scratch),
            // Re-entered on the same thread (never expected): use fresh buffers.
            Err(_) => run(&mut GuardScratch::new()),
        });
        found.sort_unstable_by_key(|&(a, b, o)| (a, std::cmp::Reverse(b), o));
        let mut out: Vec<Widen> = Vec::with_capacity(found.len());
        for (a, b, owner) in found {
            match out.last_mut() {
                Some(w) if a < w.end => w.end = w.end.max(b),
                _ => out.push(Widen {
                    start: a,
                    end: b,
                    owner,
                }),
            }
        }
        out
    }

    /// One pass over `input`. Matches overlapping a `widen` range are replaced together with it
    /// by that range's value. With `inner`, records every match of a nested value as
    /// `(start, end, reach)`.
    fn redact_pass<'r>(
        &'r self,
        input: &[u8],
        out: &mut Vec<u8>,
        on_hit: &mut dyn FnMut(Hit<'r>),
        ms: Option<&mut MatchScratch>,
        widen: &[Widen],
        mut inner: Option<&mut Vec<(usize, usize, u32)>>,
    ) -> Result<Stats, Error> {
        if input.len() > self.max_input {
            return Err(Error::InputTooLarge);
        }
        out.clear();
        out.reserve(input.len() + input.len() / 16 + MAX_PLACEHOLDER_LEN);
        let mut st = Stats::default();
        let mut cur = match ms {
            Some(ms) if self.workers(input.len()) > 1 => {
                self.collect_matches(input, ms);
                Stream::listed(&ms.list)
            }
            _ => Stream::engine(),
        };
        let mut pos = 0;
        let mut k = 0;
        let mut pending: Option<Match> = None;
        loop {
            let next = match pending.take() {
                Some(m) => Some(m),
                None => cur.next(&*self.engine, &self.set, input),
            };
            while widen.get(k).is_some_and(|w| w.end <= pos) {
                k += 1;
            }
            if let Some(w) = widen.get(k)
                && next.is_none_or(|m| m.end > w.start)
            {
                let (mut start, mut end) = (w.start, w.end);
                match next {
                    Some(m) if m.start < w.end => {
                        start = start.min(m.start);
                        end = end.max(m.end);
                    }
                    Some(m) => pending = Some(m),
                    None => {}
                }
                let start = start.max(pos);
                self.gap(input, pos, start, out, &mut st, on_hit);
                let e = &self.entries[w.owner as usize];
                out.extend_from_slice(&e.placeholder);
                match e.meta.class {
                    ValueClass::Credential => st.credential += 1,
                    ValueClass::Display => st.display += 1,
                }
                on_hit(Hit::Known {
                    meta: &e.meta,
                    variant: Variant::Enclosing,
                    start,
                    end,
                });
                pos = end;
                cur.seek(end);
                k += 1;
                continue;
            }
            let Some(m) = next else { break };
            if let Some((ps, pe)) = self.resolver.covering(input, m.start, m.end)
                && ps >= pos
            {
                // Inside a genuine placeholder from an earlier turn: keep it byte for byte.
                self.gap(input, pos, pe, out, &mut st, on_hit);
                pos = pe;
                cur.seek(pe);
                continue;
            }
            self.gap(input, pos, m.start, out, &mut st, on_hit);
            let info = self.set.info[m.pattern as usize];
            let e = &self.entries[info.owner as usize];
            out.extend_from_slice(&e.placeholder);
            match e.meta.class {
                ValueClass::Credential => st.credential += 1,
                ValueClass::Display => st.display += 1,
            }
            on_hit(Hit::Known {
                meta: &e.meta,
                variant: info.variant,
                start: m.start,
                end: m.end,
            });
            if let (Some(inner), Some(nested)) = (inner.as_deref_mut(), &self.nested) {
                let o = info.owner as usize;
                let reach = nested.reach[o];
                // A textual match with bytes on both sides that cannot border it inside a longer
                // value's encoding is not inside one.
                let apart = info.variant.is_textual()
                    && nested.sides[o].as_ref().is_some_and(|sides| {
                        let (before, after) = &**sides;
                        m.start
                            .checked_sub(1)
                            .is_some_and(|i| !before.has(input[i]))
                            && input.get(m.end).is_some_and(|&c| !after.has(c))
                    });
                if reach > 0 && !apart {
                    inner.push((m.start, m.end, reach));
                }
            }
            pos = m.end;
        }
        self.gap(input, pos, input.len(), out, &mut st, on_hit);
        Ok(st)
    }

    /// Reports every replacement [`Redactor::redact`] would make, in order, as
    /// `(start, end, placeholder)` over `input`, without producing the output for the caller.
    ///
    /// For callers that apply replacements themselves (the HTTPS tool proxy's streaming
    /// redactor). Allocates one scratch buffer per call.
    pub fn find_matches(
        &self,
        input: &[u8],
        f: &mut dyn FnMut(usize, usize, &[u8]),
    ) -> Result<(), Error> {
        let mut spans: Vec<(usize, usize, Option<usize>)> = Vec::new();
        let mut out = Vec::new();
        self.redact_with(input, &mut out, &mut |h| match h {
            Hit::Known {
                meta, start, end, ..
            } => {
                let len = self
                    .entries
                    .binary_search_by_key(&meta.id, |e| e.meta.id)
                    .ok()
                    .map(|i| self.entries[i].placeholder.len());
                spans.push((start, end, len));
            }
            Hit::Detected { start, end, .. } => spans.push((start, end, None)),
        })?;
        // The output is the input with each span replaced by one placeholder: walk both.
        let (mut in_pos, mut out_pos) = (0, 0);
        for (start, end, known) in spans {
            out_pos += start - in_pos;
            let len = match known {
                Some(len) => len,
                None => match crate::placeholder::parse(&out[out_pos..]) {
                    crate::placeholder::Parse::Complete(p) => p.len,
                    _ => unreachable!("redactor output holds a placeholder at every replacement"),
                },
            };
            f(start, end, &out[out_pos..out_pos + len]);
            out_pos += len;
            in_pos = end;
        }
        zeroize::Zeroize::zeroize(&mut out);
        Ok(())
    }

    /// Longest input span one replacement can cover: the longest compiled pattern, or the
    /// longest a fallback detector matches. A streaming caller holds back this many bytes minus
    /// one.
    pub fn max_match_len(&self) -> usize {
        let pats = (0..self.set.len() as u32)
            .map(|i| self.set.get(i).len())
            .max()
            .unwrap_or(0);
        pats.max(self.detectors.max_match_len())
    }

    /// Copies `input[from..to]`, running the fallback detectors over it.
    fn gap<'r>(
        &'r self,
        input: &[u8],
        from: usize,
        to: usize,
        out: &mut Vec<u8>,
        st: &mut Stats,
        on_hit: &mut dyn FnMut(Hit<'r>),
    ) {
        if from >= to {
            return;
        }
        let gap = &input[from..to];
        if self.detectors.is_empty() {
            out.extend_from_slice(gap);
            return;
        }
        if self.resolver.has_shaped() {
            // A format-preserving placeholder looks like the token it stands for, so a detector
            // would take it for one: it is copied as it is and only the text around it is scanned.
            let spans = self.resolver.shaped_spans(gap);
            if !spans.is_empty() {
                let mut at = from;
                for (s, e) in spans {
                    self.detect(input, at, from + s, out, st, on_hit);
                    out.extend_from_slice(&input[from + s..from + e]);
                    at = from + e;
                }
                self.detect(input, at, to, out, st, on_hit);
                return;
            }
        }
        self.detect(input, from, to, out, st, on_hit);
    }

    /// Copies `input[from..to]` with fallback detector matches replaced.
    fn detect<'r>(
        &'r self,
        input: &[u8],
        from: usize,
        to: usize,
        out: &mut Vec<u8>,
        st: &mut Stats,
        on_hit: &mut dyn FnMut(Hit<'r>),
    ) {
        if from >= to {
            return;
        }
        let gap = &input[from..to];
        let mut pos = 0;
        let key = self.keyring.current();
        self.detectors.scan(gap, |d| {
            out.extend_from_slice(&gap[pos..d.start]);
            let fallback;
            let slug = if let Some((_, s)) = self.det_slugs.iter().find(|(r, _)| *r == d.rule) {
                s
            } else {
                fallback = detector_slug(d.rule);
                &fallback
            };
            write_placeholder(out, key, slug, &gap[d.start..d.end]);
            st.detected += 1;
            on_hit(Hit::Detected {
                rule: d.rule,
                start: from + d.start,
                end: from + d.end,
            });
            pos = d.end;
        });
        out.extend_from_slice(&gap[pos..]);
    }

    /// Engine in use.
    pub fn engine(&self) -> EngineKind {
        self.kind
    }

    fn workers(&self, n: usize) -> usize {
        if self.threads <= 1 || n < self.parallel_min {
            1
        } else {
            let chunk = (self.parallel_min / self.threads).max(1);
            self.threads.min(n / chunk).max(1)
        }
    }

    /// All matches a single cursor run over `input` yields (no seeks), found region by region on
    /// scoped threads and stitched into `ms.list`.
    ///
    /// Region `r` starts its own cursor at `q_r` and keeps the matches that start before
    /// `q_{r+1}`, searching only up to `q_{r+1} + max_pattern`: every such match fits there,
    /// so leftmost-longest among them is decided as on the whole input. Stitching keeps the
    /// invariant that the list holds exactly the true matches starting before `q_r`. If the last
    /// of them ends at or before `q_r`, the true next match is the first one at or after `q_r`,
    /// so region `r`'s list continues it as is. If it ends inside region `r`, a cursor from that
    /// end runs until it yields a match region `r` also found; from there the two agree.
    fn collect_matches(&self, input: &[u8], ms: &mut MatchScratch) {
        let n = input.len();
        let k = self.workers(n);
        let cut = |r: usize| r * n / k;
        let hay_end = |r: usize| (cut(r + 1) + self.max_pattern).min(n);
        if ms.parts.len() < k {
            ms.parts.resize_with(k, Vec::new);
        }
        let region = |r: usize, list: &mut Vec<Match>| {
            list.clear();
            let hay = &input[..hay_end(r)];
            let mut cur = Cursor::default();
            cur.seek(cut(r));
            while let Some(m) = self.engine.next(&self.set, hay, &mut cur) {
                if m.start >= cut(r + 1) {
                    break;
                }
                list.push(m);
            }
        };
        std::thread::scope(|sc| {
            let (first, rest) = ms.parts.split_at_mut(1);
            for (i, list) in rest[..k - 1].iter_mut().enumerate() {
                sc.spawn(move || region(i + 1, list));
            }
            region(0, &mut first[0]);
        });

        ms.list.clear();
        for r in 0..k {
            let part = &ms.parts[r];
            let pos = ms.list.last().map_or(0, |m| m.end);
            if pos <= cut(r) {
                ms.list.extend_from_slice(part);
                continue;
            }
            let hay = &input[..hay_end(r)];
            let mut cur = Cursor::default();
            cur.seek(pos);
            while let Some(m) = self.engine.next(&self.set, hay, &mut cur) {
                if m.start >= cut(r + 1) {
                    break;
                }
                ms.list.push(m);
                let at = part.partition_point(|x| x.start < m.start);
                if part.get(at) == Some(&m) {
                    ms.list.extend_from_slice(&part[at + 1..]);
                    break;
                }
            }
        }
    }
}

/// Most threads one body uses.
const MAX_THREADS: usize = 8;

/// Buffers for matching in parallel. Part of [`Workspace`].
#[derive(Default)]
struct MatchScratch {
    parts: Vec<Vec<Match>>,
    list: Vec<Match>,
}

/// The match sequence [`Redactor::redact_core`] consumes: an engine cursor, or a precomputed
/// list of what a cursor without seeks yields. After a seek past a listed match's start, the
/// list is still right from its first match at or after the new position, unless the match
/// before that one ends beyond the position; then the engine runs from the position until it
/// yields a listed match again.
struct Stream<'a> {
    list: &'a [Match],
    /// Next list index.
    i: usize,
    /// Search position: the end of the last match, or a seek target.
    pos: usize,
    /// `Some` while the engine runs, with its cursor.
    engine: Option<Cursor>,
}

impl<'a> Stream<'a> {
    /// The engine throughout.
    fn engine() -> Self {
        Self {
            list: &[],
            i: 0,
            pos: 0,
            engine: Some(Cursor::default()),
        }
    }

    /// From a precomputed list.
    fn listed(list: &'a [Match]) -> Self {
        Self {
            list,
            i: 0,
            pos: 0,
            engine: None,
        }
    }

    fn seek(&mut self, pos: usize) {
        self.pos = self.pos.max(pos);
    }

    fn next(&mut self, engine: &dyn Engine, set: &PatternSet, hay: &[u8]) -> Option<Match> {
        if self.engine.is_none() {
            let mut last_end = None;
            while let Some(m) = self.list.get(self.i)
                && m.start < self.pos
            {
                last_end = Some(m.end);
                self.i += 1;
            }
            if last_end.is_none_or(|e| e <= self.pos) {
                let m = *self.list.get(self.i)?;
                self.i += 1;
                self.pos = m.end;
                return Some(m);
            }
            self.engine = Some(Cursor::default());
        }
        let cur = self.engine.as_mut()?;
        cur.seek(self.pos);
        let m = engine.next(set, hay, cur)?;
        self.pos = m.end;
        if !self.list.is_empty() {
            let at = self.i + self.list[self.i..].partition_point(|x| x.start < m.start);
            if self.list.get(at) == Some(&m) {
                self.i = at + 1;
                self.engine = None;
            } else {
                self.i = at;
            }
        }
        Some(m)
    }
}

fn detector_slug(rule: &str) -> RefSlug {
    RefSlug::from_alias(&format!("det-{rule}"))
}

/// One immutable, consistent redaction state: redactor, guard and resolver built from the same
/// values and keyring. Share it as `Arc<Snapshot>`; it is `Send + Sync` and every method takes
/// `&self`. A request should load one snapshot and use it from start to end.
pub struct Snapshot {
    redactor: Redactor,
    guard: Arc<Guard>,
    resolver: Arc<Resolver>,
    report: BuildReport,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

/// Reusable per-request buffers for [`Snapshot::protect`]. Not shared between threads; keep one
/// per worker and reuse it so the hot path does not allocate.
#[derive(Default)]
pub struct Workspace {
    out: Vec<u8>,
    guard: GuardScratch,
    matches: MatchScratch,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Workspace(<redacted>)")
    }
}

impl Workspace {
    /// Empty workspace.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wipes buffers that held request bytes, keeping their capacity.
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.out.zeroize();
        self.guard.wipe();
    }
}

/// What the guard did in [`Snapshot::protect`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardOutcome {
    /// Nothing found.
    Clean,
    /// The guard repaired the redactor's output; audit each finding.
    Repaired,
}

/// The bytes to send, with what happened to them.
#[derive(Debug)]
pub struct Protected<'w> {
    /// Exactly the bytes to forward.
    pub bytes: &'w [u8],
    /// Redactor counts.
    pub stats: Stats,
    /// Guard outcome.
    pub guard: GuardOutcome,
    /// Guard findings (empty when clean). Every one is a guard intervention for the audit log.
    pub findings: &'w [GuardFinding],
}

impl Snapshot {
    /// Builds a snapshot. Expensive (milliseconds to about a second for 10,000 values); run it
    /// off the request path and publish it with [`SnapshotHandle::store`].
    ///
    /// Entries are ordered by id. When several entries hold the same value the lowest id wins, so
    /// the output does not depend on the order entries are given in.
    pub fn build(
        entries: Vec<Entry>,
        keyring: Arc<Keyring>,
        config: &Config,
    ) -> Result<Self, BuildError> {
        if config.short_floor < 4 {
            return Err(BuildError::InvalidConfig("short_floor below 4"));
        }
        if config.max_input > u32::MAX as usize {
            return Err(BuildError::InvalidConfig("max_input above 4 GiB"));
        }
        if config.min_len < config.short_floor {
            return Err(BuildError::InvalidConfig("min_len below short_floor"));
        }
        if !(2..=MAX_JSON_DEPTH).contains(&config.json_depth) {
            return Err(BuildError::InvalidConfig("json_depth outside 2 to 4"));
        }
        let mut entries = entries;
        entries.sort_by_key(|e| e.meta.id);

        let mut seen: HashSet<&[u8]> = HashSet::with_capacity(entries.len());
        let mut keep = vec![false; entries.len()];
        let mut rejected = Vec::new();
        let mut duplicates = 0;
        for (i, e) in entries.iter().enumerate() {
            if e.value.len() < config.short_floor {
                rejected.push(e.meta.id);
            } else if !seen.insert(e.value.expose()) {
                duplicates += 1;
            } else {
                keep[i] = true;
            }
        }
        drop(seen);
        let kept: Vec<Entry> = entries
            .into_iter()
            .zip(keep)
            .filter_map(|(e, k)| k.then_some(e))
            .collect();

        let key = keyring.current();
        let mut compiled = Vec::with_capacity(kept.len());
        let mut set = PatternSet::new();
        let mut pat_seen: HashSet<Vec<u8>> = HashSet::new();
        let mut short = 0;
        let mut shaped_items: Vec<(Vec<u8>, u32)> = Vec::new();
        let mut shape_fallback = Vec::new();
        for (i, e) in kept.iter().enumerate() {
            let mut ph = Vec::with_capacity(MAX_PLACEHOLDER_LEN);
            let shaped = (e.shape && e.meta.class == ValueClass::Credential)
                .then(|| {
                    let mut all = Vec::new();
                    for k in keyring.keys() {
                        all.push(shaped_placeholder_for(k, &e.meta.slug, e.value.expose())?);
                    }
                    Some(all)
                })
                .flatten();
            if e.shape && shaped.is_none() {
                shape_fallback.push(e.meta.id);
            }
            match shaped {
                Some(all) => {
                    ph.extend_from_slice(all[0].as_bytes());
                    for p in all {
                        shaped_items.push((p.into_bytes(), i as u32));
                    }
                }
                None => write_placeholder(&mut ph, key, &e.meta.slug, e.value.expose()),
            }
            compiled.push(CompiledEntry {
                meta: e.meta.clone(),
                placeholder: ph.into(),
            });
            let is_short = e.value.len() < config.min_len;
            short += usize::from(is_short);
            for (variant, bytes) in variants(e.value.expose(), is_short, config.json_depth) {
                if pat_seen.contains(&bytes) {
                    zeroize::Zeroize::zeroize(&mut { bytes });
                    continue;
                }
                set.push(&bytes, i as u32, variant);
                pat_seen.insert(bytes);
            }
        }
        for mut k in pat_seen.drain() {
            zeroize::Zeroize::zeroize(&mut k);
        }

        let kind = match config.engine {
            EngineChoice::Fixed(k) => k,
            EngineChoice::Auto if set.len() > config.engine_threshold => EngineKind::HashWindow,
            EngineChoice::Auto => EngineKind::AhoCorasick,
        };
        let engine = build_engine(&set, kind)?;
        let detectors = Detectors::build(&config.detectors)?;

        let mut map = HashMap::with_capacity(kept.len() * 2);
        for (i, e) in kept.iter().enumerate() {
            for k in keyring.keys() {
                map.insert((k.version(), k.tag(e.value.expose())), i as u32);
            }
        }
        let res_entries: Arc<[ResolverEntry]> = kept
            .into_iter()
            .map(|e| ResolverEntry {
                meta: e.meta,
                value: e.value,
            })
            .collect();
        // A shaped placeholder that equals another entry's value or another shaped placeholder
        // would be ambiguous: refuse the build rather than guess.
        {
            // Two keys with the same bytes give one entry the same shaped placeholder twice;
            // that is harmless. The same placeholder for two entries is not.
            shaped_items.sort();
            shaped_items.dedup();
            let mut seen: HashSet<&[u8]> = HashSet::new();
            for (p, _) in &shaped_items {
                if !seen.insert(p) || res_entries.iter().any(|e| e.value.expose() == p.as_slice()) {
                    return Err(BuildError::InvalidConfig(
                        "a format-preserving placeholder collides with a value or another placeholder",
                    ));
                }
            }
        }
        let resolver = Arc::new(Resolver::new(map, res_entries, Shaped::new(shaped_items)?));

        let guard_inputs: Vec<GuardInput<'_>> = resolver
            .entries()
            .iter()
            .zip(&compiled)
            .map(|(e, c)| GuardInput {
                value: e.value.expose(),
                entry: e.meta.id,
                placeholder: &c.placeholder,
            })
            .collect();
        let guard = Arc::new(Guard::build(
            &guard_inputs,
            config.min_len,
            config.guard_max_repairs,
            config.json_depth,
            (config.parallel_threads, config.parallel_min_bytes),
            resolver.clone(),
        ));
        drop(guard_inputs);
        let enclosing = enclosures(
            &resolver
                .entries()
                .iter()
                .map(|e| e.value.expose())
                .collect::<Vec<_>>(),
        );
        let nested = enclosing.iter().any(|e| e.len > 0).then(|| Nested {
            reach: enclosing
                .iter()
                .map(|e| {
                    if e.len == 0 {
                        0
                    } else {
                        u32::try_from(e.len * ENCODED_SPREAD + ENCODED_SLACK).unwrap_or(u32::MAX)
                    }
                })
                .collect(),
            sides: enclosing
                .iter()
                .map(|e| (e.len > 0).then(|| Box::new((e.before, e.after))))
                .collect(),
            guard: guard.clone(),
        });

        let report = BuildReport {
            values: compiled.len(),
            duplicates,
            short,
            rejected,
            patterns: set.len(),
            engine: kind,
            shape_fallback,
        };
        let det_slugs = crate::detect::builtin_rule_names()
            .into_iter()
            .chain(std::iter::once(crate::detect::ENTROPY_RULE))
            .map(|r| (r, detector_slug(r)))
            .collect();
        let redactor = Redactor {
            entries: compiled,
            engine,
            kind,
            detectors,
            keyring,
            det_slugs,
            resolver: resolver.clone(),
            max_input: config.max_input,
            max_pattern: (0..set.len() as u32)
                .map(|i| set.get(i).len())
                .max()
                .unwrap_or(0),
            threads: config.parallel_threads.clamp(1, MAX_THREADS),
            parallel_min: config.parallel_min_bytes,
            set,
            nested,
        };
        Ok(Self {
            redactor,
            guard,
            resolver,
            report,
        })
    }

    /// The redactor.
    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// The guard.
    pub fn guard(&self) -> &Guard {
        &self.guard
    }

    /// The resolver for placeholders in responses.
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// Build counts (for `scrim status`).
    pub fn report(&self) -> &BuildReport {
        &self.report
    }

    /// Redacts `input` and runs the guard over the result: the full outbound check.
    ///
    /// `Ok` carries exactly the bytes to forward. `Err` means refuse the request; nothing may be
    /// forwarded, and there is no unredacted fallback.
    pub fn protect<'w>(&self, input: &[u8], ws: &'w mut Workspace) -> Result<Protected<'w>, Error> {
        let stats = self
            .redactor
            .redact_par(input, &mut ws.out, &mut ws.matches)?;
        match self.guard.check(&ws.out, &mut ws.guard) {
            Verdict::Clean => Ok(Protected {
                bytes: &ws.out,
                stats,
                guard: GuardOutcome::Clean,
                findings: &[],
            }),
            Verdict::Repaired { bytes, findings } => Ok(Protected {
                bytes,
                stats,
                guard: GuardOutcome::Repaired,
                findings,
            }),
            Verdict::Withhold(r) => Err(Error::Withheld(r)),
        }
    }
}

/// Holds the current snapshot and swaps it atomically.
///
/// Readers call [`SnapshotHandle::load`] once per request and keep the returned `Arc` until the
/// request is done, so a request sees one consistent snapshot even if a rebuild is published
/// meanwhile. Loading is lock-free and never waits for a rebuild; [`SnapshotHandle::store`] is a
/// single atomic swap, and the old snapshot is freed when its last request drops it.
#[derive(Debug, Default)]
pub struct SnapshotHandle {
    cur: ArcSwapOption<Snapshot>,
}

impl SnapshotHandle {
    /// A handle with no snapshot: [`SnapshotHandle::load`] returns [`Error::NotReady`] until the
    /// first [`SnapshotHandle::store`].
    pub fn new() -> Self {
        Self::default()
    }

    /// The current snapshot, or [`Error::NotReady`] if none has been stored.
    pub fn load(&self) -> Result<Arc<Snapshot>, Error> {
        self.cur.load_full().ok_or(Error::NotReady)
    }

    /// Publishes `snap` for all later loads.
    pub fn store(&self, snap: Arc<Snapshot>) {
        self.cur.store(Some(snap));
    }

    /// Whether a snapshot has been stored.
    pub fn is_ready(&self) -> bool {
        self.cur.load().is_some()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;
    use crate::placeholder::PlaceholderKey;
    use crate::secret::SecretValue;
    use proptest::prelude::*;

    fn snap(values: &[Vec<u8>], kind: EngineKind, threads: usize, min: usize) -> Snapshot {
        let kr = Arc::new(Keyring::new(PlaceholderKey::new(1, &[3; 32]).unwrap()));
        let entries = values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                Entry::new(
                    i as u64 + 1,
                    RefSlug::new(&format!("v{i}")).unwrap(),
                    ValueClass::Display,
                    SecretValue::from_slice(v),
                )
            })
            .collect();
        let cfg = Config {
            min_len: 4,
            engine: EngineChoice::Fixed(kind),
            parallel_threads: threads,
            parallel_min_bytes: min,
            detectors: DetectorConfig {
                rules_enabled: false,
                ..Default::default()
            },
            ..Config::default()
        };
        Snapshot::build(entries, kr, &cfg).unwrap()
    }

    /// What one cursor yields over `hay`, seeking to `seeks[k]` after the `k`-th match when
    /// given.
    fn chain(r: &Redactor, hay: &[u8], seeks: &[usize]) -> Vec<Match> {
        let mut cur = Cursor::default();
        let mut v = Vec::new();
        while let Some(m) = r.engine.next(&r.set, hay, &mut cur) {
            if let Some(&s) = seeks.get(v.len()) {
                cur.seek(s);
            }
            v.push(m);
        }
        v
    }

    fn values() -> impl Strategy<Value = Vec<Vec<u8>>> {
        prop::collection::vec(
            prop::collection::vec(prop::sample::select(b"ab".to_vec()), 4..14),
            1..8,
        )
    }

    fn hay() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(prop::sample::select(b"aab".to_vec()), 0..400)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        /// Stitched region lists are exactly the single-cursor match list, with matches
        /// overlapping region ends nearly everywhere (values over a two-letter alphabet).
        #[test]
        fn collected_matches_equal_one_cursor(vals in values(), hay in hay(), threads in 2usize..9) {
            for kind in [EngineKind::AhoCorasick, EngineKind::HashWindow] {
                let s = snap(&vals, kind, threads, 8);
                let r = s.redactor();
                let mut ms = MatchScratch::default();
                r.collect_matches(&hay, &mut ms);
                prop_assert_eq!(&ms.list, &chain(r, &hay, &[]));
            }
        }

        /// A stream over the stitched list with seeks yields what a cursor with the same seeks
        /// yields.
        #[test]
        fn stream_with_seeks_equals_cursor(
            vals in values(),
            hay in hay(),
            jumps in prop::collection::vec(0usize..12, 0..40),
        ) {
            for kind in [EngineKind::AhoCorasick, EngineKind::HashWindow] {
                let s = snap(&vals, kind, 4, 8);
                let r = s.redactor();
                let mut ms = MatchScratch::default();
                r.collect_matches(&hay, &mut ms);
                // Seek targets relative to each match's end, as the redactor's skip of a
                // genuine placeholder does.
                let mut want = Vec::new();
                let mut cur = Cursor::default();
                let mut stream = Stream::listed(&ms.list);
                let mut got = Vec::new();
                let mut k = 0;
                while let Some(m) = r.engine.next(&r.set, &hay, &mut cur) {
                    want.push(m);
                    let g = stream.next(&*r.engine, &r.set, &hay);
                    got.push(g);
                    let j = jumps.get(k).copied().unwrap_or(0);
                    k += 1;
                    cur.seek(m.end + j);
                    stream.seek(m.end + j);
                }
                prop_assert_eq!(stream.next(&*r.engine, &r.set, &hay), None);
                let want: Vec<Option<Match>> = want.into_iter().map(Some).collect();
                prop_assert_eq!(got, want);
            }
        }
    }

    #[test]
    fn enclosures_find_values_inside_other_values() {
        let vals: [&[u8]; 9] = [
            b"test",
            b"xx-TEST-yy-zz",
            b"xx-test",
            b"unrelated-value",
            b"Test",
            b"lue",
            b"2d74",
            b"spaced test value",
            b"<-74657374->",
        ];
        let got: Vec<usize> = enclosures(&vals).iter().map(|e| e.len).collect();
        // `test` and `Test` are in `xx-TEST-yy-zz` (13 bytes), `xx-test` (7), `spaced test
        // value` (17) and, in hex form, in `<-74657374->` (12); `xx-test` is a prefix of
        // `xx-TEST-yy-zz`; `2d74` is the hex form of `-t` in `xx-test` (`xx-TEST` has `-T`,
        // 2d54); `lue` is below four bytes and never indexed.
        assert_eq!(got, vec![17, 0, 13, 0, 17, 0, 7, 0, 0]);
        let e = enclosures(&vals);
        // Hex containment and prefixes allow anything next to the match.
        assert!(e[0].before == ByteSet::ALL);
        assert!(e[2].before == ByteSet::ALL);
        assert!(e[6].after == ByteSet::ALL);

        // Strictly inside, raw only: the neighbours (and their case, rot13 and rot47 forms) and
        // the structural bytes.
        let vals: [&[u8]; 2] = [b"test", b"sk-test-value"];
        let e = enclosures(&vals)[0];
        assert_eq!(e.len, 13);
        // The neighbour `-` and its rot47 form `\`, line breaks.
        for c in *b"-\\\n" {
            assert!(e.before.has(c) && e.after.has(c), "{}", c as char);
        }
        // The end of an escape, the end of a JSON line break.
        for c in *b"f7;n" {
            assert!(e.before.has(c) && !e.after.has(c), "{}", c as char);
        }
        // The start of an escape, the end of a `hexdump -C` text column.
        for c in *b"%&|" {
            assert!(!e.before.has(c) && e.after.has(c), "{}", c as char);
        }
        for c in *b" \"._(,xX!+" {
            assert!(!e.before.has(c) && !e.after.has(c), "{}", c as char);
        }
        // An unprintable or space neighbour shows as `.` in a dump, as `+` in a form.
        let vals: [&[u8]; 2] = [b"test", b"sk\x01test value"];
        let e = enclosures(&vals)[0];
        for c in *b".+ " {
            assert!(e.before.has(c) && e.after.has(c), "{}", c as char);
        }
    }

    #[test]
    fn bench_sets_have_no_nested_values() {
        // The reference sets take the plain path, so the benchmarks measure it unchanged.
        let kr = Arc::new(Keyring::new(PlaceholderKey::new(1, &[3; 32]).unwrap()));
        for n in [10usize, 1_000, 10_000] {
            let entries = crate::guard_tests::fixtures::gen_secrets(20_261_120 + n as u64, n)
                .into_iter()
                .enumerate()
                .map(|(i, v)| {
                    Entry::new(
                        i as u64 + 1,
                        RefSlug::new(&format!("s{i}")).unwrap(),
                        ValueClass::Credential,
                        SecretValue::from_slice(v.as_bytes()),
                    )
                })
                .collect();
            let s = Snapshot::build(entries, kr.clone(), &Config::default()).unwrap();
            assert!(s.redactor().nested.is_none(), "set of {n}");
        }
    }

    #[test]
    fn nested_values_take_the_widening_path() {
        let s = snap(
            &[b"test".to_vec(), b"sk-test-0123456789abcdef".to_vec()],
            EngineKind::AhoCorasick,
            1,
            8,
        );
        let n = s.redactor().nested.as_ref().unwrap();
        assert_eq!(n.reach[0] as usize, 24 * ENCODED_SPREAD + ENCODED_SLACK);
        assert_eq!(n.reach[1], 0);
    }
}
