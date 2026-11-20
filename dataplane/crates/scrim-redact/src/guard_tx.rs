//! Transform decoders of the guard (design D4: the guard decodes transforms the redactor does not
//! attempt).
//!
//! `guard.rs` reads the bytes through the encodings a client or serialiser applies (JSON escapes,
//! percent-encoding, base64, hex). This module covers what an agent's own tools make of a value:
//! the output of `rev`, `tr`, `base32`, `xxd`, `hexdump`, `od`, `fold`, `sed` and one-line
//! scripts. It reaches the guard through two narrow hooks, so the guard's own views stay as they
//! are:
//!
//! * [`derived_forms`]: forms of every long value the guard indexes next to the value itself, so
//!   its ordinary scan of every view finds them: the value reversed (`rev`), rot13 and rot47
//!   (`tr`), and its inner base64 forms at the three byte alignments (base64 of base64, a
//!   base64-encoded document holding base64). Indexing costs nothing per request.
//! * [`Transforms::collect`]: decoded views of the once-unescaped bytes, scanned with the guard's
//!   own matcher, plus fragment matching:
//!   * separated units: a value written one unit at a time with a fixed separator between units
//!     (spaced letters, one per line, commas, dashes, zero-width characters, Python character and
//!     byte lists, decimal byte lists, `0x41, 0x42`) or as a run of self-delimiting escapes
//!     (`\x41`, `\101`, `&#65;`, `&#x41;`, `%2541`);
//!   * byte dumps: `xxd`, `xxd -p`, `hexdump -C`, `od -An -tx1`, `od -tx1` and `od -c` lines,
//!     joined across lines, with the ASCII column covered by the repair;
//!   * base32 in both alphabets (`base32`, `basenc --base32hex`), at every alignment, runs
//!     continuing across line breaks;
//!   * fragments: a run of a value's bytes (or of the reversed value) of at least half its length (at least the minimum
//!     length, at most 24 bytes) that is not only format-fixed text (PEM armour, a JWT header).
//!
//! Every decoder is linear in the input, bounded per byte, and allocates nothing once its scratch
//! space has grown: clean text costs one table lookup per byte for the unit and base32 scanners, a
//! check per line start for dumps and one probe every four bytes for fragments.
//!
//! What is deliberately not decoded (documented limitations): look-alike Unicode (homoglyphs,
//! fullwidth forms), spelling alphabets, compression, the base85 family and arbitrary ciphers.

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::guard::GuardView;

/// Fewest units a separated or escaped run needs to be decoded (the guard's long values are at
/// least eight bytes).
const MIN_UNITS: usize = 8;
/// Longest separator between units, in bytes.
const MAX_SEP: usize = 6;
/// Shortest base32 run worth decoding: an eight-byte value is thirteen characters.
const MIN_B32_RUN: usize = 13;
/// Fewest decoded bytes a dump run needs.
const MIN_DUMP_BYTES: usize = 8;
/// Fragment index gram length and probe stride: a fragment of at least eight bytes holds a gram
/// starting at a multiple of four.
const GRAM: usize = 5;
const STRIDE: usize = 4;
/// Longest fragment length required, so a single line of a private key counts.
const MAX_FRAGMENT: usize = 24;
/// Offsets kept per gram and value, so a value repeating one gram cannot make probes expensive.
const MAX_OFFSETS_PER_GRAM: usize = 8;

// ---------------------------------------------------------------------------- derived forms

/// Calls `push` with every form of `v` the guard indexes besides `v` itself: reversed, rot13,
/// rot47 and the inner base64 forms at byte offsets 0, 1 and 2 (standard alphabet, and URL-safe
/// when different). Forms equal to `v` or to each other (ignoring ASCII case) and forms shorter
/// than eight bytes are skipped.
pub(crate) fn derived_forms(v: &[u8], mut push: impl FnMut(Zeroizing<Vec<u8>>)) {
    let mut forms: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(9);
    let mut add = |f: Zeroizing<Vec<u8>>| {
        if f.len() >= 8
            && !f.eq_ignore_ascii_case(v)
            && !forms.iter().any(|g| g.eq_ignore_ascii_case(&f))
        {
            forms.push(f);
        }
    };
    let mut r = Zeroizing::new(v.to_vec());
    r.reverse();
    add(r);
    add(Zeroizing::new(v.iter().map(|&c| rot13(c)).collect()));
    add(Zeroizing::new(v.iter().map(|&c| rot47(c)).collect()));
    for k in 0..3 {
        let std = b64_inner(v, k);
        if std.iter().any(|&c| c == b'+' || c == b'/') {
            let url = Zeroizing::new(
                std.iter()
                    .map(|&c| match c {
                        b'+' => b'-',
                        b'/' => b'_',
                        c => c,
                    })
                    .collect(),
            );
            add(std);
            add(url);
        } else {
            add(std);
        }
    }
    forms.into_iter().for_each(&mut push);
}

fn rot13(c: u8) -> u8 {
    match c {
        b'a'..=b'z' => b'a' + (c - b'a' + 13) % 26,
        b'A'..=b'Z' => b'A' + (c - b'A' + 13) % 26,
        _ => c,
    }
}

fn rot47(c: u8) -> u8 {
    if (b'!'..=b'~').contains(&c) {
        b'!' + (c - b'!' + 47) % 94
    } else {
        c
    }
}

/// The base64 characters (standard alphabet) that encode only `v`'s bits when `v` starts at byte
/// offset `k` of a stream.
fn b64_inner(v: &[u8], k: usize) -> Zeroizing<Vec<u8>> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let first = (8 * k).div_ceil(6);
    let last = (8 * (k + v.len())) / 6;
    let mut out = Zeroizing::new(Vec::with_capacity(last.saturating_sub(first)));
    for c in first..last {
        let mut x = 0usize;
        for bit in 0..6 {
            let pos = 6 * c + bit;
            let byte = pos / 8 - k;
            x = (x << 1) | usize::from((v[byte] >> (7 - pos % 8)) & 1);
        }
        out.push(A[x]);
    }
    out
}

// ---------------------------------------------------------------------------- the index

/// The guard's matcher: pushes `(start, end, owner)` for every value found in a view.
pub(crate) type Scan<'a> = dyn Fn(&[u8], &mut Vec<(usize, usize, u32)>) + 'a;

/// The transform part of the guard, built with it from the same values.
pub(crate) struct Transforms {
    frags: Fragments,
}

impl Transforms {
    /// `long` holds the long values (at least `min_len` bytes, at least eight) with their owner.
    pub(crate) fn build<'a>(long: impl Iterator<Item = (&'a [u8], u32)>, min_len: usize) -> Self {
        Self {
            frags: Fragments::build(long, min_len.max(8)),
        }
    }

    /// Decodes `base` (the once-unescaped outgoing bytes) into the transform views, finds values
    /// in them with `scan` (the guard's matcher: `(view, out)` pushes `(start, end, owner)`), and
    /// calls `emit(start, end, owner, view)` with each hit in `base` coordinates, fragments last.
    pub(crate) fn collect(
        &self,
        base: &[u8],
        s: &mut TxScratch,
        scan: &Scan<'_>,
        emit: &mut dyn FnMut(usize, usize, u32, GuardView),
    ) {
        self.collect_in(base, s, scan, emit);
        // Text documents sent as base64 data URLs: the guard's base64 view shows their text, and
        // the transform views are taken over that text too.
        let mut doc = std::mem::take(&mut s.doc);
        let mut sub = s.sub.take().unwrap_or_default();
        for m in memchr::memmem::find_iter(base, b";base64,") {
            let st = m + 8;
            let len = base[st..]
                .iter()
                .take_while(|&&c| B64V[usize::from(c)] != 0xFF)
                .count();
            if len < 16 {
                continue;
            }
            doc.clear();
            b64_decode(&base[st..st + len], &mut doc);
            // Only text: binary documents (images, PDFs) hold no tool output.
            let probe = &doc[..doc.len().min(256)];
            if probe
                .iter()
                .filter(|&&c| c < 0x09 || (c > 0x0D && c < 0x20))
                .count()
                * 16
                > probe.len()
            {
                continue;
            }
            // Byte k of the document holds bits 8k..8k+8 of the characters.
            let at = |k: usize| st + (8 * k) / 6;
            let to = |k: usize| (st + (8 * k + 7) / 6 + 1).min(st + len);
            self.collect_in(&doc, &mut sub, scan, &mut |a, b, o, v| {
                emit(at(a), to(b - 1), o, v);
            });
        }
        s.sub = Some(sub);
        s.doc = doc;
    }

    fn collect_in(
        &self,
        base: &[u8],
        s: &mut TxScratch,
        scan: &Scan<'_>,
        emit: &mut dyn FnMut(usize, usize, u32, GuardView),
    ) {
        s.clear();
        separated(base, s);
        dumps(base, s);
        base32(base, s);
        if !s.bytes.is_empty() {
            s.hits.clear();
            scan(&s.bytes, &mut s.hits);
            let whole = s.hits.len();
            // Fragments too: a decoded run may start or end inside the value.
            self.frags.scan(&s.bytes, &mut s.hits);
            for (i, &(x, y, o)) in s.hits.iter().enumerate() {
                let k = s.segs.partition_point(|g| g.at as usize <= x);
                let g = s.segs[k - 1];
                if y > g.end as usize {
                    // Straddles two decoded runs: not a real occurrence.
                    continue;
                }
                let view = if i < whole {
                    g.view
                } else {
                    GuardView::Fragment
                };
                emit(s.spans[x].0 as usize, s.spans[y - 1].1 as usize, o, view);
            }
        }
        s.hits.clear();
        self.frags.scan(base, &mut s.hits);
        for &(a, b, o) in &s.hits {
            emit(a, b, o, GuardView::Fragment);
        }
    }
}

/// Reusable buffers for [`Transforms::collect`]. Part of `GuardScratch`.
#[derive(Default)]
pub(crate) struct TxScratch {
    /// Every decoded run, back to back.
    bytes: Vec<u8>,
    /// Per decoded byte, the range of `base` that produced it (for dumps, up to the end of the
    /// line's ASCII column).
    spans: Vec<(u32, u32)>,
    /// One per decoded run, in order.
    segs: Vec<Seg>,
    /// Positions of a base32 run's characters when it spans line breaks.
    pos: Vec<u32>,
    hits: Vec<(usize, usize, u32)>,
    /// A decoded base64 document and the scratch space for its views.
    doc: Vec<u8>,
    sub: Option<Box<TxScratch>>,
}

#[derive(Clone, Copy)]
struct Seg {
    at: u32,
    end: u32,
    view: GuardView,
}

impl TxScratch {
    fn clear(&mut self) {
        self.bytes.clear();
        self.spans.clear();
        self.segs.clear();
        self.pos.clear();
        self.hits.clear();
    }

    /// Wipes the decoded bytes. Capacity is kept.
    pub(crate) fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
        self.doc.zeroize();
        if let Some(sub) = &mut self.sub {
            sub.wipe();
        }
    }

    fn push(&mut self, byte: u8, from: usize, to: usize) {
        self.bytes.push(byte);
        self.spans.push((from as u32, to as u32));
    }

    /// Opens a decoded run; returns the mark to pass to [`TxScratch::close`].
    fn mark(&self) -> usize {
        self.bytes.len()
    }

    /// Keeps the run opened at `at` when it has at least `min` bytes, else drops it.
    fn close(&mut self, at: usize, min: usize, view: GuardView) -> bool {
        if self.bytes.len() - at >= min {
            self.segs.push(Seg {
                at: at as u32,
                end: self.bytes.len() as u32,
                view,
            });
            true
        } else {
            self.bytes.truncate(at);
            self.spans.truncate(at);
            false
        }
    }
}

// ---------------------------------------------------------------------------- separated units

/// How one unit of a separated or escaped run is written.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fam {
    /// One character, or a backslash escape `\n \t \r \0 \\` (`od -c` on one line), `\"` or `\/`
    /// (JSON inside a JSON string, such as tool-call arguments, still escaped once).
    Char,
    /// A quoted character: `'a'`, `"a"`, `'\n'`, `'\x00'` (Python's `list(s)`).
    Quoted,
    /// A decimal byte, 0 to 255 (`od -An -tu1`, Python's `list(s.encode())`).
    Dec,
    /// `0x41` (`xxd -i`).
    Hex0x,
    /// `\x41`.
    CHex,
    /// `\101`.
    Oct,
    /// `&#65;` or `&#x41;`.
    Entity,
    /// `%2541`, a percent-encoded percent escape.
    Url25,
}

const FAMS: [Fam; 8] = [
    Fam::Quoted,
    Fam::Dec,
    Fam::Hex0x,
    Fam::CHex,
    Fam::Oct,
    Fam::Entity,
    Fam::Url25,
    Fam::Char,
];

impl Fam {
    /// Units that need no separator between them.
    fn self_delimiting(self) -> bool {
        matches!(self, Fam::CHex | Fam::Oct | Fam::Entity | Fam::Url25)
    }

    /// Whether a run of this family can start at `i` (cheap test on the first bytes).
    fn starts(self, b: &[u8], i: usize) -> bool {
        let at = |k: usize| b.get(i + k).copied().unwrap_or(0);
        let prev_word = i > 0 && b[i - 1].is_ascii_alphanumeric();
        match self {
            // Not whitespace: a run of spaced characters is entered at its first character, not
            // in the padding before it.
            Fam::Char => !prev_word && at(0) > 0x20,
            Fam::Quoted => matches!(at(0), b'\'' | b'"'),
            Fam::Dec => !prev_word && at(0).is_ascii_digit(),
            Fam::Hex0x => !prev_word && at(0) == b'0' && matches!(at(1), b'x' | b'X'),
            Fam::CHex => at(0) == b'\\' && at(1) == b'x',
            Fam::Oct => at(0) == b'\\' && matches!(at(1), b'0'..=b'7'),
            Fam::Entity => at(0) == b'&' && at(1) == b'#',
            Fam::Url25 => at(0) == b'%' && at(1) == b'2' && at(2) == b'5',
        }
    }
}

/// Length of the separator token at `i`: one ASCII separator, or a zero-width character
/// (U+200B to U+200D, U+2060, U+FEFF). 0 when there is none.
#[inline]
fn sep_tok(b: &[u8], i: usize) -> usize {
    match b.get(i) {
        Some(
            b' ' | b'\t' | b'\n' | b'\r' | b',' | b'-' | b'.' | b'_' | b':' | b';' | b'|' | b'/',
        ) => 1,
        Some(0xE2)
            if b.len() >= i + 3
                && ((b[i + 1] == 0x80 && matches!(b[i + 2], 0x8B..=0x8D))
                    || (b[i + 1] == 0x81 && b[i + 2] == 0xA0)) =>
        {
            3
        }
        Some(0xEF) if b.len() >= i + 3 && b[i + 1] == 0xBB && b[i + 2] == 0xBF => 3,
        _ => 0,
    }
}

/// Decoded bytes of one unit (at most four: one UTF-8 character).
#[derive(Clone, Copy)]
struct Dec {
    len: usize,
    out: [u8; 4],
    n: u8,
}

impl Dec {
    fn byte(len: usize, c: u8) -> Self {
        Self {
            len,
            out: [c, 0, 0, 0],
            n: 1,
        }
    }
    fn bytes(&self) -> &[u8] {
        &self.out[..usize::from(self.n)]
    }
}

/// Length of the UTF-8 character at `i` (1 for an invalid or truncated sequence).
fn char_len(b: &[u8], i: usize) -> usize {
    let n = match b[i] {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return 1,
    };
    if i + n <= b.len() && b[i + 1..i + n].iter().all(|&c| c & 0xC0 == 0x80) {
        n
    } else {
        1
    }
}

fn char_unit(b: &[u8], i: usize, len_extra: usize) -> Dec {
    let n = char_len(b, i);
    let mut out = [0u8; 4];
    out[..n].copy_from_slice(&b[i..i + n]);
    Dec {
        len: n + len_extra,
        out,
        n: n as u8,
    }
}

fn escape_byte(c: u8) -> Option<u8> {
    Some(match c {
        b'n' => b'\n',
        b't' => b'\t',
        b'r' => b'\r',
        b'0' => 0,
        b'\\' => b'\\',
        b'\'' => b'\'',
        b'"' => b'"',
        b'/' => b'/',
        _ => return None,
    })
}

#[inline]
fn hexv(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex2(b: &[u8], i: usize) -> Option<u8> {
    Some((hexv(*b.get(i)?)? << 4) | hexv(*b.get(i + 1)?)?)
}

fn push_utf8(cp: u32) -> Option<([u8; 4], u8)> {
    let c = char::from_u32(cp)?;
    let mut out = [0u8; 4];
    let n = c.encode_utf8(&mut out).len();
    Some((out, n as u8))
}

/// Parses one unit of `f` at `i`.
fn unit(f: Fam, b: &[u8], i: usize) -> Option<Dec> {
    let at = |k: usize| b.get(i + k).copied();
    match f {
        Fam::Char => {
            let c = at(0)?;
            if c == b'\\'
                && let Some(e) =
                    at(1).filter(|&e| matches!(e, b'n' | b't' | b'r' | b'0' | b'\\' | b'"' | b'/'))
            {
                return Some(Dec::byte(2, escape_byte(e)?));
            }
            Some(char_unit(b, i, 0))
        }
        Fam::Quoted => {
            let q = at(0)?;
            if at(1)? == b'\\' {
                if at(2)? == b'x' {
                    let v = hex2(b, i + 3)?;
                    return (at(5)? == q).then(|| Dec::byte(6, v));
                }
                let v = escape_byte(at(2)?)?;
                return (at(3)? == q).then(|| Dec::byte(4, v));
            }
            if i + 2 > b.len() {
                return None;
            }
            let d = char_unit(b, i + 1, 2);
            (at(d.len - 1)? == q && d.len >= 3).then_some(d)
        }
        Fam::Dec => {
            let mut v = 0u32;
            let mut n = 0;
            while n < 4 && at(n).is_some_and(|c| c.is_ascii_digit()) {
                v = v * 10 + u32::from(at(n)? - b'0');
                n += 1;
            }
            (n > 0 && n <= 3 && v <= 255).then(|| Dec::byte(n, v as u8))
        }
        Fam::Hex0x => {
            if at(0)? != b'0' || !matches!(at(1)?, b'x' | b'X') {
                return None;
            }
            let mut v = 0u32;
            let mut n = 0;
            while n < 3
                && let Some(h) = at(2 + n).and_then(hexv)
            {
                v = (v << 4) | u32::from(h);
                n += 1;
            }
            (n > 0 && n <= 2).then(|| Dec::byte(2 + n, v as u8))
        }
        Fam::CHex => {
            if at(0)? != b'\\' || at(1)? != b'x' {
                return None;
            }
            hex2(b, i + 2).map(|v| Dec::byte(4, v))
        }
        Fam::Oct => {
            if at(0)? != b'\\' {
                return None;
            }
            let mut v = 0u32;
            let mut n = 0;
            while n < 3
                && let Some(c) = at(1 + n).filter(|c| matches!(c, b'0'..=b'7'))
            {
                v = v * 8 + u32::from(c - b'0');
                n += 1;
            }
            (n > 0 && v <= 255).then(|| Dec::byte(1 + n, v as u8))
        }
        Fam::Entity => {
            if at(0)? != b'&' || at(1)? != b'#' {
                return None;
            }
            let hex = matches!(at(2)?, b'x' | b'X');
            let mut k = 2 + usize::from(hex);
            let mut v = 0u32;
            let d0 = k;
            while k - d0 < 7 {
                let c = at(k)?;
                let d = if hex {
                    hexv(c)
                } else {
                    c.is_ascii_digit().then(|| c - b'0')
                };
                let Some(d) = d else { break };
                v = v * if hex { 16 } else { 10 } + u32::from(d);
                k += 1;
            }
            if k == d0 || at(k)? != b';' {
                return None;
            }
            let (out, n) = push_utf8(v)?;
            Some(Dec { len: k + 1, out, n })
        }
        Fam::Url25 => {
            if b.get(i..i + 3)? != b"%25" {
                return None;
            }
            hex2(b, i + 3).map(|v| Dec::byte(5, v))
        }
    }
}

/// Counts the units of a run of `f` starting at `i` with separator `sep`; returns the count and
/// the end of the last unit.
fn walk(f: Fam, b: &[u8], i: usize, sep: &[u8]) -> (usize, usize) {
    let (mut count, mut p, mut end) = (0, i, i);
    while let Some(d) = unit(f, b, p) {
        count += 1;
        end = p + d.len;
        if sep.is_empty() {
            p = end;
        } else if b[end..].starts_with(sep) {
            p = end + sep.len();
        } else {
            break;
        }
    }
    (count, end)
}

/// Finds runs of separated or escaped units in `b` and appends each one's decoded bytes.
fn separated(b: &[u8], s: &mut TxScratch) {
    let n = b.len();
    let mut i = 0;
    let mut lens = [0usize; MAX_SEP + 1];
    while i < n {
        let mut next = i + 1;
        // Inside a word no family can start: the cheap common case.
        if i > 0 && b[i].is_ascii_alphanumeric() && b[i - 1].is_ascii_alphanumeric() {
            i = next;
            continue;
        }
        for f in FAMS {
            if !f.starts(b, i) {
                continue;
            }
            let Some(first) = unit(f, b, i) else {
                continue;
            };
            let j = i + first.len;
            // Separator candidates: each prefix of the separator tokens after the first unit.
            let mut nl = 0;
            if f.self_delimiting() {
                lens[nl] = 0;
                nl += 1;
            }
            let mut q = j;
            while q - j < MAX_SEP {
                let t = sep_tok(b, q);
                if t == 0 || q + t - j > MAX_SEP {
                    break;
                }
                q += t;
                lens[nl] = q - j;
                nl += 1;
            }
            // A separator character can also be a unit ("a   b" is "ab" spaced by three, or
            // "a b" spaced by one), so every separator that gives a long enough run is decoded.
            for &l in &lens[..nl] {
                let sep = &b[j..j + l];
                // A first unit equal to the separator is a rule line ("-----", "....").
                if f == Fam::Char && sep.first() == Some(&b[i]) {
                    continue;
                }
                let (count, end) = walk(f, b, i, sep);
                if count < MIN_UNITS {
                    continue;
                }
                let at = s.mark();
                let mut p = i;
                while let Some(d) = unit(f, b, p) {
                    for &c in d.bytes() {
                        s.push(c, p, p + d.len);
                    }
                    let end = p + d.len;
                    if sep.is_empty() {
                        p = end;
                    } else if b[end..].starts_with(sep) {
                        p = end + sep.len();
                    } else {
                        break;
                    }
                }
                s.close(at, MIN_UNITS, GuardView::Separated);
                next = next.max(end);
            }
        }
        i = next;
    }
}

const fn b64v_table() -> [u8; 256] {
    let mut t = [0xFFu8; 256];
    let a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    while i < 64 {
        t[a[i] as usize] = i as u8;
        i += 1;
    }
    t
}
static B64V: [u8; 256] = b64v_table();

/// Standard base64 (no padding, no line breaks) of `chars` into `out`.
fn b64_decode(chars: &[u8], out: &mut Vec<u8>) {
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in chars {
        acc = (acc << 6) | u32::from(B64V[usize::from(c)]);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
}

// ---------------------------------------------------------------------------- byte dumps

#[derive(Clone, Copy, PartialEq, Eq)]
enum Offset {
    /// No offset column (`xxd -p`, `od -An`).
    None,
    /// Hex digits and a colon (`xxd`).
    Colon,
    /// Seven or eight digits and a space (`hexdump -C`, `od`).
    Plain,
}

/// Parses the offset column at `p`: its style and the position after it.
fn offset(b: &[u8], p: usize) -> (Offset, usize) {
    let mut q = p;
    while q < b.len() && q - p < 9 && b[q].is_ascii_hexdigit() {
        q += 1;
    }
    let d = q - p;
    if (4..=8).contains(&d) && b.get(q) == Some(&b':') && b.get(q + 1) == Some(&b' ') {
        return (Offset::Colon, q + 1);
    }
    if (d == 7 || d == 8) && b.get(q) == Some(&b' ') {
        return (Offset::Plain, q);
    }
    (Offset::None, p)
}

fn spaces(b: &[u8], p: usize) -> usize {
    b[p..].iter().take_while(|&&c| c == b' ').count()
}

/// One `od -c` cell (four columns, right-aligned) at `p`.
fn od_cell(b: &[u8], p: usize) -> Option<u8> {
    let c = b.get(p..p + 4)?;
    match c {
        [b' ', b' ', b' ', b' '] => Some(b' '),
        [b' ', b' ', b' ', x] if *x > b' ' && *x != b'\\' && *x < 0x7F => Some(*x),
        [b' ', b' ', b'\\', e] => Some(match e {
            b'0' => 0,
            b'a' => 7,
            b'b' => 8,
            b'f' => 12,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'v' => 11,
            b'\\' => b'\\',
            _ => return None,
        }),
        [b' ', x, y, z] if [x, y, z].iter().all(|c| matches!(c, b'0'..=b'7')) => {
            let v = u32::from(x - b'0') * 64 + u32::from(y - b'0') * 8 + u32::from(z - b'0');
            u8::try_from(v).ok()
        }
        _ => None,
    }
}

/// Parses one dump line at `s`, appending its bytes. Returns the end of what the line covers
/// (including its ASCII column) when it decoded at least one byte; on `None` nothing was appended.
fn dump_line(b: &[u8], s: usize, out: &mut TxScratch) -> Option<usize> {
    let n = b.len();
    let lead = spaces(b, s).min(8);
    let (style, p0) = offset(b, s + lead);
    let at = out.bytes.len();

    // od -c cells, right after a plain offset or leading spaces.
    if style != Offset::Colon {
        let start = if style == Offset::Plain {
            p0
        } else {
            s + lead.saturating_sub(3)
        };
        let mut p = start;
        while let Some(c) = od_cell(b, p) {
            out.push(c, p, p + 4);
            p += 4;
        }
        if out.bytes.len() - at >= 2 && matches!(b.get(p), None | Some(b'\n' | b'\r' | b'"')) {
            return Some(p);
        }
        out.bytes.truncate(at);
        out.spans.truncate(at);
    }

    // Hex tokens.
    let mut p = p0;
    if style != Offset::None {
        let sp = spaces(b, p);
        if sp == 0 || sp > 2 {
            return None;
        }
        p += sp;
    }
    let mut hex_end = p;
    let mut doubled = false;
    loop {
        let t0 = p;
        while p < n && b[p].is_ascii_hexdigit() {
            p += 1;
        }
        let tl = p - t0;
        let ends = matches!(b.get(p), None | Some(b' ' | b'\n' | b'\r' | b'"'));
        if tl == 0 || tl % 2 == 1 || !ends {
            break;
        }
        for k in (t0..p).step_by(2) {
            let v = hex2(b, k).unwrap_or(0);
            out.push(v, k, k + 2);
        }
        hex_end = p;
        let sp = spaces(b, p);
        // xxd ends its hex area with two spaces; hexdump -C has two in the middle of it.
        if sp == 0 || sp > 2 || (sp == 2 && (style == Offset::Colon || doubled)) {
            break;
        }
        doubled |= sp == 2;
        p += sp;
        if b.get(p) == Some(&b'|') {
            break;
        }
    }
    let nb = out.bytes.len() - at;
    if nb == 0 {
        return None;
    }
    // The ASCII column shows the same bytes: cover it.
    let q = hex_end + spaces(b, hex_end);
    let col_ok = |a: usize, z: usize| z <= n && !b[a..z].contains(&b'\n');
    let mut end = hex_end;
    if b.get(q) == Some(&b'|') && col_ok(q, q + nb + 2) && b[q + nb + 1] == b'|' {
        end = q + nb + 2;
    } else if style == Offset::Colon && q > hex_end + 1 && col_ok(q, q + nb) {
        end = q + nb;
    }
    for sp in &mut out.spans[at..] {
        sp.1 = end as u32;
    }
    Some(end)
}

/// Bytes after which a dump can start: a line break, the quote opening a JSON string, and the
/// `=`, `:` or tab before a value (`TOKEN=` followed by the dump of the value alone).
const fn dump_pred() -> [bool; 256] {
    let mut t = [false; 256];
    t[b'\n' as usize] = true;
    t[b'"' as usize] = true;
    t[b'=' as usize] = true;
    t[b':' as usize] = true;
    t[b'\t' as usize] = true;
    t
}
static DUMP_PRED: [bool; 256] = dump_pred();

/// Finds runs of dump lines and appends each run's bytes.
fn dumps(b: &[u8], s: &mut TxScratch) {
    let mut done = 0;
    for st in 0..b.len() {
        let c = b[st];
        if st < done
            || !(c.is_ascii_hexdigit() || c == b' ')
            || (st > 0 && !DUMP_PRED[usize::from(b[st - 1])])
        {
            continue;
        }
        let at = s.mark();
        let mut p = st;
        let mut end = st;
        while let Some(e) = dump_line(b, p, s) {
            end = e;
            // The next line must follow directly.
            let mut q = e;
            if b.get(q) == Some(&b'\r') {
                q += 1;
            }
            if b.get(q) != Some(&b'\n') {
                break;
            }
            p = q + 1;
        }
        if s.close(at, MIN_DUMP_BYTES, GuardView::Dump) {
            done = end;
        }
    }
}

// ---------------------------------------------------------------------------- base32

const B32_STD: u8 = 1;
const B32_HEX: u8 = 2;
const B32_UPPER: u8 = 4;
const B32_LOWER: u8 = 8;

const fn b32_class() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let c = i as u8;
        let mut x = 0;
        if c.is_ascii_uppercase() {
            x |= B32_STD | B32_UPPER;
            if c <= b'V' {
                x |= B32_HEX;
            }
        } else if c.is_ascii_lowercase() {
            x |= B32_STD | B32_LOWER;
            if c <= b'v' {
                x |= B32_HEX;
            }
        } else if c.is_ascii_digit() {
            x |= B32_HEX;
            if c >= b'2' && c <= b'7' {
                x |= B32_STD;
            }
        }
        t[i] = x;
        i += 1;
    }
    t
}
static B32C: [u8; 256] = b32_class();

fn b32_val(c: u8, hex: bool) -> u8 {
    let c = c.to_ascii_uppercase();
    if hex {
        if c.is_ascii_digit() {
            c - b'0'
        } else {
            c - b'A' + 10
        }
    } else if c.is_ascii_uppercase() {
        c - b'A'
    } else {
        c - b'2' + 26
    }
}

/// Finds base32 runs (upper case, either alphabet, continuing across single line breaks) and
/// appends their decoding at all eight character alignments.
fn base32(b: &[u8], s: &mut TxScratch) {
    let n = b.len();
    let cls = |i: usize| B32C[usize::from(b[i])] & (B32_STD | B32_HEX) != 0;
    let brk = |i: usize| {
        if b[i..].starts_with(b"\r\n") {
            2
        } else {
            usize::from(b[i] == b'\n')
        }
    };
    let mut i = 0;
    while i < n {
        if !cls(i) || (i > 0 && cls(i - 1)) {
            i += 1;
            continue;
        }
        // Extent of the run.
        let start = i;
        let (mut len, mut all, mut any, mut broken) = (0usize, 0xFFu8, 0u8, false);
        loop {
            while i < n && cls(i) {
                let c = B32C[usize::from(b[i])];
                all &= c;
                any |= c;
                len += 1;
                i += 1;
            }
            if i < n {
                let k = brk(i);
                if k > 0 && i + k < n && cls(i + k) {
                    broken = true;
                    i += k;
                    continue;
                }
            }
            break;
        }
        let end = i;
        // As the tools print it: upper-case letters and digits, at least one letter. Words and
        // lower-case hex digests are not decoded.
        let upper = any & B32_UPPER != 0 && any & B32_LOWER == 0;
        if len < MIN_B32_RUN || !upper || all & (B32_STD | B32_HEX) == 0 {
            continue;
        }
        // Character positions (only copied when line breaks interrupt the run).
        s.pos.clear();
        if broken {
            s.pos
                .extend((start..end).filter(|&p| cls(p)).map(|p| p as u32));
        }
        let pos = |s: &TxScratch, k: usize| {
            if broken { s.pos[k] as usize } else { start + k }
        };
        for hex in [false, true] {
            if all & if hex { B32_HEX } else { B32_STD } == 0 {
                continue;
            }
            for align in 0..8 {
                if len - align < MIN_B32_RUN {
                    break;
                }
                let at = s.mark();
                let (mut acc, mut bits, mut j) = (0u32, 0u32, 0usize);
                for k in align..len {
                    acc = (acc << 5) | u32::from(b32_val(b[pos(s, k)], hex));
                    bits += 5;
                    if bits >= 8 {
                        bits -= 8;
                        let byte = (acc >> bits) as u8;
                        acc &= (1 << bits) - 1;
                        let c0 = align + (8 * j) / 5;
                        let c1 = align + (8 * j + 7) / 5;
                        let (from, to) = (pos(s, c0), pos(s, c1) + 1);
                        s.push(byte, from, to);
                        j += 1;
                    }
                }
                s.close(at, 8, GuardView::Base32);
            }
        }
    }
}

// ---------------------------------------------------------------------------- fragments

struct FragValue {
    value: Zeroizing<Vec<u8>>,
    owner: u32,
    /// Shortest fragment that counts.
    min: u32,
    /// `secret[k]`: bytes before offset `k` that are not format-fixed.
    secret: Vec<u32>,
}

/// Index of every five-byte gram at every offset of every long value.
struct Fragments {
    vals: Vec<FragValue>,
    min_len: usize,
    bits: Vec<u64>,
    shift: u32,
    grams: HashMap<u64, (u32, u32)>,
    cands: Vec<(u32, u32)>,
}

#[inline]
fn lower(c: u8) -> u8 {
    c.to_ascii_lowercase()
}

#[inline]
fn gram(b: &[u8], p: usize) -> u64 {
    let mut g = 0u64;
    for k in 0..GRAM {
        g |= u64::from(lower(b[p + k])) << (8 * k);
    }
    g
}

#[inline]
fn hash(g: u64) -> u64 {
    let h = (g ^ (g >> 29)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^ (h >> 32)
}

/// ASCII lower-casing of eight bytes at once.
#[inline]
fn swar_lower(x: u64) -> u64 {
    const H: u64 = 0x8080_8080_8080_8080;
    let a = x & !H;
    let ge_a = a.wrapping_add(0x3F3F_3F3F_3F3F_3F3F);
    let gt_z = a.wrapping_add(0x2525_2525_2525_2525);
    x | ((ge_a & !gt_z & !x & H) >> 2)
}

/// Bytes of `v` fixed by its format, which a fragment must reach beyond: PEM armour lines, a
/// JWT's header and the first twelve characters of its payload, and a short lower-case prefix
/// ending in `_` or `-` (`ghp_`, `sk-`).
fn public_mask(v: &[u8]) -> Vec<bool> {
    let mut m = vec![false; v.len()];
    if v.starts_with(b"-----BEGIN") {
        let first = memchr::memchr(b'\n', v).map_or(v.len(), |i| i + 1);
        m[..first].fill(true);
        if let Some(last) = memchr::memmem::rfind(v, b"-----END") {
            let from = memchr::memrchr(b'\n', &v[..last]).unwrap_or(last);
            m[from..].fill(true);
        }
    }
    if v.starts_with(b"eyJ")
        && let Some(d1) = memchr::memchr(b'.', v)
        && memchr::memchr(b'.', &v[d1 + 1..]).is_some()
    {
        m[..(d1 + 13).min(v.len())].fill(true);
    }
    let pre = v
        .iter()
        .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_uppercase())
        .count();
    if (2..=6).contains(&pre) && matches!(v.get(pre), Some(b'_' | b'-')) {
        m[..=pre].fill(true);
    }
    m
}

impl Fragments {
    fn build<'a>(long: impl Iterator<Item = (&'a [u8], u32)>, min_len: usize) -> Self {
        let mut vals = Vec::new();
        let mut pairs: Vec<(u64, u32, u32)> = Vec::new();
        for (v, owner) in long {
            let len = v.len();
            // Half the value, at least the minimum length, at most MAX_FRAGMENT, at most all.
            let min = len.div_ceil(2).max(min_len).min(MAX_FRAGMENT).min(len);
            if min >= len {
                // Only whole occurrences count, and the guard's own index finds those.
                continue;
            }
            let mask = public_mask(v);
            // The value and its reversal (`rev` reverses each line: every reversed line is a
            // fragment of the reversed value).
            let mut rv = Zeroizing::new(v.to_vec());
            rv.reverse();
            let rmask: Vec<bool> = mask.iter().rev().copied().collect();
            for (form, mask) in [(Zeroizing::new(v.to_vec()), mask), (rv, rmask)] {
                let mut secret = Vec::with_capacity(len + 1);
                secret.push(0u32);
                for &p in &mask {
                    secret.push(secret[secret.len() - 1] + u32::from(!p));
                }
                let vi = vals.len() as u32;
                let mut seen: HashMap<u64, usize> = HashMap::new();
                for off in 0..=len - GRAM {
                    let g = gram(&form, off);
                    let k = seen.entry(g).or_insert(0);
                    if *k < MAX_OFFSETS_PER_GRAM {
                        *k += 1;
                        pairs.push((g, vi, off as u32));
                    }
                }
                vals.push(FragValue {
                    value: form,
                    owner,
                    min: min as u32,
                    secret,
                });
            }
        }
        pairs.sort_unstable();
        let mut grams = HashMap::new();
        let mut cands = Vec::with_capacity(pairs.len());
        let mut i = 0;
        while i < pairs.len() {
            let g = pairs[i].0;
            let lo = cands.len() as u32;
            while i < pairs.len() && pairs[i].0 == g {
                cands.push((pairs[i].1, pairs[i].2));
                i += 1;
            }
            grams.insert(g, (lo, cands.len() as u32));
        }
        let nbits = (grams.len() * 64).next_power_of_two().max(1 << 12);
        let shift = 64 - nbits.trailing_zeros();
        let mut bits = vec![0u64; nbits / 64];
        for &g in grams.keys() {
            let h = (hash(g) >> shift) as usize;
            bits[h >> 6] |= 1 << (h & 63);
        }
        Self {
            vals,
            min_len,
            bits,
            shift,
            grams,
            cands,
        }
    }

    /// Pushes `(start, end, owner)` for every fragment found in `v`.
    fn scan(&self, v: &[u8], out: &mut Vec<(usize, usize, u32)>) {
        if self.vals.is_empty() || v.len() < 8 {
            return;
        }
        let n = v.len();
        // Last fragment found: probes inside it are skipped for its owner.
        let mut last = (u32::MAX, 0usize);
        let mut p = 0;
        while p + GRAM <= n {
            let g = if p + 8 <= n {
                let x = u64::from_le_bytes([
                    v[p],
                    v[p + 1],
                    v[p + 2],
                    v[p + 3],
                    v[p + 4],
                    v[p + 5],
                    v[p + 6],
                    v[p + 7],
                ]);
                swar_lower(x) & 0xFF_FFFF_FFFF
            } else {
                gram(v, p)
            };
            let h = (hash(g) >> self.shift) as usize;
            if self.bits[h >> 6] & (1 << (h & 63)) != 0 {
                self.verify(v, p, g, &mut last, out);
            }
            p += STRIDE;
        }
    }

    #[inline(never)]
    fn verify(
        &self,
        v: &[u8],
        p: usize,
        g: u64,
        last: &mut (u32, usize),
        out: &mut Vec<(usize, usize, u32)>,
    ) {
        let Some(&(lo, hi)) = self.grams.get(&g) else {
            return;
        };
        for &(vi, off) in &self.cands[lo as usize..hi as usize] {
            let fv = &self.vals[vi as usize];
            if last.0 == fv.owner && p + GRAM <= last.1 {
                continue;
            }
            let val = &fv.value[..];
            let off = off as usize;
            let mut l = 0;
            while l < p && l < off && lower(v[p - l - 1]) == lower(val[off - l - 1]) {
                l += 1;
            }
            let mut r = GRAM;
            while p + r < v.len() && off + r < val.len() && lower(v[p + r]) == lower(val[off + r]) {
                r += 1;
            }
            let m = l + r;
            let vo = off - l;
            let secret = (fv.secret[vo + m] - fv.secret[vo]) as usize;
            if m >= fv.min as usize && (m == val.len() || secret >= self.min_len) {
                out.push((p - l, p + r, fv.owner));
                *last = (fv.owner, p + r);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    fn decoded(input: &[u8]) -> Vec<Vec<u8>> {
        let mut s = TxScratch::default();
        separated(input, &mut s);
        dumps(input, &mut s);
        base32(input, &mut s);
        s.segs
            .iter()
            .map(|g| s.bytes[g.at as usize..g.end as usize].to_vec())
            .collect()
    }

    fn finds(input: &[u8], v: &[u8]) -> bool {
        decoded(input)
            .iter()
            .any(|d| d.windows(v.len()).any(|w| w == v))
    }

    const V: &[u8] = b"Zq7-xK2p_Lm9\\vR4'tW8\"";

    #[test]
    fn separated_forms() {
        let join = |sep: &str| {
            V.iter()
                .map(|&c| (c as char).to_string())
                .collect::<Vec<_>>()
                .join(sep)
        };
        for sep in [" ", "\n", ",", "-", ", ", "   ", "\u{200b}", "_", "|"] {
            assert!(finds(join(sep).as_bytes(), V), "sep {sep:?}");
        }
        let py: Vec<String> = V
            .iter()
            .map(|&c| match c {
                b'\'' => "\"'\"".to_string(),
                b'\\' => "'\\\\'".to_string(),
                c => format!("'{}'", c as char),
            })
            .collect();
        assert!(finds(format!("[{}]", py.join(", ")).as_bytes(), V));
        let each = |f: &dyn Fn(u8) -> String, sep: &str| {
            V.iter().map(|&c| f(c)).collect::<Vec<_>>().join(sep)
        };
        for (name, form) in [
            ("dec", each(&|c| c.to_string(), " ")),
            ("pylist", format!("[{}]", each(&|c| c.to_string(), ", "))),
            ("xxd-i", each(&|c| format!("0x{c:02x}"), ", ")),
            ("chex", each(&|c| format!("\\x{c:02x}"), "")),
            ("oct", each(&|c| format!("\\{c:03o}"), "")),
            ("ent", each(&|c| format!("&#{c};"), "")),
            ("entx", each(&|c| format!("&#x{c:x};"), "")),
            ("url25", each(&|c| format!("%25{c:02X}"), "")),
        ] {
            assert!(finds(form.as_bytes(), V), "{name}");
        }
    }

    #[test]
    fn separator_characters_as_units() {
        let v = b"-----BEGIN X-----\nab--cd";
        for sep in [" ", "\n", "\u{200b}", "   "] {
            let j: Vec<String> = v.iter().map(|&c| (c as char).to_string()).collect();
            let form = format!("API_TOKEN={}\n", j.join(sep));
            assert!(finds(form.as_bytes(), v), "sep {sep:?}");
        }
    }

    #[test]
    fn spaced_inside_json_in_json() {
        let v = br#"a"b\c/d"e\f/gh"#;
        let j: Vec<String> = v
            .iter()
            .map(|&c| match c {
                b'"' => "\\\"".to_string(),
                b'\\' => "\\\\".to_string(),
                c => (c as char).to_string(),
            })
            .collect();
        assert!(finds(
            format!("{{\"command\":\"echo {}\"}}", j.join(" ")).as_bytes(),
            v
        ));
    }

    #[test]
    fn digits_spaced_and_as_numbers() {
        let v = b"4815162342";
        let spaced: Vec<String> = v.iter().map(|&c| (c as char).to_string()).collect();
        assert!(finds(spaced.join(" ").as_bytes(), v));
    }

    fn xxd(v: &[u8]) -> String {
        let mut s = String::new();
        for (l, line) in v.chunks(16).enumerate() {
            s += &format!("{:08x}: ", l * 16);
            for i in 0..16 {
                match line.get(i) {
                    Some(c) => s += &format!("{c:02x}"),
                    None => s += "  ",
                }
                if i % 2 == 1 {
                    s.push(' ');
                }
            }
            s.push(' ');
            for &c in line {
                s.push(if (0x20..0x7f).contains(&c) {
                    c as char
                } else {
                    '.'
                });
            }
            s.push('\n');
        }
        s
    }

    fn od_c(v: &[u8]) -> String {
        let mut s = String::new();
        for (l, line) in v.chunks(16).enumerate() {
            s += &format!("{:07o}", l * 16);
            for &c in line {
                s += &match c {
                    b'\n' => "  \\n".to_string(),
                    b'\\' => "  \\\\".to_string(),
                    0x20..0x7f => format!("   {}", c as char),
                    c => format!(" {c:03o}"),
                };
            }
            s.push('\n');
        }
        s + &format!("{:07o}\n", v.len())
    }

    #[test]
    fn dumps_across_lines() {
        let v: Vec<u8> = (0..70u8)
            .map(|i| b"Kp3x\\Tz9-wQ\n"[i as usize % 12] ^ (i & 1))
            .collect();
        let x = xxd(&v);
        assert!(finds(x.as_bytes(), &v), "xxd");
        assert!(finds(format!("\"{x}\"").as_bytes(), &v), "xxd quoted");
        assert!(
            finds(format!("API_TOKEN={x}").as_bytes(), &v),
            "xxd after ="
        );
        let one: Vec<String> = v.iter().map(|c| format!("{c:02x}")).collect();
        let one = format!("TOKEN= {}\n", one.join(" "));
        assert!(finds(one.as_bytes(), &v), "od -An -tx1 on one line");
        assert!(finds(od_c(&v).as_bytes(), &v), "od -c");
        let plain: String = v.iter().map(|c| format!("{c:02x}")).collect();
        let wrapped: Vec<&str> = plain
            .as_bytes()
            .chunks(60)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        assert!(finds(wrapped.join("\n").as_bytes(), &v), "xxd -p");
        let od: Vec<String> = v.iter().map(|c| format!("{c:02x}")).collect();
        let od_lines: Vec<String> = od
            .chunks(16)
            .enumerate()
            .map(|(l, c)| format!("{:07o} {}", l * 16, c.join(" ")))
            .collect();
        assert!(finds(od_lines.join("\n").as_bytes(), &v), "od -tx1");
        let hd: Vec<String> = v
            .chunks(16)
            .enumerate()
            .map(|(l, c)| {
                let h: Vec<String> = c.iter().map(|b| format!("{b:02x}")).collect();
                let (a, b) = h.split_at(h.len().min(8));
                let asc: String = c
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7f).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                format!(
                    "{:08x}  {:<23}  {:<23}  |{asc}|",
                    l * 16,
                    a.join(" "),
                    b.join(" ")
                )
            })
            .collect();
        assert!(finds(hd.join("\n").as_bytes(), &v), "hexdump -C");
    }

    #[test]
    fn dump_span_covers_ascii_column() {
        let v = b"0123456789abcdefXYZW";
        let x = xxd(v);
        let mut s = TxScratch::default();
        dumps(x.as_bytes(), &mut s);
        let last = s.spans[s.spans.len() - 1].1 as usize;
        assert_eq!(&x.as_bytes()[last - 4..last], b"XYZW");
    }

    #[test]
    fn base32_both_alphabets_wrapped() {
        let v = b"base32-value!!xy";
        let std = {
            // RFC 4648 encoder, independent of the decoder.
            let a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let mut out = String::new();
            let (mut acc, mut bits) = (0u32, 0);
            for &c in b"__".iter().chain(v.iter()) {
                acc = (acc << 8) | u32::from(c);
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    out.push(a[((acc >> bits) & 31) as usize] as char);
                }
            }
            if bits > 0 {
                out.push(a[((acc << (5 - bits)) & 31) as usize] as char);
            }
            out
        };
        assert!(finds(std.as_bytes(), v));
        let wrapped = format!("{}\n{}", &std[..10], &std[10..]);
        assert!(finds(wrapped.as_bytes(), v));
        let hexalpha: String = std
            .bytes()
            .map(|c| {
                let x = if c.is_ascii_uppercase() {
                    c - b'A'
                } else {
                    c - b'2' + 26
                };
                b"0123456789ABCDEFGHIJKLMNOPQRSTUV"[x as usize] as char
            })
            .collect();
        assert!(finds(hexalpha.as_bytes(), v));
        // Lower-case runs are words or digests, not base32 output.
        assert!(!finds(std.to_ascii_lowercase().as_bytes(), v));
    }

    #[test]
    fn od_c_on_one_line() {
        for v in [
            &b"aZ!#%&*+-./:<=>?@^_~\"\\$'q"[..],
            b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
        ] {
            let parts: Vec<String> = v
                .iter()
                .map(|&c| match c {
                    b'\n' => "\\n".into(),
                    c => (c as char).to_string(),
                })
                .collect();
            let text = format!("API_TOKEN=0000000   {}\nLOG=1", parts.join("   "));
            assert!(finds(text.as_bytes(), v));
        }
    }

    #[test]
    fn spaced_inside_a_base64_data_url() {
        let v: &[u8] = b"DataUrl-Value-0123456789";
        let tx = Transforms::build([(v, 0u32)].into_iter(), 8);
        let spaced: Vec<String> = v.iter().map(|&c| (c as char).to_string()).collect();
        let text = format!("# env\nAPI_TOKEN={}\nX=1\n", spaced.join(" "));
        let a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let enc: String = text
            .as_bytes()
            .chunks(3)
            .flat_map(|c| {
                let x = (u32::from(c[0]) << 16)
                    | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                    | u32::from(*c.get(2).unwrap_or(&0));
                let n = c.len() + 1;
                (0..4).map(move |i| {
                    if i < n {
                        a[((x >> (18 - 6 * i)) & 63) as usize] as char
                    } else {
                        '='
                    }
                })
            })
            .collect();
        let body = format!("{{\"file_data\":\"data:text/plain;base64,{enc}\"}}");
        let mut s = TxScratch::default();
        let mut hits = vec![];
        let scan = |view: &[u8], out: &mut Vec<(usize, usize, u32)>| {
            for (i, w) in view.windows(v.len()).enumerate() {
                if w == v {
                    out.push((i, i + v.len(), 0));
                }
            }
        };
        tx.collect(body.as_bytes(), &mut s, &scan, &mut |a, b, o, view| {
            hits.push((a, b, o, view))
        });
        let start = body.find("base64,").unwrap() + 7;
        assert!(
            hits.iter()
                .any(|&(a, b, _, view)| view == GuardView::Separated
                    && a >= start
                    && b <= start + enc.len()),
            "{hits:?}"
        );
    }

    #[test]
    fn rule_lines_are_not_runs() {
        assert!(decoded(&[b'-'; 200]).is_empty());
        assert!(decoded(&[b' '; 200]).is_empty());
        assert!(decoded("= = = = = = = = = = =".as_bytes()).len() <= 1);
    }

    #[test]
    fn prose_and_code_decode_little() {
        let text =
            b"The quick brown fox jumps over the lazy dog. fn main() { let x = [1, 2, 3]; }\n\
            a b c are letters; 2026-11-20 10:00 deadbeef 0x10 \\n \"quoted\" internationalization";
        let total: usize = decoded(text).iter().map(Vec::len).sum();
        assert!(total < 64, "{total}");
    }

    #[test]
    fn derived_forms_are_distinct() {
        let mut n = 0;
        derived_forms(b"abcdefgh12345678", |f| {
            assert!(f.len() >= 8);
            n += 1;
        });
        assert!(n >= 5);
        let mut m = 0;
        derived_forms(b"aaaaaaaa", |_| m += 1);
        assert!(m < n);
    }

    #[test]
    fn b64_inner_matches_encoder() {
        let v = b"inner-form-check";
        for k in 0..3 {
            let inner = b64_inner(v, k);
            let mut stream = vec![b'Q'; k];
            stream.extend_from_slice(v);
            stream.extend_from_slice(b"QQ");
            let a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let enc: Vec<u8> = stream
                .chunks(3)
                .flat_map(|c| {
                    let x = (u32::from(c[0]) << 16)
                        | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                        | u32::from(*c.get(2).unwrap_or(&0));
                    (0..4).map(move |i| a[((x >> (18 - 6 * i)) & 63) as usize])
                })
                .collect();
            assert!(enc.windows(inner.len()).any(|w| w == &inner[..]), "k={k}");
        }
    }

    fn frag_index(vals: &[&[u8]]) -> Fragments {
        Fragments::build(vals.iter().enumerate().map(|(i, v)| (*v, i as u32)), 8)
    }

    #[test]
    fn fragments_threshold_and_public_parts() {
        // A token-shaped value built at runtime: a short prefix and 36 generated characters.
        let tail = b"Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zQ7cR";
        let token: Vec<u8> = b"tok_"
            .iter()
            .copied()
            .chain((0..36).map(|i| tail[(i * 7) % 36]))
            .collect();
        let v = &token[..];
        let f = frag_index(&[v]);
        let mut out = vec![];
        // Half the value (20 bytes) is found.
        let body = [b"x ".as_slice(), &v[10..30], b" y"].concat();
        f.scan(&body, &mut out);
        assert_eq!(out, vec![(2, 22, 0)]);
        // Reversed too.
        out.clear();
        let mut r = v[5..30].to_vec();
        r.reverse();
        f.scan(&[b"x ".as_slice(), &r, b" y"].concat(), &mut out);
        assert_eq!(out, vec![(2, 27, 0)]);
        // Shorter is not.
        out.clear();
        f.scan(&[b"x ".as_slice(), &v[10..28], b" y"].concat(), &mut out);
        assert!(out.is_empty());
        // PEM armour alone is not a fragment.
        let pem: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----";
        let f = frag_index(&[pem]);
        out.clear();
        f.scan(b"see -----BEGIN PRIVATE KEY-----\nMIIE here", &mut out);
        assert!(out.is_empty(), "{out:?}");
        out.clear();
        f.scan(&pem[20..60], &mut out);
        assert_eq!(out.len(), 1);
    }
}
