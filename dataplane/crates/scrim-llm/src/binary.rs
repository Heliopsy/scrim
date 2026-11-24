// SPDX-License-Identifier: AGPL-3.0-only

//! Decoding and text extraction for binary content parts (images, documents, audio) under the
//! `scan` binary policy.
//!
//! [`decode`] turns the string value of a part into bytes: bare base64 (standard or URL-safe
//! alphabet, padding optional, ASCII whitespace ignored) or a `data:` URL (base64 or
//! percent-encoded). The decoded size is checked against [`Limits::max_decoded`] before anything
//! is allocated.
//!
//! [`scan_views`] hands the caller every byte view of the decoded part in which the text of a
//! secret could sit, so the redactor and the guard can check each one. Every part yields the raw
//! bytes and two UTF-16 views (little and big endian runs of printable ASCII, collapsed to the
//! ASCII bytes). The format is then picked from magic bytes, never from the declared media type,
//! and the format's text is extracted:
//!
//! - PNG: `tEXt`, `zTXt` and `iTXt` chunks (inflated when compressed), the inflated `iCCP`
//!   profile, UTF-16 runs of `eXIf`. Pixel data (`IDAT`) is not inflated. Bytes after `IEND`
//!   are scanned as their own format; a PNG without `IEND` is malformed.
//! - JPEG: marker segments up to the first scan. `APPn` segments that share a marker and an
//!   identifier are joined in order (XMP, `ExtendedXMP` reassembled by offset, `ICC_PROFILE` by
//!   sequence number, Exif, others), so a value split across segments is contiguous. `COM`
//!   segments are views of their own. The entropy-coded image data is not read.
//! - GIF: comment, plain text and application extensions, each with its sub-blocks joined. Image
//!   data sub-blocks are skipped.
//! - XML, SVG and HTML-like text: a view with numeric and the five predefined XML entities
//!   decoded.
//! - gzip: inflated and scanned again. ZIP (docx, xlsx, odt, epub, ...): every entry named in the
//!   central directory, stored or deflated, scanned again.
//! - PDF: every `stream` found by its keyword (a direct `/Length` is used only when it checks
//!   out), its filter chain decoded (`FlateDecode` and `LZWDecode` with PNG and TIFF predictors,
//!   `ASCIIHexDecode`, `ASCII85Decode`, `RunLengthDecode`) and scanned again. String objects are
//!   extracted from each decoded stream into a `pdf text` view with no separator, so text split
//!   across `TJ` array elements or consecutive `Tj` operators is contiguous, and from the bytes
//!   outside streams (info dictionary, annotations, form fields) into a `pdf strings` view.
//!   Strings starting with a UTF-16BE byte order mark are converted to UTF-8.
//!
//! Formats nest (a JPEG in a PDF in a ZIP): every decoded or extracted buffer goes through the
//! same dispatcher. Anything scrim must read but cannot is an error and the request is refused:
//! encrypted PDF and ZIP, unknown or indirect filters and parameters, the PDF `Crypt` filter,
//! ZIP64 and compression methods other than stored and deflate, bzip2, xz, zstd, 7z and RAR
//! archives, and structures that are malformed where they must be walked. The bounds in
//! [`Limits`] (decoded size, total decompressed bytes, object count, nesting depth, total bytes
//! of all views, wall-clock budget) are errors too when exceeded, never a pass.
//!
//! Not covered: text drawn in pixels (OCR is out of scope, so PNG `IDAT`, JPEG scan data, GIF
//! LZW data and PDF image streams other than the metadata of `DCTDecode` images are not
//! decoded); PDF text shown through fonts with custom encodings or CID fonts, whose glyph codes
//! only map to text through a `ToUnicode` `CMap` that is not decoded; ZIP local entries that the
//! central directory does not list; and data URLs embedded inside XML or HTML text. WebP and
//! other RIFF files, audio, video and unknown binary data are opaque: they get the raw and UTF-16
//! views only.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::time::{Duration, Instant};

use flate2::read::{DeflateDecoder, MultiGzDecoder, ZlibDecoder};
use memchr::memmem;

/// Bounds on the work one binary part may cause. Exceeding any bound is an error (the request is
/// refused), never a pass.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// Largest decoded (base64) part, in bytes.
    pub max_decoded: usize,
    /// Most bytes all decompression and filter decoding in one part may produce together.
    pub max_inflated: usize,
    /// Most streams, chunks, segments or archive entries one part may hold.
    pub max_objects: usize,
    /// Deepest nesting of formats (a JPEG in a PDF in a ZIP is depth 3).
    pub max_depth: usize,
    /// Most bytes all views of one part may hold together, the raw view included.
    pub max_view_bytes: usize,
    /// Wall-clock budget for one part, plus `budget_per_mib` for each MiB of decoded data: the
    /// redactor and the guard scan every view, so the time a valid part needs grows with it.
    pub budget: Duration,
    /// Budget added per MiB of decoded data.
    pub budget_per_mib: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_decoded: 64 << 20,
            max_inflated: 64 << 20,
            max_objects: 100_000,
            max_depth: 4,
            max_view_bytes: 4 * (64 << 20),
            budget: Duration::from_secs(2),
            budget_per_mib: Duration::from_millis(250),
        }
    }
}

/// Why a part could not be scanned. Messages are fixed text and never contain part content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Undecodable {
    /// The data is not valid base64 (or a valid data URL).
    NotBase64,
    /// A size or count bound was exceeded.
    TooLarge(&'static str),
    /// The time budget was exceeded.
    OverBudget,
    /// The document is encrypted.
    Encrypted,
    /// A compression or filter scrim does not decode.
    Unsupported(&'static str),
    /// The structure is broken where scrim must read it.
    Corrupt(&'static str),
}

impl fmt::Display for Undecodable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBase64 => f.write_str("not valid base64"),
            Self::TooLarge(what) => write!(f, "too large to scan: {what}"),
            Self::OverBudget => f.write_str("took too long to scan"),
            Self::Encrypted => f.write_str("encrypted"),
            Self::Unsupported(what) => write!(f, "unsupported encoding: {what}"),
            Self::Corrupt(what) => write!(f, "malformed: {what}"),
        }
    }
}

/// One byte view of a part to scan. `source` is a fixed label (`raw`, `png text chunk`, `pdf
/// text`, ...), never part content.
#[derive(Debug)]
pub(crate) struct View<'a> {
    /// What the view is.
    pub source: &'static str,
    /// The bytes.
    pub bytes: &'a [u8],
}

// ---------------------------------------------------------------------------------------------
// decode

/// Decodes the JSON-unescaped string value of a binary part: base64 (standard or URL-safe,
/// padding optional, ASCII whitespace ignored), or a `data:` URL (base64 or percent-encoded).
pub(crate) fn decode(s: &str, limits: &Limits) -> Result<Vec<u8>, Undecodable> {
    let t = s.trim_ascii().as_bytes();
    let is_data_url = t.get(..5).is_some_and(|p| p.eq_ignore_ascii_case(b"data:"));
    if !is_data_url {
        return base64_decode(t, limits);
    }
    let comma = memchr::memchr(b',', t).ok_or(Undecodable::NotBase64)?;
    let header = t.get(5..comma).unwrap_or_default();
    let body = t.get(comma + 1..).unwrap_or_default();
    let is_base64 = header
        .split(|&c| c == b';')
        .skip(1)
        .any(|p| p.trim_ascii().eq_ignore_ascii_case(b"base64"));
    if is_base64 {
        base64_decode(body, limits)
    } else {
        percent_decode(body, limits)
    }
}

const B64_INVALID: u8 = 0xFF;

const B64_TABLE: [u8; 256] = {
    let mut t = [B64_INVALID; 256];
    let mut i = 0u8;
    while i < 26 {
        t[(b'A' + i) as usize] = i;
        t[(b'a' + i) as usize] = 26 + i;
        i += 1;
    }
    let mut d = 0u8;
    while d < 10 {
        t[(b'0' + d) as usize] = 52 + d;
        d += 1;
    }
    t[b'+' as usize] = 62;
    t[b'/' as usize] = 63;
    t[b'-' as usize] = 62;
    t[b'_' as usize] = 63;
    t
};

fn b64_value(c: u8) -> Option<u8> {
    let v = B64_TABLE[usize::from(c)];
    (v != B64_INVALID).then_some(v)
}

fn base64_decode(input: &[u8], limits: &Limits) -> Result<Vec<u8>, Undecodable> {
    // Pass 1: validate and size, without allocating.
    let mut symbols = 0usize;
    let mut pad = 0usize;
    for &c in input {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            pad += 1;
            continue;
        }
        if pad > 0 || b64_value(c).is_none() {
            return Err(Undecodable::NotBase64);
        }
        symbols += 1;
    }
    let rem = symbols % 4;
    if pad > 2 || rem == 1 || (pad > 0 && !(rem + pad).is_multiple_of(4)) {
        return Err(Undecodable::NotBase64);
    }
    let out_len = symbols / 4 * 3 + rem.saturating_sub(1);
    if out_len > limits.max_decoded {
        return Err(Undecodable::TooLarge("decoded size"));
    }
    // Pass 2: decode.
    let mut out = Vec::with_capacity(out_len);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in input {
        let Some(v) = b64_value(c) else { continue };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(low_byte(acc >> bits));
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn percent_decode(input: &[u8], limits: &Limits) -> Result<Vec<u8>, Undecodable> {
    let escapes = input.windows(3).filter(|w| is_escape(w)).count();
    let out_len = input.len().saturating_sub(escapes.saturating_mul(2));
    if out_len > limits.max_decoded {
        return Err(Undecodable::TooLarge("decoded size"));
    }
    let mut out = Vec::with_capacity(out_len);
    let mut i = 0;
    while let Some(&c) = input.get(i) {
        match input.get(i..i + 3) {
            Some(&[b'%', h, l]) if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => {
                out.push(hex_val(h).unwrap_or(0) << 4 | hex_val(l).unwrap_or(0));
                i += 3;
            }
            _ => {
                // A `%` not followed by two hex digits stays literal, as browsers keep it.
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn is_escape(w: &[u8]) -> bool {
    matches!(w, [b'%', h, l] if h.is_ascii_hexdigit() && l.is_ascii_hexdigit())
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn low_byte(v: u32) -> u8 {
    v.to_le_bytes()[0]
}

// ---------------------------------------------------------------------------------------------
// scan driver

/// Calls `visit` with every view of `decoded`; stops early when `visit` returns `false`.
pub(crate) fn scan_views(
    decoded: &[u8],
    limits: &Limits,
    visit: &mut dyn FnMut(View<'_>) -> bool,
) -> Result<(), Undecodable> {
    let mib = u32::try_from(decoded.len() >> 20).unwrap_or(u32::MAX);
    let budget = limits
        .budget
        .saturating_add(limits.budget_per_mib.saturating_mul(mib));
    let clock = Clock {
        deadline: Instant::now().checked_add(budget),
    };
    let mut ctx = Ctx {
        limits,
        meter: Meter {
            clock,
            used: 0,
            max: limits.max_inflated,
        },
        objects: 0,
        view_bytes: 0,
        visit,
    };
    match ctx.top(decoded) {
        Ok(()) | Err(Stop::Done) => Ok(()),
        Err(Stop::Fail(e)) => Err(e),
    }
}

/// How often (in bytes processed) long loops look at the clock.
const TICK: usize = 1 << 16;

#[derive(Clone, Copy)]
struct Clock {
    deadline: Option<Instant>,
}

impl Clock {
    fn check(self) -> Result<(), Undecodable> {
        match self.deadline {
            Some(d) if Instant::now() >= d => Err(Undecodable::OverBudget),
            _ => Ok(()),
        }
    }
}

/// Counts decompressed and filter-decoded bytes across the whole part.
struct Meter {
    clock: Clock,
    used: usize,
    max: usize,
}

impl Meter {
    fn remaining(&self) -> usize {
        self.max.saturating_sub(self.used)
    }

    fn add(&mut self, n: usize) -> Result<(), Undecodable> {
        self.used = self.used.saturating_add(n);
        if self.used > self.max {
            return Err(TOO_INFLATED);
        }
        Ok(())
    }

    /// Reads a decompressor to the end, stopping as soon as the part's budget is exceeded, so a
    /// bomb costs at most one read past the bound.
    fn inflate(&mut self, mut reader: impl Read) -> Result<Vec<u8>, Undecodable> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; TICK];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Undecodable::Corrupt("compressed data")),
            };
            if n == 0 {
                return Ok(out);
            }
            self.add(n)?;
            out.extend_from_slice(buf.get(..n).unwrap_or_default());
            self.clock.check()?;
        }
    }
}

const TOO_INFLATED: Undecodable = Undecodable::TooLarge("decompressed size");

enum Stop {
    Fail(Undecodable),
    /// The visitor asked to stop.
    Done,
}

impl From<Undecodable> for Stop {
    fn from(e: Undecodable) -> Self {
        Self::Fail(e)
    }
}

type Step = Result<(), Stop>;

struct Ctx<'a> {
    limits: &'a Limits,
    meter: Meter,
    objects: usize,
    view_bytes: usize,
    visit: &'a mut dyn FnMut(View<'_>) -> bool,
}

impl Ctx<'_> {
    fn top(&mut self, b: &[u8]) -> Step {
        self.emit("raw", b)?;
        self.utf16(b)?;
        self.dispatch(b, 0)
    }

    fn clock(&self) -> Clock {
        self.meter.clock
    }

    fn tick(&self) -> Result<(), Undecodable> {
        self.meter.clock.check()
    }

    fn emit(&mut self, source: &'static str, bytes: &[u8]) -> Step {
        if bytes.is_empty() {
            return Ok(());
        }
        self.view_bytes = self.view_bytes.saturating_add(bytes.len());
        if self.view_bytes > self.limits.max_view_bytes {
            return Err(Undecodable::TooLarge("extracted text").into());
        }
        if (self.visit)(View { source, bytes }) {
            Ok(())
        } else {
            Err(Stop::Done)
        }
    }

    fn object(&mut self) -> Result<(), Undecodable> {
        self.objects = self.objects.saturating_add(1);
        if self.objects > self.limits.max_objects {
            return Err(Undecodable::TooLarge("object count"));
        }
        self.tick()
    }

    fn utf16(&mut self, b: &[u8]) -> Step {
        let (le, be) = utf16_runs(b, self.clock())?;
        self.emit("utf-16le", &le)?;
        self.emit("utf-16be", &be)
    }

    /// A buffer that does not appear in the raw bytes: its own view, its UTF-16 runs, and
    /// whatever its format holds.
    fn derived(&mut self, source: &'static str, b: &[u8], depth: usize) -> Step {
        self.emit(source, b)?;
        self.utf16(b)?;
        self.dispatch(b, depth)
    }

    fn enter(&self, depth: usize) -> Result<usize, Undecodable> {
        let level = depth.saturating_add(1);
        if level > self.limits.max_depth {
            return Err(Undecodable::TooLarge("nesting depth"));
        }
        Ok(level)
    }

    /// Picks the format from magic bytes. `depth` counts the containers above `b`.
    fn dispatch(&mut self, b: &[u8], depth: usize) -> Step {
        self.tick()?;
        if b.starts_with(PNG_SIG) {
            let level = self.enter(depth)?;
            return self.png(b, level);
        }
        if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
            let level = self.enter(depth)?;
            return self.jpeg(b, level);
        }
        if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
            let level = self.enter(depth)?;
            return self.gif(b, level);
        }
        if b.starts_with(&[0x1F, 0x8B, 0x08]) {
            let level = self.enter(depth)?;
            let out = self.meter.inflate(MultiGzDecoder::new(b))?;
            return self.derived("gzip content", &out, level);
        }
        if b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") {
            let level = self.enter(depth)?;
            return self.zip(b, level);
        }
        if is_compressed_archive(b) {
            return Err(Undecodable::Unsupported("compressed archive").into());
        }
        if memmem::find(b.get(..1024).unwrap_or(b), b"%PDF-").is_some() {
            let level = self.enter(depth)?;
            return self.pdf(b, level);
        }
        if is_markup(b)
            && let Some(decoded) = entity_decode(b, self.clock())?
        {
            self.emit("xml entities", &decoded)?;
        }
        Ok(())
    }
}

const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";

fn is_compressed_archive(b: &[u8]) -> bool {
    let bzip2 = b.starts_with(b"BZh") && b.get(3).is_some_and(|c| (b'1'..=b'9').contains(c));
    bzip2
        || b.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00])
        || b.starts_with(&[0x28, 0xB5, 0x2F, 0xFD])
        || b.starts_with(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C])
        || b.starts_with(b"Rar!\x1A\x07")
}

// ---------------------------------------------------------------------------------------------
// shared helpers

fn corrupt(what: &'static str) -> Undecodable {
    Undecodable::Corrupt(what)
}

fn slice<'b>(
    b: &'b [u8],
    start: usize,
    len: usize,
    what: &'static str,
) -> Result<&'b [u8], Undecodable> {
    start
        .checked_add(len)
        .and_then(|end| b.get(start..end))
        .ok_or(Undecodable::Corrupt(what))
}

fn arr<const N: usize>(b: &[u8], at: usize, what: &'static str) -> Result<[u8; N], Undecodable> {
    slice(b, at, N, what)?.try_into().map_err(|_| corrupt(what))
}

fn byte(b: &[u8], at: usize, what: &'static str) -> Result<u8, Undecodable> {
    b.get(at).copied().ok_or(Undecodable::Corrupt(what))
}

fn be16(b: &[u8], at: usize, what: &'static str) -> Result<usize, Undecodable> {
    Ok(usize::from(u16::from_be_bytes(arr(b, at, what)?)))
}

fn be32(b: &[u8], at: usize, what: &'static str) -> Result<u32, Undecodable> {
    Ok(u32::from_be_bytes(arr(b, at, what)?))
}

fn le16(b: &[u8], at: usize, what: &'static str) -> Result<usize, Undecodable> {
    Ok(usize::from(u16::from_le_bytes(arr(b, at, what)?)))
}

fn le32(b: &[u8], at: usize, what: &'static str) -> Result<u32, Undecodable> {
    Ok(u32::from_le_bytes(arr(b, at, what)?))
}

fn to_usize(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

fn split_nul<'b>(b: &'b [u8], what: &'static str) -> Result<(&'b [u8], &'b [u8]), Undecodable> {
    let i = memchr::memchr(0, b).ok_or(Undecodable::Corrupt(what))?;
    Ok((
        b.get(..i).unwrap_or_default(),
        b.get(i + 1..).unwrap_or_default(),
    ))
}

fn printable(c: u8) -> bool {
    (0x20..=0x7E).contains(&c) || c == b'\t' || c == b'\n' || c == b'\r'
}

/// Collects runs of at least four characters, separated by a newline.
#[derive(Default)]
struct Runs {
    out: Vec<u8>,
    mark: usize,
    len: usize,
}

impl Runs {
    fn push(&mut self, c: u8) {
        if self.len == 0 {
            self.mark = self.out.len();
            if !self.out.is_empty() {
                self.out.push(b'\n');
            }
        }
        self.out.push(c);
        self.len += 1;
    }

    fn end(&mut self) {
        if self.len > 0 && self.len < 4 {
            self.out.truncate(self.mark);
        }
        self.len = 0;
    }
}

/// Runs of UTF-16 code units whose high byte is zero and whose low byte is printable ASCII, in
/// little and big endian order, at both byte alignments.
fn utf16_runs(b: &[u8], clock: Clock) -> Result<(Vec<u8>, Vec<u8>), Undecodable> {
    let mut little = Runs::default();
    let mut big = Runs::default();
    for align in 0..2 {
        let pairs = b.get(align..).unwrap_or_default().as_chunks::<2>().0;
        for (k, &[x, y]) in pairs.iter().enumerate() {
            if k % TICK == TICK - 1 {
                clock.check()?;
            }
            if y == 0 && printable(x) {
                little.push(x);
            } else {
                little.end();
            }
            if x == 0 && printable(y) {
                big.push(y);
            } else {
                big.end();
            }
        }
        little.end();
        big.end();
    }
    Ok((little.out, big.out))
}

fn is_markup(b: &[u8]) -> bool {
    let b = b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b);
    b.iter().find(|c| !c.is_ascii_whitespace()) == Some(&b'<')
}

/// Decodes `&#NNN;`, `&#xHH;` and the five predefined XML entities. `None` when there is no `&`.
fn entity_decode(b: &[u8], clock: Clock) -> Result<Option<Vec<u8>>, Undecodable> {
    if memchr::memchr(b'&', b).is_none() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut next_tick = TICK;
    while let Some(off) = memchr::memchr(b'&', b.get(i..).unwrap_or_default()) {
        let amp = i + off;
        out.extend_from_slice(b.get(i..amp).unwrap_or_default());
        if amp >= next_tick {
            clock.check()?;
            next_tick = amp.saturating_add(TICK);
        }
        let window = b.get(amp + 1..b.len().min(amp + 16)).unwrap_or_default();
        let decoded = memchr::memchr(b';', window)
            .and_then(|semi| Some((semi, entity(window.get(..semi)?)?)));
        if let Some((semi, ch)) = decoded {
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            i = amp + semi + 2;
        } else {
            out.push(b'&');
            i = amp + 1;
        }
    }
    out.extend_from_slice(b.get(i..).unwrap_or_default());
    Ok(Some(out))
}

fn entity(name: &[u8]) -> Option<char> {
    match name {
        b"lt" => Some('<'),
        b"gt" => Some('>'),
        b"amp" => Some('&'),
        b"quot" => Some('"'),
        b"apos" => Some('\''),
        _ => {
            let num = name.strip_prefix(b"#")?;
            let (digits, radix) = match num.strip_prefix(b"x").or_else(|| num.strip_prefix(b"X")) {
                Some(hex) => (hex, 16),
                None => (num, 10),
            };
            let s = std::str::from_utf8(digits).ok()?;
            char::from_u32(u32::from_str_radix(s, radix).ok()?)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// PNG

impl Ctx<'_> {
    fn png(&mut self, b: &[u8], level: usize) -> Step {
        const W: &str = "png chunk";
        let mut pos = PNG_SIG.len();
        while pos < b.len() {
            let len = to_usize(be32(b, pos, W)?);
            if len > 0x7FFF_FFFF {
                return Err(corrupt(W).into());
            }
            let ty: [u8; 4] = arr(b, pos + 4, W)?;
            let data = slice(b, pos + 8, len, W)?;
            let end = (pos + 12).checked_add(len).ok_or(corrupt(W))?;
            if end > b.len() {
                return Err(corrupt(W).into());
            }
            self.object()?;
            match &ty {
                // Bytes appended after the image (a polyglot archive) are scanned as their own
                // format.
                b"IEND" => return self.dispatch(b.get(end..).unwrap_or_default(), level),
                b"tEXt" => self.derived("png text chunk", data, level)?,
                b"zTXt" => self.png_ztxt(data, level)?,
                b"iTXt" => self.png_itxt(data, level)?,
                b"iCCP" => self.png_iccp(data, level)?,
                b"eXIf" => self.utf16(data)?,
                _ => {}
            }
            pos = end;
        }
        // No `IEND`: truncated.
        Err(corrupt(W).into())
    }

    fn png_ztxt(&mut self, data: &[u8], level: usize) -> Step {
        const W: &str = "png text chunk";
        let (keyword, rest) = split_nul(data, W)?;
        let (&method, compressed) = rest.split_first().ok_or(corrupt(W))?;
        if method != 0 {
            return Err(Undecodable::Unsupported("png compression method").into());
        }
        let text = self.meter.inflate(ZlibDecoder::new(compressed))?;
        let mut v = Vec::with_capacity(keyword.len() + 1 + text.len());
        v.extend_from_slice(keyword);
        v.push(0);
        v.extend_from_slice(&text);
        self.derived("png compressed text", &v, level)
    }

    fn png_itxt(&mut self, data: &[u8], level: usize) -> Step {
        const W: &str = "png text chunk";
        let (_, rest) = split_nul(data, W)?;
        let [flag, method] = arr::<2>(rest, 0, W)?;
        let (_, rest) = split_nul(rest.get(2..).unwrap_or_default(), W)?;
        let (_, text) = split_nul(rest, W)?;
        match flag {
            0 => self.derived("png international text", data, level),
            1 => {
                if method != 0 {
                    return Err(Undecodable::Unsupported("png compression method").into());
                }
                let inflated = self.meter.inflate(ZlibDecoder::new(text))?;
                let header = data.get(..data.len() - text.len()).unwrap_or_default();
                let mut v = Vec::with_capacity(header.len() + inflated.len());
                v.extend_from_slice(header);
                v.extend_from_slice(&inflated);
                self.derived("png international text", &v, level)
            }
            _ => Err(corrupt(W).into()),
        }
    }

    fn png_iccp(&mut self, data: &[u8], level: usize) -> Step {
        const W: &str = "png icc profile";
        let (_, rest) = split_nul(data, W)?;
        let (&method, compressed) = rest.split_first().ok_or(corrupt(W))?;
        if method != 0 {
            return Err(Undecodable::Unsupported("png compression method").into());
        }
        let profile = self.meter.inflate(ZlibDecoder::new(compressed))?;
        self.derived("png icc profile", &profile, level)
    }
}

// ---------------------------------------------------------------------------------------------
// JPEG

const XMP_STD: &[u8] = b"http://ns.adobe.com/xap/1.0/";
const XMP_EXT: &[u8] = b"http://ns.adobe.com/xmp/extension/";

/// Segments of one `APPn` marker and identifier, with their reassembly order.
struct AppGroup<'b> {
    label: &'static str,
    parts: Vec<(&'b [u8], u64, &'b [u8])>,
}

type AppIndex<'b> = HashMap<(u8, &'b [u8]), usize>;

impl Ctx<'_> {
    fn jpeg(&mut self, b: &[u8], level: usize) -> Step {
        const W: &str = "jpeg marker";
        let mut groups: Vec<AppGroup<'_>> = Vec::new();
        let mut index: AppIndex<'_> = HashMap::new();
        let mut pos = 2;
        loop {
            if byte(b, pos, W)? != 0xFF {
                return Err(corrupt(W).into());
            }
            while byte(b, pos, W)? == 0xFF {
                pos += 1;
            }
            let marker = byte(b, pos, W)?;
            pos += 1;
            match marker {
                0xD9 | 0xDA => break,
                0x01 | 0xD0..=0xD8 => continue,
                0x00 => return Err(corrupt(W).into()),
                _ => {}
            }
            let len = be16(b, pos, W)?;
            let payload = slice(b, pos + 2, len.checked_sub(2).ok_or(corrupt(W))?, W)?;
            pos += len;
            self.object()?;
            if marker == 0xFE {
                self.derived("jpeg comment", payload, level)?;
            } else if (0xE0..=0xEF).contains(&marker) {
                add_app(&mut groups, &mut index, marker, payload)?;
            }
        }
        for group in &mut groups {
            self.tick()?;
            group.parts.sort_by(|x, y| (x.0, x.1).cmp(&(y.0, y.1)));
            let joined: Cow<'_, [u8]> = match group.parts.as_slice() {
                [(_, _, only)] => Cow::Borrowed(only),
                parts => Cow::Owned(parts.iter().flat_map(|p| p.2.iter().copied()).collect()),
            };
            self.derived(group.label, &joined, level)?;
        }
        Ok(())
    }
}

fn add_app<'b>(
    groups: &mut Vec<AppGroup<'b>>,
    index: &mut AppIndex<'b>,
    marker: u8,
    payload: &'b [u8],
) -> Result<(), Undecodable> {
    const W: &str = "jpeg app segment";
    let head = payload.get(..80).unwrap_or(payload);
    let (id, data): (&[u8], &[u8]) = match memchr::memchr(0, head) {
        Some(i) => (
            payload.get(..i).unwrap_or_default(),
            payload.get(i + 1..).unwrap_or_default(),
        ),
        None => (&[], payload),
    };
    let ext_xmp = marker == 0xE1 && id == XMP_EXT;
    let icc = marker == 0xE2 && id == b"ICC_PROFILE";
    let slot = *index.entry((marker, id)).or_insert_with(|| {
        let label = if ext_xmp {
            "jpeg extended xmp"
        } else if icc {
            "jpeg icc profile"
        } else if marker == 0xE1 && id == XMP_STD {
            "jpeg xmp"
        } else if marker == 0xE1 && id == b"Exif" {
            "jpeg exif"
        } else {
            "jpeg app segment"
        };
        groups.push(AppGroup {
            label,
            parts: Vec::new(),
        });
        groups.len() - 1
    });
    let group = groups.get_mut(slot).ok_or(corrupt(W))?;
    let part = if ext_xmp {
        // GUID, full length, offset, then the chunk: reassembled by GUID and offset.
        (
            slice(data, 0, 32, W)?,
            u64::from(be32(data, 36, W)?),
            data.get(40..).ok_or(corrupt(W))?,
        )
    } else if icc {
        // Sequence number, count, then the chunk.
        (
            &[][..],
            u64::from(byte(data, 0, W)?),
            data.get(2..).ok_or(corrupt(W))?,
        )
    } else {
        (
            &[][..],
            u64::try_from(group.parts.len()).unwrap_or(u64::MAX),
            data,
        )
    };
    group.parts.push(part);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// GIF

fn color_table(packed: u8) -> usize {
    if packed & 0x80 == 0 {
        0
    } else {
        3 << ((packed & 7) + 1)
    }
}

/// Walks data sub-blocks from `pos` to the terminator and returns the position after it. With
/// `out`, appends the sub-blocks (all, or all but the first with `skip_first`).
fn sub_blocks(
    b: &[u8],
    mut pos: usize,
    mut out: Option<&mut Vec<u8>>,
    skip_first: bool,
    clock: Clock,
) -> Result<usize, Undecodable> {
    const W: &str = "gif block";
    let mut n = 0usize;
    loop {
        let size = usize::from(byte(b, pos, W)?);
        pos += 1;
        if size == 0 {
            return Ok(pos);
        }
        let data = slice(b, pos, size, W)?;
        pos += size;
        if let Some(o) = out.as_deref_mut()
            && !(skip_first && n == 0)
        {
            o.extend_from_slice(data);
        }
        n += 1;
        if n.is_multiple_of(256) {
            clock.check()?;
        }
    }
}

impl Ctx<'_> {
    fn gif(&mut self, b: &[u8], level: usize) -> Step {
        const W: &str = "gif block";
        let mut pos = 13 + color_table(byte(b, 10, W)?);
        while pos < b.len() {
            let intro = byte(b, pos, W)?;
            pos += 1;
            self.object()?;
            match intro {
                0x3B => return Ok(()),
                0x2C => {
                    let packed = byte(b, pos + 8, W)?;
                    // Descriptor, local color table, LZW minimum code size, image data.
                    pos += 9 + color_table(packed) + 1;
                    pos = sub_blocks(b, pos, None, false, self.clock())?;
                }
                0x21 => {
                    let label = byte(b, pos, W)?;
                    pos += 1;
                    let (source, skip_first) = match label {
                        0xFE => (Some("gif comment"), false),
                        0x01 => (Some("gif plain text"), false),
                        0xFF => (Some("gif application data"), true),
                        _ => (None, false),
                    };
                    if let Some(source) = source {
                        let mut joined = Vec::new();
                        pos = sub_blocks(b, pos, Some(&mut joined), skip_first, self.clock())?;
                        self.derived(source, &joined, level)?;
                    } else {
                        pos = sub_blocks(b, pos, None, false, self.clock())?;
                    }
                }
                _ => return Err(corrupt(W).into()),
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// ZIP

impl Ctx<'_> {
    fn zip(&mut self, b: &[u8], level: usize) -> Step {
        const W: &str = "zip directory";
        let tail_start = b.len().saturating_sub(22 + 0xFFFF);
        let eocd = memmem::rfind(b.get(tail_start..).unwrap_or_default(), b"PK\x05\x06")
            .ok_or(corrupt(W))?
            + tail_start;
        let disk = le16(b, eocd + 4, W)?;
        let cd_disk = le16(b, eocd + 6, W)?;
        let entries = le16(b, eocd + 10, W)?;
        let cd_size = le32(b, eocd + 12, W)?;
        let cd_off = le32(b, eocd + 16, W)?;
        if entries == 0xFFFF || cd_size == u32::MAX || cd_off == u32::MAX {
            return Err(Undecodable::Unsupported("zip64").into());
        }
        if disk != 0 || cd_disk != 0 {
            return Err(Undecodable::Unsupported("multi-disk zip").into());
        }
        if entries > self.limits.max_objects.saturating_sub(self.objects) {
            return Err(Undecodable::TooLarge("object count").into());
        }
        let mut p = to_usize(cd_off);
        for _ in 0..entries {
            if b.get(p..p.saturating_add(4)) != Some(b"PK\x01\x02") {
                return Err(corrupt(W).into());
            }
            self.object()?;
            let flags = le16(b, p + 8, W)?;
            let method = le16(b, p + 10, W)?;
            let compressed = le32(b, p + 20, W)?;
            let uncompressed = le32(b, p + 24, W)?;
            let name_len = le16(b, p + 28, W)?;
            let extra_len = le16(b, p + 30, W)?;
            let comment_len = le16(b, p + 32, W)?;
            let local = le32(b, p + 42, W)?;
            p += 46 + name_len + extra_len + comment_len;
            if flags & 1 != 0 || method == 99 {
                return Err(Undecodable::Encrypted.into());
            }
            if compressed == u32::MAX || uncompressed == u32::MAX || local == u32::MAX {
                return Err(Undecodable::Unsupported("zip64").into());
            }
            let data = zip_entry_data(b, to_usize(local), to_usize(compressed))?;
            match method {
                // Stored: the raw view already holds these bytes.
                0 => self.dispatch(data, level)?,
                8 => {
                    let out = self.meter.inflate(DeflateDecoder::new(data))?;
                    self.derived("zip entry", &out, level)?;
                }
                _ => return Err(Undecodable::Unsupported("zip compression method").into()),
            }
        }
        Ok(())
    }
}

fn zip_entry_data(b: &[u8], local: usize, len: usize) -> Result<&[u8], Undecodable> {
    const W: &str = "zip entry";
    if b.get(local..local.saturating_add(4)) != Some(b"PK\x03\x04") {
        return Err(corrupt(W));
    }
    let name_len = le16(b, local + 26, W)?;
    let extra_len = le16(b, local + 28, W)?;
    slice(b, local + 30 + name_len + extra_len, len, W)
}

// ---------------------------------------------------------------------------------------------
// PDF objects

fn is_ws(c: u8) -> bool {
    matches!(c, 0 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

fn is_regular(c: u8) -> bool {
    !is_ws(c) && !b"()<>[]{}/%".contains(&c)
}

/// The parts of a PDF object scrim needs; everything else is `Other`.
enum Obj {
    Name(Vec<u8>),
    Int(i64),
    Ref,
    Null,
    Dict(Dict),
    Array(Vec<Obj>),
    Other,
}

type Dict = Vec<(Vec<u8>, Obj)>;

const MAX_NEST: usize = 32;

fn dict_get<'d>(d: &'d [(Vec<u8>, Obj)], key: &[u8]) -> Option<&'d Obj> {
    d.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn skip_literal(b: &[u8], mut i: usize) -> Option<usize> {
    let mut depth = 1usize;
    loop {
        match *b.get(i)? {
            b'\\' => i += 1,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
}

fn decode_name(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while let Some(&c) = raw.get(i) {
        match raw.get(i..i + 3) {
            Some(&[b'#', h, l]) if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => {
                out.push(hex_val(h).unwrap_or(0) << 4 | hex_val(l).unwrap_or(0));
                i += 3;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

struct Lexer<'b> {
    b: &'b [u8],
    pos: usize,
}

impl Lexer<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if is_ws(c) {
                self.pos += 1;
            } else if c == b'%' {
                while self.peek().is_some_and(|c| c != b'\r' && c != b'\n') {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn skip_regular(&mut self) -> usize {
        let start = self.pos;
        while self.peek().is_some_and(is_regular) {
            self.pos += 1;
        }
        start
    }

    fn object(&mut self, depth: usize) -> Option<Obj> {
        if depth > MAX_NEST {
            return None;
        }
        self.skip_ws();
        let c = self.peek()?;
        match c {
            b'<' if self.b.get(self.pos + 1) == Some(&b'<') => {
                self.pos += 2;
                self.dict(depth)
            }
            b'<' => {
                self.pos += memchr::memchr(b'>', self.b.get(self.pos..)?)? + 1;
                Some(Obj::Other)
            }
            b'[' => {
                self.pos += 1;
                self.array(depth)
            }
            b'(' => {
                self.pos = skip_literal(self.b, self.pos + 1)?;
                Some(Obj::Other)
            }
            b'/' => {
                self.pos += 1;
                let start = self.skip_regular();
                Some(Obj::Name(decode_name(self.b.get(start..self.pos)?)))
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => {
                let start = self.skip_regular();
                let s = std::str::from_utf8(self.b.get(start..self.pos)?).ok()?;
                Some(s.parse().map_or(Obj::Other, Obj::Int))
            }
            _ if is_regular(c) => {
                let start = self.skip_regular();
                Some(match self.b.get(start..self.pos)? {
                    b"null" => Obj::Null,
                    _ => Obj::Other,
                })
            }
            _ => None,
        }
    }

    fn dict(&mut self, depth: usize) -> Option<Obj> {
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.b.get(self.pos..)?.starts_with(b">>") {
                self.pos += 2;
                return Some(Obj::Dict(items));
            }
            if self.peek()? != b'/' {
                return None;
            }
            let Obj::Name(key) = self.object(depth + 1)? else {
                return None;
            };
            let value = self.value(depth + 1)?;
            items.push((key, value));
        }
    }

    fn array(&mut self, depth: usize) -> Option<Obj> {
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek()? == b']' {
                self.pos += 1;
                return Some(Obj::Array(items));
            }
            items.push(self.value(depth + 1)?);
        }
    }

    /// An object, folding `N G R` into a reference.
    fn value(&mut self, depth: usize) -> Option<Obj> {
        let o = self.object(depth)?;
        if matches!(o, Obj::Int(_)) && self.ref_follows() {
            return Some(Obj::Ref);
        }
        Some(o)
    }

    fn ref_follows(&mut self) -> bool {
        let save = self.pos;
        self.skip_ws();
        let digits = self
            .b
            .get(self.pos..)
            .unwrap_or_default()
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if digits > 0 {
            self.pos += digits;
            self.skip_ws();
            let after = self.b.get(self.pos + 1).copied();
            if self.peek() == Some(b'R') && after.is_none_or(|c| !is_regular(c)) {
                self.pos += 1;
                return true;
            }
        }
        self.pos = save;
        false
    }
}

/// Parses the dictionary starting at `start` and returns it if it ends, after whitespace,
/// exactly at `end`.
fn dict_ending_at(b: &[u8], start: usize, end: usize) -> Option<Dict> {
    let mut lx = Lexer {
        b: b.get(..end)?,
        pos: start,
    };
    let Obj::Dict(d) = lx.object(0)? else {
        return None;
    };
    lx.skip_ws();
    (lx.pos == end).then_some(d)
}

/// How far back from a `stream` keyword its dictionary may start.
const DICT_WINDOW: usize = 1 << 16;

/// Finds the dictionary in front of the `stream` keyword at `s`, looking no further back than
/// `lo` (the end of the previous stream).
fn stream_dict(b: &[u8], lo: usize, s: usize) -> Result<Dict, Undecodable> {
    const W: &str = "pdf stream dictionary";
    let lo = lo.max(s.saturating_sub(DICT_WINDOW));
    let mut j = s;
    while j > lo && b.get(j - 1).copied().is_some_and(is_ws) {
        j -= 1;
    }
    if j < lo + 2 || b.get(j - 2..j) != Some(b">>") {
        return Err(corrupt(W));
    }
    // Match `<<` backwards, then confirm with a forward parse.
    let mut depth = 0usize;
    let mut p = j;
    while p >= lo + 2 {
        match b.get(p - 2..p) {
            Some(b">>") => {
                depth += 1;
                p -= 2;
            }
            Some(b"<<") => {
                depth = depth.saturating_sub(1);
                p -= 2;
                if depth == 0 {
                    if let Some(d) = dict_ending_at(b, p, s) {
                        return Ok(d);
                    }
                    break;
                }
            }
            _ => p -= 1,
        }
    }
    // A `>>` inside a string fooled the backward match: parse forward from `obj`.
    memmem::rfind(b.get(lo..s).unwrap_or_default(), b"obj")
        .and_then(|o| dict_ending_at(b, lo + o + 3, s))
        .ok_or(corrupt(W))
}

/// The stream data's end and the position after `endstream`.
fn stream_end(
    b: &[u8],
    dict: &[(Vec<u8>, Obj)],
    start: usize,
) -> Result<(usize, usize), Undecodable> {
    if let Some(Obj::Int(len)) = dict_get(dict, b"Length") {
        let end = usize::try_from(*len)
            .ok()
            .and_then(|l| start.checked_add(l));
        if let Some(end) = end.filter(|&e| e <= b.len()) {
            let mut q = end;
            while b.get(q).copied().is_some_and(is_ws) {
                q += 1;
            }
            if b.get(q..).unwrap_or_default().starts_with(b"endstream") {
                return Ok((end, q + 9));
            }
        }
    }
    let k = memmem::find(b.get(start..).unwrap_or_default(), b"endstream")
        .ok_or(corrupt("pdf stream end"))?
        + start;
    let mut end = k;
    if end > start && b.get(end - 1) == Some(&b'\n') {
        end -= 1;
    }
    if end > start && b.get(end - 1) == Some(&b'\r') {
        end -= 1;
    }
    Ok((end, k + 9))
}

// ---------------------------------------------------------------------------------------------
// PDF filters

#[derive(Clone, Copy, PartialEq, Eq)]
enum Filter {
    Flate,
    Lzw,
    Hex,
    A85,
    RunLength,
    Dct,
    /// JPX, JBIG2, CCITT fax: image data scrim does not read.
    Image,
    Crypt,
    Unknown,
}

fn filter_kind(name: &[u8]) -> Filter {
    match name {
        b"FlateDecode" | b"Fl" => Filter::Flate,
        b"LZWDecode" | b"LZW" => Filter::Lzw,
        b"ASCIIHexDecode" | b"AHx" => Filter::Hex,
        b"ASCII85Decode" | b"A85" => Filter::A85,
        b"RunLengthDecode" | b"RL" => Filter::RunLength,
        b"DCTDecode" | b"DCT" => Filter::Dct,
        b"JPXDecode" | b"JBIG2Decode" | b"CCITTFaxDecode" | b"CCF" => Filter::Image,
        b"Crypt" => Filter::Crypt,
        _ => Filter::Unknown,
    }
}

#[derive(Clone, Copy)]
enum Parms<'d> {
    None,
    Dict(&'d [(Vec<u8>, Obj)]),
    Indirect,
}

const INDIRECT_PARMS: Undecodable = Undecodable::Unsupported("indirect pdf decode parameters");

fn parms_of(o: Option<&Obj>) -> Result<Parms<'_>, Undecodable> {
    match o {
        None | Some(Obj::Null) => Ok(Parms::None),
        Some(Obj::Dict(d)) => Ok(Parms::Dict(d)),
        Some(Obj::Ref) => Ok(Parms::Indirect),
        Some(_) => Err(corrupt("pdf decode parameters")),
    }
}

fn pdf_filters(dict: &[(Vec<u8>, Obj)]) -> Result<Vec<(Filter, Parms<'_>)>, Undecodable> {
    const W: &str = "pdf filter";
    let names: Vec<&[u8]> = match dict_get(dict, b"Filter") {
        None | Some(Obj::Null) => return Ok(Vec::new()),
        Some(Obj::Name(n)) => vec![n],
        Some(Obj::Array(a)) => a
            .iter()
            .map(|o| match o {
                Obj::Name(n) => Ok(n.as_slice()),
                Obj::Ref => Err(Undecodable::Unsupported("indirect pdf filter")),
                _ => Err(corrupt(W)),
            })
            .collect::<Result<_, _>>()?,
        Some(Obj::Ref) => return Err(Undecodable::Unsupported("indirect pdf filter")),
        Some(_) => return Err(corrupt(W)),
    };
    let parms = dict_get(dict, b"DecodeParms").or_else(|| dict_get(dict, b"DP"));
    let mut out = Vec::with_capacity(names.len());
    for (i, name) in names.iter().enumerate() {
        let p = match parms {
            Some(Obj::Array(a)) => parms_of(a.get(i))?,
            // A single dictionary for a chain is ambiguous unless the chain has one filter.
            Some(Obj::Dict(_)) if names.len() > 1 => {
                return Err(Undecodable::Unsupported("pdf decode parameters"));
            }
            other => parms_of(other)?,
        };
        out.push((filter_kind(name), p));
    }
    Ok(out)
}

fn parm_int(p: Parms<'_>, key: &[u8], default: i64) -> Result<i64, Undecodable> {
    match p {
        Parms::None => Ok(default),
        Parms::Indirect => Err(INDIRECT_PARMS),
        Parms::Dict(d) => match dict_get(d, key) {
            None | Some(Obj::Null) => Ok(default),
            Some(Obj::Int(v)) => Ok(*v),
            Some(Obj::Ref) => Err(INDIRECT_PARMS),
            Some(_) => Err(corrupt("pdf decode parameters")),
        },
    }
}

fn parm_in(p: Parms<'_>, key: &[u8], default: i64, max: i64) -> Result<usize, Undecodable> {
    let v = parm_int(p, key, default)?;
    if !(1..=max).contains(&v) {
        return Err(corrupt("pdf decode parameters"));
    }
    usize::try_from(v).map_err(|_| corrupt("pdf decode parameters"))
}

/// Undoes a `/Predictor` from the filter's decode parameters.
fn unpredict(raw: Vec<u8>, p: Parms<'_>, clock: Clock) -> Result<Vec<u8>, Undecodable> {
    let predictor = parm_int(p, b"Predictor", 1)?;
    if predictor == 1 {
        return Ok(raw);
    }
    if predictor != 2 && !(10..=15).contains(&predictor) {
        return Err(Undecodable::Unsupported("pdf predictor"));
    }
    let colors = parm_in(p, b"Colors", 1, 64)?;
    let bpc = parm_in(p, b"BitsPerComponent", 8, 16)?;
    let columns = parm_in(p, b"Columns", 1, 1 << 24)?;
    let bits = colors * bpc;
    let bpp = bits.div_ceil(8).max(1);
    let row = (bits * columns).div_ceil(8);
    if predictor == 2 {
        if bpc != 8 {
            return Err(Undecodable::Unsupported("pdf predictor"));
        }
        return Ok(tiff_unpredict(raw, row, bpp));
    }
    png_unpredict(&raw, row, bpp, clock)
}

fn tiff_unpredict(mut raw: Vec<u8>, row: usize, bpp: usize) -> Vec<u8> {
    for line in raw.chunks_mut(row) {
        for i in bpp..line.len() {
            let left = line.get(i - bpp).copied().unwrap_or(0);
            if let Some(x) = line.get_mut(i) {
                *x = x.wrapping_add(left);
            }
        }
    }
    raw
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let pa = (p - i16::from(a)).abs();
    let pb = (p - i16::from(b)).abs();
    let pc = (p - i16::from(c)).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

fn png_unpredict(raw: &[u8], row: usize, bpp: usize, clock: Clock) -> Result<Vec<u8>, Undecodable> {
    let mut out = Vec::with_capacity(raw.len());
    let mut prev = vec![0u8; row.min(raw.len())];
    let stride = row.checked_add(1).ok_or(TOO_INFLATED)?;
    for (n, chunk) in raw.chunks(stride).enumerate() {
        if n % 1024 == 1023 {
            clock.check()?;
        }
        let Some((&kind, line)) = chunk.split_first() else {
            continue;
        };
        let start = out.len();
        for (i, &x) in line.iter().enumerate() {
            let left = i.checked_sub(bpp);
            let a = left.and_then(|k| out.get(start + k)).copied().unwrap_or(0);
            let b = prev.get(i).copied().unwrap_or(0);
            let c = left.and_then(|k| prev.get(k)).copied().unwrap_or(0);
            let v = match kind {
                0 => x,
                1 => x.wrapping_add(a),
                2 => x.wrapping_add(b),
                3 => x.wrapping_add(low_byte(u32::midpoint(u32::from(a), u32::from(b)))),
                4 => x.wrapping_add(paeth(a, b, c)),
                _ => return Err(corrupt("pdf predictor")),
            };
            out.push(v);
        }
        let decoded = out.get(start..).unwrap_or_default();
        if let Some(dst) = prev.get_mut(..decoded.len()) {
            dst.copy_from_slice(decoded);
        }
    }
    Ok(out)
}

fn ascii_hex(input: &[u8]) -> Result<Vec<u8>, Undecodable> {
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut hi: Option<u8> = None;
    for &c in input {
        if c == b'>' {
            break;
        }
        if is_ws(c) {
            continue;
        }
        let v = hex_val(c).ok_or(corrupt("pdf hex data"))?;
        match hi.take() {
            Some(h) => out.push(h << 4 | v),
            None => hi = Some(v),
        }
    }
    if let Some(h) = hi {
        out.push(h << 4);
    }
    Ok(out)
}

fn ascii85(input: &[u8], limit: usize) -> Result<Vec<u8>, Undecodable> {
    const W: &str = "pdf ascii85 data";
    let trimmed = input.trim_ascii_start();
    let body = trimmed.strip_prefix(b"<~").unwrap_or(trimmed);
    let mut out = Vec::with_capacity(body.len() / 5 * 4 + 4);
    let mut acc = 0u64;
    let mut n = 0usize;
    for &c in body {
        if c == b'~' {
            break;
        }
        if is_ws(c) {
            continue;
        }
        if c == b'z' {
            if n != 0 {
                return Err(corrupt(W));
            }
            out.extend_from_slice(&[0; 4]);
        } else if (b'!'..=b'u').contains(&c) {
            acc = acc * 85 + u64::from(c - b'!');
            n += 1;
            if n == 5 {
                let v = u32::try_from(acc).map_err(|_| corrupt(W))?;
                out.extend_from_slice(&v.to_be_bytes());
                acc = 0;
                n = 0;
            }
        } else {
            return Err(corrupt(W));
        }
        if out.len() > limit {
            return Err(TOO_INFLATED);
        }
    }
    match n {
        0 => {}
        1 => return Err(corrupt(W)),
        _ => {
            for _ in n..5 {
                acc = acc * 85 + 84;
            }
            let v = u32::try_from(acc).map_err(|_| corrupt(W))?;
            out.extend_from_slice(v.to_be_bytes().get(..n - 1).unwrap_or_default());
        }
    }
    Ok(out)
}

fn run_length(input: &[u8], limit: usize, clock: Clock) -> Result<Vec<u8>, Undecodable> {
    const W: &str = "pdf run length data";
    let mut out = Vec::new();
    let mut i = 0;
    let mut next_tick = TICK;
    while let Some(&l) = input.get(i) {
        i += 1;
        match l {
            128 => break,
            0..=127 => {
                let n = usize::from(l) + 1;
                out.extend_from_slice(slice(input, i, n, W)?);
                i += n;
            }
            _ => {
                let v = byte(input, i, W)?;
                i += 1;
                out.resize(out.len() + 257 - usize::from(l), v);
            }
        }
        if out.len() > limit {
            return Err(TOO_INFLATED);
        }
        if out.len() >= next_tick {
            clock.check()?;
            next_tick = out.len() + TICK;
        }
    }
    Ok(out)
}

#[derive(Clone, Copy)]
struct LzwEntry {
    prefix: u16,
    first: u8,
    last: u8,
    len: u16,
}

/// Appends the string for `code` and returns its first byte.
fn lzw_emit(table: &[LzwEntry], code: usize, out: &mut Vec<u8>) -> Result<u8, Undecodable> {
    const W: &str = "pdf lzw data";
    let entry = table.get(code).ok_or(corrupt(W))?;
    let len = usize::from(entry.len);
    let start = out.len();
    out.resize(start + len, 0);
    let mut c = code;
    for i in (start..start + len).rev() {
        let e = table.get(c).ok_or(corrupt(W))?;
        if let Some(slot) = out.get_mut(i) {
            *slot = e.last;
        }
        c = usize::from(e.prefix);
    }
    Ok(entry.first)
}

fn lzw(input: &[u8], early: bool, limit: usize, clock: Clock) -> Result<Vec<u8>, Undecodable> {
    const W: &str = "pdf lzw data";
    let fresh = |c: u8| LzwEntry {
        prefix: 0,
        first: c,
        last: c,
        len: 1,
    };
    let mut table: Vec<LzwEntry> = (0..=255u8).map(fresh).collect();
    table.extend([fresh(0), fresh(0)]); // 256 clear, 257 end: never looked up
    let early = usize::from(early);
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut nbits = 0u32;
    let mut width = 9u32;
    let mut prev: Option<usize> = None;
    let mut bytes = input.iter();
    let mut next_tick = TICK;
    loop {
        while nbits < width {
            let Some(&c) = bytes.next() else {
                return Ok(out);
            };
            acc = (acc << 8) | u32::from(c);
            nbits += 8;
        }
        nbits -= width;
        let code = usize::try_from((acc >> nbits) & ((1 << width) - 1)).map_err(|_| corrupt(W))?;
        acc &= (1 << nbits) - 1;
        match (code, prev) {
            (256, _) => {
                table.truncate(258);
                width = 9;
                prev = None;
                continue;
            }
            (257, _) => return Ok(out),
            (_, None) => {
                out.push(u8::try_from(code).map_err(|_| corrupt(W))?);
            }
            (_, Some(p)) => {
                let first = match code.cmp(&table.len()) {
                    std::cmp::Ordering::Less => lzw_emit(&table, code, &mut out)?,
                    // The code being defined right now (KwKwK): the previous string plus its
                    // own first byte.
                    std::cmp::Ordering::Equal => {
                        let f = lzw_emit(&table, p, &mut out)?;
                        out.push(f);
                        f
                    }
                    std::cmp::Ordering::Greater => return Err(corrupt(W)),
                };
                if table.len() < 4096 {
                    let pe = *table.get(p).ok_or(corrupt(W))?;
                    table.push(LzwEntry {
                        prefix: u16::try_from(p).map_err(|_| corrupt(W))?,
                        first: pe.first,
                        last: first,
                        len: pe.len.saturating_add(1),
                    });
                }
                if table.len() + early >= (1 << width) && width < 12 {
                    width += 1;
                }
            }
        }
        prev = Some(code);
        if out.len() > limit {
            return Err(TOO_INFLATED);
        }
        if out.len() >= next_tick {
            clock.check()?;
            next_tick = out.len() + TICK;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// PDF strings

/// Appends one decoded string: UTF-16BE (with byte order mark) becomes UTF-8, a UTF-8 byte
/// order mark is dropped, anything else is kept as is.
fn push_pdf_string(s: &[u8], out: &mut Vec<u8>) {
    if let Some(rest) = s.strip_prefix(b"\xFE\xFF") {
        let units = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&p| u16::from_be_bytes(p));
        for ch in char::decode_utf16(units) {
            let ch = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    } else {
        out.extend_from_slice(s.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(s));
    }
}

/// Decodes a literal string whose `(` is just before `i`; returns the position after `)`.
fn literal(src: &[u8], mut i: usize, buf: &mut Vec<u8>) -> usize {
    let mut depth = 1usize;
    while let Some(&c) = src.get(i) {
        i += 1;
        match c {
            b'\\' => {
                let Some(&esc) = src.get(i) else { break };
                i += 1;
                match esc {
                    b'n' => buf.push(b'\n'),
                    b'r' => buf.push(b'\r'),
                    b't' => buf.push(b'\t'),
                    b'b' => buf.push(0x08),
                    b'f' => buf.push(0x0C),
                    b'0'..=b'7' => {
                        let mut val = u32::from(esc - b'0');
                        for _ in 0..2 {
                            match src.get(i) {
                                Some(&digit @ b'0'..=b'7') => {
                                    val = val * 8 + u32::from(digit - b'0');
                                    i += 1;
                                }
                                _ => break,
                            }
                        }
                        buf.push(low_byte(val));
                    }
                    b'\r' => {
                        if src.get(i) == Some(&b'\n') {
                            i += 1;
                        }
                    }
                    b'\n' => {}
                    other => buf.push(other),
                }
            }
            b'(' => {
                depth += 1;
                buf.push(c);
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                buf.push(c);
            }
            b'\r' => {
                if src.get(i) == Some(&b'\n') {
                    i += 1;
                }
                buf.push(b'\n');
            }
            _ => buf.push(c),
        }
    }
    i
}

/// Decodes a hex string whose `<` is just before `i`; `None` when it is not one.
fn hex_string(src: &[u8], mut i: usize, buf: &mut Vec<u8>) -> Option<usize> {
    let mut hi: Option<u8> = None;
    loop {
        let c = *src.get(i)?;
        i += 1;
        if c == b'>' {
            break;
        }
        if is_ws(c) {
            continue;
        }
        let val = hex_val(c)?;
        match hi.take() {
            Some(high) => buf.push(high << 4 | val),
            None => hi = Some(val),
        }
    }
    if let Some(high) = hi {
        buf.push(high << 4);
    }
    Some(i)
}

/// Appends every string object in `r`, in order, with no separator.
fn extract_strings(r: &[u8], out: &mut Vec<u8>, clock: Clock) -> Result<(), Undecodable> {
    let mut i = 0;
    let mut s = Vec::new();
    let mut next_tick = TICK;
    while let Some(off) = memchr::memchr3(b'%', b'(', b'<', r.get(i..).unwrap_or_default()) {
        i += off;
        if i >= next_tick {
            clock.check()?;
            next_tick = i.saturating_add(TICK);
        }
        match r.get(i) {
            Some(b'%') => {
                let rest = r.get(i..).unwrap_or_default();
                i = memchr::memchr2(b'\r', b'\n', rest).map_or(r.len(), |o| i + o);
            }
            Some(b'(') => {
                s.clear();
                i = literal(r, i + 1, &mut s);
                push_pdf_string(&s, out);
            }
            _ if r.get(i + 1) == Some(&b'<') => i += 2,
            _ => {
                s.clear();
                if let Some(end) = hex_string(r, i + 1, &mut s) {
                    push_pdf_string(&s, out);
                    i = end;
                } else {
                    i += 1;
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// PDF

struct PdfStream<'b> {
    dict: Dict,
    data: &'b [u8],
}

type Gaps = Vec<(usize, usize)>;

fn name_is(o: Option<&Obj>, name: &[u8]) -> bool {
    matches!(o, Some(Obj::Name(n)) if n == name)
}

impl Ctx<'_> {
    fn pdf(&mut self, b: &[u8], level: usize) -> Step {
        pdf_trailers_unencrypted(b)?;
        let (streams, gaps) = self.pdf_streams(b)?;
        for st in &streams {
            self.tick()?;
            self.pdf_stream(st, level)?;
        }
        let mut strings = Vec::new();
        for (from, to) in gaps {
            extract_strings(
                b.get(from..to).unwrap_or_default(),
                &mut strings,
                self.clock(),
            )?;
        }
        self.emit("pdf strings", &strings)
    }

    /// Finds every stream by its keyword. Returns the streams and the byte ranges outside them.
    fn pdf_streams<'b>(&mut self, b: &'b [u8]) -> Result<(Vec<PdfStream<'b>>, Gaps), Undecodable> {
        let finder = memmem::Finder::new(b"stream");
        let mut streams = Vec::new();
        let mut gaps = Vec::new();
        let mut pos = 0;
        let mut prev_end = 0;
        while let Some(off) = finder.find(b.get(pos..).unwrap_or_default()) {
            let s = pos + off;
            pos = s + 6;
            if s >= 3 && b.get(s - 3..s) == Some(b"end") {
                continue;
            }
            let data_start = match (b.get(s + 6), b.get(s + 7)) {
                (Some(b'\r'), Some(b'\n')) => s + 8,
                (Some(b'\n' | b'\r'), _) => s + 7,
                _ => continue,
            };
            let before = s.checked_sub(1).and_then(|i| b.get(i)).copied();
            if !before.is_some_and(|c| is_ws(c) || c == b'>') {
                continue;
            }
            self.object()?;
            let dict = stream_dict(b, prev_end, s)?;
            if dict_get(&dict, b"Encrypt").is_some() {
                return Err(Undecodable::Encrypted);
            }
            let (data_end, after) = stream_end(b, &dict, data_start)?;
            gaps.push((prev_end, s));
            streams.push(PdfStream {
                dict,
                data: b.get(data_start..data_end).unwrap_or_default(),
            });
            pos = after;
            prev_end = after;
        }
        gaps.push((prev_end, b.len()));
        Ok((streams, gaps))
    }

    fn pdf_stream(&mut self, st: &PdfStream<'_>, level: usize) -> Step {
        let filters = pdf_filters(&st.dict)?;
        if filters.iter().any(|(f, _)| *f == Filter::Crypt) {
            return Err(Undecodable::Encrypted.into());
        }
        let is_image = name_is(dict_get(&st.dict, b"Subtype"), b"Image");
        if is_image && !filters.iter().any(|(f, _)| *f == Filter::Dct) {
            // Pixels: out of scope.
            return Ok(());
        }
        let mut data: Cow<'_, [u8]> = Cow::Borrowed(st.data);
        let mut image = false;
        for &(filter, parms) in &filters {
            self.tick()?;
            let limit = self.meter.remaining();
            let clock = self.clock();
            let out = match filter {
                Filter::Flate => {
                    let raw = self.meter.inflate(ZlibDecoder::new(&*data))?;
                    unpredict(raw, parms, clock)?
                }
                Filter::Lzw => {
                    let early = parm_int(parms, b"EarlyChange", 1)? != 0;
                    let raw = lzw(&data, early, limit, clock)?;
                    self.meter.add(raw.len())?;
                    unpredict(raw, parms, clock)?
                }
                Filter::Hex => self.metered(ascii_hex(&data)?)?,
                Filter::A85 => self.metered(ascii85(&data, limit)?)?,
                Filter::RunLength => self.metered(run_length(&data, limit, clock)?)?,
                Filter::Dct | Filter::Image => {
                    image = true;
                    break;
                }
                Filter::Crypt => return Err(Undecodable::Encrypted.into()),
                Filter::Unknown => return Err(Undecodable::Unsupported("pdf filter").into()),
            };
            data = Cow::Owned(out);
        }
        let borrowed = matches!(data, Cow::Borrowed(_));
        if image {
            // Only the image's own metadata (a JPEG's segments) is read.
            return if borrowed {
                self.dispatch(&data, level)
            } else {
                self.derived("pdf image", &data, level)
            };
        }
        if borrowed {
            // Unfiltered: the raw view already holds these bytes.
            self.dispatch(&data, level)?;
        } else {
            self.derived("pdf stream", &data, level)?;
        }
        let mut text = Vec::new();
        extract_strings(&data, &mut text, self.clock())?;
        self.emit("pdf text", &text)?;
        self.utf16(&text)
    }

    fn metered(&mut self, out: Vec<u8>) -> Result<Vec<u8>, Undecodable> {
        self.meter.add(out.len())?;
        self.tick()?;
        Ok(out)
    }
}

/// Refuses a PDF whose trailer names an `/Encrypt` dictionary.
fn pdf_trailers_unencrypted(b: &[u8]) -> Result<(), Undecodable> {
    for t in memmem::find_iter(b, b"trailer") {
        let mut p = t + 7;
        while b.get(p).copied().is_some_and(is_ws) {
            p += 1;
        }
        if !b.get(p..).unwrap_or_default().starts_with(b"<<") {
            continue;
        }
        let mut lx = Lexer { b, pos: p };
        match lx.object(0) {
            Some(Obj::Dict(d)) => {
                if dict_get(&d, b"Encrypt").is_some() {
                    return Err(Undecodable::Encrypted);
                }
            }
            _ => return Err(corrupt("pdf trailer")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write as _;
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use flate2::Compression;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use proptest::prelude::*;

    use super::*;

    /// A value generated for this run, shaped like a secret (lowercase hex and dashes, so it
    /// needs no escaping in any of the formats).
    fn generated_value() -> String {
        use std::hash::BuildHasher as _;
        let h = std::collections::hash_map::RandomState::new().hash_one(0u8);
        format!("zq-test-value-{h:016x}")
    }

    /// Every view of `b`, as `(source, bytes)`.
    fn views_with(b: &[u8], limits: &Limits) -> Result<Vec<(&'static str, Vec<u8>)>, Undecodable> {
        let mut out = Vec::new();
        scan_views(b, limits, &mut |v| {
            out.push((v.source, v.bytes.to_vec()));
            true
        })?;
        Ok(out)
    }

    /// The sources of the views of `b` that contain `needle`.
    fn found_with(b: &[u8], needle: &str, limits: &Limits) -> Vec<&'static str> {
        views_with(b, limits)
            .unwrap_or_else(|e| panic!("scan failed: {e}"))
            .into_iter()
            .filter(|(_, v)| memmem::find(v, needle.as_bytes()).is_some())
            .map(|(s, _)| s)
            .collect()
    }

    fn found(b: &[u8], needle: &str) -> Vec<&'static str> {
        found_with(b, needle, &Limits::default())
    }

    fn scan_err_with(b: &[u8], limits: &Limits) -> Undecodable {
        match views_with(b, limits) {
            Ok(views) => panic!("the scan should fail; it gave {} views", views.len()),
            Err(e) => e,
        }
    }

    fn scan_err(b: &[u8]) -> Undecodable {
        scan_err_with(b, &Limits::default())
    }

    /// Text around `v` that makes the compressors emit coded blocks rather than stored ones,
    /// so the value is not in the compressed bytes in plain.
    fn padded(v: &str) -> String {
        format!("{}{v}{}", "lorem ".repeat(40), " ipsum".repeat(40))
    }

    /// Asserts that only a decoded or extracted view holds `v`, never the raw bytes.
    fn hidden_from_raw(b: &[u8], v: &str) {
        assert!(
            memmem::find(b, v.as_bytes()).is_none(),
            "fixture holds the value in plain"
        );
    }

    // -----------------------------------------------------------------------------------------
    // fixture builders

    fn zlib(d: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(d).unwrap();
        e.finish().unwrap()
    }

    fn deflate(d: &[u8]) -> Vec<u8> {
        let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(d).unwrap();
        e.finish().unwrap()
    }

    fn gzip(d: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(d).unwrap();
        e.finish().unwrap()
    }

    fn png_chunk(out: &mut Vec<u8>, ty: [u8; 4], data: &[u8]) {
        out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&ty);
        out.extend_from_slice(data);
        let mut h = crc32fast::Hasher::new();
        h.update(&ty);
        h.update(data);
        out.extend_from_slice(&h.finalize().to_be_bytes());
    }

    /// A 1x1 greyscale PNG with `chunks` between the header and the image data.
    fn png(chunks: &[([u8; 4], Vec<u8>)]) -> Vec<u8> {
        let mut p = PNG_SIG.to_vec();
        png_chunk(&mut p, *b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]);
        for (ty, data) in chunks {
            png_chunk(&mut p, *ty, data);
        }
        png_chunk(&mut p, *b"IDAT", &zlib(&[0, 0]));
        png_chunk(&mut p, *b"IEND", &[]);
        p
    }

    /// A PNG chunk: type and data.
    type Chunk = ([u8; 4], Vec<u8>);

    fn ztxt(text: &[u8]) -> Chunk {
        (*b"zTXt", [b"Comment\0\0", &zlib(text)[..]].concat())
    }

    /// A JPEG with `segments` (marker, payload) before a scan whose data must not be read.
    fn jpeg(segments: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut j = vec![0xFF, 0xD8];
        for (marker, payload) in segments {
            j.extend_from_slice(&[0xFF, *marker]);
            j.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap().to_be_bytes());
            j.extend_from_slice(payload);
        }
        j.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x00, 0xFF, 0x00, 0x13, 0xFF, 0xD9]);
        j
    }

    fn app(id: &[u8], data: &[u8]) -> Vec<u8> {
        [id, b"\0", data].concat()
    }

    /// GIF data sub-blocks of at most `size` bytes, with the terminator.
    fn sub(data: &[u8], size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for c in data.chunks(size) {
            out.push(u8::try_from(c.len()).unwrap());
            out.extend_from_slice(c);
        }
        out.push(0);
        out
    }

    /// A 1x1 GIF: header, a two-colour global table, `body`, trailer.
    fn gif(body: &[u8]) -> Vec<u8> {
        let mut g = b"GIF89a\x01\x00\x01\x00\x80\x00\x00".to_vec();
        g.extend_from_slice(&[0; 6]);
        g.extend_from_slice(body);
        g.push(0x3B);
        g
    }

    fn gif_image() -> Vec<u8> {
        let mut b = vec![0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2];
        b.extend_from_slice(&sub(&[0x44, 0x01], 255));
        b
    }

    /// A ZIP of `(name, flags, method, content)`; method 8 entries are deflated, any other
    /// method is written as is.
    fn zip(entries: &[(&str, u16, u16, &[u8])]) -> Vec<u8> {
        let mut z = Vec::new();
        let mut central = Vec::new();
        for &(name, flags, method, content) in entries {
            let data = if method == 8 {
                deflate(content)
            } else {
                content.to_vec()
            };
            let crc = crc32fast::hash(content);
            let local = u32::try_from(z.len()).unwrap();
            let size = |n: usize| u32::try_from(n).unwrap().to_le_bytes();
            let name_len = u16::try_from(name.len()).unwrap().to_le_bytes();
            z.extend_from_slice(b"PK\x03\x04\x14\x00");
            z.extend_from_slice(&flags.to_le_bytes());
            z.extend_from_slice(&method.to_le_bytes());
            z.extend_from_slice(&[0; 4]);
            z.extend_from_slice(&crc.to_le_bytes());
            z.extend_from_slice(&size(data.len()));
            z.extend_from_slice(&size(content.len()));
            z.extend_from_slice(&name_len);
            z.extend_from_slice(&[0, 0]);
            z.extend_from_slice(name.as_bytes());
            z.extend_from_slice(&data);
            central.extend_from_slice(b"PK\x01\x02\x14\x00\x14\x00");
            central.extend_from_slice(&flags.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&size(data.len()));
            central.extend_from_slice(&size(content.len()));
            central.extend_from_slice(&name_len);
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&local.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_off = u32::try_from(z.len()).unwrap();
        let count = u16::try_from(entries.len()).unwrap().to_le_bytes();
        let cd_size = u32::try_from(central.len()).unwrap();
        z.extend_from_slice(&central);
        z.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        z.extend_from_slice(&count);
        z.extend_from_slice(&count);
        z.extend_from_slice(&cd_size.to_le_bytes());
        z.extend_from_slice(&cd_off.to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        z
    }

    /// A PDF with one object per `(dictionary entries, stream data)`; `None` is a plain
    /// dictionary. `trailer` adds entries to the trailer dictionary.
    fn pdf(objects: &[(&str, Option<&[u8]>)], trailer: &str) -> Vec<u8> {
        let mut p = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
        for (i, (dict, data)) in objects.iter().enumerate() {
            writeln!(p, "{} 0 obj", i + 1).unwrap();
            match data {
                Some(d) => {
                    writeln!(p, "<< {dict} /Length {} >>\nstream", d.len()).unwrap();
                    p.extend_from_slice(d);
                    p.extend_from_slice(b"\nendstream\n");
                }
                None => writeln!(p, "<< {dict} >>").unwrap(),
            }
            p.extend_from_slice(b"endobj\n");
        }
        writeln!(p, "trailer\n<< /Root 1 0 R {trailer} >>\n%%EOF").unwrap();
        p
    }

    /// A content stream showing `v` split across two strings of a `TJ` array, as a PDF writer
    /// kerns text: the value is never contiguous in the stream itself.
    fn content(v: &str, split: usize) -> Vec<u8> {
        let (a, b) = v.split_at(split);
        format!("BT /F1 12 Tf 72 712 Td [({a}) -20 ({b})] TJ ET\n").into_bytes()
    }

    /// LZW as PDF writes it: a clear code first, code widths following the decoder's table
    /// (`EarlyChange`), the table cleared before it fills. The golden vectors check the decoder
    /// against Ghostscript's encoder independently of this one.
    fn lzw_encode(data: &[u8], early: bool) -> Vec<u8> {
        struct Bits {
            out: Vec<u8>,
            acc: u64,
            n: u32,
        }
        impl Bits {
            fn put(&mut self, code: usize, width: u32) {
                self.acc = (self.acc << width) | u64::try_from(code).unwrap();
                self.n += width;
                while self.n >= 8 {
                    self.n -= 8;
                    self.out.push(low_byte(
                        u32::try_from((self.acc >> self.n) & 0xFF).unwrap(),
                    ));
                }
            }
        }
        let early = usize::from(early);
        let fresh = || -> HashMap<Vec<u8>, usize> {
            (0..=255u8).map(|c| (vec![c], usize::from(c))).collect()
        };
        let mut dict = fresh();
        let mut bits = Bits {
            out: Vec::new(),
            acc: 0,
            n: 0,
        };
        let (mut width, mut decoder_len, mut first) = (9u32, 258usize, true);
        // What the decoder does after reading one code.
        let step = |width: &mut u32, decoder_len: &mut usize, first: &mut bool| {
            if !std::mem::take(first) {
                *decoder_len = (*decoder_len + 1).min(4096);
                if *decoder_len + early >= 1 << *width && *width < 12 {
                    *width += 1;
                }
            }
        };
        bits.put(256, 9);
        let mut w: Vec<u8> = Vec::new();
        for &c in data {
            let mut wc = w.clone();
            wc.push(c);
            if dict.contains_key(&wc) {
                w = wc;
                continue;
            }
            bits.put(dict[&w], width);
            step(&mut width, &mut decoder_len, &mut first);
            let next = 258 + dict.len() - 256;
            if next >= 4000 {
                bits.put(256, width);
                dict = fresh();
                (width, decoder_len, first) = (9, 258, true);
            } else {
                dict.insert(wc, next);
            }
            w = vec![c];
        }
        if !w.is_empty() {
            bits.put(dict[&w], width);
            step(&mut width, &mut decoder_len, &mut first);
        }
        bits.put(257, width);
        bits.put(0, 7);
        bits.out
    }

    fn ascii85_encode(d: &[u8]) -> Vec<u8> {
        let mut out = b"<~".to_vec();
        for ch in d.chunks(4) {
            let mut b = [0u8; 4];
            b.get_mut(..ch.len()).unwrap().copy_from_slice(ch);
            let v = u32::from_be_bytes(b);
            if ch.len() == 4 && v == 0 {
                out.push(b'z');
                continue;
            }
            let mut digits = [0u8; 5];
            let mut x = v;
            for k in (0..5).rev() {
                digits[k] = b'!' + u8::try_from(x % 85).unwrap();
                x /= 85;
            }
            out.extend_from_slice(&digits[..=ch.len()]);
        }
        out.extend_from_slice(b"~>");
        out
    }

    fn run_length_encode(d: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < d.len() {
            let run = d[i..].iter().take(128).take_while(|&&c| c == d[i]).count();
            if run >= 2 {
                out.push(u8::try_from(257 - run).unwrap());
                out.push(d[i]);
                i += run;
            } else {
                let n = (d.len() - i).min(128);
                out.push(u8::try_from(n - 1).unwrap());
                out.extend_from_slice(&d[i..i + n]);
                i += n;
            }
        }
        out.push(128);
        out
    }

    fn hex_encode(d: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, b) in d.iter().enumerate() {
            write!(out, "{b:02X}{}", if i % 32 == 31 { "\n" } else { "" }).unwrap();
        }
        out.push(b'>');
        out
    }

    /// PNG predictors, cycling through None, Sub, Up, Average and Paeth row by row.
    fn png_predict(d: &[u8], row: usize, bpp: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev = vec![0u8; row];
        for (n, line) in d.chunks(row).enumerate() {
            let kind = u8::try_from(n % 5).unwrap();
            out.push(kind);
            for (i, &x) in line.iter().enumerate() {
                let left = i.checked_sub(bpp).map_or(0, |k| line[k]);
                let up = prev[i];
                let corner = i.checked_sub(bpp).map_or(0, |k| prev[k]);
                let p = match kind {
                    0 => 0,
                    1 => left,
                    2 => up,
                    3 => low_byte(u32::midpoint(u32::from(left), u32::from(up))),
                    _ => paeth(left, up, corner),
                };
                out.push(x.wrapping_sub(p));
            }
            prev[..line.len()].copy_from_slice(line);
        }
        out
    }

    fn tiff_predict(d: &[u8], row: usize, bpp: usize) -> Vec<u8> {
        let mut out = d.to_vec();
        for line in out.chunks_mut(row) {
            for i in (bpp..line.len()).rev() {
                line[i] = line[i].wrapping_sub(line[i - bpp]);
            }
        }
        out
    }

    fn utf16(v: &str, big: bool) -> Vec<u8> {
        v.encode_utf16()
            .flat_map(|u| {
                if big {
                    u.to_be_bytes()
                } else {
                    u.to_le_bytes()
                }
            })
            .collect()
    }

    // -----------------------------------------------------------------------------------------
    // decode

    #[test]
    fn decode_accepts_both_alphabets_padding_and_whitespace() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let l = Limits::default();
        for e in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
            let s = e.encode(&data);
            assert_eq!(decode(&s, &l).unwrap(), data);
            let spaced: String = s
                .chars()
                .enumerate()
                .flat_map(|(i, c)| (i % 76 == 75).then_some('\n').into_iter().chain([c]))
                .collect();
            assert_eq!(decode(&format!("  {spaced}\r\n"), &l).unwrap(), data);
        }
        assert_eq!(decode("", &l).unwrap(), b"");
    }

    #[test]
    fn decode_reads_data_urls() {
        let l = Limits::default();
        let b64 = STANDARD.encode(b"hello there");
        for url in [
            format!("data:image/png;base64,{b64}"),
            format!("DATA:image/png;name=a.png;BASE64,{b64}"),
            format!("data:;base64,{}", URL_SAFE_NO_PAD.encode(b"hello there")),
        ] {
            assert_eq!(decode(&url, &l).unwrap(), b"hello there", "{url}");
        }
        assert_eq!(
            decode("data:text/plain,a%20b%zz%4", &l).unwrap(),
            b"a b%zz%4",
            "percent-encoded, a stray % stays literal"
        );
        assert_eq!(decode("data:text/plain", &l), Err(Undecodable::NotBase64));
    }

    #[test]
    fn decode_rejects_what_is_not_base64() {
        let l = Limits::default();
        for s in [
            "%%% not base64 %%%",
            "abcde",
            "ab=c",
            "a===",
            "ab===",
            "abc==",
        ] {
            assert_eq!(decode(s, &l), Err(Undecodable::NotBase64), "{s}");
        }
    }

    #[test]
    fn decode_checks_the_size_before_allocating() {
        let l = Limits {
            max_decoded: 5,
            ..Limits::default()
        };
        assert_eq!(
            decode("AAAAAAAA", &l),
            Err(Undecodable::TooLarge("decoded size"))
        );
        assert_eq!(decode("AAAAAA==", &l).unwrap(), [0; 4]);
        assert_eq!(
            decode("data:,abcdef", &l),
            Err(Undecodable::TooLarge("decoded size"))
        );
        assert_eq!(decode("data:,%61%62%63%64%65", &l).unwrap(), b"abcde");
    }

    // -----------------------------------------------------------------------------------------
    // views common to every part

    #[test]
    fn every_part_has_raw_and_utf16_views() {
        let v = generated_value();
        let mut b = b"RIFF\0\0\0\0WEBPVP8 ".to_vec();
        b.extend_from_slice(v.as_bytes());
        b.push(0x01);
        b.extend_from_slice(&utf16(&v, false));
        b.push(0x02);
        b.extend_from_slice(&utf16(&v, true));
        let mut sources = found(&b, &v);
        sources.sort_unstable();
        assert_eq!(sources, ["raw", "utf-16be", "utf-16le"]);
        // Opaque formats get nothing else.
        let all: Vec<_> = views_with(&b, &Limits::default()).unwrap();
        assert!(
            all.iter()
                .all(|(s, _)| ["raw", "utf-16le", "utf-16be"].contains(s))
        );
    }

    #[test]
    fn markup_gets_an_entity_decoded_view() {
        let v = generated_value();
        let escaped = v.replace('-', "&#45;").replacen('z', "&#x7A;", 1);
        let svg = format!(
            "\u{feff}  <svg xmlns=\"http://www.w3.org/2000/svg\"><text>a &amp; {escaped}</text></svg>"
        );
        let b = svg.as_bytes();
        hidden_from_raw(b, &v);
        assert_eq!(found(b, &v), ["xml entities"]);
        // Text that is not markup gets no such view.
        let plain = format!("note: {escaped}");
        assert_eq!(found(plain.as_bytes(), &v), [] as [&str; 0]);
    }

    // -----------------------------------------------------------------------------------------
    // PNG

    #[test]
    fn png_text_chunks_and_profiles_are_read() {
        let v = generated_value();
        let text = format!("key={}", padded(&v));
        let mut exif = b"MM\0*".to_vec();
        exif.extend_from_slice(&utf16(&v, false));
        let cases: [(Chunk, &str); 6] = [
            (
                (*b"tEXt", app(b"Comment", text.as_bytes())),
                "png text chunk",
            ),
            (ztxt(text.as_bytes()), "png compressed text"),
            (
                (*b"iTXt", [b"XML\0\0\0en\0\0", text.as_bytes()].concat()),
                "png international text",
            ),
            (
                (
                    *b"iTXt",
                    [b"XML\0\x01\0en\0t\0", &zlib(text.as_bytes())[..]].concat(),
                ),
                "png international text",
            ),
            (
                (*b"iCCP", [b"icc\0\0", &zlib(text.as_bytes())[..]].concat()),
                "png icc profile",
            ),
            ((*b"eXIf", exif), "utf-16le"),
        ];
        for (chunk, source) in cases {
            let p = png(&[chunk]);
            assert!(
                found(&p, &v).contains(&source),
                "{source}: {:?}",
                found(&p, &v)
            );
        }
        let p = png(&[ztxt(text.as_bytes())]);
        hidden_from_raw(&p, &v);
        // An archive appended after the image is read too.
        let polyglot = [png(&[]), gzip(text.as_bytes())].concat();
        assert_eq!(found(&polyglot, &v), ["gzip content"]);
    }

    #[test]
    fn png_fails_closed() {
        let p = png(&[ztxt(b"some text")]);
        assert_eq!(
            scan_err(&p[..p.len() - 20]),
            Undecodable::Corrupt("png chunk")
        );
        let bad_method = png(&[(*b"zTXt", [b"Comment\0\x01", &zlib(b"x")[..]].concat())]);
        assert_eq!(
            scan_err(&bad_method),
            Undecodable::Unsupported("png compression method")
        );
        let bad_zlib = png(&[(*b"zTXt", b"Comment\0\0not zlib at all".to_vec())]);
        assert_eq!(scan_err(&bad_zlib), Undecodable::Corrupt("compressed data"));
        assert_eq!(scan_err(PNG_SIG), Undecodable::Corrupt("png chunk"));
        let mut no_end = png(&[]);
        no_end.truncate(no_end.len() - 12);
        assert_eq!(scan_err(&no_end), Undecodable::Corrupt("png chunk"));
        let bad_flag = png(&[(*b"iTXt", b"XML\0\x02\0en\0\0text".to_vec())]);
        assert_eq!(scan_err(&bad_flag), Undecodable::Corrupt("png text chunk"));
    }

    // -----------------------------------------------------------------------------------------
    // JPEG

    #[test]
    fn jpeg_segments_are_read_and_joined() {
        let v = generated_value();
        let (a, b) = v.as_bytes().split_at(9);
        let guid = [b'A'; 32];
        let ext = |off: u32, chunk: &[u8]| {
            let mut d = guid.to_vec();
            d.extend_from_slice(&u32::try_from(v.len()).unwrap().to_be_bytes());
            d.extend_from_slice(&off.to_be_bytes());
            d.extend_from_slice(chunk);
            app(XMP_EXT, &d)
        };
        let off = u32::try_from(a.len()).unwrap();
        let j = jpeg(&[
            (0xE0, app(b"JFIF", &[1, 1, 0, 0, 1, 0, 1, 0, 0])),
            (0xFE, format!("made by {v}").into_bytes()),
            (
                0xE1,
                app(XMP_STD, format!("<x:xmpmeta>{v}</x:xmpmeta>").as_bytes()),
            ),
            // Extended XMP and ICC chunks out of order, the value split across them.
            (0xE1, ext(off, b)),
            (0xE1, ext(0, a)),
            (
                0xE2,
                app(b"ICC_PROFILE", &[[2u8, 2].as_slice(), b].concat()),
            ),
            (
                0xE2,
                app(b"ICC_PROFILE", &[[1u8, 2].as_slice(), a].concat()),
            ),
            (0xE1, app(b"Exif", &[b"\0MM\0*", a].concat())),
            (0xED, app(b"Photoshop 3.0", v.as_bytes())),
            (0xE1, app(b"Exif", b)),
        ]);
        let mut sources = found(&j, &v);
        sources.sort_unstable();
        sources.dedup();
        assert_eq!(
            sources,
            [
                "jpeg app segment",
                "jpeg comment",
                "jpeg exif",
                "jpeg extended xmp",
                "jpeg icc profile",
                "jpeg xmp",
                "raw",
            ]
        );
    }

    #[test]
    fn jpeg_fails_closed() {
        let past_end = [0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x40, b'a'];
        assert_eq!(scan_err(&past_end), Undecodable::Corrupt("jpeg marker"));
        let short = [0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x01, 0xFF, 0xD9];
        assert_eq!(scan_err(&short), Undecodable::Corrupt("jpeg marker"));
        let stuffed = [0xFF, 0xD8, 0xFF, 0x00, 0xFF, 0xD9];
        assert_eq!(scan_err(&stuffed), Undecodable::Corrupt("jpeg marker"));
        let no_ff = [0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x03, b'a', 0x12, 0x34];
        assert_eq!(scan_err(&no_ff), Undecodable::Corrupt("jpeg marker"));
        let short_icc = jpeg(&[(0xE2, app(b"ICC_PROFILE", &[1]))]);
        assert_eq!(
            scan_err(&short_icc),
            Undecodable::Corrupt("jpeg app segment")
        );
    }

    // -----------------------------------------------------------------------------------------
    // GIF

    #[test]
    fn gif_extensions_are_read_and_image_data_skipped() {
        let v = generated_value();
        let mut body = gif_image();
        body.extend_from_slice(&[0x21, 0xFE]);
        body.extend_from_slice(&sub(format!("comment {v}").as_bytes(), 5));
        body.extend_from_slice(&[0x21, 0x01]);
        body.extend_from_slice(&sub(&[[0u8; 12].as_slice(), v.as_bytes()].concat(), 7));
        body.extend_from_slice(&[0x21, 0xFF]);
        let mut app_data = vec![11];
        app_data.extend_from_slice(b"XMP DataXMP");
        app_data.extend_from_slice(&sub(v.as_bytes(), 6));
        body.extend_from_slice(&app_data);
        body.extend_from_slice(&[0x21, 0xF9]);
        body.extend_from_slice(&sub(&[0, 0, 0, 0], 4));
        let g = gif(&body);
        hidden_from_raw(&g, &v);
        let mut sources = found(&g, &v);
        sources.sort_unstable();
        assert_eq!(
            sources,
            ["gif application data", "gif comment", "gif plain text"]
        );
    }

    #[test]
    fn gif_fails_closed() {
        let mut body = vec![0x21, 0xFE];
        body.extend_from_slice(&sub(b"a comment", 4));
        let g = gif(&body);
        assert_eq!(
            scan_err(&g[..g.len() - 4]),
            Undecodable::Corrupt("gif block")
        );
        assert_eq!(scan_err(&gif(&[0x99])), Undecodable::Corrupt("gif block"));
        assert_eq!(
            scan_err(b"GIF89a\x01\x00"),
            Undecodable::Corrupt("gif block")
        );
    }

    // -----------------------------------------------------------------------------------------
    // containers

    #[test]
    fn gzip_is_inflated_and_scanned_again() {
        let v = generated_value();
        let g = gzip(format!("log line {}\n", padded(&v)).as_bytes());
        hidden_from_raw(&g, &v);
        assert_eq!(found(&g, &v), ["gzip content"]);
        let nested = gzip(&png(&[ztxt(v.as_bytes())]));
        assert_eq!(found(&nested, &v), ["png compressed text"]);
        let mut corrupt = gzip(b"some text to compress, some text to compress");
        let n = corrupt.len();
        corrupt.truncate(n - 12);
        assert_eq!(scan_err(&corrupt), Undecodable::Corrupt("compressed data"));
    }

    #[test]
    fn zip_entries_are_read() {
        let v = generated_value();
        let doc = format!("<w:document><w:t>{v}</w:t></w:document>");
        let z = zip(&[
            ("mimetype", 0, 0, b"application/vnd.oasis.opendocument.text"),
            ("word/document.xml", 0, 8, doc.as_bytes()),
            ("media/image1.png", 0, 0, &png(&[ztxt(v.as_bytes())])),
            ("notes.txt", 0, 0, format!("stored {v}").as_bytes()),
        ]);
        let mut sources = found(&z, &v);
        sources.sort_unstable();
        assert_eq!(sources, ["png compressed text", "raw", "zip entry"]);
    }

    #[test]
    fn zip_fails_closed() {
        let enc = zip(&[("a.txt", 1, 8, b"secret stuff")]);
        assert_eq!(scan_err(&enc), Undecodable::Encrypted);
        let aes = zip(&[("a.txt", 0, 99, b"secret stuff")]);
        assert_eq!(scan_err(&aes), Undecodable::Encrypted);
        let bzip2 = zip(&[("a.txt", 0, 12, b"secret stuff")]);
        assert_eq!(
            scan_err(&bzip2),
            Undecodable::Unsupported("zip compression method")
        );
        let good = zip(&[("a.txt", 0, 8, b"some text"), ("b.txt", 0, 0, b"more")]);
        let n = good.len();
        let mut zip64 = good.clone();
        zip64[n - 12..n - 10].copy_from_slice(&[0xFF, 0xFF]);
        assert_eq!(scan_err(&zip64), Undecodable::Unsupported("zip64"));
        let mut multi = good.clone();
        multi[n - 18] = 1;
        assert_eq!(scan_err(&multi), Undecodable::Unsupported("multi-disk zip"));
        assert_eq!(
            scan_err(&good[..n - 22]),
            Undecodable::Corrupt("zip directory")
        );
        let mut bad_local = good.clone();
        bad_local[0..4].copy_from_slice(b"PK\x07\x08");
        bad_local.splice(0..0, *b"PK\x03\x04");
        assert!(matches!(scan_err(&bad_local), Undecodable::Corrupt(_)));
        let few = Limits {
            max_objects: 1,
            ..Limits::default()
        };
        assert_eq!(
            scan_err_with(&good, &few),
            Undecodable::TooLarge("object count")
        );
    }

    #[test]
    fn other_compressed_archives_are_unsupported() {
        for magic in [
            &b"BZh91AY&SY"[..],
            &[0xFD, b'7', b'z', b'X', b'Z', 0x00, 0, 4],
            &[0x28, 0xB5, 0x2F, 0xFD, 0, 0],
            &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4],
            b"Rar!\x1A\x07\x01\x00",
        ] {
            assert_eq!(
                scan_err(magic),
                Undecodable::Unsupported("compressed archive"),
                "{magic:?}"
            );
        }
    }

    // -----------------------------------------------------------------------------------------
    // PDF

    #[test]
    fn pdf_text_is_extracted_through_every_filter() {
        let v = generated_value();
        let text = content(&v, 9);
        let predicted = png_predict(&text, 7, 1);
        let tiff = tiff_predict(&text, 15, 3);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("/Filter /FlateDecode", zlib(&text)),
            ("/Filter /Fl", zlib(&text)),
            ("/Filter /LZWDecode", lzw_encode(&text, true)),
            (
                "/Filter /LZW /DecodeParms << /EarlyChange 0 >>",
                lzw_encode(&text, false),
            ),
            ("/Filter /ASCIIHexDecode", hex_encode(&text)),
            ("/Filter /ASCII85Decode", ascii85_encode(&text)),
            ("/Filter /RunLengthDecode", run_length_encode(&text)),
            ("/Filter [/A85 /FlateDecode]", ascii85_encode(&zlib(&text))),
            (
                "/Filter [/AHx /LZW /RL]",
                hex_encode(&lzw_encode(&run_length_encode(&text), true)),
            ),
            (
                "/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >>",
                zlib(&predicted),
            ),
            (
                "/Filter [/FlateDecode] /DecodeParms [<< /Predictor 15 /Columns 7 >>]",
                zlib(&predicted),
            ),
            (
                "/Filter /LZWDecode /DecodeParms << /Predictor 2 /Colors 3 /Columns 5 >>",
                lzw_encode(&tiff, true),
            ),
            ("", text.clone()),
        ];
        for (dict, data) in cases {
            let p = pdf(&[(dict, Some(&data))], "");
            hidden_from_raw(&p, &v);
            assert_eq!(found(&p, &v), ["pdf text"], "{dict}");
        }
    }

    #[test]
    fn pdf_strings_outside_streams_are_extracted() {
        let v = generated_value();
        // An octal escape and a line continuation inside the literal.
        let literal = format!("\\172{}\\\n{}", &v[1..5], &v[5..]);
        let hex: String = std::iter::once("FEFF".to_string())
            .chain(v.encode_utf16().map(|u| format!("{u:04X}")))
            .collect();
        for (key, info) in [
            ("literal", format!("/Title ({literal})")),
            ("hex", format!("/Author <{hex}>")),
        ] {
            let p = pdf(&[("/Type /Catalog", None), (&info, None)], "/Info 2 0 R");
            hidden_from_raw(&p, &v);
            assert_eq!(found(&p, &v), ["pdf strings"], "{key} string");
        }
    }

    #[test]
    fn pdf_dct_images_have_their_metadata_read() {
        let v = generated_value();
        let j = jpeg(&[(0xFE, padded(&v).into_bytes())]);
        let dict = "/Type /XObject /Subtype /Image /Filter [/FlateDecode /DCTDecode]";
        let p = pdf(&[(dict, Some(&zlib(&j)))], "");
        hidden_from_raw(&p, &v);
        let mut sources = found(&p, &v);
        sources.sort_unstable();
        assert_eq!(sources, ["jpeg comment", "pdf image"]);
        let p = pdf(&[("/Subtype /Image /Filter /DCTDecode", Some(&j))], "");
        assert!(found(&p, &v).contains(&"jpeg comment"));
    }

    #[test]
    fn pdf_image_pixels_are_not_read() {
        // Documented limitation: text drawn into pixels is not decoded.
        let v = generated_value();
        let p = pdf(
            &[(
                "/Subtype /Image /Filter /FlateDecode",
                Some(&zlib(v.as_bytes())),
            )],
            "",
        );
        assert_eq!(found(&p, &v), [] as [&str; 0]);
    }

    #[test]
    fn pdf_stream_length_is_checked_against_endstream() {
        let v = generated_value();
        let data = zlib(&content(&v, 4));
        let good = pdf(&[("/Filter /FlateDecode", Some(&data))], "");
        let wrong = format!("/Length {}", data.len());
        for len in ["/Length 3", "/Length 999999", "/Length 7 0 R"] {
            let s = String::from_utf8_lossy(&good).replace(&wrong, len);
            // Only ASCII was replaced; the stream bytes are copied from the original.
            let at = memmem::find(&good, wrong.as_bytes()).unwrap();
            let p = [&good[..at], len.as_bytes(), &good[at + wrong.len()..]].concat();
            assert!(s.contains(len));
            assert_eq!(found(&p, &v), ["pdf text"], "{len}");
        }
    }

    #[test]
    fn pdf_fails_closed() {
        let z = zlib(b"BT (hello) Tj ET");
        let cases: Vec<(Vec<u8>, Undecodable)> = vec![
            (
                pdf(&[("/Type /Catalog", None)], "/Encrypt 5 0 R"),
                Undecodable::Encrypted,
            ),
            (
                pdf(&[("/Type /XRef /Encrypt 5 0 R", Some(b"\0\0"))], ""),
                Undecodable::Encrypted,
            ),
            (
                pdf(&[("/Filter /Crypt", Some(b"xx"))], ""),
                Undecodable::Encrypted,
            ),
            (
                pdf(&[("/Filter [/FlateDecode /Crypt]", Some(&z))], ""),
                Undecodable::Encrypted,
            ),
            (
                pdf(&[("/Filter /BrotliDecode", Some(b"xx"))], ""),
                Undecodable::Unsupported("pdf filter"),
            ),
            (
                pdf(&[("/Filter 7 0 R", Some(&z))], ""),
                Undecodable::Unsupported("indirect pdf filter"),
            ),
            (
                pdf(&[("/Filter [7 0 R]", Some(&z))], ""),
                Undecodable::Unsupported("indirect pdf filter"),
            ),
            (
                pdf(&[("/Filter /FlateDecode /DecodeParms 7 0 R", Some(&z))], ""),
                Undecodable::Unsupported("indirect pdf decode parameters"),
            ),
            (
                pdf(
                    &[("/Filter /Fl /DecodeParms << /Predictor 9 0 R >>", Some(&z))],
                    "",
                ),
                Undecodable::Unsupported("indirect pdf decode parameters"),
            ),
            (
                pdf(
                    &[(
                        "/Filter [/AHx /Fl] /DecodeParms << /Predictor 12 >>",
                        Some(&z),
                    )],
                    "",
                ),
                Undecodable::Unsupported("pdf decode parameters"),
            ),
            (
                pdf(
                    &[("/Filter /Fl /DecodeParms << /Predictor 3 >>", Some(&z))],
                    "",
                ),
                Undecodable::Unsupported("pdf predictor"),
            ),
            (
                pdf(&[("/Filter /Fl", Some(b"not zlib"))], ""),
                Undecodable::Corrupt("compressed data"),
            ),
            (
                b"%PDF-1.7\n1 0 obj\n<< /Length 4 >>\nstream\nabcd\nendobj\n".to_vec(),
                Undecodable::Corrupt("pdf stream end"),
            ),
            (
                b"%PDF-1.7\n1 0 obj\n(text)\nstream\nabcd\nendstream\n".to_vec(),
                Undecodable::Corrupt("pdf stream dictionary"),
            ),
            (
                b"%PDF-1.7\ntrailer\n<< /Root".to_vec(),
                Undecodable::Corrupt("pdf trailer"),
            ),
        ];
        for (p, want) in cases {
            assert_eq!(scan_err(&p), want, "{}", String::from_utf8_lossy(&p));
        }
    }

    // -----------------------------------------------------------------------------------------
    // LZW

    /// The input Ghostscript encoded for the golden vectors: 2200 bytes of a 16-letter alphabet
    /// from xorshift64, enough codes to widen from 9 to 11 bits.
    fn golden_input() -> Vec<u8> {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        (0..2200)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                b'a' + u8::try_from(x % 16).unwrap()
            })
            .collect()
    }

    /// Written by Ghostscript's `LZWEncode` filter (`<< /EarlyChange 0|1 >>`), an encoder
    /// independent of this module. The two vectors first differ where the code width changes.
    const GOLDEN_EARLY_0: &[u8] = include_bytes!("../testdata/lzw/early0.lzw");
    const GOLDEN_EARLY_1: &[u8] = include_bytes!("../testdata/lzw/early1.lzw");

    fn no_clock() -> Clock {
        Clock { deadline: None }
    }

    #[test]
    fn lzw_decodes_ghostscript_output_with_either_early_change() {
        let input = golden_input();
        assert_ne!(GOLDEN_EARLY_0, GOLDEN_EARLY_1);
        for (data, early) in [(GOLDEN_EARLY_0, false), (GOLDEN_EARLY_1, true)] {
            let out = lzw(data, early, usize::MAX, no_clock()).unwrap();
            assert!(out == input, "EarlyChange {}", u8::from(early));
            // The wrong setting misreads the codes after the first width change.
            let wrong = lzw(data, !early, usize::MAX, no_clock());
            assert!(wrong.map_or(true, |w| w != input));
            // The test encoder agrees with Ghostscript's.
            assert!(lzw_decode_roundtrip(&input, early));
        }
    }

    fn lzw_decode_roundtrip(input: &[u8], early: bool) -> bool {
        lzw(&lzw_encode(input, early), early, usize::MAX, no_clock()).as_deref() == Ok(input)
    }

    #[test]
    fn lzw_matches_the_pdf_reference_example() {
        // PDF 1.7 reference, 7.4.4.2: "-----A---B" with EarlyChange 1.
        let codes = [0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01];
        assert_eq!(
            lzw(&codes, true, usize::MAX, no_clock()).unwrap(),
            b"-----A---B"
        );
        assert_eq!(lzw_encode(b"-----A---B", true)[..9], codes);
    }

    #[test]
    fn lzw_handles_clear_codes_and_full_width() {
        // Enough distinct strings to clear the table at 12 bits more than once.
        let mut x = 1u32;
        let data: Vec<u8> = (0..60_000)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                low_byte(x >> 16)
            })
            .collect();
        for early in [true, false] {
            assert!(lzw_decode_roundtrip(&data, early));
        }
    }

    #[test]
    fn lzw_rejects_codes_past_the_table() {
        // Clear, then 300 as the first code: not a single byte.
        let mut bits = 0x100u32 << 9 | 0x12C;
        bits <<= 32 - 18;
        assert_eq!(
            lzw(&bits.to_be_bytes(), true, usize::MAX, no_clock()),
            Err(Undecodable::Corrupt("pdf lzw data"))
        );
        // 'a', then 400 while the table ends at 258.
        let mut bits = u32::from(b'a') << 9 | 0x190;
        bits <<= 32 - 18;
        assert_eq!(
            lzw(&bits.to_be_bytes(), true, usize::MAX, no_clock()),
            Err(Undecodable::Corrupt("pdf lzw data"))
        );
    }

    // -----------------------------------------------------------------------------------------
    // bounds

    #[test]
    fn nesting_is_bounded() {
        let v = generated_value();
        let p = pdf(
            &[("/Filter /FlateDecode", Some(&zlib(&content(&v, 3))))],
            "",
        );
        let nested = gzip(&zip(&[("doc.pdf", 0, 8, &p)]));
        assert_eq!(found(&nested, &v), ["pdf text"]);
        let shallow = Limits {
            max_depth: 2,
            ..Limits::default()
        };
        assert_eq!(
            scan_err_with(&nested, &shallow),
            Undecodable::TooLarge("nesting depth")
        );
        let mut deep = b"text".to_vec();
        for _ in 0..5 {
            deep = gzip(&deep);
        }
        assert_eq!(scan_err(&deep), Undecodable::TooLarge("nesting depth"));
    }

    #[test]
    fn decompression_is_bounded() {
        let small = Limits {
            max_inflated: 1 << 20,
            ..Limits::default()
        };
        let zeros = vec![0u8; 8 << 20];
        let bombs = [
            png(&[ztxt(&zeros)]),
            gzip(&zeros),
            zip(&[("a", 0, 8, &zeros)]),
            pdf(&[("/Filter /FlateDecode", Some(&zlib(&zeros)))], ""),
            pdf(
                &[(
                    "/Filter /LZWDecode",
                    Some(&lzw_encode(&zeros[..2 << 20], true)),
                )],
                "",
            ),
            pdf(
                &[(
                    "/Filter /RunLengthDecode",
                    Some(&run_length_encode(&zeros[..2 << 20])),
                )],
                "",
            ),
            pdf(
                &[("/Filter /A85", Some(&ascii85_encode(&zeros[..2 << 20])))],
                "",
            ),
        ];
        for b in bombs {
            assert_eq!(
                scan_err_with(&b, &small),
                Undecodable::TooLarge("decompressed size"),
                "{:?}",
                &b[..8]
            );
        }
        // Filters in a chain count together.
        let half = vec![b'x'; 600 << 10];
        let chain = pdf(
            &[("/Filter [/AHx /Fl]", Some(&hex_encode(&zlib(&half))))],
            "",
        );
        assert!(views_with(&chain, &small).is_ok());
        let two = pdf(
            &[
                ("/Filter /Fl", Some(&zlib(&half))),
                ("/Filter /Fl", Some(&zlib(&half))),
            ],
            "",
        );
        assert_eq!(
            scan_err_with(&two, &small),
            Undecodable::TooLarge("decompressed size")
        );
    }

    #[test]
    fn object_count_and_view_bytes_are_bounded() {
        let chunks: Vec<_> = (0..20)
            .map(|i| (*b"tEXt", format!("k\0{i}").into_bytes()))
            .collect();
        let p = png(&chunks);
        let few = Limits {
            max_objects: 10,
            ..Limits::default()
        };
        assert_eq!(
            scan_err_with(&p, &few),
            Undecodable::TooLarge("object count")
        );
        let tight = Limits {
            max_view_bytes: p.len() - 1,
            ..Limits::default()
        };
        assert_eq!(
            scan_err_with(&p, &tight),
            Undecodable::TooLarge("extracted text")
        );
        let raw_only = Limits {
            max_view_bytes: p.len(),
            ..Limits::default()
        };
        assert_eq!(
            scan_err_with(&p, &raw_only),
            Undecodable::TooLarge("extracted text")
        );
    }

    #[test]
    fn a_zero_budget_is_over_budget() {
        let none = Limits {
            budget: Duration::ZERO,
            budget_per_mib: Duration::ZERO,
            ..Limits::default()
        };
        for b in fixtures() {
            assert_eq!(scan_err_with(&b, &none), Undecodable::OverBudget);
        }
        assert_eq!(scan_err_with(b"plain", &none), Undecodable::OverBudget);
        // The budget grows with the decoded size.
        let per_mib = Limits {
            budget: Duration::ZERO,
            budget_per_mib: Duration::from_secs(3600),
            ..Limits::default()
        };
        assert_eq!(
            scan_err_with(&vec![b'x'; (1 << 20) - 1], &per_mib),
            Undecodable::OverBudget
        );
        assert!(views_with(&vec![b'x'; 1 << 20], &per_mib).is_ok());
    }

    #[test]
    fn the_visitor_can_stop_the_scan() {
        let v = generated_value();
        let p = png(&[ztxt(v.as_bytes()), ztxt(v.as_bytes())]);
        let mut seen = Vec::new();
        scan_views(&p, &Limits::default(), &mut |view| {
            seen.push(view.source);
            view.source != "png compressed text"
        })
        .unwrap();
        assert_eq!(seen.last(), Some(&"png compressed text"));
        assert_eq!(
            seen.iter().filter(|s| **s == "png compressed text").count(),
            1
        );
    }

    // -----------------------------------------------------------------------------------------
    // properties

    /// One fixture of each format, for the zero-budget and mutation tests.
    fn fixtures() -> Vec<Vec<u8>> {
        let v = "zq-test-value-fixture";
        let text = content(v, 5);
        vec![
            png(&[ztxt(v.as_bytes()), (*b"tEXt", app(b"a", v.as_bytes()))]),
            jpeg(&[(0xFE, v.into()), (0xE1, app(XMP_STD, v.as_bytes()))]),
            gif(&[&gif_image()[..], &[0x21, 0xFE], &sub(v.as_bytes(), 4)].concat()),
            gzip(format!("<a>{v}&amp;</a>").as_bytes()),
            zip(&[("a.xml", 0, 8, text.as_slice()), ("b", 0, 0, b"stored")]),
            pdf(
                &[
                    ("/Filter /FlateDecode", Some(&zlib(&text))),
                    (
                        "/Filter [/AHx /LZW]",
                        Some(&hex_encode(&lzw_encode(&text, true))),
                    ),
                    (
                        "/Filter /Fl /DecodeParms << /Predictor 12 /Columns 4 >>",
                        Some(&zlib(&png_predict(&text, 4, 1))),
                    ),
                    ("/Title (a title)", None),
                ],
                "/Info 4 0 R",
            ),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn decode_round_trips(
            data in prop::collection::vec(any::<u8>(), 0..300),
            alphabet in 0usize..4,
            wrap in any::<bool>(),
            gap in 1usize..80,
        ) {
            let e = [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD][alphabet];
            let s: String = e
                .encode(&data)
                .chars()
                .enumerate()
                .flat_map(|(i, c)| (i % gap == gap - 1).then_some(' ').into_iter().chain([c]))
                .collect();
            let s = if wrap { format!("data:application/octet-stream;base64,{s}") } else { s };
            prop_assert_eq!(decode(&s, &Limits::default()).unwrap(), data);
        }

        #[test]
        fn decode_never_panics(s in "\\PC{0,200}") {
            let _ = decode(&s, &Limits::default());
            let _ = decode(&format!("data:{s}"), &Limits::default());
        }

        #[test]
        fn random_bytes_never_panic(
            magic in 0usize..8,
            tail in prop::collection::vec(any::<u8>(), 0..2048),
        ) {
            let prefix: &[u8] = [
                PNG_SIG, b"\xFF\xD8\xFF", b"GIF89a", b"\x1F\x8B\x08", b"PK\x03\x04", b"%PDF-1.7\n",
                b"<svg>", b"",
            ][magic];
            let b = [prefix, &tail].concat();
            let _ = views_with(&b, &Limits::default());
        }

        #[test]
        fn mutated_fixtures_never_panic(
            which in 0usize..6,
            edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
            cut in any::<Option<prop::sample::Index>>(),
        ) {
            let mut b = fixtures().swap_remove(which);
            for (at, byte) in edits {
                let i = at.index(b.len());
                b[i] = byte;
            }
            if let Some(cut) = cut {
                b.truncate(cut.index(b.len()));
            }
            let _ = views_with(&b, &Limits::default());
        }

        #[test]
        fn lzw_round_trips(data in prop::collection::vec(any::<u8>(), 0..4000), early in any::<bool>()) {
            prop_assert!(lzw_decode_roundtrip(&data, early));
        }

        #[test]
        fn a_value_split_by_kerning_is_found(split in 1usize..30, kern in -500i32..500) {
            let v = generated_value();
            let (a, b) = v.split_at(split);
            let text = format!("BT [({a}) {kern} ({b})] TJ ET");
            let p = pdf(&[("/Filter /FlateDecode", Some(&zlib(text.as_bytes())))], "");
            prop_assert_eq!(found(&p, &v), vec!["pdf text"]);
        }
    }
}
