// SPDX-License-Identifier: AGPL-3.0-only

//! Server-sent events framing that keeps the original bytes.
//!
//! [`Framer`] splits a byte stream into complete events (each including its terminating blank
//! line) without copying more than one incomplete event. Events are handed out as raw bytes so a
//! codec can pass an untouched event through byte for byte and only rebuild the ones it changes.

use std::borrow::Cow;

/// Output of the framer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Piece<'a> {
    /// A complete event, including the blank line that ends it.
    Event(&'a [u8]),
    /// Bytes passed through without framing, because an event outgrew the buffer limit.
    Raw(&'a [u8]),
}

/// Incremental SSE framer with a bound on buffered bytes.
#[derive(Debug)]
pub(crate) struct Framer {
    buf: Vec<u8>,
    max_event: usize,
    /// Inside an oversized event: pass bytes through until its end.
    overflow: bool,
    /// Last byte seen while in overflow, to find a blank line across chunks.
    overflow_tail: [u8; 3],
    /// Scan progress over `buf`.
    scan: Scan,
}

/// Scan state for finding the end of an event.
#[derive(Debug, Default, Clone, Copy)]
struct Scan {
    /// Where to resume scanning.
    pos: usize,
    /// Start of the current line.
    line_start: usize,
}

/// Finds the end (exclusive) of the first complete event in `b`, resuming from `st`. An event
/// ends at a blank line; line terminators are `\n`, `\r\n` or `\r`. On `None`, `st` is updated
/// so the next call does not rescan.
fn event_end(b: &[u8], st: &mut Scan) -> Option<usize> {
    let mut i = st.pos;
    while let Some(j) = memchr::memchr2(b'\n', b'\r', &b[i..]) {
        let t = i + j;
        let next = if b[t] == b'\r' {
            match b.get(t + 1) {
                Some(b'\n') => t + 2,
                // A lone CR at the very end could be the first half of CRLF; wait for more.
                None => {
                    st.pos = t;
                    return None;
                }
                _ => t + 1,
            }
        } else {
            t + 1
        };
        if t == st.line_start {
            *st = Scan::default();
            return Some(next);
        }
        st.line_start = next;
        i = next;
    }
    st.pos = b.len();
    None
}

impl Framer {
    pub(crate) fn new(max_event: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_event,
            overflow: false,
            overflow_tail: [0; 3],
            scan: Scan::default(),
        }
    }

    /// Bytes currently buffered.
    pub(crate) fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Feeds `chunk` and calls `f` for every piece that is ready, in order.
    pub(crate) fn push(&mut self, chunk: &[u8], f: &mut dyn FnMut(Piece<'_>)) {
        let mut chunk = chunk;
        if self.overflow {
            if let Some(n) = self.overflow_end(chunk) {
                f(Piece::Raw(&chunk[..n]));
                self.overflow = false;
                chunk = &chunk[n..];
            } else {
                f(Piece::Raw(chunk));
                return;
            }
        }
        if self.buf.is_empty() {
            // Fast path: frame straight from the chunk.
            let mut off = 0;
            loop {
                let mut st = Scan::default();
                if let Some(n) = event_end(&chunk[off..], &mut st) {
                    f(Piece::Event(&chunk[off..off + n]));
                    off += n;
                } else {
                    self.scan = st;
                    break;
                }
            }
            self.stash(&chunk[off..], f);
            return;
        }
        self.buf.extend_from_slice(chunk);
        let mut st = self.scan;
        let Some(n) = event_end(&self.buf, &mut st) else {
            self.scan = st;
            let buf = std::mem::take(&mut self.buf);
            self.stash_keep_scan(buf, f);
            return;
        };
        let buf = std::mem::take(&mut self.buf);
        f(Piece::Event(&buf[..n]));
        let mut off = n;
        loop {
            let mut st = Scan::default();
            if let Some(n) = event_end(&buf[off..], &mut st) {
                f(Piece::Event(&buf[off..off + n]));
                off += n;
            } else {
                self.scan = st;
                break;
            }
        }
        self.stash(&buf[off..], f);
    }

    /// Like `stash` for a buffer that is already the whole pending event.
    fn stash_keep_scan(&mut self, buf: Vec<u8>, f: &mut dyn FnMut(Piece<'_>)) {
        if buf.len() > self.max_event {
            self.stash(&buf, f);
        } else {
            self.buf = buf;
        }
    }

    fn stash(&mut self, rest: &[u8], f: &mut dyn FnMut(Piece<'_>)) {
        if rest.len() > self.max_event {
            // Too large to hold: release it raw and pass the remainder of this event raw too.
            f(Piece::Raw(rest));
            self.overflow = true;
            let mut tail = [0u8; 3];
            let k = rest.len().min(3);
            tail[3 - k..].copy_from_slice(&rest[rest.len() - k..]);
            self.overflow_tail = tail;
            self.buf.clear();
            self.scan = Scan::default();
        } else {
            self.buf.clear();
            self.buf.extend_from_slice(rest);
        }
    }

    /// In overflow mode, the length of the prefix of `chunk` that completes the oversized event.
    fn overflow_end(&mut self, chunk: &[u8]) -> Option<usize> {
        let mut joined = Vec::with_capacity(3 + chunk.len());
        joined.extend_from_slice(&self.overflow_tail);
        joined.extend_from_slice(chunk);
        // Look for a blank line: "\n\n", "\r\n\r\n", "\r\r", "\n\r\n".
        for i in 0..joined.len() {
            for pat in [&b"\n\n"[..], b"\r\n\r\n", b"\n\r\n", b"\r\r"] {
                if joined[i..].starts_with(pat) {
                    let end = i + pat.len();
                    if end > 3 {
                        return Some(end - 3);
                    }
                }
            }
        }
        let k = joined.len().min(3);
        let mut tail = [0u8; 3];
        tail[3 - k..].copy_from_slice(&joined[joined.len() - k..]);
        self.overflow_tail = tail;
        None
    }

    /// Takes whatever is buffered at end of stream (an unterminated last event).
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        self.overflow = false;
        self.scan = Scan::default();
        std::mem::take(&mut self.buf)
    }
}

/// A parsed view of one raw event.
#[derive(Debug)]
pub(crate) struct Event<'a> {
    /// The `event:` field, if any.
    #[allow(
        dead_code,
        reason = "parsed for completeness and tests; codecs key on the data type"
    )]
    pub name: Option<&'a str>,
    /// The `data:` fields joined with `\n`.
    pub data: Cow<'a, str>,
    /// Whether the event has at least one `data:` field.
    pub has_data: bool,
}

fn lines(raw: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    // Yields (line content, terminator).
    let mut rest = raw;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let (content, term, next) = match memchr::memchr2(b'\n', b'\r', rest) {
            None => (rest, &rest[rest.len()..], &rest[rest.len()..]),
            Some(t) => {
                let tl = if rest[t] == b'\r' && rest.get(t + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                (&rest[..t], &rest[t..t + tl], &rest[t + tl..])
            }
        };
        rest = next;
        Some((content, term))
    })
}

fn field(line: &[u8]) -> (&[u8], &[u8]) {
    match memchr::memchr(b':', line) {
        None => (line, &[]),
        Some(c) => {
            let mut v = &line[c + 1..];
            if v.first() == Some(&b' ') {
                v = &v[1..];
            }
            (&line[..c], v)
        }
    }
}

impl<'a> Event<'a> {
    /// Parses a raw event. Returns `None` when it is not valid UTF-8.
    pub(crate) fn parse(raw: &'a [u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut name = None;
        let mut data: Option<Cow<'a, str>> = None;
        for (line, _) in lines(text.as_bytes()) {
            if line.is_empty() || line[0] == b':' {
                continue;
            }
            let (k, v) = field(line);
            // Fields are ASCII and the source is valid UTF-8, so these slices are valid.
            let v = std::str::from_utf8(v).ok()?;
            match k {
                b"event" => name = Some(v),
                b"data" => {
                    data = Some(match data {
                        None => Cow::Borrowed(v),
                        Some(d) => Cow::Owned(format!("{d}\n{v}")),
                    });
                }
                _ => {}
            }
        }
        Some(Self {
            name,
            has_data: data.is_some(),
            data: data.unwrap_or(Cow::Borrowed("")),
        })
    }
}

/// Rebuilds `raw` with its data replaced by `data` (a single line), keeping every other line and
/// the terminators.
pub(crate) fn with_data(raw: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + data.len());
    let mut wrote = false;
    for (line, term) in lines(raw) {
        if line.is_empty() {
            out.extend_from_slice(term);
            continue;
        }
        let (k, _) = field(line);
        if k == b"data" && line[0] != b':' {
            if !wrote {
                out.extend_from_slice(b"data: ");
                out.extend_from_slice(data);
                out.extend_from_slice(term);
                wrote = true;
            }
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(term);
    }
    out
}

/// Builds a new event from a name and one data line.
pub(crate) fn build(name: Option<&str>, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 32);
    if let Some(n) = name {
        out.extend_from_slice(b"event: ");
        out.extend_from_slice(n.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(b"data: ");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\n\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_all(chunks: &[&[u8]], max: usize) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut f = Framer::new(max);
        let mut events = Vec::new();
        let mut raw = Vec::new();
        for c in chunks {
            f.push(c, &mut |p| match p {
                Piece::Event(e) => events.push(e.to_vec()),
                Piece::Raw(r) => raw.extend_from_slice(r),
            });
        }
        let rest = f.finish();
        raw.extend_from_slice(&rest);
        (events, raw)
    }

    #[test]
    fn frames_lf_crlf_cr() {
        let s = b"event: a\ndata: 1\n\nevent: b\r\ndata: 2\r\n\r\ndata: 3\r\r: comment\n\n";
        let (ev, raw) = frame_all(&[s], 1 << 20);
        assert_eq!(ev.len(), 4);
        assert_eq!(ev[0], b"event: a\ndata: 1\n\n");
        assert_eq!(ev[1], b"event: b\r\ndata: 2\r\n\r\n");
        assert_eq!(ev[2], b"data: 3\r\r");
        assert_eq!(raw, [] as [u8; 0]);
        assert_eq!(ev.concat(), s);
    }

    #[test]
    fn every_split_yields_same_events() {
        let s: &[u8] = b"event: a\r\ndata: {\"x\":1}\r\n\r\nevent: b\ndata: 2\n\n";
        let whole = frame_all(&[s], 1 << 20).0;
        for i in 0..s.len() {
            for j in i..s.len() {
                let (ev, raw) = frame_all(&[&s[..i], &s[i..j], &s[j..]], 1 << 20);
                assert_eq!(ev, whole, "split {i} {j}");
                assert_eq!(raw, [] as [u8; 0]);
            }
        }
    }

    #[test]
    fn oversized_event_passes_raw_and_framing_resumes() {
        let big = format!("data: {}\n\n", "x".repeat(100));
        let s = format!("data: a\n\n{big}data: b\n\n");
        let bytes = s.as_bytes();
        let mut out_events = Vec::new();
        let mut out_all = Vec::new();
        let mut f = Framer::new(16);
        for c in bytes.chunks(7) {
            f.push(c, &mut |p| match p {
                Piece::Event(e) => {
                    out_events.push(e.to_vec());
                    out_all.extend_from_slice(e);
                }
                Piece::Raw(r) => out_all.extend_from_slice(r),
            });
            assert!(f.buffered() <= 16 + 7);
        }
        out_all.extend_from_slice(&f.finish());
        assert_eq!(out_all, bytes);
        assert_eq!(out_events.first().unwrap(), b"data: a\n\n");
        assert_eq!(out_events.last().unwrap(), b"data: b\n\n");
    }

    #[test]
    fn parse_and_rewrite() {
        let raw = b"event: x\nid: 7\ndata: {\"a\":\ndata: 1}\n\n";
        let e = Event::parse(raw).unwrap();
        assert_eq!(e.name, Some("x"));
        assert_eq!(e.data, "{\"a\":\n1}");
        let r = with_data(raw, b"{\"a\":2}");
        assert_eq!(r, b"event: x\nid: 7\ndata: {\"a\":2}\n\n");
        assert_eq!(build(Some("y"), b"{}"), b"event: y\ndata: {}\n\n");
        assert_eq!(build(None, b"{}"), b"data: {}\n\n");
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn output_is_lossless(events in prop::collection::vec("[a-z:{} \"]{0,30}", 0..10), cuts in prop::collection::vec(1usize..20, 0..20), crlf in any::<bool>(), max in 4usize..64) {
                let nl = if crlf { "\r\n" } else { "\n" };
                let s: String = events.iter().fold(String::new(), |mut acc, e| {
                    acc.push_str("data: ");
                    acc.push_str(e);
                    acc.push_str(nl);
                    acc.push_str(nl);
                    acc
                });
                let b = s.as_bytes();
                let mut f = Framer::new(max);
                let mut out = Vec::new();
                let mut pos = 0;
                for c in cuts {
                    let end = (pos + c).min(b.len());
                    f.push(&b[pos..end], &mut |p| match p { Piece::Event(e) | Piece::Raw(e) => out.extend_from_slice(e) });
                    pos = end;
                }
                f.push(&b[pos..], &mut |p| match p { Piece::Event(e) | Piece::Raw(e) => out.extend_from_slice(e) });
                out.extend_from_slice(&f.finish());
                prop_assert_eq!(out, b.to_vec());
            }
        }
    }
}
