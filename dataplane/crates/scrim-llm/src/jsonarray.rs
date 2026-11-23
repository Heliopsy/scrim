// SPDX-License-Identifier: AGPL-3.0-only

//! Framing for a JSON array streamed element by element (Gemini `streamGenerateContent` without
//! `alt=sse`: `[{...}\r\n,{...}\r\n]`), keeping the original bytes.
//!
//! [`ArrayFramer`] hands out each complete top-level element as raw bytes, everything between
//! elements (the brackets, commas and whitespace) as raw pass-through, and the closing bracket
//! on its own so a codec can release held text just before it. It buffers at most one
//! incomplete element; an element larger than the limit is passed through raw, unresolved, as
//! the SSE framer does with an oversized event.

/// Output of the framer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Piece<'a> {
    /// A complete top-level element.
    Element(&'a [u8]),
    /// Bytes outside elements, or inside an element too large to hold.
    Raw(&'a [u8]),
    /// The `]` that closes the top-level array.
    Close(&'a [u8]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Where {
    /// Before the opening `[`.
    Before,
    /// Inside the array, between elements.
    Between,
    /// Inside an element.
    Element,
    /// After the closing `]`: everything passes through.
    After,
}

/// Lexical state inside an element.
#[derive(Debug, Default, Clone, Copy)]
struct Lex {
    depth: u32,
    in_str: bool,
    esc: bool,
    /// The element is a bare scalar (number, literal), which ends at a delimiter.
    scalar: bool,
}

/// Incremental framer with a bound on buffered bytes.
#[derive(Debug)]
pub(crate) struct ArrayFramer {
    buf: Vec<u8>,
    max: usize,
    at: Where,
    lex: Lex,
    /// Inside an oversized element: its bytes pass through raw until it ends.
    overflow: bool,
}

impl ArrayFramer {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            max,
            at: Where::Before,
            lex: Lex::default(),
            overflow: false,
        }
    }

    /// Bytes currently buffered.
    pub(crate) fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Feeds `chunk` and calls `f` for every piece that is ready, in order.
    pub(crate) fn push(&mut self, chunk: &[u8], f: &mut dyn FnMut(Piece<'_>)) {
        // Start of the run of bytes not yet handed out.
        let mut start = 0;
        let mut i = 0;
        while i < chunk.len() {
            let b = chunk[i];
            match self.at {
                Where::After => {
                    i = chunk.len();
                }
                Where::Before => {
                    match b {
                        b' ' | b'\t' | b'\r' | b'\n' => {}
                        b'[' => self.at = Where::Between,
                        // Not an array: nothing to frame.
                        _ => self.at = Where::After,
                    }
                    i += 1;
                }
                Where::Between => match b {
                    b' ' | b'\t' | b'\r' | b'\n' | b',' => i += 1,
                    b']' => {
                        if i > start {
                            f(Piece::Raw(&chunk[start..i]));
                        }
                        f(Piece::Close(&chunk[i..=i]));
                        self.at = Where::After;
                        i += 1;
                        start = i;
                    }
                    _ => {
                        if i > start {
                            f(Piece::Raw(&chunk[start..i]));
                        }
                        start = i;
                        self.at = Where::Element;
                        self.lex = Lex {
                            scalar: !matches!(b, b'{' | b'[' | b'"'),
                            ..Lex::default()
                        };
                        // Scalars are scanned from their first byte; containers and strings
                        // from the opening byte, which the lexer below consumes.
                    }
                },
                Where::Element => {
                    let end = self.scan(&chunk[i..]);
                    match end {
                        Some(n) => {
                            let stop = i + n;
                            self.element_done(&chunk[start..stop], f);
                            self.at = Where::Between;
                            i = stop;
                            start = stop;
                        }
                        None => {
                            i = chunk.len();
                        }
                    }
                }
            }
        }
        if start < chunk.len() {
            let rest = &chunk[start..];
            if self.at == Where::Element {
                self.hold(rest, f);
            } else {
                f(Piece::Raw(rest));
            }
        }
    }

    /// Scans element bytes; `Some(n)` when the element ends after `n` bytes of `s` (a scalar
    /// ends before its delimiter).
    fn scan(&mut self, s: &[u8]) -> Option<usize> {
        let lx = &mut self.lex;
        for (k, &b) in s.iter().enumerate() {
            if lx.scalar {
                if matches!(b, b',' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                    return Some(k);
                }
                continue;
            }
            if lx.in_str {
                if lx.esc {
                    lx.esc = false;
                } else if b == b'\\' {
                    lx.esc = true;
                } else if b == b'"' {
                    lx.in_str = false;
                    if lx.depth == 0 {
                        return Some(k + 1);
                    }
                }
                continue;
            }
            match b {
                b'"' => lx.in_str = true,
                b'{' | b'[' => lx.depth += 1,
                b'}' | b']' => {
                    lx.depth = lx.depth.saturating_sub(1);
                    if lx.depth == 0 {
                        return Some(k + 1);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// An element ended; `tail` is its part in the current chunk.
    fn element_done(&mut self, tail: &[u8], f: &mut dyn FnMut(Piece<'_>)) {
        if self.overflow {
            self.overflow = false;
            f(Piece::Raw(tail));
        } else if self.buf.is_empty() {
            f(Piece::Element(tail));
        } else {
            let mut buf = std::mem::take(&mut self.buf);
            buf.extend_from_slice(tail);
            f(Piece::Element(&buf));
        }
    }

    /// Keeps the incomplete element's bytes, or releases them raw once it outgrows the limit.
    fn hold(&mut self, rest: &[u8], f: &mut dyn FnMut(Piece<'_>)) {
        if self.overflow {
            f(Piece::Raw(rest));
            return;
        }
        if self.buf.len() + rest.len() > self.max {
            let buf = std::mem::take(&mut self.buf);
            if !buf.is_empty() {
                f(Piece::Raw(&buf));
            }
            f(Piece::Raw(rest));
            self.overflow = true;
        } else {
            self.buf.extend_from_slice(rest);
        }
    }

    /// Takes whatever is buffered at end of stream (an unterminated element).
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        self.overflow = false;
        std::mem::take(&mut self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum P {
        E(String),
        R(String),
        C,
    }

    fn frame(chunks: &[&[u8]], max: usize) -> (Vec<P>, Vec<u8>) {
        let mut f = ArrayFramer::new(max);
        let mut out = Vec::new();
        for c in chunks {
            f.push(c, &mut |p| {
                out.push(match p {
                    Piece::Element(e) => P::E(String::from_utf8(e.to_vec()).unwrap()),
                    Piece::Raw(r) => P::R(String::from_utf8(r.to_vec()).unwrap()),
                    Piece::Close(_) => P::C,
                });
            });
        }
        let rest = f.finish();
        (out, rest)
    }

    fn joined(ps: &[P]) -> (Vec<String>, String) {
        let mut els = Vec::new();
        let mut all = String::new();
        for p in ps {
            match p {
                P::E(e) => {
                    els.push(e.clone());
                    all.push_str(e);
                }
                P::R(r) => all.push_str(r),
                P::C => all.push(']'),
            }
        }
        (els, all)
    }

    const BODY: &str =
        "[{\"a\":\"x]}\\\"{\",\"b\":[1,{\"c\":2}]}\r\n,{\"d\":\"\"}\r\n,  \"s,]\" , 12 ,true]\n";

    #[test]
    fn every_split_frames_the_same() {
        let b = BODY.as_bytes();
        let (whole, rest) = frame(&[b], 1 << 20);
        assert_eq!(rest, [] as [u8; 0]);
        let (els, all) = joined(&whole);
        assert_eq!(
            els,
            vec![
                "{\"a\":\"x]}\\\"{\",\"b\":[1,{\"c\":2}]}",
                "{\"d\":\"\"}",
                "\"s,]\"",
                "12",
                "true"
            ]
        );
        assert_eq!(all, BODY);
        assert!(whole.contains(&P::C));
        for cut in 0..b.len() {
            for cut2 in cut..b.len() {
                let (ps, rest) = frame(&[&b[..cut], &b[cut..cut2], &b[cut2..]], 1 << 20);
                assert_eq!(rest, [] as [u8; 0]);
                let (e, a) = joined(&ps);
                assert_eq!(e, els, "cuts {cut} {cut2}");
                assert_eq!(a, BODY, "cuts {cut} {cut2}");
            }
        }
    }

    #[test]
    fn oversized_element_passes_raw() {
        let body = "[{\"a\":\"0123456789\"},{\"b\":1}]";
        let b = body.as_bytes();
        for cut in 1..b.len() {
            let (ps, rest) = frame(&[&b[..cut], &b[cut..]], 8);
            assert_eq!(rest, [] as [u8; 0]);
            let (els, all) = joined(&ps);
            assert_eq!(all, body);
            // The first element spans bytes 1..19; it is given up once more than 8 of its bytes
            // would have to be held. A complete element in one chunk is never held.
            let first = "{\"a\":\"0123456789\"}";
            if (10..19).contains(&cut) {
                assert_eq!(els, vec!["{\"b\":1}"], "cut {cut}");
            } else {
                assert_eq!(els, vec![first, "{\"b\":1}"], "cut {cut}");
            }
        }
    }

    #[test]
    fn unterminated_element_returned_at_finish() {
        let (ps, rest) = frame(&[b"[{\"a\":1},{\"b\""], 1 << 20);
        assert_eq!(joined(&ps).0, vec!["{\"a\":1}"]);
        assert_eq!(rest, b"{\"b\"");
    }

    #[test]
    fn not_an_array_passes_through() {
        let (ps, rest) = frame(&[b"{\"error\":", b"{\"d\":[{}]}}"], 1 << 20);
        assert_eq!(rest, [] as [u8; 0]);
        assert_eq!(
            joined(&ps),
            (vec![], "{\"error\":{\"d\":[{}]}}".to_string())
        );
    }
}
