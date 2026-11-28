// SPDX-License-Identifier: AGPL-3.0-only

//! A strict JSON scanner that records byte spans instead of building values.
//!
//! Request bodies are redacted on their raw bytes (design D2). The codecs still need to know
//! where a few fields sit (configuration, signed thinking, binary data) without decoding and
//! re-serialising the body, so this module parses the body once into a flat arena of nodes that
//! point back into the original bytes. Strings are not decoded unless asked for.
//!
//! The scanner follows RFC 8259 strictly (no comments, no trailing commas, no leading zeros, no
//! raw control characters, valid escapes, valid UTF-8). Anything it rejects is refused upstream
//! of the provider, so the proxy and the provider never disagree about a body's structure.

// Offsets are stored as u32; `Doc::parse` refuses documents of 4 GiB or more.
#![allow(clippy::cast_possible_truncation)]

use std::borrow::Cow;

/// Maximum nesting depth accepted.
pub const MAX_DEPTH: usize = 512;

const NONE: u32 = u32::MAX;

/// JSON value kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `{...}`
    Object,
    /// `[...]`
    Array,
    /// `"..."`
    String,
    /// A number.
    Number,
    /// `true` or `false`.
    Bool,
    /// `null`.
    Null,
}

/// Why a body was rejected. Carries an offset only, never content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid JSON at byte {offset}: {reason}")]
pub struct JsonError {
    /// Byte offset of the problem.
    pub offset: usize,
    /// What was wrong.
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct Node {
    kind: Kind,
    start: u32,
    end: u32,
    key_start: u32,
    key_end: u32,
    first_child: u32,
    next_sibling: u32,
    key_escaped: bool,
    escaped: bool,
    /// Skipped unparsed ([`Skip`]): an object the caller already knows.
    opaque: bool,
}

/// Lets the caller skip objects it already knows while a document is parsed: the elements of
/// the arrays that are members of the root object named in `members` (`messages` of a provider
/// request). At such an element, `skip` gets the index of the member name and the element's
/// start offset, and returns the length of a complete JSON object that starts there, which
/// the parser then steps over without reading it, or `None` to parse it. The node is marked
/// [`Value::is_opaque`] and has no children.
///
/// The caller is responsible for the length: only bytes that parsed as one object before may be
/// skipped (the plan cache knows them by hash), and an object's validity does not depend on
/// what surrounds it.
pub(crate) struct Skip<'h> {
    /// Root members whose array elements may be skipped.
    pub members: &'h [&'h str],
    /// Length of the known object at an element start, if any.
    pub skip: &'h mut dyn FnMut(usize, usize) -> Option<usize>,
}

/// A parsed document: the source bytes plus a node arena.
#[derive(Debug)]
pub struct Doc<'a> {
    src: &'a [u8],
    nodes: Vec<Node>,
}

/// A value inside a [`Doc`].
#[derive(Debug, Clone, Copy)]
pub struct Value<'d, 'a> {
    doc: &'d Doc<'a>,
    idx: u32,
}

impl<'a> Doc<'a> {
    /// Parses `src` as one JSON value surrounded by optional whitespace.
    pub fn parse(src: &'a [u8]) -> Result<Self, JsonError> {
        if src.len() >= NONE as usize {
            return Err(JsonError {
                offset: 0,
                reason: "document too large",
            });
        }
        if let Err(e) = std::str::from_utf8(src) {
            return Err(JsonError {
                offset: e.valid_up_to(),
                reason: "invalid UTF-8",
            });
        }
        let mut p = Parser {
            src,
            pos: 0,
            nodes: Vec::with_capacity(src.len() / 32 + 4),
            members: &[],
            skip: None,
            role: None,
        };
        p.parse_document()?;
        Ok(Doc {
            src,
            nodes: p.nodes,
        })
    }

    /// [`Doc::parse`], stepping over the objects `skip` already knows. The result, error
    /// included, is the one [`Doc::parse`] gives: a skipped object is bytes that parsed before,
    /// so they are valid UTF-8 and only the bytes around them are checked, before any JSON
    /// error is reported, as [`Doc::parse`] checks the encoding first.
    pub(crate) fn parse_skipping(src: &'a [u8], skip: &mut Skip<'_>) -> Result<Self, JsonError> {
        if src.len() >= NONE as usize {
            return Err(JsonError {
                offset: 0,
                reason: "document too large",
            });
        }
        let mut p = Parser {
            src,
            pos: 0,
            nodes: Vec::with_capacity(src.len() / 256 + 4),
            members: skip.members,
            skip: Some(&mut *skip.skip),
            role: None,
        };
        let parsed = p.parse_document();
        // Every byte outside the skipped objects, in order.
        let mut from = 0;
        let skipped = p.nodes.iter().filter(|n| n.opaque);
        for (a, b) in skipped
            .map(|n| (n.start as usize, n.end as usize))
            .chain(std::iter::once((src.len(), src.len())))
        {
            if let Err(e) = std::str::from_utf8(&src[from..a]) {
                return Err(JsonError {
                    offset: from + e.valid_up_to(),
                    reason: "invalid UTF-8",
                });
            }
            from = b;
        }
        parsed?;
        Ok(Doc {
            src,
            nodes: p.nodes,
        })
    }

    /// The root value.
    pub fn root(&self) -> Value<'_, 'a> {
        Value { doc: self, idx: 0 }
    }

    /// The source bytes.
    pub fn src(&self) -> &'a [u8] {
        self.src
    }
}

impl<'d, 'a> Value<'d, 'a> {
    fn node(&self) -> &'d Node {
        &self.doc.nodes[self.idx as usize]
    }

    /// The value's kind.
    pub fn kind(&self) -> Kind {
        self.node().kind
    }

    /// Whether the value was stepped over unparsed ([`Skip`]): it is an object, and its
    /// members are not available.
    pub(crate) fn is_opaque(&self) -> bool {
        self.node().opaque
    }

    /// Byte span of the whole value in the source (strings include their quotes).
    pub fn span(&self) -> (usize, usize) {
        let n = self.node();
        (n.start as usize, n.end as usize)
    }

    /// Raw source bytes of the value.
    pub fn raw(&self) -> &'a [u8] {
        let (s, e) = self.span();
        &self.doc.src[s..e]
    }

    /// Byte span of a string's content, without quotes. `None` for non-strings.
    pub fn str_content_span(&self) -> Option<(usize, usize)> {
        let n = self.node();
        (n.kind == Kind::String).then_some((n.start as usize + 1, n.end as usize - 1))
    }

    /// Decoded string content. `None` for non-strings.
    pub fn as_str(&self) -> Option<Cow<'a, str>> {
        let n = self.node();
        if n.kind != Kind::String {
            return None;
        }
        let raw = &self.doc.src[n.start as usize + 1..n.end as usize - 1];
        Some(if n.escaped {
            Cow::Owned(unescape(raw))
        } else {
            Cow::Borrowed(as_utf8(raw))
        })
    }

    /// The member key of this value when it is an object member, decoded.
    pub fn key(&self) -> Option<Cow<'a, str>> {
        let n = self.node();
        if n.key_start == NONE {
            return None;
        }
        let raw = &self.doc.src[n.key_start as usize..n.key_end as usize];
        Some(if n.key_escaped {
            Cow::Owned(unescape(raw))
        } else {
            Cow::Borrowed(as_utf8(raw))
        })
    }

    fn key_is(&self, key: &str) -> bool {
        let n = self.node();
        if n.key_start == NONE {
            return false;
        }
        let raw = &self.doc.src[n.key_start as usize..n.key_end as usize];
        if n.key_escaped {
            unescape(raw) == key
        } else {
            raw == key.as_bytes()
        }
    }

    /// Child values of an object or array, in source order.
    pub fn children(&self) -> Children<'d, 'a> {
        let first = match self.node().kind {
            Kind::Object | Kind::Array => self.node().first_child,
            _ => NONE,
        };
        Children {
            doc: self.doc,
            next: first,
        }
    }

    /// Object members as (key, value) pairs.
    pub fn members(&self) -> impl Iterator<Item = (Cow<'a, str>, Value<'d, 'a>)> + 'd {
        self.children().filter_map(|v| v.key().map(|k| (k, v)))
    }

    /// The member named `key`. If the key occurs more than once, returns [`Duplicate`] so that
    /// a caller relying on the field fails closed instead of guessing which one a provider would
    /// read.
    pub fn get(&self, key: &str) -> Result<Option<Value<'d, 'a>>, Duplicate> {
        if self.kind() != Kind::Object {
            return Ok(None);
        }
        let mut found = None;
        for c in self.children() {
            if c.key_is(key) {
                if found.is_some() {
                    return Err(Duplicate { offset: c.span().0 });
                }
                found = Some(c);
            }
        }
        Ok(found)
    }

    /// Decoded string of member `key`, when it exists and is a string.
    pub fn get_str(&self, key: &str) -> Result<Option<Cow<'a, str>>, Duplicate> {
        Ok(self.get(key)?.and_then(|v| v.as_str()))
    }
}

/// A key that appears twice in an object where the proxy needs to read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("duplicate object key at byte {offset}")]
pub struct Duplicate {
    /// Offset of the second occurrence.
    pub offset: usize,
}

/// Iterator over child values.
#[derive(Debug, Clone)]
pub struct Children<'d, 'a> {
    doc: &'d Doc<'a>,
    next: u32,
}

impl<'d, 'a> Iterator for Children<'d, 'a> {
    type Item = Value<'d, 'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == NONE {
            return None;
        }
        let v = Value {
            doc: self.doc,
            idx: self.next,
        };
        self.next = v.node().next_sibling;
        Some(v)
    }
}

fn as_utf8(b: &[u8]) -> &str {
    // Doc::parse validated the whole source as UTF-8 and string boundaries are ASCII quotes.
    std::str::from_utf8(b).unwrap_or_default()
}

struct Parser<'a, 'h> {
    src: &'a [u8],
    pos: usize,
    nodes: Vec<Node>,
    members: &'h [&'h str],
    skip: Option<&'h mut dyn FnMut(usize, usize) -> Option<usize>>,
    /// While inside an array whose elements may be skipped: its node and the member index.
    role: Option<(u32, usize)>,
}

enum Frame {
    Object { node: u32, last: u32 },
    Array { node: u32, last: u32 },
}

impl Parser<'_, '_> {
    fn err<T>(&self, reason: &'static str) -> Result<T, JsonError> {
        Err(JsonError {
            offset: self.pos,
            reason,
        })
    }

    fn ws(&mut self) {
        while let Some(&c) = self.src.get(self.pos) {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn push(&mut self, kind: Kind, start: usize) -> u32 {
        let idx = self.nodes.len() as u32;
        self.nodes.push(Node {
            kind,
            start: start as u32,
            end: start as u32,
            key_start: NONE,
            key_end: NONE,
            first_child: NONE,
            next_sibling: NONE,
            key_escaped: false,
            escaped: false,
            opaque: false,
        });
        idx
    }

    /// At an element start of a skippable array: steps over a known object, returning its node.
    fn try_skip(&mut self, stack: &[Frame], start: usize) -> Option<u32> {
        let (node, role) = self.role?;
        if stack.len() != 2
            || !matches!(stack.last(), Some(Frame::Array { node: n, .. }) if *n == node)
        {
            return None;
        }
        let skip = self.skip.as_mut()?;
        let len = skip(role, start)?;
        let end = start
            .checked_add(len)
            .filter(|&e| e <= self.src.len() && len >= 2)?;
        let idx = self.push(Kind::Object, start);
        let n = &mut self.nodes[idx as usize];
        n.end = end as u32;
        n.opaque = true;
        self.pos = end;
        Some(idx)
    }

    /// When an array opens as a member of the root object, whether its elements may be skipped.
    fn role_of(&self, stack: &[Frame], key: Option<(u32, u32, bool)>) -> Option<usize> {
        let (ks, ke, esc) = key?;
        if esc || stack.len() != 1 || !matches!(stack.first(), Some(Frame::Object { .. })) {
            return None;
        }
        let k = &self.src[ks as usize..ke as usize];
        self.members.iter().position(|m| m.as_bytes() == k)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one iterative state machine reads better whole"
    )]
    fn parse_document(&mut self) -> Result<(), JsonError> {
        self.ws();
        let mut stack: Vec<Frame> = Vec::new();
        let mut pending_key: Option<(u32, u32, bool)> = None;
        loop {
            // Expect a value.
            self.ws();
            let start = self.pos;
            let Some(&c) = self.src.get(self.pos) else {
                return self.err("unexpected end of input");
            };
            let skipped = if c == b'{' && self.role.is_some() {
                self.try_skip(&stack, start)
            } else {
                None
            };
            let idx = match c {
                _ if skipped.is_some() => {
                    let idx = skipped.unwrap_or(NONE);
                    self.attach(&mut stack, idx, pending_key.take());
                    idx
                }
                b'{' | b'[' => {
                    if stack.len() >= MAX_DEPTH {
                        return self.err("nesting too deep");
                    }
                    let kind = if c == b'{' { Kind::Object } else { Kind::Array };
                    let idx = self.push(kind, start);
                    if c == b'['
                        && self.skip.is_some()
                        && let Some(role) = self.role_of(&stack, pending_key)
                    {
                        self.role = Some((idx, role));
                    }
                    self.attach(&mut stack, idx, pending_key.take());
                    self.pos += 1;
                    stack.push(if c == b'{' {
                        Frame::Object {
                            node: idx,
                            last: NONE,
                        }
                    } else {
                        Frame::Array {
                            node: idx,
                            last: NONE,
                        }
                    });
                    self.ws();
                    let close = if c == b'{' { b'}' } else { b']' };
                    if self.src.get(self.pos) == Some(&close) {
                        self.pos += 1;
                        self.nodes[idx as usize].end = self.pos as u32;
                        stack.pop();
                        // fallthrough to "after value"
                    } else {
                        if c == b'{' {
                            pending_key = Some(self.parse_key()?);
                        }
                        continue;
                    }
                    idx
                }
                b'"' => {
                    let escaped = self.scan_string()?;
                    let idx = self.push(Kind::String, start);
                    self.nodes[idx as usize].end = self.pos as u32;
                    self.nodes[idx as usize].escaped = escaped;
                    self.attach(&mut stack, idx, pending_key.take());
                    idx
                }
                b't' | b'f' | b'n' => {
                    let (lit, kind): (&[u8], Kind) = match c {
                        b't' => (b"true", Kind::Bool),
                        b'f' => (b"false", Kind::Bool),
                        _ => (b"null", Kind::Null),
                    };
                    if !self.src[self.pos..].starts_with(lit) {
                        return self.err("invalid literal");
                    }
                    self.pos += lit.len();
                    let idx = self.push(kind, start);
                    self.nodes[idx as usize].end = self.pos as u32;
                    self.attach(&mut stack, idx, pending_key.take());
                    idx
                }
                b'-' | b'0'..=b'9' => {
                    self.scan_number()?;
                    let idx = self.push(Kind::Number, start);
                    self.nodes[idx as usize].end = self.pos as u32;
                    self.attach(&mut stack, idx, pending_key.take());
                    idx
                }
                _ => return self.err("expected a value"),
            };
            let _ = idx;
            // After a value: close containers or expect a separator.
            loop {
                self.ws();
                let Some(top) = stack.last() else {
                    if self.pos != self.src.len() {
                        return self.err("trailing data after document");
                    }
                    return Ok(());
                };
                let (node, is_obj) = match top {
                    Frame::Object { node, .. } => (*node, true),
                    Frame::Array { node, .. } => (*node, false),
                };
                match self.src.get(self.pos) {
                    Some(b',') => {
                        self.pos += 1;
                        if is_obj {
                            self.ws();
                            pending_key = Some(self.parse_key()?);
                        }
                        break;
                    }
                    Some(b'}') if is_obj => {
                        self.pos += 1;
                        self.nodes[node as usize].end = self.pos as u32;
                        stack.pop();
                    }
                    Some(b']') if !is_obj => {
                        self.pos += 1;
                        self.nodes[node as usize].end = self.pos as u32;
                        stack.pop();
                    }
                    None => return self.err("unexpected end of input"),
                    _ => {
                        return self.err(if is_obj {
                            "expected ',' or '}'"
                        } else {
                            "expected ',' or ']'"
                        });
                    }
                }
            }
        }
    }

    fn attach(&mut self, stack: &mut [Frame], idx: u32, key: Option<(u32, u32, bool)>) {
        if let Some((ks, ke, kesc)) = key {
            let n = &mut self.nodes[idx as usize];
            n.key_start = ks;
            n.key_end = ke;
            n.key_escaped = kesc;
        }
        match stack.last_mut() {
            Some(Frame::Object { node, last } | Frame::Array { node, last }) => {
                if *last == NONE {
                    self.nodes[*node as usize].first_child = idx;
                } else {
                    self.nodes[*last as usize].next_sibling = idx;
                }
                *last = idx;
            }
            None => {}
        }
    }

    /// Parses `"key" :` and returns the key content span.
    fn parse_key(&mut self) -> Result<(u32, u32, bool), JsonError> {
        self.ws();
        if self.src.get(self.pos) != Some(&b'"') {
            return self.err("expected object key");
        }
        let ks = self.pos + 1;
        let escaped = self.scan_string()?;
        let ke = self.pos - 1;
        self.ws();
        if self.src.get(self.pos) != Some(&b':') {
            return self.err("expected ':'");
        }
        self.pos += 1;
        Ok((ks as u32, ke as u32, escaped))
    }

    /// Scans a string starting at the opening quote; leaves `pos` after the closing quote.
    /// Returns whether it contains escapes.
    fn scan_string(&mut self) -> Result<bool, JsonError> {
        self.pos += 1;
        let mut escaped = false;
        loop {
            let rest = &self.src[self.pos..];
            let Some(i) = memchr::memchr2(b'"', b'\\', rest) else {
                self.pos = self.src.len();
                return self.err("unterminated string");
            };
            if let Some(bad) = rest[..i].iter().position(|&b| b < 0x20) {
                self.pos += bad;
                return self.err("control character in string");
            }
            self.pos += i;
            if self.src[self.pos] == b'"' {
                self.pos += 1;
                return Ok(escaped);
            }
            escaped = true;
            self.pos += 1;
            match self.src.get(self.pos) {
                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.pos += 1,
                Some(b'u') => {
                    let hex = self.src.get(self.pos + 1..self.pos + 5);
                    match hex {
                        Some(h) if h.iter().all(u8::is_ascii_hexdigit) => self.pos += 5,
                        _ => return self.err("invalid \\u escape"),
                    }
                }
                _ => return self.err("invalid escape"),
            }
        }
    }

    fn scan_number(&mut self) -> Result<(), JsonError> {
        let s = self.src;
        if s.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        match s.get(self.pos) {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(s.get(self.pos), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return self.err("invalid number"),
        }
        if s.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            if !matches!(s.get(self.pos), Some(b'0'..=b'9')) {
                return self.err("invalid number fraction");
            }
            while matches!(s.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(s.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(s.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(s.get(self.pos), Some(b'0'..=b'9')) {
                return self.err("invalid number exponent");
            }
            while matches!(s.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(())
    }
}

/// Decodes the content of a validated JSON string (without quotes). Lone surrogates become
/// U+FFFD, as most JSON decoders do.
pub fn unescape(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let Some(j) = memchr::memchr(b'\\', &raw[i..]) else {
            out.push_str(as_utf8(&raw[i..]));
            break;
        };
        out.push_str(as_utf8(&raw[i..i + j]));
        i += j + 1;
        let Some(&e) = raw.get(i) else { break };
        i += 1;
        match e {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{8}'),
            b'f' => out.push('\u{c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let hi = hex4(raw.get(i..i + 4));
                i += 4;
                let Some(hi) = hi else {
                    out.push('\u{fffd}');
                    continue;
                };
                if (0xD800..0xDC00).contains(&hi)
                    && raw.get(i) == Some(&b'\\')
                    && raw.get(i + 1) == Some(&b'u')
                    && let Some(lo) =
                        hex4(raw.get(i + 2..i + 6)).filter(|lo| (0xDC00..0xE000).contains(lo))
                {
                    i += 6;
                    let c = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                    out.push(char::from_u32(c).unwrap_or('\u{fffd}'));
                    continue;
                }
                out.push(char::from_u32(hi).unwrap_or('\u{fffd}'));
            }
            _ => out.push('\u{fffd}'),
        }
    }
    out
}

fn hex4(b: Option<&[u8]>) -> Option<u32> {
    let b = b?;
    let s = std::str::from_utf8(b).ok()?;
    u32::from_str_radix(s, 16).ok()
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Appends `s` JSON-escaped (without quotes) to `out`. Escapes `"`, `\` and control characters;
/// everything else, including non-ASCII, is written as is.
pub fn escape_into(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let mut start = 0;
    for (i, &c) in b.iter().enumerate() {
        let esc: &[u8] = match c {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x08 => b"\\b",
            0x0c => b"\\f",
            0..=0x1f => {
                out.extend_from_slice(&b[start..i]);
                out.extend_from_slice(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[(c >> 4) as usize],
                    HEX[(c & 15) as usize],
                ]);
                start = i + 1;
                continue;
            }
            _ => continue,
        };
        out.extend_from_slice(&b[start..i]);
        out.extend_from_slice(esc);
        start = i + 1;
    }
    out.extend_from_slice(&b[start..]);
}

/// `s` as a JSON string literal, with quotes.
pub fn quote(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 2);
    v.push(b'"');
    escape_into(&mut v, s);
    v.push(b'"');
    v
}

/// Applies non-overlapping `(start, end, replacement)` edits to `src`. Edits must be sorted by
/// start.
pub fn splice(src: &[u8], edits: &[(usize, usize, Vec<u8>)]) -> Vec<u8> {
    let extra: usize = edits.iter().map(|e| e.2.len()).sum();
    let mut out = Vec::with_capacity(src.len() + extra);
    let mut pos = 0;
    for (s, e, r) in edits {
        debug_assert!(*s >= pos && e >= s);
        out.extend_from_slice(&src[pos..*s]);
        out.extend_from_slice(r);
        pos = *e;
    }
    out.extend_from_slice(&src[pos..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<Kind> {
        let d = Doc::parse(src.as_bytes()).unwrap();
        d.nodes.iter().map(|n| n.kind).collect()
    }

    #[test]
    fn parses_nested() {
        let src = br#" {"a": [1, -2.5e3, true, null, "x\n"], "b": {"c": {}} , "d": []} "#;
        let d = Doc::parse(src).unwrap();
        let root = d.root();
        assert_eq!(root.kind(), Kind::Object);
        let a = root.get("a").unwrap().unwrap();
        let items: Vec<_> = a.children().map(|v| v.kind()).collect();
        assert_eq!(
            items,
            vec![
                Kind::Number,
                Kind::Number,
                Kind::Bool,
                Kind::Null,
                Kind::String
            ]
        );
        assert_eq!(a.children().nth(4).unwrap().as_str().unwrap(), "x\n");
        assert_eq!(a.children().nth(1).unwrap().raw(), b"-2.5e3");
        let b = root.get("b").unwrap().unwrap();
        assert_eq!(b.get("c").unwrap().unwrap().raw(), b"{}");
        assert_eq!(root.get("d").unwrap().unwrap().raw(), b"[]");
        assert!(root.get("zz").unwrap().is_none());
        let keys: Vec<_> = root.members().map(|(k, _)| k.into_owned()).collect();
        assert_eq!(keys, vec!["a", "b", "d"]);
    }

    #[test]
    fn spans_point_into_source() {
        let src = br#"{"k":"v\u00e9","n":12}"#;
        let d = Doc::parse(src).unwrap();
        let k = d.root().get("k").unwrap().unwrap();
        assert_eq!(k.raw(), br#""v\u00e9""#);
        assert_eq!(k.as_str().unwrap(), "vé");
        let (s, e) = k.str_content_span().unwrap();
        assert_eq!(&src[s..e], br"v\u00e9");
    }

    #[test]
    fn scalar_roots() {
        assert_eq!(kinds("1"), vec![Kind::Number]);
        assert_eq!(kinds(" \"s\" "), vec![Kind::String]);
        assert_eq!(kinds("null"), vec![Kind::Null]);
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            " ",
            "{",
            "}",
            "[1,]",
            "{\"a\":1,}",
            "{\"a\" 1}",
            "{a:1}",
            "01",
            "1.",
            "1e",
            "-",
            "+1",
            "tru",
            "\"abc",
            "\"\\x\"",
            "\"\\u12g4\"",
            "\"a\u{1}b\"",
            "[1] [2]",
            "{\"a\":1}x",
            "NaN",
            "'a'",
            "[1 2]",
            "{\"a\":1 \"b\":2}",
        ] {
            assert!(Doc::parse(bad.as_bytes()).is_err(), "accepted {bad:?}");
        }
        assert!(Doc::parse(b"\"\xff\"").is_err());
    }

    #[test]
    fn depth_limit() {
        let deep = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
        assert!(Doc::parse(deep.as_bytes()).is_err());
        let ok = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        assert!(Doc::parse(ok.as_bytes()).is_ok());
    }

    #[test]
    fn duplicate_keys_detected_on_get() {
        let d = Doc::parse(br#"{"type":"text","type":"thinking"}"#).unwrap();
        assert!(d.root().get("type").is_err());
    }

    #[test]
    fn escaped_keys_compare_decoded() {
        let d = Doc::parse(br#"{"t\u0079pe":"x"}"#).unwrap();
        assert_eq!(d.root().get_str("type").unwrap().unwrap(), "x");
    }

    #[test]
    fn unescape_surrogates() {
        assert_eq!(unescape(br"\ud83d\ude00"), "😀");
        assert_eq!(unescape(br"\ud83d"), "\u{fffd}");
        assert_eq!(
            unescape(br#"a\/b\\c\"d\b\f\n\r\t"#),
            "a/b\\c\"d\u{8}\u{c}\n\r\t"
        );
    }

    #[test]
    fn escape_round_trips() {
        let s = "q\"b\\n\n\t\u{1}é😀/";
        let lit = quote(s);
        let d = Doc::parse(&lit).unwrap();
        assert_eq!(d.root().as_str().unwrap(), s);
        assert_eq!(serde_json::from_slice::<String>(&lit).unwrap(), s);
    }

    #[test]
    fn splice_edits() {
        let out = splice(
            b"0123456789",
            &[
                (1, 3, b"ab".to_vec()),
                (5, 5, b"X".to_vec()),
                (8, 10, vec![]),
            ],
        );
        assert_eq!(out, b"0ab34X567");
    }

    mod props {
        use super::super::*;
        use proptest::prelude::*;

        fn arb_json() -> impl Strategy<Value = serde_json::Value> {
            let leaf = prop_oneof![
                Just(serde_json::Value::Null),
                any::<bool>().prop_map(serde_json::Value::Bool),
                any::<i64>().prop_map(|n| serde_json::json!(n)),
                (-1e6f64..1e6).prop_map(|n| serde_json::json!(n)),
                ".*".prop_map(serde_json::Value::String),
            ];
            leaf.prop_recursive(4, 64, 8, |inner| {
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..8).prop_map(serde_json::Value::Array),
                    prop::collection::btree_map(".*", inner, 0..8)
                        .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
                ]
            })
        }

        proptest! {
            #[test]
            fn accepts_everything_serde_writes(v in arb_json(), pretty in any::<bool>()) {
                let s = if pretty { serde_json::to_vec_pretty(&v).unwrap() } else { serde_json::to_vec(&v).unwrap() };
                let d = Doc::parse(&s).unwrap();
                prop_assert_eq!(d.root().raw().len(), s.len());
            }

            #[test]
            fn agrees_with_serde_on_validity(s in "[\\[\\]{}\",:0-9a-z \\\\.eE+-]{0,40}") {
                let ours = Doc::parse(s.as_bytes()).is_ok();
                let theirs = serde_json::from_str::<serde_json::Value>(&s).is_ok();
                prop_assert_eq!(ours, theirs, "input {:?}", s);
            }

            #[test]
            fn strings_decode_like_serde(v in ".*") {
                let lit = serde_json::to_vec(&v).unwrap();
                let d = Doc::parse(&lit).unwrap();
                prop_assert_eq!(d.root().as_str().unwrap(), v.as_str());
                prop_assert_eq!(quote(&v), lit);
            }
        }
    }
}
