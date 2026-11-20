//! Rust implementation of the shared redact/restore spec (see README).
use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::borrow::Cow;
use std::collections::HashMap;

pub const MIN_VARIANT_LEN: usize = 8;
pub const PLACEHOLDER_LEN: usize = 3 + 4 + 12 + 3;
const PH_OPEN: &[u8] = "\u{27e6}kss:".as_bytes();
const PH_CLOSE: &[u8] = "\u{27e7}".as_bytes();
const LHEX: &[u8; 16] = b"0123456789abcdef";

pub fn placeholder(key: &[u8], v: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(v);
    let h = m.finalize().into_bytes();
    let mut out = Vec::with_capacity(PLACEHOLDER_LEN);
    out.extend_from_slice(PH_OPEN);
    for b in &h[..6] {
        out.push(LHEX[(b >> 4) as usize]);
        out.push(LHEX[(b & 15) as usize]);
    }
    out.extend_from_slice(PH_CLOSE);
    out
}

/// Append s as JSON string content. slash: '/' -> "\/"; uni: non-ASCII -> \uXXXX.
pub fn json_escape_into(out: &mut Vec<u8>, s: &[u8], slash: bool, uni: bool) {
    let mut start = 0;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if (c >= 0x20 && c != b'"' && c != b'\\' && c < 0x80 && !(slash && c == b'/')) || (c >= 0x80 && !uni) {
            i += 1;
            continue;
        }
        out.extend_from_slice(&s[start..i]);
        if c >= 0x80 {
            let w = utf8_width(c).min(s.len() - i);
            let ch = std::str::from_utf8(&s[i..i + w]).ok().and_then(|x| x.chars().next()).unwrap_or('\u{fffd}');
            let mut u4 = |x: u32| {
                out.extend_from_slice(b"\\u");
                for sh in [12, 8, 4, 0] {
                    out.push(LHEX[((x >> sh) & 15) as usize]);
                }
            };
            let r = ch as u32;
            if r >= 0x10000 {
                let r = r - 0x10000;
                u4(0xD800 + (r >> 10));
                u4(0xDC00 + (r & 0x3FF));
            } else {
                u4(r);
            }
            i += w;
            start = i;
            continue;
        }
        match c {
            b'"' | b'\\' | b'/' => out.extend_from_slice(&[b'\\', c]),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            _ => out.extend_from_slice(&[b'\\', b'u', b'0', b'0', LHEX[(c >> 4) as usize], LHEX[(c & 15) as usize]]),
        }
        i += 1;
        start = i;
    }
    out.extend_from_slice(&s[start..]);
}

fn utf8_width(c: u8) -> usize {
    match c {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

fn json_escape(s: &[u8], slash: bool, uni: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 8);
    json_escape_into(&mut v, s, slash, uni);
    v
}

fn b64_stable(e: &base64::engine::GeneralPurpose, v: &[u8], k: usize) -> Vec<u8> {
    let mut buf = vec![0u8; k + v.len()];
    buf[k..].copy_from_slice(v);
    let full = e.encode(&buf);
    let (js, je) = ((8 * k + 5) / 6, (8 * (k + v.len())) / 6);
    if je <= js {
        return Vec::new();
    }
    full.as_bytes()[js..je].to_vec()
}

fn url_encode(s: &[u8]) -> Vec<u8> {
    const HX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(s.len() * 3);
    for &c in s {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
            out.push(c);
        } else {
            out.extend_from_slice(&[b'%', HX[(c >> 4) as usize], HX[(c & 15) as usize]]);
        }
    }
    out
}

/// Encoded forms of v in canonical order.
pub fn variants(v: &[u8]) -> Vec<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD as STD, URL_SAFE_NO_PAD as URL};
    vec![
        v.to_vec(),
        json_escape(v, false, false),
        json_escape(v, true, false),
        json_escape(v, false, true),
        json_escape(v, true, true),
        b64_stable(&STD, v, 0),
        b64_stable(&STD, v, 1),
        b64_stable(&STD, v, 2),
        b64_stable(&URL, v, 0),
        b64_stable(&URL, v, 1),
        b64_stable(&URL, v, 2),
        hex::encode(v).into_bytes(),
        url_encode(v),
    ]
}

/// Deduplicated patterns (first occurrence wins) and owning secret index.
pub fn patterns(secrets: &[Vec<u8>]) -> (Vec<Vec<u8>>, Vec<u32>) {
    let mut seen = std::collections::HashSet::with_capacity(secrets.len() * 6);
    let (mut pats, mut owner) = (Vec::new(), Vec::new());
    for (i, s) in secrets.iter().enumerate() {
        for v in variants(s) {
            if v.len() < MIN_VARIANT_LEN || seen.contains(&v) {
                continue;
            }
            seen.insert(v.clone());
            pats.push(v);
            owner.push(i as u32);
        }
    }
    (pats, owner)
}

pub struct Redactor {
    pub ac: AhoCorasick,
    owner: Vec<u32>,
    ph: Vec<Vec<u8>>,
}

pub const ENGINES: &[&str] = &["ac-auto", "ac-dfa", "ac-nfa-contig", "ac-nfa-noncontig"];

impl Redactor {
    pub fn new(secrets: &[Vec<u8>], key: &[u8], engine: &str) -> Redactor {
        let (pats, owner) = patterns(secrets);
        let ph = secrets.iter().map(|s| placeholder(key, s)).collect();
        Self::from_patterns(&pats, owner, ph, engine)
    }

    /// Build from an already computed (deduplicated) pattern list; ph is indexed by owner value.
    pub fn from_patterns(pats: &[Vec<u8>], owner: Vec<u32>, ph: Vec<Vec<u8>>, engine: &str) -> Redactor {
        let kind = match engine {
            "ac-auto" => None,
            "ac-dfa" => Some(AhoCorasickKind::DFA),
            "ac-nfa-contig" => Some(AhoCorasickKind::ContiguousNFA),
            "ac-nfa-noncontig" => Some(AhoCorasickKind::NoncontiguousNFA),
            e => panic!("unknown engine {e}"),
        };
        let ac = AhoCorasick::builder().match_kind(MatchKind::LeftmostLongest).kind(kind).build(pats).unwrap();
        Redactor { ac, owner, ph }
    }

    /// Like redact_into, also records the matched secret indices (owner values) into refs.
    pub fn redact_refs(&self, body: &[u8], out: &mut Vec<u8>, refs: &mut Vec<u32>) -> usize {
        out.clear();
        let (mut pos, mut n) = (0, 0);
        for m in self.ac.find_iter(body) {
            if n == 0 {
                out.reserve(body.len() + body.len() / 16);
            }
            let o = self.owner[m.pattern().as_usize()];
            refs.push(o);
            out.extend_from_slice(&body[pos..m.start()]);
            out.extend_from_slice(&self.ph[o as usize]);
            pos = m.end();
            n += 1;
        }
        if n > 0 {
            out.extend_from_slice(&body[pos..]);
        }
        n
    }

    /// Redact body into out (cleared first). Returns the number of replacements.
    /// When 0, `out` is left empty and the caller should use `body` as is.
    pub fn redact_into(&self, body: &[u8], out: &mut Vec<u8>) -> usize {
        out.clear();
        let mut pos = 0;
        let mut n = 0;
        for m in self.ac.find_iter(body) {
            if n == 0 {
                out.reserve(body.len() + body.len() / 16);
            }
            out.extend_from_slice(&body[pos..m.start()]);
            out.extend_from_slice(&self.ph[self.owner[m.pattern().as_usize()] as usize]);
            pos = m.end();
            n += 1;
        }
        if n > 0 {
            out.extend_from_slice(&body[pos..]);
        }
        n
    }

    pub fn redact<'a>(&self, body: &'a [u8], buf: &'a mut Vec<u8>) -> (&'a [u8], usize) {
        let n = self.redact_into(body, buf);
        if n == 0 { (body, 0) } else { (&buf[..], n) }
    }

    pub fn count(&self, body: &[u8]) -> usize {
        self.ac.find_iter(body).count()
    }
}

// ---------------------------------------------------------------- restore

pub struct Table {
    m: HashMap<[u8; 12], u32>,
    v: Vec<Vec<u8>>,
    j: Vec<Vec<u8>>,
}

impl Table {
    pub fn new(secrets: &[Vec<u8>], key: &[u8]) -> Table {
        let mut m = HashMap::with_capacity(secrets.len());
        let (mut v, mut j) = (Vec::new(), Vec::new());
        for (i, s) in secrets.iter().enumerate() {
            let ph = placeholder(key, s);
            let mut k = [0u8; 12];
            k.copy_from_slice(&ph[7..19]);
            m.entry(k).or_insert(i as u32);
            v.push(s.clone());
            j.push(json_escape(s, false, false));
        }
        Table { m, v, j }
    }

    /// Appends p to dst with known placeholders replaced. Returns (hold_start, replaced).
    fn substitute(&self, dst: &mut Vec<u8>, p: &[u8], json_esc: bool) -> (usize, bool) {
        let (mut pos, mut i, mut hold) = (0, 0, p.len());
        let mut replaced = false;
        while let Some(j) = memchr::memchr(0xE2, &p[i..]) {
            let j = j + i;
            if p.len() - j >= PLACEHOLDER_LEN {
                if is_placeholder(&p[j..j + PLACEHOLDER_LEN]) {
                    let mut k = [0u8; 12];
                    k.copy_from_slice(&p[j + 7..j + 19]);
                    if let Some(&idx) = self.m.get(&k) {
                        dst.extend_from_slice(&p[pos..j]);
                        dst.extend_from_slice(if json_esc { &self.j[idx as usize] } else { &self.v[idx as usize] });
                        pos = j + PLACEHOLDER_LEN;
                        i = pos;
                        replaced = true;
                        continue;
                    }
                }
            } else if is_placeholder_prefix(&p[j..]) {
                hold = j;
                break;
            }
            i = j + 1;
        }
        dst.extend_from_slice(&p[pos..hold]);
        (hold, replaced)
    }
}

#[inline]
fn shape_byte(k: usize, c: u8) -> bool {
    if k < 7 {
        c == PH_OPEN[k]
    } else if k < 19 {
        c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
    } else {
        c == PH_CLOSE[k - 19]
    }
}

fn is_placeholder(b: &[u8]) -> bool {
    (0..PLACEHOLDER_LEN).all(|k| shape_byte(k, b[k]))
}

fn is_placeholder_prefix(b: &[u8]) -> bool {
    b.iter().enumerate().all(|(k, &c)| shape_byte(k, c))
}

#[derive(Default, Clone)]
struct Block {
    held: Vec<u8>,
    dtype: u8,
}

const DTYPE_NAME: [&str; 4] = ["", "text_delta", "thinking_delta", "input_json_delta"];
const DTYPE_FIELD: [&str; 4] = ["", "text", "thinking", "partial_json"];
const MAX_INDEX: i64 = 1 << 16;

#[derive(Deserialize)]
struct DeltaEv<'a> {
    #[serde(default)]
    index: i64,
    #[serde(borrow)]
    delta: Delta<'a>,
}

#[derive(Deserialize)]
struct Delta<'a> {
    #[serde(rename = "type", borrow)]
    ty: Cow<'a, str>,
    #[serde(borrow, default)]
    text: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    thinking: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    partial_json: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
struct StopEv {
    #[serde(default)]
    index: i64,
}

pub struct Restorer {
    t: std::sync::Arc<Table>,
    inbuf: Vec<u8>,
    blocks: Vec<Block>,
    p: Vec<u8>,
    e: Vec<u8>,
}

fn parse_event(ev: &[u8]) -> Option<(&[u8], &[u8])> {
    let body = &ev[..ev.len() - 2];
    let nl = memchr::memchr(b'\n', body)?;
    let (l1, l2) = (&body[..nl], &body[nl + 1..]);
    if !l1.starts_with(b"event:") || !l2.starts_with(b"data:") || memchr::memchr(b'\n', l2).is_some() {
        return None;
    }
    let (mut name, mut data) = (&l1[6..], &l2[5..]);
    if name.first() == Some(&b' ') {
        name = &name[1..];
    }
    if data.first() == Some(&b' ') {
        data = &data[1..];
    }
    Some((name, data))
}

fn push_usize(dst: &mut Vec<u8>, mut n: usize) {
    let mut b = [0u8; 20];
    let mut i = b.len();
    loop {
        i -= 1;
        b[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    dst.extend_from_slice(&b[i..]);
}

static SEP: std::sync::LazyLock<memchr::memmem::Finder<'static>> =
    std::sync::LazyLock::new(|| memchr::memmem::Finder::new(b"\n\n"));

impl Restorer {
    pub fn new(t: std::sync::Arc<Table>) -> Self {
        Restorer { t, inbuf: Vec::with_capacity(8192), blocks: Vec::new(), p: Vec::with_capacity(256), e: Vec::with_capacity(256) }
    }

    pub fn reset(&mut self) {
        self.inbuf.clear();
        self.blocks.clear();
    }

    /// Consume one chunk, append restored output to dst.
    pub fn feed(&mut self, dst: &mut Vec<u8>, chunk: &[u8]) {
        let use_in = !self.inbuf.is_empty();
        let mut inbuf = std::mem::take(&mut self.inbuf);
        if use_in {
            inbuf.extend_from_slice(chunk);
        }
        let buf: &[u8] = if use_in { &inbuf } else { chunk };
        let mut off = 0;
        while let Some(k) = SEP.find(&buf[off..]) {
            let end = off + k + 2;
            self.event(dst, &buf[off..end]);
            off = end;
        }
        if use_in {
            inbuf.drain(..off);
        } else {
            inbuf.extend_from_slice(&chunk[off..]);
        }
        self.inbuf = inbuf;
    }

    /// Flush held text of open blocks (index order) and any trailing partial event.
    pub fn finish(&mut self, dst: &mut Vec<u8>) {
        for i in 0..self.blocks.len() {
            self.flush(dst, i);
        }
        dst.extend_from_slice(&self.inbuf);
        self.inbuf.clear();
    }

    fn write_delta(dst: &mut Vec<u8>, idx: usize, dt: u8, text: &[u8]) {
        dst.extend_from_slice(b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":");
        push_usize(dst, idx);
        dst.extend_from_slice(b",\"delta\":{\"type\":\"");
        dst.extend_from_slice(DTYPE_NAME[dt as usize].as_bytes());
        dst.extend_from_slice(b"\",\"");
        dst.extend_from_slice(DTYPE_FIELD[dt as usize].as_bytes());
        dst.extend_from_slice(b"\":\"");
        json_escape_into(dst, text, false, false);
        dst.extend_from_slice(b"\"}}\n\n");
    }

    fn flush(&mut self, dst: &mut Vec<u8>, i: usize) {
        let b = &mut self.blocks[i];
        if b.held.is_empty() {
            return;
        }
        Self::write_delta(dst, i, b.dtype, &b.held);
        b.held.clear();
    }

    fn event(&mut self, dst: &mut Vec<u8>, ev: &[u8]) {
        let Some((name, data)) = parse_event(ev) else {
            dst.extend_from_slice(ev);
            return;
        };
        match name {
            b"content_block_delta" => {
                let Ok(d) = serde_json::from_slice::<DeltaEv>(data) else {
                    dst.extend_from_slice(ev);
                    return;
                };
                if d.index < 0 || d.index >= MAX_INDEX {
                    dst.extend_from_slice(ev);
                    return;
                }
                let (dt, s): (u8, &str) = match &*d.delta.ty {
                    "text_delta" => (1, d.delta.text.as_deref().unwrap_or("")),
                    "thinking_delta" => (2, d.delta.thinking.as_deref().unwrap_or("")),
                    "input_json_delta" => (3, d.delta.partial_json.as_deref().unwrap_or("")),
                    _ => {
                        dst.extend_from_slice(ev);
                        return;
                    }
                };
                let idx = d.index as usize;
                if self.blocks.len() <= idx {
                    self.blocks.resize(idx + 1, Block::default());
                }
                let b = &mut self.blocks[idx];
                b.dtype = dt;
                let had_held = !b.held.is_empty();
                self.p.clear();
                self.p.extend_from_slice(&b.held);
                self.p.extend_from_slice(s.as_bytes());
                self.e.clear();
                let (hold, replaced) = self.t.substitute(&mut self.e, &self.p, dt == 3);
                b.held.clear();
                b.held.extend_from_slice(&self.p[hold..]);
                if !had_held && !replaced && hold == self.p.len() {
                    dst.extend_from_slice(ev);
                    return;
                }
                if self.e.is_empty() {
                    return;
                }
                Self::write_delta(dst, idx, dt, &self.e);
            }
            b"content_block_stop" => {
                if let Ok(st) = serde_json::from_slice::<StopEv>(data)
                    && st.index >= 0
                    && st.index < MAX_INDEX
                    && (st.index as usize) < self.blocks.len()
                {
                    self.flush(dst, st.index as usize);
                }
                dst.extend_from_slice(ev);
            }
            _ => dst.extend_from_slice(ev),
        }
    }
}

// ---------------------------------------------------------------- fixtures

pub fn load_secrets(path: &str) -> (Vec<Vec<u8>>, Vec<u8>) {
    #[derive(Deserialize)]
    struct F {
        hmac_key_hex: String,
        secrets: Vec<String>,
    }
    let f: F = serde_json::from_slice(&std::fs::read(path).expect(path)).unwrap();
    (f.secrets.into_iter().map(String::into_bytes).collect(), hex::decode(f.hmac_key_hex).unwrap())
}

pub fn load_chunks(path: &str) -> Vec<usize> {
    std::fs::read_to_string(path).expect(path).split_whitespace().map(|l| l.parse().unwrap()).collect()
}

pub fn split_chunks<'a>(data: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
    let mut off = 0;
    sizes
        .iter()
        .map(|&n| {
            let c = &data[off..off + n];
            off += n;
            c
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_spec() {
        assert_eq!(json_escape(b"a/\"\\\n\x01\xc3\xa9", false, false), b"a/\\\"\\\\\\n\\u0001\xc3\xa9");
        assert_eq!(json_escape("é😀/".as_bytes(), true, true), b"\\u00e9\\ud83d\\ude00\\/");
    }

    #[test]
    fn split_placeholder_restored() {
        let key = b"k".to_vec();
        let secrets = vec![b"s3cr3t-value-123".to_vec()];
        let t = std::sync::Arc::new(Table::new(&secrets, &key));
        let ph = String::from_utf8(placeholder(&key, &secrets[0])).unwrap();
        let (a, b) = ph.split_at(10);
        let sse = format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"x{a}\"}}}}\n\nevent: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{b}y\"}}}}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n"
        );
        let mut r = Restorer::new(t.clone());
        let mut out = Vec::new();
        for c in sse.as_bytes().chunks(7) {
            r.feed(&mut out, c);
        }
        r.finish(&mut out);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("\"text\":\"x\""), "{s}");
        assert!(s.contains("s3cr3t-value-123y"), "{s}");
    }

    #[test]
    fn redact_roundtrip() {
        let key = b"k".to_vec();
        let secrets = vec![b"ghp_abcdefghijklmnopqrstuvwxyz0123456789".to_vec()];
        let r = Redactor::new(&secrets, &key, "ac-auto");
        let body = br#"{"t":"token ghp_abcdefghijklmnopqrstuvwxyz0123456789 end"}"#;
        let mut buf = Vec::new();
        let (o, n) = r.redact(body, &mut buf);
        assert_eq!(n, 1);
        assert_eq!(r.count(o), 0);
    }
}
