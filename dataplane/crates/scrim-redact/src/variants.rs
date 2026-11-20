//! Encoded forms of a value that the redactor matches in raw request bytes (design D2).
//!
//! The redactor never decodes the request; instead every value is compiled together with the
//! byte strings it turns into under the encodings agents and their tools commonly apply.

use std::fmt;

/// Base64 alphabet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum B64Alphabet {
    /// RFC 4648 section 4 (`+`, `/`).
    Standard,
    /// RFC 4648 section 5 (`-`, `_`).
    UrlSafe,
}

/// One encoded form of a value. Reported in [`crate::Hit`] so audits can name the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Variant {
    /// The value's own bytes.
    Raw,
    /// JSON string content, minimal escaping (`"`, `\`, control characters).
    Json,
    /// JSON with `/` escaped as `\/` (PHP, some Java encoders).
    JsonSlash,
    /// JSON with non-ASCII escaped as lowercase `\uXXXX` (Python `ensure_ascii`).
    JsonAscii,
    /// JSON with non-ASCII escaped as lowercase `\uXXXX` and `/` as `\/` (PHP default).
    JsonAsciiSlash,
    /// JSON with every `\u` escape in uppercase hex.
    JsonAsciiUpper,
    /// JSON with `<`, `>`, `&`, U+2028 and U+2029 escaped (Go `encoding/json`).
    JsonHtml,
    /// JSON with `<`, `>`, `&`, `=`, `'`, U+2028 and U+2029 escaped (Gson).
    JsonHtmlGson,
    /// Minimal JSON escaping applied twice (JSON text embedded in a JSON string).
    JsonDouble,
    /// The stable inner substring of the value base64-encoded at byte offset `offset` (0 to 2)
    /// inside a longer stream: every character whose six bits come only from the value.
    Base64 {
        /// Alphabet.
        alphabet: B64Alphabet,
        /// Byte offset of the value within its 3-byte group.
        offset: u8,
    },
    /// The complete base64 encoding of the value on its own (used for short values, which are not
    /// matched as inner fragments).
    Base64Whole {
        /// Alphabet.
        alphabet: B64Alphabet,
        /// Whether `=` padding is included.
        padded: bool,
    },
    /// Lowercase hexadecimal.
    HexLower,
    /// Uppercase hexadecimal.
    HexUpper,
    /// Percent-encoding of everything but RFC 3986 unreserved characters, `%2F` style.
    UrlUpper,
    /// As [`Variant::UrlUpper`] with lowercase hex digits, `%2f` style.
    UrlLower,
    /// `application/x-www-form-urlencoded`: space as `+`, uppercase hex.
    UrlForm,
    /// Percent-encoding that keeps `/` (Python `urllib.parse.quote`).
    UrlKeepSlash,
    /// Percent-encoding that keeps `!'()*` (JavaScript `encodeURIComponent`).
    UrlComponent,
}

impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Raw => "raw",
            Self::Json => "json",
            Self::JsonSlash => "json-slash",
            Self::JsonAscii => "json-ascii",
            Self::JsonAsciiSlash => "json-ascii-slash",
            Self::JsonAsciiUpper => "json-ascii-upper",
            Self::JsonHtml => "json-html",
            Self::JsonHtmlGson => "json-html-gson",
            Self::JsonDouble => "json-double",
            Self::Base64 {
                alphabet: B64Alphabet::Standard,
                offset,
            } => return write!(f, "base64-{offset}"),
            Self::Base64 {
                alphabet: B64Alphabet::UrlSafe,
                offset,
            } => return write!(f, "base64url-{offset}"),
            Self::Base64Whole {
                alphabet: B64Alphabet::Standard,
                padded: true,
            } => "base64-whole-padded",
            Self::Base64Whole {
                alphabet: B64Alphabet::Standard,
                padded: false,
            } => "base64-whole",
            Self::Base64Whole {
                alphabet: B64Alphabet::UrlSafe,
                padded: true,
            } => "base64url-whole-padded",
            Self::Base64Whole {
                alphabet: B64Alphabet::UrlSafe,
                padded: false,
            } => "base64url-whole",
            Self::HexLower => "hex",
            Self::HexUpper => "hex-upper",
            Self::UrlUpper => "url",
            Self::UrlLower => "url-lower",
            Self::UrlForm => "url-form",
            Self::UrlKeepSlash => "url-keep-slash",
            Self::UrlComponent => "url-component",
        };
        f.write_str(s)
    }
}

const LHEX: &[u8; 16] = b"0123456789abcdef";
const UHEX: &[u8; 16] = b"0123456789ABCDEF";
const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
struct JsonStyle {
    slash: bool,
    ascii: bool,
    upper: bool,
    html: bool,
    gson: bool,
}

/// Appends `s` as JSON string content (without quotes), minimal escaping.
///
/// This is the encoder the stream restorer uses to re-encode restored text.
pub fn json_escape_into(out: &mut Vec<u8>, s: &[u8]) {
    json_escape_styled(out, s, JsonStyle::default());
}

fn push_u4(out: &mut Vec<u8>, x: u32, upper: bool) {
    let h = if upper { UHEX } else { LHEX };
    out.extend_from_slice(b"\\u");
    for sh in [12, 8, 4, 0] {
        out.push(h[((x >> sh) & 15) as usize]);
    }
}

fn json_escape_styled(out: &mut Vec<u8>, s: &[u8], st: JsonStyle) {
    // Non-ASCII handling needs whole characters; invalid UTF-8 is copied as is.
    let text = if st.ascii || st.html {
        std::str::from_utf8(s).ok()
    } else {
        None
    };
    if let Some(text) = text {
        for ch in text.chars() {
            let c = ch as u32;
            if c < 0x80 {
                json_escape_ascii(out, c as u8, st);
            } else if st.ascii || (st.html && (c == 0x2028 || c == 0x2029)) {
                if c >= 0x10000 {
                    let r = c - 0x10000;
                    push_u4(out, 0xD800 + (r >> 10), st.upper);
                    push_u4(out, 0xDC00 + (r & 0x3FF), st.upper);
                } else {
                    push_u4(out, c, st.upper);
                }
            } else {
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }
        return;
    }
    for &c in s {
        if c < 0x80 {
            json_escape_ascii(out, c, st);
        } else {
            out.push(c);
        }
    }
}

fn json_escape_ascii(out: &mut Vec<u8>, c: u8, st: JsonStyle) {
    match c {
        b'"' => out.extend_from_slice(b"\\\""),
        b'\\' => out.extend_from_slice(b"\\\\"),
        b'/' if st.slash => out.extend_from_slice(b"\\/"),
        b'\n' => out.extend_from_slice(b"\\n"),
        b'\r' => out.extend_from_slice(b"\\r"),
        b'\t' => out.extend_from_slice(b"\\t"),
        0x08 => out.extend_from_slice(b"\\b"),
        0x0c => out.extend_from_slice(b"\\f"),
        b'<' | b'>' | b'&' if st.html => push_u4(out, u32::from(c), st.upper),
        b'=' | b'\'' if st.gson => push_u4(out, u32::from(c), st.upper),
        0..0x20 => push_u4(out, u32::from(c), st.upper),
        _ => out.push(c),
    }
}

/// The stable inner base64 substring of `v` placed at byte offset `k` of a stream.
fn b64_stable(alpha: &[u8; 64], v: &[u8], k: usize) -> Vec<u8> {
    let total = k + v.len();
    let mut full = Vec::with_capacity(total.div_ceil(3) * 4);
    let mut i = 0;
    let byte = |j: usize| if j < k { 0 } else { v[j - k] };
    while i < total {
        let n = (total - i).min(3);
        let b0 = u32::from(byte(i));
        let b1 = if n > 1 { u32::from(byte(i + 1)) } else { 0 };
        let b2 = if n > 2 { u32::from(byte(i + 2)) } else { 0 };
        let x = (b0 << 16) | (b1 << 8) | b2;
        for q in 0..=n {
            full.push(alpha[((x >> (18 - 6 * q)) & 63) as usize]);
        }
        i += 3;
    }
    // Characters fully inside the value's bits: from ceil(8k/6) to floor(8(k+len)/6).
    let js = (8 * k).div_ceil(6);
    let je = (8 * total) / 6;
    if je <= js {
        return Vec::new();
    }
    full[js..je].to_vec()
}

fn b64_whole(alpha: &[u8; 64], v: &[u8], padded: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len().div_ceil(3) * 4);
    for ch in v.chunks(3) {
        let b0 = u32::from(ch[0]);
        let b1 = ch.get(1).map_or(0, |&b| u32::from(b));
        let b2 = ch.get(2).map_or(0, |&b| u32::from(b));
        let x = (b0 << 16) | (b1 << 8) | b2;
        for q in 0..=ch.len() {
            out.push(alpha[((x >> (18 - 6 * q)) & 63) as usize]);
        }
        if padded {
            out.extend(std::iter::repeat_n(b'=', 3 - ch.len()));
        }
    }
    out
}

fn hex(v: &[u8], upper: bool) -> Vec<u8> {
    let h = if upper { UHEX } else { LHEX };
    let mut out = Vec::with_capacity(v.len() * 2);
    for &b in v {
        out.push(h[usize::from(b >> 4)]);
        out.push(h[usize::from(b & 15)]);
    }
    out
}

#[derive(Clone, Copy)]
enum UrlStyle {
    Upper,
    Lower,
    Form,
    KeepSlash,
    Component,
}

fn url(v: &[u8], style: UrlStyle) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 3);
    for &c in v {
        let keep = c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'.' | b'_' | b'~')
            || (matches!(style, UrlStyle::KeepSlash) && c == b'/')
            || (matches!(style, UrlStyle::Component)
                && matches!(c, b'!' | b'\'' | b'(' | b')' | b'*'));
        if keep {
            out.push(c);
        } else if c == b' ' && matches!(style, UrlStyle::Form) {
            out.push(b'+');
        } else {
            let h = if matches!(style, UrlStyle::Lower) {
                LHEX
            } else {
                UHEX
            };
            out.extend_from_slice(&[b'%', h[usize::from(c >> 4)], h[usize::from(c & 15)]]);
        }
    }
    out
}

fn json_variant(v: &[u8], st: JsonStyle) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() + 8);
    json_escape_styled(&mut out, v, st);
    out
}

/// Every encoded form of `v` that the redactor matches, in a fixed order, duplicates removed
/// (the first variant producing given bytes wins). `short` selects the short-value rule: verbatim
/// and whole encodings only, never inner base64 fragments.
pub(crate) fn variants(v: &[u8], short: bool) -> Vec<(Variant, Vec<u8>)> {
    use B64Alphabet::{Standard, UrlSafe};
    let mut out: Vec<(Variant, Vec<u8>)> = Vec::with_capacity(24);
    let mut push = |k: Variant, b: Vec<u8>| {
        if !b.is_empty() && !out.iter().any(|(_, x)| *x == b) {
            out.push((k, b));
        }
    };
    let d = JsonStyle::default();
    push(Variant::Raw, v.to_vec());
    push(Variant::Json, json_variant(v, d));
    push(
        Variant::JsonSlash,
        json_variant(v, JsonStyle { slash: true, ..d }),
    );
    push(
        Variant::JsonAscii,
        json_variant(v, JsonStyle { ascii: true, ..d }),
    );
    push(
        Variant::JsonAsciiSlash,
        json_variant(
            v,
            JsonStyle {
                ascii: true,
                slash: true,
                ..d
            },
        ),
    );
    push(
        Variant::JsonAsciiUpper,
        json_variant(
            v,
            JsonStyle {
                ascii: true,
                upper: true,
                ..d
            },
        ),
    );
    push(
        Variant::JsonHtml,
        json_variant(v, JsonStyle { html: true, ..d }),
    );
    push(
        Variant::JsonHtmlGson,
        json_variant(
            v,
            JsonStyle {
                html: true,
                gson: true,
                ..d
            },
        ),
    );
    let once = json_variant(v, d);
    push(Variant::JsonDouble, json_variant(&once, d));
    if short {
        for (alphabet, table) in [(Standard, B64_STD), (UrlSafe, B64_URL)] {
            for padded in [true, false] {
                push(
                    Variant::Base64Whole { alphabet, padded },
                    b64_whole(table, v, padded),
                );
            }
        }
    } else {
        for (alphabet, table) in [(Standard, B64_STD), (UrlSafe, B64_URL)] {
            for offset in 0..3u8 {
                push(
                    Variant::Base64 { alphabet, offset },
                    b64_stable(table, v, usize::from(offset)),
                );
            }
        }
    }
    push(Variant::HexLower, hex(v, false));
    push(Variant::HexUpper, hex(v, true));
    push(Variant::UrlUpper, url(v, UrlStyle::Upper));
    push(Variant::UrlLower, url(v, UrlStyle::Lower));
    push(Variant::UrlForm, url(v, UrlStyle::Form));
    push(Variant::UrlKeepSlash, url(v, UrlStyle::KeepSlash));
    push(Variant::UrlComponent, url(v, UrlStyle::Component));
    out
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

    fn get(v: &[u8], short: bool, k: Variant) -> Option<Vec<u8>> {
        variants(v, short)
            .into_iter()
            .find(|(x, _)| *x == k)
            .map(|(_, b)| b)
    }

    fn std_b64(data: &[u8]) -> Vec<u8> {
        b64_whole(B64_STD, data, true)
    }

    #[test]
    fn json_forms() {
        let v = "a/\"\\\n\u{1}é😀<=".as_bytes();
        assert_eq!(
            get(v, false, Variant::Json).unwrap(),
            b"a/\\\"\\\\\\n\\u0001\xc3\xa9\xf0\x9f\x98\x80<="
        );
        assert_eq!(
            get(v, false, Variant::JsonSlash).unwrap(),
            "a\\/\\\"\\\\\\n\\u0001é😀<=".as_bytes()
        );
        assert_eq!(
            get(v, false, Variant::JsonAscii).unwrap(),
            b"a/\\\"\\\\\\n\\u0001\\u00e9\\ud83d\\ude00<="
        );
        assert_eq!(
            get(v, false, Variant::JsonAsciiSlash).unwrap(),
            b"a\\/\\\"\\\\\\n\\u0001\\u00e9\\ud83d\\ude00<="
        );
        assert_eq!(
            get(v, false, Variant::JsonAsciiUpper).unwrap(),
            b"a/\\\"\\\\\\n\\u0001\\u00E9\\uD83D\\uDE00<="
        );
        assert_eq!(
            get(v, false, Variant::JsonHtml).unwrap(),
            "a/\\\"\\\\\\n\\u0001é😀\\u003c=".as_bytes()
        );
        assert_eq!(
            get(v, false, Variant::JsonHtmlGson).unwrap(),
            "a/\\\"\\\\\\n\\u0001é😀\\u003c\\u003d".as_bytes()
        );
        assert_eq!(
            get(b"p\"w", false, Variant::JsonDouble).unwrap(),
            b"p\\\\\\\"w"
        );
    }

    #[test]
    fn plain_value_dedups() {
        // A base62 value has identical raw, JSON and URL forms: only one survives.
        let vs = variants(b"Zyxwvu0123456789", false);
        let kinds: Vec<_> = vs.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds[0], Variant::Raw);
        assert!(!kinds.contains(&Variant::Json));
        assert!(!kinds.contains(&Variant::UrlUpper));
        assert!(kinds.contains(&Variant::HexLower));
        assert!(kinds.contains(&Variant::HexUpper));
    }

    #[test]
    fn base64_stable_inner_at_every_offset() {
        let v = b"s3cr3t-v@lue-with/odd+bytes\xff";
        for offset in 0..3u8 {
            for (alphabet, table) in [
                (B64Alphabet::Standard, B64_STD),
                (B64Alphabet::UrlSafe, B64_URL),
            ] {
                let inner = b64_stable(table, v, usize::from(offset));
                for pre in [0usize, 3, 6] {
                    for post in [0usize, 1, 2, 5] {
                        let mut stream = vec![b'x'; pre + usize::from(offset)];
                        stream.extend_from_slice(v);
                        stream.extend(std::iter::repeat_n(b'y', post));
                        let enc = b64_whole(table, &stream, true);
                        assert!(
                            enc.windows(inner.len()).any(|w| w == inner.as_slice()),
                            "{alphabet:?} offset {offset} pre {pre} post {post}"
                        );
                    }
                }
                assert!(!inner.is_empty());
            }
        }
    }

    #[test]
    fn base64_whole_for_short() {
        assert_eq!(std_b64(b"hunter2"), b"aHVudGVyMg==");
        let vs = variants(b"hunter2", true);
        assert!(vs.iter().any(
            |(k, b)| matches!(k, Variant::Base64Whole { padded: true, .. }) && b == b"aHVudGVyMg=="
        ));
        assert!(vs.iter().any(
            |(k, b)| matches!(k, Variant::Base64Whole { padded: false, .. }) && b == b"aHVudGVyMg"
        ));
        assert!(!vs.iter().any(|(k, _)| matches!(k, Variant::Base64 { .. })));
    }

    #[test]
    fn hex_and_url() {
        assert_eq!(
            get(b"a/b c+\xff", false, Variant::HexLower).unwrap(),
            b"612f6220632bff"
        );
        assert_eq!(
            get(b"a/b c+\xff", false, Variant::HexUpper).unwrap(),
            b"612F6220632BFF"
        );
        assert_eq!(
            get(b"a/b c+'", false, Variant::UrlUpper).unwrap(),
            b"a%2Fb%20c%2B%27"
        );
        assert_eq!(
            get(b"a/b c+'", false, Variant::UrlLower).unwrap(),
            b"a%2fb%20c%2b%27"
        );
        assert_eq!(
            get(b"a/b c+'", false, Variant::UrlForm).unwrap(),
            b"a%2Fb+c%2B%27"
        );
        assert_eq!(
            get(b"a/b c+'", false, Variant::UrlKeepSlash).unwrap(),
            b"a/b%20c%2B%27"
        );
        assert_eq!(
            get(b"a/b c+'", false, Variant::UrlComponent).unwrap(),
            b"a%2Fb%20c%2B'"
        );
    }

    #[test]
    fn edge_lengths() {
        for len in 1..=12 {
            let v: Vec<u8> = (0..len).map(|i| b'A' + i as u8).collect();
            for short in [false, true] {
                for (k, b) in variants(&v, short) {
                    assert!(!b.is_empty(), "{k} len {len}");
                }
            }
            // An offset-2 inner substring exists for every length >= 1 once at least one full
            // character fits; for length 1 at offset 1 or 2 it may legitimately be empty and is
            // then dropped.
            let inner2 = b64_stable(B64_STD, &v, 2);
            assert_eq!(inner2.len(), (8 * (2 + len)) / 6 - 16usize.div_ceil(6));
        }
    }
}
