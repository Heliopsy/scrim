//! Finding placeholders in request bytes and writing real values in their place.
//!
//! Each placeholder is matched in the forms clients actually send: as written, percent-encoded
//! (fully, or only its non-ASCII bytes, in either hex case) and JSON-escaped with `\uXXXX`
//! (Python's default) with or without escaped slashes. The replacement is encoded to match the form
//! that was found and the [`Context`] it sits in, so a value with a quote lands in a JSON body as
//! `\"` and a value with `&` lands in a query string as `%26`.

use std::fmt::Write as _;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

use crate::credential::{CredentialSet, PlaceholderKind};
use crate::redactor::json_escape;

/// Everything except RFC 3986 unreserved characters is encoded.
pub(crate) const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// How a placeholder occurrence was encoded in the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Form {
    /// As written.
    Raw,
    /// Percent-encoded.
    Percent,
    /// JSON `\uXXXX` escapes.
    JsonEscaped,
}

/// The syntax around an occurrence, which decides how the value is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Context {
    /// A header value (after Basic decoding where applicable). Raw bytes, no line breaks.
    Header,
    /// A cookie header. Raw bytes, no `;`, no line breaks.
    Cookie,
    /// A URL path. Percent-encoded.
    Path,
    /// A URL query string or a form body. Percent-encoded.
    Query,
    /// A JSON document. String-escaped.
    Json,
    /// An XML document. Entity-escaped.
    Xml,
    /// Any other body. Raw bytes.
    Opaque,
}

/// One placeholder occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Hit {
    pub start: usize,
    pub end: usize,
    /// Index into [`CredentialSet::credentials`].
    pub credential: usize,
    /// Index into that credential's placeholders.
    pub placeholder: usize,
    pub form: Form,
}

struct Pattern {
    credential: usize,
    placeholder: usize,
    form: Form,
    /// Declared placeholders made of word characters must not be part of a longer word.
    word_bounded: bool,
}

/// Placeholder matcher for one credential set.
pub(crate) struct Injector {
    ac: Option<AhoCorasick>,
    patterns: Vec<Pattern>,
    max_len: usize,
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn percent_non_ascii(p: &[u8], upper: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in p {
        if b >= 0x80 || b == b' ' {
            if upper {
                out.extend_from_slice(format!("%{b:02X}").as_bytes());
            } else {
                out.extend_from_slice(format!("%{b:02x}").as_bytes());
            }
        } else {
            out.push(b);
        }
    }
    out
}

fn percent_full(p: &[u8], upper: bool) -> Vec<u8> {
    let s = percent_encoding::percent_encode(p, COMPONENT).to_string();
    if upper {
        s.into_bytes()
    } else {
        lower_hex_escapes(s.as_bytes())
    }
}

fn lower_hex_escapes(s: &[u8]) -> Vec<u8> {
    let mut out = s.to_vec();
    let mut i = 0;
    while i < out.len() {
        if out[i] == b'%' && i + 2 < out.len() {
            out[i + 1] = out[i + 1].to_ascii_lowercase();
            out[i + 2] = out[i + 2].to_ascii_lowercase();
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

/// `\uXXXX` for every non-ASCII code point (surrogate pairs above the BMP), like Python's
/// `json.dumps` default.
fn json_ascii(p: &str, upper: bool, escape_slash: bool) -> Vec<u8> {
    let mut out = String::new();
    for ch in p.chars() {
        if ch.is_ascii() {
            if ch == '/' && escape_slash {
                out.push_str("\\/");
            } else {
                out.push(ch);
            }
        } else {
            let mut buf = [0u16; 2];
            for unit in ch.encode_utf16(&mut buf) {
                if upper {
                    let _ = write!(out, "\\u{unit:04X}");
                } else {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.into_bytes()
}

impl Injector {
    pub(crate) fn new(set: &CredentialSet) -> Result<Self, aho_corasick::BuildError> {
        let mut texts: Vec<Vec<u8>> = Vec::new();
        let mut patterns = Vec::new();
        for (ci, cred) in set.credentials().iter().enumerate() {
            for (pi, ph) in cred.placeholders.iter().enumerate() {
                let raw = ph.text.as_bytes();
                let word_bounded = ph.kind == PlaceholderKind::Declared
                    && raw.first().copied().is_some_and(is_word)
                    && raw.last().copied().is_some_and(is_word);
                let mut variants: Vec<(Vec<u8>, Form)> = vec![(raw.to_vec(), Form::Raw)];
                for upper in [true, false] {
                    variants.push((percent_full(raw, upper), Form::Percent));
                    variants.push((percent_non_ascii(raw, upper), Form::Percent));
                    for slash in [false, true] {
                        variants.push((json_ascii(&ph.text, upper, slash), Form::JsonEscaped));
                    }
                }
                let mut seen: Vec<Vec<u8>> = Vec::new();
                for (v, form) in variants {
                    if seen.contains(&v) {
                        continue;
                    }
                    seen.push(v.clone());
                    texts.push(v);
                    patterns.push(Pattern {
                        credential: ci,
                        placeholder: pi,
                        form,
                        word_bounded,
                    });
                }
            }
        }
        let max_len = texts.iter().map(Vec::len).max().unwrap_or(0);
        let ac = if texts.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&texts)?,
            )
        };
        Ok(Self {
            ac,
            patterns,
            max_len,
        })
    }

    /// Longest pattern, for stream holdback.
    pub(crate) fn max_len(&self) -> usize {
        self.max_len
    }

    /// Every placeholder occurrence in `hay`.
    pub(crate) fn scan(&self, hay: &[u8]) -> Vec<Hit> {
        let Some(ac) = &self.ac else {
            return Vec::new();
        };
        let mut hits = Vec::new();
        for m in ac.find_iter(hay) {
            let p = &self.patterns[m.pattern().as_usize()];
            if p.word_bounded {
                let before = m.start().checked_sub(1).map(|i| hay[i]);
                let after = hay.get(m.end()).copied();
                if before.is_some_and(is_word) || after.is_some_and(is_word) {
                    continue;
                }
            }
            hits.push(Hit {
                start: m.start(),
                end: m.end(),
                credential: p.credential,
                placeholder: p.placeholder,
                form: p.form,
            });
        }
        hits
    }
}

/// The value cannot be written into this context without changing the message structure.
#[derive(Debug)]
pub(crate) struct Unrepresentable(pub &'static str);

/// Encodes `value` for an occurrence of `form` in `ctx`.
pub(crate) fn encode_value(
    value: &[u8],
    form: Form,
    ctx: Context,
) -> Result<Vec<u8>, Unrepresentable> {
    match form {
        Form::Percent => {
            return Ok(percent_encoding::percent_encode(value, COMPONENT)
                .to_string()
                .into_bytes());
        }
        Form::JsonEscaped => {
            let s = std::str::from_utf8(value)
                .map_err(|_| Unrepresentable("value is not UTF-8, cannot JSON-escape"))?;
            let mut out = String::with_capacity(s.len());
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    c if (c as u32) < 0x20 || !c.is_ascii() => {
                        let mut buf = [0u16; 2];
                        for unit in c.encode_utf16(&mut buf) {
                            let _ = write!(out, "\\u{unit:04x}");
                        }
                    }
                    c => out.push(c),
                }
            }
            return Ok(out.into_bytes());
        }
        Form::Raw => {}
    }
    match ctx {
        Context::Header => {
            if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
                return Err(Unrepresentable(
                    "value contains control characters, it cannot go into a header",
                ));
            }
            Ok(value.to_vec())
        }
        Context::Cookie => {
            if value.iter().any(|&b| b < 0x20 || b == 0x7f || b == b';') {
                return Err(Unrepresentable(
                    "value contains `;` or control characters, it cannot go into a cookie",
                ));
            }
            Ok(value.to_vec())
        }
        Context::Path | Context::Query => Ok(percent_encoding::percent_encode(value, COMPONENT)
            .to_string()
            .into_bytes()),
        Context::Json => {
            std::str::from_utf8(value)
                .map_err(|_| Unrepresentable("value is not UTF-8, cannot go into JSON"))?;
            Ok(json_escape(value))
        }
        Context::Xml => {
            std::str::from_utf8(value)
                .map_err(|_| Unrepresentable("value is not UTF-8, cannot go into XML"))?;
            let mut out = Vec::with_capacity(value.len());
            for &b in value {
                match b {
                    b'<' => out.extend_from_slice(b"&lt;"),
                    b'>' => out.extend_from_slice(b"&gt;"),
                    b'&' => out.extend_from_slice(b"&amp;"),
                    b'"' => out.extend_from_slice(b"&quot;"),
                    b'\'' => out.extend_from_slice(b"&apos;"),
                    b => out.push(b),
                }
            }
            Ok(out)
        }
        Context::Opaque => Ok(value.to_vec()),
    }
}

/// Writes `input` with every hit replaced by its credential's value, encoded for the context
/// `ctx_of` gives the hit.
pub(crate) fn substitute<'v>(
    input: &[u8],
    hits: &[Hit],
    ctx_of: &dyn Fn(&Hit) -> Context,
    value_of: &dyn Fn(usize) -> Option<&'v [u8]>,
) -> Result<Vec<u8>, Unrepresentable> {
    let mut out = Vec::with_capacity(input.len() + 64);
    let mut at = 0;
    for h in hits {
        out.extend_from_slice(&input[at..h.start]);
        let v = value_of(h.credential).ok_or(Unrepresentable("value unavailable"))?;
        out.extend_from_slice(&encode_value(v, h.form, ctx_of(h))?);
        at = h.end;
    }
    out.extend_from_slice(&input[at..]);
    Ok(out)
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
    use crate::credential::{BindingSpec, CredentialSpec};
    use crate::secret::SecretValue;

    fn set() -> CredentialSet {
        let mut b = CredentialSet::builder();
        b.add(
            CredentialSpec {
                name: "acme".into(),
                reference: "bao://kv/acme#key".into(),
                placeholders: vec!["SCRIM_ACME_KEY".into()],
                binding: Some(BindingSpec {
                    hosts: vec!["api.acme.test".into()],
                    ..Default::default()
                }),
                inject: vec!["anywhere".into()],
                aws_sigv4: None,
                client_certificate: false,
            },
            Some(SecretValue::new("real\"&val")),
            vec!["⟦scrim:acme:0123abcd⟧".into()],
        );
        b.build().unwrap()
    }

    #[test]
    fn finds_every_form() {
        let inj = Injector::new(&set()).unwrap();
        let cases: &[(&[u8], Form)] = &[
            ("x ⟦scrim:acme:0123abcd⟧ y".as_bytes(), Form::Raw),
            (
                b"q=%E2%9F%A6scrim%3Aacme%3A0123abcd%E2%9F%A7",
                Form::Percent,
            ),
            (b"q=%e2%9f%a6scrim:acme:0123abcd%e2%9f%a7", Form::Percent),
            (
                br#"{"k":"\u27e6scrim:acme:0123abcd\u27e7"}"#,
                Form::JsonEscaped,
            ),
            (
                br#"{"k":"\u27E6scrim:acme:0123abcd\u27E7"}"#,
                Form::JsonEscaped,
            ),
            (
                br#"{"k":"{{scrim:bao:\/\/kv\/acme#key}}"}"#,
                Form::JsonEscaped,
            ),
            (b"api_key: SCRIM_ACME_KEY\n", Form::Raw),
            (b"{{scrim:bao://kv/acme#key}}", Form::Raw),
            (
                b"%7B%7Bscrim%3Abao%3A%2F%2Fkv%2Facme%23key%7D%7D",
                Form::Percent,
            ),
        ];
        for (hay, form) in cases {
            let hits = inj.scan(hay);
            assert_eq!(hits.len(), 1, "{}", String::from_utf8_lossy(hay));
            assert_eq!(hits[0].form, *form, "{}", String::from_utf8_lossy(hay));
        }
    }

    #[test]
    fn declared_word_placeholders_respect_boundaries() {
        let inj = Injector::new(&set()).unwrap();
        assert!(inj.scan(b"SCRIM_ACME_KEY_2").is_empty());
        assert!(inj.scan(b"XSCRIM_ACME_KEY").is_empty());
        assert_eq!(inj.scan(b"\"SCRIM_ACME_KEY\"").len(), 1);
        assert_eq!(inj.scan(b"Bearer SCRIM_ACME_KEY").len(), 1);
    }

    #[test]
    fn encodes_per_context() {
        let v = b"real\"&val";
        assert_eq!(
            encode_value(v, Form::Raw, Context::Json).unwrap(),
            br#"real\"&val"#
        );
        assert_eq!(
            encode_value(v, Form::Raw, Context::Query).unwrap(),
            b"real%22%26val"
        );
        assert_eq!(
            encode_value(v, Form::Raw, Context::Xml).unwrap(),
            b"real&quot;&amp;val"
        );
        assert_eq!(encode_value(v, Form::Raw, Context::Header).unwrap(), v);
        assert_eq!(
            encode_value(v, Form::Percent, Context::Opaque).unwrap(),
            b"real%22%26val"
        );
        assert_eq!(
            encode_value("é\"".as_bytes(), Form::JsonEscaped, Context::Json).unwrap(),
            br#"\u00e9\""#
        );
        assert!(encode_value(b"a\r\nb", Form::Raw, Context::Header).is_err());
        assert!(encode_value(b"a;b", Form::Raw, Context::Cookie).is_err());
    }

    #[test]
    fn substitutes() {
        let s = set();
        let inj = Injector::new(&s).unwrap();
        let input = br#"{"a":"SCRIM_ACME_KEY","b":"\u27e6scrim:acme:0123abcd\u27e7"}"#;
        let hits = inj.scan(input);
        let out = substitute(input, &hits, &|_| Context::Json, &|i| {
            s.credentials()[i].value.as_ref().map(|v| v.expose())
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["a"], "real\"&val");
        assert_eq!(parsed["b"], "real\"&val");
    }
}
