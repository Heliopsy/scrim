//! The seam to the redaction core, and streaming redaction over it.
//!
//! The tool proxy does not own value matching. It asks a [`Redactor`] for the matches in a byte
//! slice and replaces them; the data plane passes the `scrim-redact` matcher here. Until that
//! crate is wired in, [`ValueRedactor`] is a small exact matcher over the credential values and a
//! few encodings, enough to keep the proxy fail-closed on its own.
//!
//! [`StreamRedactor`] makes any redactor work over a stream: it holds back the last
//! `max_match_len - 1` bytes of each chunk, so a value split across chunks is still found.

use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine as _;

use crate::secret::SecretValue;

/// A match: `haystack[start..end]` is replaced by `replacement`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactMatch {
    /// Start offset, inclusive.
    pub start: usize,
    /// End offset, exclusive.
    pub end: usize,
    /// Placeholder bytes to write instead.
    pub replacement: Arc<[u8]>,
}

/// Redaction failed. The caller withholds the data.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("redaction failed: {0}")]
pub struct RedactError(pub String);

/// Finds known values in bytes.
///
/// Implementations return non-overlapping matches in ascending order, leftmost-longest, and never
/// a match longer than [`Redactor::max_match_len`]. They must be deterministic: the same input
/// gives the same matches.
pub trait Redactor: Send + Sync + 'static {
    /// Whether the set of known values has loaded. The proxy refuses traffic until it has.
    fn is_ready(&self) -> bool {
        true
    }

    /// Length in bytes of the longest sequence this redactor can match. Zero when it holds no
    /// values.
    fn max_match_len(&self) -> usize;

    /// Appends the matches in `haystack` to `out`.
    fn find(&self, haystack: &[u8], out: &mut Vec<RedactMatch>) -> Result<(), RedactError>;
}

/// Redacts `input` fully. Returns `None` when nothing matched, so the caller can keep the original
/// bytes untouched.
pub fn redact_all(r: &dyn Redactor, input: &[u8]) -> Result<Option<(Vec<u8>, usize)>, RedactError> {
    let mut matches = Vec::new();
    r.find(input, &mut matches)?;
    if matches.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(input.len());
    let mut at = 0;
    for m in &matches {
        if m.start < at || m.end > input.len() || m.start >= m.end {
            return Err(RedactError(
                "redactor returned overlapping or out-of-range matches".into(),
            ));
        }
        out.extend_from_slice(&input[at..m.start]);
        out.extend_from_slice(&m.replacement);
        at = m.end;
    }
    out.extend_from_slice(&input[at..]);
    Ok(Some((out, matches.len())))
}

/// Applies several redactors in order (for example the redaction core, then values captured by
/// this proxy that the core has not received yet).
#[derive(Clone, Default)]
pub struct RedactorChain(pub Vec<Arc<dyn Redactor>>);

impl RedactorChain {
    /// Redacts `input` through every stage. `None` when nothing matched.
    pub fn redact_all(&self, input: &[u8]) -> Result<Option<(Vec<u8>, usize)>, RedactError> {
        let mut cur: Option<Vec<u8>> = None;
        let mut total = 0;
        for r in &self.0 {
            let src = cur.as_deref().unwrap_or(input);
            if let Some((out, n)) = redact_all(r.as_ref(), src)? {
                total += n;
                cur = Some(out);
            }
        }
        Ok(cur.map(|c| (c, total)))
    }

    /// Whether every stage is ready.
    pub fn is_ready(&self) -> bool {
        self.0.iter().all(|r| r.is_ready())
    }

    /// One [`StreamRedactor`] per stage, to be fed in sequence.
    pub fn stream(&self) -> Vec<StreamRedactor> {
        self.0
            .iter()
            .map(|r| StreamRedactor::new(r.clone()))
            .collect()
    }
}

/// Streaming wrapper around a [`Redactor`] with a holdback of `max_match_len - 1` bytes.
pub struct StreamRedactor {
    inner: Arc<dyn Redactor>,
    pending: Vec<u8>,
    replaced: usize,
}

impl StreamRedactor {
    /// Wraps `inner`.
    pub fn new(inner: Arc<dyn Redactor>) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            replaced: 0,
        }
    }

    /// Number of replacements made so far.
    pub fn replaced(&self) -> usize {
        self.replaced
    }

    /// Feeds a chunk and appends every byte that can no longer be part of a match to `out`.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), RedactError> {
        self.pending.extend_from_slice(chunk);
        let max = self.inner.max_match_len();
        if max == 0 {
            out.append(&mut self.pending);
            return Ok(());
        }
        let len = self.pending.len();
        if len < max {
            return Ok(());
        }
        // Every match starting before `boundary` lies wholly inside `pending`, because no match is
        // longer than `max`. Matches starting at or after it may still grow and wait.
        let boundary = len - (max - 1);
        let mut matches = Vec::new();
        self.inner.find(&self.pending, &mut matches)?;
        let mut at = 0;
        for m in matches.iter().filter(|m| m.start < boundary) {
            if m.start < at || m.end > len || m.start >= m.end {
                return Err(RedactError(
                    "redactor returned overlapping or out-of-range matches".into(),
                ));
            }
            out.extend_from_slice(&self.pending[at..m.start]);
            out.extend_from_slice(&m.replacement);
            at = m.end;
            self.replaced += 1;
        }
        let emit_to = boundary.max(at);
        out.extend_from_slice(&self.pending[at..emit_to]);
        self.pending.drain(..emit_to);
        Ok(())
    }

    /// Flushes the held-back tail at the end of the stream.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), RedactError> {
        let rest = std::mem::take(&mut self.pending);
        match redact_all(self.inner.as_ref(), &rest)? {
            Some((red, n)) => {
                self.replaced += n;
                out.extend_from_slice(&red);
            }
            None => out.extend_from_slice(&rest),
        }
        Ok(())
    }
}

/// Exact matcher over a list of values and their common encodings (raw, JSON-escaped,
/// percent-encoded, base64 standard and URL-safe). A stand-in for the redaction core: it does not
/// cover base64 at every alignment or hex, which `scrim-redact` does.
pub struct ValueRedactor {
    ac: Option<AhoCorasick>,
    replacements: Vec<Arc<[u8]>>,
    max_len: usize,
}

impl ValueRedactor {
    /// A matcher that matches nothing.
    pub fn empty() -> Self {
        Self {
            ac: None,
            replacements: Vec::new(),
            max_len: 0,
        }
    }

    /// Builds a matcher. Each entry is a value and the placeholder that replaces it. Fails only
    /// when the pattern set exceeds the automaton's size limits.
    pub fn new<'a>(
        entries: impl IntoIterator<Item = (&'a SecretValue, &'a [u8])>,
    ) -> Result<Self, RedactError> {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut replacements = Vec::new();
        for (value, placeholder) in entries {
            let v = value.expose();
            if v.is_empty() {
                continue;
            }
            let ph: Arc<[u8]> = Arc::from(placeholder);
            let mut variants = vec![v.to_vec(), json_escape(v), percent_component(v)];
            let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(v);
            let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
            variants.push(b64.into_bytes());
            variants.push(b64url.into_bytes());
            variants.sort();
            variants.dedup();
            for var in variants {
                patterns.push(var);
                replacements.push(ph.clone());
            }
        }
        let max_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let ac = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&patterns)
                    .map_err(|e| RedactError(format!("building the value matcher failed: {e}")))?,
            )
        };
        Ok(Self {
            ac,
            replacements,
            max_len,
        })
    }
}

impl Redactor for ValueRedactor {
    fn max_match_len(&self) -> usize {
        self.max_len
    }

    fn find(&self, haystack: &[u8], out: &mut Vec<RedactMatch>) -> Result<(), RedactError> {
        if let Some(ac) = &self.ac {
            for m in ac.find_iter(haystack) {
                out.push(RedactMatch {
                    start: m.start(),
                    end: m.end(),
                    replacement: self.replacements[m.pattern().as_usize()].clone(),
                });
            }
        }
        Ok(())
    }
}

/// JSON string-content escaping (quotes, backslash, control characters). Non-ASCII stays as is.
pub(crate) fn json_escape(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() + 2);
    for &b in v {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b if b < 0x20 => out.extend_from_slice(format!("\\u{b:04x}").as_bytes()),
            b => out.push(b),
        }
    }
    out
}

/// Percent-encodes everything except RFC 3986 unreserved characters.
pub(crate) fn percent_component(v: &[u8]) -> Vec<u8> {
    percent_encoding::percent_encode(v, crate::inject::COMPONENT)
        .to_string()
        .into_bytes()
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

    fn redactor(values: &[(&str, &str)]) -> Arc<dyn Redactor> {
        let vals: Vec<(SecretValue, Vec<u8>)> = values
            .iter()
            .map(|(v, p)| (SecretValue::new(*v), p.as_bytes().to_vec()))
            .collect();
        Arc::new(ValueRedactor::new(vals.iter().map(|(v, p)| (v, p.as_slice()))).unwrap())
    }

    #[test]
    fn whole_buffer() {
        let r = redactor(&[("s3cr3t-value-1", "⟦P1⟧")]);
        let (out, n) = redact_all(r.as_ref(), b"a s3cr3t-value-1 b")
            .unwrap()
            .unwrap();
        assert_eq!(out, "a ⟦P1⟧ b".as_bytes());
        assert_eq!(n, 1);
        assert!(redact_all(r.as_ref(), b"nothing here").unwrap().is_none());
    }

    #[test]
    fn encoded_variants() {
        let r = redactor(&[("pa\"ss/word+1", "<P>")]);
        let cases: &[&[u8]] = &[
            br#"{"x":"pa\"ss/word+1"}"#,
            b"q=pa%22ss%2Fword%2B1",
            b"cGEic3Mvd29yZCsx",
        ];
        for c in cases {
            let (out, _) = redact_all(r.as_ref(), c).unwrap().expect("matched");
            assert!(
                String::from_utf8_lossy(&out).contains("<P>"),
                "{}",
                String::from_utf8_lossy(c)
            );
        }
    }

    #[test]
    fn stream_matches_whole_buffer_for_every_split() {
        let r = redactor(&[("abcdefgh-secret", "[A]"), ("zz-other-secret-zz", "[B]")]);
        let input = b"xx abcdefgh-secret yy zz-other-secret-zz abcdefgh-secretabcdefgh-secret end";
        let (expected, _) = redact_all(r.as_ref(), input).unwrap().unwrap();
        for split in 0..input.len() {
            for split2 in split..input.len() {
                let mut s = StreamRedactor::new(r.clone());
                let mut out = Vec::new();
                s.push(&input[..split], &mut out).unwrap();
                s.push(&input[split..split2], &mut out).unwrap();
                s.push(&input[split2..], &mut out).unwrap();
                s.finish(&mut out).unwrap();
                assert_eq!(out, expected, "split at {split}/{split2}");
                assert_eq!(s.replaced(), 4);
            }
        }
    }

    #[test]
    fn byte_by_byte_stream() {
        let r = redactor(&[("abcdefgh-secret", "[A]")]);
        let input = b"abcdefgh-secre abcdefgh-secret";
        let mut s = StreamRedactor::new(r.clone());
        let mut out = Vec::new();
        for b in input {
            s.push(std::slice::from_ref(b), &mut out).unwrap();
        }
        s.finish(&mut out).unwrap();
        assert_eq!(out, b"abcdefgh-secre [A]");
    }

    #[test]
    fn chain_applies_in_order() {
        let chain = RedactorChain(vec![
            redactor(&[("first-secret", "[1]")]),
            redactor(&[("second-secret", "[2]")]),
        ]);
        let (out, n) = chain
            .redact_all(b"first-secret second-secret")
            .unwrap()
            .unwrap();
        assert_eq!(out, b"[1] [2]");
        assert_eq!(n, 2);
    }
}
