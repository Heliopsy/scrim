//! Deterministic placeholders and the versioned key that makes them.
//!
//! Format (UTF-8): `⟦scrim:<slug>:<vv><tag>⟧`
//!
//! * `⟦` is U+27E6 (`E2 9F A6`), `⟧` is U+27E7 (`E2 9F A7`).
//! * `<slug>` is the reference alias, `[a-z0-9-]{1,48}`, see [`crate::RefSlug`].
//! * `<vv>` is the key version as two lowercase hex digits, `01` to `ff`.
//! * `<tag>` is the first 8 bytes of `HMAC-SHA256(key_vv, "scrim-placeholder-v1" || 0x00 ||
//!   value)` as 16 lowercase hex digits.
//!
//! The longest placeholder is [`MAX_PLACEHOLDER_LEN`] bytes. Nothing in it needs escaping in JSON
//! strings, shell words (quoted or not), YAML plain scalars, Markdown or source-code string
//! literals, and it contains no whitespace, so tokenisers and compressors keep it whole.
//!
//! Percent form (ASCII): `%E2%9F%A6scrim:<slug>:<vv><tag>%E2%9F%A7`, the same placeholder with
//! its two brackets percent-encoded (hex digits of the brackets in either case). It is what an
//! HTTP request target or header value carries, since those are visible ASCII. It names the same
//! entry, so everything that parses placeholders here accepts both forms; where a percent-form
//! placeholder is replaced by its value, the value is percent-encoded too. The longest one is
//! [`MAX_PERCENT_PLACEHOLDER_LEN`] bytes.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::BuildError;
use crate::secret::{RefSlug, is_slug_byte};

/// `⟦scrim:`
pub(crate) const OPEN: &[u8] = "\u{27e6}scrim:".as_bytes();
/// `⟧`
pub(crate) const CLOSE: &[u8] = "\u{27e7}".as_bytes();
/// First byte of `⟦`, used to find candidate placeholders quickly.
pub(crate) const LEAD: u8 = 0xE2;
/// `%E2%9F%A6scrim:`, the opening of the percent form.
const PCT_OPEN: &[u8] = b"%E2%9F%A6scrim:";
/// `%E2%9F%A7`, the closing of the percent form.
const PCT_CLOSE: &[u8] = b"%E2%9F%A7";
/// First byte of the percent form.
pub(crate) const PCT_LEAD: u8 = b'%';
/// Leading bytes of each delimiter whose hex digits may be in either case.
const PCT_FOLD: usize = 9;
/// Hex digits after the slug separator: 2 for the version, 16 for the tag.
pub(crate) const CODE_LEN: usize = 18;
const TAG_BYTES: usize = 8;
const DOMAIN: &[u8] = b"scrim-placeholder-v1\0";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Length in bytes of the longest possible placeholder (slug of [`RefSlug::MAX_LEN`] bytes).
pub const MAX_PLACEHOLDER_LEN: usize = OPEN.len() + RefSlug::MAX_LEN + 1 + CODE_LEN + CLOSE.len();
/// Length in bytes of the shortest possible placeholder (one-byte slug).
pub const MIN_PLACEHOLDER_LEN: usize = OPEN.len() + 1 + 1 + CODE_LEN + CLOSE.len();
/// Length in bytes of the longest possible placeholder in percent form. Streaming callers that
/// accept both forms hold back at most this many bytes minus one.
pub const MAX_PERCENT_PLACEHOLDER_LEN: usize =
    PCT_OPEN.len() + RefSlug::MAX_LEN + 1 + CODE_LEN + PCT_CLOSE.len();

/// One version of the placeholder key. The key bytes are wiped on drop and never printed.
pub struct PlaceholderKey {
    version: u8,
    key: Zeroizing<Vec<u8>>,
}

impl PlaceholderKey {
    /// Creates key `version` (1 to 255) from `key` bytes (at least 16, 32 recommended).
    pub fn new(version: u8, key: &[u8]) -> Result<Self, BuildError> {
        if version == 0 {
            return Err(BuildError::InvalidKeyVersion);
        }
        if key.len() < 16 {
            return Err(BuildError::InvalidConfig(
                "placeholder key shorter than 16 bytes",
            ));
        }
        Ok(Self {
            version,
            key: Zeroizing::new(key.to_vec()),
        })
    }

    /// The key version.
    pub fn version(&self) -> u8 {
        self.version
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.key
    }

    pub(crate) fn tag(&self, value: &[u8]) -> [u8; TAG_BYTES] {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key)
            .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
        m.update(DOMAIN);
        m.update(value);
        let full = m.finalize().into_bytes();
        let mut t = [0u8; TAG_BYTES];
        t.copy_from_slice(&full[..TAG_BYTES]);
        t
    }
}

impl fmt::Debug for PlaceholderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlaceholderKey(v{}, <redacted>)", self.version)
    }
}

/// The current placeholder key plus older keys retained so their placeholders still resolve.
///
/// Rotation: build a new keyring with the new key as current and the previous current key
/// retained, then build and swap a new snapshot. New placeholders use the current key; any
/// placeholder made with a retained key resolves until that key is dropped from the ring.
#[derive(Debug)]
pub struct Keyring {
    current: PlaceholderKey,
    retained: Vec<PlaceholderKey>,
}

impl Keyring {
    /// A keyring with only `current`.
    pub fn new(current: PlaceholderKey) -> Self {
        Self {
            current,
            retained: Vec::new(),
        }
    }

    /// Adds an older key that still resolves.
    pub fn retain(mut self, older: PlaceholderKey) -> Result<Self, BuildError> {
        if older.version == self.current.version
            || self.retained.iter().any(|k| k.version == older.version)
        {
            return Err(BuildError::DuplicateKeyVersion);
        }
        self.retained.push(older);
        Ok(self)
    }

    /// The key new placeholders are made with.
    pub fn current(&self) -> &PlaceholderKey {
        &self.current
    }

    /// Current key first, then retained keys.
    pub fn keys(&self) -> impl Iterator<Item = &PlaceholderKey> {
        std::iter::once(&self.current).chain(self.retained.iter())
    }
}

/// Appends `value` percent-encoded (every byte but RFC 3986 unreserved characters): what a
/// percent-form placeholder is replaced with.
pub(crate) fn percent_encode_into(out: &mut Vec<u8>, value: &[u8]) {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    for &b in value {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(&[b'%', UPPER[usize::from(b >> 4)], UPPER[usize::from(b & 15)]]);
        }
    }
}

/// The percent form of a placeholder: its brackets percent-encoded, everything else as is.
pub fn percent_form(placeholder: &str) -> String {
    placeholder
        .replace('\u{27e6}', "%E2%9F%A6")
        .replace('\u{27e7}', "%E2%9F%A7")
}

/// Writes the placeholder for `value` under `slug` with `key` into `out`.
pub(crate) fn write_placeholder(
    out: &mut Vec<u8>,
    key: &PlaceholderKey,
    slug: &RefSlug,
    value: &[u8],
) {
    let tag = key.tag(value);
    out.extend_from_slice(OPEN);
    out.extend_from_slice(slug.as_str().as_bytes());
    out.push(b':');
    out.push(HEX[usize::from(key.version >> 4)]);
    out.push(HEX[usize::from(key.version & 15)]);
    for b in tag {
        out.push(HEX[usize::from(b >> 4)]);
        out.push(HEX[usize::from(b & 15)]);
    }
    out.extend_from_slice(CLOSE);
}

/// Computes the placeholder for `value` under `slug` with `key`.
///
/// This is the same function the redactor uses; it is public so other components (the HTTPS tool
/// proxy, the CLI `share` command, tests in other crates) can produce placeholders without a
/// snapshot.
pub fn placeholder_for(key: &PlaceholderKey, slug: &RefSlug, value: &[u8]) -> String {
    let mut out = Vec::with_capacity(MAX_PLACEHOLDER_LEN);
    write_placeholder(&mut out, key, slug, value);
    String::from_utf8(out)
        .unwrap_or_else(|_| unreachable!("placeholder is ASCII plus two fixed code points"))
}

/// A syntactically valid placeholder found in some bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedPlaceholder<'a> {
    /// Total length in bytes.
    pub len: usize,
    /// The slug bytes.
    pub slug: &'a [u8],
    /// Key version.
    pub version: u8,
    /// Truncated HMAC tag.
    pub tag: [u8; TAG_BYTES],
    /// `true` for the percent form (`%E2%9F%A6...%E2%9F%A7`).
    pub percent: bool,
}

/// Result of parsing at a position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Parse<'a> {
    /// A complete placeholder.
    Complete(ParsedPlaceholder<'a>),
    /// The input ends while it is still a valid placeholder prefix.
    Prefix,
    /// Not a placeholder.
    Invalid,
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Matches delimiter `pat` at the start of `b`; the first `fold` bytes compare ASCII
/// case-insensitively. `None` when it does not match, `Some(false)` when `b` ends inside it.
fn delim(b: &[u8], pat: &[u8], fold: usize) -> Option<bool> {
    let n = b.len().min(pat.len());
    let ok = b[..n].iter().zip(pat).enumerate().all(|(i, (&x, &p))| {
        if i < fold {
            x.to_ascii_uppercase() == p
        } else {
            x == p
        }
    });
    ok.then_some(n == pat.len())
}

/// Parses a placeholder, in either form, starting at `b[0]`.
pub(crate) fn parse(b: &[u8]) -> Parse<'_> {
    let percent = b.first() == Some(&PCT_LEAD);
    let (open, close, fold) = if percent {
        (PCT_OPEN, PCT_CLOSE, PCT_FOLD)
    } else {
        (OPEN, CLOSE, 0)
    };
    // Opening delimiter and `scrim:`.
    match delim(b, open, fold) {
        None => return Parse::Invalid,
        Some(false) => return Parse::Prefix,
        Some(true) => {}
    }
    // Slug up to ':'.
    let mut i = open.len();
    let slug_start = i;
    while i < b.len() && i - slug_start <= RefSlug::MAX_LEN && is_slug_byte(b[i]) {
        i += 1;
    }
    let slug_len = i - slug_start;
    if slug_len > RefSlug::MAX_LEN {
        return Parse::Invalid;
    }
    if i == b.len() {
        return Parse::Prefix;
    }
    if slug_len == 0 || b[i] != b':' || b[slug_start] == b'-' || b[i - 1] == b'-' {
        return Parse::Invalid;
    }
    let slug = &b[slug_start..i];
    i += 1;
    // 18 hex digits.
    let mut code = [0u8; CODE_LEN];
    for slot in &mut code {
        if i == b.len() {
            return Parse::Prefix;
        }
        match hex_val(b[i]) {
            Some(v) => *slot = v,
            None => return Parse::Invalid,
        }
        i += 1;
    }
    // Closing delimiter.
    match delim(&b[i..], close, fold) {
        None => return Parse::Invalid,
        Some(false) => return Parse::Prefix,
        Some(true) => {}
    }
    let version = (code[0] << 4) | code[1];
    if version == 0 {
        return Parse::Invalid;
    }
    let mut tag = [0u8; TAG_BYTES];
    for (k, t) in tag.iter_mut().enumerate() {
        *t = (code[2 + 2 * k] << 4) | code[3 + 2 * k];
    }
    Parse::Complete(ParsedPlaceholder {
        len: i + close.len(),
        slug,
        version,
        tag,
        percent,
    })
}

/// Finds every syntactically valid placeholder in `b`, either form, in order, without overlaps.
pub fn find_placeholders(b: &[u8]) -> impl Iterator<Item = (usize, ParsedPlaceholder<'_>)> {
    let mut pos = 0;
    std::iter::from_fn(move || {
        while let Some(off) = memchr::memchr2(LEAD, PCT_LEAD, &b[pos..]) {
            let at = pos + off;
            if let Parse::Complete(p) = parse(&b[at..]) {
                pos = at + p.len;
                return Some((at, p));
            }
            pos = at + 1;
        }
        pos = b.len();
        None
    })
}

/// Where the first placeholder in some bytes sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaceholderAt {
    /// A complete, well-formed placeholder at `start..end`.
    Complete {
        /// First byte.
        start: usize,
        /// One past the last byte.
        end: usize,
    },
    /// `b[start..]` runs to the end and could still become a placeholder.
    Partial {
        /// First byte.
        start: usize,
    },
}

/// The first complete placeholder in `b` (either form), or the trailing bytes that could still
/// become one, whichever comes first. For streaming callers that keep their own holdback of up
/// to [`MAX_PERCENT_PLACEHOLDER_LEN`]` - 1` bytes.
pub fn next_placeholder(b: &[u8]) -> Option<PlaceholderAt> {
    let mut i = 0;
    while let Some(off) = memchr::memchr2(LEAD, PCT_LEAD, &b[i..]) {
        let at = i + off;
        match parse(&b[at..]) {
            Parse::Complete(p) => {
                return Some(PlaceholderAt::Complete {
                    start: at,
                    end: at + p.len,
                });
            }
            Parse::Prefix => return Some(PlaceholderAt::Partial { start: at }),
            Parse::Invalid => i = at + 1,
        }
    }
    None
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

    fn key(v: u8) -> PlaceholderKey {
        PlaceholderKey::new(v, &[v; 32]).unwrap()
    }

    #[test]
    fn format_is_fixed() {
        let s = RefSlug::new("github-token").unwrap();
        let p = placeholder_for(&key(1), &s, b"ghp_example_value_123456");
        assert!(p.starts_with("\u{27e6}scrim:github-token:01"));
        assert!(p.ends_with('\u{27e7}'));
        assert_eq!(p.len(), OPEN.len() + 12 + 1 + CODE_LEN + CLOSE.len());
        assert!(
            matches!(parse(p.as_bytes()), Parse::Complete(x) if x.len == p.len() && x.version == 1)
        );
    }

    #[test]
    fn deterministic_and_keyed() {
        let s = RefSlug::new("a").unwrap();
        assert_eq!(
            placeholder_for(&key(1), &s, b"value-one"),
            placeholder_for(&key(1), &s, b"value-one")
        );
        assert_ne!(
            placeholder_for(&key(1), &s, b"value-one"),
            placeholder_for(&key(2), &s, b"value-one")
        );
        assert_ne!(
            placeholder_for(&key(1), &s, b"value-one"),
            placeholder_for(&key(1), &s, b"value-two")
        );
    }

    #[test]
    fn known_vector() {
        // Pinned so any change to the derivation is a visible, deliberate break.
        let k = PlaceholderKey::new(1, b"0123456789abcdef0123456789abcdef").unwrap();
        let p = placeholder_for(
            &k,
            &RefSlug::new("db-password").unwrap(),
            b"correct horse battery staple",
        );
        assert_eq!(p, "\u{27e6}scrim:db-password:0120a7d732ee4c8da2\u{27e7}");
    }

    #[test]
    fn lengths() {
        let long = "a".repeat(RefSlug::MAX_LEN);
        let p = placeholder_for(&key(9), &RefSlug::new(&long).unwrap(), b"x");
        assert_eq!(p.len(), MAX_PLACEHOLDER_LEN);
        let p = placeholder_for(&key(9), &RefSlug::new("a").unwrap(), b"x");
        assert_eq!(p.len(), MIN_PLACEHOLDER_LEN);
    }

    #[test]
    fn prefixes_and_invalid() {
        let p = placeholder_for(&key(3), &RefSlug::new("k-1").unwrap(), b"some value here");
        let b = p.as_bytes();
        for cut in 1..b.len() {
            assert_eq!(parse(&b[..cut]), Parse::Prefix, "cut {cut}");
        }
        assert_eq!(parse("\u{27e6}scrim::01".as_bytes()), Parse::Invalid);
        assert_eq!(parse("\u{27e6}scrim:-a:".as_bytes()), Parse::Invalid);
        assert_eq!(parse("\u{27e6}scrim:A".as_bytes()), Parse::Invalid);
        assert_eq!(
            parse("\u{27e6}scrim:a:00000000000000000000\u{27e7}".as_bytes()),
            Parse::Invalid
        );
        assert_eq!(parse("\u{27e6}scrim:a:0g".as_bytes()), Parse::Invalid);
        let too_long = format!("\u{27e6}scrim:{}", "a".repeat(RefSlug::MAX_LEN + 1));
        assert_eq!(parse(too_long.as_bytes()), Parse::Invalid);
    }

    #[test]
    fn percent_form_parses() {
        let p = placeholder_for(&key(3), &RefSlug::new("k-1").unwrap(), b"some value here");
        let pct = percent_form(&p);
        assert_eq!(pct.len(), p.len() + 12);
        assert!(pct.is_ascii());
        match parse(pct.as_bytes()) {
            Parse::Complete(x) => {
                assert!(x.percent && x.len == pct.len() && x.version == 3 && x.slug == b"k-1");
                let Parse::Complete(r) = parse(p.as_bytes()) else {
                    panic!("raw form")
                };
                assert!(!r.percent);
                assert_eq!((r.tag, r.version, r.slug), (x.tag, x.version, x.slug));
            }
            other => panic!("{other:?}"),
        }
        let b = pct.as_bytes();
        for cut in 1..b.len() {
            assert_eq!(parse(&b[..cut]), Parse::Prefix, "cut {cut}");
        }
        // Only the bracket hex folds case; `scrim` and the code do not.
        let lower = pct.to_ascii_lowercase();
        assert!(matches!(parse(lower.as_bytes()), Parse::Complete(_)));
        let upper = pct.replace("scrim", "SCRIM");
        assert_eq!(parse(upper.as_bytes()), Parse::Invalid);
        assert_eq!(parse(b"%E2%9F%A6scrim:k-1:"), Parse::Prefix);
        assert_eq!(parse(b"%41"), Parse::Invalid);
        assert_eq!(parse(b"%E2%9F%A7"), Parse::Invalid);
        // Mixed forms are not a placeholder.
        let mixed = format!("{}{}", &pct[..pct.len() - 9], "\u{27e7}");
        assert_eq!(parse(mixed.as_bytes()), Parse::Invalid);
        let long = "a".repeat(RefSlug::MAX_LEN);
        let p = placeholder_for(&key(9), &RefSlug::new(&long).unwrap(), b"x");
        assert_eq!(percent_form(&p).len(), MAX_PERCENT_PLACEHOLDER_LEN);
    }

    #[test]
    fn find_all() {
        let s = RefSlug::new("x").unwrap();
        let a = placeholder_for(&key(1), &s, b"aaaaaaaaaa");
        let text = format!("pre {a} mid \u{27e6}scrim:x {a}{a} end \u{27e6}");
        let found: Vec<_> = find_placeholders(text.as_bytes())
            .map(|(at, p)| (at, p.len))
            .collect();
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].0, 4);
    }

    #[test]
    fn key_debug_is_redacted() {
        let k = PlaceholderKey::new(1, b"supersecretkeybytes!").unwrap();
        let d1 = format!("{k:?}");
        let d = format!("{d1} {:?}", Keyring::new(k));
        assert!(!d.contains("supersecret"));
    }
}
