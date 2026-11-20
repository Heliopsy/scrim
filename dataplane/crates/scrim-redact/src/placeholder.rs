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
/// Hex digits after the slug separator: 2 for the version, 16 for the tag.
pub(crate) const CODE_LEN: usize = 18;
const TAG_BYTES: usize = 8;
const DOMAIN: &[u8] = b"scrim-placeholder-v1\0";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Length in bytes of the longest possible placeholder (slug of [`RefSlug::MAX_LEN`] bytes).
pub const MAX_PLACEHOLDER_LEN: usize = OPEN.len() + RefSlug::MAX_LEN + 1 + CODE_LEN + CLOSE.len();
/// Length in bytes of the shortest possible placeholder (one-byte slug).
pub const MIN_PLACEHOLDER_LEN: usize = OPEN.len() + 1 + 1 + CODE_LEN + CLOSE.len();

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

/// Parses a placeholder starting at `b[0]`.
pub(crate) fn parse(b: &[u8]) -> Parse<'_> {
    // Opening delimiter and `scrim:`.
    let n = b.len().min(OPEN.len());
    if b[..n] != OPEN[..n] {
        return Parse::Invalid;
    }
    if b.len() < OPEN.len() {
        return Parse::Prefix;
    }
    // Slug up to ':'.
    let mut i = OPEN.len();
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
    let rest = &b[i..];
    let n = rest.len().min(CLOSE.len());
    if rest[..n] != CLOSE[..n] {
        return Parse::Invalid;
    }
    if rest.len() < CLOSE.len() {
        return Parse::Prefix;
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
        len: i + CLOSE.len(),
        slug,
        version,
        tag,
    })
}

/// Finds every syntactically valid placeholder in `b`, in order, without overlaps.
pub fn find_placeholders(b: &[u8]) -> impl Iterator<Item = (usize, ParsedPlaceholder<'_>)> {
    let mut pos = 0;
    std::iter::from_fn(move || {
        while let Some(off) = memchr::memchr(LEAD, &b[pos..]) {
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
