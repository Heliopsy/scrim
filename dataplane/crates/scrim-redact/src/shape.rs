//! Format-preserving placeholders (redaction spec "Format-preserving placeholders"; task 10a.3).
//!
//! Some clients check a token's shape before they send it: `ghp_` and 36 characters, `AKIA` and
//! 16, a 40-character AWS secret, `xoxb-` with dash-separated parts, a JWT. For such a credential
//! the placeholder can keep the value's known prefix, its length and its alphabet, so the client
//! accepts it. It is still a keyed HMAC of the value, deterministic for a key, slug and value, and
//! it never passes a token checksum (GitHub's CRC32 suffix).
//!
//! Derivation, for a value of 16 to 1,024 bytes of visible ASCII (anything else has no shape and
//! keeps the bracket form):
//!
//! 1. A JWT (`eyJ...` header, three non-empty base64url segments) becomes
//!    `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0` (`{"alg":"none","typ":"JWT"}`), `.`, the unpadded
//!    base64url of `{"scrim":"<slug>"}`, `.`, and as many base64url characters as the value's
//!    signature segment has (at least 22), drawn as below.
//! 2. Otherwise the longest prefix from [`PREFIXES`] the value starts with is kept. For the Slack
//!    (`xox?-`, `xapp-`) and GitHub fine-grained (`github_pat_`) prefixes, `-` and `_` in the rest
//!    keep their positions (they separate fixed-length fields). A trailing run of `=` is kept.
//! 3. Every other position is drawn from the alphabet: base32 (`A-Z2-7`) after an AWS key id
//!    prefix; otherwise digits, upper case and lower case letters, each if the rest of the value
//!    holds one, and every other character it holds, in byte order.
//! 4. Characters are drawn from the bytes of `HMAC-SHA256(key, "scrim-placeholder-shape-v1" ||
//!    0x00 || u32be(i) || slug || 0x00 || value)` for `i = 0, 1, ...`, concatenated; a byte `b`
//!    is used when `b < 256 - 256 % n` (n the alphabet size) and gives character `b % n`.
//! 5. A value whose drawn positions carry fewer than 64 bits (`count * floor(log2(n))`) has no
//!    shape.
//! 6. After `ghp_`, `gho_`, `ghu_`, `ghs_` or `ghr_` with 36 characters, the last six must not be
//!    a base62 CRC32 checksum of the first thirty (with or without the prefix, either base62
//!    alphabet order). While they are, the last character is drawn again.
//!
//! The Go control plane computes the same function (`internal/placeholder`), and
//! `internal/placeholder/testdata/shaped.json` holds the vectors both check.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::placeholder::PlaceholderKey;
use crate::secret::RefSlug;

const DOMAIN: &[u8] = b"scrim-placeholder-shape-v1\0";
/// Shortest value with a shape.
pub const MIN_SHAPED_LEN: usize = 16;
/// Longest value with a shape.
pub const MAX_SHAPED_LEN: usize = 1024;
const JWT_HEADER: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Known token prefixes kept as they are, longest match wins.
pub const PREFIXES: &[&str] = &[
    "github_pat_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "glrt-",
    "gldt-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "xoxe-",
    "xapp-",
    "sk-ant-api03-",
    "sk-ant-admin01-",
    "sk-proj-",
    "sk-svcacct-",
    "sk-",
    "AKIA",
    "ASIA",
    "hf_",
    "npm_",
    "pypi-",
    "dop_v1_",
    "doo_v1_",
    "shpat_",
    "shpss_",
    "sq0atp-",
    "SG.",
    "AIza",
    "hvs.",
    "hvb.",
    "glsa_",
    "lin_api_",
    "rk_live_",
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "pk_test_",
];

const KEEP_SEPARATORS: &[&str] = &[
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "xoxe-",
    "xapp-",
];
const GITHUB_CHECKSUMMED: &[&str] = &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"];

struct Stream<'a> {
    key: &'a PlaceholderKey,
    slug: &'a [u8],
    value: &'a [u8],
    block: [u8; 32],
    pos: usize,
    counter: u32,
}

impl<'a> Stream<'a> {
    fn new(key: &'a PlaceholderKey, slug: &'a [u8], value: &'a [u8]) -> Self {
        Self {
            key,
            slug,
            value,
            block: [0; 32],
            pos: 32,
            counter: 0,
        }
    }

    fn byte(&mut self) -> u8 {
        if self.pos == 32 {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(self.key.bytes())
                .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
            m.update(DOMAIN);
            m.update(&self.counter.to_be_bytes());
            m.update(self.slug);
            m.update(&[0]);
            m.update(self.value);
            self.block = m.finalize().into_bytes().into();
            self.counter = self.counter.wrapping_add(1);
            self.pos = 0;
        }
        let b = self.block[self.pos];
        self.pos += 1;
        b
    }

    fn pick(&mut self, alphabet: &[u8]) -> u8 {
        let n = alphabet.len();
        let limit = 256 - 256 % n;
        loop {
            let b = usize::from(self.byte());
            if b < limit {
                return alphabet[b % n];
            }
        }
    }
}

fn is_b64url(s: &[u8]) -> bool {
    !s.is_empty()
        && s.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
}

/// Bits `count` characters of an `n`-symbol alphabet carry at least: `count * floor(log2(n))`.
fn bits(count: usize, n: usize) -> usize {
    count * (usize::BITS - 1 - n.leading_zeros()) as usize
}

fn base62(mut v: u32, alphabet: &[u8; 62]) -> [u8; 6] {
    let mut out = [alphabet[0]; 6];
    for slot in out.iter_mut().rev() {
        *slot = alphabet[(v % 62) as usize];
        v /= 62;
    }
    out
}

/// Whether the last six characters of a GitHub-style token are a checksum of the first thirty.
fn github_checksum_valid(prefix: &str, body: &[u8]) -> bool {
    const A1: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const A2: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let tail = &body[30..36];
    let mut with_prefix = prefix.as_bytes().to_vec();
    with_prefix.extend_from_slice(&body[..30]);
    for data in [&body[..30], &with_prefix[..]] {
        let crc = crc32fast::hash(data);
        if tail == base62(crc, A1) || tail == base62(crc, A2) {
            return true;
        }
    }
    false
}

/// The format-preserving placeholder for `value` under `slug` with `key`, or `None` when the
/// value has no shape (see the module documentation). Never equal to the value.
pub fn shaped_placeholder_for(
    key: &PlaceholderKey,
    slug: &RefSlug,
    value: &[u8],
) -> Option<String> {
    if !(MIN_SHAPED_LEN..=MAX_SHAPED_LEN).contains(&value.len())
        || !value.iter().all(|c| (0x21..=0x7e).contains(c))
    {
        return None;
    }
    let slug_b = slug.as_str().as_bytes();
    let mut st = Stream::new(key, slug_b, value);

    // JWT.
    let segs: Vec<&[u8]> = value.split(|c| *c == b'.').collect();
    if segs.len() == 3 && value.starts_with(b"eyJ") && segs.iter().all(|s| is_b64url(s)) {
        let n = segs[2].len().max(22);
        let mut out = String::with_capacity(JWT_HEADER.len() + 64 + n);
        out.push_str(JWT_HEADER);
        out.push('.');
        out.push_str(&b64url_nopad(
            format!("{{\"scrim\":\"{}\"}}", slug.as_str()).as_bytes(),
        ));
        out.push('.');
        for _ in 0..n {
            out.push(st.pick(B64URL) as char);
        }
        return (out.as_bytes() != value).then_some(out);
    }

    let prefix = PREFIXES
        .iter()
        .filter(|p| value.starts_with(p.as_bytes()))
        .max_by_key(|p| p.len())
        .copied()
        .unwrap_or("");
    let rest = &value[prefix.len()..];
    let pad = rest.iter().rev().take_while(|c| **c == b'=').count();
    let body = &rest[..rest.len() - pad];
    let keep_sep = KEEP_SEPARATORS.contains(&prefix);
    let kept = |c: u8| keep_sep && (c == b'-' || c == b'_');

    let alphabet: Vec<u8> = if prefix == "AKIA" || prefix == "ASIA" {
        BASE32.to_vec()
    } else {
        let mut a = Vec::new();
        let has = |f: fn(&u8) -> bool| body.iter().any(|c| !kept(*c) && f(c));
        if has(u8::is_ascii_digit) {
            a.extend(b'0'..=b'9');
        }
        if has(u8::is_ascii_uppercase) {
            a.extend(b'A'..=b'Z');
        }
        if has(u8::is_ascii_lowercase) {
            a.extend(b'a'..=b'z');
        }
        let mut other: Vec<u8> = body
            .iter()
            .copied()
            .filter(|c| !c.is_ascii_alphanumeric() && !kept(*c))
            .collect();
        other.sort_unstable();
        other.dedup();
        a.extend(other);
        a
    };
    let count = body.iter().filter(|c| !kept(**c)).count();
    if alphabet.len() < 2 || bits(count, alphabet.len()) < 64 {
        return None;
    }
    let mut out_body: Vec<u8> = body
        .iter()
        .map(|&c| if kept(c) { c } else { st.pick(&alphabet) })
        .collect();
    if GITHUB_CHECKSUMMED.contains(&prefix) && out_body.len() == 36 {
        while github_checksum_valid(prefix, &out_body) {
            out_body[35] = st.pick(&alphabet);
        }
    }
    let mut out = String::with_capacity(value.len());
    out.push_str(prefix);
    out.push_str(std::str::from_utf8(&out_body).ok()?);
    out.extend(std::iter::repeat_n('=', pad));
    (out.as_bytes() != value).then_some(out)
}

fn b64url_nopad(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            out.push(B64URL[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
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

    fn key() -> PlaceholderKey {
        PlaceholderKey::new(1, b"0123456789abcdef0123456789abcdef").unwrap()
    }

    fn slug(s: &str) -> RefSlug {
        RefSlug::new(s).unwrap()
    }

    #[test]
    fn keeps_prefix_length_and_alphabet() {
        let k = key();
        let cases: &[(&str, &str)] = &[
            ("github", "ghp_TeStaB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"),
            ("aws-akid", "AKIAIOSFODNN7EXAMPLE"),
            ("aws-secret", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            // Split so the source holds no token-shaped literal.
            (
                "slack",
                concat!("xox", "b-123456789012-1234567890123-TeStGhIjKlMnOpQrStUvWx"),
            ),
            ("token", "TeStZSBiYXNlNjQgdG9rZW4gd2l0aCBwYWRkaW5nIQ=="),
        ];
        for (s, v) in cases {
            let p = shaped_placeholder_for(&k, &slug(s), v.as_bytes()).unwrap();
            assert_eq!(p.len(), v.len(), "{s}: {p}");
            assert_ne!(p, *v);
            let prefix = PREFIXES
                .iter()
                .filter(|x| v.starts_with(**x))
                .max_by_key(|x| x.len())
                .copied()
                .unwrap_or("");
            assert!(p.starts_with(prefix), "{p}");
            // Deterministic.
            assert_eq!(
                Some(p.clone()),
                shaped_placeholder_for(&k, &slug(s), v.as_bytes())
            );
            // Another slug or value gives another placeholder.
            assert_ne!(
                Some(p.clone()),
                shaped_placeholder_for(&k, &slug("other"), v.as_bytes())
            );
        }
        let akid = shaped_placeholder_for(&k, &slug("a"), b"AKIAIOSFODNN7EXAMPLE").unwrap();
        assert!(akid[4..].bytes().all(|c| BASE32.contains(&c)), "{akid}");
        let slack = shaped_placeholder_for(&k, &slug("s"), cases[3].1.as_bytes()).unwrap();
        let dashes = |s: &str| s.match_indices('-').map(|(i, _)| i).collect::<Vec<_>>();
        assert_eq!(dashes(&slack), dashes(cases[3].1));
        let padded = shaped_placeholder_for(&k, &slug("t"), cases[4].1.as_bytes()).unwrap();
        assert!(padded.ends_with("=="));
    }

    #[test]
    fn github_checksum_never_validates() {
        let k = key();
        for i in 0..2000 {
            let v = format!("ghp_{:036}", i);
            let p = shaped_placeholder_for(&k, &slug("gh"), v.as_bytes()).unwrap();
            assert!(!github_checksum_valid("ghp_", &p.as_bytes()[4..]), "{p}");
        }
    }

    #[test]
    fn jwt_shape() {
        let k = key();
        let v =
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.TeStbmF0dXJlLWJ5dGVzLWhlcmUtMDEyMzQ1Njc4OQ";
        let p = shaped_placeholder_for(&k, &slug("kube"), v.as_bytes()).unwrap();
        let segs: Vec<&str> = p.split('.').collect();
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0], JWT_HEADER);
        assert_eq!(segs[1], b64url_nopad(br#"{"scrim":"kube"}"#));
        assert_eq!(segs[2].len(), v.rsplit('.').next().unwrap().len());
    }

    #[test]
    fn no_shape_for_short_or_low_entropy_or_binary() {
        let k = key();
        for v in [
            &b"short-value"[..],
            b"0000000000000000",
            b"ghp_0123456789",
            "näive-value-with-umlaut".as_bytes(),
            b"has space in the value here",
        ] {
            let r = shaped_placeholder_for(&k, &slug("x"), v);
            assert!(r.is_none(), "{:?}", String::from_utf8_lossy(v));
        }
        // 21 digits carry 63 bits, 22 carry 66.
        assert!(shaped_placeholder_for(&k, &slug("x"), b"000000000000000000000").is_none());
        assert!(shaped_placeholder_for(&k, &slug("x"), b"0000000000000000000000").is_some());
    }

    #[test]
    fn bits_floor_log2() {
        assert_eq!(bits(1, 2), 1);
        assert_eq!(bits(1, 10), 3);
        assert_eq!(bits(2, 32), 10);
        assert_eq!(bits(1, 62), 5);
        assert_eq!(bits(1, 64), 6);
    }

    /// The vectors the Go control plane checks too (`internal/placeholder/testdata/shaped.json`).
    /// `SCRIM_WRITE_SHAPE_VECTORS=1` rewrites the file from this implementation.
    #[test]
    fn shared_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../internal/placeholder/testdata/shaped.json"
        );
        let inputs: &[(&str, &str)] = &[
            ("github", "ghp_TeStV4lu3N0tR34l0123456789abcdefABCD"),
            ("github-oauth", "gho_0000000000aaaaaaaaaaBBBBBBBBBB111111"),
            (
                "github-fine",
                "github_pat_11ABCDEFG0123456789abc_defghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab",
            ),
            ("aws-akid", "AKIATESTVALUE7Q2W4E6"),
            ("aws-sts", "ASIATESTVALUE7Q2W4E6"),
            ("aws-secret", "tEsTsEcReT/0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c"),
            (
                "openai",
                "sk-proj-TeStVaLuE_nOt-ReAl0123456789abcdefghijklmn",
            ),
            ("padded", "TeStdCB2YWx1ZSB3aXRoIHBhZGRpbmcgMDEyMzQ1Njc4OQ=="),
            ("symbols", "TeSt-p@ss-w0rd!with#symbols$and%more"),
            ("digits", "0000000000000000000000"),
            (
                "kube",
                "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJzdWIiOiJ0ZXN0In0.TeStdC1zaWduYXR1cmUtbm90LXJlYWwtMDEyMzQ1Njc4OQ",
            ),
            ("too-short", "short-test-val"),
            ("low-entropy", "000000000000000000000"),
            ("spaced", "value with spaces inside it"),
        ];
        let keys: &[(u8, &[u8])] = &[(1, b"0123456789abcdef0123456789abcdef"), (7, &[0x5a; 32])];
        let mut rows = Vec::new();
        for (v, k) in keys {
            let key = PlaceholderKey::new(*v, k).unwrap();
            for (s, val) in inputs {
                let got = shaped_placeholder_for(&key, &slug(s), val.as_bytes());
                rows.push(format!(
                    "  {{\"key_version\": {v}, \"key_hex\": \"{}\", \"slug\": \"{s}\", \"value\": {}, \"placeholder\": {}}}",
                    k.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    serde_json_str(val),
                    got.as_deref().map_or("null".to_owned(), serde_json_str),
                ));
            }
        }
        let text = format!("[\n{}\n]\n", rows.join(",\n"));
        if std::env::var_os("SCRIM_WRITE_SHAPE_VECTORS").is_some() {
            std::fs::write(path, &text).unwrap();
        }
        let want = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            want, text,
            "regenerate with SCRIM_WRITE_SHAPE_VECTORS=1 after a deliberate change"
        );
    }

    fn serde_json_str(s: &str) -> String {
        let mut o = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str("\\\\"),
                c => o.push(c),
            }
        }
        o.push('"');
        o
    }
}
