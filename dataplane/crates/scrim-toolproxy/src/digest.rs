//! Recomputing body digests after a body was rewritten.
//!
//! Handles `Content-Digest` and `Repr-Digest` (RFC 9530, `sha-256` and `sha-512`), the legacy
//! `Digest` header (RFC 3230, `SHA-256`, `SHA-512`, `MD5`) and `Content-MD5`. With no range
//! requests involved, both RFC 9530 fields cover the bytes as sent, content coding included.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderMap, HeaderName, HeaderValue};
use md5::Md5;
use sha2::{Digest as _, Sha256, Sha512};

const CONTENT_DIGEST: HeaderName = HeaderName::from_static("content-digest");
const REPR_DIGEST: HeaderName = HeaderName::from_static("repr-digest");
const DIGEST: HeaderName = HeaderName::from_static("digest");
const CONTENT_MD5: HeaderName = HeaderName::from_static("content-md5");

/// Every digest header name this module understands.
pub(crate) const DIGEST_HEADERS: [HeaderName; 4] =
    [CONTENT_DIGEST, REPR_DIGEST, DIGEST, CONTENT_MD5];

fn hash(alg: &str, body: &[u8]) -> Option<Vec<u8>> {
    match alg.to_ascii_lowercase().as_str() {
        "sha-256" => Some(Sha256::digest(body).to_vec()),
        "sha-512" => Some(Sha512::digest(body).to_vec()),
        "md5" => Some(Md5::digest(body).to_vec()),
        _ => None,
    }
}

/// Whether any digest header is present.
pub(crate) fn has_digest(headers: &HeaderMap) -> bool {
    DIGEST_HEADERS.iter().any(|h| headers.contains_key(h))
}

/// Recomputes every digest header for `body`. Returns the first algorithm it cannot compute; the
/// caller then refuses (requests) or drops the header (responses).
pub(crate) fn recompute(
    headers: &mut HeaderMap,
    body: &[u8],
    drop_unsupported: bool,
) -> Result<(), String> {
    for name in [CONTENT_DIGEST, REPR_DIGEST] {
        let Some(v) = joined(headers, &name) else {
            continue;
        };
        let mut parts = Vec::new();
        for member in v.split(',') {
            let member = member.trim();
            if member.is_empty() {
                continue;
            }
            let alg = member.split('=').next().unwrap_or("").trim();
            // RFC 9530 algorithms are lower-case; md5 is not registered there.
            match hash(alg, body).filter(|_| alg != "md5") {
                Some(d) => parts.push(format!("{alg}=:{}:", STANDARD.encode(d))),
                None if drop_unsupported => {}
                None => return Err(alg.to_owned()),
            }
        }
        set_or_remove(headers, name, &parts.join(", "));
    }
    if let Some(v) = joined(headers, &DIGEST) {
        let mut parts = Vec::new();
        for member in v.split(',') {
            let member = member.trim();
            if member.is_empty() {
                continue;
            }
            let alg = member.split('=').next().unwrap_or("").trim();
            match hash(alg, body) {
                Some(d) => parts.push(format!("{alg}={}", STANDARD.encode(d))),
                None if drop_unsupported => {}
                None => return Err(alg.to_owned()),
            }
        }
        set_or_remove(headers, DIGEST, &parts.join(","));
    }
    if headers.contains_key(&CONTENT_MD5) {
        let d = Md5::digest(body);
        if let Ok(v) = HeaderValue::from_str(&STANDARD.encode(d)) {
            headers.insert(CONTENT_MD5, v);
        }
    }
    Ok(())
}

/// Removes every digest header (used when a streamed body is rewritten and cannot be hashed in
/// advance).
pub(crate) fn strip(headers: &mut HeaderMap) {
    for h in DIGEST_HEADERS {
        headers.remove(h);
    }
}

fn joined(headers: &HeaderMap, name: &HeaderName) -> Option<String> {
    let vals: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if vals.is_empty() {
        None
    } else {
        Some(vals.join(","))
    }
}

fn set_or_remove(headers: &mut HeaderMap, name: HeaderName, v: &str) {
    match HeaderValue::from_str(v) {
        Ok(hv) if !v.is_empty() => {
            headers.insert(name, hv);
        }
        _ => {
            headers.remove(&name);
        }
    }
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

    #[test]
    fn recomputes_all_forms() {
        let mut h = HeaderMap::new();
        h.insert(
            "content-digest",
            "sha-256=:AAAA:, sha-512=:BBBB:".parse().unwrap(),
        );
        h.insert("digest", "SHA-256=AAAA,MD5=CCCC".parse().unwrap());
        h.insert("content-md5", "CCCC".parse().unwrap());
        recompute(&mut h, b"hello", false).unwrap();
        let cd = h["content-digest"].to_str().unwrap();
        assert!(
            cd.starts_with("sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:, sha-512=:"),
            "{cd}"
        );
        assert_eq!(
            h["digest"],
            "SHA-256=LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=,MD5=XUFAKrxLKna5cZ2REBfFkg=="
        );
        assert_eq!(h["content-md5"], "XUFAKrxLKna5cZ2REBfFkg==");
    }

    #[test]
    fn unsupported_algorithm() {
        let mut h = HeaderMap::new();
        h.insert("content-digest", "crc32c=:AAAA:".parse().unwrap());
        assert_eq!(
            recompute(&mut h.clone(), b"x", false).unwrap_err(),
            "crc32c"
        );
        recompute(&mut h, b"x", true).unwrap();
        assert!(!h.contains_key("content-digest"));
    }
}
