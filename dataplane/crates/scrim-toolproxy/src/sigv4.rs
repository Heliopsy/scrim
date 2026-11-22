//! AWS Signature Version 4: parsing, verification and re-signing (credential-injection spec,
//! "Re-signing for signed request protocols"; task 10a.2).
//!
//! The agent signs with placeholder keys: the access key id is a placeholder of the credential
//! holding the real access key id, the secret it signs with is a placeholder of the credential
//! holding the real secret access key. The proxy checks that the signature was made with that
//! placeholder secret (so the request is a scrim session's, not one signed with keys the agent
//! holds itself), lets the usual substitution swap the session token, then signs the request
//! again with the real keys. Both forms are handled: the `Authorization` header and presigned
//! query parameters, with signed, unsigned (`UNSIGNED-PAYLOAD`) and chunk-signed
//! (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, with or without a signed trailer) payloads.
//!
//! The implementation is small on purpose: canonical request, string to sign and signing key as
//! AWS documents them, checked against AWS's signing test suite (`testdata/aws-sigv4-test-suite`)
//! and against the `aws-sigv4` crate in the tests. No value ever reaches an error message.

use std::fmt::Write as _;

use hmac::{Hmac, KeyInit, Mac};
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Uri};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// `AWS4-HMAC-SHA256`, the only algorithm handled. `AWS4-ECDSA-P256-SHA256` (`SigV4a`) is refused.
pub(crate) const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const UNSIGNED: &str = "UNSIGNED-PAYLOAD";
const STREAMING: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
const STREAMING_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// Largest chunk of a chunk-signed body held while it is re-signed.
pub(crate) const MAX_CHUNK: usize = 16 << 20;

/// Where the signature sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Form {
    /// `Authorization: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...`.
    Header,
    /// Presigned: `X-Amz-Algorithm`, `X-Amz-Credential`, ..., `X-Amz-Signature` in the query.
    Query,
}

/// A parsed `SigV4` authorization. Holds no secret: the access key id is a placeholder (or a key
/// id, which is not secret), the signature is public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Auth {
    pub form: Form,
    pub access_key: String,
    pub date: String,
    pub region: String,
    pub service: String,
    pub amz_date: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

impl Auth {
    /// `<date>/<region>/<service>/aws4_request`.
    pub(crate) fn scope(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date, self.region, self.service
        )
    }
}

/// Why a request that claims `SigV4` cannot be handled. Messages carry no value.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SigError(pub String);

fn err(s: impl Into<String>) -> SigError {
    SigError(s.into())
}

/// Whether the request claims a `SigV4` signature at all (cheap, before any parsing).
pub(crate) fn claims_sigv4(uri: &Uri, headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .is_some_and(|v| v.as_bytes().starts_with(b"AWS4-"))
        || uri.query().is_some_and(|q| {
            q.split('&')
                .any(|p| p.split('=').next().is_some_and(|k| k == "X-Amz-Signature"))
        })
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_date(s: &str) -> bool {
    s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit())
}

fn valid_amz_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 16
        && b[8] == b'T'
        && b[15] == b'Z'
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[9..15].iter().all(u8::is_ascii_digit)
}

fn scope_part(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Splits `AKID/date/region/service/aws4_request` from the right, so an access key id holding a
/// `/` (a reference placeholder) still parses.
fn parse_credential(c: &str) -> Result<(String, String, String, String), SigError> {
    let mut it = c.rsplitn(5, '/');
    let term = it.next().unwrap_or_default();
    let service = it.next().unwrap_or_default();
    let region = it.next().unwrap_or_default();
    let date = it.next().unwrap_or_default();
    let akid = it.next().unwrap_or_default();
    if term != "aws4_request"
        || !valid_date(date)
        || !scope_part(region)
        || !scope_part(service)
        || akid.is_empty()
        || akid.len() > 512
    {
        return Err(err("the SigV4 credential scope is malformed"));
    }
    Ok((
        akid.to_owned(),
        date.to_owned(),
        region.to_owned(),
        service.to_owned(),
    ))
}

fn parse_signed_headers(s: &str) -> Result<Vec<String>, SigError> {
    let v: Vec<String> = s.split(';').map(str::to_owned).collect();
    let ok = !v.is_empty()
        && v.len() <= 128
        && v.iter().all(|h| {
            !h.is_empty()
                && h.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
        && v.windows(2).all(|w| w[0] < w[1]);
    if ok {
        Ok(v)
    } else {
        Err(err("the SigV4 signed header list is malformed"))
    }
}

/// Parses the `SigV4` authorization of a request. `Ok(None)` when it is not signed with `SigV4`.
pub(crate) fn parse(uri: &Uri, headers: &HeaderMap) -> Result<Option<Auth>, SigError> {
    if let Some(v) = headers.get(header::AUTHORIZATION) {
        let v = v
            .to_str()
            .map_err(|_| err("the Authorization header is not ASCII"))?;
        if let Some(rest) = v.strip_prefix("AWS4-") {
            let Some(params) = rest.strip_prefix("HMAC-SHA256 ") else {
                return Err(err(format!(
                    "the request is signed with AWS4-{}, only AWS4-HMAC-SHA256 can be re-signed",
                    rest.split(' ').next().unwrap_or_default()
                )));
            };
            let (mut cred, mut sh, mut sig) = (None, None, None);
            for p in params.split(',') {
                let p = p.trim();
                let (k, val) = p
                    .split_once('=')
                    .ok_or_else(|| err("the SigV4 Authorization header is malformed"))?;
                let slot = match k {
                    "Credential" => &mut cred,
                    "SignedHeaders" => &mut sh,
                    "Signature" => &mut sig,
                    _ => return Err(err("the SigV4 Authorization header is malformed")),
                };
                if slot.replace(val).is_some() {
                    return Err(err("the SigV4 Authorization header repeats a field"));
                }
            }
            let (Some(cred), Some(sh), Some(sig)) = (cred, sh, sig) else {
                return Err(err("the SigV4 Authorization header is incomplete"));
            };
            let (access_key, date, region, service) = parse_credential(cred)?;
            let amz_date = single_header(headers, "x-amz-date")?
                .ok_or_else(|| err("a SigV4 request without X-Amz-Date cannot be re-signed"))?;
            if !valid_amz_date(&amz_date) || amz_date[..8] != date {
                return Err(err("X-Amz-Date does not match the SigV4 credential scope"));
            }
            if !is_hex64(sig) {
                return Err(err("the SigV4 signature is malformed"));
            }
            return Ok(Some(Auth {
                form: Form::Header,
                access_key,
                date,
                region,
                service,
                amz_date,
                signed_headers: parse_signed_headers(sh)?,
                signature: sig.to_ascii_lowercase(),
            }));
        }
    }
    let Some(q) = uri.query() else {
        return Ok(None);
    };
    let pairs = query_pairs(q)?;
    let get = |name: &str| -> Result<Option<String>, SigError> {
        let mut found = pairs.iter().filter(|(k, _)| k == name);
        let first = found.next().map(|(_, v)| v.clone());
        if found.next().is_some() {
            return Err(err(format!("the presigned request repeats {name}")));
        }
        Ok(first)
    };
    let Some(sig) = get("X-Amz-Signature")? else {
        return Ok(None);
    };
    match get("X-Amz-Algorithm")?.as_deref() {
        Some(ALGORITHM) => {}
        Some(other) => {
            return Err(err(format!(
                "the presigned request uses {other}, only AWS4-HMAC-SHA256 can be re-signed"
            )));
        }
        None => return Err(err("the presigned request has no X-Amz-Algorithm")),
    }
    let cred =
        get("X-Amz-Credential")?.ok_or_else(|| err("the presigned request has no credential"))?;
    let (access_key, date, region, service) = parse_credential(&cred)?;
    let amz_date = get("X-Amz-Date")?.ok_or_else(|| err("the presigned request has no date"))?;
    if !valid_amz_date(&amz_date) || amz_date[..8] != date {
        return Err(err("X-Amz-Date does not match the SigV4 credential scope"));
    }
    let sh = get("X-Amz-SignedHeaders")?
        .ok_or_else(|| err("the presigned request has no signed header list"))?;
    if !is_hex64(&sig) {
        return Err(err("the SigV4 signature is malformed"));
    }
    Ok(Some(Auth {
        form: Form::Query,
        access_key,
        date,
        region,
        service,
        amz_date,
        signed_headers: parse_signed_headers(&sh)?,
        signature: sig.to_ascii_lowercase(),
    }))
}

fn single_header(h: &HeaderMap, name: &str) -> Result<Option<String>, SigError> {
    let mut it = h.get_all(name).iter();
    let Some(first) = it.next() else {
        return Ok(None);
    };
    if it.next().is_some() {
        return Err(err(format!("the request repeats {name}")));
    }
    first
        .to_str()
        .map(|s| Some(s.trim().to_owned()))
        .map_err(|_| err(format!("{name} is not ASCII")))
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes; `+` stays `+`. Malformed escapes are kept as they are.
fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// AWS URI encoding: every byte but `A-Za-z0-9-_.~` as `%XX` (upper case); `/` kept when
/// `keep_slash`.
fn aws_encode(out: &mut String, b: &[u8], keep_slash: bool) {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    for &c in b {
        if c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && c == b'/')
        {
            out.push(c as char);
        } else {
            out.push('%');
            out.push(UPPER[usize::from(c >> 4)] as char);
            out.push(UPPER[usize::from(c & 15)] as char);
        }
    }
}

/// Query parameters, decoded. At most 1,000.
fn query_pairs(q: &str) -> Result<Vec<(String, String)>, SigError> {
    let mut out = Vec::new();
    for p in q.split('&') {
        if p.is_empty() {
            continue;
        }
        if out.len() == 1000 {
            return Err(err("the query has too many parameters to sign"));
        }
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        out.push((
            String::from_utf8_lossy(&percent_decode(k)).into_owned(),
            String::from_utf8_lossy(&percent_decode(v)).into_owned(),
        ));
    }
    Ok(out)
}

/// The canonical query string: every parameter but `X-Amz-Signature`, decoded and encoded again
/// the AWS way, sorted by encoded name, then value.
fn canonical_query(q: Option<&str>, token_unsigned: bool) -> String {
    let Some(q) = q else {
        return String::new();
    };
    let mut enc: Vec<(String, String)> = Vec::new();
    for p in q.split('&') {
        if p.is_empty() {
            continue;
        }
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        let (mut ek, mut ev) = (String::new(), String::new());
        aws_encode(&mut ek, &percent_decode(k), false);
        if ek == "X-Amz-Signature" || (token_unsigned && ek == "X-Amz-Security-Token") {
            continue;
        }
        aws_encode(&mut ev, &percent_decode(v), false);
        enc.push((ek, ev));
    }
    enc.sort();
    let mut s = String::with_capacity(q.len() + 16);
    for (i, (k, v)) in enc.iter().enumerate() {
        if i > 0 {
            s.push('&');
        }
        s.push_str(k);
        s.push('=');
        s.push_str(v);
    }
    s
}

/// How the client built the canonical URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UriMode {
    /// Every service but S3: dot segments and empty segments removed, then the path as sent
    /// encoded once more (so `%` becomes `%25`).
    Normalized,
    /// The path as sent, encoded once more, not normalised (clients that disable normalisation).
    Encoded,
    /// S3: the path decoded and encoded once, not normalised.
    S3,
}

fn canonical_uri(path: &str, mode: UriMode) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let mut out = String::with_capacity(path.len() + 8);
    match mode {
        UriMode::S3 => aws_encode(&mut out, &percent_decode(path), true),
        UriMode::Encoded => aws_encode(&mut out, path.as_bytes(), true),
        UriMode::Normalized => {
            let mut segs: Vec<&str> = Vec::new();
            for s in path.split('/') {
                match s {
                    "" | "." => {}
                    ".." => {
                        segs.pop();
                    }
                    s => segs.push(s),
                }
            }
            let mut p = String::from("/");
            p.push_str(&segs.join("/"));
            let trailing = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
            if trailing && p.len() > 1 {
                p.push('/');
            }
            aws_encode(&mut out, p.as_bytes(), true);
        }
    }
    out
}

/// Header value as signed: trimmed, runs of spaces collapsed, several values joined with `,`.
fn canonical_header_value(h: &HeaderMap, name: &str) -> Option<String> {
    let mut vals = h.get_all(name).iter().peekable();
    vals.peek()?;
    let mut out = String::new();
    for (i, v) in vals.enumerate() {
        if i > 0 {
            out.push(',');
        }
        let s = String::from_utf8_lossy(v.as_bytes());
        let mut prev_space = false;
        for c in s.trim().chars() {
            if c == ' ' || c == '\t' {
                if !prev_space {
                    out.push(' ');
                }
                prev_space = true;
            } else {
                out.push(c);
                prev_space = false;
            }
        }
    }
    Some(out)
}

/// The parts of a request a signature covers.
pub(crate) struct View<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap,
    /// The authority the request names, for a signed `host` when there is no `Host` header
    /// (HTTP/2 `:authority`).
    pub authority: Option<&'a str>,
}

/// How a signature was computed, beyond the request itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Canon {
    mode: UriMode,
    /// A presigned request whose session token was added after signing.
    token_unsigned: bool,
}

fn canonical_request(
    v: &View<'_>,
    signed: &[String],
    canon: Canon,
    payload: &str,
) -> Option<String> {
    let mut s = String::with_capacity(256);
    s.push_str(v.method.as_str());
    s.push('\n');
    s.push_str(&canonical_uri(v.path, canon.mode));
    s.push('\n');
    s.push_str(&canonical_query(v.query, canon.token_unsigned));
    s.push('\n');
    for name in signed {
        let val = match canonical_header_value(v.headers, name) {
            Some(val) => val,
            None if name == "host" => v.authority?.to_owned(),
            None => return None,
        };
        s.push_str(name);
        s.push(':');
        s.push_str(&val);
        s.push('\n');
    }
    s.push('\n');
    s.push_str(&signed.join(";"));
    s.push('\n');
    s.push_str(payload);
    Some(s)
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

pub(crate) fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
    m.update(data);
    m.finalize().into_bytes().into()
}

/// The derived signing key for a secret and scope. Wiped on drop.
pub(crate) struct SigningKey(Zeroizing<[u8; 32]>);

impl SigningKey {
    pub(crate) fn derive(secret: &[u8], date: &str, region: &str, service: &str) -> Self {
        let mut k = Zeroizing::new(Vec::with_capacity(secret.len() + 4));
        k.extend_from_slice(b"AWS4");
        k.extend_from_slice(secret);
        let d = Zeroizing::new(hmac(&k, date.as_bytes()));
        let r = Zeroizing::new(hmac(&*d, region.as_bytes()));
        let s = Zeroizing::new(hmac(&*r, service.as_bytes()));
        Self(Zeroizing::new(hmac(&*s, b"aws4_request")))
    }

    fn sign(&self, string_to_sign: &str) -> String {
        hex(&hmac(&*self.0, string_to_sign.as_bytes()))
    }
}

fn string_to_sign(amz_date: &str, scope: &str, canonical: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    )
}

/// Compares two hex signatures in constant time.
fn same_sig(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| {
            acc | (x.to_ascii_lowercase() ^ y.to_ascii_lowercase())
        }) == 0
}

/// What the payload hash in the canonical request was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Payload {
    /// `x-amz-content-sha256` held a hash of the body.
    HeaderHash,
    /// `x-amz-content-sha256` held a keyword (`UNSIGNED-PAYLOAD`, `STREAMING-...`), kept as is.
    Keyword(String),
    /// No header: the hash of the body (every service but S3).
    BodyHash,
    /// No header on a presigned request: `UNSIGNED-PAYLOAD`.
    Unsigned,
}

impl Payload {
    pub(crate) fn chunk_signed(&self) -> Option<bool> {
        match self {
            Payload::Keyword(k) if k == STREAMING => Some(false),
            Payload::Keyword(k) if k == STREAMING_TRAILER => Some(true),
            _ => None,
        }
    }
}

/// What verification established: how the client canonicalised, so re-signing does the same.
#[derive(Clone, Debug)]
pub(crate) struct Verified {
    canon: Canon,
    pub payload: Payload,
    /// Index of the secret (among those tried) that made the signature.
    pub secret: usize,
}

fn uri_modes(service: &str) -> &'static [UriMode] {
    if service == "s3" || service == "s3-object-lambda" || service == "s3express" {
        &[UriMode::S3, UriMode::Normalized]
    } else {
        &[UriMode::Normalized, UriMode::Encoded, UriMode::S3]
    }
}

/// The payload candidates for verification. `body` is `None` when the body is streamed.
fn payload_candidates(
    auth: &Auth,
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Result<Vec<(Payload, String)>, SigError> {
    if let Some(h) = single_header(headers, "x-amz-content-sha256")? {
        if is_hex64(&h) {
            return Ok(vec![(Payload::HeaderHash, h.to_ascii_lowercase())]);
        }
        if h.is_empty()
            || h.len() > 64
            || !h
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b == b'-' || b.is_ascii_digit())
        {
            return Err(err("x-amz-content-sha256 is malformed"));
        }
        return Ok(vec![(Payload::Keyword(h.clone()), h)]);
    }
    let mut v = Vec::new();
    if auth.form == Form::Query {
        v.push((Payload::Unsigned, UNSIGNED.to_owned()));
    }
    if let Some(b) = body {
        let h = if b.is_empty() {
            EMPTY_SHA256.to_owned()
        } else {
            sha256_hex(b)
        };
        v.push((Payload::BodyHash, h));
    } else if v.is_empty() {
        return Err(err(
            "a SigV4 body hash cannot be checked on a body too large to buffer",
        ));
    }
    Ok(v)
}

/// Checks `auth`'s signature over the request as the agent sent it, with each of `secrets`.
/// `None` when no secret made it.
pub(crate) fn verify<'s>(
    auth: &Auth,
    v: &View<'_>,
    body: Option<&[u8]>,
    secrets: impl IntoIterator<Item = &'s [u8]>,
) -> Result<Option<Verified>, SigError> {
    let payloads = payload_candidates(auth, v.headers, body)?;
    let scope = auth.scope();
    let has_token =
        auth.form == Form::Query && v.query.is_some_and(|q| q.contains("X-Amz-Security-Token="));
    let mut stss: Vec<(Canon, Payload, String)> = Vec::new();
    for &mode in uri_modes(&auth.service) {
        for token_unsigned in [false, true] {
            if token_unsigned && !has_token {
                continue;
            }
            let canon = Canon {
                mode,
                token_unsigned,
            };
            for (p, hash) in &payloads {
                let Some(c) = canonical_request(v, &auth.signed_headers, canon, hash) else {
                    return Err(err("a header the SigV4 signature covers is missing"));
                };
                let sts = string_to_sign(&auth.amz_date, &scope, &c);
                if !stss.iter().any(|(_, _, s)| *s == sts) {
                    stss.push((canon, p.clone(), sts));
                }
            }
        }
    }
    for (i, secret) in secrets.into_iter().enumerate() {
        let key = SigningKey::derive(secret, &auth.date, &auth.region, &auth.service);
        for (canon, p, sts) in &stss {
            if same_sig(&key.sign(sts), &auth.signature) {
                return Ok(Some(Verified {
                    canon: *canon,
                    payload: p.clone(),
                    secret: i,
                }));
            }
        }
    }
    Ok(None)
}

/// Signs the request again with `access_key` and `secret`, after substitution. `body` is the body
/// as it will be sent (`None` when streamed). Rewrites `Authorization` or the presigned query
/// parameters, and `x-amz-content-sha256` when it held a body hash. Signed headers the proxy
/// removed (hop-by-hop, `Expect`) leave the signed header list.
///
/// Returns the new seed signature, which chunk signatures chain from.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn resign(
    auth: &Auth,
    verified: &Verified,
    method: &Method,
    uri: &mut Uri,
    headers: &mut HeaderMap,
    authority: Option<&str>,
    body: Option<&[u8]>,
    access_key: &str,
    secret: &[u8],
) -> Result<String, SigError> {
    if access_key.is_empty()
        || !access_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(err(
            "the access key id cannot be written into a SigV4 credential",
        ));
    }
    let payload = match &verified.payload {
        Payload::HeaderHash => {
            let b = body
                .ok_or_else(|| err("a SigV4 body hash cannot be recomputed on a streamed body"))?;
            let h = sha256_hex(b);
            headers.insert(
                "x-amz-content-sha256",
                HeaderValue::from_str(&h).map_err(|_| err("hash header"))?,
            );
            h
        }
        Payload::Keyword(k) => k.clone(),
        Payload::BodyHash => {
            let b = body
                .ok_or_else(|| err("a SigV4 body hash cannot be recomputed on a streamed body"))?;
            sha256_hex(b)
        }
        Payload::Unsigned => UNSIGNED.to_owned(),
    };
    if let Some(a) = authority
        && !headers.contains_key(header::HOST)
        && auth.signed_headers.iter().any(|h| h == "host")
    {
        headers.insert(
            header::HOST,
            HeaderValue::from_str(a).map_err(|_| err("authority"))?,
        );
    }
    let signed: Vec<String> = auth
        .signed_headers
        .iter()
        .filter(|h| headers.contains_key(h.as_str()))
        .cloned()
        .collect();
    if !signed.iter().any(|h| h == "host") {
        return Err(err("a SigV4 request must sign the host header"));
    }
    let scope = auth.scope();
    let key = SigningKey::derive(secret, &auth.date, &auth.region, &auth.service);
    let path = uri.path().to_owned();
    match auth.form {
        Form::Header => {
            let canonical = canonical_request(
                &View {
                    method,
                    path: &path,
                    query: uri.query(),
                    headers,
                    authority,
                },
                &signed,
                verified.canon,
                &payload,
            )
            .ok_or_else(|| err("a signed header is missing"))?;
            let sig = key.sign(&string_to_sign(&auth.amz_date, &scope, &canonical));
            let mut v = HeaderValue::from_str(&format!(
                "{ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={}, Signature={sig}",
                signed.join(";")
            ))
            .map_err(|_| err("authorization header"))?;
            v.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, v);
            Ok(sig)
        }
        Form::Query => {
            // Rebuild the query with the real credential and the remaining signed headers, keep
            // every other parameter as sent, then append the new signature.
            let q = uri.query().unwrap_or_default().to_owned();
            let mut cred_enc = String::new();
            aws_encode(
                &mut cred_enc,
                format!("{access_key}/{scope}").as_bytes(),
                false,
            );
            let mut sh_enc = String::new();
            aws_encode(&mut sh_enc, signed.join(";").as_bytes(), false);
            let mut parts: Vec<String> = Vec::new();
            for p in q.split('&') {
                if p.is_empty() {
                    continue;
                }
                let k = p.split_once('=').map_or(p, |(k, _)| k);
                match String::from_utf8_lossy(&percent_decode(k)).as_ref() {
                    "X-Amz-Signature" => {}
                    "X-Amz-Credential" => parts.push(format!("X-Amz-Credential={cred_enc}")),
                    "X-Amz-SignedHeaders" => parts.push(format!("X-Amz-SignedHeaders={sh_enc}")),
                    _ => parts.push(p.to_owned()),
                }
            }
            let new_q = parts.join("&");
            let canonical = canonical_request(
                &View {
                    method,
                    path: &path,
                    query: Some(&new_q),
                    headers,
                    authority,
                },
                &signed,
                verified.canon,
                &payload,
            )
            .ok_or_else(|| err("a signed header is missing"))?;
            let sig = key.sign(&string_to_sign(&auth.amz_date, &scope, &canonical));
            let pq = format!("{path}?{new_q}&X-Amz-Signature={sig}");
            let mut up = uri.clone().into_parts();
            up.path_and_query = Some(pq.parse().map_err(|_| err("presigned URI"))?);
            *uri = Uri::from_parts(up).map_err(|_| err("presigned URI"))?;
            Ok(sig)
        }
    }
}

/// One side of a chunk-signature chain: a signing key and the previous signature.
struct Chain {
    key: SigningKey,
    prev: String,
}

impl Chain {
    fn chunk(&mut self, amz_date: &str, scope: &str, data: &[u8]) -> String {
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{}\n{EMPTY_SHA256}\n{}",
            self.prev,
            sha256_hex(data)
        );
        let s = self.key.sign(&sts);
        self.prev.clone_from(&s);
        s
    }

    fn trailer(&mut self, amz_date: &str, scope: &str, canonical_trailers: &[u8]) -> String {
        let sts = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{amz_date}\n{scope}\n{}\n{}",
            self.prev,
            sha256_hex(canonical_trailers)
        );
        self.key.sign(&sts)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    /// Reading `<hex size>;chunk-signature=<sig>\r\n`, then the whole chunk.
    Header,
    /// After the final chunk: trailer lines (trailer variant) or the closing `\r\n`.
    Trailer,
    Done,
}

/// Re-signs a chunk-signed body (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]`) as it streams:
/// checks each chunk's signature against the placeholder chain and writes the real chain's. A
/// chunk is held whole (its signature precedes its data), up to [`MAX_CHUNK`] bytes.
pub(crate) struct ChunkResigner {
    amz_date: String,
    scope: String,
    agent: Chain,
    real: Chain,
    trailer: bool,
    state: ChunkState,
    buf: Vec<u8>,
    trailer_lines: Vec<u8>,
}

impl ChunkResigner {
    pub(crate) fn new(
        auth: &Auth,
        agent_secret: &[u8],
        real_secret: &[u8],
        new_seed: String,
        trailer: bool,
    ) -> Self {
        let key = |s: &[u8]| SigningKey::derive(s, &auth.date, &auth.region, &auth.service);
        Self {
            amz_date: auth.amz_date.clone(),
            scope: auth.scope(),
            agent: Chain {
                key: key(agent_secret),
                prev: auth.signature.clone(),
            },
            real: Chain {
                key: key(real_secret),
                prev: new_seed,
            },
            trailer,
            state: ChunkState::Header,
            buf: Vec::new(),
            trailer_lines: Vec::new(),
        }
    }

    /// Feeds body bytes, appending re-signed output to `out`.
    pub(crate) fn push(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), SigError> {
        self.buf.extend_from_slice(data);
        loop {
            let progressed = match self.state {
                ChunkState::Header => self.chunk(out)?,
                ChunkState::Trailer => self.trailer_line(out)?,
                ChunkState::Done if self.buf.is_empty() => false,
                ChunkState::Done => return Err(err("a chunk-signed body continues after its end")),
            };
            if !progressed {
                return Ok(());
            }
        }
    }

    /// Re-signs one whole chunk if it is buffered. `false` when more input is needed.
    fn chunk(&mut self, out: &mut Vec<u8>) -> Result<bool, SigError> {
        let malformed = || err("a chunk header of a signed body is malformed");
        let Some(nl) = memchr::memmem::find(&self.buf, b"\r\n") else {
            return if self.buf.len() > 128 {
                Err(malformed())
            } else {
                Ok(false)
            };
        };
        let line = std::str::from_utf8(&self.buf[..nl]).map_err(|_| malformed())?;
        let (size, sig) = line
            .split_once(";chunk-signature=")
            .ok_or_else(|| err("a chunk of a signed body has no signature"))?;
        if size.is_empty() || size.len() > 8 || !is_hex64(sig) {
            return Err(malformed());
        }
        let size = usize::from_str_radix(size, 16).map_err(|_| malformed())?;
        if size > MAX_CHUNK {
            return Err(err("a chunk of a signed body is too large to re-sign"));
        }
        let start = nl + 2;
        let end = start + size + if size == 0 { 0 } else { 2 };
        if self.buf.len() < end {
            return Ok(false);
        }
        let sig = sig.to_owned();
        let chunk = self.buf[start..start + size].to_vec();
        let expect = self.agent.chunk(&self.amz_date, &self.scope, &chunk);
        if !same_sig(&expect, &sig) {
            return Err(err(
                "a chunk signature was not made with the placeholder secret",
            ));
        }
        let new = self.real.chunk(&self.amz_date, &self.scope, &chunk);
        let _ = write!(ByteWriter(out), "{size:x};chunk-signature={new}\r\n");
        out.extend_from_slice(&chunk);
        if size == 0 {
            self.state = ChunkState::Trailer;
        } else {
            if &self.buf[start + size..end] != b"\r\n" {
                return Err(err("a chunk of a signed body is not terminated"));
            }
            out.extend_from_slice(b"\r\n");
        }
        self.buf.drain(..end);
        Ok(true)
    }

    /// Handles one line after the final chunk. `false` when more input is needed.
    fn trailer_line(&mut self, out: &mut Vec<u8>) -> Result<bool, SigError> {
        let Some(nl) = memchr::memmem::find(&self.buf, b"\r\n") else {
            return if self.buf.len() > 8192 {
                Err(err("the trailer of a signed body is too long"))
            } else {
                Ok(false)
            };
        };
        let line = self.buf[..nl].to_vec();
        self.buf.drain(..nl + 2);
        if line.is_empty() {
            if self.trailer {
                return Err(err("the signed trailer has no signature"));
            }
            out.extend_from_slice(b"\r\n");
            self.state = ChunkState::Done;
            return Ok(true);
        }
        if !self.trailer {
            return Err(err(
                "a chunk-signed body carries a trailer it did not declare",
            ));
        }
        let malformed = || err("the trailer of a signed body is malformed");
        let text = std::str::from_utf8(&line).map_err(|_| malformed())?;
        let (name, value) = text.split_once(':').ok_or_else(malformed)?;
        if name.eq_ignore_ascii_case("x-amz-trailer-signature") {
            let expect = self
                .agent
                .trailer(&self.amz_date, &self.scope, &self.trailer_lines);
            if !same_sig(&expect, value.trim()) {
                return Err(err(
                    "the trailer signature was not made with the placeholder secret",
                ));
            }
            let new = self
                .real
                .trailer(&self.amz_date, &self.scope, &self.trailer_lines);
            let _ = write!(ByteWriter(out), "x-amz-trailer-signature:{new}\r\n");
            self.trailer = false;
        } else {
            if self.trailer_lines.len() + line.len() > 8192 {
                return Err(err("the trailer of a signed body is too long"));
            }
            self.trailer_lines
                .extend_from_slice(name.trim().to_ascii_lowercase().as_bytes());
            self.trailer_lines.push(b':');
            self.trailer_lines
                .extend_from_slice(value.trim().as_bytes());
            self.trailer_lines.push(b'\n');
            out.extend_from_slice(&line);
            out.extend_from_slice(b"\r\n");
        }
        Ok(true)
    }

    /// Ends the body: it must have reached its final chunk.
    pub(crate) fn finish(&mut self) -> Result<(), SigError> {
        if self.state == ChunkState::Done && self.buf.is_empty() {
            Ok(())
        } else {
            Err(err("a chunk-signed body ended early"))
        }
    }
}

struct ByteWriter<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for ByteWriter<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Signs chunks the way a client does, for tests: the seed signature and the body.
pub(crate) fn sign_chunks_for_test(
    auth: &Auth,
    secret: &[u8],
    chunks: &[&[u8]],
    trailers: &[(&str, &str)],
) -> Vec<u8> {
    let mut chain = Chain {
        key: SigningKey::derive(secret, &auth.date, &auth.region, &auth.service),
        prev: auth.signature.clone(),
    };
    let mut out = Vec::new();
    for c in chunks.iter().chain(std::iter::once(&&b""[..])) {
        let s = chain.chunk(&auth.amz_date, &auth.scope(), c);
        let _ = write!(
            ByteWriter(&mut out),
            "{:x};chunk-signature={s}\r\n",
            c.len()
        );
        out.extend_from_slice(c);
        if !c.is_empty() {
            out.extend_from_slice(b"\r\n");
        }
    }
    if trailers.is_empty() {
        out.extend_from_slice(b"\r\n");
    } else {
        let mut canon = Vec::new();
        for (k, v) in trailers {
            let _ = write!(ByteWriter(&mut out), "{k}:{v}\r\n");
            let _ = writeln!(
                ByteWriter(&mut canon),
                "{}:{}",
                k.to_ascii_lowercase(),
                v.trim()
            );
        }
        let s = chain.trailer(&auth.amz_date, &auth.scope(), &canon);
        let _ = write!(ByteWriter(&mut out), "x-amz-trailer-signature:{s}\r\n\r\n");
    }
    out
}

/// Signs a request from scratch, for tests and the fuzz target: header form.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_for_test(
    method: &Method,
    uri: &Uri,
    headers: &mut HeaderMap,
    access_key: &str,
    secret: &[u8],
    date_time: &str,
    region: &str,
    service: &str,
    payload: Option<&str>,
    body: &[u8],
) -> String {
    headers.insert(
        "x-amz-date",
        HeaderValue::from_str(date_time).unwrap_or_else(|_| HeaderValue::from_static("x")),
    );
    if let Some(p) = payload {
        headers.insert(
            "x-amz-content-sha256",
            HeaderValue::from_str(p).unwrap_or_else(|_| HeaderValue::from_static("x")),
        );
    }
    let mut signed: Vec<String> = headers.keys().map(|k| k.as_str().to_owned()).collect();
    signed.sort();
    signed.dedup();
    let auth = Auth {
        form: Form::Header,
        access_key: access_key.to_owned(),
        date: date_time[..8].to_owned(),
        region: region.to_owned(),
        service: service.to_owned(),
        amz_date: date_time.to_owned(),
        signed_headers: signed.clone(),
        signature: String::new(),
    };
    let hash = payload.map_or_else(|| sha256_hex(body), str::to_owned);
    let mode = Canon {
        mode: uri_modes(service)[0],
        token_unsigned: false,
    };
    let c = canonical_request(
        &View {
            method,
            path: uri.path(),
            query: uri.query(),
            headers,
            authority: None,
        },
        &signed,
        mode,
        &hash,
    )
    .unwrap_or_default();
    let sig = SigningKey::derive(secret, &auth.date, region, service).sign(&string_to_sign(
        date_time,
        &auth.scope(),
        &c,
    ));
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!(
            "{ALGORITHM} Credential={access_key}/{}, SignedHeaders={}, Signature={sig}",
            auth.scope(),
            signed.join(";")
        ))
        .unwrap_or_else(|_| HeaderValue::from_static("x")),
    );
    sig
}

/// Test support for integration tests and fuzz targets. Not a stable API.
#[doc(hidden)]
pub mod testing {
    use super::{HeaderMap, Method, Uri, View};

    /// Signs a request in the header form the way an AWS client does, signing every header
    /// present. Returns the signature.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        method: &Method,
        uri: &Uri,
        headers: &mut HeaderMap,
        access_key: &str,
        secret: &[u8],
        date_time: &str,
        region: &str,
        service: &str,
        payload: Option<&str>,
        body: &[u8],
    ) -> String {
        super::sign_for_test(
            method, uri, headers, access_key, secret, date_time, region, service, payload, body,
        )
    }

    /// The chunk-signed body for `chunks`, chained from the request's seed signature.
    pub fn sign_chunks(
        headers: &HeaderMap,
        uri: &Uri,
        secret: &[u8],
        chunks: &[&[u8]],
        trailers: &[(&str, &str)],
    ) -> Vec<u8> {
        match super::parse(uri, headers) {
            Ok(Some(a)) => super::sign_chunks_for_test(&a, secret, chunks, trailers),
            _ => Vec::new(),
        }
    }

    /// Whether the request carries a valid `SigV4` signature made with `secret`, and its access
    /// key id.
    pub fn verify(
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        secret: &[u8],
    ) -> Option<String> {
        let auth = super::parse(uri, headers).ok()??;
        let v = View {
            method,
            path: uri.path(),
            query: uri.query(),
            headers,
            authority: None,
        };
        super::verify(&auth, &v, body, [secret]).ok()??;
        Some(auth.access_key)
    }

    /// Parses an authorization: `(access key id, region, service)`, or the parse error.
    pub fn parse(
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<Option<(String, String, String)>, String> {
        super::parse(uri, headers)
            .map(|a| a.map(|a| (a.access_key, a.region, a.service)))
            .map_err(|e| e.0)
    }

    /// One fuzz iteration: the parsers and the chunk re-signer never panic on any input, and a
    /// request signed with one secret verifies, re-signs with another, and then verifies with
    /// that one only.
    #[allow(clippy::too_many_lines, clippy::panic)]
    pub fn fuzz_one(data: &[u8]) {
        use http::header::{AUTHORIZATION, HeaderValue};
        let parts: Vec<&[u8]> = data.splitn(6, |b| *b == 0).collect();
        let field = |i: usize| parts.get(i).copied().unwrap_or_default();
        let text = |i: usize| String::from_utf8_lossy(field(i)).into_owned();

        // Parsers on raw input.
        let mut h = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_bytes(field(0)) {
            h.insert(AUTHORIZATION, v);
        }
        if let Ok(v) = HeaderValue::from_bytes(field(1)) {
            h.insert("x-amz-date", v);
        }
        let q = text(2).replace([' ', '#', '"', '<', '>', '\\', '^', '`', '{', '|', '}'], "");
        let uri: Uri = format!("/p?{q}")
            .parse()
            .unwrap_or_else(|_| Uri::from_static("/"));
        if let Ok(Some(a)) = super::parse(&uri, &h) {
            let _ = super::verify(
                &a,
                &View {
                    method: &Method::GET,
                    path: uri.path(),
                    query: uri.query(),
                    headers: &h,
                    authority: None,
                },
                Some(field(3)),
                [b"s".as_slice()],
            );
        }
        let mut hq = HeaderMap::new();
        hq.insert("x-amz-date", HeaderValue::from_static("20260101T000000Z"));
        let _ = super::parse(&uri, &hq);
        // The chunk re-signer on raw input.
        let auth = super::Auth {
            form: super::Form::Header,
            access_key: "AK".into(),
            date: "20260101".into(),
            region: "us-east-1".into(),
            service: "s3".into(),
            amz_date: "20260101T000000Z".into(),
            signed_headers: vec!["host".into()],
            signature: "0".repeat(64),
        };
        for trailer in [false, true] {
            let mut c = super::ChunkResigner::new(&auth, b"a", b"b", "1".repeat(64), trailer);
            let mut out = Vec::new();
            for piece in field(3).chunks(7) {
                if c.push(piece, &mut out).is_err() {
                    break;
                }
            }
            let _ = c.finish();
        }

        // Round trip on a request built from the input.
        let path: String = text(4)
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "/-_.~%".contains(*c))
            .collect();
        let path = format!("/{path}");
        let Ok(uri) = format!("{path}?{q}").parse::<Uri>() else {
            return;
        };
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("s3.amazonaws.test"));
        if let Ok(v) = HeaderValue::from_bytes(field(5)) {
            h.insert("x-amz-meta-fuzz", v);
        }
        let body = field(3);
        let service = if data.first().is_some_and(|b| b & 1 == 1) {
            "s3"
        } else {
            "sts"
        };
        let payload = (service == "s3").then(|| super::sha256_hex(body));
        super::sign_for_test(
            &Method::PUT,
            &uri,
            &mut h,
            "AKAGENT",
            b"agent-secret",
            "20260101T000000Z",
            "us-east-1",
            service,
            payload.as_deref(),
            body,
        );
        let Ok(Some(auth)) = super::parse(&uri, &h) else {
            panic!("a request this module signed does not parse");
        };
        let view = |u: &Uri, hh: &HeaderMap| -> (String, Option<String>, HeaderMap) {
            (
                u.path().to_owned(),
                u.query().map(str::to_owned),
                hh.clone(),
            )
        };
        let (p0, q0, h0) = view(&uri, &h);
        let v0 = View {
            method: &Method::PUT,
            path: &p0,
            query: q0.as_deref(),
            headers: &h0,
            authority: None,
        };
        let Ok(Some(ok)) = super::verify(&auth, &v0, Some(body), [b"agent-secret".as_slice()])
        else {
            panic!("a request this module signed does not verify");
        };
        let (mut u2, mut h2) = (uri.clone(), h.clone());
        super::resign(
            &auth,
            &ok,
            &Method::PUT,
            &mut u2,
            &mut h2,
            None,
            Some(body),
            "AKREAL",
            b"real-secret",
        )
        .unwrap_or_else(|e| panic!("re-signing failed: {}", e.0));
        let a2 = super::parse(&u2, &h2)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("re-signed request does not parse"));
        let (p2, q2, hh2) = view(&u2, &h2);
        let v2 = View {
            method: &Method::PUT,
            path: &p2,
            query: q2.as_deref(),
            headers: &hh2,
            authority: None,
        };
        assert!(matches!(
            super::verify(&a2, &v2, Some(body), [b"real-secret".as_slice()]),
            Ok(Some(_))
        ));
        assert!(matches!(
            super::verify(&a2, &v2, Some(body), [b"agent-secret".as_slice()]),
            Ok(None)
        ));
    }

    /// Re-signs a chunk-signed body with the chain `secret` makes from `seed`, checking it was
    /// made with `agent` from the request's seed: the output, or the refusal.
    pub fn rechain(
        headers: &HeaderMap,
        uri: &Uri,
        agent: &[u8],
        secret: &[u8],
        seed: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, String> {
        let auth = super::parse(uri, headers)
            .map_err(|e| e.0)?
            .ok_or("not SigV4")?;
        let trailer = headers
            .get("x-amz-content-sha256")
            .is_some_and(|v| v.as_bytes().ends_with(b"-TRAILER"));
        let mut c = super::ChunkResigner::new(&auth, agent, secret, seed.to_owned(), trailer);
        let mut out = Vec::new();
        c.push(body, &mut out).map_err(|e| e.0)?;
        c.finish().map_err(|e| e.0)?;
        Ok(out)
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
    use std::path::Path;

    struct Vector {
        name: String,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    /// Parses a signed request file of the AWS signing test suite. `None` for requests `http`
    /// cannot represent (raw spaces or UTF-8 in the target, folded header lines).
    fn parse_request(name: &str, text: &str) -> Option<Vector> {
        let (head, body) = text.split_once("\n\n").unwrap_or((text, ""));
        let mut lines = head.lines();
        let first = lines.next()?;
        let rest = first.strip_suffix(" HTTP/1.1")?;
        let (m, target) = rest.split_once(' ')?;
        let uri: Uri = target.parse().ok()?;
        let mut headers = HeaderMap::new();
        for l in lines {
            let (k, v) = l.split_once(':')?;
            let name = http::HeaderName::from_bytes(k.as_bytes()).ok()?;
            headers.append(name, HeaderValue::from_str(v).ok()?);
        }
        Some(Vector {
            name: name.to_owned(),
            method: m.parse().ok()?,
            uri,
            headers,
            body: body.trim_end_matches('\n').as_bytes().to_vec(),
        })
    }

    fn suite() -> Vec<(Vector, serde_json::Value, &'static str)> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/aws-sigv4-test-suite");
        let mut out = Vec::new();
        let mut dirs: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();
        dirs.sort_by_key(|e| e.path());
        for d in dirs {
            let name = d.file_name().to_string_lossy().into_owned();
            let ctx: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(d.path().join("context.json")).unwrap(),
            )
            .unwrap();
            for (file, form) in [
                ("header-signed-request.txt", "header"),
                ("query-signed-request.txt", "query"),
            ] {
                let Ok(text) = std::fs::read_to_string(d.path().join(file)) else {
                    continue;
                };
                if let Some(v) = parse_request(&name, &text) {
                    out.push((v, ctx.clone(), form));
                }
            }
        }
        out
    }

    fn view<'a>(v: &'a Vector) -> View<'a> {
        View {
            method: &v.method,
            path: v.uri.path(),
            query: v.uri.query(),
            headers: &v.headers,
            authority: None,
        }
    }

    #[test]
    fn aws_test_suite_verifies_and_resigns_identically() {
        let all = suite();
        assert!(all.len() >= 50, "only {} vectors parsed", all.len());
        for (v, ctx, form) in &all {
            let secret = ctx["credentials"]["secret_access_key"].as_str().unwrap();
            let akid = ctx["credentials"]["access_key_id"].as_str().unwrap();
            let auth = parse(&v.uri, &v.headers)
                .unwrap_or_else(|e| panic!("{} {form}: {e:?}", v.name))
                .unwrap_or_else(|| panic!("{} {form}: not SigV4", v.name));
            assert_eq!(auth.access_key, akid);
            let body = Some(v.body.as_slice());
            let ok = verify(&auth, &view(v), body, [secret.as_bytes()]).unwrap();
            let ok = ok.unwrap_or_else(|| panic!("{} {form}: did not verify", v.name));
            assert!(
                verify(&auth, &view(v), body, [b"wrong secret".as_slice()])
                    .unwrap()
                    .is_none(),
                "{}",
                v.name
            );
            // Signing again with the same keys reproduces the vector's signature.
            let (mut uri, mut headers) = (v.uri.clone(), v.headers.clone());
            let sig = resign(
                &auth,
                &ok,
                &v.method,
                &mut uri,
                &mut headers,
                None,
                body,
                akid,
                secret.as_bytes(),
            )
            .unwrap();
            assert_eq!(sig, auth.signature, "{} {form}", v.name);
            let again = parse(&uri, &headers).unwrap().unwrap();
            assert_eq!(again.signature, auth.signature, "{} {form}", v.name);
            assert_eq!(
                again.signed_headers, auth.signed_headers,
                "{} {form}",
                v.name
            );
        }
    }

    #[test]
    fn canonical_requests_match_the_suite() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/aws-sigv4-test-suite");
        let mut checked = 0;
        for (v, ctx, form) in suite() {
            let file = format!("{form}-canonical-request.txt");
            let Ok(expected) = std::fs::read_to_string(root.join(&v.name).join(file)) else {
                continue;
            };
            let auth = parse(&v.uri, &v.headers).unwrap().unwrap();
            let mode = if ctx["normalize"].as_bool().unwrap_or(true) {
                UriMode::Normalized
            } else {
                UriMode::Encoded
            };
            let payload = match payload_candidates(&auth, &v.headers, Some(&v.body))
                .unwrap()
                .pop()
            {
                Some((_, p))
                    if form == "query" && !v.headers.contains_key("x-amz-content-sha256") =>
                {
                    if expected.ends_with(UNSIGNED) {
                        UNSIGNED.to_owned()
                    } else {
                        p
                    }
                }
                Some((_, p)) => p,
                None => unreachable!(),
            };
            let canon = Canon {
                mode,
                token_unsigned: ctx["omit_session_token"].as_bool().unwrap_or(false),
            };
            let got = canonical_request(&view(&v), &auth.signed_headers, canon, &payload).unwrap();
            assert_eq!(got, expected.trim_end_matches('\n'), "{} {form}", v.name);
            checked += 1;
        }
        assert!(checked >= 50, "{checked}");
    }

    fn auth_for(headers: &HeaderMap, uri: &Uri) -> Auth {
        parse(uri, headers).unwrap().unwrap()
    }

    #[test]
    fn placeholder_signed_request_is_resigned_with_the_real_secret() {
        let method = Method::PUT;
        let uri: Uri = "/bucket/key%20one?x-id=PutObject".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "s3.us-east-1.amazonaws.com".parse().unwrap());
        h.insert(
            "x-amz-security-token",
            "session-placeholder".parse().unwrap(),
        );
        let body = b"hello";
        sign_for_test(
            &method,
            &uri,
            &mut h,
            "AKIAPLACEHOLDER00000",
            b"placeholder-secret",
            "20260101T000000Z",
            "us-east-1",
            "s3",
            Some(&sha256_hex(body)),
            body,
        );
        let auth = auth_for(&h, &uri);
        let v = View {
            method: &method,
            path: uri.path(),
            query: uri.query(),
            headers: &h,
            authority: None,
        };
        let ok = verify(
            &auth,
            &v,
            Some(body),
            [b"other".as_slice(), b"placeholder-secret".as_slice()],
        )
        .unwrap()
        .unwrap();
        assert_eq!(ok.secret, 1);
        assert_eq!(ok.canon.mode, UriMode::S3);
        // Substitution swapped the session token and the body; re-sign with the real keys.
        let (mut uri2, mut h2) = (uri.clone(), h.clone());
        h2.insert("x-amz-security-token", "real-session".parse().unwrap());
        let new_body = b"hello, world";
        resign(
            &auth,
            &ok,
            &method,
            &mut uri2,
            &mut h2,
            None,
            Some(new_body),
            "AKIAREAL000000000000",
            b"real-secret",
        )
        .unwrap();
        assert_eq!(h2["x-amz-content-sha256"], sha256_hex(new_body).as_str());
        let a2 = auth_for(&h2, &uri2);
        assert_eq!(a2.access_key, "AKIAREAL000000000000");
        let v2 = View {
            method: &method,
            path: uri2.path(),
            query: uri2.query(),
            headers: &h2,
            authority: None,
        };
        assert!(
            verify(&a2, &v2, Some(new_body), [b"real-secret".as_slice()])
                .unwrap()
                .is_some()
        );
        assert!(
            verify(&a2, &v2, Some(new_body), [b"placeholder-secret".as_slice()])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn removed_headers_leave_the_signed_list() {
        let method = Method::PUT;
        let uri: Uri = "/b/k".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "s3.amazonaws.com".parse().unwrap());
        h.insert(header::EXPECT, "100-continue".parse().unwrap());
        sign_for_test(
            &method,
            &uri,
            &mut h,
            "AK",
            b"p",
            "20260101T000000Z",
            "us-east-1",
            "s3",
            Some(UNSIGNED),
            b"",
        );
        let auth = auth_for(&h, &uri);
        let v = View {
            method: &method,
            path: uri.path(),
            query: uri.query(),
            headers: &h,
            authority: None,
        };
        let ok = verify(&auth, &v, None, [b"p".as_slice()]).unwrap().unwrap();
        let (mut uri2, mut h2) = (uri.clone(), h.clone());
        h2.remove(header::EXPECT);
        resign(
            &auth, &ok, &method, &mut uri2, &mut h2, None, None, "AKREAL", b"r",
        )
        .unwrap();
        let a2 = auth_for(&h2, &uri2);
        assert!(!a2.signed_headers.contains(&"expect".to_owned()));
    }

    #[test]
    fn presigned_query_is_resigned() {
        let (v, ctx, _) = suite()
            .into_iter()
            .find(|(v, _, f)| v.name == "get-vanilla-with-session-token" && *f == "query")
            .unwrap();
        let secret = ctx["credentials"]["secret_access_key"].as_str().unwrap();
        let auth = auth_for(&v.headers, &v.uri);
        assert_eq!(auth.form, Form::Query);
        let ok = verify(&auth, &view(&v), Some(&v.body), [secret.as_bytes()])
            .unwrap()
            .unwrap();
        let mut uri = v.uri.clone();
        let mut h = v.headers.clone();
        resign(
            &auth,
            &ok,
            &v.method,
            &mut uri,
            &mut h,
            None,
            Some(&v.body),
            "AKIDREAL",
            b"real",
        )
        .unwrap();
        let a2 = auth_for(&h, &uri);
        assert_eq!(a2.access_key, "AKIDREAL");
        let v2 = View {
            method: &v.method,
            path: uri.path(),
            query: uri.query(),
            headers: &h,
            authority: None,
        };
        assert!(
            verify(&a2, &v2, Some(&v.body), [b"real".as_slice()])
                .unwrap()
                .is_some()
        );
        assert_eq!(uri.query().unwrap().matches("X-Amz-Signature=").count(), 1);
    }

    #[test]
    fn chunk_signatures_are_rechained() {
        let method = Method::PUT;
        let uri: Uri = "/examplebucket/chunkObject.txt".parse().unwrap();
        for trailers in [&[][..], &[("x-amz-checksum-crc32c", "sOO8/Q==")][..]] {
            let kw = if trailers.is_empty() {
                STREAMING
            } else {
                STREAMING_TRAILER
            };
            let mut h = HeaderMap::new();
            h.insert(header::HOST, "s3.amazonaws.com".parse().unwrap());
            h.insert("x-amz-decoded-content-length", "66560".parse().unwrap());
            sign_for_test(
                &method,
                &uri,
                &mut h,
                "AK",
                b"agent",
                "20130524T000000Z",
                "us-east-1",
                "s3",
                Some(kw),
                b"",
            );
            let auth = auth_for(&h, &uri);
            let a = vec![b'a'; 65536];
            let b = vec![b'b'; 1024];
            let body = sign_chunks_for_test(&auth, b"agent", &[&a, &b], trailers);
            let v = View {
                method: &method,
                path: uri.path(),
                query: uri.query(),
                headers: &h,
                authority: None,
            };
            let ok = verify(&auth, &v, None, [b"agent".as_slice()])
                .unwrap()
                .unwrap();
            assert_eq!(ok.payload.chunk_signed(), Some(!trailers.is_empty()));
            let (mut uri2, mut h2) = (uri.clone(), h.clone());
            let seed = resign(
                &auth, &ok, &method, &mut uri2, &mut h2, None, None, "AKREAL", b"real",
            )
            .unwrap();
            // Fed in odd pieces, the output equals a body the real key signed from the start.
            let mut cr =
                ChunkResigner::new(&auth, b"agent", b"real", seed.clone(), !trailers.is_empty());
            let mut out = Vec::new();
            for piece in body.chunks(777) {
                cr.push(piece, &mut out).unwrap();
            }
            cr.finish().unwrap();
            let mut real_auth = auth.clone();
            real_auth.signature = seed.clone();
            assert_eq!(
                out,
                sign_chunks_for_test(&real_auth, b"real", &[&a, &b], trailers)
            );
            assert_eq!(out.len(), body.len());
            // A chunk signed with another key is refused.
            let forged = sign_chunks_for_test(&auth, b"other", &[&a], trailers);
            let mut cr =
                ChunkResigner::new(&auth, b"agent", b"real", seed.clone(), !trailers.is_empty());
            assert!(cr.push(&forged, &mut Vec::new()).is_err());
            // A truncated body does not finish.
            let mut cr = ChunkResigner::new(&auth, b"agent", b"real", seed, !trailers.is_empty());
            cr.push(&body[..body.len() - 10], &mut Vec::new()).unwrap();
            assert!(cr.finish().is_err());
        }
    }

    #[test]
    fn s3_documented_chunked_example() {
        // "Signature Calculations for the Authorization Header: Transferring Payload in Multiple
        // Chunks", Amazon S3 API reference: seed and chunk signatures.
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "s3.amazonaws.com".parse().unwrap());
        h.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        h.insert("x-amz-storage-class", "REDUCED_REDUNDANCY".parse().unwrap());
        h.insert("x-amz-content-sha256", STREAMING.parse().unwrap());
        h.insert(header::CONTENT_ENCODING, "aws-chunked".parse().unwrap());
        h.insert("x-amz-decoded-content-length", "66560".parse().unwrap());
        h.insert(header::CONTENT_LENGTH, "66824".parse().unwrap());
        h.insert(header::AUTHORIZATION, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class, Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9".parse().unwrap());
        let uri: Uri = "/examplebucket/chunkObject.txt".parse().unwrap();
        let auth = auth_for(&h, &uri);
        let secret = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let v = View {
            method: &Method::PUT,
            path: uri.path(),
            query: None,
            headers: &h,
            authority: None,
        };
        assert!(
            verify(&auth, &v, None, [secret.as_slice()])
                .unwrap()
                .is_some()
        );
        let body =
            sign_chunks_for_test(&auth, secret, &[&vec![b'a'; 65536], &vec![b'a'; 1024]], &[]);
        let text = String::from_utf8_lossy(&body);
        assert!(text.starts_with("10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n"));
        assert!(text.contains("400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n"));
        assert!(text.contains(
            "0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n"
        ));
        assert_eq!(body.len(), 66824);
    }

    #[test]
    fn malformed_authorizations_are_refused_not_panicking() {
        let uri: Uri = "/".parse().unwrap();
        for a in [
            "AWS4-ECDSA-P256-SHA256 Credential=x",
            "AWS4-HMAC-SHA256 Credential=AK/20150830/us-east-1/s/aws4_request",
            "AWS4-HMAC-SHA256 Credential=AK/2015/us-east-1/s/aws4_request, SignedHeaders=host, Signature=00",
            "AWS4-HMAC-SHA256 Credential=AK/20150830/us-east-1/s/aws4_request, SignedHeaders=x-b;host, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
            "AWS4-HMAC-SHA256 Credential=AK/20150830/us-east-1/s/aws4_request, Credential=x, SignedHeaders=host, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        ] {
            let mut h = HeaderMap::new();
            h.insert(header::AUTHORIZATION, a.parse().unwrap());
            h.insert("x-amz-date", "20150830T123600Z".parse().unwrap());
            assert!(parse(&uri, &h).is_err(), "{a}");
        }
        assert_eq!(parse(&uri, &HeaderMap::new()), Ok(None));
    }
}
