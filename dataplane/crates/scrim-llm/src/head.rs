// SPDX-License-Identifier: AGPL-3.0-only

//! Redacts and guards what leaves outside the body: the request target (path and query) and
//! every request header forwarded upstream.
//!
//! The body has its own codec plan ([`crate::outgoing`]); this is the same two checks for the
//! request head. Header values and target components are redacted on their raw bytes, then on
//! their decoded form (percent-decoding, and `+` as a space in the query) so a value a client
//! URL-encoded is still found; a component whose decoded form changed is re-encoded. The guard
//! then checks the exact outgoing request line and header block, plus the decoded view of every
//! target component. When the whole head is clean (the common case) that is one guard call per
//! view; otherwise each component is repaired on its own and the head is checked again, and
//! anything still found is refused.
//!
//! A header value is visible ASCII on the wire (RFC 9110 `field-value`; strict provider front
//! ends reject obs-text), so every placeholder in one leaves in its percent form: the
//! placeholder's non-ASCII brackets percent-encoded, `%E2%9F%A6scrim:<slug>:<vv><tag>%E2%9F%A7`.
//! That form resolves like the placeholder and the guard reads through it. In the request target
//! the same bytes come out of the target's own percent-encoding.
//!
//! Only the agent's own provider credentials ([`PASSTHROUGH`], and on a Gemini route the `key`
//! and `access_token` query parameters, [`crate::Provider::query_credentials`]) are forwarded
//! untouched: they skip both checks, as the spec requires, and capture masks them. Every other
//! header and query parameter is redacted, known or not (design D4 applied to headers).

use http::header::{HeaderMap, HeaderName, HeaderValue};

use crate::audit::RefusalReason;
use crate::engine::{GuardVerdict, PlaceholderMatch, RedactReport, SecretRef, Snapshot};
use crate::error::Refusal;

/// Request headers forwarded byte for byte, never redacted or guarded: the agent's own provider
/// authentication. Capture masks them (they are not in [`crate::capture::RECORDED_HEADERS`])
/// and nothing logs header values.
pub const PASSTHROUGH: &[&str] = &["authorization", "x-api-key", "x-goog-api-key"];

/// What the head checks did.
#[derive(Debug, Default)]
pub struct Head {
    /// The path to forward.
    pub path: String,
    /// The query to forward, without `?`.
    pub query: Option<String>,
    /// What the redactor replaced in the head.
    pub report: RedactReport,
    /// References the guard repaired in the head.
    pub guard_repaired: Vec<SecretRef>,
}

impl Head {
    fn repaired(&mut self, refs: Vec<SecretRef>) {
        for r in refs {
            if !self.guard_repaired.contains(&r) {
                self.guard_repaired.push(r);
            }
        }
    }
}

/// Which grammar a target component follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Syntax {
    /// A path segment: `%XX` only.
    Path,
    /// A query key or value: `%XX`, and `+` may stand for a space.
    Query,
}

/// Redacts and guards `path`, `query` and `headers` (already stripped of hop-by-hop headers).
/// `headers` is rewritten in place; the returned [`Head`] carries the target to forward.
pub fn prepare(
    snap: &Snapshot,
    method: &http::Method,
    path: &str,
    query: Option<&str>,
    headers: &mut HeaderMap,
) -> Result<Head, Refusal> {
    prepare_with(snap, method, path, query, headers, &[])
}

/// [`prepare`], forwarding the values of the query parameters named in `query_credentials`
/// (the agent's own provider credential, matched on the raw key) untouched: they are neither
/// redacted nor guarded.
pub fn prepare_with(
    snap: &Snapshot,
    method: &http::Method,
    path: &str,
    query: Option<&str>,
    headers: &mut HeaderMap,
    query_credentials: &[&str],
) -> Result<Head, Refusal> {
    let mut head = Head::default();

    // Request target: redact each component, raw then decoded.
    let mut segs: Vec<Vec<u8>> = path
        .as_bytes()
        .split(|&b| b == b'/')
        .map(|s| redact_component(snap, s, Syntax::Path, &mut head.report))
        .collect::<Result<_, _>>()?;
    let mut pairs = match query {
        None => Vec::new(),
        Some(q) => redact_query(snap, q, query_credentials, &mut head.report)?,
    };
    let creds = query_credentials;
    if !target_clean(snap, method, &segs, query.is_some(), &pairs, creds)? {
        for s in &mut segs {
            guard_component(snap, s, Syntax::Path, &mut head)?;
        }
        for (k, v) in &mut pairs {
            if is_credential(k, creds) {
                continue;
            }
            guard_component(snap, k, Syntax::Query, &mut head)?;
            if let Some(v) = v {
                guard_component(snap, v, Syntax::Query, &mut head)?;
            }
        }
        if !target_clean(snap, method, &segs, query.is_some(), &pairs, creds)? {
            return Err(guard_refused(Vec::new()));
        }
    }
    head.path = utf8(segs.join(&b'/'))?;
    head.query = query
        .is_some()
        .then(|| utf8(join_query(&pairs)))
        .transpose()?;

    // Headers: every value but the agent's own credentials.
    let old = std::mem::take(headers);
    let mut last: Option<HeaderName> = None;
    let mut values: Vec<(HeaderName, Vec<u8>, bool)> = Vec::with_capacity(old.len());
    for (name, value) in old {
        let name = match name {
            Some(n) => {
                last = Some(n.clone());
                n
            }
            None => match &last {
                Some(n) => n.clone(),
                None => continue,
            },
        };
        let pass = PASSTHROUGH.contains(&name.as_str());
        let bytes = if pass {
            value.as_bytes().to_vec()
        } else {
            let mut out = Vec::with_capacity(value.len());
            head.report.merge(redact(snap, value.as_bytes(), &mut out)?);
            ascii_placeholders(snap, out)
        };
        values.push((name, bytes, pass));
    }
    if !headers_clean(snap, &values)? {
        for (_, v, pass) in &mut values {
            if *pass {
                continue;
            }
            match guard(snap, v)? {
                GuardVerdict::Clean => {}
                GuardVerdict::Repaired { bytes, refs } => {
                    head.repaired(refs);
                    *v = ascii_placeholders(snap, bytes);
                }
                GuardVerdict::Refused { refs } => return Err(guard_refused(refs)),
            }
        }
        // Still found: in a header name, or split across headers. Nothing to repair.
        if !headers_clean(snap, &values)? {
            return Err(guard_refused(Vec::new()));
        }
    }
    for (name, v, _) in values {
        let v = HeaderValue::from_bytes(&v).map_err(|_| {
            Refusal::new(
                RefusalReason::RedactorFailed,
                format!("header {name} is not a valid value after redaction"),
            )
        })?;
        headers.append(name, v);
    }
    Ok(head)
}

/// Rewrites every placeholder in a header value to its percent form: each non-ASCII byte of
/// the placeholder (its two brackets) becomes `%XX`. Everything else is left as the agent sent
/// it.
fn ascii_placeholders(snap: &Snapshot, v: Vec<u8>) -> Vec<u8> {
    if v.is_ascii() {
        return v;
    }
    let mut out = Vec::with_capacity(v.len() + 16);
    for chunk in v.utf8_chunks() {
        let mut text = chunk.valid();
        while let Some(m) = snap.placeholders.find(text) {
            let PlaceholderMatch::Complete { start, end } = m else {
                break;
            };
            out.extend_from_slice(&text.as_bytes()[..start]);
            for &b in &text.as_bytes()[start..end] {
                if b.is_ascii() {
                    out.push(b);
                } else {
                    pct(&mut out, b);
                }
            }
            text = &text[end..];
        }
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(chunk.invalid());
    }
    out
}

fn redact(snap: &Snapshot, input: &[u8], out: &mut Vec<u8>) -> Result<RedactReport, Refusal> {
    if input.is_empty() {
        return Ok(RedactReport::default());
    }
    snap.redactor
        .redact(input, out)
        .map_err(|e| Refusal::new(RefusalReason::RedactorFailed, e.message().to_string()))
}

fn guard(snap: &Snapshot, bytes: &[u8]) -> Result<GuardVerdict, Refusal> {
    snap.guard
        .check(bytes)
        .map_err(|e| Refusal::new(RefusalReason::GuardFailed, e.message().to_string()))
}

fn guard_refused(refs: Vec<SecretRef>) -> Refusal {
    Refusal {
        reason: RefusalReason::GuardRefused,
        detail: String::new(),
        refs,
    }
}

fn utf8(b: Vec<u8>) -> Result<String, Refusal> {
    // Every byte outside printable ASCII is percent-encoded by `escape`.
    String::from_utf8(b).map_err(|_| {
        Refusal::new(
            RefusalReason::RedactorFailed,
            "request target is not valid after redaction",
        )
    })
}

/// Redacts one target component on its raw bytes and on each decoded reading of it.
fn redact_component(
    snap: &Snapshot,
    raw: &[u8],
    syn: Syntax,
    report: &mut RedactReport,
) -> Result<Vec<u8>, Refusal> {
    let mut cur = Vec::with_capacity(raw.len());
    report.merge(redact(snap, raw, &mut cur)?);
    for &plus in readings(&cur, syn) {
        let Some(d) = decode(&cur, plus) else {
            continue;
        };
        let mut out = Vec::with_capacity(d.len());
        let r = redact(snap, &d, &mut out)?;
        if r.replacements > 0 {
            report.merge(r);
            cur = encode(&out);
        }
    }
    Ok(escape(&cur))
}

/// Repairs one component with the guard: exact bytes, then each decoded reading.
fn guard_component(
    snap: &Snapshot,
    cur: &mut Vec<u8>,
    syn: Syntax,
    head: &mut Head,
) -> Result<(), Refusal> {
    match guard(snap, cur)? {
        GuardVerdict::Clean => {}
        GuardVerdict::Repaired { bytes, refs } => {
            head.repaired(refs);
            *cur = escape(&bytes);
        }
        GuardVerdict::Refused { refs } => return Err(guard_refused(refs)),
    }
    for &plus in readings(cur, syn) {
        let Some(d) = decode(cur, plus) else {
            continue;
        };
        match guard(snap, &d)? {
            GuardVerdict::Clean => {}
            GuardVerdict::Repaired { bytes, refs } => {
                head.repaired(refs);
                *cur = encode(&bytes);
            }
            GuardVerdict::Refused { refs } => return Err(guard_refused(refs)),
        }
    }
    Ok(())
}

/// The decoded readings of a component: `+` as a space (query only), then `+` as itself.
fn readings(cur: &[u8], syn: Syntax) -> &'static [bool] {
    match syn {
        Syntax::Query if cur.contains(&b'+') => &[true, false],
        Syntax::Query => &[true],
        Syntax::Path => &[false],
    }
}

/// A query key and its value, if it has one.
type QueryPair = (Vec<u8>, Option<Vec<u8>>);

/// Splits `query` into pairs and redacts each key and value, credential values excepted.
fn redact_query(
    snap: &Snapshot,
    query: &str,
    creds: &[&str],
    report: &mut RedactReport,
) -> Result<Vec<QueryPair>, Refusal> {
    query
        .as_bytes()
        .split(|&b| b == b'&')
        .map(|p| {
            let (k, v) = match memchr::memchr(b'=', p) {
                Some(i) => (&p[..i], Some(&p[i + 1..])),
                None => (p, None),
            };
            if is_credential(k, creds) {
                return Ok((k.to_vec(), v.map(<[u8]>::to_vec)));
            }
            let k = redact_component(snap, k, Syntax::Query, report)?;
            let v = v
                .map(|v| redact_component(snap, v, Syntax::Query, report))
                .transpose()?;
            Ok((k, v))
        })
        .collect()
}

/// Whether the raw query key `k` names a credential parameter.
fn is_credential(k: &[u8], creds: &[&str]) -> bool {
    creds.iter().any(|c| c.as_bytes() == k)
}

/// One guard pass over the exact request line and over the decoded query and path, the values
/// of credential parameters excepted.
fn target_clean(
    snap: &Snapshot,
    method: &http::Method,
    segs: &[Vec<u8>],
    has_query: bool,
    pairs: &[(Vec<u8>, Option<Vec<u8>>)],
    creds: &[&str],
) -> Result<bool, Refusal> {
    let masked;
    let pairs = if pairs.iter().any(|(k, _)| is_credential(k, creds)) {
        masked = pairs
            .iter()
            .map(|(k, v)| {
                let v = if is_credential(k, creds) {
                    v.as_ref().map(|_| Vec::new())
                } else {
                    v.clone()
                };
                (k.clone(), v)
            })
            .collect::<Vec<_>>();
        &masked[..]
    } else {
        pairs
    };
    let path = segs.join(&b'/');
    let mut line = Vec::with_capacity(path.len() + 64);
    line.extend_from_slice(method.as_str().as_bytes());
    line.push(b' ');
    line.extend_from_slice(&path);
    if has_query {
        line.push(b'?');
        line.extend_from_slice(&join_query(pairs));
    }
    if !matches!(guard(snap, &line)?, GuardVerdict::Clean) {
        return Ok(false);
    }
    // The decoded view: what a server that percent-decodes (and maps `+`) would see.
    let mut view = Vec::with_capacity(line.len());
    for s in segs {
        view.extend_from_slice(&decode(s, false).unwrap_or_else(|| s.clone()));
        view.push(b'\n');
    }
    for (k, v) in pairs {
        for c in std::iter::once(k).chain(v) {
            view.extend_from_slice(&decode(c, true).unwrap_or_else(|| c.clone()));
            view.push(b'\n');
            if c.contains(&b'+') {
                view.extend_from_slice(&decode(c, false).unwrap_or_else(|| c.clone()));
                view.push(b'\n');
            }
        }
    }
    Ok(matches!(guard(snap, &view)?, GuardVerdict::Clean))
}

/// One guard pass over the exact header block as it leaves, credentials excepted.
fn headers_clean(snap: &Snapshot, values: &[(HeaderName, Vec<u8>, bool)]) -> Result<bool, Refusal> {
    let mut block = Vec::with_capacity(
        values
            .iter()
            .map(|(n, v, _)| n.as_str().len() + v.len() + 4)
            .sum(),
    );
    for (n, v, pass) in values {
        if *pass {
            continue;
        }
        block.extend_from_slice(n.as_str().as_bytes());
        block.extend_from_slice(b": ");
        block.extend_from_slice(v);
        block.extend_from_slice(b"\r\n");
    }
    if block.is_empty() {
        return Ok(true);
    }
    Ok(matches!(guard(snap, &block)?, GuardVerdict::Clean))
}

fn join_query(pairs: &[(Vec<u8>, Option<Vec<u8>>)]) -> Vec<u8> {
    let mut q = Vec::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            q.push(b'&');
        }
        q.extend_from_slice(k);
        if let Some(v) = v {
            q.push(b'=');
            q.extend_from_slice(v);
        }
    }
    q
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes `s` (`+` as a space when `plus`); `None` when that changes nothing.
/// A `%` not followed by two hex digits stays as it is.
fn decode(s: &[u8], plus: bool) -> Option<Vec<u8>> {
    if !s.iter().any(|&b| b == b'%' || (plus && b == b'+')) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' if i + 2 < s.len() => match (hex(s[i + 1]), hex(s[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' if plus => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    (out != s).then_some(out)
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn pct(out: &mut Vec<u8>, b: u8) {
    out.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn encode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 3);
    for &b in s {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            pct(&mut out, b);
        }
    }
    out
}

/// Percent-encodes only the bytes a request target cannot carry (a placeholder's non-ASCII
/// brackets, controls, space, `#`), leaving existing escapes and delimiters alone.
fn escape(s: &[u8]) -> Vec<u8> {
    if s.iter().all(|&b| b > 0x20 && b < 0x7f && b != b'#') {
        return s.to_vec();
    }
    let mut out = Vec::with_capacity(s.len() + 16);
    for &b in s {
        if b > 0x20 && b < 0x7f && b != b'#' {
            out.push(b);
        } else {
            pct(&mut out, b);
        }
    }
    out
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::*;
    use crate::testing::{Fault, Fixture, GuardMode};

    const V: &str = "alpha secret+value/01=";

    fn fx() -> Fixture {
        Fixture::new(&[("a", V)])
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn run(
        fx: &Fixture,
        path: &str,
        query: Option<&str>,
        h: &mut HeaderMap,
    ) -> Result<Head, Refusal> {
        prepare(&fx.snapshot(), &http::Method::POST, path, query, h)
    }

    /// Every decoded reading of the forwarded target, for leak checks.
    fn decoded(head: &Head) -> Vec<u8> {
        let mut all = head.path.clone().into_bytes();
        if let Some(q) = &head.query {
            all.extend_from_slice(q.as_bytes());
            all.extend(decode(q.as_bytes(), true).unwrap_or_default());
            all.extend(decode(q.as_bytes(), false).unwrap_or_default());
        }
        all.extend(decode(head.path.as_bytes(), false).unwrap_or_default());
        all
    }

    #[test]
    fn custom_headers_are_redacted_and_credentials_pass_through() {
        let fx = fx();
        let mut h = headers(&[
            ("x-debug-context", &format!("token {V} end")),
            ("x-meta", &format!("k=\"{V}\"; q=1")),
            ("x-debug-context", "second"),
            ("authorization", &format!("Bearer {V}")),
            ("x-api-key", V),
        ]);
        let head = run(&fx, "/v1/messages", None, &mut h).unwrap();
        let ph = fx.placeholder_ascii("a");
        let all: Vec<_> = h.get_all("x-debug-context").iter().collect();
        assert_eq!(all.len(), 2, "every value of a repeated header is kept");
        assert_eq!(all[0].as_bytes(), format!("token {ph} end").as_bytes());
        assert_eq!(all[1], "second");
        assert_eq!(
            h["x-meta"].as_bytes(),
            format!("k=\"{ph}\"; q=1").as_bytes()
        );
        // The agent's own provider credentials leave exactly as sent.
        assert_eq!(
            h["authorization"].as_bytes(),
            format!("Bearer {V}").as_bytes()
        );
        assert_eq!(h["x-api-key"].as_bytes(), V.as_bytes());
        assert_eq!(head.report.replacements, 2);
        assert_eq!(head.guard_repaired, [] as [SecretRef; 0]);
        assert_eq!(
            PASSTHROUGH,
            ["authorization", "x-api-key", "x-goog-api-key"]
        );
    }

    /// RFC 9110 `field-value` without obs-text: visible ASCII, space and tab.
    fn field_value(v: &[u8]) -> bool {
        v.iter()
            .all(|&b| b == b' ' || b == b'\t' || b.is_ascii_graphic())
    }

    #[test]
    fn header_placeholders_are_visible_ascii_and_resolve() {
        let mut fx = fx();
        let ph = fx.placeholder_ascii("a");
        assert!(ph.starts_with("%E2%9F%A6scrim:a:") && ph.ends_with("%E2%9F%A7"));
        // Redacted, and repaired by the guard when the redactor misses.
        for miss in [false, true] {
            fx.redactor_misses = if miss { vec!["a".into()] } else { vec![] };
            let mut h = headers(&[("x-debug-context", &format!("token {V} end"))]);
            let head = run(&fx, "/v1/messages", None, &mut h).unwrap();
            let v = h["x-debug-context"].as_bytes();
            assert!(field_value(v), "{}", String::from_utf8_lossy(v));
            assert_eq!(v, format!("token {ph} end").as_bytes(), "miss {miss}");
            assert_eq!(head.guard_repaired.len(), usize::from(miss));
            let snap = fx.snapshot();
            let r = snap
                .placeholders
                .resolve(&ph)
                .expect("percent form resolves");
            assert_eq!(r.value.expose(), V.as_bytes());
        }
        // Other non-ASCII bytes the agent sent are its own; only placeholders are rewritten.
        fx.redactor_misses.clear();
        let mut h = HeaderMap::new();
        let mut raw = format!("caf\u{e9} {V} ").into_bytes();
        raw.push(0xff);
        h.insert("x-note", HeaderValue::from_bytes(&raw).unwrap());
        run(&fx, "/v1/messages", None, &mut h).unwrap();
        let mut want = format!("caf\u{e9} {ph} ").into_bytes();
        want.push(0xff);
        assert_eq!(h["x-note"].as_bytes(), want);
    }

    #[test]
    fn known_config_headers_are_redacted_too() {
        let fx = fx();
        let mut h = headers(&[("anthropic-beta", V), ("user-agent", V)]);
        run(&fx, "/v1/messages", None, &mut h).unwrap();
        assert_eq!(fx.leaks(h["anthropic-beta"].as_bytes()), [] as [String; 0]);
        assert_eq!(fx.leaks(h["user-agent"].as_bytes()), [] as [String; 0]);
    }

    #[test]
    fn query_is_redacted_raw_form_and_percent_encoded() {
        let fx = fx();
        let form = encode(V.as_bytes()); // `%20`, `%2B`, `%2F`, `%3D`
        let plus = String::from_utf8(form.clone()).unwrap().replace("%20", "+");
        for q in [
            format!("trace={}", String::from_utf8(form.clone()).unwrap()),
            format!("trace={plus}&beta=true"),
            format!("{plus}=x"),
        ] {
            let mut h = HeaderMap::new();
            let head = run(&fx, "/v1/messages", Some(&q), &mut h).unwrap();
            let out = head.query.clone().unwrap();
            assert_eq!(fx.leaks(&decoded(&head)), [] as [String; 0], "{q}");
            assert!(out.is_ascii(), "{q}");
            let ph = encode(fx.placeholder("a").as_bytes());
            assert!(out.as_bytes().windows(ph.len()).any(|w| w == ph), "{q}");
            assert_eq!(head.report.replacements, 1, "{q}");
            if q.ends_with("&beta=true") {
                assert!(out.ends_with("&beta=true"), "other pairs are untouched");
            }
            // The target is still a valid URI.
            format!("/v1/messages?{out}").parse::<http::Uri>().unwrap();
        }
    }

    #[test]
    fn path_segments_are_redacted() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let mut h = HeaderMap::new();
        let head = run(
            &fx,
            "/v1/files/alpha%2Dsecret-value-01/content",
            None,
            &mut h,
        )
        .unwrap();
        assert_eq!(
            fx.leaks(&decoded(&head)),
            [] as [String; 0],
            "{}",
            head.path
        );
        assert!(
            head.path.starts_with("/v1/files/%E2%9F%A6"),
            "{}",
            head.path
        );
        assert!(head.path.ends_with("/content"));
        format!("{}?x", head.path).parse::<http::Uri>().unwrap();
    }

    #[test]
    fn clean_head_is_unchanged() {
        let fx = fx();
        let mut h = headers(&[("content-type", "application/json"), ("x-a", "b c")]);
        let before = h.clone();
        let head = run(&fx, "/v1/chat/completions", Some("a=b+c&d=%41&e"), &mut h).unwrap();
        assert_eq!(h, before);
        assert_eq!(head.path, "/v1/chat/completions");
        assert_eq!(head.query.as_deref(), Some("a=b+c&d=%41&e"));
        assert_eq!(head.report.replacements, 0);
    }

    #[test]
    fn guard_checks_headers_and_target_when_the_redactor_misses() {
        let mut fx = fx();
        fx.redactor_misses = vec!["a".into()];
        let enc = String::from_utf8(encode(V.as_bytes())).unwrap();
        let mut h = headers(&[("x-debug-context", V), ("x-api-key", V)]);
        let head = run(&fx, "/v1/messages", Some(&format!("trace={enc}")), &mut h).unwrap();
        assert_eq!(head.report.replacements, 0, "the redactor was bypassed");
        assert_eq!(head.guard_repaired, vec![SecretRef::new("a")]);
        assert_eq!(fx.leaks(h["x-debug-context"].as_bytes()), [] as [String; 0]);
        assert_eq!(fx.leaks(&decoded(&head)), [] as [String; 0]);
        assert_eq!(
            h["x-api-key"].as_bytes(),
            V.as_bytes(),
            "credentials are not guarded"
        );

        fx.guard_mode = GuardMode::Refuse;
        for (q, hv) in [(Some(enc.as_str()), "clean"), (None, V)] {
            let mut h = headers(&[("x-debug-context", hv)]);
            let e = run(&fx, "/v1/messages", q, &mut h).unwrap_err();
            assert_eq!(e.reason, RefusalReason::GuardRefused);
            assert_eq!(e.refs, vec![SecretRef::new("a")]);
        }
    }

    #[test]
    fn value_in_a_header_name_is_refused() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let mut h = headers(&[("alpha-secret-value-01", "1")]);
        let e = run(&fx, "/v1/messages", None, &mut h).unwrap_err();
        assert_eq!(e.reason, RefusalReason::GuardRefused);
    }

    #[test]
    fn errors_fail_closed() {
        let mut fx = fx();
        fx.redactor_fault = Fault::Error;
        let mut h = headers(&[("x-a", "b")]);
        let e = run(&fx, "/v1/messages", None, &mut h).unwrap_err();
        assert_eq!(e.reason, RefusalReason::RedactorFailed);
        fx.redactor_fault = Fault::None;
        fx.guard_fault = Fault::Error;
        let e = run(&fx, "/v1/messages", Some("a=b"), &mut h).unwrap_err();
        assert_eq!(e.reason, RefusalReason::GuardFailed);
    }

    #[test]
    fn codec_helpers() {
        assert_eq!(decode(b"a+b%2Bc%zz%4", true).unwrap(), b"a b+c%zz%4");
        assert_eq!(decode(b"a+b%2Bc", false).unwrap(), b"a+b+c");
        assert_eq!(decode(b"plain", true), None);
        assert_eq!(encode(b"a b/+~"), b"a%20b%2F%2B~");
        assert_eq!(escape("x\u{27e6}#".as_bytes()), b"x%E2%9F%A6%23");
        assert_eq!(escape(b"%41&b=c"), b"%41&b=c");
    }

    #[test]
    fn gemini_query_key_and_header_pass_through() {
        let fx = fx();
        let enc = encode(V.as_bytes());
        let enc = std::str::from_utf8(&enc).unwrap();
        let q = format!("alt=sse&key={enc}&trace={enc}");
        let mut h = headers(&[("x-goog-api-key", V)]);
        let head = prepare_with(
            &fx.snapshot(),
            &http::Method::POST,
            "/v1beta/models/m:streamGenerateContent",
            Some(&q),
            &mut h,
            &["key"],
        )
        .unwrap();
        let fq = head.query.unwrap();
        assert!(fq.starts_with(&format!("alt=sse&key={enc}&trace=")), "{fq}");
        assert!(!fq[fq.find("trace=").unwrap()..].contains(enc));
        assert_eq!(h["x-goog-api-key"].as_bytes(), V.as_bytes());

        // Without the route's credential list the key is ordinary content.
        let mut h = HeaderMap::new();
        let head = run(&fx, "/v1beta/models/m:generateContent", Some(&q), &mut h).unwrap();
        assert!(!head.query.unwrap().contains(enc));

        // Only the exact key: `KEY` or `key2` are redacted.
        let q = format!("KEY={enc}&key2={enc}");
        let head = prepare_with(
            &fx.snapshot(),
            &http::Method::POST,
            "/x",
            Some(&q),
            &mut HeaderMap::new(),
            &["key"],
        )
        .unwrap();
        assert!(!head.query.unwrap().contains(enc));
    }
}
