//! Request rewriting: find placeholders, check bindings and locations, substitute, fix framing.
//!
//! The order is fixed and fail-closed. Every location is scanned first; then every occurrence is
//! checked (binding, location, value available); only if all pass is anything substituted. A
//! request that fails any check is refused whole and nothing reaches the upstream.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::request::Parts;
use http::{Method, Request, Uri, Version};
use http_body::Body;

use crate::audit::AuditEvent;
use crate::body::{
    BoxError, Collected, Pipeline, Prefixed, ProxyBody, ScanStage, Stage, TransformBody,
    collect_limited, full,
};
use crate::capture::CaptureRule;
use crate::codec::{Codings, decode_all, encode_all, parse_codings};
use crate::credential::Location;
use crate::decide::{InjectionDecision, InjectionRequest};
use crate::digest;
use crate::engine::Engine;
use crate::error::{ErrorCode, Refusal};
use crate::host::{Destination, split_host_port};
use crate::inject::{Context, Hit, substitute};
use crate::multipart;
use crate::proxy::Shared;
use crate::redactor::{Redactor, ValueRedactor};
use crate::secret::SecretValue;
use http_body_util::BodyExt;

/// Headers that apply to one connection only, never forwarded, and scrim's own session header
/// (`x-scrim-session`, which carries a session token for the LLM proxy and must not reach a tool
/// API either).
const HOP_BY_HOP: [HeaderName; 9] = [
    HeaderName::from_static("x-scrim-session"),
    header::CONNECTION,
    HeaderName::from_static("proxy-connection"),
    HeaderName::from_static("keep-alive"),
    header::PROXY_AUTHORIZATION,
    header::PROXY_AUTHENTICATE,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
];

/// Removes hop-by-hop headers, including those named in `Connection`.
pub(crate) fn strip_hop_by_hop(h: &mut http::HeaderMap) {
    let named: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().to_ascii_lowercase().as_bytes()).ok())
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in HOP_BY_HOP {
        h.remove(n);
    }
}

/// What the response side needs to know about the request.
pub(crate) struct RequestMeta {
    pub dest: Destination,
    pub method: Method,
    /// Credential values and the exact placeholder the agent used, so echoes map back to it.
    pub echo: Option<Arc<dyn Redactor>>,
    pub capture: Vec<CaptureRule>,
    /// Set when a streamed request body was cut off because a placeholder showed up in it. The
    /// upstream's answer to a truncated request is then not returned.
    pub aborted: Arc<AtomicBool>,
}

pub(crate) struct Prepared {
    pub req: Request<ProxyBody>,
    pub meta: RequestMeta,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Json,
    Form,
    Xml,
    Multipart,
    Opaque,
}

fn body_kind(content_type: Option<&str>) -> BodyKind {
    let Some(ct) = content_type else {
        return BodyKind::Opaque;
    };
    let mt = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if mt == "application/json"
        || mt.ends_with("+json")
        || mt == "application/x-ndjson"
        || mt == "application/jsonl"
    {
        BodyKind::Json
    } else if mt == "application/x-www-form-urlencoded" {
        BodyKind::Form
    } else if mt.starts_with("multipart/") {
        BodyKind::Multipart
    } else if mt.ends_with("/xml") || mt.ends_with("+xml") {
        BodyKind::Xml
    } else {
        BodyKind::Opaque
    }
}

fn kind_context(k: BodyKind) -> Context {
    match k {
        BodyKind::Json => Context::Json,
        BodyKind::Form => Context::Query,
        BodyKind::Xml => Context::Xml,
        BodyKind::Multipart | BodyKind::Opaque => Context::Opaque,
    }
}

/// Removes `.` and `..` segments (RFC 3986 5.2.4) after decoding `%2e`, so a path binding cannot
/// be escaped with `/v1/../admin`.
pub(crate) fn normalise_path(path: &str) -> String {
    let decoded = path.replace("%2e", ".").replace("%2E", ".");
    let mut out: Vec<&str> = Vec::new();
    let trailing = decoded.ends_with('/') || decoded.ends_with("/.") || decoded.ends_with("/..");
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut s = String::from("/");
    s.push_str(&out.join("/"));
    if trailing && s.len() > 1 {
        s.push('/');
    }
    s
}

struct HeaderHits {
    index: usize,
    basic: bool,
    hits: Vec<Hit>,
}

/// Collected placeholder occurrences of one request.
#[derive(Default)]
struct Uses {
    items: Vec<(usize, Location)>,
}

impl Uses {
    fn add(&mut self, hits: &[Hit], loc: &Location) {
        for h in hits {
            self.items.push((h.credential, loc.clone()));
        }
    }
}

fn header_value(b: &[u8]) -> Result<HeaderValue, Refusal> {
    HeaderValue::from_bytes(b).map_err(|_| {
        Refusal::new(
            ErrorCode::UnrepresentableValue,
            "a substituted header value is not valid in HTTP",
        )
    })
}

/// The authority the request claims (Host header or URI authority) must be the destination.
fn check_authority(parts: &Parts, dest: &Destination) -> Result<(), Refusal> {
    let claimed = parts
        .headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .or_else(|| parts.uri.authority().map(|a| a.as_str().to_owned()));
    let Some(claimed) = claimed else {
        return Ok(());
    };
    let ok = split_host_port(&claimed).is_some_and(|(h, p)| {
        let host = Destination::new(dest.scheme, h, 0).host;
        host == dest.host && p.unwrap_or(dest.scheme.default_port()) == dest.port
    });
    if ok {
        Ok(())
    } else {
        Err(Refusal::new(
            ErrorCode::MisdirectedRequest,
            format!("the request names host `{claimed}` but the connection goes to {dest}"),
        ))
    }
}

/// Which signature scheme covers the request, if any.
fn signature_scheme(parts: &Parts) -> Option<&'static str> {
    let auth = parts
        .headers
        .get(header::AUTHORIZATION)
        .map_or_default(http::HeaderValue::as_bytes);
    if auth.starts_with(b"AWS4-HMAC-SHA256")
        || parts
            .uri
            .query()
            .is_some_and(|q| q.contains("X-Amz-Signature="))
    {
        return Some("AWS SigV4");
    }
    if parts.headers.contains_key("signature-input") {
        return Some("HTTP message signatures");
    }
    if auth.len() > 6
        && auth[..6].eq_ignore_ascii_case(b"oauth ")
        && auth.windows(15).any(|w| w == b"oauth_signature")
    {
        return Some("OAuth 1.0");
    }
    None
}

fn filter_accept_encoding(h: &mut http::HeaderMap) {
    let Some(v) = h
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    else {
        return;
    };
    let mut keep = Vec::new();
    for tok in v.split(',') {
        let t = tok.trim();
        let name = t
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match name.as_str() {
            "gzip" | "x-gzip" | "deflate" | "br" | "zstd" | "identity" => keep.push(t.to_owned()),
            "*" => keep.extend(["gzip", "deflate", "br", "zstd"].map(str::to_owned)),
            _ => {}
        }
    }
    if keep.is_empty() {
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
    } else if let Ok(v) = HeaderValue::from_str(&keep.join(", ")) {
        h.insert(header::ACCEPT_ENCODING, v);
    }
}

enum Out {
    Bytes(Bytes),
    Stream(ProxyBody),
}

enum BodyPlan {
    /// Forward these bytes unchanged.
    Unchanged(Bytes),
    /// Decoded body with placeholder hits, to be substituted and re-encoded.
    Rewrite {
        decoded: Vec<u8>,
        hits: Vec<Hit>,
        ctx: Vec<Context>,
        codings: Codings,
        kind: BodyKind,
        boundary: Option<String>,
    },
    /// Too large to buffer: streamed, refused mid-stream if a placeholder shows up.
    Stream(ProxyBody),
}

impl Engine {
    #[allow(clippy::unused_self)]
    fn refuse(
        &self,
        shared: &Shared,
        dest: &Destination,
        method: &Method,
        path: &str,
        creds: &BTreeSet<String>,
        r: Refusal,
    ) -> Refusal {
        shared.audit.record(AuditEvent::RequestRefused {
            code: r.code,
            credentials: creds.iter().cloned().collect(),
            destination: dest.to_string(),
            method: method.to_string(),
            path: path.to_owned(),
            message: r.message.clone(),
        });
        r
    }

    /// Rewrites a request toward `dest`. Refusals are audited here. One linear pipeline: scan
    /// every location, check every occurrence, then substitute; splitting it would scatter the
    /// fail-closed ordering.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn prepare_request<B>(
        &self,
        shared: &Shared,
        dest: &Destination,
        req: Request<B>,
    ) -> Result<Prepared, Refusal>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError>,
    {
        let (mut parts, body) = req.into_parts();
        let method = parts.method.clone();
        let raw_path = parts.uri.path().to_owned();
        let audit_path = normalise_path(&raw_path);
        let mut used = BTreeSet::new();
        let refuse = |used: &BTreeSet<String>, r: Refusal| {
            self.refuse(shared, dest, &method, &audit_path, used, r)
        };

        if parts.headers.contains_key(header::UPGRADE) || method == Method::CONNECT {
            return Err(refuse(
                &used,
                Refusal::new(
                    ErrorCode::UpgradeUnsupported,
                    "protocol upgrades cannot be inspected and are refused",
                ),
            ));
        }
        check_authority(&parts, dest).map_err(|r| refuse(&used, r))?;
        strip_hop_by_hop(&mut parts.headers);
        parts.headers.remove(header::EXPECT);

        let inj = &self.injector;
        let mut occurrences = Uses::default();
        let aborted = Arc::new(AtomicBool::new(false));
        let dest_bound = self.credentials.any_bound_to(dest);
        // Toward a bound host, a placeholder no credential resolves is refused rather than sent
        // as text (credential-injection spec, "Unresolved placeholders are refused").
        let unresolved = |bytes: &[u8], hits: &[Hit], loc: &dyn std::fmt::Display| {
            if !dest_bound {
                return Ok(());
            }
            match crate::unresolved::find(bytes, hits) {
                None => Ok(()),
                Some(u) => Err(refuse(
                    &BTreeSet::new(),
                    Refusal::new(
                        ErrorCode::CredentialUnavailable,
                        format!(
                            "the {loc} carries {} that no available credential resolves; nothing was sent to {dest}",
                            u.describe()
                        ),
                    ),
                )),
            }
        };

        // URL.
        let query = parts.uri.query().map(str::to_owned);
        let path_hits = inj.scan(raw_path.as_bytes());
        unresolved(raw_path.as_bytes(), &path_hits, &Location::Path)?;
        occurrences.add(&path_hits, &Location::Path);
        let query_hits = query.as_deref().map_or_default(|q| inj.scan(q.as_bytes()));
        if let Some(q) = &query {
            unresolved(q.as_bytes(), &query_hits, &Location::Query)?;
        }
        occurrences.add(&query_hits, &Location::Query);

        // Headers.
        let mut header_hits: Vec<HeaderHits> = Vec::new();
        for (index, (name, value)) in parts.headers.iter().enumerate() {
            let loc = if name == header::COOKIE {
                Location::Cookie
            } else {
                Location::Header(name.clone())
            };
            let bytes = value.as_bytes();
            let hits = inj.scan(bytes);
            unresolved(bytes, &hits, &loc)?;
            if !hits.is_empty() {
                occurrences.add(&hits, &loc);
                header_hits.push(HeaderHits {
                    index,
                    basic: false,
                    hits,
                });
                continue;
            }
            if name == header::AUTHORIZATION
                && bytes.len() > 6
                && bytes[..6].eq_ignore_ascii_case(b"basic ")
                && let Ok(decoded) = STANDARD.decode(bytes[6..].trim_ascii())
            {
                let hits = inj.scan(&decoded);
                unresolved(&decoded, &hits, &loc)?;
                if !hits.is_empty() {
                    occurrences.add(&hits, &loc);
                    header_hits.push(HeaderHits {
                        index,
                        basic: true,
                        hits,
                    });
                }
            }
        }

        // Body.
        let ct = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let kind = body_kind(ct.as_deref());
        let codings = parse_codings(&parts.headers);
        let plan = match collect_limited(body, shared.settings.max_buffered_body).await {
            Err(e) => {
                return Err(refuse(
                    &used,
                    Refusal::new(
                        ErrorCode::BadRequest,
                        format!("reading the request body failed: {e}"),
                    ),
                ));
            }
            Ok(Collected::Overflow(prefix, rest)) => {
                let identity = matches!(&codings, Ok(c) if c.0.is_empty());
                if !identity && dest_bound {
                    return Err(refuse(
                        &used,
                        Refusal::new(
                            ErrorCode::BodyTooLarge,
                            format!(
                                "encoded request body to {dest} exceeds {} bytes and cannot be inspected",
                                shared.settings.max_buffered_body
                            ),
                        ),
                    ));
                }
                let stages = if identity {
                    vec![Stage::Scan(ScanStage::new(inj.clone(), dest_bound))]
                } else {
                    Vec::new()
                };
                let audit = shared.audit.clone();
                let (d, m, p) = (dest.to_string(), method.to_string(), audit_path.clone());
                let flag = aborted.clone();
                let on_end = Box::new(move |r: Result<u64, String>| {
                    if let Err(message) = r {
                        flag.store(true, Ordering::SeqCst);
                        audit.record(AuditEvent::RequestRefused {
                            code: ErrorCode::BodyTooLarge,
                            credentials: Vec::new(),
                            destination: d,
                            method: m,
                            path: p,
                            message,
                        });
                    }
                });
                let body = TransformBody::new(
                    Prefixed::new(prefix, rest),
                    Pipeline::new(stages),
                    None,
                    on_end,
                );
                BodyPlan::Stream(body.boxed_unsync())
            }
            Ok(Collected::Complete(bytes, _trailers)) if bytes.is_empty() => {
                BodyPlan::Unchanged(bytes)
            }
            Ok(Collected::Complete(bytes, _trailers)) => match &codings {
                Err(token) => {
                    if dest_bound {
                        return Err(refuse(
                            &used,
                            Refusal::new(
                                ErrorCode::UnsupportedEncoding,
                                format!(
                                    "request body uses content coding `{token}`, which scrim cannot rewrite"
                                ),
                            ),
                        ));
                    }
                    let hits = inj.scan(&bytes);
                    occurrences.add(&hits, &Location::Body);
                    BodyPlan::Unchanged(bytes)
                }
                Ok(cs) => {
                    let decoded = if cs.0.is_empty() {
                        Ok(bytes.to_vec())
                    } else {
                        decode_all(&bytes, cs, shared.settings.max_decoded_body)
                    };
                    match decoded {
                        Err(e) => {
                            if dest_bound {
                                let code = if e.to_string().contains("limit") {
                                    ErrorCode::BodyTooLarge
                                } else {
                                    ErrorCode::MalformedBody
                                };
                                return Err(refuse(
                                    &used,
                                    Refusal::new(
                                        code,
                                        format!("request body could not be decoded: {e}"),
                                    ),
                                ));
                            }
                            BodyPlan::Unchanged(bytes)
                        }
                        Ok(decoded) => {
                            let hits = inj.scan(&decoded);
                            unresolved(&decoded, &hits, &Location::Body)?;
                            if hits.is_empty() {
                                BodyPlan::Unchanged(bytes)
                            } else {
                                occurrences.add(&hits, &Location::Body);
                                let (ctx, boundary) = if kind == BodyKind::Multipart {
                                    let boundary = ct.as_deref().and_then(multipart::boundary);
                                    let parts_ = boundary
                                        .as_deref()
                                        .and_then(|b| multipart::parse(&decoded, b));
                                    let Some(mp) = parts_ else {
                                        return Err(refuse(
                                            &used,
                                            Refusal::new(
                                                ErrorCode::MalformedBody,
                                                "multipart body could not be parsed",
                                            ),
                                        ));
                                    };
                                    let ctx = hits
                                        .iter()
                                        .map(|h| {
                                            mp.iter()
                                                .find_map(|p| {
                                                    if p.body.contains(&h.start)
                                                        && h.end <= p.body.end
                                                    {
                                                        Some(kind_context(body_kind(
                                                            p.content_type.as_deref(),
                                                        )))
                                                    } else if p.headers.contains(&h.start) {
                                                        Some(Context::Header)
                                                    } else {
                                                        None
                                                    }
                                                })
                                                .unwrap_or(Context::Header)
                                        })
                                        .collect();
                                    (ctx, boundary)
                                } else {
                                    (vec![kind_context(kind); hits.len()], None)
                                };
                                BodyPlan::Rewrite {
                                    decoded,
                                    hits,
                                    ctx,
                                    codings: cs.clone(),
                                    kind,
                                    boundary,
                                }
                            }
                        }
                    }
                }
            },
        };

        // Checks, for every occurrence, before anything is substituted.
        for (ci, _) in &occurrences.items {
            used.insert(self.credential_name(*ci).to_owned());
        }
        let path_for_binding = normalise_path(&raw_path);
        for (ci, loc) in &occurrences.items {
            let c = &self.credentials.credentials()[*ci];
            let Some(binding) = &c.binding else {
                return Err(refuse(
                    &used,
                    Refusal::new(
                        ErrorCode::UnboundCredential,
                        format!(
                            "credential `{}` has no destination binding and is never injected",
                            c.name
                        ),
                    ),
                ));
            };
            if !binding.covers(dest, &method, &path_for_binding) {
                return Err(refuse(
                    &used,
                    Refusal::new(
                        ErrorCode::UnboundDestination,
                        format!(
                            "credential `{}` is not bound to {dest} ({method} {path_for_binding})",
                            c.name
                        ),
                    ),
                ));
            }
            if !c.locations.allows(loc) {
                return Err(refuse(
                    &used,
                    Refusal::new(
                        ErrorCode::UndeclaredLocation,
                        format!("credential `{}` may not be injected into the {loc}", c.name),
                    ),
                ));
            }
            if c.value.is_none() {
                return Err(refuse(
                    &used,
                    Refusal::new(
                        ErrorCode::CredentialUnavailable,
                        format!("the value of credential `{}` is not available", c.name),
                    ),
                ));
            }
        }

        // The per-request decision, once per credential, before anything is substituted.
        if let Some(policy) = &self.injection {
            let mut asked = BTreeSet::new();
            for (ci, _) in &occurrences.items {
                if !asked.insert(*ci) {
                    continue;
                }
                let c = &self.credentials.credentials()[*ci];
                let req = InjectionRequest {
                    credential: c.name.clone(),
                    reference: c.reference.clone(),
                    destination: dest.clone(),
                    method: method.to_string(),
                    path: path_for_binding.clone(),
                };
                if let InjectionDecision::Deny(why) = policy.decide(&req, &parts.extensions).await {
                    return Err(refuse(
                        &used,
                        Refusal::new(
                            ErrorCode::PolicyDenied,
                            format!(
                                "injecting credential `{}` toward {dest} was denied: {why}",
                                c.name
                            ),
                        ),
                    ));
                }
            }
        }

        let creds = self.credentials.credentials();
        let value_of = |i: usize| creds[i].value.as_ref().map(SecretValue::expose);
        let unrep =
            |e: crate::inject::Unrepresentable| Refusal::new(ErrorCode::UnrepresentableValue, e.0);

        // Substitute: URL.
        if !path_hits.is_empty() || !query_hits.is_empty() {
            let new_path = substitute(
                raw_path.as_bytes(),
                &path_hits,
                &|_| Context::Path,
                &value_of,
            )
            .map_err(|e| refuse(&used, unrep(e)))?;
            let mut pq = String::from_utf8(new_path).map_err(|_| {
                refuse(
                    &used,
                    Refusal::new(
                        ErrorCode::UnrepresentableValue,
                        "substituted URL is invalid",
                    ),
                )
            })?;
            if let Some(q) = &query {
                let new_q = substitute(q.as_bytes(), &query_hits, &|_| Context::Query, &value_of)
                    .map_err(|e| refuse(&used, unrep(e)))?;
                pq.push('?');
                pq.push_str(&String::from_utf8(new_q).map_err(|_| {
                    refuse(
                        &used,
                        Refusal::new(
                            ErrorCode::UnrepresentableValue,
                            "substituted URL is invalid",
                        ),
                    )
                })?);
            }
            let mut up = parts.uri.clone().into_parts();
            up.path_and_query = Some(pq.parse().map_err(|_| {
                refuse(
                    &used,
                    Refusal::new(
                        ErrorCode::UnrepresentableValue,
                        "substituted URL is invalid",
                    ),
                )
            })?);
            parts.uri = Uri::from_parts(up).map_err(|_| {
                refuse(
                    &used,
                    Refusal::new(
                        ErrorCode::UnrepresentableValue,
                        "substituted URL is invalid",
                    ),
                )
            })?;
        }

        // Substitute: headers.
        if !header_hits.is_empty() {
            let mut next = header_hits.iter().peekable();
            for (idx, (name, value)) in parts.headers.iter_mut().enumerate() {
                if let Some(hh) = next.peek()
                    && hh.index == idx
                {
                    let ctx = if name == header::COOKIE {
                        Context::Cookie
                    } else {
                        Context::Header
                    };
                    let new = if hh.basic {
                        let decoded = STANDARD
                            .decode(value.as_bytes()[6..].trim_ascii())
                            .unwrap_or_default();
                        let sub = substitute(&decoded, &hh.hits, &|_| Context::Header, &value_of)
                            .map_err(|e| refuse(&used, unrep(e)))?;
                        let mut v = b"Basic ".to_vec();
                        v.extend_from_slice(STANDARD.encode(&sub).as_bytes());
                        v
                    } else {
                        substitute(value.as_bytes(), &hh.hits, &|_| ctx, &value_of)
                            .map_err(|e| refuse(&used, unrep(e)))?
                    };
                    let mut hv = header_value(&new).map_err(|r| refuse(&used, r))?;
                    hv.set_sensitive(true);
                    *value = hv;
                    next.next();
                }
            }
        }

        // Substitute: body.
        let out = match plan {
            BodyPlan::Unchanged(b) => {
                if !b.is_empty() || parts.headers.contains_key(header::CONTENT_LENGTH) {
                    parts
                        .headers
                        .insert(header::CONTENT_LENGTH, HeaderValue::from(b.len()));
                }
                Out::Bytes(b)
            }
            BodyPlan::Stream(b) => Out::Stream(b),
            BodyPlan::Rewrite {
                decoded,
                hits,
                ctx,
                codings,
                kind,
                boundary,
            } => {
                let ctx_of = |h: &Hit| ctx[hits.iter().position(|x| x == h).unwrap_or(0)];
                let sub = substitute(&decoded, &hits, &ctx_of, &value_of)
                    .map_err(|e| refuse(&used, unrep(e)))?;
                if kind == BodyKind::Multipart
                    && let Some(b) = &boundary
                {
                    let delim = format!("--{b}");
                    let count = |s: &[u8]| {
                        s.windows(delim.len())
                            .filter(|w| *w == delim.as_bytes())
                            .count()
                    };
                    if count(&sub) != count(&decoded) {
                        return Err(refuse(
                            &used,
                            Refusal::new(
                                ErrorCode::UnrepresentableValue,
                                "a substituted value contains the multipart boundary",
                            ),
                        ));
                    }
                }
                let encoded = encode_all(&sub, &codings).map_err(|e| {
                    refuse(
                        &used,
                        Refusal::new(
                            ErrorCode::MalformedBody,
                            format!("re-encoding the body failed: {e}"),
                        ),
                    )
                })?;
                if let Err(alg) = digest::recompute(&mut parts.headers, &encoded, false) {
                    return Err(refuse(
                        &used,
                        Refusal::new(
                            ErrorCode::ResigningUnsupported,
                            format!("the request carries a `{alg}` digest scrim cannot recompute"),
                        ),
                    ));
                }
                parts
                    .headers
                    .insert(header::CONTENT_LENGTH, HeaderValue::from(encoded.len()));
                Out::Bytes(Bytes::from(encoded))
            }
        };

        if !occurrences.items.is_empty()
            && let Some(scheme) = signature_scheme(&parts)
        {
            let body_bytes: &[u8] = match &out {
                Out::Bytes(b) => b,
                Out::Stream(_) => &[],
            };
            match shared.signers.iter().find(|s| s.applies(&parts)) {
                Some(s) => s
                    .resign(&mut parts, body_bytes, dest, &self.credentials)
                    .map_err(|r| refuse(&used, r))?,
                None => {
                    return Err(refuse(
                        &used,
                        Refusal::new(
                            ErrorCode::ResigningUnsupported,
                            format!(
                                "the request is signed with {scheme}; re-signing after substitution is not available"
                            ),
                        ),
                    ));
                }
            }
        }
        let body = match out {
            Out::Bytes(b) => full(b),
            Out::Stream(b) => b,
        };

        filter_accept_encoding(&mut parts.headers);
        let authority = dest.authority();
        let pq = parts
            .uri
            .path_and_query()
            .map_or_else(|| "/".into(), |p| p.as_str().to_owned());
        parts.uri = format!("{}://{authority}{pq}", dest.scheme.as_str())
            .parse()
            .map_err(|_| {
                refuse(
                    &used,
                    Refusal::new(ErrorCode::BadRequest, "request URI is invalid"),
                )
            })?;
        parts.version = Version::HTTP_11;

        // Echo map: each injected value maps back to the placeholder text the agent sent.
        let echo = if occurrences.items.is_empty() {
            None
        } else {
            let mut seen = BTreeSet::new();
            let mut entries: Vec<(SecretValue, Vec<u8>)> = Vec::new();
            let all_hits = path_hits
                .iter()
                .chain(&query_hits)
                .chain(header_hits.iter().flat_map(|h| &h.hits));
            for h in all_hits {
                if seen.insert(h.credential) {
                    let c = &creds[h.credential];
                    if let Some(v) = &c.value {
                        entries.push((
                            v.clone(),
                            c.placeholders[h.placeholder].text.as_bytes().to_vec(),
                        ));
                    }
                }
            }
            for (ci, _) in &occurrences.items {
                if seen.insert(*ci) {
                    let c = &creds[*ci];
                    if let Some(v) = &c.value {
                        entries.push((v.clone(), c.placeholders[0].text.as_bytes().to_vec()));
                    }
                }
            }
            Some(Arc::new(
                ValueRedactor::new(entries.iter().map(|(v, p)| (v, p.as_slice())))
                    .map_err(|e| refuse(&used, Refusal::new(ErrorCode::RedactionFailed, e.0)))?,
            ) as Arc<dyn Redactor>)
        };

        if !used.is_empty() {
            shared.audit.record(AuditEvent::CredentialInjected {
                credentials: used.iter().cloned().collect(),
                destination: dest.to_string(),
                method: method.to_string(),
                path: audit_path.clone(),
            });
        }

        let capture = self
            .capture_rules
            .iter()
            .filter(|r| r.matches_request(dest, &method, &path_for_binding))
            .cloned()
            .collect();
        Ok(Prepared {
            req: Request::from_parts(parts, body),
            meta: RequestMeta {
                dest: dest.clone(),
                method,
                echo,
                capture,
                aborted,
            },
        })
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
    fn dot_segments_are_removed() {
        assert_eq!(normalise_path("/v1/../admin"), "/admin");
        assert_eq!(normalise_path("/v1/%2e%2e/admin"), "/admin");
        assert_eq!(normalise_path("/v1/./x/"), "/v1/x/");
        assert_eq!(normalise_path("/../../"), "/");
        assert_eq!(normalise_path(""), "/");
    }

    #[test]
    fn body_kinds() {
        assert!(matches!(
            body_kind(Some("application/json; charset=utf-8")),
            BodyKind::Json
        ));
        assert!(matches!(
            body_kind(Some("application/vnd.api+json")),
            BodyKind::Json
        ));
        assert!(matches!(
            body_kind(Some("application/x-www-form-urlencoded")),
            BodyKind::Form
        ));
        assert!(matches!(
            body_kind(Some("multipart/form-data; boundary=x")),
            BodyKind::Multipart
        ));
        assert!(matches!(body_kind(Some("text/xml")), BodyKind::Xml));
        assert!(matches!(body_kind(None), BodyKind::Opaque));
    }

    #[test]
    fn accept_encoding_is_limited_to_supported_codings() {
        let mut h = http::HeaderMap::new();
        h.insert(
            header::ACCEPT_ENCODING,
            "gzip, compress, br;q=0.5".parse().unwrap(),
        );
        filter_accept_encoding(&mut h);
        assert_eq!(h[header::ACCEPT_ENCODING], "gzip, br;q=0.5");
        h.insert(header::ACCEPT_ENCODING, "compress".parse().unwrap());
        filter_accept_encoding(&mut h);
        assert_eq!(h[header::ACCEPT_ENCODING], "identity");
    }

    #[test]
    fn hop_by_hop_headers_are_removed() {
        let mut h = http::HeaderMap::new();
        h.insert(header::CONNECTION, "close, x-custom".parse().unwrap());
        h.insert("x-custom", "1".parse().unwrap());
        h.insert(header::PROXY_AUTHORIZATION, "Basic x".parse().unwrap());
        h.insert("x-scrim-session", "scrim_st_x".parse().unwrap());
        h.insert("x-keep", "1".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-keep"));
    }
}
