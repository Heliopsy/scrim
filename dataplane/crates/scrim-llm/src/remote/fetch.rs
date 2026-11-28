// SPDX-License-Identifier: AGPL-3.0-only

//! Fetching attachments referenced by URL, and splicing them into the body inline.
//!
//! Every fetch goes through the upstream proxy in force (`network.upstream-proxy`), with the same
//! trust roots as the providers, and carries no header from the agent's request. Before
//! connecting, the host is resolved and every address checked ([`super::addr::permitted`]); the
//! connection then goes to exactly those addresses ([`scrim_dns::FixedResolver`]), so a second
//! lookup cannot answer differently. Redirects are followed by hand, at most
//! [`FetchLimits::max_redirects`], and each target is checked the same way. When the upstream
//! proxy applies to a host, the proxy resolves it: scrim still refuses a name its own resolver
//! maps to a refused address, and an address literal is always checked, but the proxy's egress
//! policy decides what else it reaches.
//!
//! Bounds reuse the binary scan bounds: the bytes fetched for one request together stay within
//! the largest part the scan decodes (64 MiB), and all fetches of a request share the time the
//! scan allows a part of that size (2 s plus 250 ms per MiB).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http::{Request, Uri, header};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use scrim_upstream_proxy::{ProxyConnector, ProxyHandle};

use super::addr::{Network, permitted};
use super::{Add, Edit, Reference, Target};
use crate::audit::RefusalReason;
use crate::binary;
use crate::codec::sanitize_media_type;
use crate::engine::Snapshot;
use crate::error::Refusal;
use crate::json;

/// Bounds on fetching the references of one request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FetchLimits {
    /// Most bytes all fetches of one request may return together.
    pub max_bytes: usize,
    /// Wall-clock budget for all fetches of one request.
    pub timeout: Duration,
    /// Most redirects followed per reference.
    pub max_redirects: usize,
}

impl Default for FetchLimits {
    fn default() -> Self {
        let scan = binary::Limits::default();
        let mib = u32::try_from(scan.max_decoded >> 20).unwrap_or(u32::MAX);
        Self {
            max_bytes: scan.max_decoded,
            timeout: scan.budget + scan.budget_per_mib.saturating_mul(mib),
            max_redirects: 5,
        }
    }
}

type FetchClient = Client<
    hyper_rustls::HttpsConnector<ProxyConnector<HttpConnector<scrim_dns::FixedResolver>>>,
    Empty<Bytes>,
>;

/// Fetches remote attachments. One per proxy.
pub(crate) struct Fetcher {
    tls: Arc<rustls::ClientConfig>,
    proxy: ProxyHandle,
    connect_timeout: Duration,
    pub(crate) limits: FetchLimits,
}

/// Why one fetch failed. Fixed text: never the URL or response content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchError {
    /// scrim will not fetch it (address, scheme, credentials, redirects).
    Refused(&'static str),
    /// The server could not be reached or answered badly.
    Unavailable(&'static str),
    /// The server answered with this status.
    Status(u16),
    /// Over [`FetchLimits::max_bytes`].
    TooLarge,
}

impl FetchError {
    fn refusal(self, i: usize) -> Refusal {
        let n = i + 1;
        match self {
            Self::Refused(why) => Refusal::new(
                RefusalReason::RemoteAttachment,
                format!("reference {n} (URL): {why}"),
            ),
            Self::Unavailable(why) => Refusal::new(
                RefusalReason::AttachmentUnavailable,
                format!("reference {n} (URL): {why}"),
            ),
            Self::Status(code) => Refusal::new(
                RefusalReason::AttachmentUnavailable,
                format!("reference {n} (URL): the server answered {code}"),
            ),
            Self::TooLarge => Refusal::new(
                RefusalReason::UnscannableContent,
                format!("reference {n} (URL): too large to scan"),
            ),
        }
    }
}

/// The body and declared type of one fetched attachment.
pub(crate) struct Fetched {
    bytes: Vec<u8>,
    content_type: Option<String>,
}

const PRIVATE: &str = "it resolves to an address that is not public (private, loopback, \
                       link-local or metadata); allow its network in \
                       redaction.remote-attachments-allowed-networks";

impl Fetcher {
    /// A fetcher with `tls` roots, through `proxy`.
    pub(crate) fn new(
        tls: Arc<rustls::ClientConfig>,
        proxy: ProxyHandle,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            tls,
            proxy,
            connect_timeout,
            limits: FetchLimits::default(),
        }
    }

    /// Fetches every reference in `refs` (URL references, with their position in the request)
    /// and returns `body` with each replaced by its content inline. Nothing is fetched when a
    /// URL contains a secret value: the fetch itself would send it.
    pub(crate) async fn inline(
        &self,
        snap: &Snapshot,
        body: &[u8],
        refs: &[(usize, Reference)],
    ) -> Result<Vec<u8>, Refusal> {
        let mut scratch = Vec::new();
        let mut urls = Vec::with_capacity(refs.len());
        for (i, r) in refs {
            let Target::Url(u) = &r.target else {
                return Err(Refusal::new(
                    RefusalReason::RemoteAttachment,
                    format!("reference {}: not a URL", i + 1),
                ));
            };
            if let Some((found, _)) = crate::outgoing::check_view(snap, u.as_bytes(), &mut scratch)?
            {
                return Err(Refusal {
                    reason: RefusalReason::RemoteAttachment,
                    detail: format!("reference {} (URL): the URL contains a secret value", i + 1),
                    refs: found,
                });
            }
            urls.push((*i, u.as_str()));
        }
        let budget = AtomicUsize::new(self.limits.max_bytes);
        let allowed = &snap.remote.allowed_networks;
        let all = futures_util::future::try_join_all(urls.iter().map(|&(i, u)| {
            let budget = &budget;
            async move { self.get(u, allowed, budget).await.map_err(|e| e.refusal(i)) }
        }));
        let fetched = tokio::time::timeout(self.limits.timeout, all)
            .await
            .map_err(|_| {
                Refusal::new(
                    RefusalReason::AttachmentUnavailable,
                    "fetching the attachments referenced by URL took too long",
                )
            })??;
        let mut edits = Vec::with_capacity(refs.len());
        for (((_, r), (_, url)), f) in refs.iter().zip(&urls).zip(fetched) {
            if let Some(e) = edit(body, r, url, &f) {
                edits.push(e);
            }
        }
        edits.sort_unstable_by_key(|e| e.0);
        Ok(json::splice(body, &edits))
    }

    /// Fetches one URL, following redirects.
    pub(crate) async fn get(
        &self,
        url: &str,
        allowed: &[Network],
        budget: &AtomicUsize,
    ) -> Result<Fetched, FetchError> {
        let mut url = url.to_owned();
        for _ in 0..=self.limits.max_redirects {
            let uri: Uri = url
                .parse()
                .map_err(|_| FetchError::Refused("not a valid URL"))?;
            let default_port = match uri.scheme_str() {
                Some("https") => 443,
                Some("http") => 80,
                _ => return Err(FetchError::Refused("only http and https URLs are fetched")),
            };
            let auth = uri
                .authority()
                .ok_or(FetchError::Refused("not a valid URL"))?;
            if auth.as_str().contains('@') {
                return Err(FetchError::Refused("URLs with credentials are not fetched"));
            }
            let host = auth.host().trim_start_matches('[').trim_end_matches(']');
            let port = auth.port_u16().unwrap_or(default_port);
            let addrs = self.vet(host, port, allowed).await?;
            let req = Request::get(uri.clone())
                .header(header::USER_AGENT, "scrim")
                .header(header::ACCEPT, "*/*")
                .header(header::ACCEPT_ENCODING, "identity")
                .body(Empty::new())
                .map_err(|_| FetchError::Refused("not a valid URL"))?;
            let resp = self
                .client(addrs)
                .request(req)
                .await
                .map_err(|_| FetchError::Unavailable("the server could not be reached"))?;
            let status = resp.status();
            if matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
                let loc = resp
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or(FetchError::Unavailable("a redirect without a location"))?;
                url = join(&uri, loc)?;
                continue;
            }
            if !status.is_success() {
                return Err(FetchError::Status(status.as_u16()));
            }
            let h = resp.headers();
            if h.get_all(header::CONTENT_ENCODING).iter().any(|v| {
                !v.to_str()
                    .is_ok_and(|s| s.trim().eq_ignore_ascii_case("identity"))
            }) {
                return Err(FetchError::Unavailable("a compressed response"));
            }
            let content_type = h
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            if let Some(len) = h
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()?.parse::<usize>().ok())
                && len > budget.load(Ordering::Relaxed)
            {
                return Err(FetchError::TooLarge);
            }
            let mut body = resp.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame =
                    frame.map_err(|_| FetchError::Unavailable("the response body failed"))?;
                if let Ok(d) = frame.into_data() {
                    budget
                        .try_update(Ordering::Relaxed, Ordering::Relaxed, |b| {
                            b.checked_sub(d.len())
                        })
                        .map_err(|_| FetchError::TooLarge)?;
                    bytes.extend_from_slice(&d);
                }
            }
            return Ok(Fetched {
                bytes,
                content_type,
            });
        }
        Err(FetchError::Refused("too many redirects"))
    }

    /// Resolves `host` and checks every address. Empty when the upstream proxy resolves it.
    async fn vet(
        &self,
        host: &str,
        port: u16,
        allowed: &[Network],
    ) -> Result<Vec<SocketAddr>, FetchError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !permitted(ip, allowed) {
                return Err(FetchError::Refused(PRIVATE));
            }
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        if host.is_empty() {
            return Err(FetchError::Refused("not a valid URL"));
        }
        let tunnelled = self.proxy.route(host, port).is_some();
        match scrim_dns::resolve(host).await {
            Ok(addrs) if !addrs.is_empty() => {
                if addrs.iter().any(|a| !permitted(a.ip(), allowed)) {
                    return Err(FetchError::Refused(PRIVATE));
                }
                Ok(addrs)
            }
            // Networks without outside DNS: the proxy resolves the name.
            _ if tunnelled => Ok(Vec::new()),
            _ => Err(FetchError::Unavailable("the host name does not resolve")),
        }
    }

    fn client(&self, addrs: Vec<SocketAddr>) -> FetchClient {
        let mut http = HttpConnector::new_with_resolver(scrim_dns::FixedResolver(addrs));
        http.enforce_http(false);
        http.set_connect_timeout(Some(self.connect_timeout));
        http.set_nodelay(true);
        let http = ProxyConnector::new(
            http,
            self.proxy.clone(),
            Arc::clone(&self.tls),
            self.connect_timeout,
        );
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config((*self.tls).clone())
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(0)
            .build(https)
    }
}

/// Resolves a `Location` header against the URL that answered with it.
fn join(base: &Uri, loc: &str) -> Result<String, FetchError> {
    let loc = loc.trim();
    let scheme_end = loc.find("://");
    if let Some(end) = scheme_end
        && loc.get(..end).is_some_and(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"+-.".contains(&c))
        })
    {
        return Ok(loc.to_owned());
    }
    let scheme = base.scheme_str().unwrap_or("https");
    let auth = base.authority().map_or("", http::uri::Authority::as_str);
    if let Some(rest) = loc.strip_prefix("//") {
        return Ok(format!("{scheme}://{rest}"));
    }
    if loc.starts_with('/') {
        return Ok(format!("{scheme}://{auth}{loc}"));
    }
    if loc.is_empty() {
        return Err(FetchError::Unavailable("a redirect without a location"));
    }
    let path = base.path();
    let dir = path
        .rfind('/')
        .map_or("/", |i| path.get(..=i).unwrap_or("/"));
    Ok(format!("{scheme}://{auth}{dir}{loc}"))
}

/// The media type of fetched content: from its magic bytes when the format is known (as the
/// binary scan decides it), else from the server's or the request's declared type.
fn media_type(bytes: &[u8], header: Option<&str>, declared: Option<&str>) -> String {
    if let Some(m) = magic(bytes) {
        return m.to_owned();
    }
    let clean = |m: Option<&str>| {
        m.map(|m| sanitize_media_type(m.split(';').next().unwrap_or_default().trim()))
            .filter(|m| m != "unknown")
    };
    let (header, declared) = (clean(header), clean(declared));
    if !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok() {
        let textual = |m: &String| {
            m.starts_with("text/")
                || matches!(
                    m.as_str(),
                    "application/json" | "application/xml" | "image/svg+xml"
                )
        };
        return header
            .filter(textual)
            .or(declared.filter(textual))
            .unwrap_or_else(|| "text/plain".to_owned());
    }
    header
        .or(declared)
        .unwrap_or_else(|| "application/octet-stream".to_owned())
}

fn magic(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WEBP") {
        Some("image/webp")
    } else if memchr::memmem::find(b.get(..1024).unwrap_or(b), b"%PDF-").is_some() {
        Some("application/pdf")
    } else {
        None
    }
}

/// A file name for an `OpenAI` `input_file` that has none: the last path segment of the URL,
/// restricted to safe characters.
fn file_name(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default();
    let name: String = last
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(64)
        .collect();
    if name.trim_matches('.').is_empty() {
        "attachment".to_owned()
    } else {
        name
    }
}

/// The edit that puts `fetched` in place of `reference`.
fn edit(
    body: &[u8],
    reference: &Reference,
    url: &str,
    fetched: &Fetched,
) -> Option<(usize, usize, Vec<u8>)> {
    let declared = match &reference.edit {
        Edit::Rebuild {
            add: Add::GeminiInline { declared, .. },
            ..
        } => declared.as_deref(),
        _ => None,
    };
    let mt = media_type(&fetched.bytes, fetched.content_type.as_deref(), declared);
    let data_url = || {
        let mut s = String::with_capacity(fetched.bytes.len() * 4 / 3 + mt.len() + 16);
        s.push_str("data:");
        s.push_str(&mt);
        s.push_str(";base64,");
        B64.encode_string(&fetched.bytes, &mut s);
        s
    };
    match &reference.edit {
        Edit::None => None,
        Edit::DataUrl { span } => Some((span.0, span.1, json::quote(&data_url()))),
        Edit::AnthropicSource { span } => {
            let mut out = Vec::with_capacity(fetched.bytes.len() * 4 / 3 + 96);
            match std::str::from_utf8(&fetched.bytes) {
                Ok(text) if mt == "text/plain" => {
                    out.extend_from_slice(br#"{"type":"text","media_type":"text/plain","data":"#);
                    out.extend_from_slice(&json::quote(text));
                }
                _ => {
                    out.extend_from_slice(br#"{"type":"base64","media_type":"#);
                    out.extend_from_slice(&json::quote(&mt));
                    out.extend_from_slice(br#","data":""#);
                    out.extend_from_slice(B64.encode(&fetched.bytes).as_bytes());
                    out.push(b'"');
                }
            }
            out.push(b'}');
            Some((span.0, span.1, out))
        }
        Edit::Rebuild { span, keep, add } => {
            let mut out = Vec::with_capacity(fetched.bytes.len() * 4 / 3 + 128);
            out.push(b'{');
            for (k, (s, e)) in keep {
                out.extend_from_slice(&json::quote(k));
                out.push(b':');
                out.extend_from_slice(body.get(*s..*e).unwrap_or(b"null"));
                out.push(b',');
            }
            match add {
                Add::ResponsesFile { has_filename } => {
                    out.extend_from_slice(br#""file_data":"#);
                    out.extend_from_slice(&json::quote(&data_url()));
                    if !has_filename {
                        out.extend_from_slice(br#","filename":"#);
                        out.extend_from_slice(&json::quote(&file_name(url)));
                    }
                }
                Add::GeminiInline { snake, .. } => {
                    let (key, mime) = if *snake {
                        ("inline_data", "mime_type")
                    } else {
                        ("inlineData", "mimeType")
                    };
                    out.extend_from_slice(format!(r#""{key}":{{"{mime}":"#).as_bytes());
                    out.extend_from_slice(&json::quote(&mt));
                    out.extend_from_slice(br#","data":""#);
                    out.extend_from_slice(B64.encode(&fetched.bytes).as_bytes());
                    out.extend_from_slice(b"\"}");
                }
            }
            out.push(b'}');
            Some((span.0, span.1, out))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_locations() {
        let base: Uri = "https://a.example/dir/x.png?q=1".parse().unwrap();
        assert_eq!(
            join(&base, "https://b.example/y").unwrap(),
            "https://b.example/y"
        );
        assert_eq!(join(&base, "//c.example/z").unwrap(), "https://c.example/z");
        assert_eq!(join(&base, "/root").unwrap(), "https://a.example/root");
        assert_eq!(
            join(&base, "rel.png").unwrap(),
            "https://a.example/dir/rel.png"
        );
        assert_eq!(
            join(&base, "/p?u=http://x").unwrap(),
            "https://a.example/p?u=http://x"
        );
    }

    #[test]
    fn media_type_prefers_magic_bytes() {
        assert_eq!(
            media_type(b"%PDF-1.7\n", Some("image/png"), None),
            "application/pdf"
        );
        assert_eq!(
            media_type(b"\x89PNG\r\n\x1a\n...", None, Some("text/plain")),
            "image/png"
        );
        assert_eq!(
            media_type(b"hello", Some("text/markdown; charset=utf-8"), None),
            "text/markdown"
        );
        assert_eq!(
            media_type(b"hello", Some("application/octet-stream"), None),
            "text/plain"
        );
        assert_eq!(
            media_type(b"\0\x01\x02", Some("audio/mpeg"), None),
            "audio/mpeg"
        );
        assert_eq!(
            media_type(b"\0\x01\x02", Some("x y"), None),
            "application/octet-stream"
        );
    }

    #[test]
    fn file_names_are_safe() {
        assert_eq!(file_name("https://a/b/report.pdf?sig=x"), "report.pdf");
        assert_eq!(file_name("https://a/"), "attachment");
        assert_eq!(file_name("https://a/%2e%2e"), "2e2e");
        assert_eq!(file_name("https://a/.."), "attachment");
    }

    #[cfg(feature = "test-util")]
    #[tokio::test]
    async fn oversized_and_redirect_loops_refuse() {
        use crate::testing::{FakeUpstream, Scripted};
        let big = vec![b'a'; 4096];
        let srv = FakeUpstream::start_with(move |r| {
            if r.uri.starts_with("/loop") {
                Scripted {
                    status: 302,
                    headers: vec![("location".into(), "/loop".into())],
                    chunks: vec![],
                    delay: Duration::ZERO,
                }
            } else {
                Scripted {
                    status: 200,
                    headers: vec![("content-type".into(), "text/plain".into())],
                    chunks: vec![Bytes::from(big.clone())],
                    delay: Duration::ZERO,
                }
            }
        })
        .await;
        let cfg = crate::config::ProxyConfig::default();
        let mut f = Fetcher::new(
            Arc::new(crate::upstream::tls_config(&cfg).unwrap()),
            ProxyHandle::new(),
            Duration::from_secs(5),
        );
        let allow = ["127.0.0.0/8".parse::<Network>().unwrap()];
        let ok = f
            .get(
                &format!("{}/big", srv.url()),
                &allow,
                &AtomicUsize::new(4096),
            )
            .await;
        assert_eq!(ok.map(|f| f.bytes.len()).ok(), Some(4096));
        let over = f
            .get(
                &format!("{}/big", srv.url()),
                &allow,
                &AtomicUsize::new(4095),
            )
            .await;
        assert_eq!(over.err(), Some(FetchError::TooLarge));
        f.limits.max_redirects = 3;
        let looped = f
            .get(
                &format!("{}/loop", srv.url()),
                &allow,
                &AtomicUsize::new(4096),
            )
            .await;
        assert_eq!(
            looped.err(),
            Some(FetchError::Refused("too many redirects"))
        );
        assert_eq!(
            srv.received().len(),
            2 + 4,
            "two fetches, then four redirect hops"
        );
        let ftp = f
            .get("ftp://example.com/x", &allow, &AtomicUsize::new(1))
            .await;
        assert!(matches!(ftp.err(), Some(FetchError::Refused(_))));
        let creds = f
            .get("http://user:pw@example.com/x", &allow, &AtomicUsize::new(1))
            .await;
        assert!(matches!(creds.err(), Some(FetchError::Refused(_))));
    }

    #[test]
    fn default_limits_follow_the_scan_bounds() {
        let l = FetchLimits::default();
        assert_eq!(l.max_bytes, 64 << 20);
        assert_eq!(l.timeout, Duration::from_secs(18));
    }
}
