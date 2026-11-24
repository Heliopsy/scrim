// SPDX-License-Identifier: AGPL-3.0-only

//! The request path: route, load snapshot, read body, redact and guard, capture, forward
//! (through a chained upstream if configured), restore the response.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full, Limited};

use crate::audit::{AuditEvent, AuditSink, RefusalReason};
use crate::auth::{AGENT_AUTH_HEADERS, RouteAuth};
use crate::body::{BoxError, ProxyBody, Restoring, full};
use crate::capture::{Capture, CaptureError, Record};
use crate::codec::{self, Api};
use crate::config::{OnUnavailable, Provider, ProxyConfig, bedrock_action};
use crate::engine::{Admission, RedactReport, RequestInfo, Snapshot, SnapshotCell};
use crate::error::Refusal;
use crate::eventstream::{self, EventStreamRestorer};
use crate::head;
use crate::metrics::{LlmMetrics, RouteMetrics, Stage, UpstreamError};
use crate::outgoing::{self, Outgoing};
use crate::restore::{Ctx, RestoreStats};
use crate::route::{Route, RouteError, RouteTable};
use crate::stream::{ChunkRestore, SseRestorer};
use crate::upstream::{TlsError, UpstreamClient, build_client, build_ws_client};

/// Proxy construction failed.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// Bad route.
    #[error(transparent)]
    Route(#[from] RouteError),
    /// Upstream TLS setup.
    #[error(transparent)]
    Tls(#[from] TlsError),
    /// Capture directory.
    #[error(transparent)]
    Capture(#[from] CaptureError),
}

/// The LLM proxy. Cheap to share behind an [`Arc`]; one instance serves every listener.
pub struct Proxy {
    pub(crate) cfg: ProxyConfig,
    routes: Arc<RouteTable>,
    pub(crate) snapshots: Arc<SnapshotCell>,
    pub(crate) client: UpstreamClient,
    /// HTTP/1.1-only client for WebSocket handshakes.
    pub(crate) ws_client: UpstreamClient,
    pub(crate) audit: Arc<dyn AuditSink>,
    pub(crate) capture: Option<Arc<Capture>>,
    pub(crate) metrics: Option<Arc<LlmMetrics>>,
    pub(crate) tokens: Arc<crate::token::TokenCache>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("routes", &self.routes)
            .field("snapshots", &self.snapshots)
            .finish_non_exhaustive()
    }
}

/// Where a request goes.
struct Target<'a> {
    route: &'a Route,
    rest: &'a str,
    query: Option<&'a str>,
    method: &'a http::Method,
    headers: &'a HeaderMap,
    metrics: Option<&'a RouteMetrics>,
    /// Authentication the route adds after redaction.
    auth: Option<&'a RouteAuth>,
}

/// Why one send failed.
enum SendError {
    /// Capture could not record the request; nothing was sent.
    Capture,
    /// No connection could be made; nothing was sent.
    Connect,
    /// The connection failed after (part of) the request may have been sent.
    Failed,
    /// The route could not authenticate the request; nothing was sent.
    Auth(Refusal),
}

impl SendError {
    fn into_forward(self, chain_skipped: bool) -> Forward {
        match self {
            SendError::Capture => Forward::Refused(Refusal::new(RefusalReason::CaptureFailed, "")),
            SendError::Auth(r) => Forward::Refused(r),
            SendError::Connect => {
                Forward::Refused(Refusal::new(RefusalReason::UpstreamUnavailable, ""))
            }
            SendError::Failed => Forward::AfterSend(
                Refusal::new(
                    RefusalReason::UpstreamUnavailable,
                    "upstream connection failed",
                ),
                chain_skipped,
            ),
        }
    }
}

/// Why forwarding failed.
enum Forward {
    /// Nothing left; refuse and audit the refusal.
    Refused(Refusal),
    /// The request may have left.
    AfterSend(Refusal, bool),
}

/// Request headers never forwarded: hop-by-hop headers (RFC 9110 section 7.6.1), `host` (set
/// from the upstream URI), `content-length` (recomputed after redaction), `accept-encoding`
/// (replaced by `identity` so responses can be restored) and scrim's own session header.
pub(crate) const STRIP_REQUEST: &[&str] = &[
    SESSION_HEADER,
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
];

/// The header an agent identifies its scrim session with on a base-URL listener
/// (`x-scrim-session: <session token>`, or a bare session id, which proves nothing). Read by the
/// request gate, never forwarded.
pub const SESSION_HEADER: &str = "x-scrim-session";

/// Response headers never forwarded.
pub(crate) const STRIP_RESPONSE: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

pub(crate) fn strip(headers: &mut HeaderMap, names: &[&str]) {
    // Headers named in Connection are hop-by-hop too.
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in listed {
        headers.remove(n);
    }
    for n in names {
        headers.remove(*n);
    }
}

/// Runs the snapshot's request gate, if any. Returns the snapshot the request uses from here
/// on: the same one with the restore policy bound to this request's caller, and the caller's
/// narrower redactor and guard when the gate returned them.
pub(crate) async fn admit(
    snap: Arc<Snapshot>,
    route: &Route,
    parts: &http::request::Parts,
) -> Result<Arc<Snapshot>, Refusal> {
    let Some(gate) = snap.gate.clone() else {
        return Ok(snap);
    };
    let info = RequestInfo {
        route: &route.name,
        provider: route.provider.name(),
        headers: &parts.headers,
        extensions: &parts.extensions,
    };
    match gate.admit(info).await {
        Admission::Forward { policy, redaction } => {
            let mut s = (*snap).clone();
            s.policy = policy;
            if let Some(r) = redaction {
                s.redactor = r.redactor;
                s.guard = r.guard;
            }
            s.gate = None;
            Ok(Arc::new(s))
        }
        Admission::Deny { detail } => Err(Refusal::new(RefusalReason::PolicyDenied, detail)),
    }
}

/// Whether the request asks for a protocol upgrade: an `Upgrade` header, or `upgrade` among
/// the `Connection` options.
fn is_upgrade(h: &HeaderMap) -> bool {
    h.contains_key(header::UPGRADE)
        || h.get_all(header::CONNECTION).iter().any(|v| {
            v.to_str().is_ok_and(|s| {
                s.split(',')
                    .any(|o| o.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
}

/// `uri` with the values of the credential query parameters `creds` replaced by `masked`, for
/// capture files.
pub(crate) fn mask_query(uri: &http::Uri, creds: &[&str]) -> http::Uri {
    let Some(q) = uri.query() else {
        return uri.clone();
    };
    if creds.is_empty() {
        return uri.clone();
    }
    let masked: Vec<String> = q
        .split('&')
        .map(|p| match p.split_once('=') {
            Some((k, _)) if creds.contains(&k) => format!("{k}=masked"),
            _ => p.to_string(),
        })
        .collect();
    let pq = format!("{}?{}", uri.path(), masked.join("&"));
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = pq.parse().ok();
    http::Uri::from_parts(parts).unwrap_or_else(|_| {
        // Never record the credential: fall back to the path alone.
        let mut p = uri.clone().into_parts();
        p.path_and_query = uri.path().parse().ok();
        http::Uri::from_parts(p).unwrap_or_default()
    })
}

fn is_identity(h: &HeaderMap) -> bool {
    h.get_all(header::CONTENT_ENCODING).iter().all(|v| {
        v.to_str()
            .is_ok_and(|s| s.trim().eq_ignore_ascii_case("identity"))
    })
}

fn mime_is(h: &HeaderMap, want: &str) -> bool {
    h.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case(want))
}

impl Proxy {
    /// Builds a proxy. `snapshots` is shared with whatever applies control-plane snapshots.
    pub fn new(
        cfg: ProxyConfig,
        snapshots: Arc<SnapshotCell>,
        audit: Arc<dyn AuditSink>,
    ) -> Result<Self, BuildError> {
        let routes = RouteTable::new(&cfg.routes)?;
        let client = build_client(&cfg)?;
        let ws_client = build_ws_client(&cfg)?;
        let capture = cfg.capture.as_ref().map(Capture::open).transpose()?;
        if let Some(c) = &capture {
            tracing::warn!(dir = %c.dir().display(), "capture mode is on: outgoing requests and responses are written to disk");
        }
        Ok(Self {
            cfg,
            routes: Arc::new(routes),
            snapshots,
            client,
            ws_client,
            audit,
            capture,
            metrics: None,
            tokens: Arc::default(),
        })
    }

    /// Records the proxy's metrics into `m` (see [`crate::metrics`]). Without it nothing is
    /// measured.
    #[must_use]
    pub fn with_metrics(mut self, m: Arc<LlmMetrics>) -> Self {
        self.metrics = Some(m);
        self
    }

    /// The metrics this proxy records into, if any.
    pub fn metrics(&self) -> Option<&Arc<LlmMetrics>> {
        self.metrics.as_ref()
    }

    /// The snapshot cell.
    pub fn snapshots(&self) -> &Arc<SnapshotCell> {
        &self.snapshots
    }

    /// The capture sink, when capture mode is on.
    pub fn capture(&self) -> Option<&Arc<Capture>> {
        self.capture.as_ref()
    }

    pub(crate) fn refuse(
        &self,
        route: Option<&Route>,
        api: Api,
        r: &Refusal,
    ) -> Response<ProxyBody> {
        tracing::info!(
            route = route.map(|r| r.name.as_str()),
            reason = r.reason.code(),
            "request refused"
        );
        if let Some(m) = &self.metrics {
            let rm = route.map_or_else(|| m.route("", ""), |r| m.route(&r.name, r.provider.name()));
            rm.refused(r.reason);
            if r.reason == RefusalReason::ChainUnavailable {
                rm.upstream_error(UpstreamError::ChainUnavailable);
            }
        }
        self.audit.record(AuditEvent::Refused {
            route: route.map(|r| r.name.clone()),
            reason: r.reason,
            refs: r.refs.clone(),
        });
        r.to_response(api).map(full)
    }

    /// Handles one request.
    pub async fn handle<B>(&self, req: Request<B>) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let path = req.uri().path().to_string();
        let snap = self.snapshots.load();
        let routes = self.routes_of(snap.as_ref());
        let Some((route, rest)) = routes.find(&path) else {
            let r = Refusal::new(RefusalReason::NoRoute, "");
            return self.refuse(None, Api::Generic, &r);
        };
        self.serve(snap, route, rest, req).await
    }

    /// Whether a route claims provider host `host` (see [`RouteConfig::hosts`]).
    ///
    /// [`RouteConfig::hosts`]: crate::config::RouteConfig::hosts
    pub fn claims_host(&self, host: &str) -> bool {
        self.routes_of(self.snapshots.load().as_ref())
            .find_host(host)
            .is_some()
    }

    /// The routes of `snap` when it carries them, else the configured ones.
    fn routes_of(&self, snap: Option<&Arc<Snapshot>>) -> Arc<RouteTable> {
        snap.and_then(|s| s.routes.clone())
            .unwrap_or_else(|| self.routes.clone())
    }

    /// Handles a request that arrived for provider host `host` through the forward proxy or a
    /// transparent listener: the route is chosen by host and the whole origin-form path is
    /// forwarded to the route's upstream.
    pub async fn handle_for_host<B>(&self, host: &str, req: Request<B>) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let snap = self.snapshots.load();
        let routes = self.routes_of(snap.as_ref());
        let Some(route) = routes.find_host(host) else {
            let r = Refusal::new(RefusalReason::NoRoute, "");
            return self.refuse(None, Api::Generic, &r);
        };
        let path = req.uri().path().to_string();
        self.serve(snap, route, &path, req).await
    }

    /// Serves one request with the one snapshot it loaded (route, dictionary, guard and restore
    /// policy all from the same version).
    async fn serve<B>(
        &self,
        snap: Option<Arc<Snapshot>>,
        route: &Route,
        rest: &str,
        req: Request<B>,
    ) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let api = route.provider.api_for(req.method(), rest);
        if is_upgrade(req.headers()) {
            // A WebSocket handshake is served message by message (crate::websocket). Any other
            // upgrade, or a handshake on a listener that cannot upgrade, would carry bytes scrim
            // cannot redact: it is refused first, before the snapshot, the gate or the body.
            if crate::websocket::is_handshake(&req) {
                return self.websocket(snap, route, rest, req).await;
            }
            let r = Refusal::new(RefusalReason::UpgradeUnsupported, "");
            return self.refuse(Some(route), api, &r);
        }
        let Some(snap) = snap else {
            let r = Refusal::new(RefusalReason::NotReady, "");
            return self.refuse(Some(route), api, &r);
        };
        let (parts, body) = req.into_parts();
        let snap = match admit(snap, route, &parts).await {
            Ok(s) => s,
            Err(r) => return self.refuse(Some(route), api, &r),
        };
        // A route that signs with credentials scrim holds refuses before reading the body when
        // they are not loaded.
        if let Some(Err(r)) = route.auth.as_deref().map(RouteAuth::check) {
            return self.refuse(Some(route), api, &r);
        }
        let count_tokens = route.provider == Provider::Bedrock
            && parts.method == http::Method::POST
            && bedrock_action(rest) == Some("count-tokens");
        let rm = self
            .metrics
            .as_ref()
            .map(|m| m.route(&route.name, route.provider.name()));
        let (mut out, began) = match self
            .prepare(
                &snap,
                api,
                count_tokens,
                &parts.headers,
                body,
                rm.as_deref(),
            )
            .await
        {
            Ok(o) => o,
            Err(r) => return self.refuse(Some(route), api, &r),
        };
        let mut headers = parts.headers;
        strip(&mut headers, STRIP_REQUEST);
        if route.auth.is_some() {
            // The route authenticates itself; whatever the agent sent stays here.
            strip(&mut headers, AGENT_AUTH_HEADERS);
        }
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        // The request target and headers leave too: same redactor, same guard.
        let head = match head::prepare_with(
            &snap,
            &parts.method,
            rest,
            parts.uri.query(),
            &mut headers,
            route.provider.query_credentials(),
        ) {
            Ok(h) => h,
            Err(r) => return self.refuse(Some(route), api, &r),
        };
        out.report.merge(head.report);
        for r in head.guard_repaired {
            if !out.guard_repaired.contains(&r) {
                out.guard_repaired.push(r);
            }
        }
        if let (Some(rm), Some(began)) = (&rm, began) {
            rm.stage(Stage::Redaction, out.stages.redaction);
            rm.stage(Stage::Guard, out.stages.guard);
            rm.stage(Stage::Total, began.elapsed());
        }
        let target = Target {
            route,
            rest: &head.path,
            query: head.query.as_deref(),
            method: &parts.method,
            headers: &headers,
            metrics: rm.as_deref(),
            auth: route.auth.as_deref(),
        };
        match self.forward(&target, &out).await {
            Ok((upstream_resp, record, chain_skipped)) => {
                self.audit_forwarded(route, &snap, &out, chain_skipped, rm.as_deref());
                self.respond(route, api, snap, upstream_resp, record, rm)
                    .await
            }
            Err(Forward::Refused(r)) => self.refuse(Some(route), api, &r),
            Err(Forward::AfterSend(r, chain_skipped)) => {
                // The request may have left, so it is audited as forwarded.
                self.audit_forwarded(route, &snap, &out, chain_skipped, rm.as_deref());
                r.to_response(api).map(full)
            }
        }
    }

    /// Reads the body within the limit, then redacts and guards it. With metrics, also returns
    /// when the checks began (after the body was read), for the total added latency.
    async fn prepare<B>(
        &self,
        snap: &Arc<Snapshot>,
        api: Api,
        count_tokens: bool,
        headers: &HeaderMap,
        body: B,
        rm: Option<&RouteMetrics>,
    ) -> Result<(Outgoing, Option<Instant>), Refusal>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        if !is_identity(headers) {
            return Err(Refusal::new(RefusalReason::UnsupportedEncoding, ""));
        }
        let body = match Limited::new(body, self.cfg.limits.max_request_body)
            .collect()
            .await
        {
            Ok(b) => b.to_bytes(),
            Err(e)
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some() =>
            {
                return Err(Refusal::new(RefusalReason::BodyTooLarge, ""));
            }
            Err(_) => {
                return Err(Refusal::new(
                    RefusalReason::MalformedBody,
                    "body could not be read",
                ));
            }
        };
        if let Some(rm) = rm {
            rm.body_bytes(body.len());
        }
        let began = rm.map(|_| Instant::now());
        let timed = began.is_some();
        if body.is_empty() && api == Api::Generic {
            return Ok((
                Outgoing {
                    body: Bytes::new(),
                    report: RedactReport::default(),
                    guard_repaired: vec![],
                    unscanned: vec![],
                    stages: outgoing::Stages::default(),
                },
                began,
            ));
        }
        let run = move |s: &Snapshot, body: &[u8]| {
            if count_tokens {
                outgoing::prepare_bedrock_count_tokens(s, body, timed)
            } else {
                outgoing::prepare_timed(s, api, body, timed)
            }
        };
        if body.len() < self.cfg.limits.offload_threshold {
            return run(snap, &body).map(|o| (o, began));
        }
        let s = snap.clone();
        tokio::task::spawn_blocking(move || run(&s, &body))
            .await
            .unwrap_or_else(|_| {
                Err(Refusal::new(
                    RefusalReason::RedactorFailed,
                    "redaction task failed",
                ))
            })
            .map(|o| (o, began))
    }

    /// Captures and sends the redacted request: to the chained upstream first when one is
    /// configured, then (with `on-unavailable: direct`) to the provider.
    async fn forward(
        &self,
        t: &Target<'_>,
        out: &Outgoing,
    ) -> Result<(Response<hyper::body::Incoming>, Option<Record>, bool), Forward> {
        let direct = Route::target(&t.route.upstream, t.rest, t.query);
        let Some((chain, base)) = &t.route.chain else {
            let (resp, rec) = self
                .send(t, direct, out)
                .await
                .map_err(|e| e.into_forward(false))?;
            return Ok((resp, rec, false));
        };
        match self
            .send(t, Route::target(base, t.rest, t.query), out)
            .await
        {
            Ok((resp, rec)) => Ok((resp, rec, false)),
            Err(SendError::Connect) if chain.on_unavailable == OnUnavailable::Direct => {
                tracing::warn!(route = %t.route.name, "chained upstream unavailable, sending directly to the provider");
                let (resp, rec) = self
                    .send(t, direct, out)
                    .await
                    .map_err(|e| e.into_forward(true))?;
                Ok((resp, rec, true))
            }
            Err(SendError::Connect) => Err(Forward::Refused(Refusal::new(
                RefusalReason::ChainUnavailable,
                "",
            ))),
            Err(e) => Err(e.into_forward(false)),
        }
    }

    async fn send(
        &self,
        t: &Target<'_>,
        uri: http::Uri,
        out: &Outgoing,
    ) -> Result<(Response<hyper::body::Incoming>, Option<Record>), SendError> {
        let mut record = None;
        if let Some(cap) = &self.capture {
            let shown = mask_query(&uri, t.route.provider.query_credentials());
            match cap
                .request(&t.route.name, t.method, &shown, t.headers, &out.body)
                .await
            {
                Ok(r) => record = Some(r),
                Err(e) => {
                    tracing::warn!(error = %e, "capture failed");
                    return Err(SendError::Capture);
                }
            }
        }
        let mut up = Request::new(Full::new(out.body.clone()));
        *up.method_mut() = t.method.clone();
        *up.uri_mut() = uri;
        *up.headers_mut() = t.headers.clone();
        if let Some(auth) = t.auth {
            let token = match auth.token_source() {
                Some((m, cred)) => Some(
                    self.tokens
                        .token(&self.client, &m, cred)
                        .await
                        .map_err(SendError::Auth)?,
                ),
                None => None,
            };
            let (parts, body) = up.into_parts();
            let mut parts = parts;
            auth.apply(
                &parts.method,
                &parts.uri,
                &mut parts.headers,
                &out.body,
                std::time::SystemTime::now(),
                token.as_ref(),
            )
            .map_err(SendError::Auth)?;
            up = Request::from_parts(parts, body);
        }
        let sent = t.metrics.map(|_| Instant::now());
        let res = self.client.request(up).await;
        if let (Some(m), Some(sent)) = (t.metrics, sent) {
            match &res {
                Ok(r) => m.upstream(sent.elapsed(), r.status()),
                Err(e) if e.is_connect() => m.upstream_error(UpstreamError::Connect),
                Err(_) => m.upstream_error(UpstreamError::Failed),
            }
        }
        match res {
            Ok(r) => Ok((r, record)),
            Err(e) if e.is_connect() => Err(SendError::Connect),
            Err(e) => {
                tracing::warn!(route = %t.route.name, error = %e, "upstream request failed");
                Err(SendError::Failed)
            }
        }
    }

    pub(crate) fn audit_forwarded(
        &self,
        route: &Route,
        snap: &Snapshot,
        out: &Outgoing,
        chain_skipped: bool,
        rm: Option<&RouteMetrics>,
    ) {
        if let Some(rm) = rm {
            rm.forwarded(
                out.report.replacements,
                out.report.detectors.len(),
                !out.guard_repaired.is_empty(),
            );
        }
        self.audit.record(AuditEvent::Forwarded {
            route: route.name.clone(),
            snapshot: snap.version,
            replacements: out.report.replacements,
            refs: out.report.refs.clone(),
            detectors: out.report.detectors.clone(),
            guard_repaired: out.guard_repaired.clone(),
            unscanned: out.unscanned.clone(),
            chain_skipped,
        });
    }

    /// Reads `body` into `buf` until it holds a byte that is not whitespace, the body ends or
    /// the response limit is passed. `false` when the body failed.
    async fn peek_array(&self, body: &mut hyper::body::Incoming, buf: &mut Vec<u8>) -> bool {
        while buf.iter().all(u8::is_ascii_whitespace)
            && buf.len() <= self.cfg.limits.max_response_body
        {
            match body.frame().await {
                Some(Ok(f)) => {
                    if let Ok(d) = f.into_data() {
                        buf.extend_from_slice(&d);
                    }
                }
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "upstream response body failed");
                    return false;
                }
                None => break,
            }
        }
        true
    }

    /// The chunk restorer for a streamed response: SSE, or Bedrock's event stream.
    fn stream_restorer(
        &self,
        route: &Route,
        api: Api,
        snap: &Arc<Snapshot>,
        headers: &HeaderMap,
    ) -> Option<Box<dyn ChunkRestore>> {
        if mime_is(headers, "text/event-stream") {
            return SseRestorer::new(api, snap.clone(), &self.cfg.limits)
                .map(|r| Box::new(r) as Box<dyn ChunkRestore>);
        }
        if route.provider == Provider::Bedrock && mime_is(headers, eventstream::CONTENT_TYPE) {
            return EventStreamRestorer::new(api, snap.clone(), &self.cfg.limits)
                .map(|r| Box::new(r) as Box<dyn ChunkRestore>);
        }
        None
    }

    async fn respond(
        &self,
        route: &Route,
        api: Api,
        snap: Arc<Snapshot>,
        resp: Response<hyper::body::Incoming>,
        record: Option<Record>,
        rm: Option<Arc<RouteMetrics>>,
    ) -> Response<ProxyBody> {
        let (mut parts, body) = resp.into_parts();
        let tee = match record {
            Some(r) => r.response(parts.status, &parts.headers).await,
            None => None,
        };
        strip(&mut parts.headers, STRIP_RESPONSE);
        let restorable = parts.status.is_success() && is_identity(&parts.headers);
        let json = restorable && mime_is(&parts.headers, "application/json");
        let audit = self.audit.clone();
        let name = route.name.clone();
        let end_metrics = rm.clone();
        let on_end: crate::body::OnEnd = Box::new(move |resolved, kept| {
            if let Some(m) = end_metrics {
                m.restored(resolved, kept);
            }
            if resolved + kept > 0 {
                audit.record(AuditEvent::Restored {
                    route: name,
                    resolved,
                    kept,
                });
            }
        });

        let streaming = restorable
            .then(|| self.stream_restorer(route, api, &snap, &parts.headers))
            .flatten();
        if let Some(r) = streaming {
            let b = Restoring::new(body, None, tee, Some(r), Some(on_end)).timed(rm);
            return Response::from_parts(parts, BodyExt::boxed_unsync(b));
        }
        if json && api != Api::Generic {
            // Buffer up to the limit; past it, pass through unresolved.
            let mut body = body;
            let mut buf = Vec::new();
            let mut overflow = false;
            if codec::streams_json_array(api) {
                // A JSON array here is a stream (Gemini `streamGenerateContent` without
                // `alt=sse`), restored element by element.
                if !self.peek_array(&mut body, &mut buf).await {
                    return bad_gateway();
                }
                if buf.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'[')
                    && let Some(r) = SseRestorer::json_array(api, snap.clone(), &self.cfg.limits)
                {
                    let b = Restoring::new(
                        body,
                        Some(Bytes::from(buf)),
                        tee,
                        Some(Box::new(r)),
                        Some(on_end),
                    )
                    .timed(rm);
                    return Response::from_parts(parts, BodyExt::boxed_unsync(b));
                }
                overflow = buf.len() > self.cfg.limits.max_response_body;
            }
            while !overflow && let Some(frame) = body.frame().await {
                match frame {
                    Ok(f) => {
                        if let Ok(d) = f.into_data() {
                            buf.extend_from_slice(&d);
                            if buf.len() > self.cfg.limits.max_response_body {
                                overflow = true;
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "upstream response body failed");
                        return bad_gateway();
                    }
                }
            }
            if overflow {
                let b = Restoring::new(body, Some(Bytes::from(buf)), tee, None, None);
                return Response::from_parts(parts, BodyExt::boxed_unsync(b));
            }
            let raw = Bytes::from(buf);
            if let Some(t) = tee {
                t.write(&raw);
                drop(t.close());
            }
            let stats = RestoreStats::default();
            let restored = {
                let ctx = Ctx {
                    snap: &snap,
                    stats: &stats,
                };
                codec::restore_json(api, &ctx, &raw)
            };
            on_end(stats.resolved.get(), stats.kept.get());
            let out = restored.map(Bytes::from).unwrap_or(raw);
            return Response::from_parts(parts, full(out));
        }
        let b = Restoring::new(body, None, tee, None, None);
        Response::from_parts(parts, BodyExt::boxed_unsync(b))
    }
}

/// The answer when the provider's response body fails part way.
fn bad_gateway() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(crate::error::ERROR_HEADER, "upstream_unavailable")
        .body(full(Bytes::new()))
        .unwrap_or_else(|_| Response::new(full(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_credentials_masked_for_capture() {
        let u: http::Uri =
            "https://g.example/v1beta/models/m:generateContent?alt=sse&key=AIzaSyFake-0123&x=1"
                .parse()
                .unwrap();
        assert_eq!(
            mask_query(&u, &["key"]).to_string(),
            "https://g.example/v1beta/models/m:generateContent?alt=sse&key=masked&x=1"
        );
        assert_eq!(mask_query(&u, &[]), u);
        let plain: http::Uri = "https://g.example/a".parse().unwrap();
        assert_eq!(mask_query(&plain, &["key"]), plain);
    }

    #[test]
    fn strips_hop_by_hop_and_connection_listed() {
        let mut h = HeaderMap::new();
        h.insert("connection", "keep-alive, x-custom-hop".parse().unwrap());
        h.insert("x-custom-hop", "1".parse().unwrap());
        h.insert("authorization", "Bearer t".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("host", "127.0.0.1".parse().unwrap());
        strip(&mut h, STRIP_REQUEST);
        assert_eq!(h.len(), 1);
        assert_eq!(h["authorization"], "Bearer t");
    }

    #[test]
    fn content_type_and_encoding() {
        let mut h = HeaderMap::new();
        h.insert(
            "content-type",
            "text/event-stream; charset=utf-8".parse().unwrap(),
        );
        assert!(mime_is(&h, "text/event-stream"));
        assert!(is_identity(&h));
        h.insert("content-encoding", "gzip".parse().unwrap());
        assert!(!is_identity(&h));
        h.insert("content-encoding", "identity".parse().unwrap());
        assert!(is_identity(&h));
    }
}
