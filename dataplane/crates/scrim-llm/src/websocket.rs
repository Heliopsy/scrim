// SPDX-License-Identifier: AGPL-3.0-only

//! WebSocket connections to provider routes (llm-proxy spec, "WebSocket connections").
//!
//! scrim terminates the WebSocket on both sides: it accepts the agent's handshake, opens its own
//! WebSocket to the provider, and relays message by message. Nothing is spliced at the byte
//! level, so every frame the provider receives was built by scrim from a message that passed
//! the same two checks as an HTTP body.
//!
//! ```text
//! agent ──handshake──▶ route ─▶ gate ─▶ route auth ─▶ head redaction + guard
//!                                                          │
//!                         provider handshake (HTTP/1.1, scrim's own key) ◀┘
//!                                │ 101 (anything else is passed back as the answer)
//!   agent ◀── 101 ───────────────┘
//!
//! client message (reassembled, ≤ max-request-body) ─▶ codec plan ─▶ redactor ─▶ guard ─▶ provider
//!                                                     (any failure: error event + close 1008)
//! provider message ─▶ stream codec (as one SSE event) ─▶ placeholders restored ─▶ agent
//! ```
//!
//! * **Handshake.** Before anything is sent upstream the handshake goes through what an HTTP
//!   request does before its body: values loaded, the request gate, the route's own
//!   credentials, and the redactor and guard over the request target and headers. The upstream
//!   handshake is HTTP/1.1 with scrim's own `Sec-WebSocket-Key`; the agent's credentials pass
//!   through, or the route authenticates the handshake itself as it signs HTTP requests.
//!   Extensions are never negotiated (`permessage-deflate` would hide content from the
//!   redactor), and the agent gets `101` only once the provider has answered `101`.
//! * **Client messages.** Fragmented messages are reassembled by the WebSocket layer, bounded by
//!   `proxy.limits.max-request-body`; past it the connection closes with 1009. A text message is
//!   one JSON event, planned per protocol ([`WsApi`]), redacted on its raw bytes and guarded over
//!   the exact bytes that leave. A binary message is redacted whole when it is UTF-8 and refused
//!   otherwise (`unscannable_content`). Pings are answered locally, never forwarded; a close
//!   frame is forwarded with its code and without its reason.
//! * **Refusal.** A message that cannot be made safe is never forwarded: the agent gets one
//!   error event ([`Refusal::ws_event`]) and a close frame ([`Refusal::close_code`], 1008 for
//!   every redaction and guard failure), and the provider connection is closed.
//! * **Snapshots.** Each client message uses the snapshot in force when it arrives. When it
//!   changed since the last message, the request gate is asked again for the new one, so new
//!   values are redacted on connections that are already open and a rule change applies to
//!   them.
//! * **Provider messages.** Each text message is handed to the API's stream codec as one SSE
//!   event, so the HTTP and WebSocket transports share one restore implementation: Realtime
//!   events ([`crate::codec::openai_realtime`]) and the Responses events of WebSocket mode.
//!   Unchanged messages leave byte for byte; binary messages pass through.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message, Utf8Bytes};

use crate::audit::{AuditEvent, AuditSink, RefusalReason};
use crate::auth::{AGENT_AUTH_HEADERS, RouteAuth};
use crate::body::{BoxError, ProxyBody, Restoring, full};
use crate::capture::Capture;
use crate::codec::{self, Api, Plan, PlanError, StreamCodec, StreamLimits};
use crate::config::{Limits, OnUnavailable, Provider};
use crate::engine::{Snapshot, SnapshotCell};
use crate::error::Refusal;
use crate::json::Doc;
use crate::metrics::{RouteMetrics, Stage, UpstreamError};
use crate::outgoing::{self, Outgoing};
use crate::proxy::{Proxy, STRIP_REQUEST, STRIP_RESPONSE, admit, mask_query, strip};
use crate::restore::{Ctx, RestoreStats};
use crate::route::Route;
use crate::sse;

/// Which protocol the messages of a connection speak, from the route's provider and the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsApi {
    /// `OpenAI` Realtime (`.../realtime`, also on Azure `OpenAI`).
    OpenAiRealtime,
    /// `OpenAI` Responses API WebSocket mode (`.../responses`).
    OpenAiResponses,
    /// Anything else on a provider route (for example the Gemini Live API): every client
    /// message is redacted whole and provider messages pass through without restore.
    Generic,
}

impl WsApi {
    /// The protocol of a WebSocket on `provider`'s route at `path` (after the prefix).
    pub fn for_path(provider: Provider, path: &str) -> Self {
        let p = path.trim_end_matches('/');
        match provider {
            Provider::Openai if p.ends_with("/realtime") => Self::OpenAiRealtime,
            Provider::Openai if p.ends_with("/responses") => Self::OpenAiResponses,
            _ => Self::Generic,
        }
    }

    /// Stable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::OpenAiRealtime => "openai-realtime",
            Self::OpenAiResponses => "openai-responses-ws",
            Self::Generic => "generic",
        }
    }

    fn plan(self, body: &[u8]) -> Result<Plan, PlanError> {
        let plan = match self {
            Self::Generic => return Ok(Plan::default()),
            Self::OpenAiRealtime => codec::openai_realtime::plan(&Doc::parse(body)?)?,
            Self::OpenAiResponses => codec::openai_responses::plan_ws(&Doc::parse(body)?)?,
        };
        Ok(plan.finish())
    }

    fn codec(self, limits: &Limits) -> Option<Box<dyn StreamCodec>> {
        let l = StreamLimits {
            max_buffered_tool_input: limits.max_buffered_tool_input,
        };
        match self {
            Self::OpenAiRealtime => Some(Box::new(codec::openai_realtime::Stream::new(l))),
            Self::OpenAiResponses => Some(Box::new(codec::openai_responses::Stream::new(l))),
            Self::Generic => None,
        }
    }
}

/// Redacts and guards one client message of protocol `api` (what the relay does with every
/// message), for benchmarks and tests. `text` is false for a binary message, which is redacted
/// whole.
pub fn prepare_message(
    snap: &Snapshot,
    api: WsApi,
    data: &[u8],
    text: bool,
) -> Result<Outgoing, Refusal> {
    prepare(snap, api, data, text, false)
}

fn prepare(
    snap: &Snapshot,
    api: WsApi,
    data: &[u8],
    text: bool,
    timed: bool,
) -> Result<Outgoing, Refusal> {
    if !text && std::str::from_utf8(data).is_err() {
        return Err(Refusal::new(
            RefusalReason::UnscannableContent,
            "binary WebSocket message",
        ));
    }
    let api = if text { api } else { WsApi::Generic };
    let out = outgoing::prepare_planned(snap, data, timed, |b| api.plan(b))?;
    if std::str::from_utf8(&out.body).is_err() {
        return Err(Refusal::new(
            RefusalReason::RedactorFailed,
            "message is not UTF-8 after redaction",
        ));
    }
    Ok(out)
}

/// Request headers of the agent's handshake that belong to its own WebSocket: scrim negotiates
/// the provider connection itself, with its own key and without extensions.
const STRIP_HANDSHAKE: &[&str] = &[
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-extensions",
    "sec-websocket-accept",
];

/// How long closing a connection may take before scrim drops it.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// After refusing a message, how long scrim waits for the agent's close frame, or the end of
/// its stream, before it drops the connection. Dropping a socket with unread data from the
/// agent (the rest of an oversized message) resets it, and on Windows a reset discards the
/// error event and close frame the agent has not read yet.
const LINGER: Duration = Duration::from_secs(1);

fn token_in(h: &HeaderMap, name: HeaderName, token: &str) -> bool {
    h.get_all(name).iter().any(|v| {
        v.to_str()
            .is_ok_and(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    })
}

/// Whether `req` is a WebSocket handshake this connection can upgrade: `GET` over HTTP/1.1 with
/// `Upgrade: websocket`, `Sec-WebSocket-Version: 13` and a key, on a listener that serves
/// upgrades.
pub(crate) fn is_handshake<B>(req: &Request<B>) -> bool {
    let h = req.headers();
    req.method() == http::Method::GET
        && req.version() == http::Version::HTTP_11
        && token_in(h, header::UPGRADE, "websocket")
        && h.get(header::SEC_WEBSOCKET_VERSION)
            .is_some_and(|v| v.as_bytes() == b"13")
        && h.contains_key(header::SEC_WEBSOCKET_KEY)
        && req.extensions().get::<OnUpgrade>().is_some()
}

fn ws_config(max: usize) -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(max))
        .max_frame_size(Some(max))
}

/// The error shape for answers before the upgrade.
fn error_api(p: Provider) -> Api {
    match p {
        Provider::Openai => Api::OpenAiResponses,
        Provider::Gemini | Provider::Vertex => Api::Gemini,
        Provider::Anthropic | Provider::Bedrock => Api::Generic,
    }
}

type Socket = WebSocketStream<TokioIo<Upgraded>>;

/// The provider's answer to scrim's handshake.
enum Dialed {
    /// `101`: the provider socket and the response head.
    Open(Box<Socket>, http::response::Parts),
    /// Anything else: passed back to the agent as the answer.
    Answered(Response<hyper::body::Incoming>),
}

/// Why dialling failed before an answer.
enum DialError {
    /// Nothing was sent.
    Refused(Refusal),
    /// No connection could be made.
    Connect,
    /// The connection or the handshake failed.
    Failed,
}

impl Proxy {
    /// Serves a WebSocket handshake on `route` (see the module documentation).
    pub(crate) async fn websocket<B>(
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
        let api = error_api(route.provider);
        let Some(base) = snap else {
            let r = Refusal::new(RefusalReason::NotReady, "");
            return self.refuse(Some(route), api, &r);
        };
        let (mut parts, _) = req.into_parts();
        let Some(on_upgrade) = parts.extensions.remove::<OnUpgrade>() else {
            let r = Refusal::new(RefusalReason::UpgradeUnsupported, "");
            return self.refuse(Some(route), api, &r);
        };
        let snap = match admit(base.clone(), route, &parts).await {
            Ok(s) => s,
            Err(r) => return self.refuse(Some(route), api, &r),
        };
        if let Some(Err(r)) = route.auth.as_deref().map(RouteAuth::check) {
            return self.refuse(Some(route), api, &r);
        }
        let Some(client_key) = parts.headers.get(header::SEC_WEBSOCKET_KEY).cloned() else {
            let r = Refusal::new(RefusalReason::UpgradeUnsupported, "");
            return self.refuse(Some(route), api, &r);
        };
        let mut headers = parts.headers.clone();
        strip(&mut headers, STRIP_REQUEST);
        strip(&mut headers, STRIP_HANDSHAKE);
        if route.auth.is_some() {
            strip(&mut headers, AGENT_AUTH_HEADERS);
        }
        let head = match crate::head::prepare_with(
            &snap,
            &http::Method::GET,
            rest,
            parts.uri.query(),
            &mut headers,
            route.provider.query_credentials(),
        ) {
            Ok(h) => h,
            Err(r) => return self.refuse(Some(route), api, &r),
        };
        let rm = self
            .metrics
            .as_ref()
            .map(|m| m.route(&route.name, route.provider.name()));
        let (dialed, uri, chain_skipped) = match self
            .dial_route(
                route,
                &head.path,
                head.query.as_deref(),
                &headers,
                rm.as_deref(),
            )
            .await
        {
            Ok(d) => d,
            Err(r) => return self.refuse(Some(route), api, &r),
        };
        // The handshake left: audited as a forwarded request, whatever the provider answers.
        let out = handshake_out(head);
        self.audit_forwarded(route, &snap, &out, chain_skipped, rm.as_deref());
        let (upstream, up_parts) = match dialed {
            Dialed::Open(s, p) => (s, p),
            Dialed::Answered(answer) => {
                let (mut p, body) = answer.into_parts();
                strip(&mut p.headers, STRIP_RESPONSE);
                let b = Restoring::new(body, None, None, None, None);
                return Response::from_parts(p, BodyExt::boxed_unsync(b));
            }
        };
        tracing::debug!(route = %route.name, "websocket open");
        let capture = self.capture.clone().map(|c| {
            let shown = mask_query(&uri, route.provider.query_credentials());
            (c, shown, headers)
        });
        let relay = Relay {
            route: route.clone(),
            api: WsApi::for_path(route.provider, rest),
            parts,
            snapshots: self.snapshots.clone(),
            base,
            snap,
            audit: self.audit.clone(),
            capture,
            rm,
            limits: self.cfg.limits,
            seen: Vec::new(),
            refused: false,
        };
        tokio::spawn(relay.start(on_upgrade, *upstream));
        switching_protocols(&up_parts.headers, &client_key)
    }

    /// Opens the provider WebSocket for `route`: through the chained upstream first when one is
    /// configured, as HTTP requests are sent.
    async fn dial_route(
        &self,
        route: &Route,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        rm: Option<&RouteMetrics>,
    ) -> Result<(Dialed, http::Uri, bool), Refusal> {
        let direct = Route::target(&route.upstream, path, query);
        let upstream_failed = || {
            Refusal::new(
                RefusalReason::UpstreamUnavailable,
                "websocket handshake failed",
            )
        };
        let Some((chain, base)) = &route.chain else {
            return match self.dial(route, direct.clone(), headers, rm).await {
                Ok(d) => Ok((d, direct, false)),
                Err(DialError::Refused(r)) => Err(r),
                Err(DialError::Connect) => {
                    Err(Refusal::new(RefusalReason::UpstreamUnavailable, ""))
                }
                Err(DialError::Failed) => Err(upstream_failed()),
            };
        };
        let via = Route::target(base, path, query);
        match self.dial(route, via.clone(), headers, rm).await {
            Ok(d) => Ok((d, via, false)),
            Err(DialError::Connect) if chain.on_unavailable == OnUnavailable::Direct => {
                tracing::warn!(route = %route.name, "chained upstream unavailable, opening the websocket directly to the provider");
                match self.dial(route, direct.clone(), headers, rm).await {
                    Ok(d) => Ok((d, direct, true)),
                    Err(DialError::Refused(r)) => Err(r),
                    Err(DialError::Connect) => {
                        Err(Refusal::new(RefusalReason::UpstreamUnavailable, ""))
                    }
                    Err(DialError::Failed) => Err(upstream_failed()),
                }
            }
            Err(DialError::Connect) => Err(Refusal::new(RefusalReason::ChainUnavailable, "")),
            Err(DialError::Refused(r)) => Err(r),
            Err(DialError::Failed) => Err(upstream_failed()),
        }
    }

    /// Sends scrim's handshake to `uri` and waits for the provider's answer.
    async fn dial(
        &self,
        route: &Route,
        uri: http::Uri,
        headers: &HeaderMap,
        rm: Option<&RouteMetrics>,
    ) -> Result<Dialed, DialError> {
        let key = generate_key();
        let mut up = Request::new(Full::new(Bytes::new()));
        *up.method_mut() = http::Method::GET;
        *up.uri_mut() = uri;
        *up.headers_mut() = headers.clone();
        let h = up.headers_mut();
        h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(
            header::SEC_WEBSOCKET_VERSION,
            HeaderValue::from_static("13"),
        );
        h.insert(
            header::SEC_WEBSOCKET_KEY,
            HeaderValue::from_str(&key).map_err(|_| DialError::Failed)?,
        );
        if let Some(auth) = route.auth.as_deref() {
            let token = match auth.token_source() {
                Some((m, cred)) => Some(
                    self.tokens
                        .token(&self.client, &m, cred)
                        .await
                        .map_err(DialError::Refused)?,
                ),
                None => None,
            };
            let (mut parts, body) = up.into_parts();
            auth.apply(
                &parts.method,
                &parts.uri,
                &mut parts.headers,
                b"",
                std::time::SystemTime::now(),
                token.as_ref(),
            )
            .map_err(DialError::Refused)?;
            up = Request::from_parts(parts, body);
        }
        if let Some(cap) = &self.capture {
            let shown = mask_query(up.uri(), route.provider.query_credentials());
            if let Err(e) = cap
                .request(&route.name, up.method(), &shown, headers, b"")
                .await
            {
                tracing::warn!(error = %e, "capture failed");
                return Err(DialError::Refused(Refusal::new(
                    RefusalReason::CaptureFailed,
                    "",
                )));
            }
        }
        let sent = Instant::now();
        let res = self.ws_client.request(up).await;
        if let Some(m) = rm {
            match &res {
                Ok(r) => m.upstream(sent.elapsed(), r.status()),
                Err(e) if e.is_connect() => m.upstream_error(UpstreamError::Connect),
                Err(_) => m.upstream_error(UpstreamError::Failed),
            }
        }
        let mut res = match res {
            Ok(r) => r,
            Err(e) if e.is_connect() => return Err(DialError::Connect),
            Err(e) => {
                tracing::warn!(route = %route.name, error = %e, "websocket handshake failed");
                return Err(DialError::Failed);
            }
        };
        if res.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Ok(Dialed::Answered(res));
        }
        let accept_ok = res
            .headers()
            .get(header::SEC_WEBSOCKET_ACCEPT)
            .is_some_and(|v| v.as_bytes() == derive_accept_key(key.as_bytes()).as_bytes());
        // scrim offered no extension, so a provider that picks one speaks a framing scrim
        // would not read correctly.
        if !accept_ok || res.headers().contains_key(header::SEC_WEBSOCKET_EXTENSIONS) {
            tracing::warn!(route = %route.name, "provider answered the websocket handshake incorrectly");
            return Err(DialError::Failed);
        }
        let io = match hyper::upgrade::on(&mut res).await {
            Ok(io) => io,
            Err(e) => {
                tracing::warn!(route = %route.name, error = %e, "websocket upgrade from the provider failed");
                return Err(DialError::Failed);
            }
        };
        let (parts, _) = res.into_parts();
        let socket = WebSocketStream::from_raw_socket(
            TokioIo::new(io),
            Role::Client,
            Some(ws_config(self.cfg.limits.max_response_body)),
        )
        .await;
        Ok(Dialed::Open(Box::new(socket), parts))
    }
}

/// What the audit and metrics see of a handshake that left: the head's redaction report.
fn handshake_out(head: crate::head::Head) -> Outgoing {
    Outgoing {
        body: Bytes::new(),
        report: head.report,
        guard_repaired: head.guard_repaired,
        unscanned: Vec::new(),
        stages: outgoing::Stages::default(),
    }
}

/// The agent's `101`: the provider's response headers (its chosen subprotocol, request ids),
/// without hop-by-hop headers and its own accept key, plus the accept key for the agent's key.
fn switching_protocols(upstream: &HeaderMap, client_key: &HeaderValue) -> Response<ProxyBody> {
    let mut headers = upstream.clone();
    strip(&mut headers, STRIP_RESPONSE);
    strip(&mut headers, STRIP_HANDSHAKE);
    headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    if let Ok(v) = HeaderValue::from_str(&derive_accept_key(client_key.as_bytes())) {
        headers.insert(header::SEC_WEBSOCKET_ACCEPT, v);
    }
    let mut resp = Response::new(full(Bytes::new()));
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *resp.headers_mut() = headers;
    resp
}

type Sink = SplitSink<Socket, Message>;

/// One open connection.
struct Relay {
    route: Route,
    api: WsApi,
    /// The agent's handshake, for the request gate when the snapshot changes.
    parts: http::request::Parts,
    snapshots: Arc<SnapshotCell>,
    /// The snapshot as loaded, before the gate bound it to this caller.
    base: Arc<Snapshot>,
    /// What the gate made of it: the one in use.
    snap: Arc<Snapshot>,
    audit: Arc<dyn AuditSink>,
    /// Capture sink, the target as recorded and the handshake headers as sent.
    capture: Option<(Arc<Capture>, http::Uri, HeaderMap)>,
    rm: Option<Arc<RouteMetrics>>,
    limits: Limits,
    /// Unscanned media types already audited on this connection.
    seen: Vec<String>,
    /// A message was refused: the connection ends with the agent's close, see [`LINGER`].
    refused: bool,
}

/// Restore state for provider messages, kept out of [`Relay`] so no `Cell` is held across an
/// await of the client path.
struct Restore {
    codec: Option<Box<dyn StreamCodec>>,
    stats: RestoreStats,
}

impl Relay {
    /// Waits for the agent's side of the upgrade, then relays until either side closes.
    async fn start(self, on_upgrade: OnUpgrade, mut upstream: Socket) {
        match on_upgrade.await {
            Ok(io) => {
                let client = WebSocketStream::from_raw_socket(
                    TokioIo::new(io),
                    Role::Server,
                    Some(ws_config(self.limits.max_request_body)),
                )
                .await;
                self.run(client, upstream).await;
            }
            Err(e) => {
                tracing::debug!(error = %e, "websocket upgrade from the agent failed");
                let _ = tokio::time::timeout(CLOSE_GRACE, upstream.close(None)).await;
            }
        }
    }

    async fn run(mut self, client: Socket, upstream: Socket) {
        let (mut to_client, mut from_client) = client.split();
        let (mut to_up, mut from_up) = upstream.split();
        let mut restore = Restore {
            codec: self.api.codec(&self.limits),
            stats: RestoreStats::default(),
        };
        loop {
            tokio::select! {
                m = from_client.next() => {
                    if !self.on_client(m, &mut to_client, &mut to_up).await {
                        break;
                    }
                }
                m = from_up.next() => {
                    if !self.on_upstream(m, &mut restore, &mut to_client, &mut to_up).await {
                        break;
                    }
                }
            }
        }
        if self.refused {
            let deadline = tokio::time::Instant::now() + LINGER;
            // Without the agent's close frame the stream may have stopped at an oversized
            // frame (tungstenite then ends it, as if the agent had), so the rest of the
            // agent's message is read off the socket itself.
            if !linger(&mut from_client, deadline).await
                && let Ok(mut s) = to_client.reunite(from_client)
            {
                drain(s.get_mut(), deadline).await;
            }
        }
        let (resolved, kept) = (restore.stats.resolved.get(), restore.stats.kept.get());
        if let Some(m) = &self.rm {
            m.restored(resolved, kept);
        }
        if resolved + kept > 0 {
            self.audit.record(AuditEvent::Restored {
                route: self.route.name.clone(),
                resolved,
                kept,
            });
        }
        tracing::debug!(route = %self.route.name, "websocket closed");
    }

    /// Handles one item from the agent. `false` ends the connection.
    async fn on_client(
        &mut self,
        m: Option<Result<Message, WsError>>,
        to_client: &mut Sink,
        to_up: &mut Sink,
    ) -> bool {
        let (data, text) = match m {
            Some(Ok(Message::Text(t))) => (Bytes::from(t), true),
            Some(Ok(Message::Binary(b))) => (b, false),
            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => return true,
            Some(Ok(Message::Close(f))) => {
                // The code is forwarded; the reason is the agent's text and is not.
                let code = f.map_or(CloseCode::Normal, |f| f.code);
                close(to_up, code, "").await;
                return false;
            }
            Some(Err(WsError::Capacity(_))) => {
                let r = Refusal::new(RefusalReason::BodyTooLarge, "websocket message");
                self.refuse(&r, to_client, to_up).await;
                return false;
            }
            Some(Err(WsError::Utf8(_))) => {
                let r = Refusal::new(RefusalReason::MalformedBody, "text message is not UTF-8");
                self.refuse(&r, to_client, to_up).await;
                return false;
            }
            Some(Err(e)) => {
                tracing::debug!(route = %self.route.name, error = %e, "websocket from the agent failed");
                close(to_up, CloseCode::Away, "").await;
                return false;
            }
            None => {
                close(to_up, CloseCode::Away, "").await;
                return false;
            }
        };
        match self.forwardable(data, text).await {
            Ok(msg) => {
                if let Err(e) = to_up.send(msg).await {
                    tracing::debug!(route = %self.route.name, error = %e, "websocket to the provider failed");
                    let r = Refusal::new(RefusalReason::UpstreamUnavailable, "");
                    self.refuse(&r, to_client, to_up).await;
                    return false;
                }
                true
            }
            Err(r) => {
                self.refuse(&r, to_client, to_up).await;
                false
            }
        }
    }

    /// Handles one item from the provider. `false` ends the connection.
    async fn on_upstream(
        &mut self,
        m: Option<Result<Message, WsError>>,
        restore: &mut Restore,
        to_client: &mut Sink,
        to_up: &mut Sink,
    ) -> bool {
        let out = match m {
            Some(Ok(Message::Text(t))) => self.restore(restore, t),
            Some(Ok(Message::Binary(b))) => vec![Message::Binary(b)],
            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => return true,
            Some(Ok(Message::Close(f))) => {
                for msg in self.finish(restore) {
                    let _ = to_client.send(msg).await;
                }
                let (code, reason) = f.map_or((CloseCode::Normal, Utf8Bytes::default()), |f| {
                    (f.code, f.reason)
                });
                close_with(to_client, code, reason).await;
                return false;
            }
            Some(Err(e)) => {
                tracing::debug!(route = %self.route.name, error = %e, "websocket from the provider failed");
                for msg in self.finish(restore) {
                    let _ = to_client.send(msg).await;
                }
                let r = Refusal::new(RefusalReason::UpstreamUnavailable, "");
                self.refuse(&r, to_client, to_up).await;
                return false;
            }
            None => {
                for msg in self.finish(restore) {
                    let _ = to_client.send(msg).await;
                }
                close(to_client, CloseCode::Away, "").await;
                return false;
            }
        };
        for msg in out {
            if to_client.send(msg).await.is_err() {
                close(to_up, CloseCode::Away, "").await;
                return false;
            }
        }
        true
    }

    /// The snapshot for the next message: the current one, bound to this caller by the gate
    /// again when it changed.
    async fn current(&mut self) -> Result<Arc<Snapshot>, Refusal> {
        let Some(latest) = self.snapshots.load() else {
            return Err(Refusal::new(RefusalReason::NotReady, ""));
        };
        if !Arc::ptr_eq(&latest, &self.base) {
            self.snap = admit(latest.clone(), &self.route, &self.parts).await?;
            self.base = latest;
        }
        Ok(self.snap.clone())
    }

    /// Redacts and guards one client message and returns what may leave.
    async fn forwardable(&mut self, data: Bytes, text: bool) -> Result<Message, Refusal> {
        let snap = self.current().await?;
        if let Some(rm) = &self.rm {
            rm.body_bytes(data.len());
        }
        let began = self.rm.as_ref().map(|_| Instant::now());
        let timed = began.is_some();
        let api = self.api;
        let out = if data.len() < self.limits.offload_threshold {
            prepare(&snap, api, &data, text, timed)?
        } else {
            let s = snap.clone();
            tokio::task::spawn_blocking(move || prepare(&s, api, &data, text, timed))
                .await
                .unwrap_or_else(|_| {
                    Err(Refusal::new(
                        RefusalReason::RedactorFailed,
                        "redaction task failed",
                    ))
                })?
        };
        if let Some((cap, uri, headers)) = &self.capture
            && let Err(e) = cap
                .request(
                    &self.route.name,
                    &http::Method::GET,
                    uri,
                    headers,
                    &out.body,
                )
                .await
        {
            tracing::warn!(error = %e, "capture failed");
            return Err(Refusal::new(RefusalReason::CaptureFailed, ""));
        }
        if let (Some(rm), Some(began)) = (&self.rm, began) {
            rm.stage(Stage::Redaction, out.stages.redaction);
            rm.stage(Stage::Guard, out.stages.guard);
            rm.stage(Stage::Total, began.elapsed());
            rm.forwarded(
                out.report.replacements,
                out.report.detectors.len(),
                !out.guard_repaired.is_empty(),
            );
        }
        self.audit_message(&snap, &out);
        if text {
            let t = Utf8Bytes::try_from(out.body).map_err(|_| {
                Refusal::new(
                    RefusalReason::RedactorFailed,
                    "message is not UTF-8 after redaction",
                )
            })?;
            Ok(Message::Text(t))
        } else {
            Ok(Message::Binary(out.body))
        }
    }

    /// Audits a forwarded message when something happened to it: a replacement, a detector, a
    /// guard repair, or an unscanned media type not yet audited on this connection. A Realtime
    /// session sends audio many times a second; one entry per message would flood the log.
    fn audit_message(&mut self, snap: &Snapshot, out: &Outgoing) {
        let mut fresh: Vec<String> = Vec::new();
        for t in &out.unscanned {
            if !self.seen.contains(t) && !fresh.contains(t) {
                fresh.push(t.clone());
            }
        }
        if out.report.replacements == 0
            && out.report.detectors.is_empty()
            && out.guard_repaired.is_empty()
            && fresh.is_empty()
        {
            return;
        }
        self.seen.extend(fresh.iter().cloned());
        self.audit.record(AuditEvent::Forwarded {
            route: self.route.name.clone(),
            snapshot: snap.version,
            replacements: out.report.replacements,
            refs: out.report.refs.clone(),
            detectors: out.report.detectors.clone(),
            guard_repaired: out.guard_repaired.clone(),
            unscanned: fresh,
            chain_skipped: false,
        });
    }

    /// Restores one provider text message into the messages the agent receives.
    fn restore(&self, r: &mut Restore, text: Utf8Bytes) -> Vec<Message> {
        let Some(codec) = r.codec.as_mut() else {
            return vec![Message::Text(text)];
        };
        if text.len() > self.limits.max_event {
            return vec![Message::Text(text)];
        }
        let began = self.rm.as_ref().map(|_| Instant::now());
        // One message is one SSE event with one data line. JSON has line breaks only as
        // whitespace, so they become spaces; an unchanged message still leaves as received.
        let s: &str = &text;
        let line: Cow<'_, str> = if s.contains(['\r', '\n']) {
            Cow::Owned(s.replace(['\r', '\n'], " "))
        } else {
            Cow::Borrowed(s)
        };
        let mut raw = Vec::with_capacity(line.len() + 8);
        raw.extend_from_slice(b"data: ");
        raw.extend_from_slice(line.as_bytes());
        raw.extend_from_slice(b"\n\n");
        let mut out = Vec::with_capacity(raw.len() + 64);
        codec.event(
            &Ctx {
                snap: &self.snap,
                stats: &r.stats,
            },
            &raw,
            &mut out,
        );
        let msgs = if out == raw {
            vec![Message::Text(text)]
        } else {
            messages(&out)
        };
        if let (Some(rm), Some(b)) = (&self.rm, began) {
            rm.chunk(b.elapsed());
        }
        msgs
    }

    /// Releases what the codec still holds when the provider stops.
    fn finish(&self, r: &mut Restore) -> Vec<Message> {
        let Some(codec) = r.codec.as_mut() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        codec.finish(
            &Ctx {
                snap: &self.snap,
                stats: &r.stats,
            },
            &mut out,
        );
        messages(&out)
    }

    async fn refuse(&mut self, r: &Refusal, to_client: &mut Sink, to_up: &mut Sink) {
        self.refused = true;
        tracing::info!(route = %self.route.name, reason = r.reason.code(), "websocket message refused");
        if let Some(m) = &self.rm {
            m.refused(r.reason);
        }
        self.audit.record(AuditEvent::Refused {
            route: Some(self.route.name.clone()),
            reason: r.reason,
            refs: r.refs.clone(),
        });
        let _ = tokio::time::timeout(CLOSE_GRACE, async {
            let _ = to_client.send(Message::text(r.ws_event())).await;
        })
        .await;
        close(to_client, CloseCode::from(r.close_code()), r.reason.code()).await;
        close(to_up, CloseCode::Away, "").await;
    }
}

/// The data of each SSE event in `out` as a text message.
fn messages(out: &[u8]) -> Vec<Message> {
    let mut msgs = Vec::new();
    let mut framer = sse::Framer::new(usize::MAX);
    framer.push(out, &mut |p| {
        if let sse::Piece::Event(e) = p
            && let Some(ev) = sse::Event::parse(e)
            && ev.has_data
        {
            msgs.push(Message::text(ev.data.into_owned()));
        }
    });
    msgs
}

/// Reads and drops what the agent still sends after a refusal, until its close frame, the end
/// of its stream or `deadline`, so the socket is not reset under the error event and close
/// frame scrim sent. Nothing read here is forwarded. `true` only for the agent's close frame:
/// after an oversized message the stream ends or fails with the rest of it still unread on
/// the socket.
async fn linger<S>(from_client: &mut S, deadline: tokio::time::Instant) -> bool
where
    S: futures_util::Stream<Item = Result<Message, WsError>> + Unpin,
{
    loop {
        match tokio::time::timeout_at(deadline, from_client.next()).await {
            Ok(Some(Ok(Message::Close(_)))) => return true,
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_)) | None) | Err(_) => return false,
        }
    }
}

/// Reads and drops raw bytes from the agent's socket until it ends its stream, fails or
/// `deadline` passes: the lingering close for a WebSocket stream that can no longer be read.
async fn drain<R>(io: &mut R, deadline: tokio::time::Instant)
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 8192];
    while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, io.read(&mut buf)).await {
        if n == 0 {
            return;
        }
    }
}

async fn close(s: &mut Sink, code: CloseCode, reason: &'static str) {
    close_with(s, code, Utf8Bytes::from_static(reason)).await;
}

async fn close_with(s: &mut Sink, code: CloseCode, reason: Utf8Bytes) {
    let _ = tokio::time::timeout(CLOSE_GRACE, async {
        let _ = s
            .send(Message::Close(Some(CloseFrame { code, reason })))
            .await;
        let _ = s.close().await;
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_the_agents_close_frame_ends_the_linger_cleanly() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut closed =
            futures_util::stream::iter([Ok(Message::text("late")), Ok(Message::Close(None))]);
        assert!(linger(&mut closed, deadline).await);
        // What tungstenite yields after an oversized message: the stream ends, or fails.
        let mut ended = futures_util::stream::iter(Vec::<Result<Message, WsError>>::new());
        assert!(!linger(&mut ended, deadline).await);
        let mut failed = futures_util::stream::iter([Err(WsError::AlreadyClosed)]);
        assert!(!linger(&mut failed, deadline).await);
    }

    #[tokio::test]
    async fn drain_reads_until_the_agent_ends_its_stream() {
        use tokio::io::AsyncWriteExt;
        let (mut agent, mut scrim) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            agent.write_all(&[7u8; 4096]).await.unwrap();
            drop(agent);
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        drain(&mut scrim, deadline).await;
        assert!(tokio::time::Instant::now() < deadline);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn drain_stops_at_the_deadline() {
        let (_agent, mut scrim) = tokio::io::duplex(64);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        drain(&mut scrim, deadline).await;
        assert!(tokio::time::Instant::now() >= deadline);
    }

    #[test]
    fn protocol_from_path() {
        assert_eq!(
            WsApi::for_path(Provider::Openai, "/v1/realtime"),
            WsApi::OpenAiRealtime
        );
        assert_eq!(
            WsApi::for_path(Provider::Openai, "/openai/realtime/"),
            WsApi::OpenAiRealtime
        );
        assert_eq!(
            WsApi::for_path(Provider::Openai, "/v1/responses"),
            WsApi::OpenAiResponses
        );
        assert_eq!(
            WsApi::for_path(Provider::Gemini, "/ws/BidiGenerateContent"),
            WsApi::Generic
        );
        assert_eq!(
            WsApi::for_path(Provider::Anthropic, "/v1/realtime"),
            WsApi::Generic
        );
    }

    #[test]
    fn handshake_detection() {
        let req = |f: &dyn Fn(http::request::Builder) -> http::request::Builder| {
            let b = Request::get("/openai/v1/realtime")
                .version(http::Version::HTTP_11)
                .header("connection", "Upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
            f(b).body(()).unwrap()
        };
        // No OnUpgrade extension: a listener that cannot upgrade.
        assert!(!is_handshake(&req(&|b| b)));
        assert!(token_in(
            req(&|b| b.header("upgrade", "foo, WebSocket")).headers(),
            header::UPGRADE,
            "websocket"
        ));
        assert!(!token_in(req(&|b| b).headers(), header::UPGRADE, "h2c"));
    }

    #[test]
    fn messages_split_events() {
        let out = b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\n";
        let m = messages(out);
        assert_eq!(
            m,
            vec![Message::text("{\"a\":1}"), Message::text("{\"b\":2}")]
        );
    }
}
