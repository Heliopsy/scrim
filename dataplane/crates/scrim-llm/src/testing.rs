// SPDX-License-Identifier: AGPL-3.0-only

//! Test doubles for the redaction contracts and a recording fake upstream.
//!
//! Enabled by the `test-util` feature. The fakes are small and honest: the redactor matches raw
//! and JSON-escaped values with Aho-Corasick, the guard does its own `memmem` scan, placeholders
//! follow the design D3 shape `⟦scrim:<slug>:<12 hex of HMAC-SHA256>⟧`. Each fake can be told to
//! fail so the fail-closed paths can be exercised. Values are generated at runtime; nothing here
//! is a real secret.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::panic,
    reason = "test support code; a broken fixture should fail the test loudly"
)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aho_corasick::{AhoCorasick, MatchKind};
use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use sha2::Sha256;

use crate::audit::{AuditEvent, AuditSink};
use crate::engine::{
    BinaryPolicy, EngineError, Guard, GuardVerdict, PlaceholderMatch, Placeholders, RedactReport,
    Redactor, Resolved, RestoreDecision, RestorePolicy, RestoreSite, SecretRef, SecretValue,
    Snapshot, ToolMode, ValueClass,
};
use crate::json;

/// Opening delimiter of fake placeholders.
pub const OPEN: &str = "\u{27e6}scrim:";
/// Closing delimiter.
pub const CLOSE: &str = "\u{27e7}";
const SLUG_MAX: usize = 32;
const HASH_HEX: usize = 12;

/// A generated value unlikely to collide with anything, `prefix` plus 24 random alphanumerics.
pub fn random_value(prefix: &str) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut raw = [0u8; 24];
    getrandom::fill(&mut raw).expect("getrandom");
    let tail: String = raw
        .iter()
        .map(|b| ALPHA[(*b as usize) % ALPHA.len()] as char)
        .collect();
    format!("{prefix}{tail}")
}

fn slug(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(SLUG_MAX)
        .collect();
    if s.is_empty() { "x".into() } else { s }
}

/// One secret known to the fixture.
#[derive(Clone)]
pub struct Entry {
    /// Reference name.
    pub reference: SecretRef,
    /// Class.
    pub class: ValueClass,
    /// Value.
    pub value: Arc<SecretValue>,
    /// Placeholder text.
    pub placeholder: String,
}

/// Placeholder table built from the fixture's entries.
pub struct FakePlaceholders {
    by_ph: HashMap<String, Entry>,
}

impl FakePlaceholders {
    fn shape_prefix_len(text: &[u8]) -> (usize, bool) {
        // Returns (bytes matched, complete).
        let open = OPEN.as_bytes();
        let close = CLOSE.as_bytes();
        let mut i = 0;
        while i < open.len() {
            match text.get(i) {
                None => return (i, false),
                Some(&c) if c == open[i] => i += 1,
                Some(_) => return (0, false),
            }
        }
        let slug_start = i;
        while i - slug_start < SLUG_MAX {
            match text.get(i) {
                None => return (i, false),
                Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' => i += 1,
                Some(_) => break,
            }
        }
        if i == slug_start {
            return (0, false);
        }
        match text.get(i) {
            None => return (i, false),
            Some(b':') => i += 1,
            Some(_) => return (0, false),
        }
        let h = i;
        while i - h < HASH_HEX {
            match text.get(i) {
                None => return (i, false),
                Some(c) if c.is_ascii_digit() || (b'a'..=b'f').contains(c) => i += 1,
                Some(_) => return (0, false),
            }
        }
        for &c in close {
            match text.get(i) {
                None => return (i, false),
                Some(&x) if x == c => i += 1,
                Some(_) => return (0, false),
            }
        }
        (i, true)
    }
}

impl Placeholders for FakePlaceholders {
    fn max_len(&self) -> usize {
        OPEN.len() + SLUG_MAX + 1 + HASH_HEX + CLOSE.len()
    }

    fn find(&self, text: &str) -> Option<PlaceholderMatch> {
        let b = text.as_bytes();
        let first = OPEN.as_bytes()[0];
        let mut from = 0;
        while let Some(j) = memchr::memchr(first, &b[from..]) {
            let start = from + j;
            match Self::shape_prefix_len(&b[start..]) {
                (n, true) => {
                    return Some(PlaceholderMatch::Complete {
                        start,
                        end: start + n,
                    });
                }
                (n, false) if n > 0 && start + n == b.len() => {
                    return Some(PlaceholderMatch::Partial { start });
                }
                _ => from = start + 1,
            }
        }
        None
    }

    fn resolve(&self, placeholder: &str) -> Option<Resolved> {
        // The percent form (brackets percent-encoded, as in header values) names the same entry.
        let raw;
        let placeholder = if placeholder.starts_with('%') {
            raw = from_percent_form(placeholder);
            raw.as_str()
        } else {
            placeholder
        };
        self.by_ph.get(placeholder).map(|e| Resolved {
            reference: e.reference.clone(),
            class: e.class,
            value: e.value.clone(),
        })
    }
}

/// The percent form of a placeholder: its non-ASCII brackets percent-encoded.
pub fn percent_form(placeholder: &str) -> String {
    placeholder
        .replace(OPEN, "%E2%9F%A6scrim:")
        .replace(CLOSE, "%E2%9F%A7")
}

fn from_percent_form(placeholder: &str) -> String {
    let mut s = placeholder.to_string();
    for (enc, raw) in [("%E2%9F%A6scrim:", OPEN), ("%E2%9F%A7", CLOSE)] {
        if let Some(i) = s.to_ascii_uppercase().find(&enc.to_ascii_uppercase()) {
            s.replace_range(i..i + enc.len(), raw);
        }
    }
    s
}

/// Failure injection for the fake redactor and guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fault {
    /// Behave.
    #[default]
    None,
    /// Return an error.
    Error,
}

/// Fake redactor: Aho-Corasick over raw and JSON-escaped values, leftmost-longest.
pub struct FakeRedactor {
    detector: Option<String>,
    ac: Option<AhoCorasick>,
    owner: Vec<usize>,
    entries: Vec<Entry>,
    fault: Fault,
}

impl FakeRedactor {
    fn new(entries: &[Entry], fault: Fault, miss: &[String], detector: Option<String>) -> Self {
        let mut pats: Vec<Vec<u8>> = Vec::new();
        let mut owner = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            if miss.iter().any(|m| m == e.reference.as_str()) {
                continue;
            }
            let raw = e.value.expose().to_vec();
            let mut esc = Vec::new();
            json::escape_into(&mut esc, std::str::from_utf8(&raw).unwrap_or_default());
            for p in [raw, esc] {
                if !pats.contains(&p) {
                    pats.push(p);
                    owner.push(i);
                }
            }
        }
        let ac = (!pats.is_empty()).then(|| {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&pats)
                .expect("aho-corasick")
        });
        Self {
            detector,
            ac,
            owner,
            entries: entries.to_vec(),
            fault,
        }
    }
}

/// Placeholder the fake detector writes.
pub const DETECTED: &str = "\u{27e6}scrim:detected:000000000000\u{27e7}";

impl Redactor for FakeRedactor {
    fn redact(&self, input: &[u8], out: &mut Vec<u8>) -> Result<RedactReport, EngineError> {
        let Some(d) = self.detector.as_deref().filter(|d| !d.is_empty()) else {
            return self.redact_known(input, out);
        };
        let mut tmp = Vec::new();
        let mut rep = self.redact_known(input, &mut tmp)?;
        let mut pos = 0;
        for i in memchr::memmem::find_iter(&tmp, d.as_bytes()) {
            if i < pos {
                continue;
            }
            out.extend_from_slice(&tmp[pos..i]);
            out.extend_from_slice(DETECTED.as_bytes());
            pos = i + d.len();
            rep.replacements += 1;
            if !rep.detectors.iter().any(|x| x == "fake-pattern") {
                rep.detectors.push("fake-pattern".into());
            }
        }
        out.extend_from_slice(&tmp[pos..]);
        Ok(rep)
    }
}

impl FakeRedactor {
    fn redact_known(&self, input: &[u8], out: &mut Vec<u8>) -> Result<RedactReport, EngineError> {
        if self.fault == Fault::Error {
            return Err(EngineError::new("injected redactor fault"));
        }
        let mut rep = RedactReport::default();
        let Some(ac) = &self.ac else {
            out.extend_from_slice(input);
            return Ok(rep);
        };
        let mut pos = 0;
        for m in ac.find_iter(input) {
            let e = &self.entries[self.owner[m.pattern().as_usize()]];
            out.extend_from_slice(&input[pos..m.start()]);
            out.extend_from_slice(e.placeholder.as_bytes());
            pos = m.end();
            rep.replacements += 1;
            if !rep.refs.contains(&e.reference) {
                rep.refs.push(e.reference.clone());
            }
        }
        out.extend_from_slice(&input[pos..]);
        Ok(rep)
    }
}

/// Guard behaviour when it finds a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GuardMode {
    /// Replace with the placeholder.
    #[default]
    Repair,
    /// Refuse the request.
    Refuse,
}

/// Fake guard: independent `memmem` scan for raw values.
pub struct FakeGuard {
    entries: Vec<Entry>,
    mode: GuardMode,
    fault: Fault,
    /// One automaton over all raw values, for benchmark-sized sets (`Fixture::fast_guard`).
    automaton: Option<AhoCorasick>,
}

impl Guard for FakeGuard {
    fn check(&self, outgoing: &[u8]) -> Result<GuardVerdict, EngineError> {
        if self.fault == Fault::Error {
            return Err(EngineError::new("injected guard fault"));
        }
        if self.entries.is_empty() {
            return Ok(GuardVerdict::Clean);
        }
        if let Some(ac) = &self.automaton {
            // Fast path: one pass to see whether anything is there at all.
            if !ac.is_match(outgoing) {
                return Ok(GuardVerdict::Clean);
            }
        }
        let mut refs = Vec::new();
        let mut bytes = outgoing.to_vec();
        for e in &self.entries {
            let v = e.value.expose();
            if v.is_empty() || memchr::memmem::find(&bytes, v).is_none() {
                continue;
            }
            refs.push(e.reference.clone());
            let mut next = Vec::with_capacity(bytes.len());
            let mut pos = 0;
            for i in memchr::memmem::find_iter(&bytes, v) {
                if i < pos {
                    continue;
                }
                next.extend_from_slice(&bytes[pos..i]);
                next.extend_from_slice(e.placeholder.as_bytes());
                pos = i + v.len();
            }
            next.extend_from_slice(&bytes[pos..]);
            bytes = next;
        }
        Ok(match (refs.is_empty(), self.mode) {
            (true, _) => GuardVerdict::Clean,
            (false, GuardMode::Repair) => GuardVerdict::Repaired { bytes, refs },
            (false, GuardMode::Refuse) => GuardVerdict::Refused { refs },
        })
    }
}

/// One policy consultation: tool name (empty for text) and the full arguments if given.
pub type Seen = (String, Option<String>);

/// Configurable restore policy.
#[derive(Debug, Clone, Default)]
pub struct FakePolicy {
    /// Resolve in assistant text.
    pub text: bool,
    /// Tools whose arguments may receive values.
    pub tools: Vec<String>,
    /// Resolve in every tool.
    pub all_tools: bool,
    /// Tools fed in buffered mode.
    pub buffered: Vec<String>,
    /// Sites seen, for assertions: (tool or "", had full arguments).
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakePolicy {
    /// Resolve everywhere the proxy allows.
    pub fn resolve_all() -> Self {
        Self {
            text: true,
            all_tools: true,
            ..Self::default()
        }
    }

    /// Keep every placeholder.
    pub fn keep_all() -> Self {
        Self::default()
    }

    /// Resolve in text only.
    pub fn text_only() -> Self {
        Self {
            text: true,
            ..Self::default()
        }
    }
}

impl RestorePolicy for FakePolicy {
    fn decide(
        &self,
        site: &RestoreSite<'_>,
        _reference: &SecretRef,
        _class: ValueClass,
    ) -> RestoreDecision {
        let ok = match site {
            RestoreSite::Text => {
                self.seen.lock().unwrap().push((String::new(), None));
                self.text
            }
            RestoreSite::ToolInput { tool, arguments } => {
                self.seen
                    .lock()
                    .unwrap()
                    .push((tool.to_string(), arguments.map(str::to_string)));
                self.all_tools || self.tools.iter().any(|t| t == tool)
            }
        };
        if ok {
            RestoreDecision::Resolve
        } else {
            RestoreDecision::Keep
        }
    }

    fn tool_mode(&self, tool: &str) -> ToolMode {
        if self.buffered.iter().any(|t| t == tool) {
            ToolMode::Buffered
        } else {
            ToolMode::Stream
        }
    }
}

/// A set of generated secrets plus knobs, producing snapshots.
#[derive(Clone)]
pub struct Fixture {
    key: Vec<u8>,
    entries: Vec<Entry>,
    /// Restore policy used by [`Fixture::snapshot`]. Defaults to resolve everywhere allowed.
    pub policy: FakePolicy,
    /// Redactor fault.
    pub redactor_fault: Fault,
    /// Guard fault.
    pub guard_fault: Fault,
    /// Guard behaviour on findings.
    pub guard_mode: GuardMode,
    /// References the redactor is made to miss, to exercise the guard.
    pub redactor_misses: Vec<String>,
    /// Binary policy.
    pub binary: BinaryPolicy,
    /// A literal the fake redactor treats as a fallback-detector hit (stands in for pattern
    /// and entropy rules, which would fire on signatures and encrypted blobs).
    pub detector: Option<String>,
    /// Let the fake guard pre-check with one automaton, so benchmarks with thousands of values
    /// measure something closer to a real guard than one scan per value.
    pub fast_guard: bool,
    /// Snapshot version.
    pub version: u64,
}

impl Fixture {
    /// A fixture with display-class `(reference, value)` pairs and a random placeholder key.
    pub fn new(display: &[(&str, &str)]) -> Self {
        let mut key = vec![0u8; 32];
        getrandom::fill(&mut key).expect("getrandom");
        let mut fx = Self {
            key,
            entries: Vec::new(),
            policy: FakePolicy::resolve_all(),
            redactor_fault: Fault::None,
            guard_fault: Fault::None,
            guard_mode: GuardMode::Repair,
            redactor_misses: Vec::new(),
            binary: BinaryPolicy::default(),
            detector: None,
            fast_guard: false,
            version: 1,
        };
        for (r, v) in display {
            fx.add(r, v, ValueClass::Display);
        }
        fx
    }

    /// A fixture with `n` generated display values named `s0..sN`.
    pub fn generated(n: usize) -> Self {
        let mut fx = Self::new(&[]);
        for i in 0..n {
            fx.add(
                &format!("s{i}"),
                &random_value(&format!("sv{i}_")),
                ValueClass::Display,
            );
        }
        fx
    }

    /// Adds a value.
    pub fn add(&mut self, reference: &str, value: &str, class: ValueClass) {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key).expect("hmac key");
        mac.update(value.as_bytes());
        let h = mac.finalize().into_bytes();
        let hex: String = h
            .iter()
            .take(HASH_HEX / 2)
            .fold(String::new(), |mut acc, b| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{b:02x}");
                acc
            });
        let placeholder = format!("{OPEN}{}:{hex}{CLOSE}", slug(reference));
        self.entries.push(Entry {
            reference: SecretRef::new(reference),
            class,
            value: Arc::new(SecretValue::new(value.as_bytes().to_vec())),
            placeholder,
        });
    }

    /// Adds a credential-class value.
    pub fn add_credential(&mut self, reference: &str, value: &str) {
        self.add(reference, value, ValueClass::Credential);
    }

    /// Entries.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The value of `reference`.
    pub fn value(&self, reference: &str) -> String {
        let e = self
            .entries
            .iter()
            .find(|e| e.reference.as_str() == reference)
            .expect("known reference");
        String::from_utf8(e.value.expose().to_vec()).expect("utf-8 value")
    }

    /// The placeholder of `reference`.
    pub fn placeholder(&self, reference: &str) -> String {
        self.entries
            .iter()
            .find(|e| e.reference.as_str() == reference)
            .expect("known reference")
            .placeholder
            .clone()
    }

    /// The placeholder of `reference` in percent form, as a header value carries it.
    pub fn placeholder_ascii(&self, reference: &str) -> String {
        percent_form(&self.placeholder(reference))
    }

    /// Longest placeholder length.
    pub fn placeholders_max_len(&self) -> usize {
        self.fake_placeholders().max_len()
    }

    fn fake_placeholders(&self) -> FakePlaceholders {
        FakePlaceholders {
            by_ph: self
                .entries
                .iter()
                .map(|e| (e.placeholder.clone(), e.clone()))
                .collect(),
        }
    }

    /// Builds a snapshot.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: self.version,
            redactor: Arc::new(FakeRedactor::new(
                &self.entries,
                self.redactor_fault,
                &self.redactor_misses,
                self.detector.clone(),
            )),
            guard: Arc::new(FakeGuard {
                entries: self.entries.clone(),
                mode: self.guard_mode,
                fault: self.guard_fault,
                automaton: self.fast_guard.then(|| {
                    AhoCorasick::new(self.entries.iter().map(|e| e.value.expose().to_vec()))
                        .expect("aho-corasick")
                }),
            }),
            placeholders: Arc::new(self.fake_placeholders()),
            policy: Arc::new(self.policy.clone()),
            binary: self.binary,
            routes: None,
            gate: None,
        }
    }

    /// Returns `true` when `bytes` contains any value verbatim or JSON-escaped.
    pub fn leaks(&self, bytes: &[u8]) -> Vec<String> {
        let mut found = Vec::new();
        for e in &self.entries {
            let v = e.value.expose();
            let mut esc = Vec::new();
            json::escape_into(&mut esc, std::str::from_utf8(v).unwrap_or_default());
            if memchr::memmem::find(bytes, v).is_some()
                || memchr::memmem::find(bytes, &esc).is_some()
            {
                found.push(e.reference.as_str().to_string());
            }
        }
        found
    }
}

/// Audit sink that keeps events in memory.
#[derive(Debug, Default, Clone)]
pub struct RecordingAudit {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl RecordingAudit {
    /// Events so far.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl AuditSink for RecordingAudit {
    fn record(&self, event: AuditEvent) {
        self.events.lock().unwrap().push(event);
    }
}

/// A request the fake upstream received.
#[derive(Debug, Clone)]
pub struct Recorded {
    /// Method.
    pub method: http::Method,
    /// Path and query.
    pub uri: String,
    /// HTTP version.
    pub version: http::Version,
    /// Headers.
    pub headers: http::HeaderMap,
    /// Body bytes.
    pub body: Bytes,
}

/// A scripted response.
#[derive(Debug, Clone)]
pub struct Scripted {
    /// Status.
    pub status: u16,
    /// Headers.
    pub headers: Vec<(String, String)>,
    /// Body chunks, sent with `delay` between them.
    pub chunks: Vec<Bytes>,
    /// Delay between chunks.
    pub delay: Duration,
}

impl Scripted {
    /// A JSON response.
    pub fn json(status: u16, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            chunks: vec![body.into()],
            delay: Duration::ZERO,
        }
    }

    /// An SSE response sent in `chunks`.
    pub fn sse(chunks: Vec<Bytes>) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            chunks,
            delay: Duration::ZERO,
        }
    }
}

type Responder = Arc<dyn Fn(&Recorded) -> Scripted + Send + Sync>;

/// Whether a header value is an RFC 9110 `field-value` without obs-text: visible ASCII, space
/// and tab. The fake upstream is as strict as the strictest provider front end.
pub fn is_strict_field_value(v: &[u8]) -> bool {
    v.iter()
        .all(|&b| b == b' ' || b == b'\t' || b.is_ascii_graphic())
}

/// A fake provider that records every request and answers from a script.
///
/// Like a strict provider front end, it answers `400` with `x-fake-upstream: obs-text` and
/// records nothing when a request header value holds bytes outside visible ASCII.
pub struct FakeUpstream {
    /// Listening address.
    pub addr: SocketAddr,
    received: Arc<Mutex<Vec<Recorded>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeUpstream {
    /// Starts on 127.0.0.1 with a fixed response.
    pub async fn start(response: Scripted) -> Self {
        Self::start_with(move |_| response.clone()).await
    }

    /// Starts with a response function.
    pub async fn start_with(f: impl Fn(&Recorded) -> Scripted + Send + Sync + 'static) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        Self::serve(listener, addr, Arc::new(f))
    }

    fn serve(listener: tokio::net::TcpListener, addr: SocketAddr, f: Responder) -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let rec = received.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let rec = rec.clone();
                let f = f.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let rec = rec.clone();
                        let f = f.clone();
                        async move { Ok::<_, Infallible>(handle(req, &rec, &f).await) }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                    .await;
                });
            }
        });
        Self {
            addr,
            received,
            task,
        }
    }

    /// Base URL, `http://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Requests received so far.
    pub fn received(&self) -> Vec<Recorded> {
        self.received.lock().unwrap().clone()
    }
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type BoxedBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

async fn handle(
    req: Request<Incoming>,
    rec: &Mutex<Vec<Recorded>>,
    f: &Responder,
) -> Response<BoxedBody> {
    let (parts, body) = req.into_parts();
    if !parts
        .headers
        .values()
        .all(|v| is_strict_field_value(v.as_bytes()))
    {
        return Response::builder()
            .status(400)
            .header("x-fake-upstream", "obs-text")
            .body(BodyExt::boxed(http_body_util::Full::new(
                Bytes::from_static(b"header value outside visible ASCII"),
            )))
            .expect("response");
    }
    let body = body
        .collect()
        .await
        .map_or_default(http_body_util::Collected::to_bytes);
    let r = Recorded {
        method: parts.method,
        uri: parts
            .uri
            .path_and_query()
            .map_or_default(std::string::ToString::to_string),
        version: parts.version,
        headers: parts.headers,
        body,
    };
    let script = f(&r);
    rec.lock().unwrap().push(r);
    let mut b = Response::builder().status(script.status);
    for (k, v) in &script.headers {
        b = b.header(k, v);
    }
    let delay = script.delay;
    let stream =
        futures_util::stream::unfold(script.chunks.into_iter(), move |mut it| async move {
            let c = it.next()?;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            Some((Ok::<_, Infallible>(Frame::data(c)), it))
        });
    b.body(BodyExt::boxed(StreamBody::new(stream)))
        .expect("response")
}

/// What the fake WebSocket provider received on its connections, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsReceived {
    /// A text message.
    Text(String),
    /// A binary message.
    Binary(Bytes),
    /// A ping (scrim never forwards one).
    Ping(Bytes),
    /// A close frame: code and reason.
    Close(Option<(u16, String)>),
}

/// The fake WebSocket provider's answer to one text message: the text messages it sends back.
pub type WsResponder = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;

/// A fake WebSocket provider: records every handshake and message, sends `greeting` when a
/// connection opens, answers each text message with what the responder returns, and with
/// `refuse` answers every handshake with that status instead of upgrading.
pub struct FakeWsUpstream {
    /// Listening address.
    pub addr: SocketAddr,
    handshakes: Arc<Mutex<Vec<Recorded>>>,
    received: Arc<Mutex<Vec<WsReceived>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeWsUpstream {
    /// Starts on 127.0.0.1.
    pub async fn start(
        greeting: Vec<String>,
        responder: impl Fn(&str) -> Vec<String> + Send + Sync + 'static,
    ) -> Self {
        Self::serve(greeting, Arc::new(responder), None).await
    }

    /// Starts a provider that answers every handshake with `status` and a JSON error body.
    pub async fn refusing(status: u16) -> Self {
        Self::serve(Vec::new(), Arc::new(|_| Vec::new()), Some(status)).await
    }

    async fn serve(greeting: Vec<String>, f: WsResponder, refuse: Option<u16>) -> Self {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::tungstenite::handshake::server::{
            ErrorResponse, Request as WsReq, Response as WsResp,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handshakes = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::new(Mutex::new(Vec::new()));
        let (hs, rec) = (handshakes.clone(), received.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (hs, rec, f, greeting) = (hs.clone(), rec.clone(), f.clone(), greeting.clone());
                tokio::spawn(async move {
                    // The callback's signature is tungstenite's.
                    #[allow(clippy::result_large_err)]
                    let cb = |req: &WsReq, resp: WsResp| -> Result<WsResp, ErrorResponse> {
                        hs.lock().unwrap().push(Recorded {
                            method: req.method().clone(),
                            uri: req
                                .uri()
                                .path_and_query()
                                .map_or_default(std::string::ToString::to_string),
                            version: req.version(),
                            headers: req.headers().clone(),
                            body: Bytes::new(),
                        });
                        match refuse {
                            Some(status) => {
                                let mut e = ErrorResponse::new(Some(
                                    r#"{"error":{"message":"refused by the fake provider"}}"#
                                        .to_string(),
                                ));
                                *e.status_mut() =
                                    http::StatusCode::from_u16(status).expect("status");
                                Err(e)
                            }
                            None => Ok(resp),
                        }
                    };
                    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, cb).await else {
                        return;
                    };
                    for g in greeting {
                        let _ = ws.send(Message::text(g)).await;
                    }
                    while let Some(Ok(m)) = ws.next().await {
                        match m {
                            Message::Text(t) => {
                                let replies = f(&t);
                                rec.lock().unwrap().push(WsReceived::Text(t.to_string()));
                                for r in replies {
                                    if ws.send(Message::text(r)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Message::Binary(b) => {
                                rec.lock().unwrap().push(WsReceived::Binary(b));
                            }
                            Message::Ping(p) => rec.lock().unwrap().push(WsReceived::Ping(p)),
                            Message::Close(c) => {
                                rec.lock().unwrap().push(WsReceived::Close(
                                    c.map(|c| (u16::from(c.code), c.reason.to_string())),
                                ));
                            }
                            Message::Pong(_) | Message::Frame(_) => {}
                        }
                    }
                });
            }
        });
        Self {
            addr,
            handshakes,
            received,
            task,
        }
    }

    /// Base URL, `http://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Handshakes received so far (method, path and query, headers).
    pub fn handshakes(&self) -> Vec<Recorded> {
        self.handshakes.lock().unwrap().clone()
    }

    /// Messages received so far, across connections.
    pub fn received(&self) -> Vec<WsReceived> {
        self.received.lock().unwrap().clone()
    }

    /// The text messages received so far.
    pub fn texts(&self) -> Vec<String> {
        self.received()
            .into_iter()
            .filter_map(|m| match m {
                WsReceived::Text(t) => Some(t),
                _ => None,
            })
            .collect()
    }
}

impl Drop for FakeWsUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_shape_and_find() {
        let fx = Fixture::new(&[("GitHub Token", "value-aaaaaaaaaaaa")]);
        let ph = fx.placeholder("GitHub Token");
        assert!(ph.starts_with("\u{27e6}scrim:github-token:"));
        let p = fx.fake_placeholders();
        let t = format!("ab{ph}cd");
        assert_eq!(
            p.find(&t),
            Some(PlaceholderMatch::Complete {
                start: 2,
                end: 2 + ph.len()
            })
        );
        for cut in 1..ph.len() {
            if ph.is_char_boundary(cut) {
                let t = format!("ab{}", &ph[..cut]);
                assert_eq!(
                    p.find(&t),
                    Some(PlaceholderMatch::Partial { start: 2 }),
                    "cut {cut}"
                );
            }
        }
        assert_eq!(p.find("no placeholder \u{27e6} here"), None);
        assert!(p.resolve(&ph).is_some());
        assert!(ph.len() <= p.max_len());
    }

    #[test]
    fn redactor_and_guard_are_independent() {
        let mut fx = Fixture::new(&[("a", "alpha-value-0001"), ("b", "bravo-value-0002")]);
        fx.redactor_misses = vec!["b".into()];
        let s = fx.snapshot();
        let mut out = Vec::new();
        let rep = s
            .redactor
            .redact(b"x alpha-value-0001 bravo-value-0002", &mut out)
            .unwrap();
        assert_eq!(rep.refs, vec![SecretRef::new("a")]);
        match s.guard.check(&out).unwrap() {
            GuardVerdict::Repaired { bytes, refs } => {
                assert_eq!(refs, vec![SecretRef::new("b")]);
                assert_eq!(fx.leaks(&bytes), [] as [std::string::String; 0]);
            }
            v => panic!("unexpected {v:?}"),
        }
    }
}
