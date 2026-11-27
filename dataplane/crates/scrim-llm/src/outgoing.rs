// SPDX-License-Identifier: AGPL-3.0-only

//! Turns an agent's request body into the bytes that may leave: plan, redact, guard.
//!
//! The body is split at the codec's verbatim spans. The redactor runs over every other segment
//! on its raw bytes; verbatim spans are copied unchanged. The guard then checks the complete
//! outgoing bytes, verbatim spans included, so a known value inside an allowlisted field or a
//! thinking block is still repaired or refused. Any error refuses the request.

use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::audit::RefusalReason;
use crate::binary;
use crate::codec::{self, Api};
use crate::engine::{BinaryPolicy, GuardVerdict, RedactReport, SecretRef, Snapshot};
use crate::error::Refusal;
use crate::remote;

/// A request body that passed redaction and the guard.
#[derive(Debug)]
pub struct Outgoing {
    /// Bytes to forward.
    pub body: Bytes,
    /// What the redactor did.
    pub report: RedactReport,
    /// References the guard repaired.
    pub guard_repaired: Vec<SecretRef>,
    /// Media types of binary parts forwarded unscanned under the `pass` policy.
    pub unscanned: Vec<String>,
    /// Time the redactor and the guard took, when measured ([`prepare_timed`]).
    pub stages: Stages,
}

/// Time spent in each check over the body. Zero when not measured.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stages {
    /// The redactor over every non-verbatim segment.
    pub redaction: Duration,
    /// The guard over the complete outgoing bytes.
    pub guard: Duration,
}

/// Redacts and checks `body` for `api` with one snapshot.
pub fn prepare(snap: &Snapshot, api: Api, body: &[u8]) -> Result<Outgoing, Refusal> {
    prepare_timed(snap, api, body, false)
}

/// [`prepare`], also measuring the redactor and the guard into [`Outgoing::stages`] when
/// `timed` (two clock reads per stage; none otherwise).
pub fn prepare_timed(
    snap: &Snapshot,
    api: Api,
    body: &[u8],
    timed: bool,
) -> Result<Outgoing, Refusal> {
    let cache = snap.redactor.plan_cache();
    prepare_planned(snap, body, timed, |b| codec::plan_cached(api, b, cache))
}

/// [`prepare_timed`] with the codec plan made by `planner` (WebSocket messages, whose events are
/// planned per protocol in [`crate::websocket`]). It is called again when text documents inside
/// binary parts were redacted and the body re-encoded.
pub(crate) fn prepare_planned(
    snap: &Snapshot,
    body: &[u8],
    timed: bool,
    planner: impl Fn(&[u8]) -> Result<codec::Plan, codec::PlanError>,
) -> Result<Outgoing, Refusal> {
    match prepare_refs(snap, body, timed, remote::Context::NONE, planner)? {
        Prepared::Done(o) => Ok(o),
        // `Context::NONE` cannot fetch, so `remote::check` refuses before asking for it.
        Prepared::Fetch(_) => Err(Refusal::new(
            RefusalReason::RemoteAttachment,
            "attachments referenced by URL cannot be fetched here",
        )),
    }
}

/// What [`prepare_refs`] decided.
#[derive(Debug)]
pub(crate) enum Prepared {
    /// The body that may leave.
    Done(Outgoing),
    /// The request references attachments by URL and the remote policy is `inline`: fetch
    /// these, splice them into the body ([`remote::fetch::Fetcher::inline`]) and prepare the
    /// new body with [`remote::Context::fetched`] set.
    Fetch(Vec<(usize, remote::Reference)>),
}

/// [`prepare_planned`], with the remote attachment policy applied under `cx` first. Nothing is
/// redacted before the references are settled, so a request that needs fetching costs one plan.
pub(crate) fn prepare_refs(
    snap: &Snapshot,
    body: &[u8],
    timed: bool,
    cx: remote::Context<'_>,
    planner: impl Fn(&[u8]) -> Result<codec::Plan, codec::PlanError>,
) -> Result<Prepared, Refusal> {
    let clock = || timed.then(Instant::now);
    let since = |t: Option<Instant>| t.map_or(Duration::ZERO, |t| t.elapsed());
    let started = clock();
    let malformed = |e: codec::PlanError| Refusal::new(RefusalReason::MalformedBody, e.to_string());
    let mut plan = planner(body).map_err(malformed)?;
    let checked = remote::check(&snap.remote, &plan.remote, cx)?;
    if !checked.fetch.is_empty() {
        return Ok(Prepared::Fetch(checked.fetch));
    }
    let mut report = RedactReport::default();
    let mut text_repaired = Vec::new();
    let spliced;
    let mut body = body;
    let unscanned = match snap.binary {
        _ if plan.binary.is_empty() => Vec::new(),
        BinaryPolicy::Block => {
            let mut types = plan.binary.clone();
            types.sort();
            types.dedup();
            return Err(Refusal::new(
                RefusalReason::UnscannableContent,
                format!("content types: {}", types.join(", ")),
            ));
        }
        BinaryPolicy::Scan => {
            let mut text = scan_parts(snap, body, &plan, &binary::Limits::default())?;
            if !text.edits.is_empty() {
                // Text documents were redacted and encoded again: plan the new body.
                text.edits.sort_unstable_by_key(|e| e.0);
                spliced = crate::json::splice(body, &text.edits);
                body = &spliced;
                plan = planner(body).map_err(malformed)?;
            }
            report = text.report;
            text_repaired = text.guard_repaired;
            Vec::new()
        }
        BinaryPolicy::Pass => plan.binary.clone(),
    };
    let mut unscanned = unscanned;
    unscanned.extend(checked.unscanned);
    let mut out = Vec::with_capacity(body.len() + body.len() / 16 + 64);
    let mut pos = 0;
    let redact =
        |seg: &[u8], out: &mut Vec<u8>, report: &mut RedactReport| -> Result<(), Refusal> {
            if seg.is_empty() {
                return Ok(());
            }
            let r = snap.redactor.redact(seg, out).map_err(|e| {
                Refusal::new(RefusalReason::RedactorFailed, e.message().to_string())
            })?;
            report.merge(r);
            Ok(())
        };
    for &(s, e) in &plan.verbatim {
        redact(&body[pos..s], &mut out, &mut report)?;
        out.extend_from_slice(&body[s..e]);
        pos = e;
    }
    redact(&body[pos..], &mut out, &mut report)?;
    let redaction = since(started);

    let guard_started = clock();
    let verdict = snap
        .guard
        .check(&out)
        .map_err(|e| Refusal::new(RefusalReason::GuardFailed, e.message().to_string()))?;
    let guard = since(guard_started);
    let (out, mut guard_repaired) = match verdict {
        GuardVerdict::Clean => (out, Vec::new()),
        GuardVerdict::Repaired { bytes, refs } => (bytes, refs),
        GuardVerdict::Refused { refs } => {
            return Err(Refusal {
                reason: RefusalReason::GuardRefused,
                detail: String::new(),
                refs,
            });
        }
    };
    for r in text_repaired {
        if !guard_repaired.contains(&r) {
            guard_repaired.push(r);
        }
    }
    Ok(Prepared::Done(Outgoing {
        body: Bytes::from(out),
        report,
        guard_repaired,
        unscanned,
        stages: Stages { redaction, guard },
    }))
}

/// The `scan` binary policy: decodes every binary part of `plan` and runs the redactor and the
/// guard over each view of it (the decoded bytes, the text extracted from its metadata or
/// document streams). A secret value found in a view refuses the request with
/// `secret_in_binary`, naming the part and the references, because a part cannot be redacted in
/// place without corrupting it. A part that cannot be decoded within `limits` refuses it with
/// `unscannable_content`. Nothing is ever forwarded unscanned under this policy.
fn scan_parts(
    snap: &Snapshot,
    body: &[u8],
    plan: &codec::Plan,
    limits: &binary::Limits,
) -> Result<TextParts, Refusal> {
    let mut text_parts = TextParts::default();
    let mut scratch = Vec::new();
    for (i, (part, media_type)) in plan.parts.iter().zip(&plan.binary).enumerate() {
        let name = format!("binary part {} ({media_type})", i + 1);
        let undecodable = |e: binary::Undecodable| {
            Refusal::new(RefusalReason::UnscannableContent, format!("{name}: {e}"))
        };
        if !part.string {
            return Err(undecodable(binary::Undecodable::Corrupt(
                "data is not a string",
            )));
        }
        let text = crate::json::unescape(&body[part.span.0..part.span.1]);
        let decoded = binary::decode(&text, limits).map_err(undecodable)?;
        if is_text_document(media_type, &decoded) {
            redact_text_part(snap, part.span, &text, &decoded, &mut text_parts)?;
            continue;
        }
        drop(text);
        scan_decoded(snap, &name, &decoded, limits, &mut scratch)?;
    }
    Ok(text_parts)
}

/// Runs the redactor and the guard over every view of one decoded binary part, see
/// [`scan_parts`]. `name` says which part it is in a refusal.
fn scan_decoded(
    snap: &Snapshot,
    name: &str,
    decoded: &[u8],
    limits: &binary::Limits,
    scratch: &mut Vec<u8>,
) -> Result<(), Refusal> {
    let undecodable = |e: binary::Undecodable| {
        Refusal::new(RefusalReason::UnscannableContent, format!("{name}: {e}"))
    };
    let mut found: Option<Hit> = None;
    let mut failure: Option<Refusal> = None;
    let mut batch = Batch::default();
    let mut check = |batch: &mut Batch, bytes: Option<(&'static str, &[u8])>| {
        let r = match bytes {
            Some((source, b)) => check_view(snap, b, scratch).map(|h| {
                h.map(|(refs, detectors)| Hit {
                    source,
                    refs,
                    detectors,
                })
            }),
            None => batch.flush(snap, scratch),
        };
        match r {
            Ok(None) => true,
            Ok(Some(hit)) => {
                found = Some(hit);
                false
            }
            Err(e) => {
                failure = Some(e);
                false
            }
        }
    };
    let mut stopped = false;
    let scanned = binary::scan_views(decoded, limits, &mut |view| {
        let go_on = if view.bytes.len() >= BATCH_BYTES {
            check(&mut batch, Some((view.source, view.bytes)))
        } else if batch.buf.len() + view.bytes.len() > BATCH_BYTES && !check(&mut batch, None) {
            false
        } else {
            batch.push(view.source, view.bytes);
            true
        };
        stopped = !go_on;
        go_on
    });
    if !stopped {
        check(&mut batch, None);
    }
    scanned.map_err(undecodable)?;
    if let Some(f) = failure {
        return Err(f);
    }
    if let Some(Hit {
        source,
        refs,
        detectors,
    }) = found
    {
        let mut detail = format!("{name}, in its {source}");
        if !detectors.is_empty() {
            detail.push_str("; detectors: ");
            detail.push_str(&detectors.join(", "));
        }
        return Err(Refusal {
            reason: RefusalReason::SecretInBinary,
            detail,
            refs,
        });
    }
    Ok(())
}

/// Scans a file uploaded to a provider's Files API under the binary policy `scan`. A text
/// document is left to the redaction of the whole body (it is redacted in place there); anything
/// else is scanned like a binary part and refuses the upload on a match. Returns whether the
/// content was scanned, so its file ID may be referenced later.
pub(crate) fn scan_upload(
    snap: &Snapshot,
    media_type: &str,
    bytes: &[u8],
) -> Result<bool, Refusal> {
    if snap.binary != BinaryPolicy::Scan {
        return Ok(false);
    }
    if is_text_document(media_type, bytes) {
        return Ok(true);
    }
    let limits = binary::Limits::default();
    if bytes.len() > limits.max_decoded {
        return Err(Refusal::new(
            RefusalReason::UnscannableContent,
            format!("uploaded file ({media_type}): too large to scan"),
        ));
    }
    let name = format!("uploaded file ({media_type})");
    scan_decoded(snap, &name, bytes, &limits, &mut Vec::new())?;
    Ok(true)
}

/// Views smaller than this are scanned together, in batches of up to this many bytes: the
/// redactor and the guard have a fixed cost per call, and a PDF yields hundreds of small views.
const BATCH_BYTES: usize = 1 << 20;

/// Separates views in a batch. No value contains a NUL byte, so no value spans two views.
const VIEW_SEPARATOR: &[u8] = b"\0\n\0";

/// What the redactor or the guard found in a view: the references and the detectors.
type Found = (Vec<SecretRef>, Vec<String>);

/// A match in one view of a binary part.
struct Hit {
    source: &'static str,
    refs: Vec<SecretRef>,
    detectors: Vec<String>,
}

/// Small views waiting to be scanned together.
#[derive(Default)]
struct Batch {
    buf: Vec<u8>,
    views: Vec<(usize, usize, &'static str)>,
}

impl Batch {
    fn push(&mut self, source: &'static str, bytes: &[u8]) {
        let start = self.buf.len();
        self.buf.extend_from_slice(bytes);
        self.views.push((start, self.buf.len(), source));
        self.buf.extend_from_slice(VIEW_SEPARATOR);
    }

    /// Scans the batch and empties it. On a match, scans its views one by one to name the view
    /// that holds the value.
    fn flush(&mut self, snap: &Snapshot, scratch: &mut Vec<u8>) -> Result<Option<Hit>, Refusal> {
        if self.views.is_empty() {
            return Ok(None);
        }
        let hit = check_view(snap, &self.buf, scratch)?.map(|(refs, detectors)| {
            let mut hit = Hit {
                source: "extracted text",
                refs,
                detectors,
            };
            for &(start, end, source) in &self.views {
                if let Ok(Some((refs, detectors))) =
                    check_view(snap, self.buf.get(start..end).unwrap_or_default(), scratch)
                {
                    hit = Hit {
                        source,
                        refs,
                        detectors,
                    };
                    break;
                }
            }
            hit
        });
        self.buf.clear();
        self.views.clear();
        Ok(hit)
    }
}

/// Runs the redactor, then the guard, over one view; returns the references (and detectors) of
/// what either found.
pub(crate) fn check_view(
    snap: &Snapshot,
    bytes: &[u8],
    scratch: &mut Vec<u8>,
) -> Result<Option<Found>, Refusal> {
    scratch.clear();
    let r = snap
        .redactor
        .redact(bytes, scratch)
        .map_err(|e| Refusal::new(RefusalReason::RedactorFailed, e.message().to_string()))?;
    if r.replacements > 0 {
        return Ok(Some((r.refs, r.detectors)));
    }
    match snap
        .guard
        .check(bytes)
        .map_err(|e| Refusal::new(RefusalReason::GuardFailed, e.message().to_string()))?
    {
        GuardVerdict::Clean => Ok(None),
        GuardVerdict::Repaired { refs, .. } | GuardVerdict::Refused { refs } => {
            Ok(Some((refs, Vec::new())))
        }
    }
}

/// What redacting the text documents of a request did.
#[derive(Default)]
struct TextParts {
    /// `(start, end, new JSON string content)` for each part that changed.
    edits: Vec<(usize, usize, Vec<u8>)>,
    report: RedactReport,
    guard_repaired: Vec<SecretRef>,
}

/// A part declared as text that decodes to UTF-8 without NUL bytes is a text document (a `.env`
/// or log the agent attached as a file): it is redacted like any other text and encoded again,
/// instead of refused. Anything else, including a part declared as text whose bytes are not
/// text, is scanned as binary.
fn is_text_document(media_type: &str, decoded: &[u8]) -> bool {
    let declared = media_type.starts_with("text/")
        || matches!(
            media_type,
            "application/json"
                | "application/xml"
                | "application/yaml"
                | "application/x-yaml"
                | "application/toml"
                // Bedrock Converse names documents by format.
                | "application/txt"
                | "application/csv"
                | "application/md"
                | "application/html"
        );
    declared && !decoded.contains(&0) && std::str::from_utf8(decoded).is_ok()
}

/// Redacts one text document part and checks the result with the guard; when anything changed,
/// records the part's new JSON string content: its `data:` URL prefix, if any, and the redacted
/// text in standard base64.
fn redact_text_part(
    snap: &Snapshot,
    span: (usize, usize),
    original: &str,
    decoded: &[u8],
    acc: &mut TextParts,
) -> Result<(), Refusal> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    let mut redacted = Vec::with_capacity(decoded.len() + decoded.len() / 16 + 64);
    let r = snap
        .redactor
        .redact(decoded, &mut redacted)
        .map_err(|e| Refusal::new(RefusalReason::RedactorFailed, e.message().to_string()))?;
    let changed = r.replacements > 0;
    acc.report.merge(r);
    let redacted = match snap
        .guard
        .check(&redacted)
        .map_err(|e| Refusal::new(RefusalReason::GuardFailed, e.message().to_string()))?
    {
        GuardVerdict::Clean if !changed => return Ok(()),
        GuardVerdict::Clean => redacted,
        GuardVerdict::Repaired { bytes, refs } => {
            for r in refs {
                if !acc.guard_repaired.contains(&r) {
                    acc.guard_repaired.push(r);
                }
            }
            bytes
        }
        GuardVerdict::Refused { refs } => {
            return Err(Refusal {
                reason: RefusalReason::GuardRefused,
                detail: String::new(),
                refs,
            });
        }
    };
    let mut prefix = String::new();
    if let Some(rest) = original.strip_prefix("data:")
        && let Some((meta, _)) = rest.split_once(',')
    {
        prefix.push_str("data:");
        prefix.push_str(meta);
        if !meta.ends_with(";base64") {
            prefix.push_str(";base64");
        }
        prefix.push(',');
    }
    let mut content = Vec::with_capacity(prefix.len() + redacted.len() * 4 / 3 + 4);
    crate::json::escape_into(&mut content, &prefix);
    content.extend_from_slice(B64.encode(&redacted).as_bytes());
    acc.edits.push((span.0, span.1, content));
    Ok(())
}

/// [`prepare_timed`] for a Bedrock `count-tokens` body,
/// `{"input":{"invokeModel":{"body":"<base64 Anthropic Messages body>"}}}`: the inner body is
/// decoded, redacted and guarded as Anthropic Messages and encoded again, then the whole body is
/// redacted and guarded as generic JSON (which also covers the `converse` form). Base64 the
/// redactor could not see through would otherwise carry values past it.
pub fn prepare_bedrock_count_tokens(
    snap: &Snapshot,
    body: &[u8],
    timed: bool,
) -> Result<Outgoing, Refusal> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    fn get<'d, 'a>(
        v: Option<crate::json::Value<'d, 'a>>,
        k: &str,
    ) -> Result<Option<crate::json::Value<'d, 'a>>, Refusal> {
        match v {
            Some(v) if v.kind() == crate::json::Kind::Object => v
                .get(k)
                .map_err(|e| Refusal::new(RefusalReason::MalformedBody, e.to_string())),
            _ => Ok(None),
        }
    }
    let malformed = |d: &str| Refusal::new(RefusalReason::MalformedBody, d.to_owned());
    let doc = crate::json::Doc::parse(body).map_err(|e| malformed(&e.to_string()))?;
    let inner = get(get(get(Some(doc.root()), "input")?, "invokeModel")?, "body")?;
    let Some(inner) = inner else {
        return prepare_timed(snap, Api::Generic, body, timed);
    };
    let encoded = inner
        .as_str()
        .ok_or_else(|| malformed("input.invokeModel.body is not a string"))?;
    let decoded = B64
        .decode(encoded.as_bytes())
        .map_err(|_| malformed("input.invokeModel.body is not base64"))?;
    let i = prepare_timed(snap, Api::AnthropicMessages, &decoded, timed)?;
    let spliced = crate::json::splice(
        body,
        &[(
            inner.span().0,
            inner.span().1,
            crate::json::quote(&B64.encode(&i.body)),
        )],
    );
    let mut o = prepare_timed(snap, Api::Generic, &spliced, timed)?;
    o.report.merge(i.report);
    for r in i.guard_repaired {
        if !o.guard_repaired.contains(&r) {
            o.guard_repaired.push(r);
        }
    }
    o.unscanned = i.unscanned;
    o.stages.redaction += i.stages.redaction;
    o.stages.guard += i.stages.guard;
    Ok(o)
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::*;
    use crate::testing::{Fault, Fixture, GuardMode};

    fn anthropic_body(fx: &Fixture) -> String {
        let v = fx.value("a");
        format!(
            r#"{{"model":"claude-x","messages":[{{"role":"user","content":"read {v}"}}],"odd_field":"{v}","stream":true}}"#
        )
    }

    #[test]
    fn redacts_content_and_unknown_fields_but_not_config() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let body = anthropic_body(&fx);
        let o = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap();
        let s = std::str::from_utf8(&o.body).unwrap();
        assert!(fx.leaks(&o.body).is_empty(), "{s}");
        assert_eq!(s.matches(&fx.placeholder("a")).count(), 2);
        assert!(s.starts_with(r#"{"model":"claude-x","#));
        assert!(s.ends_with(r#""stream":true}"#));
        assert_eq!(o.report.replacements, 2);
    }

    #[test]
    fn deterministic_for_cache_prefix() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let snap = fx.snapshot();
        let body = anthropic_body(&fx);
        let a = prepare(&snap, Api::AnthropicMessages, body.as_bytes()).unwrap();
        let b = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap();
        assert_eq!(a.body, b.body);
    }

    #[test]
    fn errors_fail_closed() {
        let mut fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let body = anthropic_body(&fx);
        fx.redactor_fault = Fault::Error;
        let e = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap_err();
        assert_eq!(e.reason, RefusalReason::RedactorFailed);
        fx.redactor_fault = Fault::None;
        fx.guard_fault = Fault::Error;
        let e = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap_err();
        assert_eq!(e.reason, RefusalReason::GuardFailed);
        let e = prepare(&fx.snapshot(), Api::AnthropicMessages, b"{not json").unwrap_err();
        assert_eq!(e.reason, RefusalReason::MalformedBody);
    }

    #[test]
    fn guard_catches_redactor_miss_and_value_in_verbatim_span() {
        let mut fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        fx.redactor_misses = vec!["a".into()];
        let body = anthropic_body(&fx);
        let o = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap();
        assert_eq!(fx.leaks(&o.body), [] as [std::string::String; 0]);
        assert_eq!(o.guard_repaired, vec![SecretRef::new("a")]);

        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let v = fx.value("a");
        let body = format!(r#"{{"model":"{v}","messages":[]}}"#);
        let o = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap();
        assert_eq!(o.report.replacements, 0, "allowlisted span is not redacted");
        assert_eq!(
            o.guard_repaired,
            vec![SecretRef::new("a")],
            "but the guard still checks it"
        );
        assert_eq!(fx.leaks(&o.body), [] as [std::string::String; 0]);

        let mut fx = fx;
        fx.guard_mode = GuardMode::Refuse;
        let e = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap_err();
        assert_eq!(e.reason, RefusalReason::GuardRefused);
        assert_eq!(e.refs, vec![SecretRef::new("a")]);
    }

    #[test]
    fn bedrock_count_tokens_redacts_inside_base64() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let inner = anthropic_body(&fx);
        let body = format!(
            r#"{{"input":{{"invokeModel":{{"body":"{}"}}}}}}"#,
            B64.encode(inner.as_bytes())
        );
        let o = prepare_bedrock_count_tokens(&fx.snapshot(), body.as_bytes(), false).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&o.body).unwrap();
        let sent = B64
            .decode(v["input"]["invokeModel"]["body"].as_str().unwrap())
            .unwrap();
        assert_eq!(fx.leaks(&sent), [] as [String; 0]);
        assert_eq!(
            std::str::from_utf8(&sent)
                .unwrap()
                .matches(&fx.placeholder("a"))
                .count(),
            2
        );
        assert_eq!(o.report.replacements, 2);
        // The converse form is plain JSON.
        let body = format!(
            r#"{{"input":{{"converse":{{"messages":[{{"role":"user","content":[{{"text":"{}"}}]}}]}}}}}}"#,
            fx.value("a")
        );
        let o = prepare_bedrock_count_tokens(&fx.snapshot(), body.as_bytes(), false).unwrap();
        assert_eq!(fx.leaks(&o.body), [] as [String; 0]);
        let e = prepare_bedrock_count_tokens(
            &fx.snapshot(),
            br#"{"input":{"invokeModel":{"body":"%%%"}}}"#,
            false,
        )
        .unwrap_err();
        assert_eq!(e.reason, RefusalReason::MalformedBody);
    }

    #[test]
    fn binary_policy() {
        let mut fx = Fixture::new(&[]);
        fx.binary = BinaryPolicy::Pass;
        let body = r#"{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]}]}"#;
        let o = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap();
        assert_eq!(o.unscanned, vec!["image/png"]);
        assert_eq!(&o.body[..], body.as_bytes());
        fx.binary = BinaryPolicy::Block;
        let e = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap_err();
        assert_eq!(e.reason, RefusalReason::UnscannableContent);
        assert!(e.detail.contains("image/png"));
    }

    fn png_chunk(out: &mut Vec<u8>, typ: [u8; 4], data: &[u8]) {
        out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&typ);
        out.extend_from_slice(data);
        let mut h = crc32fast::Hasher::new();
        h.update(&typ);
        h.update(data);
        out.extend_from_slice(&h.finalize().to_be_bytes());
    }

    /// A 1x1 greyscale PNG with a tEXt chunk holding `text`.
    fn png_with_text(text: &[u8]) -> Vec<u8> {
        let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
        png_chunk(&mut p, *b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]);
        let mut t = b"Comment\0".to_vec();
        t.extend_from_slice(text);
        png_chunk(&mut p, *b"tEXt", &t);
        png_chunk(
            &mut p,
            *b"IDAT",
            &[0x78, 0x9c, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01],
        );
        png_chunk(&mut p, *b"IEND", &[]);
        p
    }

    fn image_body(data: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        format!(
            r#"{{"model":"claude-x","messages":[{{"role":"user","content":[{{"type":"text","text":"look"}},{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{b64}"}}}}]}}]}}"#
        )
    }

    #[test]
    fn scan_is_the_default_and_forwards_a_clean_image_unchanged() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        assert_eq!(fx.binary, BinaryPolicy::Scan);
        let body = image_body(&png_with_text(b"nothing to see"));
        let o = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap();
        assert_eq!(&o.body[..], body.as_bytes());
        assert!(o.unscanned.is_empty(), "scanned parts are not unscanned");
    }

    #[test]
    fn scan_refuses_a_secret_in_image_metadata_naming_part_and_reference() {
        let mut fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let body = image_body(&png_with_text(format!("key={}", fx.value("a")).as_bytes()));
        for misses in [vec![], vec!["a".to_string()]] {
            // The redactor finds it, or it misses and the guard does.
            fx.redactor_misses = misses;
            let e = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap_err();
            assert_eq!(e.reason, RefusalReason::SecretInBinary);
            assert_eq!(e.refs, vec![SecretRef::new("a")]);
            assert!(
                e.detail.starts_with("binary part 1 (image/png)"),
                "{}",
                e.detail
            );
            let msg = format!("{e:?}");
            assert!(!msg.contains(&fx.value("a")), "{msg}");
        }
        // The pass policy forwards it unscanned, as before.
        fx.binary = BinaryPolicy::Pass;
        let o = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap();
        assert_eq!(o.unscanned, vec!["image/png"]);
    }

    #[test]
    fn scan_batches_small_views_and_names_the_one_that_matched() {
        use std::io::Write as _;
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let ztxt = |text: &[u8]| {
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
            z.write_all(text).unwrap();
            [b"Comment\0\0".as_slice(), &z.finish().unwrap()].concat()
        };
        let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
        png_chunk(&mut p, *b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]);
        // Many small clean views first, then the value in a compressed chunk.
        for i in 0..200 {
            png_chunk(&mut p, *b"tEXt", format!("k{i}\0clean text {i}").as_bytes());
        }
        let padding = "lorem ipsum ".repeat(30);
        png_chunk(
            &mut p,
            *b"zTXt",
            &ztxt(format!("{padding}{}{padding}", fx.value("a")).as_bytes()),
        );
        png_chunk(&mut p, *b"IEND", &[]);
        let e = prepare(
            &fx.snapshot(),
            Api::AnthropicMessages,
            image_body(&p).as_bytes(),
        )
        .unwrap_err();
        assert_eq!(e.reason, RefusalReason::SecretInBinary);
        assert_eq!(e.refs, vec![SecretRef::new("a")]);
        assert_eq!(
            e.detail,
            "binary part 1 (image/png), in its png compressed text"
        );
    }

    #[test]
    fn scan_refuses_a_detector_hit_in_a_binary_part() {
        let mut fx = Fixture::new(&[]);
        fx.detector = Some("zq-detector-shaped-token".into());
        let body = image_body(&png_with_text(b"zq-detector-shaped-token"));
        let e = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap_err();
        assert_eq!(e.reason, RefusalReason::SecretInBinary);
        assert!(e.detail.contains("detectors:"), "{}", e.detail);
    }

    #[test]
    fn scan_refuses_what_it_cannot_decode() {
        let fx = Fixture::new(&[]);
        for data in ["%%% not base64 %%%", "iVBORw0KGgo="] {
            let body = format!(
                r#"{{"messages":[{{"role":"user","content":[{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{data}"}}}}]}}]}}"#
            );
            let e = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap_err();
            assert_eq!(e.reason, RefusalReason::UnscannableContent, "{data}");
            assert!(
                e.detail.starts_with("binary part 1 (image/png): "),
                "{}",
                e.detail
            );
        }
        let body = r#"{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":{"x":1}}}]}]}"#;
        let e = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap_err();
        assert_eq!(e.reason, RefusalReason::UnscannableContent);
    }

    #[test]
    fn scan_redacts_a_text_document_and_encodes_it_again() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let env = format!("TOKEN={}\n", fx.value("a"));
        let body = format!(
            r#"{{"model":"gpt-x","messages":[{{"role":"user","content":[{{"type":"file","file":{{"filename":".env","file_data":"data:text/plain;base64,{}"}}}}]}}]}}"#,
            B64.encode(env.as_bytes())
        );
        let o = prepare(&fx.snapshot(), Api::OpenAiChat, body.as_bytes()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&o.body).unwrap();
        let sent = v["messages"][0]["content"][0]["file"]["file_data"]
            .as_str()
            .unwrap();
        let b64 = sent.strip_prefix("data:text/plain;base64,").unwrap();
        let text = String::from_utf8(B64.decode(b64).unwrap()).unwrap();
        assert_eq!(text, format!("TOKEN={}\n", fx.placeholder("a")));
        assert_eq!(fx.leaks(&o.body), [] as [String; 0]);
        assert_eq!(o.report.replacements, 1);
        assert_eq!(o.report.refs, vec![SecretRef::new("a")]);
        // A part declared as text whose bytes are not text is scanned as binary.
        let body = format!(
            r#"{{"model":"gpt-x","messages":[{{"role":"user","content":[{{"type":"file","file":{{"filename":"a.txt","file_data":"data:text/plain;base64,{}"}}}}]}}]}}"#,
            B64.encode(png_with_text(fx.value("a").as_bytes()))
        );
        let e = prepare(&fx.snapshot(), Api::OpenAiChat, body.as_bytes()).unwrap_err();
        assert_eq!(e.reason, RefusalReason::SecretInBinary);
    }
}
