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
use crate::codec::{self, Api};
use crate::engine::{BinaryPolicy, GuardVerdict, RedactReport, SecretRef, Snapshot};
use crate::error::Refusal;

/// A request body that passed redaction and the guard.
#[derive(Debug)]
pub struct Outgoing {
    /// Bytes to forward.
    pub body: Bytes,
    /// What the redactor did.
    pub report: RedactReport,
    /// References the guard repaired.
    pub guard_repaired: Vec<SecretRef>,
    /// Media types of unscannable parts forwarded under the `pass` policy.
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
    let clock = || timed.then(Instant::now);
    let since = |t: Option<Instant>| t.map_or(Duration::ZERO, |t| t.elapsed());
    let started = clock();
    let plan = codec::plan(api, body)
        .map_err(|e| Refusal::new(RefusalReason::MalformedBody, e.to_string()))?;
    if !plan.binary.is_empty() && snap.binary == BinaryPolicy::Block {
        let mut types = plan.binary.clone();
        types.sort();
        types.dedup();
        return Err(Refusal::new(
            RefusalReason::UnscannableContent,
            format!("content types: {}", types.join(", ")),
        ));
    }
    let mut out = Vec::with_capacity(body.len() + body.len() / 16 + 64);
    let mut report = RedactReport::default();
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
    let (out, guard_repaired) = match verdict {
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
    Ok(Outgoing {
        body: Bytes::from(out),
        report,
        guard_repaired,
        unscanned: plan.binary,
        stages: Stages { redaction, guard },
    })
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
        let body = r#"{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]}]}"#;
        let o = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap();
        assert_eq!(o.unscanned, vec!["image/png"]);
        assert_eq!(&o.body[..], body.as_bytes());
        fx.binary = BinaryPolicy::Block;
        let e = prepare(&fx.snapshot(), Api::AnthropicMessages, body.as_bytes()).unwrap_err();
        assert_eq!(e.reason, RefusalReason::UnscannableContent);
        assert!(e.detail.contains("image/png"));
    }
}
