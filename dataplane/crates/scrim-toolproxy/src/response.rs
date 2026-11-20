//! Response rewriting: capture rules, then redaction of headers and body.
//!
//! Small bodies (a known length within the buffering limit), bodies with digests and bodies a
//! capture rule applies to are buffered, decoded, rewritten and re-encoded with a correct length.
//! Everything else streams through decoder, redactor and encoder chunk by chunk. A body scrim
//! cannot decode is withheld; a stream that fails midway is cut off, never finished unredacted.

use std::sync::Arc;

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Response, StatusCode};
use http_body::Body;
use http_body_util::BodyExt;

use crate::audit::AuditEvent;
use crate::body::{
    BoxError, Collected, OnEnd, Pipeline, Prefixed, ProxyBody, Stage, TransformBody,
    collect_limited, empty, full, redact_headers,
};
use crate::capture::{CaptureRequest, CaptureRule, CaptureSource, WITHHELD_MARKER};
use crate::codec::{Codings, Decoder, Encoder, decode_all, encode_all, parse_codings};
use crate::digest;
use crate::engine::Engine;
use crate::error::{ErrorCode, Refusal};
use crate::proxy::Shared;
use crate::redactor::{Redactor, RedactorChain};
use crate::request::{RequestMeta, strip_hop_by_hop};
use crate::secret::SecretValue;

fn withheld(shared: &Shared, meta: &RequestMeta, code: ErrorCode, message: String) -> Refusal {
    shared.audit.record(AuditEvent::ResponseWithheld {
        code,
        destination: meta.dest.to_string(),
        message: message.clone(),
    });
    Refusal::new(code, message)
}

enum CaptureOutcome {
    Stored(String),
    Failed,
}

impl Engine {
    fn chain_for(&self, meta: &RequestMeta) -> RedactorChain {
        let mut stages: Vec<Arc<dyn Redactor>> = Vec::with_capacity(3);
        if let Some(e) = &meta.echo {
            stages.push(e.clone());
        }
        stages.extend(self.redactors.0.iter().cloned());
        RedactorChain(stages)
    }

    async fn capture_value(
        &self,
        shared: &Shared,
        meta: &RequestMeta,
        rule: &CaptureRule,
        value: SecretValue,
    ) -> CaptureOutcome {
        let req = CaptureRequest {
            rule: rule.name.clone(),
            reference: rule.store.clone(),
            destination: meta.dest.to_string(),
            value: value.clone(),
        };
        match shared.capture_sink.store(req).await {
            Ok(placeholder) => {
                shared.captured.add(value, &placeholder);
                shared.audit.record(AuditEvent::ValueCaptured {
                    rule: rule.name.clone(),
                    reference: rule.store.clone(),
                    destination: meta.dest.to_string(),
                });
                CaptureOutcome::Stored(placeholder)
            }
            Err(e) => {
                shared.audit.record(AuditEvent::CaptureFailed {
                    rule: rule.name.clone(),
                    reference: rule.store.clone(),
                    destination: meta.dest.to_string(),
                    message: e.0,
                });
                CaptureOutcome::Failed
            }
        }
    }

    /// Rewrites an upstream response for the agent.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn rewrite_response<B>(
        &self,
        shared: &Shared,
        meta: &RequestMeta,
        resp: Response<B>,
    ) -> Result<Response<ProxyBody>, Refusal>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError>,
    {
        let (mut parts, body) = resp.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        let status = parts.status.as_u16();
        let rules: Vec<&CaptureRule> = meta
            .capture
            .iter()
            .filter(|r| r.matches_status(status))
            .collect();

        // Header capture comes before header redaction, so the rule sees the value it names.
        for rule in rules
            .iter()
            .filter(|r| matches!(r.source, CaptureSource::Header(_)))
        {
            let CaptureSource::Header(name) = &rule.source else {
                continue;
            };
            let Some(v) = parts
                .headers
                .get(name)
                .map(|v| SecretValue::new(v.as_bytes().to_vec()))
            else {
                continue;
            };
            let text = match self.capture_value(shared, meta, rule, v).await {
                CaptureOutcome::Stored(p) => p,
                CaptureOutcome::Failed => WITHHELD_MARKER.to_owned(),
            };
            let hv = HeaderValue::from_str(&text).map_err(|_| {
                withheld(
                    shared,
                    meta,
                    ErrorCode::ResponseWithheld,
                    "capture placeholder is not a valid header value".into(),
                )
            })?;
            parts.headers.insert(name.clone(), hv);
        }

        let chain = self.chain_for(meta);
        let header_replacements = redact_headers(&chain, &mut parts.headers)
            .map_err(|e| withheld(shared, meta, ErrorCode::RedactionFailed, e))?;

        let no_body = meta.method == Method::HEAD
            || parts.status.is_informational()
            || parts.status == StatusCode::NO_CONTENT
            || parts.status == StatusCode::NOT_MODIFIED;
        if no_body {
            self.report(shared, meta, header_replacements);
            return Ok(Response::from_parts(parts, empty()));
        }

        let codings = match parse_codings(&parts.headers) {
            Ok(c) => c,
            Err(tok) => {
                return Err(withheld(
                    shared,
                    meta,
                    ErrorCode::ResponseWithheld,
                    format!("response uses content coding `{tok}`, which scrim cannot scan"),
                ));
            }
        };
        let body_rules: Vec<&CaptureRule> = rules
            .into_iter()
            .filter(|r| matches!(r.source, CaptureSource::JsonPointer(_)))
            .collect();
        let length: Option<u64> = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let event_stream = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().starts_with("text/event-stream"));
        let must_buffer = !body_rules.is_empty() || digest::has_digest(&parts.headers);
        let limit = shared.settings.max_buffered_body;
        let small = length.is_some_and(|l| l <= limit as u64) && !event_stream;

        if must_buffer || small {
            match collect_limited(body, limit).await {
                Err(e) => {
                    return Err(withheld(
                        shared,
                        meta,
                        ErrorCode::UpstreamUnavailable,
                        format!("reading the upstream response failed: {e}"),
                    ));
                }
                Ok(Collected::Complete(bytes, _trailers)) => {
                    return self
                        .rewrite_buffered(
                            shared,
                            meta,
                            parts,
                            bytes,
                            &codings,
                            &body_rules,
                            header_replacements,
                        )
                        .await;
                }
                Ok(Collected::Overflow(prefix, remainder)) => {
                    if must_buffer {
                        return Err(withheld(
                            shared,
                            meta,
                            ErrorCode::ResponseWithheld,
                            format!(
                                "response exceeds {limit} bytes and needs buffering for capture or digest checks"
                            ),
                        ));
                    }
                    return self.rewrite_streamed(
                        shared,
                        meta,
                        parts,
                        Prefixed::new(prefix, remainder),
                        &codings,
                        chain,
                        header_replacements,
                    );
                }
            }
        }
        self.rewrite_streamed(
            shared,
            meta,
            parts,
            body,
            &codings,
            chain,
            header_replacements,
        )
    }

    #[allow(clippy::unused_self)]
    fn report(&self, shared: &Shared, meta: &RequestMeta, replacements: u64) {
        if replacements > 0 {
            shared.audit.record(AuditEvent::ResponseRedacted {
                destination: meta.dest.to_string(),
                replacements,
            });
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn rewrite_buffered(
        &self,
        shared: &Shared,
        meta: &RequestMeta,
        mut parts: http::response::Parts,
        bytes: Bytes,
        codings: &Codings,
        body_rules: &[&CaptureRule],
        header_replacements: u64,
    ) -> Result<Response<ProxyBody>, Refusal> {
        let decoded = if codings.0.is_empty() {
            bytes.to_vec()
        } else {
            decode_all(&bytes, codings, shared.settings.max_decoded_body).map_err(|e| {
                withheld(
                    shared,
                    meta,
                    ErrorCode::ResponseWithheld,
                    format!("response body could not be decoded: {e}"),
                )
            })?
        };
        let mut doc = decoded;
        let mut changed = false;
        if !body_rules.is_empty() && !doc.is_empty() {
            let mut json: serde_json::Value = serde_json::from_slice(&doc).map_err(|_| {
                withheld(
                    shared,
                    meta,
                    ErrorCode::ResponseWithheld,
                    "a capture rule applies but the response body is not JSON".into(),
                )
            })?;
            let mut any = false;
            for rule in body_rules {
                let CaptureSource::JsonPointer(ptr) = &rule.source else {
                    continue;
                };
                let Some(field) = json.pointer_mut(ptr) else {
                    continue;
                };
                any = true;
                let replacement = match field {
                    serde_json::Value::String(s) => {
                        let v = SecretValue::new(std::mem::take(s).into_bytes());
                        match self.capture_value(shared, meta, rule, v).await {
                            CaptureOutcome::Stored(p) => p,
                            CaptureOutcome::Failed => WITHHELD_MARKER.to_owned(),
                        }
                    }
                    serde_json::Value::Null => continue,
                    _ => {
                        shared.audit.record(AuditEvent::CaptureFailed {
                            rule: rule.name.clone(),
                            reference: rule.store.clone(),
                            destination: meta.dest.to_string(),
                            message: "captured field is not a string".into(),
                        });
                        WITHHELD_MARKER.to_owned()
                    }
                };
                *field = serde_json::Value::String(replacement);
            }
            if any {
                doc = serde_json::to_vec(&json).map_err(|_| {
                    withheld(
                        shared,
                        meta,
                        ErrorCode::ResponseWithheld,
                        "re-serialising the captured response failed".into(),
                    )
                })?;
                changed = true;
            }
        }
        let chain = self.chain_for(meta);
        let mut replacements = header_replacements;
        match chain.redact_all(&doc) {
            Err(e) => {
                return Err(withheld(
                    shared,
                    meta,
                    ErrorCode::RedactionFailed,
                    e.to_string(),
                ));
            }
            Ok(Some((out, n))) => {
                doc = out;
                replacements += n as u64;
                changed = true;
            }
            Ok(None) => {}
        }
        self.report(shared, meta, replacements);
        if !changed {
            return Ok(Response::from_parts(parts, full(bytes)));
        }
        let encoded = encode_all(&doc, codings).map_err(|e| {
            withheld(
                shared,
                meta,
                ErrorCode::ResponseWithheld,
                format!("re-encoding the response failed: {e}"),
            )
        })?;
        let _ = digest::recompute(&mut parts.headers, &encoded, true);
        parts
            .headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(encoded.len()));
        Ok(Response::from_parts(parts, full(encoded)))
    }

    #[allow(clippy::too_many_arguments, clippy::unused_self)]
    fn rewrite_streamed<B>(
        &self,
        shared: &Shared,
        meta: &RequestMeta,
        mut parts: http::response::Parts,
        body: B,
        codings: &Codings,
        chain: RedactorChain,
        header_replacements: u64,
    ) -> Result<Response<ProxyBody>, Refusal>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError>,
    {
        parts.headers.remove(header::CONTENT_LENGTH);
        digest::strip(&mut parts.headers);
        let mut stages = Vec::new();
        let err = |e: std::io::Error| {
            withheld(
                shared,
                meta,
                ErrorCode::ResponseWithheld,
                format!("setting up the decoder failed: {e}"),
            )
        };
        for c in codings.0.iter().rev() {
            stages.push(Stage::Codec(Box::new(
                Decoder::new(*c, u64::MAX).map_err(err)?,
            )));
        }
        for r in chain.stream() {
            stages.push(Stage::Redact(r));
        }
        for c in &codings.0 {
            stages.push(Stage::Codec(Box::new(Encoder::new(*c, true).map_err(err)?)));
        }
        let audit = shared.audit.clone();
        let destination = meta.dest.to_string();
        let on_end: OnEnd = Box::new(move |r| match r {
            Ok(n) => {
                let replacements = n + header_replacements;
                if replacements > 0 {
                    audit.record(AuditEvent::ResponseRedacted {
                        destination,
                        replacements,
                    });
                }
            }
            Err(message) => audit.record(AuditEvent::ResponseWithheld {
                code: ErrorCode::ResponseWithheld,
                destination,
                message,
            }),
        });
        let body = TransformBody::new(body, Pipeline::new(stages), Some(chain), on_end);
        Ok(Response::from_parts(parts, body.boxed_unsync()))
    }
}
