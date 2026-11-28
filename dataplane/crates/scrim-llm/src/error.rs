// SPDX-License-Identifier: AGPL-3.0-only

//! The documented errors the proxy answers with itself.
//!
//! | reason                 | status | when                                                   |
//! |------------------------|--------|--------------------------------------------------------|
//! | `not_ready`            | 503    | no snapshot (value dictionary) loaded yet              |
//! | `no_route`             | 404    | path matches no route                                  |
//! | `malformed_body`       | 422    | body cannot be parsed well enough to redact            |
//! | `redactor_failed`      | 422    | the redactor returned an error                         |
//! | `guard_failed`         | 422    | the guard returned an error                            |
//! | `guard_refused`        | 422    | the guard found a value it could not repair            |
//! | `unscannable_content`  | 422    | binary part under `block`, or undecodable under `scan` |
//! | `secret_in_binary`     | 422    | `scan` found a secret value inside a binary part       |
//! | `remote_attachment`    | 422    | an attachment reference the remote policy refuses      |
//! | `attachment_unavailable` | 502  | an attachment referenced by URL could not be fetched   |
//! | `unsupported_encoding` | 415    | compressed request body                                |
//! | `body_too_large`       | 413    | body over `proxy.limits.max-request-body`              |
//! | `capture_failed`       | 500    | capture mode could not record the outgoing request     |
//! | `chain_unavailable`    | 502    | chained upstream unreachable, `on-unavailable: fail`   |
//! | `upstream_unavailable` | 502    | provider unreachable                                   |
//! | `policy_denied`        | 403    | denied by a rule, or the approval was not granted      |
//! | `upgrade_unsupported`  | 501    | protocol upgrade other than WebSocket, or a WebSocket  |
//! |                        |        | handshake on a listener that cannot upgrade            |
//!
//! On an open WebSocket connection a refusal cannot be an HTTP response: the client gets one
//! text message, [`Refusal::ws_event`], and a close frame with [`Refusal::close_code`] and the
//! reason code as the close reason.
//!
//! 422 is the redaction-failed status: every redaction or guard failure uses it, and nothing is
//! forwarded. Every proxy-generated response carries `x-scrim-error: <reason>` so it is never
//! mistaken for a provider answer, and its body has the provider's error shape so agents
//! display the message. Messages never contain request content or secret values.

use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode};

use crate::audit::RefusalReason;
use crate::codec::Api;
use crate::engine::SecretRef;

/// Header naming the reason on every response scrim generates itself.
pub const ERROR_HEADER: &str = "x-scrim-error";

/// A refusal: the request is answered by scrim and nothing goes upstream.
#[derive(Debug, Clone)]
pub struct Refusal {
    /// Reason.
    pub reason: RefusalReason,
    /// Human-readable, value-free detail.
    pub detail: String,
    /// Secret references involved (guard refusals). Names only.
    pub refs: Vec<SecretRef>,
}

impl Refusal {
    /// A refusal with a detail message.
    pub fn new(reason: RefusalReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
            refs: Vec::new(),
        }
    }

    /// HTTP status for the reason.
    pub fn status(&self) -> StatusCode {
        match self.reason {
            RefusalReason::NotReady | RefusalReason::CredentialUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            RefusalReason::NoRoute => StatusCode::NOT_FOUND,
            RefusalReason::MalformedBody
            | RefusalReason::RedactorFailed
            | RefusalReason::GuardFailed
            | RefusalReason::GuardRefused
            | RefusalReason::UnscannableContent
            | RefusalReason::SecretInBinary
            | RefusalReason::RemoteAttachment => StatusCode::UNPROCESSABLE_ENTITY,
            RefusalReason::UnsupportedEncoding => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RefusalReason::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            RefusalReason::CaptureFailed => StatusCode::INTERNAL_SERVER_ERROR,
            RefusalReason::ChainUnavailable
            | RefusalReason::UpstreamUnavailable
            | RefusalReason::AttachmentUnavailable => StatusCode::BAD_GATEWAY,
            RefusalReason::PolicyDenied => StatusCode::FORBIDDEN,
            RefusalReason::UpgradeUnsupported => StatusCode::NOT_IMPLEMENTED,
        }
    }

    /// The `google.rpc.Code` name for the status, for Gemini-shaped errors.
    fn rpc_status(&self) -> &'static str {
        match self.status() {
            StatusCode::SERVICE_UNAVAILABLE | StatusCode::BAD_GATEWAY => "UNAVAILABLE",
            StatusCode::NOT_FOUND => "NOT_FOUND",
            StatusCode::FORBIDDEN => "PERMISSION_DENIED",
            StatusCode::NOT_IMPLEMENTED => "UNIMPLEMENTED",
            StatusCode::INTERNAL_SERVER_ERROR => "INTERNAL",
            _ => "INVALID_ARGUMENT",
        }
    }

    fn message(&self) -> String {
        let what = match self.reason {
            RefusalReason::NotReady => {
                "scrim: redaction is not ready (secret values not loaded yet)"
            }
            RefusalReason::NoRoute => "scrim: no provider route for this path",
            RefusalReason::MalformedBody => {
                "scrim: redaction failed, request body could not be parsed"
            }
            RefusalReason::RedactorFailed => "scrim: redaction failed",
            RefusalReason::GuardFailed => {
                "scrim: redaction failed, the leak guard could not check the request"
            }
            RefusalReason::GuardRefused => {
                "scrim: redaction failed, the request still contained a secret value"
            }
            RefusalReason::UnscannableContent => {
                "scrim: request refused, it contains content that cannot be scanned"
            }
            RefusalReason::SecretInBinary => {
                "scrim: request refused, an image, document or other attachment contains a secret \
                 value, and an attachment cannot be redacted without corrupting it; remove the \
                 secret from the attachment"
            }
            RefusalReason::RemoteAttachment => {
                "scrim: request refused, it references an attachment by URL or file ID that \
                 scrim cannot scan; send the content inline, or see redaction.remote-attachments"
            }
            RefusalReason::AttachmentUnavailable => {
                "scrim: an attachment referenced by URL could not be fetched to scan it"
            }
            RefusalReason::UnsupportedEncoding => {
                "scrim: compressed request bodies cannot be redacted"
            }
            RefusalReason::BodyTooLarge => "scrim: request body too large",
            RefusalReason::CaptureFailed => "scrim: capture mode could not record the request",
            RefusalReason::ChainUnavailable => "scrim: the chained upstream is unavailable",
            RefusalReason::UpstreamUnavailable => "scrim: the provider is unreachable",
            RefusalReason::PolicyDenied => "scrim: request denied by policy",
            RefusalReason::UpgradeUnsupported => {
                "scrim: this protocol upgrade cannot be redacted; only WebSocket is supported"
            }
            RefusalReason::CredentialUnavailable => {
                "scrim: the provider credentials for this route are unavailable"
            }
        };
        let mut m = what.to_string();
        if !self.detail.is_empty() {
            m.push_str(" (");
            m.push_str(&self.detail);
            m.push(')');
        }
        if !self.refs.is_empty() {
            m.push_str("; references: ");
            m.push_str(
                &self
                    .refs
                    .iter()
                    .map(SecretRef::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        m
    }

    /// The WebSocket close code for a refusal on an open connection (RFC 6455 section 7.4):
    /// 1009 for a message over the limit, 1013 (try again later) when values or credentials are
    /// not loaded, 1014 (bad gateway) when the provider failed, 1011 when capture failed, and
    /// 1008 (policy violation) for everything else, every redaction and guard failure included.
    pub fn close_code(&self) -> u16 {
        match self.reason {
            RefusalReason::BodyTooLarge => 1009,
            RefusalReason::NotReady | RefusalReason::CredentialUnavailable => 1013,
            RefusalReason::UpstreamUnavailable | RefusalReason::ChainUnavailable => 1014,
            RefusalReason::CaptureFailed => 1011,
            _ => 1008,
        }
    }

    /// The error event sent on an open WebSocket connection before it is closed, in the shape of
    /// an `OpenAI` Realtime and Responses `error` event:
    /// `{"type":"error","error":{"type":"scrim_error","code":...,"message":...}}`. It carries
    /// nothing from the refused message, not even its `event_id`.
    pub fn ws_event(&self) -> String {
        serde_json::json!({
            "type": "error",
            "error": {
                "type": "scrim_error",
                "code": self.reason.code(),
                "message": self.message(),
                "param": null,
            }
        })
        .to_string()
    }

    /// Renders the refusal in the error shape of `api`.
    pub fn to_response(&self, api: Api) -> Response<Bytes> {
        let message = self.message();
        let code = self.reason.code();
        let body = match api {
            Api::OpenAiChat | Api::OpenAiResponses => serde_json::json!({
                "error": { "message": message, "type": "scrim_error", "code": code, "param": null }
            }),
            // google.rpc.Status, as the Gemini API and Vertex AI answer errors.
            Api::Gemini => serde_json::json!({
                "error": {
                    "code": self.status().as_u16(),
                    "message": message,
                    "status": self.rpc_status(),
                    "details": [{
                        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                        "reason": code,
                        "domain": "scrim",
                    }],
                }
            }),
            // Bedrock's own error shape, `{"message": ...}`, with the code alongside.
            Api::BedrockConverse => serde_json::json!({ "message": message, "code": code }),
            Api::AnthropicMessages | Api::Generic => serde_json::json!({
                "type": "error",
                "error": { "type": "scrim_error", "code": code, "message": message }
            }),
        };
        let mut resp = Response::new(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()));
        *resp.status_mut() = self.status();
        let h = resp.headers_mut();
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        h.insert(ERROR_HEADER, HeaderValue::from_static(code));
        if self.reason == RefusalReason::NotReady {
            h.insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_and_statuses() {
        let r = Refusal {
            reason: RefusalReason::GuardRefused,
            detail: String::new(),
            refs: vec![SecretRef::new("db/pw")],
        };
        let a = r.to_response(Api::AnthropicMessages);
        assert_eq!(a.status(), 422);
        assert_eq!(a.headers()[ERROR_HEADER], "guard_refused");
        let v: serde_json::Value = serde_json::from_slice(a.body()).unwrap();
        assert_eq!(v["type"], "error");
        assert_eq!(v["error"]["code"], "guard_refused");
        assert!(v["error"]["message"].as_str().unwrap().contains("db/pw"));
        let o = r.to_response(Api::OpenAiResponses);
        let v: serde_json::Value = serde_json::from_slice(o.body()).unwrap();
        assert_eq!(v["error"]["code"], "guard_refused");
        let gemini = r.to_response(Api::Gemini);
        let v: serde_json::Value = serde_json::from_slice(gemini.body()).unwrap();
        assert_eq!(v["error"]["code"], 422);
        assert_eq!(v["error"]["status"], "INVALID_ARGUMENT");
        assert_eq!(v["error"]["details"][0]["reason"], "guard_refused");
        assert!(v["error"]["message"].as_str().unwrap().contains("db/pw"));
        let ev: serde_json::Value = serde_json::from_str(&r.ws_event()).unwrap();
        assert_eq!(ev["type"], "error");
        assert_eq!(ev["error"]["code"], "guard_refused");
        assert!(ev["error"]["message"].as_str().unwrap().contains("db/pw"));
        assert_eq!(r.close_code(), 1008);
        assert_eq!(
            Refusal::new(RefusalReason::BodyTooLarge, "").close_code(),
            1009
        );
        let nr = Refusal::new(RefusalReason::NotReady, "").to_response(Api::Generic);
        assert_eq!(nr.status(), 503);
        assert_eq!(nr.headers()[http::header::RETRY_AFTER], "1");
    }
}
