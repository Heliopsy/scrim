//! Documented errors returned to the agent.
//!
//! Every refusal the tool proxy produces has a stable [`ErrorCode`]. The agent receives it as an
//! HTTP response with the status below, an `x-scrim-error: <code>` header and a JSON body:
//!
//! ```json
//! {"error": {"type": "scrim_tool_proxy_error", "code": "unbound_destination",
//!            "message": "credential `acme` is not bound to https://evil.test:443"}}
//! ```
//!
//! Messages name credentials by their alias, destinations, methods and encodings. They never
//! contain a secret value.

use std::fmt;

use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode};

/// Stable error codes, part of the public contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// No credential snapshot has been applied yet, so nothing can be injected or redacted. 503.
    NotReady,
    /// A placeholder belongs to a credential that has no destination binding. 403.
    UnboundCredential,
    /// A placeholder was sent toward a host, port, scheme, method or path its credential is not
    /// bound to. Nothing was sent upstream. 403.
    UnboundDestination,
    /// A placeholder appeared in a request location (header, cookie, query, path, body) its
    /// credential does not declare. 403.
    UndeclaredLocation,
    /// The credential's value is not available (store outage or not loaded). 503.
    CredentialUnavailable,
    /// The real value cannot be written into the location the placeholder occupies without
    /// changing the request's structure (for example a line break in a header). 422.
    UnrepresentableValue,
    /// A request body to a host with bound credentials uses a content coding scrim cannot
    /// rewrite. The message names the coding. 415.
    UnsupportedEncoding,
    /// A request body could not be decoded or parsed for substitution. 400.
    MalformedBody,
    /// A body is larger than the configured buffering limit and has to be rewritten. 413.
    BodyTooLarge,
    /// The request carries a signature or digest scrim cannot recompute after substitution. 422.
    ResigningUnsupported,
    /// Protocol upgrades (WebSocket and similar) cannot be scanned and are refused. 501.
    UpgradeUnsupported,
    /// The request is not a proxy request scrim can handle. 400.
    BadRequest,
    /// The TLS server name does not match the CONNECT authority. 421.
    MisdirectedRequest,
    /// The upstream could not be reached or failed TLS verification. 502.
    UpstreamUnavailable,
    /// The upstream response could not be scanned for known values (unsupported coding,
    /// decoding error, too large) and was withheld. 502.
    ResponseWithheld,
    /// Redaction itself failed; the response was withheld. 502.
    RedactionFailed,
    /// The injection policy ([`crate::InjectionPolicy`]) refused a credential for this request:
    /// a rule denied it, or an approval was denied or did not come in time. Nothing was sent
    /// upstream. 403.
    PolicyDenied,
    /// A request signed with a credential's placeholder access key id was not signed with that
    /// credential's placeholder secret (AWS `SigV4`), or presented a certificate that is not
    /// the placeholder certificate. Nothing was sent upstream. 403.
    SignatureInvalid,
}

impl ErrorCode {
    /// The `snake_case` code sent in `x-scrim-error` and the JSON body.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotReady => "not_ready",
            ErrorCode::UnboundCredential => "unbound_credential",
            ErrorCode::UnboundDestination => "unbound_destination",
            ErrorCode::UndeclaredLocation => "undeclared_location",
            ErrorCode::CredentialUnavailable => "credential_unavailable",
            ErrorCode::UnrepresentableValue => "unrepresentable_value",
            ErrorCode::UnsupportedEncoding => "unsupported_encoding",
            ErrorCode::MalformedBody => "malformed_body",
            ErrorCode::BodyTooLarge => "body_too_large",
            ErrorCode::ResigningUnsupported => "resigning_unsupported",
            ErrorCode::UpgradeUnsupported => "upgrade_unsupported",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::MisdirectedRequest => "misdirected_request",
            ErrorCode::UpstreamUnavailable => "upstream_unavailable",
            ErrorCode::ResponseWithheld => "response_withheld",
            ErrorCode::RedactionFailed => "redaction_failed",
            ErrorCode::PolicyDenied => "policy_denied",
            ErrorCode::SignatureInvalid => "signature_invalid",
        }
    }

    /// HTTP status sent to the agent.
    pub fn status(self) -> StatusCode {
        match self {
            ErrorCode::NotReady | ErrorCode::CredentialUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            ErrorCode::UnboundCredential
            | ErrorCode::UnboundDestination
            | ErrorCode::UndeclaredLocation
            | ErrorCode::PolicyDenied
            | ErrorCode::SignatureInvalid => StatusCode::FORBIDDEN,
            ErrorCode::UnrepresentableValue | ErrorCode::ResigningUnsupported => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            ErrorCode::UnsupportedEncoding => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::MalformedBody | ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            ErrorCode::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::UpgradeUnsupported => StatusCode::NOT_IMPLEMENTED,
            ErrorCode::MisdirectedRequest => StatusCode::MISDIRECTED_REQUEST,
            ErrorCode::UpstreamUnavailable
            | ErrorCode::ResponseWithheld
            | ErrorCode::RedactionFailed => StatusCode::BAD_GATEWAY,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused request or withheld response: a code plus a message free of secret values.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct Refusal {
    /// Stable code.
    pub code: ErrorCode,
    /// Human-readable explanation. Never contains a secret value.
    pub message: String,
}

impl Refusal {
    /// Builds a refusal.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The HTTP response the agent receives for this refusal.
    pub fn to_response(&self) -> Response<Bytes> {
        let body = serde_json::json!({
            "error": {
                "type": "scrim_tool_proxy_error",
                "code": self.code.as_str(),
                "message": self.message,
            }
        });
        let mut resp = Response::new(Bytes::from(body.to_string()));
        *resp.status_mut() = self.code.status();
        let h = resp.headers_mut();
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        h.insert(
            "x-scrim-error",
            HeaderValue::from_static(self.code.as_str()),
        );
        resp
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
    fn response_shape() {
        let r = Refusal::new(
            ErrorCode::UnboundDestination,
            "credential `acme` is not bound",
        );
        let resp = r.to_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers()["x-scrim-error"], "unbound_destination");
        let v: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(v["error"]["code"], "unbound_destination");
        assert_eq!(v["error"]["type"], "scrim_tool_proxy_error");
    }
}
