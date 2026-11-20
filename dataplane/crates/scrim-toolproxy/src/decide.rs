//! The per-request injection decision seam.
//!
//! Bindings say where a credential may ever go; an [`InjectionPolicy`] decides whether this
//! request may use it now (the embedder's decision table, possibly an approval). It runs once
//! per credential a request uses, after every binding and location check passed and before
//! anything is substituted, so a denial refuses the whole request with
//! [`crate::ErrorCode::PolicyDenied`] and nothing reaches the upstream.
//!
//! The proxy attaches a [`ClientInfo`] to every request it serves (request extensions), so the
//! policy can identify the caller by the transport.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::HeaderMap;
use http::header;

use crate::host::Destination;

/// What the proxy knows about the client of a request: its TCP peer and the scrim session the
/// client named on the proxy connection. Attached to every request as a request extension.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientInfo {
    /// The client's address, when the listener has one.
    pub peer: Option<SocketAddr>,
    /// The session the client named in `Proxy-Authorization: Basic` (the user name; clients send
    /// it when `HTTPS_PROXY` is `http://<session>:<token>@host:port`). The password is never
    /// read. A claim: the proxy verifies nothing.
    pub session: Option<String>,
}

impl ClientInfo {
    /// The session named in `headers` (`Proxy-Authorization: Basic`), if it is a plain session
    /// id (1 to 128 of `A-Za-z0-9._-`).
    pub fn session_from(headers: &HeaderMap) -> Option<String> {
        let v = headers.get(header::PROXY_AUTHORIZATION)?.as_bytes();
        if v.len() <= 6 || !v[..6].eq_ignore_ascii_case(b"basic ") {
            return None;
        }
        let decoded = zeroize::Zeroizing::new(STANDARD.decode(v[6..].trim_ascii()).ok()?);
        let user = decoded.split(|b| *b == b':').next()?;
        is_session_id(user).then(|| String::from_utf8_lossy(user).into_owned())
    }
}

/// Whether `s` is a plain session id: 1 to 128 of `A-Za-z0-9._-`.
pub fn is_session_id(s: &[u8]) -> bool {
    (1..=128).contains(&s.len())
        && s.iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// One credential a request would have injected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectionRequest {
    /// Credential alias.
    pub credential: String,
    /// Store reference.
    pub reference: String,
    /// Destination.
    pub destination: Destination,
    /// HTTP method.
    pub method: String,
    /// Normalised URL path, query removed.
    pub path: String,
}

/// An [`InjectionPolicy`]'s answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InjectionDecision {
    /// Inject.
    Allow,
    /// Refuse the request; the message names the rule and never contains a value.
    Deny(String),
}

/// Decides per request whether a credential may be injected. Bound to a snapshot
/// ([`crate::Snapshot::injection`]), so a request decides under the version it started with.
pub trait InjectionPolicy: Send + Sync + 'static {
    /// Decides one credential of one request. `extensions` are the request's, with the
    /// [`ClientInfo`] the proxy attached. May wait (an approval); the policy bounds the wait.
    fn decide<'a>(
        &'a self,
        req: &'a InjectionRequest,
        extensions: &'a http::Extensions,
    ) -> Pin<Box<dyn Future<Output = InjectionDecision> + Send + 'a>>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn session_from_proxy_authorization() {
        let mut h = HeaderMap::new();
        assert_eq!(ClientInfo::session_from(&h), None);
        let basic = |s: &str| format!("Basic {}", STANDARD.encode(s)).parse().unwrap();
        h.insert(header::PROXY_AUTHORIZATION, basic("sess-01.A_b:tok"));
        assert_eq!(ClientInfo::session_from(&h).as_deref(), Some("sess-01.A_b"));
        h.insert(header::PROXY_AUTHORIZATION, basic("only-user"));
        assert_eq!(ClientInfo::session_from(&h).as_deref(), Some("only-user"));
        for bad in ["", ":tok", "has space:tok", "ünï:x"] {
            h.insert(header::PROXY_AUTHORIZATION, basic(bad));
            assert_eq!(ClientInfo::session_from(&h), None, "{bad}");
        }
        h.insert(header::PROXY_AUTHORIZATION, "Bearer x".parse().unwrap());
        assert_eq!(ClientInfo::session_from(&h), None);
    }
}
