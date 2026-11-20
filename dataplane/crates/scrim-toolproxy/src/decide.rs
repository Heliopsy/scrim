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
    /// it when `HTTPS_PROXY` is `http://<session>:<token>@host:port`). A claim: the proxy
    /// verifies nothing.
    pub session: Option<String>,
    /// The verifier of the session token sent as the password, when the password is a session
    /// token of the named session. The token itself is wiped as soon as it is hashed.
    pub verifier: Option<SessionVerifier>,
}

impl ClientInfo {
    /// The session named in `headers` (`Proxy-Authorization: Basic`), if it is a plain session
    /// id (1 to 128 of `A-Za-z0-9._-`).
    pub fn session_from(headers: &HeaderMap) -> Option<String> {
        Self::credentials_from(headers).map(|(s, _)| s)
    }

    /// The session named in `headers` (`Proxy-Authorization: Basic`) and, when the password is
    /// that session's token, its verifier. Nothing of the password is kept.
    pub fn credentials_from(headers: &HeaderMap) -> Option<(String, Option<SessionVerifier>)> {
        let v = headers.get(header::PROXY_AUTHORIZATION)?.as_bytes();
        if v.len() <= 6 || !v[..6].eq_ignore_ascii_case(b"basic ") {
            return None;
        }
        let decoded = zeroize::Zeroizing::new(STANDARD.decode(v[6..].trim_ascii()).ok()?);
        let (user, pass) = match decoded.iter().position(|b| *b == b':') {
            Some(i) => (&decoded[..i], Some(&decoded[i + 1..])),
            None => (&decoded[..], None),
        };
        if !is_session_id(user) {
            return None;
        }
        let user = String::from_utf8_lossy(user).into_owned();
        let verifier = pass
            .and_then(parse_session_token)
            .filter(|(id, _)| *id == user)
            .map(|(_, v)| v);
        Some((user, verifier))
    }
}

/// Whether `s` is a plain session id: 1 to 128 of `A-Za-z0-9._-`.
pub fn is_session_id(s: &[u8]) -> bool {
    (1..=128).contains(&s.len())
        && s.iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

// The prefix of every scrim session token (`scrim_st_<id>_<secret>`).
const SESSION_TOKEN_PREFIX: &[u8] = b"scrim_st_";
const SESSION_ID_LEN: usize = 16;
const SESSION_SECRET_LEN: usize = 43;
const SESSION_HASH_DOMAIN: &[u8] = b"scrim session token v1\0";

/// `SHA-256("scrim session token v1\0" || secret)` of a session token: what the control plane
/// stores for the session, kept here only to prove possession of the token in an ask
/// (`AskCaller.session_proof`, design D14). Zeroed on drop; `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionVerifier(zeroize::Zeroizing<[u8; 32]>);

impl SessionVerifier {
    /// The verifier bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SessionVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionVerifier(..)")
    }
}

/// Splits a session token into its session id and the verifier of its secret part. `None` for
/// anything not shaped like `scrim_st_<16 of a-z2-7>_<43 of base64url>`.
pub fn parse_session_token(tok: &[u8]) -> Option<(String, SessionVerifier)> {
    use sha2::Digest as _;
    let tok = tok.trim_ascii();
    let rest = tok.strip_prefix(SESSION_TOKEN_PREFIX)?;
    if rest.len() != SESSION_ID_LEN + 1 + SESSION_SECRET_LEN || rest[SESSION_ID_LEN] != b'_' {
        return None;
    }
    let (id, secret) = (&rest[..SESSION_ID_LEN], &rest[SESSION_ID_LEN + 1..]);
    if !id
        .iter()
        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(b))
        || !secret
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return None;
    }
    let mut h = sha2::Sha256::new();
    h.update(SESSION_HASH_DOMAIN);
    h.update(secret);
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&h.finalize());
    Some((
        String::from_utf8_lossy(id).into_owned(),
        SessionVerifier(out),
    ))
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

    #[test]
    fn token_password_yields_a_verifier() {
        use sha2::Digest as _;
        let id = "abcdefghijklmn23";
        let secret = "A".repeat(43);
        let token = format!("scrim_st_{id}_{secret}");
        let mut h = HeaderMap::new();
        let basic = |s: &str| format!("Basic {}", STANDARD.encode(s)).parse().unwrap();
        h.insert(header::PROXY_AUTHORIZATION, basic(&format!("{id}:{token}")));
        let (user, v) = ClientInfo::credentials_from(&h).unwrap();
        assert_eq!(user, id);
        let v = v.unwrap();
        let mut want = sha2::Sha256::new();
        want.update(b"scrim session token v1\0");
        want.update(secret.as_bytes());
        assert_eq!(v.as_bytes()[..], want.finalize()[..]);
        assert_eq!(format!("{v:?}"), "SessionVerifier(..)");
        // A token of another session, a malformed token or no password: a claim only.
        h.insert(
            header::PROXY_AUTHORIZATION,
            basic(&format!("other:{token}")),
        );
        assert!(ClientInfo::credentials_from(&h).unwrap().1.is_none());
        h.insert(
            header::PROXY_AUTHORIZATION,
            basic(&format!("{id}:scrim_st_{id}_short")),
        );
        assert!(ClientInfo::credentials_from(&h).unwrap().1.is_none());
        h.insert(header::PROXY_AUTHORIZATION, basic(id));
        assert!(ClientInfo::credentials_from(&h).unwrap().1.is_none());
        assert!(parse_session_token(token.as_bytes()).is_some());
        assert!(
            parse_session_token(format!("scrim_st_{}_{secret}", "A".repeat(16)).as_bytes())
                .is_none()
        );
    }
}
