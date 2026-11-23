// SPDX-License-Identifier: AGPL-3.0-only

//! OAuth 2.0 access tokens a route mints for itself (Google Vertex AI, Microsoft Entra ID for
//! Foundry), cached until shortly before they expire.
//!
//! * Google service account: a JWT signed with the key's RSA private key (RS256) exchanged at
//!   the token endpoint (`urn:ietf:params:oauth:grant-type:jwt-bearer`, RFC 7523).
//! * Google metadata server: the attached service account's token (GKE workload identity, GCE).
//! * Entra ID client credentials: client id and secret exchanged for a token (RFC 6749 4.4).
//!
//! Tokens and key material live in [`SecretValue`] and zeroizing buffers. Errors name the token
//! endpoint's host and the status, never a response body (it may echo the request).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::RefusalReason;
use crate::engine::SecretValue;
use crate::error::Refusal;
use crate::upstream::UpstreamClient;

/// Default Google token endpoint.
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Default Google metadata server token URL.
pub const GOOGLE_METADATA_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
/// The scope Vertex AI needs.
pub const GOOGLE_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// The scope of Microsoft Foundry.
pub const ENTRA_SCOPE: &str = "https://ai.azure.com/.default";

/// Tokens are renewed this long before they expire.
const RENEW_BEFORE: Duration = Duration::from_secs(300);
/// Largest token response read.
const MAX_RESPONSE: usize = 64 << 10;
/// Time a token request may take.
const TIMEOUT: Duration = Duration::from_secs(15);

/// How a token is obtained. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Minter {
    /// A Google service account key (JSON) signs a JWT for `token_url`.
    GoogleServiceAccount {
        /// Token endpoint.
        token_url: String,
        /// Scope requested.
        scope: String,
    },
    /// The metadata server at `url`.
    GoogleMetadata {
        /// Token URL.
        url: String,
        /// Scope requested.
        scope: String,
    },
    /// Entra ID client credentials.
    EntraClientSecret {
        /// Token endpoint (`https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`).
        token_url: String,
        /// Application (client) id, not secret.
        client_id: String,
        /// Scope requested.
        scope: String,
    },
}

fn unavailable(detail: impl Into<String>) -> Refusal {
    Refusal::new(RefusalReason::CredentialUnavailable, detail)
}

fn host_of(url: &str) -> String {
    url.parse::<http::Uri>()
        .ok()
        .and_then(|u| u.host().map(str::to_owned))
        .unwrap_or_else(|| "the token endpoint".into())
}

/// The fields of a service account key file scrim uses. Never printed.
#[derive(serde::Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    #[serde(default)]
    private_key_id: Option<String>,
}

impl Drop for ServiceAccount {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.private_key);
    }
}

fn form_escape(out: &mut String, s: &str) {
    use std::fmt::Write as _;
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

/// An RS256 JWT assertion for a service account (RFC 7523 section 2.1, Google's claims).
fn assertion(
    sa: &ServiceAccount,
    token_url: &str,
    scope: &str,
    now: SystemTime,
) -> Result<Zeroizing<String>, Refusal> {
    let bad_key = || unavailable("the service account key is not a PKCS#8 RSA private key");
    let pem = sa.private_key.as_str();
    let b64: Zeroizing<String> = Zeroizing::new(
        pem.lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(str::chars)
            .filter(|c| !c.is_whitespace())
            .collect(),
    );
    let der = Zeroizing::new(STANDARD.decode(b64.as_bytes()).map_err(|_| bad_key())?);
    let key = ring::signature::RsaKeyPair::from_pkcs8(&der).map_err(|_| bad_key())?;
    let iat = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    if let Some(kid) = &sa.private_key_id {
        header["kid"] = serde_json::Value::String(kid.clone());
    }
    let claims = serde_json::json!({
        "iss": sa.client_email, "scope": scope, "aud": token_url, "iat": iat, "exp": iat + 3600,
    });
    let mut signing = URL_SAFE_NO_PAD.encode(header.to_string());
    signing.push('.');
    signing.push_str(&URL_SAFE_NO_PAD.encode(claims.to_string()));
    let mut sig = vec![0u8; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        signing.as_bytes(),
        &mut sig,
    )
    .map_err(|_| bad_key())?;
    signing.push('.');
    signing.push_str(&URL_SAFE_NO_PAD.encode(sig));
    Ok(Zeroizing::new(signing))
}

/// One token request: method, URL, headers and body.
struct TokenRequest {
    method: http::Method,
    url: String,
    headers: Vec<(&'static str, String)>,
    body: Zeroizing<String>,
}

impl Minter {
    fn request(
        &self,
        credential: Option<&SecretValue>,
        now: SystemTime,
    ) -> Result<TokenRequest, Refusal> {
        let form = vec![(
            "content-type",
            "application/x-www-form-urlencoded".to_owned(),
        )];
        match self {
            Self::GoogleServiceAccount { token_url, scope } => {
                let cred = credential.ok_or_else(|| unavailable("no service account key"))?;
                let sa: ServiceAccount = serde_json::from_slice(cred.expose())
                    .map_err(|_| unavailable("the service account key is not a JSON key file"))?;
                let jwt = assertion(&sa, token_url, scope, now)?;
                let mut body = Zeroizing::new(String::with_capacity(jwt.len() + 80));
                body.push_str(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=",
                );
                body.push_str(&jwt);
                Ok(TokenRequest {
                    method: http::Method::POST,
                    url: token_url.clone(),
                    headers: form,
                    body,
                })
            }
            Self::GoogleMetadata { url, scope } => {
                let mut u = url.clone();
                u.push_str(if u.contains('?') {
                    "&scopes="
                } else {
                    "?scopes="
                });
                form_escape(&mut u, scope);
                Ok(TokenRequest {
                    method: http::Method::GET,
                    url: u,
                    headers: vec![("metadata-flavor", "Google".to_owned())],
                    body: Zeroizing::new(String::new()),
                })
            }
            Self::EntraClientSecret {
                token_url,
                client_id,
                scope,
            } => {
                let cred = credential.ok_or_else(|| unavailable("no client secret"))?;
                let secret = std::str::from_utf8(cred.expose())
                    .map_err(|_| unavailable("the client secret is not text"))?;
                let mut body =
                    Zeroizing::new(String::from("grant_type=client_credentials&client_id="));
                form_escape(&mut body, client_id);
                body.push_str("&client_secret=");
                form_escape(&mut body, secret);
                body.push_str("&scope=");
                form_escape(&mut body, scope);
                Ok(TokenRequest {
                    method: http::Method::POST,
                    url: token_url.clone(),
                    headers: form,
                    body,
                })
            }
        }
    }
}

/// A cached token.
struct Cached {
    token: SecretValue,
    renew_at: Instant,
}

/// Tokens by minter and credential. Shared by every route and snapshot, so a snapshot push does
/// not mint again.
#[derive(Default)]
pub struct TokenCache {
    tokens: Mutex<HashMap<[u8; 32], Cached>>,
}

impl std::fmt::Debug for TokenCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenCache").finish_non_exhaustive()
    }
}

fn cache_key(m: &Minter, credential: Option<&SecretValue>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(format!("{m:?}").as_bytes());
    h.update([0]);
    if let Some(c) = credential {
        h.update(c.expose());
    }
    h.finalize().into()
}

impl TokenCache {
    /// A token for `m`, from the cache or minted now with `client`.
    pub async fn token(
        &self,
        client: &UpstreamClient,
        m: &Minter,
        credential: Option<&SecretValue>,
    ) -> Result<SecretValue, Refusal> {
        let key = cache_key(m, credential);
        let now = Instant::now();
        if let Ok(t) = self.tokens.lock()
            && let Some(c) = t.get(&key)
            && c.renew_at > now
        {
            return Ok(SecretValue::new(c.token.expose().to_vec()));
        }
        let (token, ttl) = mint(client, m, credential).await?;
        let renew_at = now + ttl.saturating_sub(RENEW_BEFORE).max(ttl / 2);
        if let Ok(mut t) = self.tokens.lock() {
            t.retain(|_, c| c.renew_at > now);
            t.insert(
                key,
                Cached {
                    token: SecretValue::new(token.expose().to_vec()),
                    renew_at,
                },
            );
        }
        Ok(token)
    }
}

/// The token response fields scrim reads. Never printed.
#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.access_token);
    }
}

async fn mint(
    client: &UpstreamClient,
    m: &Minter,
    credential: Option<&SecretValue>,
) -> Result<(SecretValue, Duration), Refusal> {
    let r = m.request(credential, SystemTime::now())?;
    let host = host_of(&r.url);
    let uri: http::Uri = r
        .url
        .parse()
        .map_err(|_| unavailable(format!("the token URL for {host} is not a URL")))?;
    let mut req = http::Request::new(Full::new(Bytes::from(r.body.as_bytes().to_vec())));
    *req.method_mut() = r.method;
    *req.uri_mut() = uri;
    for (k, v) in r.headers {
        if let Ok(v) = http::HeaderValue::from_str(&v) {
            req.headers_mut().insert(k, v);
        }
    }
    req.headers_mut().insert(
        http::header::ACCEPT,
        http::HeaderValue::from_static("application/json"),
    );
    let resp = tokio::time::timeout(TIMEOUT, client.request(req))
        .await
        .map_err(|_| unavailable(format!("token request to {host} timed out")))?
        .map_err(|_| unavailable(format!("token request to {host} failed")))?;
    let status = resp.status();
    let body = Limited::new(resp.into_body(), MAX_RESPONSE)
        .collect()
        .await
        .map_err(|_| unavailable(format!("token response from {host} could not be read")))?
        .to_bytes();
    let body = Zeroizing::new(body.to_vec());
    if !status.is_success() {
        return Err(unavailable(format!(
            "token request to {host} was refused with status {}",
            status.as_u16()
        )));
    }
    let t: TokenResponse = serde_json::from_slice(&body)
        .map_err(|_| unavailable(format!("token response from {host} has no access_token")))?;
    if t.access_token.is_empty() || http::HeaderValue::from_str(&t.access_token).is_err() {
        return Err(unavailable(format!(
            "token response from {host} has no usable access_token"
        )));
    }
    let ttl = Duration::from_secs(t.expires_in.unwrap_or(3600).clamp(60, 24 * 3600));
    Ok((SecretValue::new(t.access_token.as_bytes().to_vec()), ttl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_name_no_secret_in_their_errors() {
        let m = Minter::GoogleServiceAccount {
            token_url: GOOGLE_TOKEN_URL.into(),
            scope: GOOGLE_SCOPE.into(),
        };
        let bad = SecretValue::new(br#"{"client_email":"a@b","private_key":"-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5LXNlY3JldA==\n-----END PRIVATE KEY-----\n"}"#.to_vec());
        let e = m.request(Some(&bad), SystemTime::now()).err().unwrap();
        assert_eq!(e.reason, RefusalReason::CredentialUnavailable);
        assert!(!e.detail.contains("bm90"));
        let e = m
            .request(
                Some(&SecretValue::new(b"not json".to_vec())),
                SystemTime::now(),
            )
            .err()
            .unwrap();
        assert!(e.detail.contains("JSON key file"));
    }

    #[test]
    fn entra_and_metadata_requests() {
        let m = Minter::EntraClientSecret {
            token_url: "https://login.microsoftonline.com/t/oauth2/v2.0/token".into(),
            client_id: "app-id".into(),
            scope: ENTRA_SCOPE.into(),
        };
        let r = m
            .request(
                Some(&SecretValue::new(b"s3cr&t=".to_vec())),
                SystemTime::now(),
            )
            .unwrap();
        assert_eq!(
            r.body.as_str(),
            "grant_type=client_credentials&client_id=app-id&client_secret=s3cr%26t%3D&scope=https%3A%2F%2Fai.azure.com%2F.default"
        );
        let m = Minter::GoogleMetadata {
            url: GOOGLE_METADATA_URL.into(),
            scope: GOOGLE_SCOPE.into(),
        };
        let r = m.request(None, SystemTime::now()).unwrap();
        assert_eq!(r.method, http::Method::GET);
        assert!(
            r.url
                .ends_with("?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform")
        );
        assert_eq!(r.headers, vec![("metadata-flavor", "Google".to_owned())]);
    }
}
