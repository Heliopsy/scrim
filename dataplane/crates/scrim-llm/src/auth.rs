// SPDX-License-Identifier: AGPL-3.0-only

//! Provider authentication a route adds itself, with credentials scrim holds (llm-proxy spec,
//! "Cloud provider routes").
//!
//! Redaction changes the request body, so a signature the agent made over its own body cannot
//! survive it, and the agent should not hold the cloud credentials in the first place. A route
//! with [`AuthConfig`] therefore drops whatever authentication the agent sent
//! ([`AGENT_AUTH_HEADERS`]) and authenticates the redacted request itself, toward its own
//! upstream only:
//!
//! * [`AuthConfig::AwsSigv4`]: AWS Signature Version 4 over the exact bytes that leave (Amazon
//!   Bedrock, Bedrock Mantle, Claude Platform on AWS).
//! * [`AuthConfig::Header`]: a static key in a header, such as `x-api-key`, `api-key` or
//!   `Authorization: Bearer` (Bedrock API keys, Claude Platform on AWS and Microsoft Foundry API
//!   keys).
//!
//! The configuration names store references; the data plane looks their values up in the
//! snapshot. A reference whose value is not there makes every request on the route fail with
//! `credential_unavailable`, naming the reference and never forwarding anything.

use std::fmt::Write as _;
use std::time::SystemTime;

use hmac::{Hmac, KeyInit, Mac};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Uri};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::RefusalReason;
use crate::engine::SecretValue;
use crate::error::Refusal;

/// Request headers an agent may authenticate with. On a route with [`AuthConfig`] they are
/// removed before the request is redacted, so the agent's own credentials (or the dummy ones it
/// was given) never reach the provider.
pub const AGENT_AUTH_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
];

/// How a route authenticates toward its upstream. Every credential field is a store reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AuthConfig {
    /// AWS Signature Version 4.
    #[serde(rename_all = "kebab-case")]
    AwsSigv4 {
        /// Signing region (`us-east-1`).
        region: String,
        /// Signing service (`bedrock`, `bedrock-mantle`, `aws-external-anthropic`).
        service: String,
        /// Reference to the access key id.
        access_key_id: String,
        /// Reference to the secret access key.
        secret_access_key: String,
        /// Reference to the session token of temporary credentials.
        #[serde(default)]
        session_token: Option<String>,
    },
    /// A static credential in a header: `name: <prefix><value>`.
    #[serde(rename_all = "kebab-case")]
    Header {
        /// Header name (`x-api-key`, `api-key`, `authorization`).
        name: String,
        /// Text before the value (`Bearer `), usually empty.
        #[serde(default)]
        prefix: String,
        /// Reference to the value.
        value: String,
    },
}

impl AuthConfig {
    /// The store references this configuration needs.
    pub fn refs(&self) -> Vec<&str> {
        match self {
            Self::AwsSigv4 {
                access_key_id,
                secret_access_key,
                session_token,
                ..
            } => {
                let mut v = vec![access_key_id.as_str(), secret_access_key.as_str()];
                v.extend(session_token.as_deref());
                v
            }
            Self::Header { value, .. } => vec![value.as_str()],
        }
    }

    /// Checks the parts that are not references.
    pub fn validate(&self) -> Result<(), String> {
        let scope_part = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        match self {
            Self::AwsSigv4 {
                region, service, ..
            } => {
                if !scope_part(region) {
                    return Err("aws-sigv4 needs a region".into());
                }
                if !scope_part(service) {
                    return Err("aws-sigv4 needs a service".into());
                }
            }
            Self::Header { name, prefix, .. } => {
                if HeaderName::from_bytes(name.as_bytes()).is_err() {
                    return Err(format!("header auth: {name:?} is not a header name"));
                }
                if HeaderValue::from_str(prefix).is_err() {
                    return Err("header auth: the prefix is not a header value".into());
                }
            }
        }
        if self.refs().iter().any(|r| r.is_empty()) {
            return Err("every credential needs a reference".into());
        }
        Ok(())
    }
}

/// Credentials looked up for one route.
enum Creds {
    Sigv4 {
        access_key_id: SecretValue,
        secret_access_key: SecretValue,
        session_token: Option<SecretValue>,
    },
    Header {
        value: SecretValue,
    },
    /// References whose values the snapshot does not hold.
    Missing(Vec<String>),
}

/// A route's authentication with its credentials. Never printed with values.
pub struct RouteAuth {
    config: AuthConfig,
    creds: Creds,
}

impl std::fmt::Debug for RouteAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteAuth")
            .field("config", &self.config)
            .field(
                "missing",
                &match &self.creds {
                    Creds::Missing(m) => m.as_slice(),
                    _ => &[],
                },
            )
            .finish()
    }
}

impl RouteAuth {
    /// Looks every reference of `config` up with `lookup`.
    pub fn resolve(config: &AuthConfig, lookup: &dyn Fn(&str) -> Option<SecretValue>) -> Self {
        let mut missing = Vec::new();
        let mut get = |r: &str| {
            let v = lookup(r).filter(|v| !v.expose().is_empty());
            if v.is_none() {
                missing.push(r.to_owned());
            }
            v
        };
        let creds = match config {
            AuthConfig::AwsSigv4 {
                access_key_id,
                secret_access_key,
                session_token,
                ..
            } => {
                let a = get(access_key_id);
                let s = get(secret_access_key);
                let t = session_token.as_deref().map(&mut get);
                match (a, s, t) {
                    (Some(a), Some(s), None) => Creds::Sigv4 {
                        access_key_id: a,
                        secret_access_key: s,
                        session_token: None,
                    },
                    (Some(a), Some(s), Some(Some(t))) => Creds::Sigv4 {
                        access_key_id: a,
                        secret_access_key: s,
                        session_token: Some(t),
                    },
                    _ => Creds::Missing(missing),
                }
            }
            AuthConfig::Header { value, .. } => match get(value) {
                Some(v) => Creds::Header { value: v },
                None => Creds::Missing(missing),
            },
        };
        Self {
            config: config.clone(),
            creds,
        }
    }

    /// The configuration.
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// References the snapshot did not hold; empty when the route can authenticate.
    pub fn missing(&self) -> &[String] {
        match &self.creds {
            Creds::Missing(m) => m,
            _ => &[],
        }
    }

    /// Fails with `credential_unavailable` when a credential is missing, before anything is
    /// read or sent.
    pub fn check(&self) -> Result<(), Refusal> {
        match &self.creds {
            Creds::Missing(m) => Err(Refusal::new(
                RefusalReason::CredentialUnavailable,
                format!("no value for {}", m.join(", ")),
            )),
            _ => Ok(()),
        }
    }

    /// Authenticates the request that is about to leave: `uri` is where it goes, `headers` its
    /// final headers (rewritten in place) and `body` its exact bytes.
    pub fn apply(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &mut HeaderMap,
        body: &[u8],
        now: SystemTime,
    ) -> Result<(), Refusal> {
        for h in AGENT_AUTH_HEADERS {
            headers.remove(*h);
        }
        match (&self.config, &self.creds) {
            (_, Creds::Missing(_)) => self.check(),
            (AuthConfig::Header { name, prefix, .. }, Creds::Header { value }) => {
                let mut v = Zeroizing::new(Vec::with_capacity(prefix.len() + value.expose().len()));
                v.extend_from_slice(prefix.as_bytes());
                v.extend_from_slice(value.expose());
                let mut hv = HeaderValue::from_bytes(&v).map_err(|_| {
                    Refusal::new(
                        RefusalReason::CredentialUnavailable,
                        format!(
                            "the value of {} is not a valid header value",
                            self.config.refs()[0]
                        ),
                    )
                })?;
                hv.set_sensitive(true);
                let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                    Refusal::new(RefusalReason::CredentialUnavailable, "bad header name")
                })?;
                headers.insert(name, hv);
                Ok(())
            }
            (
                AuthConfig::AwsSigv4 {
                    region, service, ..
                },
                Creds::Sigv4 {
                    access_key_id,
                    secret_access_key,
                    session_token,
                },
            ) => sign_v4(
                &SigV4 {
                    access_key_id: access_key_id.expose(),
                    secret_access_key: secret_access_key.expose(),
                    session_token: session_token.as_ref().map(SecretValue::expose),
                    region,
                    service,
                },
                method,
                uri,
                headers,
                body,
                now,
            ),
            _ => Err(Refusal::new(
                RefusalReason::CredentialUnavailable,
                "credentials do not match the route's authentication",
            )),
        }
    }
}

/// What one `SigV4` signature needs.
pub(crate) struct SigV4<'a> {
    pub access_key_id: &'a [u8],
    pub secret_access_key: &'a [u8],
    pub session_token: Option<&'a [u8]>,
    pub region: &'a str,
    pub service: &'a str,
}

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
    m.update(data);
    m.finalize().into_bytes().into()
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Percent-encodes every byte but the unreserved ones (`A-Z a-z 0-9 - . _ ~`), as `SigV4`
/// canonicalisation does.
fn aws_encode(out: &mut String, b: &[u8]) {
    for &c in b {
        if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
            out.push(c as char);
        } else {
            let _ = write!(out, "%{c:02X}");
        }
    }
}

fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            )
        {
            out.push(u8::try_from(h * 16 + l).unwrap_or_default());
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// The canonical URI of a path as it goes on the wire: every segment encoded once more (every
/// AWS service but S3 signs the doubly encoded path).
fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    let mut s = String::with_capacity(path.len() + 16);
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            s.push('/');
        }
        aws_encode(&mut s, seg.as_bytes());
    }
    s
}

fn canonical_query(q: Option<&str>) -> String {
    let Some(q) = q.filter(|q| !q.is_empty()) else {
        return String::new();
    };
    let mut pairs: Vec<(String, String)> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let (mut ek, mut ev) = (String::new(), String::new());
            aws_encode(&mut ek, &percent_decode(&k.replace('+', "%20")));
            aws_encode(&mut ev, &percent_decode(&v.replace('+', "%20")));
            (ek, ev)
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The `Host` value hyper sends for `uri`: the host, and the port when it is not the scheme's
/// default.
fn host_of(uri: &Uri) -> String {
    let host = uri.host().unwrap_or_default();
    match (uri.port_u16(), uri.scheme_str()) {
        (Some(443), Some("https")) | (Some(80), Some("http")) | (None, _) => host.to_owned(),
        (Some(p), _) => format!("{host}:{p}"),
    }
}

/// Days since 1970-01-01 to a civil date (proleptic Gregorian).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// `YYYYMMDDTHHMMSSZ`.
pub(crate) fn amz_date(now: SystemTime) -> String {
    let secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let (y, m, d) = civil(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        t / 3600,
        t / 60 % 60,
        t % 60
    )
}

fn header_value(headers: &HeaderMap, name: &str) -> String {
    let vals: Vec<String> = headers
        .get_all(name)
        .iter()
        .map(|v| {
            String::from_utf8_lossy(v.as_bytes())
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    vals.join(",")
}

/// Signs the request in the header form: sets `x-amz-date`, `x-amz-security-token` when there
/// is a session token, and `Authorization`, signing `content-type` (when present), `host`, the
/// `x-amz-*` headers and the hash of `body`.
pub(crate) fn sign_v4(
    k: &SigV4<'_>,
    method: &Method,
    uri: &Uri,
    headers: &mut HeaderMap,
    body: &[u8],
    now: SystemTime,
) -> Result<(), Refusal> {
    let unusable = || {
        Refusal::new(
            RefusalReason::CredentialUnavailable,
            "the AWS credentials are not usable for signing",
        )
    };
    let date_time = amz_date(now);
    let date = &date_time[..8];
    headers.insert(
        "x-amz-date",
        HeaderValue::from_str(&date_time).map_err(|_| unusable())?,
    );
    if let Some(t) = k.session_token {
        let mut v = HeaderValue::from_bytes(t).map_err(|_| unusable())?;
        v.set_sensitive(true);
        headers.insert("x-amz-security-token", v);
    }
    let host = host_of(uri);
    let mut signed: Vec<String> = vec!["host".into()];
    for (name, _) in headers.iter() {
        let n = name.as_str();
        if (n == "content-type" || n.starts_with("x-amz-")) && !signed.iter().any(|s| s == n) {
            signed.push(n.to_owned());
        }
    }
    signed.sort();
    let mut canonical = String::with_capacity(512);
    canonical.push_str(method.as_str());
    canonical.push('\n');
    canonical.push_str(&canonical_uri(uri.path()));
    canonical.push('\n');
    canonical.push_str(&canonical_query(uri.query()));
    canonical.push('\n');
    for n in &signed {
        canonical.push_str(n);
        canonical.push(':');
        if n == "host" {
            canonical.push_str(&host);
        } else {
            canonical.push_str(&header_value(headers, n));
        }
        canonical.push('\n');
    }
    canonical.push('\n');
    canonical.push_str(&signed.join(";"));
    canonical.push('\n');
    canonical.push_str(&hex(&Sha256::digest(body)));

    let scope = format!("{date}/{}/{}/aws4_request", k.region, k.service);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{date_time}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut secret = Zeroizing::new(Vec::with_capacity(k.secret_access_key.len() + 4));
    secret.extend_from_slice(b"AWS4");
    secret.extend_from_slice(k.secret_access_key);
    let kd = Zeroizing::new(hmac(&secret, date.as_bytes()));
    let kr = Zeroizing::new(hmac(&*kd, k.region.as_bytes()));
    let ks = Zeroizing::new(hmac(&*kr, k.service.as_bytes()));
    let kk = Zeroizing::new(hmac(&*ks, b"aws4_request"));
    let sig = hex(&hmac(&*kk, to_sign.as_bytes()));

    let akid = std::str::from_utf8(k.access_key_id).map_err(|_| unusable())?;
    let mut v = HeaderValue::from_str(&format!(
        "AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={}, Signature={sig}",
        signed.join(";")
    ))
    .map_err(|_| unusable())?;
    v.set_sensitive(true);
    headers.insert(header::AUTHORIZATION, v);
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::duration_suboptimal_units,
    reason = "dates from the AWS examples"
)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn dates() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        assert_eq!(amz_date(t), "20150830T123600Z");
        assert_eq!(amz_date(SystemTime::UNIX_EPOCH), "19700101T000000Z");
        let leap = SystemTime::UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(&amz_date(leap)[..8], "20000229");
    }

    #[test]
    fn canonical_parts() {
        assert_eq!(
            canonical_uri("/model/us.anthropic.claude-x-v1:0/invoke"),
            "/model/us.anthropic.claude-x-v1%3A0/invoke"
        );
        assert_eq!(
            canonical_uri("/model/us.anthropic.claude-x-v1%3A0/invoke"),
            "/model/us.anthropic.claude-x-v1%253A0/invoke"
        );
        assert_eq!(canonical_query(Some("b=2&a=1&a=0")), "a=0&a=1&b=2");
        assert_eq!(canonical_query(Some("k=a+b%2Fc")), "k=a%20b%2Fc");
        assert_eq!(canonical_query(None), "");
        assert_eq!(
            host_of(&"https://h.example:443/x".parse().unwrap()),
            "h.example"
        );
        assert_eq!(
            host_of(&"http://127.0.0.1:8080/x".parse().unwrap()),
            "127.0.0.1:8080"
        );
    }

    /// AWS's published example (`get-vanilla` of the signing test suite): service `service`,
    /// region `us-east-1`, the documented example keys.
    #[test]
    fn aws_test_suite_get_vanilla() {
        let mut h = HeaderMap::new();
        let uri: Uri = "https://example.amazonaws.com/".parse().unwrap();
        let k = SigV4 {
            access_key_id: b"AKIDEXAMPLE",
            secret_access_key: b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            session_token: None,
            region: "us-east-1",
            service: "service",
        };
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        sign_v4(&k, &Method::GET, &uri, &mut h, b"", t).unwrap();
        assert_eq!(
            h[header::AUTHORIZATION],
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn missing_credentials_refuse_naming_the_reference() {
        let cfg = AuthConfig::Header {
            name: "x-api-key".into(),
            prefix: String::new(),
            value: "openbao://kv/foundry#key".into(),
        };
        let a = RouteAuth::resolve(&cfg, &|_| None);
        let e = a.check().unwrap_err();
        assert_eq!(e.reason, RefusalReason::CredentialUnavailable);
        assert!(e.detail.contains("openbao://kv/foundry#key"));
        let mut h = HeaderMap::new();
        assert!(
            a.apply(
                &Method::POST,
                &"https://x/".parse().unwrap(),
                &mut h,
                b"",
                SystemTime::now()
            )
            .is_err()
        );
        assert!(h.is_empty());
    }

    #[test]
    fn header_auth_replaces_agent_credentials() {
        let cfg = AuthConfig::Header {
            name: "authorization".into(),
            prefix: "Bearer ".into(),
            value: "r".into(),
        };
        let a = RouteAuth::resolve(&cfg, &|_| Some(SecretValue::new(b"tok-123".to_vec())));
        let mut h = HeaderMap::new();
        h.insert("x-api-key", "agent-dummy".parse().unwrap());
        h.insert("authorization", "Bearer agent".parse().unwrap());
        a.apply(
            &Method::POST,
            &"https://x/".parse().unwrap(),
            &mut h,
            b"{}",
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(h["authorization"], "Bearer tok-123");
        assert!(h.get("x-api-key").is_none());
        assert!(format!("{a:?}").find("tok-123").is_none());
    }
}
