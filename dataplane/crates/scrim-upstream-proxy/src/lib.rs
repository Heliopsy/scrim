// SPDX-License-Identifier: AGPL-3.0-only

//! Outbound connections through an upstream HTTP proxy (interception spec, "Outbound connections
//! through an upstream proxy").
//!
//! Networks that only let traffic out through a proxy need scrim's own connections (provider
//! routes, chained upstreams, tool hosts, transparent pass-through) to go through it. Every such
//! connection is an HTTP `CONNECT` tunnel to the destination's `host:port`, opened by
//! [`connect`]; TLS to the destination runs inside the tunnel, set up by the caller exactly as on
//! a direct connection, and is verified against the destination's name. The proxy sees the
//! `CONNECT` line and ciphertext, never a request. Redaction and the guard run before a request
//! reaches the client at all, so nothing here sees or changes request bytes.
//!
//! [`ProxyConnector`] wraps a hyper connector: destinations in the `NO_PROXY` list
//! ([`NoProxy`]) go to the wrapped connector, the rest through the tunnel. The proxy in force is
//! held in a [`ProxyHandle`] the data plane swaps on every snapshot, so a reload that changes the
//! proxy or rotates its password applies to the next connection.
//!
//! The password lives in a zeroed-on-drop buffer as the ready `Proxy-Authorization` value, is
//! written into a zeroed-on-drop request buffer, and never appears in `Debug`, an error or a log
//! line.

mod connector;
pub mod noproxy;
#[cfg(feature = "test-util")]
pub mod testing;
mod tunnel;

use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use base64::Engine as _;
use zeroize::Zeroizing;

pub use connector::{ProxyConnector, ProxyIo};
pub use noproxy::NoProxy;
pub use tunnel::{Stream, TunnelError, connect};

/// The upstream proxy configuration is not usable.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// The URL is not `http://host:port` or `https://host:port`.
    #[error(
        "upstream proxy URL {0:?}: want http://host:port or https://host:port without user info or path"
    )]
    Url(String),
    /// A `NO_PROXY` entry is not valid.
    #[error(transparent)]
    NoProxy(#[from] noproxy::BadEntry),
    /// A password without a user name, or a user name with a `:`.
    #[error("upstream proxy user name must be set with a password and must not contain ':'")]
    Username,
}

/// One upstream proxy: where it is, what bypasses it, and how to authenticate.
pub struct UpstreamProxy {
    tls: bool,
    host: String,
    port: u16,
    no_proxy: NoProxy,
    /// `Basic <base64(user:password)>`, the whole `Proxy-Authorization` value.
    authorization: Option<Zeroizing<Vec<u8>>>,
}

impl UpstreamProxy {
    /// Parses `url` (`http://host[:port]` or `https://host[:port]`, default ports 80 and 443) and
    /// the `NO_PROXY` entries. A non-empty `username` sends Basic credentials with every
    /// `CONNECT`; the password bytes are copied into a zeroed buffer and the caller wipes its own.
    pub fn new<S: AsRef<str>>(
        url: &str,
        no_proxy: &[S],
        username: &str,
        password: &[u8],
    ) -> Result<Self, ConfigError> {
        let bad = || ConfigError::Url(url.to_owned());
        let uri: http::Uri = url.parse().map_err(|_| bad())?;
        let tls = match uri.scheme_str() {
            Some("http") => false,
            Some("https") => true,
            _ => return Err(bad()),
        };
        let auth = uri.authority().ok_or_else(bad)?;
        if auth.as_str().contains('@') || !matches!(uri.path(), "" | "/") || uri.query().is_some() {
            return Err(bad());
        }
        let host = auth
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        if host.is_empty() {
            return Err(bad());
        }
        let port = auth.port_u16().unwrap_or(if tls { 443 } else { 80 });
        if username.contains(':') || (username.is_empty() && !password.is_empty()) {
            return Err(ConfigError::Username);
        }
        let authorization = (!username.is_empty()).then(|| {
            let mut raw = Zeroizing::new(Vec::with_capacity(username.len() + 1 + password.len()));
            raw.extend_from_slice(username.as_bytes());
            raw.push(b':');
            raw.extend_from_slice(password);
            let enc = base64::engine::general_purpose::STANDARD;
            let mut header = Zeroizing::new(vec![
                0u8;
                6 + base64::encoded_len(raw.len(), true)
                    .unwrap_or(0)
            ]);
            header[..6].copy_from_slice(b"Basic ");
            let n = enc
                .encode_slice(raw.as_slice(), &mut header[6..])
                .unwrap_or(0);
            header.truncate(6 + n);
            header
        });
        Ok(Self {
            tls,
            host,
            port,
            no_proxy: NoProxy::parse(no_proxy)?,
            authorization,
        })
    }

    /// Whether a connection to `host:port` goes through this proxy.
    pub fn applies(&self, host: &str, port: u16) -> bool {
        !self.no_proxy.matches(host, port)
    }

    /// The proxy's host (an IPv6 address without brackets).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The proxy's port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether scrim speaks TLS to the proxy itself (`https://`).
    pub fn is_tls(&self) -> bool {
        self.tls
    }

    /// Whether `CONNECT` carries credentials.
    pub fn has_credentials(&self) -> bool {
        self.authorization.is_some()
    }

    pub(crate) fn authorization(&self) -> Option<&[u8]> {
        self.authorization.as_deref().map(Vec::as_slice)
    }

    /// `scheme://host:port`, for logs. Never holds credentials.
    pub fn display(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        if self.host.contains(':') {
            format!("{scheme}://[{}]:{}", self.host, self.port)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamProxy")
            .field("url", &self.display())
            .field("no_proxy", &self.no_proxy)
            .field("credentials", &self.authorization.is_some())
            .finish_non_exhaustive()
    }
}

/// The upstream proxy in force, shared by every client of one data plane and swapped as a whole.
/// Empty means direct connections.
#[derive(Clone, Default)]
pub struct ProxyHandle(Arc<ArcSwapOption<UpstreamProxy>>);

impl ProxyHandle {
    /// A handle with no proxy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the proxy; `None` connects directly. Connections already open stay as they are.
    pub fn set(&self, proxy: Option<UpstreamProxy>) {
        self.0.store(proxy.map(Arc::new));
    }

    /// The proxy in force.
    pub fn current(&self) -> Option<Arc<UpstreamProxy>> {
        self.0.load_full()
    }

    /// The proxy a connection to `host:port` goes through, if any.
    pub fn route(&self, host: &str, port: u16) -> Option<Arc<UpstreamProxy>> {
        self.current().filter(|p| p.applies(host, port))
    }
}

impl PartialEq for ProxyHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ProxyHandle {}

impl fmt::Debug for ProxyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProxyHandle").field(&self.current()).finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let p = UpstreamProxy::new::<&str>("http://proxy.corp.test:3128", &[], "", b"").unwrap();
        assert_eq!(
            (p.host(), p.port(), p.is_tls()),
            ("proxy.corp.test", 3128, false)
        );
        let p = UpstreamProxy::new::<&str>("https://[fd00::1]", &[], "", b"").unwrap();
        assert_eq!((p.host(), p.port(), p.is_tls()), ("fd00::1", 443, true));
        assert_eq!(p.display(), "https://[fd00::1]:443");
        let p = UpstreamProxy::new::<&str>("http://proxy/", &[], "", b"").unwrap();
        assert_eq!(p.port(), 80);
        for bad in [
            "socks5://proxy:1080",
            "proxy:3128",
            "http://user:pw@proxy:3128",
            "http://proxy:3128/path",
            "http://proxy:3128?x=1",
            "http://:3128",
            "",
        ] {
            assert!(
                matches!(
                    UpstreamProxy::new::<&str>(bad, &[], "", b""),
                    Err(ConfigError::Url(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn credentials_become_basic_and_never_print() {
        let pw = b"generated-proxy-pw-91c2";
        let p = UpstreamProxy::new::<&str>("http://proxy:3128", &[], "scrim", pw).unwrap();
        let want = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(b"scrim:generated-proxy-pw-91c2")
        );
        assert_eq!(p.authorization().unwrap(), want.as_bytes());
        let dbg = format!("{p:?} {:?}", ProxyHandle::default());
        assert!(!dbg.contains("generated-proxy-pw"), "{dbg}");
        assert!(!dbg.contains(&want[6..]), "{dbg}");
        assert!(dbg.contains("credentials: true"));
        assert_eq!(
            UpstreamProxy::new::<&str>("http://proxy:3128", &[], "", pw).unwrap_err(),
            ConfigError::Username
        );
        assert_eq!(
            UpstreamProxy::new::<&str>("http://proxy:3128", &[], "a:b", pw).unwrap_err(),
            ConfigError::Username
        );
    }

    #[test]
    fn handle_routes_by_no_proxy() {
        let h = ProxyHandle::new();
        assert!(h.route("api.anthropic.com", 443).is_none());
        h.set(Some(
            UpstreamProxy::new("http://proxy:3128", &["localhost", "corp.test"], "", b"").unwrap(),
        ));
        assert!(h.route("api.anthropic.com", 443).is_some());
        assert!(h.route("vault.corp.test", 8200).is_none());
        assert!(h.route("localhost", 9790).is_none());
        h.set(None);
        assert!(h.route("api.anthropic.com", 443).is_none());
        assert_eq!(h.clone(), h);
        assert_ne!(h, ProxyHandle::new());
    }
}
