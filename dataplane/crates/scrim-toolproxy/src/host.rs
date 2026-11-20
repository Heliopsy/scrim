//! Destinations and host patterns.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// URL scheme of a proxied request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// TLS, intercepted with the scrim CA (CONNECT tunnels and `https://` absolute-form requests).
    Https,
    /// Plain HTTP, proxied in absolute form.
    Http,
}

impl Scheme {
    /// The port a URL of this scheme uses when it names none.
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Https => 443,
            Scheme::Http => 80,
        }
    }

    /// `"https"` or `"http"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
        }
    }
}

/// Where a request is actually going: the host scrim connects to, not what the request claims.
///
/// For a CONNECT tunnel this is the CONNECT authority; for a plain proxy request the authority of
/// the absolute-form URI. The host is lower-cased and has no trailing dot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Destination {
    /// Scheme used toward the upstream.
    pub scheme: Scheme,
    /// Lower-cased host name or IP literal (IPv6 without brackets).
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Destination {
    /// Builds a destination, normalising the host.
    pub fn new(scheme: Scheme, host: &str, port: u16) -> Self {
        Self {
            scheme,
            host: normalise_host(host),
            port,
        }
    }

    /// Parses an authority (`host`, `host:port`, `[v6]:port`) with `scheme`'s default port.
    pub fn from_authority(scheme: Scheme, authority: &str) -> Option<Self> {
        let (host, port) = split_host_port(authority)?;
        let port = match port {
            Some(p) => p,
            None => scheme.default_port(),
        };
        if host.is_empty() {
            return None;
        }
        Some(Self::new(scheme, host, port))
    }

    /// `host:port`, with IPv6 hosts bracketed.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme.as_str(), self.authority())
    }
}

fn normalise_host(host: &str) -> String {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    let h = h.strip_suffix('.').unwrap_or(h);
    h.to_ascii_lowercase()
}

/// Splits `host[:port]` and `[v6][:port]`. Returns `None` on a malformed port.
pub(crate) fn split_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        if after.is_empty() {
            return Some((host, None));
        }
        let port = after.strip_prefix(':')?.parse().ok()?;
        return Some((host, Some(port)));
    }
    match authority.rsplit_once(':') {
        // A bare IPv6 address without brackets has several colons and no port.
        Some((h, _)) if h.contains(':') => Some((authority, None)),
        Some((h, p)) => Some((h, Some(p.parse().ok()?))),
        None => Some((authority, None)),
    }
}

/// A host a credential may be sent to.
///
/// Forms: `api.example.com` (exactly that host), `*.example.com` (any host below `example.com`,
/// not `example.com` itself), an IP literal, each optionally followed by `:port` or `:*`. Without a
/// port the pattern matches only the scheme's default port, so `api.example.com` does not cover
/// `api.example.com:8443`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPattern {
    suffix_wildcard: bool,
    host: String,
    port: PortPattern,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PortPattern {
    Default,
    Any,
    Exact(u16),
}

/// A host pattern that could not be parsed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid host pattern `{pattern}`: {reason}")]
pub struct HostPatternError {
    /// The pattern as written.
    pub pattern: String,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl HostPattern {
    /// Parses a pattern, see the type documentation for the accepted forms.
    pub fn parse(pattern: &str) -> Result<Self, HostPatternError> {
        let err = |reason| HostPatternError {
            pattern: pattern.to_owned(),
            reason,
        };
        let p = pattern.trim();
        if p.is_empty() {
            return Err(err("empty"));
        }
        if p.contains("://") || p.contains('/') {
            return Err(err("a host pattern names a host, not a URL"));
        }
        let (host_part, port) = if let Some(h) = p.strip_suffix(":*") {
            (h, PortPattern::Any)
        } else {
            match split_host_port(p) {
                Some((h, Some(port))) => (h, PortPattern::Exact(port)),
                Some((h, None)) => (h, PortPattern::Default),
                None => return Err(err("malformed port")),
            }
        };
        let host_part = host_part.trim_start_matches('[').trim_end_matches(']');
        let (suffix_wildcard, host) = match host_part.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, host_part),
        };
        if host.is_empty() {
            return Err(err("empty host"));
        }
        if host.contains('*') {
            return Err(err("`*` is only allowed as the first label"));
        }
        if !host.is_ascii() {
            return Err(err("non-ASCII host, write it in punycode"));
        }
        if suffix_wildcard && host.parse::<IpAddr>().is_ok() {
            return Err(err("wildcards do not apply to IP addresses"));
        }
        if suffix_wildcard && !host.contains('.') {
            return Err(err("a wildcard needs at least two labels after `*.`"));
        }
        Ok(Self {
            suffix_wildcard,
            host: normalise_host(host),
            port,
        })
    }

    /// Whether `dest` is covered by this pattern.
    pub fn matches(&self, dest: &Destination) -> bool {
        let port_ok = match self.port {
            PortPattern::Default => dest.port == dest.scheme.default_port(),
            PortPattern::Any => true,
            PortPattern::Exact(p) => dest.port == p,
        };
        if !port_ok {
            return false;
        }
        if self.suffix_wildcard {
            dest.host.len() > self.host.len() + 1
                && dest.host.ends_with(&self.host)
                && dest.host.as_bytes()[dest.host.len() - self.host.len() - 1] == b'.'
        } else {
            dest.host == self.host
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.suffix_wildcard {
            f.write_str("*.")?;
        }
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            f.write_str(&self.host)?;
        }
        match self.port {
            PortPattern::Default => Ok(()),
            PortPattern::Any => f.write_str(":*"),
            PortPattern::Exact(p) => write!(f, ":{p}"),
        }
    }
}

/// Glob over a URL path: `*` matches any run of bytes including `/`, everything else literally.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
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

    fn d(host: &str, port: u16) -> Destination {
        Destination::new(Scheme::Https, host, port)
    }

    #[test]
    fn exact_host_default_port_only() {
        let p = HostPattern::parse("API.github.com").unwrap();
        assert!(p.matches(&d("api.github.com", 443)));
        assert!(p.matches(&d("api.github.com.", 443)));
        assert!(!p.matches(&d("api.github.com", 8443)));
        assert!(!p.matches(&d("evil-api.github.com", 443)));
        assert!(!p.matches(&d("api.github.com.evil.test", 443)));
        assert!(!p.matches(&Destination::new(Scheme::Http, "api.github.com", 443)));
    }

    #[test]
    fn wildcard_needs_a_label() {
        let p = HostPattern::parse("*.github.com").unwrap();
        assert!(p.matches(&d("api.github.com", 443)));
        assert!(p.matches(&d("a.b.github.com", 443)));
        assert!(!p.matches(&d("github.com", 443)));
        assert!(!p.matches(&d("evilgithub.com", 443)));
    }

    #[test]
    fn ports() {
        assert!(
            HostPattern::parse("h.test:8443")
                .unwrap()
                .matches(&d("h.test", 8443))
        );
        assert!(
            !HostPattern::parse("h.test:8443")
                .unwrap()
                .matches(&d("h.test", 443))
        );
        assert!(
            HostPattern::parse("h.test:*")
                .unwrap()
                .matches(&d("h.test", 1))
        );
        assert!(
            HostPattern::parse("[::1]:9000")
                .unwrap()
                .matches(&d("::1", 9000))
        );
        assert!(
            HostPattern::parse("127.0.0.1:9000")
                .unwrap()
                .matches(&d("127.0.0.1", 9000))
        );
    }

    #[test]
    fn rejects_bad_patterns() {
        for bad in [
            "",
            "https://x.test",
            "x.test/path",
            "a.*.test",
            "*.com",
            "*.1.2.3.4",
            "h:abc",
            "bücher.de",
        ] {
            assert!(HostPattern::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn authority_parsing() {
        let x = Destination::from_authority(Scheme::Https, "Example.COM:8443").unwrap();
        assert_eq!((x.host.as_str(), x.port), ("example.com", 8443));
        let x = Destination::from_authority(Scheme::Https, "[::1]:1").unwrap();
        assert_eq!((x.host.as_str(), x.port), ("::1", 1));
        assert_eq!(x.authority(), "[::1]:1");
        let x = Destination::from_authority(Scheme::Http, "h.test").unwrap();
        assert_eq!(x.port, 80);
        assert!(Destination::from_authority(Scheme::Http, "h.test:99999").is_none());
    }

    #[test]
    fn globs() {
        assert!(glob_match("/repos/*", "/repos/a/b"));
        assert!(glob_match("/v1/*/items", "/v1/x/items"));
        assert!(!glob_match("/v1/*/items", "/v1/x/other"));
        assert!(glob_match("/exact", "/exact"));
        assert!(!glob_match("/exact", "/exact/more"));
        assert!(glob_match("*", ""));
    }
}
