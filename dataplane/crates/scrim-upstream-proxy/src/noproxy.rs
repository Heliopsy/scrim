// SPDX-License-Identifier: AGPL-3.0-only

//! The `NO_PROXY` list, matched exactly as Go's `golang.org/x/net/http/httpproxy` matches it, so
//! the control plane and the data plane send the same destinations to the upstream proxy.
//!
//! Entries, case-insensitive and comma or list separated:
//!
//! - `*` matches every destination.
//! - An IP address matches that address; with `:port`, only that port.
//! - A CIDR range (`10.0.0.0/8`, `fd00::/8`) matches every address in it, on any port.
//! - A host name matches that name and its subdomains (`example.com` matches `example.com` and
//!   `api.example.com`); with a leading `.` or `*.` only its subdomains. With `:port`, only that
//!   port.
//!
//! Unlike Go, loopback is not implicit here: the control plane puts it in the list it sends.

use std::net::IpAddr;

/// A parsed `NO_PROXY` list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoProxy {
    all: bool,
    ips: Vec<(IpAddr, Option<u16>)>,
    cidrs: Vec<(IpAddr, u8)>,
    domains: Vec<Domain>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Domain {
    /// Always starts with `.`.
    suffix: String,
    /// The entry had no leading dot: the name itself matches too.
    exact_too: bool,
    port: Option<u16>,
}

/// An entry that is not a valid `NO_PROXY` entry.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("no-proxy entry {0:?} is not a host, address or CIDR range")]
pub struct BadEntry(pub String);

impl NoProxy {
    /// Parses the entries. Each may itself hold several, comma separated; empty ones are skipped.
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> Result<Self, BadEntry> {
        let mut out = Self::default();
        for raw in entries {
            for e in raw.as_ref().split(',') {
                out.add(e)?;
            }
        }
        Ok(out)
    }

    fn add(&mut self, entry: &str) -> Result<(), BadEntry> {
        let e = entry.trim().to_ascii_lowercase();
        if e.is_empty() {
            return Ok(());
        }
        let bad = || BadEntry(entry.trim().to_owned());
        if e == "*" {
            self.all = true;
            return Ok(());
        }
        if let Some((ip, bits)) = e.split_once('/') {
            let ip: IpAddr = ip.parse().map_err(|_| bad())?;
            let bits: u8 = bits.parse().map_err(|_| bad())?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if bits > max {
                return Err(bad());
            }
            self.cidrs.push((ip, bits));
            return Ok(());
        }
        let (host, port) = split_host_port(&e).ok_or_else(bad)?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.ips.push((ip, port));
            return Ok(());
        }
        let host = host.strip_prefix('*').unwrap_or(host);
        if host.is_empty()
            || host == "."
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(bad());
        }
        let (suffix, exact_too) = match host.strip_prefix('.') {
            Some(_) => (host.to_owned(), false),
            None => (format!(".{host}"), true),
        };
        self.domains.push(Domain {
            suffix,
            exact_too,
            port,
        });
        Ok(())
    }

    /// Whether `host` (a name or an address, IPv6 with or without brackets) on `port` is reached
    /// directly rather than through the proxy.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if self.all {
            return true;
        }
        let host = host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self
                .ips
                .iter()
                .any(|(a, p)| *a == ip && p.is_none_or(|p| p == port))
                || self
                    .cidrs
                    .iter()
                    .any(|(net, bits)| in_cidr(ip, *net, *bits));
        }
        self.domains.iter().any(|d| {
            (host.ends_with(&d.suffix) || (d.exact_too && host == d.suffix[1..]))
                && d.port.is_none_or(|p| p == port)
        })
    }
}

/// Splits `host[:port]`, `[v6]:port` or a bare IPv6 address. `None` for a bad port.
fn split_host_port(e: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = e.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        return match tail {
            "" => Some((h, None)),
            t => Some((h, Some(t.strip_prefix(':')?.parse().ok()?))),
        };
    }
    if e.matches(':').count() > 1 {
        // A bare IPv6 address.
        return Some((e, None));
    }
    match e.split_once(':') {
        Some((h, p)) => Some((h, Some(p.parse().ok()?))),
        None => Some((e, None)),
    }
}

fn in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => prefix_eq(&a.octets(), &n.octets(), bits),
        (IpAddr::V6(a), IpAddr::V6(n)) => prefix_eq(&a.octets(), &n.octets(), bits),
        _ => false,
    }
}

fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let full = usize::from(bits / 8);
    if a[..full] != b[..full] {
        return false;
    }
    let rest = bits % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    (a[full] & mask) == (b[full] & mask)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vectors {
        groups: Vec<Group>,
    }

    #[derive(serde::Deserialize)]
    struct Group {
        no_proxy: String,
        cases: Vec<Case>,
    }

    #[derive(serde::Deserialize)]
    struct Case {
        host: String,
        port: u16,
        proxied: bool,
    }

    /// The vectors the Go side (`internal/netproxy`) runs too: both planes agree on every case.
    #[test]
    fn shared_vectors() {
        let v: Vectors = serde_json::from_str(include_str!(
            "../../../../internal/netproxy/testdata/no_proxy_vectors.json"
        ))
        .unwrap();
        let mut n = 0;
        for g in v.groups {
            let np = NoProxy::parse(&[g.no_proxy.as_str()]).unwrap();
            for c in g.cases {
                assert_eq!(
                    !np.matches(&c.host, c.port),
                    c.proxied,
                    "NO_PROXY={:?} host {}:{}",
                    g.no_proxy,
                    c.host,
                    c.port
                );
                n += 1;
            }
        }
        assert!(n > 20, "only {n} cases");
    }

    #[test]
    fn bad_entries() {
        for e in [
            "10.0.0.0/33",
            "host:port",
            "exa mple.com",
            "1.2.3.4/x",
            "[::1",
            "*x*",
        ] {
            assert!(NoProxy::parse(&[e]).is_err(), "{e}");
        }
    }

    #[test]
    fn empty_matches_nothing() {
        let np = NoProxy::parse::<&str>(&[]).unwrap();
        assert!(!np.matches("example.com", 443));
        assert!(!np.matches("127.0.0.1", 443));
    }
}
