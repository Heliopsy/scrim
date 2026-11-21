// SPDX-License-Identifier: AGPL-3.0-only

//! Upstream name resolution that never resolves to scrim itself.
//!
//! In DNS override mode (task 15.2) provider names resolve to scrim's SNI listener through
//! `/etc/hosts` or a local resolver. scrim still has to reach the real provider, and the system
//! resolver would hand it its own address back. [`LoopSafeResolver`] resolves through the system
//! resolver first; when an answer contains an address of one of scrim's own SNI listeners
//! ([`add_self_address`]), it asks the upstream name servers directly instead, skipping
//! `/etc/hosts` and the systemd-resolved stub (which serves `/etc/hosts` too), and drops scrim's
//! own addresses from what it returns. A name that only ever resolves to scrim is an error, never
//! a connection back to scrim.

use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::RwLock;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::client::legacy::connect::dns::Name;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static SELF: RwLock<BTreeSet<IpAddr>> = RwLock::new(BTreeSet::new());

/// The resolv.conf files read for upstream name servers, in order. systemd-resolved writes the
/// real upstream servers to the first; the second may only name its stub.
const RESOLV_CONF: [&str; 2] = ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"];

/// Per-server query timeout.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Registers an address one of scrim's own listeners answers on (an SNI listener in DNS override
/// mode). An unspecified address stands for every loopback address of its family.
pub fn add_self_address(ip: IpAddr) {
    if let Ok(mut s) = SELF.write() {
        s.insert(ip);
    }
}

/// Whether `ip` reaches one of scrim's own listeners.
pub fn is_self(ip: IpAddr) -> bool {
    SELF.read().is_ok_and(|s| in_set(&s, ip))
}

fn in_set(s: &BTreeSet<IpAddr>, ip: IpAddr) -> bool {
    if s.contains(&ip) {
        return true;
    }
    let any = match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    ip.is_loopback() && s.contains(&any)
}

/// A resolver for hyper's `HttpConnector` that never answers with scrim's own addresses.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopSafeResolver;

type Addrs = std::vec::IntoIter<SocketAddr>;

impl tower_service::Service<Name> for LoopSafeResolver {
    type Response = Addrs;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Addrs>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let host = name.as_str().to_owned();
        Box::pin(async move { resolve(&host).await.map(Vec::into_iter) })
    }
}

/// Resolves `host` (port 0 in the results), see the crate documentation.
pub async fn resolve(host: &str) -> io::Result<Vec<SocketAddr>> {
    let system: Vec<SocketAddr> = tokio::net::lookup_host((host, 0)).await?.collect();
    if !system.iter().any(|a| is_self(a.ip())) {
        return Ok(system);
    }
    tracing::debug!(
        host,
        "the system resolver answers with scrim's own address; asking the name servers directly"
    );
    let servers = name_servers();
    let direct = resolve_direct(host, &servers).await?;
    let out: Vec<SocketAddr> = direct
        .into_iter()
        .filter(|ip| !is_self(*ip))
        .map(|ip| SocketAddr::new(ip, 0))
        .collect();
    if out.is_empty() {
        return Err(io::Error::other(format!(
            "{host} resolves only to scrim itself; scrim needs the real address (check the name servers in {})",
            RESOLV_CONF.join(" or ")
        )));
    }
    Ok(out)
}

/// The upstream name servers: the first resolv.conf of [`RESOLV_CONF`] that names one which is
/// not a loopback stub.
fn name_servers() -> Vec<SocketAddr> {
    for path in RESOLV_CONF {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let servers = parse_resolv_conf(&text);
        if !servers.is_empty() {
            return servers;
        }
    }
    Vec::new()
}

/// The `nameserver` lines of a resolv.conf, without loopback stubs (they may answer from
/// `/etc/hosts`).
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|l| {
            let l = l.split(['#', ';']).next()?.trim();
            let addr = l.strip_prefix("nameserver")?.trim();
            // A scope suffix (fe80::1%eth0) is not supported by IpAddr; such servers are skipped.
            addr.parse::<IpAddr>().ok()
        })
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

/// Asks each server in turn for A and AAAA records of `host`.
async fn resolve_direct(host: &str, servers: &[SocketAddr]) -> io::Result<Vec<IpAddr>> {
    if servers.is_empty() {
        return Err(io::Error::other(format!(
            "no upstream name server to resolve {host} with (none in {})",
            RESOLV_CONF.join(" or ")
        )));
    }
    let mut last = io::Error::other("no answer");
    for server in servers {
        let mut out = Vec::new();
        let mut answered = false;
        for qtype in [TYPE_A, TYPE_AAAA] {
            match query(host, qtype, *server).await {
                Ok(ips) => {
                    answered = true;
                    out.extend(ips);
                }
                Err(e) => last = e,
            }
        }
        if answered {
            return Ok(out);
        }
    }
    Err(last)
}

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// One query over UDP, repeated over TCP when the answer is truncated.
async fn query(host: &str, qtype: u16, server: SocketAddr) -> io::Result<Vec<IpAddr>> {
    let mut id = [0u8; 2];
    getrandom::fill(&mut id).map_err(|e| io::Error::other(e.to_string()))?;
    let id = u16::from_be_bytes(id);
    let msg = encode_query(id, host, qtype)?;
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    sock.send(&msg).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(QUERY_TIMEOUT, async {
        loop {
            let n = sock.recv(&mut buf).await?;
            // Skip stray datagrams with another ID.
            if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                return Ok::<_, io::Error>(n);
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "name server timed out"))??;
    match parse_answer(&buf[..n], id, qtype) {
        Err(Answer::Truncated) => query_tcp(&msg, id, qtype, server).await,
        Err(Answer::Bad(e)) => Err(io::Error::other(e)),
        Ok(ips) => Ok(ips),
    }
}

async fn query_tcp(msg: &[u8], id: u16, qtype: u16, server: SocketAddr) -> io::Result<Vec<IpAddr>> {
    tokio::time::timeout(QUERY_TIMEOUT, async {
        let mut s = tokio::net::TcpStream::connect(server).await?;
        let len = u16::try_from(msg.len()).map_err(|_| io::Error::other("query too long"))?;
        s.write_all(&len.to_be_bytes()).await?;
        s.write_all(msg).await?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut buf).await?;
        match parse_answer(&buf, id, qtype) {
            Ok(ips) => Ok(ips),
            Err(Answer::Truncated) => Err(io::Error::other("truncated answer over TCP")),
            Err(Answer::Bad(e)) => Err(io::Error::other(e)),
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "name server timed out"))?
}

/// A DNS query for `host` with recursion desired.
pub fn encode_query(id: u16, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 {
        return Err(io::Error::other("invalid host name length"));
    }
    let mut m = Vec::with_capacity(18 + host.len());
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|l| (1..=63).contains(l))
            .ok_or_else(|| io::Error::other("invalid host name label"))?;
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(io::Error::other("invalid character in host name"));
        }
        m.push(len);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(m)
}

/// Why an answer gave no addresses.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// The TC bit is set: ask again over TCP.
    Truncated,
    /// Malformed, or an error code from the server.
    Bad(&'static str),
}

/// The addresses of type `qtype` in a response to query `id`. A name that does not exist
/// (NXDOMAIN) is an empty list.
pub fn parse_answer(m: &[u8], id: u16, qtype: u16) -> Result<Vec<IpAddr>, Answer> {
    let u16_at = |i: usize| -> Result<u16, Answer> {
        m.get(i..i + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or(Answer::Bad("short message"))
    };
    if u16_at(0)? != id {
        return Err(Answer::Bad("answer to another query"));
    }
    let flags = u16_at(2)?;
    if flags & 0x8000 == 0 {
        return Err(Answer::Bad("not a response"));
    }
    if flags & 0x0200 != 0 {
        return Err(Answer::Truncated);
    }
    match flags & 0x000f {
        0 => {}
        3 => return Ok(Vec::new()),
        _ => return Err(Answer::Bad("name server error")),
    }
    let qd = u16_at(4)?;
    let an = u16_at(6)?;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(m, i)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        i = skip_name(m, i)?;
        let rtype = u16_at(i)?;
        let class = u16_at(i + 2)?;
        let rdlen = usize::from(u16_at(i + 8)?);
        let start = i + 10;
        let rdata = m
            .get(start..start + rdlen)
            .ok_or(Answer::Bad("short record"))?;
        if class == CLASS_IN && rtype == qtype {
            match (rtype, rdata.len()) {
                (TYPE_A, 4) => out.push(IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]])),
                (TYPE_AAAA, 16) => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(rdata);
                    out.push(IpAddr::from(b));
                }
                _ => return Err(Answer::Bad("malformed address record")),
            }
        }
        i = start + rdlen;
    }
    Ok(out)
}

/// The offset after the (possibly compressed) name at `i`.
fn skip_name(m: &[u8], mut i: usize) -> Result<usize, Answer> {
    loop {
        let len = *m.get(i).ok_or(Answer::Bad("short name"))?;
        match len {
            0 => return Ok(i + 1),
            l if l & 0xc0 == 0xc0 => {
                m.get(i + 1).ok_or(Answer::Bad("short pointer"))?;
                return Ok(i + 2);
            }
            l if l & 0xc0 != 0 => return Err(Answer::Bad("bad label")),
            l => i += 1 + usize::from(l),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn response(id: u16, flags: u16, qtype: u16, records: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = encode_query(id, "api.example.test", qtype).unwrap();
        m[2..4].copy_from_slice(&flags.to_be_bytes());
        m[6..8].copy_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
        for (t, rdata) in records {
            m.extend_from_slice(&[0xc0, 12]);
            m.extend_from_slice(&t.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&60u32.to_be_bytes());
            m.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    #[test]
    fn parses_a_records_and_skips_cnames() {
        let cname: &[u8] = &[3, b'c', b'd', b'n', 0xc0, 12];
        let m = response(7, 0x8180, TYPE_A, &[(5, cname), (TYPE_A, &[192, 0, 2, 7])]);
        assert_eq!(
            parse_answer(&m, 7, TYPE_A).unwrap(),
            vec![IpAddr::from([192, 0, 2, 7])]
        );
    }

    #[test]
    fn parses_aaaa() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let m = response(9, 0x8180, TYPE_AAAA, &[(TYPE_AAAA, &ip.octets())]);
        assert_eq!(
            parse_answer(&m, 9, TYPE_AAAA).unwrap(),
            vec![IpAddr::V6(ip)]
        );
    }

    #[test]
    fn rejects_wrong_id_truncation_errors_and_garbage() {
        let m = response(1, 0x8180, TYPE_A, &[(TYPE_A, &[192, 0, 2, 1])]);
        assert!(matches!(parse_answer(&m, 2, TYPE_A), Err(Answer::Bad(_))));
        let t = response(1, 0x8380, TYPE_A, &[]);
        assert_eq!(parse_answer(&t, 1, TYPE_A), Err(Answer::Truncated));
        let nx = response(1, 0x8183, TYPE_A, &[]);
        assert_eq!(parse_answer(&nx, 1, TYPE_A), Ok(Vec::new()));
        let fail = response(1, 0x8182, TYPE_A, &[]);
        assert!(parse_answer(&fail, 1, TYPE_A).is_err());
        let mut cut = response(1, 0x8180, TYPE_A, &[(TYPE_A, &[192, 0, 2, 1])]);
        cut.truncate(cut.len() - 2);
        assert!(parse_answer(&cut, 1, TYPE_A).is_err());
        for n in 0..m.len() {
            let _ = parse_answer(&m[..n], 1, TYPE_A);
        }
    }

    #[test]
    fn query_encoding_rejects_bad_names() {
        assert!(encode_query(1, "", TYPE_A).is_err());
        assert!(encode_query(1, "a..b", TYPE_A).is_err());
        assert!(encode_query(1, &"a".repeat(64), TYPE_A).is_err());
        assert!(encode_query(1, "a b.test", TYPE_A).is_err());
        let q = encode_query(0x1234, "api.example.test.", TYPE_A).unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..16], &[3, b'a', b'p', b'i']);
    }

    #[test]
    fn resolv_conf_skips_stubs_and_comments() {
        let s = parse_resolv_conf(
            "# comment\nnameserver 127.0.0.53\nnameserver 192.0.2.53 # isp\nsearch lan\nnameserver ::1\nnameserver 2001:db8::53\n",
        );
        assert_eq!(
            s,
            vec![
                "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8::53]:53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn self_addresses() {
        let me: IpAddr = "127.0.83.1".parse().unwrap();
        assert!(!is_self(me));
        add_self_address(me);
        assert!(is_self(me));
        assert!(!is_self("127.0.0.1".parse().unwrap()));
        let any = BTreeSet::from([IpAddr::V6(Ipv6Addr::UNSPECIFIED)]);
        assert!(in_set(&any, "::1".parse().unwrap()));
        assert!(!in_set(&any, "127.0.0.1".parse().unwrap()));
        assert!(!in_set(&any, "2001:db8::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn names_not_pointing_at_scrim_use_the_system_resolver() {
        let a = resolve("localhost").await.unwrap();
        assert!(a.iter().all(|a| a.ip().is_loopback()));
    }

    /// A name the system resolver maps to scrim is asked of the name servers directly; with a
    /// local fake name server the answer comes from it, never the self address.
    #[tokio::test]
    async fn direct_query_against_a_fake_server() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, from) = server.recv_from(&mut buf).await.unwrap();
                let q = &buf[..n];
                let qtype = u16::from_be_bytes([q[n - 4], q[n - 3]]);
                let mut r = q.to_vec();
                r[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                if qtype == TYPE_A {
                    r[6..8].copy_from_slice(&1u16.to_be_bytes());
                    r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 9]);
                }
                server.send_to(&r, from).await.unwrap();
            }
        });
        let ips = resolve_direct("api.example.test", &[addr]).await.unwrap();
        assert_eq!(ips, vec![IpAddr::from([192, 0, 2, 9])]);
    }
}
