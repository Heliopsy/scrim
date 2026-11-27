// SPDX-License-Identifier: AGPL-3.0-only

//! Which addresses a fetch of a remote attachment may connect to.
//!
//! Only public unicast addresses, unless `redaction.remote-attachments-allowed-networks` names
//! the network. Refused: unspecified, loopback, private (RFC 1918, unique local), shared
//! (100.64/10), link-local (which holds the cloud metadata services at 169.254.169.254 and
//! `fd00:ec2::254`), documentation and benchmarking ranges, multicast, broadcast and reserved
//! ranges, and IPv6 forms that embed an IPv4 address (mapped, 6to4, NAT64) when that address is
//! refused. scrim's own listener addresses are refused whatever the setting says.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An address range, `addr/prefix` or a single address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

/// A network that does not parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not an address or address/prefix")]
pub struct BadNetwork;

impl FromStr for Network {
    type Err = BadNetwork;

    fn from_str(s: &str) -> Result<Self, BadNetwork> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().map_err(|_| BadNetwork)?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.parse::<u8>().map_err(|_| BadNetwork)?,
            None => max,
        };
        if prefix > max {
            return Err(BadNetwork);
        }
        Ok(Self { addr, prefix })
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Network {
    /// Whether `ip` is in the network. An IPv4-mapped IPv6 address counts as its IPv4 address.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, canonical(ip)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                prefix_eq(&n.octets(), &a.octets(), usize::from(self.prefix))
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                prefix_eq(&n.octets(), &a.octets(), usize::from(self.prefix))
            }
            _ => false,
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], bits: usize) -> bool {
    let whole = bits / 8;
    if a.get(..whole) != b.get(..whole) {
        return false;
    }
    let rest = bits % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    match (a.get(whole), b.get(whole)) {
        (Some(x), Some(y)) => x & mask == y & mask,
        _ => false,
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Whether a fetch may connect to `ip`.
pub(crate) fn permitted(ip: IpAddr, allowed: &[Network]) -> bool {
    let ip = canonical(ip);
    if scrim_dns::is_self(ip) {
        return false;
    }
    is_public(ip) || allowed.iter().any(|n| n.contains(ip))
}

/// Public unicast: not in any special-purpose range that should never be reached from outside.
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(o[0] == 0                                     // this network
        || o[0] == 10                               // private
        || (o[0] == 100 && (o[1] & 0xc0) == 64)     // shared address space
        || o[0] == 127                              // loopback
        || (o[0] == 169 && o[1] == 254)             // link-local, metadata services
        || (o[0] == 172 && (o[1] & 0xf0) == 16)     // private
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)  // IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)  // documentation
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 6to4 relay anycast
        || (o[0] == 192 && o[1] == 168)             // private
        || (o[0] == 198 && (o[1] & 0xfe) == 18)     // benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // documentation
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // documentation
        || o[0] >= 224) // multicast, reserved, broadcast
}

fn public_v6(addr: Ipv6Addr) -> bool {
    let seg = addr.segments();
    if addr.is_unspecified() || addr.is_loopback() {
        return false;
    }
    let embedded = |hi: u16, lo: u16| {
        let [b0, b1] = hi.to_be_bytes();
        let [b2, b3] = lo.to_be_bytes();
        public_v4(Ipv4Addr::new(b0, b1, b2, b3))
    };
    match seg[0] {
        // IPv4-compatible (deprecated) and other ::/8 forms.
        0x0000 => false,
        // NAT64 well-known prefix 64:ff9b::/96 carries an IPv4 address; 64:ff9b:1::/48 is local.
        0x0064 if seg[1] == 0xff9b => {
            seg[2] == 0 && seg[3..6] == [0, 0, 0] && embedded(seg[6], seg[7])
        }
        // Discard-only 100::/64.
        0x0100 if seg[1..4] == [0, 0, 0] => false,
        // Teredo 2001::/32 (obfuscated IPv4), ORCHID and documentation 2001:db8::/32.
        0x2001 if seg[1] == 0 || seg[1] == 0x0db8 || (seg[1] & 0xfff0) == 0x0010 => false,
        // 6to4 2002::/16 carries an IPv4 address.
        0x2002 => embedded(seg[1], seg[2]),
        // Unique local fc00::/7 (fd00:ec2::254 is the AWS metadata service), link-local
        // fe80::/10, site-local fec0::/10, multicast ff00::/8.
        x if (x & 0xfe00) == 0xfc00 || (x & 0xffc0) == 0xfe80 || (x & 0xffc0) == 0xfec0 => false,
        x if (x & 0xff00) == 0xff00 => false,
        // Global unicast is 2000::/3; anything else is unassigned.
        x => (x & 0xe000) == 0x2000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn refuses_special_ranges() {
        for a in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "fd00:ec2::254",
            "fe80::1",
            "ff02::1",
            "64:ff9b::a9fe:a9fe",
            "2002:c0a8:0101::1",
            "2001:db8::1",
            "2001::1",
        ] {
            assert!(!is_public(ip(a)), "{a} counted as public");
            assert!(!permitted(ip(a), &[]), "{a} permitted");
        }
    }

    #[test]
    fn permits_public_addresses() {
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:0808:0808::1",
        ] {
            assert!(is_public(ip(a)), "{a} not public");
        }
    }

    #[test]
    fn allowed_networks_open_private_ranges() {
        let allow: Vec<Network> = vec!["127.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()];
        assert!(permitted(ip("127.0.0.1"), &allow));
        assert!(permitted(ip("::ffff:127.0.0.9"), &allow));
        assert!(permitted(ip("fd00:ec2::254"), &allow));
        assert!(!permitted(ip("10.0.0.1"), &allow));
        assert!(!permitted(ip("169.254.169.254"), &allow));
    }

    #[test]
    fn parses_networks() {
        assert_eq!(
            "10.0.0.0/8".parse::<Network>().unwrap().to_string(),
            "10.0.0.0/8"
        );
        assert_eq!("::1".parse::<Network>().unwrap().to_string(), "::1/128");
        let n: Network = "172.16.0.0/12".parse().unwrap();
        assert!(n.contains(ip("172.20.1.1")));
        assert!(!n.contains(ip("172.32.0.1")));
        for bad in ["", "10.0.0.0/33", "::/129", "example.com", "10.0.0.0/x"] {
            assert!(bad.parse::<Network>().is_err(), "{bad}");
        }
    }
}
