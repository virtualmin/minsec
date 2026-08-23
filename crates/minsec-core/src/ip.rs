//! IP parsing and normalisation into ban keys.

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv6Addr};

/// Parse an address as it appears in a log line. Accepts IPv4, IPv6, and
/// IPv4-mapped IPv6 (`::ffff:1.2.3.4`, which is normalised to IPv4).
pub fn parse_log_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim_matches(|c| c == '[' || c == ']');
    let ip: IpAddr = s.parse().ok()?;
    Some(normalize(ip))
}

pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Reduce an address to the network we track and ban. IPv4 is always a /32;
/// IPv6 is truncated to `v6_prefix` (default /64).
pub fn to_key(ip: IpAddr, v6_prefix: u8) -> IpNet {
    match ip {
        IpAddr::V4(a) => IpNet::V4(Ipv4Net::new(a, 32).expect("valid /32")),
        IpAddr::V6(a) => {
            let p = v6_prefix.min(128);
            let net = Ipv6Net::new(a, p).expect("valid prefix").trunc();
            IpNet::V6(net)
        }
    }
}

/// Render a key for `nft`: a bare address for host routes, CIDR otherwise.
pub fn key_to_nft(net: &IpNet) -> String {
    match net {
        IpNet::V4(n) if n.prefix_len() == 32 => n.addr().to_string(),
        IpNet::V6(n) if n.prefix_len() == 128 => n.addr().to_string(),
        n => n.to_string(),
    }
}

pub fn is_loopback_or_unspecified(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback() || a.is_unspecified(),
        IpAddr::V6(a) => a.is_loopback() || a == Ipv6Addr::UNSPECIFIED,
    }
}

/// Addresses configured on local interfaces (so we never ban ourselves).
pub fn local_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    // Portable enough for Linux and the BSDs; avoids a netlink dependency.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                let sa = &*ifa.ifa_addr;
                match sa.sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(u32::from_be(sin.sin_addr.s_addr).into()));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapped_v4() {
        assert_eq!(
            parse_log_ip("::ffff:10.1.2.3").unwrap(),
            "10.1.2.3".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            parse_log_ip("[2001:db8::1]").unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        assert!(parse_log_ip("999.1.1.1").is_none());
        assert!(parse_log_ip("example.com").is_none());
    }
    #[test]
    fn keys() {
        let k = to_key("2001:db8:1:2:3:4:5:6".parse().unwrap(), 64);
        assert_eq!(k.to_string(), "2001:db8:1:2::/64");
        let k = to_key("10.0.0.1".parse().unwrap(), 64);
        assert_eq!(key_to_nft(&k), "10.0.0.1");
    }
}
