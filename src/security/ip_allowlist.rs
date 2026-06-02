use std::net::IpAddr;

use ipnet::IpNet;

/// Whether `ip` falls inside any of `nets`. An empty list matches nothing.
pub fn ip_in_nets(ip: IpAddr, nets: &[IpNet]) -> bool {
    nets.iter().any(|net| net.contains(&ip))
}

/// Allowlist check. An empty allowlist allows all (feature disabled).
pub fn check_ip_allowlist(ip: IpAddr, allowlist: &[IpNet]) -> bool {
    allowlist.is_empty() || ip_in_nets(ip, allowlist)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_empty_allowlist_allows_all() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(check_ip_allowlist(ip, &[]));
    }

    #[test]
    fn test_exact_ip_match() {
        let allowlist: Vec<IpNet> = vec!["192.168.1.1/32".parse().unwrap()];
        assert!(check_ip_allowlist(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            &allowlist
        ));
        assert!(!check_ip_allowlist(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            &allowlist
        ));
    }

    #[test]
    fn test_cidr_range() {
        let allowlist: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(check_ip_allowlist(
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            &allowlist
        ));
        assert!(!check_ip_allowlist(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            &allowlist
        ));
    }

    #[test]
    fn test_ipv6() {
        let allowlist: Vec<IpNet> = vec!["2001:db8::/32".parse().unwrap()];
        assert!(check_ip_allowlist(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            &allowlist
        ));
        assert!(!check_ip_allowlist(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1)),
            &allowlist
        ));
    }

    #[test]
    fn test_multiple_ranges() {
        let allowlist: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
        ];
        assert!(check_ip_allowlist(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            &allowlist
        ));
        assert!(check_ip_allowlist(
            IpAddr::V4(Ipv4Addr::new(172, 20, 1, 1)),
            &allowlist
        ));
        assert!(check_ip_allowlist(
            IpAddr::V4(Ipv4Addr::new(192, 168, 5, 5)),
            &allowlist
        ));
        assert!(!check_ip_allowlist(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            &allowlist
        ));
    }
}
