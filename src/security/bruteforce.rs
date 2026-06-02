use std::{
    net::{IpAddr, SocketAddr},
    sync::LazyLock,
    time::{Duration, Instant},
};

use axum::extract::ConnectInfo;
use dashmap::DashMap;
use ipnet::IpNet;

use crate::config::CLEWDR_CONFIG;

use super::ip_in_nets;

#[derive(Clone)]
struct AttemptState {
    count: u32,
    locked_until: Option<Instant>,
}

static BRUTEFORCE_STATE: LazyLock<DashMap<IpAddr, AttemptState>> =
    LazyLock::new(DashMap::new);

fn lockout_duration(count: u32) -> Option<Duration> {
    match count {
        0..5 => None,
        5..10 => Some(Duration::from_secs(300)),
        10..20 => Some(Duration::from_secs(3600)),
        20..50 => Some(Duration::from_secs(86400)),
        _ => Some(Duration::from_secs(365 * 86400)),
    }
}

pub fn check_bruteforce(ip: IpAddr) -> Result<(), Duration> {
    if let Some(state) = BRUTEFORCE_STATE.get(&ip) {
        if let Some(locked_until) = state.locked_until {
            let now = Instant::now();
            if now < locked_until {
                return Err(locked_until - now);
            }
        }
    }
    Ok(())
}

pub fn record_auth_failure(ip: IpAddr) {
    BRUTEFORCE_STATE
        .entry(ip)
        .and_modify(|state| {
            state.count += 1;
            state.locked_until = lockout_duration(state.count).map(|d| Instant::now() + d);
        })
        .or_insert_with(|| {
            let count = 1;
            AttemptState {
                count,
                locked_until: lockout_duration(count).map(|d| Instant::now() + d),
            }
        });
}

pub fn record_auth_success(ip: IpAddr) {
    BRUTEFORCE_STATE.remove(&ip);
}

/// Determine the real client IP for a request.
///
/// Forwarding headers (`X-Real-IP` / `X-Forwarded-For`) are attacker-controlled
/// and only trusted when the request's TCP peer is a configured trusted proxy
/// (see [`crate::config::ClewdrConfig::trusted_proxies`]). A direct connection
/// from an untrusted peer uses the TCP source address and ignores the headers,
/// so a client hitting the server directly cannot spoof its IP to dodge the
/// brute-force throttle or the IP allowlist (Bug C).
pub fn extract_client_ip(parts: &axum::http::request::Parts) -> Option<IpAddr> {
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    let cfg = CLEWDR_CONFIG.load();
    let trusted = &cfg.trusted_proxies;

    match peer {
        // Behind a trusted proxy: believe the forwarding headers, falling back
        // to the proxy's own address if they are absent/unparseable.
        Some(peer_ip) if ip_in_nets(peer_ip, trusted) => {
            client_ip_from_headers(parts, trusted).or(Some(peer_ip))
        }
        // Direct, untrusted connection: trust only the real TCP source.
        Some(peer_ip) => Some(peer_ip),
        // No ConnectInfo available (e.g. unit tests): best-effort headers.
        None => client_ip_from_headers(parts, trusted),
    }
}

/// Extract a client IP from forwarding headers. Prefers `X-Real-IP` (set by the
/// proxy to its immediate client); otherwise takes the right-most address in
/// `X-Forwarded-For` that is not itself a trusted proxy (the real client when
/// the chain is `client, proxy1, proxy2, ...`).
fn client_ip_from_headers(parts: &axum::http::request::Parts, trusted: &[IpNet]) -> Option<IpAddr> {
    if let Some(ip) = parts
        .headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return Some(ip);
    }
    let xff = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())?;
    let chain: Vec<IpAddr> = xff
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect();
    chain
        .iter()
        .rev()
        .find(|ip| !ip_in_nets(**ip, trusted))
        .copied()
        .or_else(|| chain.first().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_no_lockout_under_threshold() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..4 {
            record_auth_failure(ip);
            assert!(check_bruteforce(ip).is_ok());
        }
        BRUTEFORCE_STATE.remove(&ip);
    }

    #[test]
    fn test_lockout_at_5_failures() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for _ in 0..5 {
            record_auth_failure(ip);
        }
        let result = check_bruteforce(ip);
        assert!(result.is_err());
        let retry_after = result.unwrap_err();
        assert!(retry_after.as_secs() <= 300);
        BRUTEFORCE_STATE.remove(&ip);
    }

    #[test]
    fn test_success_clears_state() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        for _ in 0..4 {
            record_auth_failure(ip);
        }
        record_auth_success(ip);
        assert!(check_bruteforce(ip).is_ok());
        assert!(!BRUTEFORCE_STATE.contains_key(&ip));
    }

    #[test]
    fn test_escalation() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        for _ in 0..10 {
            record_auth_failure(ip);
        }
        let result = check_bruteforce(ip);
        assert!(result.is_err());
        let retry_after = result.unwrap_err();
        assert!(retry_after.as_secs() > 300);
        BRUTEFORCE_STATE.remove(&ip);
    }

    #[test]
    fn test_lockout_durations() {
        assert!(lockout_duration(0).is_none());
        assert!(lockout_duration(4).is_none());
        assert_eq!(lockout_duration(5).unwrap().as_secs(), 300);
        assert_eq!(lockout_duration(10).unwrap().as_secs(), 3600);
        assert_eq!(lockout_duration(20).unwrap().as_secs(), 86400);
        assert!(lockout_duration(50).unwrap().as_secs() > 86400);
    }

    fn parts_with(headers: &[(&str, &str)]) -> axum::http::request::Parts {
        let mut b = axum::http::Request::builder();
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn trusted() -> Vec<IpNet> {
        vec![
            "127.0.0.0/8".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ]
    }

    #[test]
    fn header_x_real_ip_preferred() {
        let parts = parts_with(&[("x-real-ip", "1.2.3.4"), ("x-forwarded-for", "9.9.9.9")]);
        assert_eq!(
            client_ip_from_headers(&parts, &trusted()),
            Some("1.2.3.4".parse().unwrap())
        );
    }

    #[test]
    fn header_xff_rightmost_untrusted() {
        // chain: real client, then a trusted proxy hop — the proxy must be skipped
        let parts = parts_with(&[("x-forwarded-for", "1.2.3.4, 10.0.0.5")]);
        assert_eq!(
            client_ip_from_headers(&parts, &trusted()),
            Some("1.2.3.4".parse().unwrap())
        );
    }

    #[test]
    fn header_xff_two_untrusted_takes_rightmost() {
        let parts = parts_with(&[("x-forwarded-for", "1.2.3.4, 5.6.7.8")]);
        assert_eq!(
            client_ip_from_headers(&parts, &trusted()),
            Some("5.6.7.8".parse().unwrap())
        );
    }

    #[test]
    fn header_xff_all_trusted_falls_back_to_leftmost() {
        let parts = parts_with(&[("x-forwarded-for", "10.0.0.1, 127.0.0.1")]);
        assert_eq!(
            client_ip_from_headers(&parts, &trusted()),
            Some("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn header_none_without_forwarding_headers() {
        let parts = parts_with(&[]);
        assert_eq!(client_ip_from_headers(&parts, &trusted()), None);
    }

    #[test]
    fn ip_in_nets_empty_matches_nothing() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!ip_in_nets(ip, &[]));
        assert!(ip_in_nets(ip, &["1.2.3.0/24".parse().unwrap()]));
    }
}
