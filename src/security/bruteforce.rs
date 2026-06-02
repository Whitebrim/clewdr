use std::{
    net::IpAddr,
    sync::LazyLock,
    time::{Duration, Instant},
};

use axum::extract::ConnectInfo;
use dashmap::DashMap;

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

pub fn extract_client_ip(parts: &axum::http::request::Parts) -> Option<IpAddr> {
    if let Some(ip) = parts
        .headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
    {
        return Some(ip);
    }
    if let Some(ip) = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
    {
        return Some(ip);
    }
    parts
        .extensions
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
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
}
