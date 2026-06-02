use std::net::IpAddr;

use axum::extract::FromRequestParts;
use axum_auth::AuthBearer;
use tracing::warn;

use crate::{
    config::CLEWDR_CONFIG,
    error::ClewdrError,
    security::{check_bruteforce, extract_client_ip, record_auth_failure, record_auth_success},
};

fn enforce_bruteforce(
    parts: &axum::http::request::Parts,
) -> Result<Option<IpAddr>, ClewdrError> {
    let ip = extract_client_ip(parts);
    if let Some(ip) = ip {
        if let Err(duration) = check_bruteforce(ip) {
            return Err(ClewdrError::TooManyAuthAttempts {
                retry_after_secs: duration.as_secs().max(1),
            });
        }
    }
    Ok(ip)
}

pub struct RequireAdminAuth;
impl<S> FromRequestParts<S> for RequireAdminAuth
where
    S: Send + Sync,
{
    type Rejection = ClewdrError;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip = enforce_bruteforce(parts)?;

        let AuthBearer(key) = AuthBearer::from_request_parts(parts, &())
            .await
            .map_err(|_| ClewdrError::InvalidAuth)?;
        if !CLEWDR_CONFIG.load().admin_auth(&key) {
            warn!("Invalid admin key");
            if let Some(ip) = ip {
                record_auth_failure(ip);
            }
            return Err(ClewdrError::InvalidAuth);
        }
        if let Some(ip) = ip {
            record_auth_success(ip);
        }
        Ok(Self)
    }
}

pub struct RequireBearerAuth;
impl<S> FromRequestParts<S> for RequireBearerAuth
where
    S: Send + Sync,
{
    type Rejection = ClewdrError;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip = enforce_bruteforce(parts)?;

        let AuthBearer(key) = AuthBearer::from_request_parts(parts, &())
            .await
            .map_err(|_| ClewdrError::InvalidAuth)?;
        if !CLEWDR_CONFIG.load().user_auth(&key) {
            warn!("Invalid Bearer key");
            if let Some(ip) = ip {
                record_auth_failure(ip);
            }
            return Err(ClewdrError::InvalidAuth);
        }
        if let Some(ip) = ip {
            record_auth_success(ip);
        }
        Ok(Self)
    }
}

pub struct RequireFlexibleAuth;
impl<S> FromRequestParts<S> for RequireFlexibleAuth
where
    S: Send + Sync,
{
    type Rejection = ClewdrError;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip = enforce_bruteforce(parts)?;

        if let Some(key) = parts.headers.get("x-api-key").and_then(|v| v.to_str().ok())
            && CLEWDR_CONFIG.load().user_auth(key)
        {
            if let Some(ip) = ip {
                record_auth_success(ip);
            }
            return Ok(Self);
        }

        if let Ok(AuthBearer(key)) = AuthBearer::from_request_parts(parts, &()).await
            && CLEWDR_CONFIG.load().user_auth(&key)
        {
            if let Some(ip) = ip {
                record_auth_success(ip);
            }
            return Ok(Self);
        }

        warn!("No valid authentication found (tried x-api-key and Bearer)");
        if let Some(ip) = ip {
            record_auth_failure(ip);
        }
        Err(ClewdrError::InvalidAuth)
    }
}
