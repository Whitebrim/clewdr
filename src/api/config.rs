use axum::Json;
use axum_auth::AuthBearer;
use clewdr_types::ConfigApi;
use serde_json::json;

use super::error::ApiError;
use crate::{
    config::{CLEWDR_CONFIG, ClewdrConfig, HASHED_PLACEHOLDER},
    security::audit,
};

pub async fn api_get_config(AuthBearer(t): AuthBearer) -> Result<Json<ConfigApi>, ApiError> {
    if !CLEWDR_CONFIG.load().admin_auth(&t) {
        return Err(ApiError::unauthorized());
    }

    let api: ConfigApi = CLEWDR_CONFIG.load().as_ref().into();
    Ok(Json(api))
}

pub async fn api_post_config(
    AuthBearer(t): AuthBearer,
    Json(mut c): Json<ConfigApi>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !CLEWDR_CONFIG.load().admin_auth(&t) {
        return Err(ApiError::unauthorized());
    }

    {
        let current = CLEWDR_CONFIG.load();
        if c.password == HASHED_PLACEHOLDER || c.password.is_empty() {
            c.password = current.password().to_string();
        }
        if c.admin_password == HASHED_PLACEHOLDER || c.admin_password.is_empty() {
            c.admin_password = current.admin_password().to_string();
        }
    }

    let c: ClewdrConfig = ClewdrConfig::from(c).validate();
    CLEWDR_CONFIG.rcu(|old_c| {
        let mut new_c = ClewdrConfig::clone(&c);
        new_c.cookie_array = old_c.cookie_array.to_owned();
        new_c.wasted_cookie = old_c.wasted_cookie.to_owned();
        // Model list is managed via clewdr.toml, not the admin UI; preserve it
        // across saves instead of resetting to the default list.
        new_c.models = old_c.models.to_owned();
        new_c
    });
    if let Err(e) = CLEWDR_CONFIG.load().save().await {
        return Err(ApiError::internal(format!("Failed to save config: {}", e)));
    }

    audit("config_save", None, true, None);

    Ok(Json(json!({
        "message": "Config updated successfully",
        "config": ConfigApi::from(&c)
    })))
}
