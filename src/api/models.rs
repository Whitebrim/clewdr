//! Model-list endpoints.
//!
//! Both dialects are served from the same configured list of rich
//! [`ModelInfo`] objects ([`crate::config::ClewdrConfig::models`]):
//!
//! * [`api_get_models_anthropic`] — Anthropic `GET /v1/models` shape, the full
//!   `ModelInfo` (capabilities, token limits, dates) served verbatim
//!   (<https://platform.claude.com/docs/en/api/models/list>).
//! * [`api_get_models_openai`] — OpenAI `GET /v1/models` shape, projected from
//!   the same list
//!   (<https://developers.openai.com/api/reference/resources/models/methods/list/>).
//!
//! Neither implements pagination or filtering: the configured list is finite
//! and always returned in full.

use axum::Json;
use serde_json::{Value, json};

use crate::config::{CLEWDR_CONFIG, ModelInfo};

/// Build the OpenAI-compatible `{ object: "list", data: [...] }` body.
fn openai_list(models: &[ModelInfo]) -> Value {
    let data: Vec<Value> = models
        .iter()
        .map(|m| {
            json!({
                "id": m.id,
                "object": "model",
                "created": m.created_unix(),
                "owned_by": "clewdr",
            })
        })
        .collect();
    json!({
        "object": "list",
        "data": data,
    })
}

/// Build the Anthropic-compatible `{ data: [...], first_id, last_id, has_more }`
/// body, serving each `ModelInfo` verbatim. `has_more` is always `false` since
/// the list is finite and unpaginated.
fn anthropic_list(models: &[ModelInfo]) -> Value {
    let data = serde_json::to_value(models).unwrap_or_else(|_| Value::Array(Vec::new()));
    json!({
        "data": data,
        "first_id": models.first().map(|m| m.id.clone()),
        "last_id": models.last().map(|m| m.id.clone()),
        "has_more": false,
    })
}

/// OpenAI-compatible model list (`GET /openai/v1/models`).
pub async fn api_get_models_openai() -> Json<Value> {
    Json(openai_list(&CLEWDR_CONFIG.load().models))
}

/// Anthropic-compatible model list (`GET /anthropic/v1/models`).
pub async fn api_get_models_anthropic() -> Json<Value> {
    Json(anthropic_list(&CLEWDR_CONFIG.load().models))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_models;

    #[test]
    fn openai_shape_matches_spec() {
        let models = default_models();
        let v = openai_list(&models);
        assert_eq!(v["object"], "list");
        let data = v["data"].as_array().unwrap();
        assert_eq!(data.len(), models.len());
        assert_eq!(data[0]["id"], "claude-opus-4-8");
        assert_eq!(data[0]["object"], "model");
        assert_eq!(data[0]["owned_by"], "clewdr");
        // created is a real unix timestamp derived from created_at
        assert!(data[0]["created"].as_i64().unwrap() > 1_700_000_000);
        // no Anthropic-only fields leak in
        assert!(data[0].get("type").is_none());
        assert!(data[0].get("capabilities").is_none());
    }

    #[test]
    fn anthropic_shape_reproduces_full_schema() {
        let models = default_models();
        let v = anthropic_list(&models);
        let data = v["data"].as_array().unwrap();
        assert_eq!(data.len(), models.len());

        // envelope
        assert_eq!(v["first_id"], "claude-opus-4-8");
        assert_eq!(v["last_id"], "claude-opus-4-1-20250805");
        assert_eq!(v["has_more"], false);

        // first entry reproduced verbatim (opus-4-8)
        let m = &data[0];
        assert_eq!(m["type"], "model");
        assert_eq!(m["id"], "claude-opus-4-8");
        assert_eq!(m["display_name"], "Claude Opus 4.8");
        assert_eq!(m["created_at"], "2026-05-28T00:00:00Z");
        assert_eq!(m["max_input_tokens"], 1_000_000);
        assert_eq!(m["max_tokens"], 128_000);
        // capabilities tree
        assert_eq!(m["capabilities"]["batch"]["supported"], true);
        assert_eq!(m["capabilities"]["effort"]["xhigh"]["supported"], true);
        assert_eq!(m["capabilities"]["thinking"]["supported"], true);
        assert_eq!(m["capabilities"]["thinking"]["types"]["adaptive"]["supported"], true);
        assert_eq!(m["capabilities"]["thinking"]["types"]["enabled"]["supported"], false);
        assert_eq!(
            m["capabilities"]["context_management"]["compact_20260112"]["supported"],
            true
        );

        // a model with reduced capabilities (haiku-4-5)
        let haiku = data
            .iter()
            .find(|m| m["id"] == "claude-haiku-4-5-20251001")
            .unwrap();
        assert_eq!(haiku["capabilities"]["code_execution"]["supported"], false);
        assert_eq!(haiku["capabilities"]["effort"]["supported"], false);
        assert_eq!(haiku["capabilities"]["effort"]["high"]["supported"], false);
        assert_eq!(haiku["max_tokens"], 64_000);

        // no OpenAI-only fields leak in
        assert!(m.get("object").is_none());
        assert!(m.get("owned_by").is_none());
    }

    #[test]
    fn empty_list_has_null_cursors() {
        let v = anthropic_list(&[]);
        assert_eq!(v["data"].as_array().unwrap().len(), 0);
        assert!(v["first_id"].is_null());
        assert!(v["last_id"].is_null());
        assert_eq!(v["has_more"], false);

        let o = openai_list(&[]);
        assert_eq!(o["object"], "list");
        assert_eq!(o["data"].as_array().unwrap().len(), 0);
    }
}
