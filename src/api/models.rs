//! Model-list endpoints.
//!
//! Two dialects are served from the same configured model list
//! ([`crate::config::ClewdrConfig::models`]):
//!
//! * [`api_get_models_openai`] — OpenAI `GET /v1/models` shape
//!   (<https://developers.openai.com/api/reference/resources/models/methods/list/>)
//! * [`api_get_models_anthropic`] — Anthropic `GET /v1/models` shape
//!   (<https://platform.claude.com/docs/en/api/models/list>)
//!
//! Neither implements pagination or filtering: the configured list is finite
//! and always returned in full.

use axum::Json;
use serde_json::{Value, json};

use crate::config::CLEWDR_CONFIG;

/// Build the OpenAI-compatible `{ object: "list", data: [...] }` body.
fn openai_list(models: &[String]) -> Value {
    let data: Vec<Value> = models
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "object": "model",
                "created": 0,
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
/// body. `has_more` is always `false` since the list is finite and unpaginated.
fn anthropic_list(models: &[String]) -> Value {
    let data: Vec<Value> = models
        .iter()
        .map(|id| {
            json!({
                "type": "model",
                "id": id,
                "display_name": display_name(id),
                "created_at": created_at(id),
            })
        })
        .collect();
    json!({
        "data": data,
        "first_id": models.first().cloned(),
        "last_id": models.last().cloned(),
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

/// Derive an RFC 3339 `created_at` from an embedded `YYYYMMDD` segment in the
/// model id, falling back to a fixed epoch for dateless (4.6+) ids.
fn created_at(model_id: &str) -> String {
    for part in model_id.split('-') {
        if part.len() == 8 && part.starts_with("20") && part.chars().all(|c| c.is_ascii_digit()) {
            let (y, m, d) = (&part[0..4], &part[4..6], &part[6..8]);
            if let (Ok(mi), Ok(di)) = (m.parse::<u32>(), d.parse::<u32>())
                && (1..=12).contains(&mi)
                && (1..=31).contains(&di)
            {
                return format!("{y}-{m}-{d}T00:00:00Z");
            }
        }
    }
    "2025-01-01T00:00:00Z".to_string()
}

/// Produce a human-readable display name from a model id, e.g.
/// `claude-opus-4-6-1M-thinking` -> `Claude Opus 4 6 1M Thinking`.
fn display_name(model_id: &str) -> String {
    let mut out = String::new();
    for (i, part) in model_id.split('-').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        match part {
            "claude" => out.push_str("Claude"),
            "sonnet" => out.push_str("Sonnet"),
            "opus" => out.push_str("Opus"),
            "haiku" => out.push_str("Haiku"),
            "thinking" => out.push_str("Thinking"),
            "1M" => out.push_str("1M"),
            p if p.len() == 8 && p.chars().all(|c| c.is_ascii_digit()) => {
                out.pop();
                out.push_str(&format!(" ({}-{}-{})", &p[0..4], &p[4..6], &p[6..8]));
            }
            other => out.push_str(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<String> {
        vec![
            "claude-opus-4-8".to_string(),
            "claude-sonnet-4-5-20250929-1M".to_string(),
        ]
    }

    #[test]
    fn openai_shape_matches_spec() {
        let v = openai_list(&sample());
        assert_eq!(v["object"], "list");
        let data = v["data"].as_array().unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0]["id"], "claude-opus-4-8");
        assert_eq!(data[0]["object"], "model");
        assert_eq!(data[0]["owned_by"], "clewdr");
        assert_eq!(data[0]["created"], 0);
        // no Anthropic-only fields leak in
        assert!(data[0].get("type").is_none());
        assert!(data[0].get("display_name").is_none());
    }

    #[test]
    fn anthropic_shape_matches_spec() {
        let v = anthropic_list(&sample());
        let data = v["data"].as_array().unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0]["type"], "model");
        assert_eq!(data[0]["id"], "claude-opus-4-8");
        assert!(data[0]["display_name"].is_string());
        assert!(data[0]["created_at"].is_string());
        // envelope
        assert_eq!(v["first_id"], "claude-opus-4-8");
        assert_eq!(v["last_id"], "claude-sonnet-4-5-20250929-1M");
        assert_eq!(v["has_more"], false);
        // no OpenAI-only fields leak in
        assert!(data[0].get("object").is_none());
    }

    #[test]
    fn empty_list_has_null_cursors() {
        let v = anthropic_list(&[]);
        assert_eq!(v["data"].as_array().unwrap().len(), 0);
        assert!(v["first_id"].is_null());
        assert!(v["last_id"].is_null());
        assert_eq!(v["has_more"], false);
    }

    #[test]
    fn created_at_extracts_embedded_date() {
        assert_eq!(
            created_at("claude-sonnet-4-5-20250929"),
            "2025-09-29T00:00:00Z"
        );
        assert_eq!(
            created_at("claude-sonnet-4-5-20250929-1M-thinking"),
            "2025-09-29T00:00:00Z"
        );
    }

    #[test]
    fn created_at_falls_back_for_dateless_ids() {
        assert_eq!(created_at("claude-opus-4-8"), "2025-01-01T00:00:00Z");
    }

    #[test]
    fn display_name_formats_pieces() {
        assert_eq!(display_name("claude-opus-4-8"), "Claude Opus 4 8");
        assert_eq!(
            display_name("claude-opus-4-6-1M-thinking"),
            "Claude Opus 4 6 1M Thinking"
        );
        assert_eq!(
            display_name("claude-sonnet-4-5-20250929"),
            "Claude Sonnet 4 5 (2025-09-29)"
        );
    }

    #[test]
    fn default_models_are_advertised_in_both_dialects() {
        let models = crate::config::default_models();
        assert!(models.iter().any(|m| m == "claude-opus-4-8"));
        assert!(models.iter().any(|m| m == "claude-haiku-4-5-20251001"));
        // both builders accept the real default list without panicking
        assert_eq!(
            openai_list(&models)["data"].as_array().unwrap().len(),
            models.len()
        );
        assert_eq!(
            anthropic_list(&models)["data"].as_array().unwrap().len(),
            models.len()
        );
    }
}
