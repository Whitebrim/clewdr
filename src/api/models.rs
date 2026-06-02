use axum::{Json, extract::Query};
use serde::Deserialize;
use serde_json::{Value, json};

use super::error::ApiError;

/// Synthetic model identifiers exposed via `/v1/models`.
///
/// These include the base model ids plus proxy-specific variants (`-thinking`,
/// `-1M`) that the gateway maps to upstream Claude features.
pub const MODEL_LIST: &[&str] = &[
    "claude-3-7-sonnet-20250219",
    "claude-3-7-sonnet-20250219-thinking",
    "claude-sonnet-4-20250514",
    "claude-sonnet-4-20250514-thinking",
    "claude-sonnet-4-20250514-1M",
    "claude-sonnet-4-20250514-1M-thinking",
    "claude-sonnet-4-5-20250929",
    "claude-sonnet-4-5-20250929-thinking",
    "claude-sonnet-4-5-20250929-1M",
    "claude-sonnet-4-5-20250929-1M-thinking",
    "claude-sonnet-4-6",
    "claude-sonnet-4-6-thinking",
    "claude-sonnet-4-6-1M",
    "claude-sonnet-4-6-1M-thinking",
    "claude-opus-4-20250514",
    "claude-opus-4-20250514-thinking",
    "claude-opus-4-1-20250805",
    "claude-opus-4-1-20250805-thinking",
    "claude-opus-4-5-20251101",
    "claude-opus-4-5-20251101-thinking",
    "claude-opus-4-5",
    "claude-opus-4-5-thinking",
    "claude-opus-4-6",
    "claude-opus-4-6-thinking",
    "claude-opus-4-6-1M",
    "claude-opus-4-6-1M-thinking",
];

const DEFAULT_LIMIT: usize = 20;
const MAX_LIMIT: usize = 1000;

/// Query parameters for the Anthropic `/v1/models` list endpoint.
#[derive(Deserialize, Default)]
pub struct ModelsQuery {
    #[serde(default)]
    after_id: Option<String>,
    #[serde(default)]
    before_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

fn cap(supported: bool) -> Value {
    json!({ "supported": supported })
}

fn capabilities_for(model_id: &str) -> Value {
    let thinking = model_id.ends_with("-thinking");
    json!({
        "batch": cap(false),
        "citations": cap(true),
        "code_execution": cap(true),
        "context_management": {
            "clear_thinking_20251015": cap(true),
            "clear_tool_uses_20250919": cap(true),
            "compact_20260112": cap(true),
            "supported": true,
        },
        "effort": {
            "high": cap(true),
            "low": cap(true),
            "max": cap(true),
            "medium": cap(true),
            "xhigh": cap(true),
            "supported": true,
        },
        "image_input": cap(true),
        "pdf_input": cap(true),
        "structured_outputs": cap(true),
        "thinking": {
            "supported": thinking,
            "types": {
                "adaptive": cap(thinking),
                "enabled": cap(thinking),
            }
        }
    })
}

/// Extract a release date from the model id (looks for an 8-digit `YYYYMMDD`
/// segment). Falls back to a fixed epoch for ids without a date stamp.
fn created_at(model_id: &str) -> String {
    for part in model_id.split('-') {
        if part.len() == 8
            && part.starts_with("20")
            && part.chars().all(|c| c.is_ascii_digit())
        {
            let (y, m, d) = (&part[0..4], &part[4..6], &part[6..8]);
            if let (Ok(mi), Ok(di)) = (m.parse::<u32>(), d.parse::<u32>())
                && (1..=12).contains(&mi)
                && (1..=31).contains(&di)
            {
                return format!("{}-{}-{}T00:00:00Z", y, m, d);
            }
        }
    }
    "2025-01-01T00:00:00Z".to_string()
}

fn display_name_for(model_id: &str) -> String {
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

fn model_object(model_id: &str) -> Value {
    let is_1m = model_id.contains("-1M");
    let max_input = if is_1m { 1_000_000 } else { 200_000 };
    json!({
        "type": "model",
        "id": model_id,
        "display_name": display_name_for(model_id),
        "created_at": created_at(model_id),
        "max_input_tokens": max_input,
        "max_tokens": 64_000u32,
        "capabilities": capabilities_for(model_id),
    })
}

/// `GET /v1/models` — Anthropic-compatible model list with cursor pagination.
///
/// Spec: <https://platform.claude.com/docs/en/api/models/list>
pub async fn api_get_models(Query(q): Query<ModelsQuery>) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    if q.after_id.is_some() && q.before_id.is_some() {
        return Err(ApiError::bad_request(
            "after_id and before_id are mutually exclusive",
        ));
    }

    let start = if let Some(ref after) = q.after_id {
        let Some(pos) = MODEL_LIST.iter().position(|m| *m == after) else {
            return Err(ApiError::bad_request(format!(
                "unknown after_id cursor: {after}"
            )));
        };
        pos + 1
    } else if let Some(ref before) = q.before_id {
        let Some(pos) = MODEL_LIST.iter().position(|m| *m == before) else {
            return Err(ApiError::bad_request(format!(
                "unknown before_id cursor: {before}"
            )));
        };
        pos.saturating_sub(limit)
    } else {
        0
    };

    let end = start.saturating_add(limit).min(MODEL_LIST.len());
    let page = if start >= MODEL_LIST.len() {
        &[][..]
    } else {
        &MODEL_LIST[start..end]
    };

    let data: Vec<Value> = page.iter().map(|m| model_object(m)).collect();
    let first_id = page.first().map(|s| Value::String((*s).to_string())).unwrap_or(Value::Null);
    let last_id = page.last().map(|s| Value::String((*s).to_string())).unwrap_or(Value::Null);
    let has_more = end < MODEL_LIST.len();

    Ok(Json(json!({
        "data": data,
        "first_id": first_id,
        "last_id": last_id,
        "has_more": has_more,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_at_extracts_date_in_middle() {
        assert_eq!(
            created_at("claude-3-7-sonnet-20250219"),
            "2025-02-19T00:00:00Z"
        );
        assert_eq!(
            created_at("claude-3-7-sonnet-20250219-thinking"),
            "2025-02-19T00:00:00Z"
        );
    }

    #[test]
    fn created_at_falls_back_when_no_date() {
        assert_eq!(created_at("claude-opus-4-6"), "2025-01-01T00:00:00Z");
    }

    #[test]
    fn display_name_handles_known_pieces() {
        assert_eq!(
            display_name_for("claude-sonnet-4-6-1M-thinking"),
            "Claude Sonnet 4 6 1M Thinking"
        );
        assert_eq!(
            display_name_for("claude-3-7-sonnet-20250219"),
            "Claude 3 7 Sonnet (2025-02-19)"
        );
    }

    #[test]
    fn model_object_has_required_fields() {
        let v = model_object("claude-opus-4-6");
        assert_eq!(v["type"], "model");
        assert_eq!(v["id"], "claude-opus-4-6");
        assert!(v["display_name"].is_string());
        assert!(v["created_at"].is_string());
        assert_eq!(v["max_input_tokens"], 200_000);
        assert!(v["capabilities"]["thinking"]["supported"] == false);
    }

    #[test]
    fn one_m_models_advertise_1m_context() {
        let v = model_object("claude-sonnet-4-6-1M");
        assert_eq!(v["max_input_tokens"], 1_000_000);
    }

    #[test]
    fn thinking_models_advertise_thinking_capability() {
        let v = model_object("claude-opus-4-6-thinking");
        assert_eq!(v["capabilities"]["thinking"]["supported"], true);
        assert_eq!(
            v["capabilities"]["thinking"]["types"]["enabled"]["supported"],
            true
        );
    }

    #[tokio::test]
    async fn default_list_returns_first_page() {
        let resp = api_get_models(Query(ModelsQuery::default())).await.unwrap();
        let body = resp.0;
        let data = body["data"].as_array().unwrap();
        assert_eq!(data.len(), DEFAULT_LIMIT);
        assert_eq!(body["has_more"], true);
        assert_eq!(body["first_id"], MODEL_LIST[0]);
        assert_eq!(body["last_id"], MODEL_LIST[DEFAULT_LIMIT - 1]);
    }

    #[tokio::test]
    async fn limit_clamps_and_paginates() {
        let resp = api_get_models(Query(ModelsQuery {
            limit: Some(5),
            ..Default::default()
        }))
        .await
        .unwrap();
        let body = resp.0;
        assert_eq!(body["data"].as_array().unwrap().len(), 5);
        assert_eq!(body["has_more"], true);
        assert_eq!(body["last_id"], MODEL_LIST[4]);
    }

    #[tokio::test]
    async fn after_id_pages_forward() {
        let resp = api_get_models(Query(ModelsQuery {
            after_id: Some(MODEL_LIST[4].to_string()),
            limit: Some(3),
            ..Default::default()
        }))
        .await
        .unwrap();
        let body = resp.0;
        let data = body["data"].as_array().unwrap();
        assert_eq!(data.len(), 3);
        assert_eq!(data[0]["id"], MODEL_LIST[5]);
        assert_eq!(body["first_id"], MODEL_LIST[5]);
    }

    #[tokio::test]
    async fn before_id_pages_backward() {
        let resp = api_get_models(Query(ModelsQuery {
            before_id: Some(MODEL_LIST[10].to_string()),
            limit: Some(3),
            ..Default::default()
        }))
        .await
        .unwrap();
        let body = resp.0;
        let data = body["data"].as_array().unwrap();
        assert_eq!(data.len(), 3);
        assert_eq!(data[0]["id"], MODEL_LIST[7]);
        assert_eq!(data[2]["id"], MODEL_LIST[9]);
    }

    #[tokio::test]
    async fn last_page_reports_has_more_false() {
        let total = MODEL_LIST.len();
        let resp = api_get_models(Query(ModelsQuery {
            after_id: Some(MODEL_LIST[total - 2].to_string()),
            limit: Some(10),
            ..Default::default()
        }))
        .await
        .unwrap();
        let body = resp.0;
        let data = body["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(body["has_more"], false);
        assert_eq!(body["last_id"], MODEL_LIST[total - 1]);
    }

    #[tokio::test]
    async fn unknown_cursor_returns_400() {
        let result = api_get_models(Query(ModelsQuery {
            after_id: Some("nonexistent".to_string()),
            ..Default::default()
        }))
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mutually_exclusive_cursors_return_400() {
        let result = api_get_models(Query(ModelsQuery {
            after_id: Some(MODEL_LIST[0].to_string()),
            before_id: Some(MODEL_LIST[5].to_string()),
            ..Default::default()
        }))
        .await;
        assert!(result.is_err());
    }
}
