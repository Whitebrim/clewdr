//! Rich model metadata matching the Anthropic Models API schema
//! (<https://platform.claude.com/docs/en/api/models>).
//!
//! These types are stored in `clewdr.toml` (`[[models]]`) and served verbatim
//! by the Anthropic-compatible `/anthropic/v1/models` endpoint, and mapped to
//! the OpenAI shape by `/openai/v1/models`.
//!
//! Field ordering matters: each struct lists its scalar fields before any
//! nested table/struct fields so that the whole list round-trips through TOML
//! serialization (TOML forbids a bare key after a sub-table within a table).

use serde::{Deserialize, Serialize};

/// `{ "supported": bool }` — the leaf capability flag used throughout.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Capability {
    pub supported: bool,
}

const fn cap(supported: bool) -> Capability {
    Capability { supported }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextManagement {
    pub supported: bool,
    pub clear_thinking_20251015: Capability,
    pub clear_tool_uses_20250919: Capability,
    pub compact_20260112: Capability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Effort {
    pub supported: bool,
    pub high: Capability,
    pub low: Capability,
    pub max: Capability,
    pub medium: Capability,
    pub xhigh: Capability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThinkingTypes {
    pub adaptive: Capability,
    pub enabled: Capability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thinking {
    pub supported: bool,
    pub types: ThinkingTypes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCapabilities {
    pub batch: Capability,
    pub citations: Capability,
    pub code_execution: Capability,
    pub image_input: Capability,
    pub pdf_input: Capability,
    pub structured_outputs: Capability,
    pub context_management: ContextManagement,
    pub effort: Effort,
    pub thinking: Thinking,
}

fn default_model_type() -> String {
    "model".to_string()
}

/// A single entry of the Models API `data` array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub display_name: String,
    pub created_at: String,
    pub max_input_tokens: u64,
    pub max_tokens: u64,
    #[serde(rename = "type", default = "default_model_type")]
    pub kind: String,
    // Nested table — must stay last for TOML serialization.
    pub capabilities: ModelCapabilities,
}

impl ModelInfo {
    /// `created_at` (RFC 3339) as a Unix timestamp for the OpenAI `created`
    /// field. Falls back to 0 if the timestamp can't be parsed.
    pub fn created_unix(&self) -> i64 {
        chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.timestamp())
            .unwrap_or(0)
    }

    /// Synthesize a permissive entry from a bare model id. Used only to keep
    /// configs that still list `models = ["id", ...]` (the old string form)
    /// working after the schema upgrade.
    pub fn from_id(id: &str) -> Self {
        let all = cap(true);
        ModelInfo {
            id: id.to_string(),
            display_name: display_name_from_id(id),
            created_at: created_at_from_id(id),
            max_input_tokens: if id.contains("-1M") { 1_000_000 } else { 200_000 },
            max_tokens: 64_000,
            kind: "model".to_string(),
            capabilities: ModelCapabilities {
                batch: all,
                citations: all,
                code_execution: all,
                image_input: all,
                pdf_input: all,
                structured_outputs: all,
                context_management: ContextManagement {
                    supported: true,
                    clear_thinking_20251015: all,
                    clear_tool_uses_20250919: all,
                    compact_20260112: all,
                },
                effort: Effort {
                    supported: true,
                    high: all,
                    low: all,
                    max: all,
                    medium: all,
                    xhigh: all,
                },
                thinking: Thinking {
                    supported: true,
                    types: ThinkingTypes {
                        adaptive: all,
                        enabled: all,
                    },
                },
            },
        }
    }
}

/// Custom deserializer for the `models` config field that accepts both the rich
/// `[[models]]` table form and the legacy `models = ["id", ...]` string form.
pub fn deserialize_models<'de, D>(deserializer: D) -> Result<Vec<ModelInfo>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Entry {
        Id(String),
        Full(Box<ModelInfo>),
    }
    let raw = Vec::<Entry>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|e| match e {
            Entry::Id(id) => ModelInfo::from_id(&id),
            Entry::Full(m) => *m,
        })
        .collect())
}

fn display_name_from_id(id: &str) -> String {
    let mut out = String::new();
    for (i, part) in id.split('-').enumerate() {
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

fn created_at_from_id(id: &str) -> String {
    for part in id.split('-') {
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

/// Compact builder for a `ModelCapabilities`. Tuple args are positional and
/// match the Anthropic schema:
/// * `cm`: (supported, clear_thinking, clear_tool_uses, compact)
/// * `effort`: (supported, high, low, max, medium, xhigh)
/// * `thinking`: (supported, adaptive, enabled)
#[allow(clippy::too_many_arguments)]
fn caps(
    batch: bool,
    citations: bool,
    code_execution: bool,
    image_input: bool,
    pdf_input: bool,
    structured_outputs: bool,
    cm: (bool, bool, bool, bool),
    effort: (bool, bool, bool, bool, bool, bool),
    thinking: (bool, bool, bool),
) -> ModelCapabilities {
    ModelCapabilities {
        batch: cap(batch),
        citations: cap(citations),
        code_execution: cap(code_execution),
        image_input: cap(image_input),
        pdf_input: cap(pdf_input),
        structured_outputs: cap(structured_outputs),
        context_management: ContextManagement {
            supported: cm.0,
            clear_thinking_20251015: cap(cm.1),
            clear_tool_uses_20250919: cap(cm.2),
            compact_20260112: cap(cm.3),
        },
        effort: Effort {
            supported: effort.0,
            high: cap(effort.1),
            low: cap(effort.2),
            max: cap(effort.3),
            medium: cap(effort.4),
            xhigh: cap(effort.5),
        },
        thinking: Thinking {
            supported: thinking.0,
            types: ThinkingTypes {
                adaptive: cap(thinking.1),
                enabled: cap(thinking.2),
            },
        },
    }
}

fn mi(
    id: &str,
    display_name: &str,
    created_at: &str,
    max_input_tokens: u64,
    max_tokens: u64,
    capabilities: ModelCapabilities,
) -> ModelInfo {
    ModelInfo {
        id: id.to_string(),
        display_name: display_name.to_string(),
        created_at: created_at.to_string(),
        max_input_tokens,
        max_tokens,
        kind: "model".to_string(),
        capabilities,
    }
}

/// Default model list, mirroring the Anthropic Models API as of 2026-05.
/// Editable in `clewdr.toml` under `[[models]]`.
pub fn default_models() -> Vec<ModelInfo> {
    vec![
        mi(
            "claude-opus-4-8",
            "Claude Opus 4.8",
            "2026-05-28T00:00:00Z",
            1_000_000,
            128_000,
            caps(
                true, true, true, true, true, true,
                (true, true, true, true),
                (true, true, true, true, true, true),
                (true, true, false),
            ),
        ),
        mi(
            "claude-opus-4-7",
            "Claude Opus 4.7",
            "2026-04-14T00:00:00Z",
            1_000_000,
            128_000,
            caps(
                true, true, true, true, true, true,
                (true, true, true, true),
                (true, true, true, true, true, true),
                (true, true, false),
            ),
        ),
        mi(
            "claude-sonnet-4-6",
            "Claude Sonnet 4.6",
            "2026-02-17T00:00:00Z",
            1_000_000,
            128_000,
            caps(
                true, true, true, true, true, true,
                (true, true, true, true),
                (true, true, true, true, true, false),
                (true, true, true),
            ),
        ),
        mi(
            "claude-opus-4-6",
            "Claude Opus 4.6",
            "2026-02-04T00:00:00Z",
            1_000_000,
            128_000,
            caps(
                true, true, true, true, true, true,
                (true, true, true, true),
                (true, true, true, true, true, false),
                (true, true, true),
            ),
        ),
        mi(
            "claude-opus-4-5-20251101",
            "Claude Opus 4.5",
            "2025-11-24T00:00:00Z",
            200_000,
            64_000,
            caps(
                true, true, true, true, true, true,
                (true, true, true, false),
                (true, true, true, false, true, false),
                (true, false, true),
            ),
        ),
        mi(
            "claude-haiku-4-5-20251001",
            "Claude Haiku 4.5",
            "2025-10-15T00:00:00Z",
            200_000,
            64_000,
            caps(
                true, true, false, true, true, true,
                (true, true, true, false),
                (false, false, false, false, false, false),
                (true, false, true),
            ),
        ),
        mi(
            "claude-sonnet-4-5-20250929",
            "Claude Sonnet 4.5",
            "2025-09-29T00:00:00Z",
            1_000_000,
            64_000,
            caps(
                true, true, true, true, true, true,
                (true, true, true, false),
                (false, false, false, false, false, false),
                (true, false, true),
            ),
        ),
        mi(
            "claude-opus-4-1-20250805",
            "Claude Opus 4.1",
            "2025-08-05T00:00:00Z",
            200_000,
            32_000,
            caps(
                true, true, false, true, true, true,
                (true, true, true, false),
                (false, false, false, false, false, false),
                (true, false, true),
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_list_matches_anthropic_data() {
        let models = default_models();
        assert_eq!(models.len(), 8);
        assert_eq!(models[0].id, "claude-opus-4-8");
        assert_eq!(models[0].display_name, "Claude Opus 4.8");
        assert_eq!(models[0].max_input_tokens, 1_000_000);
        assert_eq!(models[0].max_tokens, 128_000);
        assert_eq!(models[0].kind, "model");
        // opus-4-8: thinking enabled=false, effort.xhigh=true
        assert!(!models[0].capabilities.thinking.types.enabled.supported);
        assert!(models[0].capabilities.thinking.types.adaptive.supported);
        assert!(models[0].capabilities.effort.xhigh.supported);
        // haiku: effort unsupported, code_execution false
        let haiku = models.iter().find(|m| m.id == "claude-haiku-4-5-20251001").unwrap();
        assert!(!haiku.capabilities.effort.supported);
        assert!(!haiku.capabilities.code_execution.supported);
        assert!(haiku.capabilities.thinking.types.enabled.supported);
        // last id
        assert_eq!(models.last().unwrap().id, "claude-opus-4-1-20250805");
    }

    #[test]
    fn models_round_trip_through_toml() {
        // The whole point of the field ordering: the rich list must survive
        // serialization into clewdr.toml and back.
        #[derive(Serialize, Deserialize)]
        struct Wrapper {
            models: Vec<ModelInfo>,
        }
        let original = Wrapper {
            models: default_models(),
        };
        let toml = toml::to_string_pretty(&original).expect("serialize models to TOML");
        let parsed: Wrapper = toml::from_str(&toml).expect("parse models back from TOML");
        assert_eq!(parsed.models.len(), original.models.len());
        assert_eq!(parsed.models[0].id, original.models[0].id);
        assert_eq!(
            parsed.models[0].capabilities.thinking.types.enabled.supported,
            original.models[0].capabilities.thinking.types.enabled.supported
        );
    }

    #[test]
    fn created_unix_parses_timestamp() {
        let m = &default_models()[0];
        assert!(m.created_unix() > 1_700_000_000); // well after 2023
        let bad = ModelInfo::from_id("claude-opus-4-8");
        assert_eq!(bad.created_at, "2025-01-01T00:00:00Z");
        assert!(bad.created_unix() > 0);
    }

    #[test]
    fn from_id_handles_legacy_string_entries() {
        let m = ModelInfo::from_id("claude-sonnet-4-5-20250929-1M");
        assert_eq!(m.id, "claude-sonnet-4-5-20250929-1M");
        assert_eq!(m.max_input_tokens, 1_000_000); // -1M bumps context
        assert_eq!(m.kind, "model");
        assert_eq!(m.created_at, "2025-09-29T00:00:00Z");
    }
}
