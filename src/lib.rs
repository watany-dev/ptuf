#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used, clippy::expect_used)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
}

pub fn decide(_input: &HookInput) -> Decision {
    Decision::Allow
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn sample(tool: &str) -> HookInput {
        HookInput {
            tool_name: tool.to_string(),
            tool_input: serde_json::json!({}),
        }
    }

    #[test]
    fn decide_returns_allow_by_default() {
        assert_eq!(decide(&sample("Bash")), Decision::Allow);
        assert_eq!(decide(&sample("Read")), Decision::Allow);
    }

    #[test]
    fn decision_serialises_allow() {
        let json = serde_json::to_string(&Decision::Allow).expect("serialise");
        assert_eq!(json, "{\"decision\":\"allow\"}");
    }

    #[test]
    fn decision_serialises_deny_with_reason() {
        let json = serde_json::to_string(&Decision::Deny {
            reason: "blocked by policy".into(),
        })
        .expect("serialise");
        assert!(json.contains("\"decision\":\"deny\""));
        assert!(json.contains("\"reason\":\"blocked by policy\""));
    }

    #[test]
    fn hook_input_parses_minimal_payload() {
        let raw = r#"{"tool_name":"Bash"}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert_eq!(parsed.tool_name, "Bash");
        assert!(parsed.tool_input.is_null());
    }

    #[test]
    fn hook_input_parses_full_payload() {
        let raw = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert_eq!(parsed.tool_name, "Bash");
        assert_eq!(parsed.tool_input["command"], "ls");
        let cloned = parsed.clone();
        assert_eq!(cloned.tool_name, "Bash");
    }

    #[test]
    fn decision_round_trips_through_json() {
        let original = Decision::Deny {
            reason: "no".into(),
        };
        let encoded = serde_json::to_string(&original).expect("encode");
        let decoded: Decision = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }
}
