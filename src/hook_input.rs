use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
}

impl HookInput {
    /// If this is a Bash tool call with a string `command` field, return it.
    pub fn bash_command(&self) -> Option<&str> {
        if self.tool_name != "Bash" {
            return None;
        }
        self.tool_input.get("command")?.as_str()
    }
}

#[cfg(test)]
pub(crate) fn sample(tool: &str) -> HookInput {
    HookInput {
        tool_name: tool.to_string(),
        tool_input: serde_json::json!({}),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

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
    fn bash_command_returns_string_for_bash_tool() {
        let raw = r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert_eq!(parsed.bash_command(), Some("ls -la"));
    }

    #[test]
    fn bash_command_is_none_for_other_tools() {
        let raw = r#"{"tool_name":"Read","tool_input":{"command":"ls"}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert_eq!(parsed.bash_command(), None);
    }

    #[test]
    fn bash_command_is_none_when_command_missing_or_non_string() {
        let raw = r#"{"tool_name":"Bash","tool_input":{}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert_eq!(parsed.bash_command(), None);

        let raw = r#"{"tool_name":"Bash","tool_input":{"command":123}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert_eq!(parsed.bash_command(), None);
    }
}
