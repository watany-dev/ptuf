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

    use crate::testing::proptest::hook_input;
    use proptest::prelude::*;

    proptest! {
        // Non-Bash tool ⇒ bash_command() always None, regardless of payload.
        #[test]
        fn pbt_non_bash_tool_never_returns_command(
            tool in "[A-Z][A-Za-z]{0,8}",
            cmd in "[ -~]{0,30}",
        ) {
            prop_assume!(tool != "Bash");
            let input = HookInput {
                tool_name: tool,
                tool_input: serde_json::json!({ "command": cmd }),
            };
            prop_assert_eq!(input.bash_command(), None);
        }

        // Bash + non-string `command` field ⇒ None.
        #[test]
        fn pbt_bash_with_non_string_command_is_none(n in 0i64..1_000_000) {
            let input = HookInput {
                tool_name: "Bash".into(),
                tool_input: serde_json::json!({ "command": n }),
            };
            prop_assert_eq!(input.bash_command(), None);
        }

        // Bash + string `command` ⇒ Some(s) with the same string.
        #[test]
        fn pbt_bash_with_string_command_round_trips(cmd in "[ -~]{0,40}") {
            let input = HookInput {
                tool_name: "Bash".into(),
                tool_input: serde_json::json!({ "command": cmd.clone() }),
            };
            prop_assert_eq!(input.bash_command(), Some(cmd.as_str()));
        }

        // bash_command never panics for arbitrary-but-well-formed HookInput.
        #[test]
        fn pbt_bash_command_never_panics(input in hook_input()) {
            let _ = input.bash_command();
        }
    }
}
