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

    /// String `file_path` for `Read` / `Edit` / `Write` payloads.
    pub fn file_path(&self) -> Option<&str> {
        if !matches!(self.tool_name.as_str(), "Read" | "Edit" | "Write") {
            return None;
        }
        self.tool_input.get("file_path")?.as_str()
    }

    /// String `url` for `WebFetch` payloads.
    pub fn web_fetch_url(&self) -> Option<&str> {
        if self.tool_name != "WebFetch" {
            return None;
        }
        self.tool_input.get("url")?.as_str()
    }

    /// Body the agent intends to write: `Write::content` /
    /// `Edit::new_string`. Returns `None` for tools that don't write.
    pub fn write_payload(&self) -> Option<&str> {
        match self.tool_name.as_str() {
            "Write" => self.tool_input.get("content")?.as_str(),
            "Edit" => self.tool_input.get("new_string")?.as_str(),
            _ => None,
        }
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
    use crate::testing::proptest::hook_input;
    use proptest::prelude::*;

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

    #[test]
    fn file_path_returns_string_for_read_edit_write() {
        for tool in ["Read", "Edit", "Write"] {
            let raw = format!(r#"{{"tool_name":"{tool}","tool_input":{{"file_path":"/tmp/x"}}}}"#);
            let parsed: HookInput = serde_json::from_str(&raw).expect("parse");
            assert_eq!(parsed.file_path(), Some("/tmp/x"));
        }
    }

    #[test]
    fn file_path_is_none_for_other_tools() {
        let raw = r#"{"tool_name":"Bash","tool_input":{"file_path":"/tmp/x"}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert!(parsed.file_path().is_none());
    }

    #[test]
    fn file_path_is_none_when_field_missing_or_non_string() {
        let raw = r#"{"tool_name":"Read","tool_input":{}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert!(parsed.file_path().is_none());

        let raw = r#"{"tool_name":"Read","tool_input":{"file_path":123}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert!(parsed.file_path().is_none());
    }

    #[test]
    fn web_fetch_url_returns_string_for_webfetch() {
        let raw = r#"{"tool_name":"WebFetch","tool_input":{"url":"https://x"}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert_eq!(parsed.web_fetch_url(), Some("https://x"));
    }

    #[test]
    fn web_fetch_url_is_none_for_other_tools_or_missing_field() {
        let raw = r#"{"tool_name":"Bash","tool_input":{"url":"https://x"}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert!(parsed.web_fetch_url().is_none());

        let raw = r#"{"tool_name":"WebFetch","tool_input":{}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert!(parsed.web_fetch_url().is_none());

        let raw = r#"{"tool_name":"WebFetch","tool_input":{"url":42}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert!(parsed.web_fetch_url().is_none());
    }

    #[test]
    fn write_payload_returns_content_for_write_and_new_string_for_edit() {
        let raw = r#"{"tool_name":"Write","tool_input":{"content":"hello"}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert_eq!(parsed.write_payload(), Some("hello"));

        let raw = r#"{"tool_name":"Edit","tool_input":{"new_string":"world"}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert_eq!(parsed.write_payload(), Some("world"));
    }

    #[test]
    fn write_payload_is_none_for_other_tools_or_missing_fields() {
        let raw = r#"{"tool_name":"Bash","tool_input":{"content":"x"}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert!(parsed.write_payload().is_none());

        let raw = r#"{"tool_name":"Write","tool_input":{}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert!(parsed.write_payload().is_none());

        let raw = r#"{"tool_name":"Edit","tool_input":{"new_string":42}}"#;
        let parsed: HookInput = serde_json::from_str(raw).expect("parse");
        assert!(parsed.write_payload().is_none());
    }

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

        // ----- file_path -----------------------------------------------

        #[test]
        fn pbt_file_path_round_trips(
            tool in proptest::sample::select(&["Read", "Edit", "Write"][..]),
            fp in crate::testing::proptest::file_path(),
        ) {
            let input = HookInput {
                tool_name: tool.to_string(),
                tool_input: serde_json::json!({ "file_path": fp.clone() }),
            };
            prop_assert_eq!(input.file_path(), Some(fp.as_str()));
        }

        #[test]
        fn pbt_file_path_none_for_non_path_tool(
            tool in "[A-Z][A-Za-z]{0,8}",
            fp in crate::testing::proptest::file_path(),
        ) {
            prop_assume!(!matches!(tool.as_str(), "Read" | "Edit" | "Write"));
            let input = HookInput {
                tool_name: tool,
                tool_input: serde_json::json!({ "file_path": fp }),
            };
            prop_assert_eq!(input.file_path(), None);
        }

        #[test]
        fn pbt_file_path_none_for_non_string_value(
            tool in proptest::sample::select(&["Read", "Edit", "Write"][..]),
            n in 0i64..1_000,
        ) {
            let input = HookInput {
                tool_name: tool.to_string(),
                tool_input: serde_json::json!({ "file_path": n }),
            };
            prop_assert_eq!(input.file_path(), None);
        }

        // ----- web_fetch_url -------------------------------------------

        #[test]
        fn pbt_web_fetch_url_round_trips(
            url in crate::testing::proptest::web_url(),
        ) {
            let input = HookInput {
                tool_name: "WebFetch".into(),
                tool_input: serde_json::json!({ "url": url.clone() }),
            };
            prop_assert_eq!(input.web_fetch_url(), Some(url.as_str()));
        }

        #[test]
        fn pbt_web_fetch_url_none_for_non_webfetch_tool(
            tool in "[A-Z][A-Za-z]{0,8}",
            url in crate::testing::proptest::web_url(),
        ) {
            prop_assume!(tool != "WebFetch");
            let input = HookInput {
                tool_name: tool,
                tool_input: serde_json::json!({ "url": url }),
            };
            prop_assert_eq!(input.web_fetch_url(), None);
        }

        // ----- write_payload -------------------------------------------

        #[test]
        fn pbt_write_payload_returns_content_for_write(
            content in "[ -~]{0,40}",
        ) {
            let input = HookInput {
                tool_name: "Write".into(),
                tool_input: serde_json::json!({ "content": content.clone() }),
            };
            prop_assert_eq!(input.write_payload(), Some(content.as_str()));
        }

        #[test]
        fn pbt_write_payload_returns_new_string_for_edit(
            new_string in "[ -~]{0,40}",
        ) {
            let input = HookInput {
                tool_name: "Edit".into(),
                tool_input: serde_json::json!({ "new_string": new_string.clone() }),
            };
            prop_assert_eq!(input.write_payload(), Some(new_string.as_str()));
        }

        // Other tool names never expose a write_payload.
        #[test]
        fn pbt_write_payload_none_for_non_writer_tool(
            tool in "[A-Z][A-Za-z]{0,8}",
            content in "[ -~]{0,40}",
        ) {
            prop_assume!(!matches!(tool.as_str(), "Write" | "Edit"));
            let input = HookInput {
                tool_name: tool,
                tool_input: serde_json::json!({
                    "content": content.clone(),
                    "new_string": content,
                }),
            };
            prop_assert_eq!(input.write_payload(), None);
        }

        // None of the accessors panic for any richer_hook_input shape.
        #[test]
        fn pbt_accessors_never_panic(
            input in crate::testing::proptest::richer_hook_input(),
        ) {
            let _ = input.bash_command();
            let _ = input.file_path();
            let _ = input.web_fetch_url();
            let _ = input.write_payload();
        }
    }
}
