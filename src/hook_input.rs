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

    /// String `file_path` for `Read` / `Edit` / `Write` payloads, or the
    /// generic `path` field for `mcp__*` tool calls. MCP servers vary in
    /// payload shape; v1 only inspects the top-level `path` key (not
    /// nested arrays such as `mcp__github__push_files.files[].path`).
    pub fn file_path(&self) -> Option<&str> {
        match self.tool_name.as_str() {
            "Read" | "Edit" | "Write" => self.tool_input.get("file_path")?.as_str(),
            name if is_mcp(name) => self.tool_input.get("path")?.as_str(),
            _ => None,
        }
    }

    /// String `url` for `WebFetch` payloads, or the generic `url` field
    /// for `mcp__*` tool calls.
    pub fn web_fetch_url(&self) -> Option<&str> {
        match self.tool_name.as_str() {
            "WebFetch" => self.tool_input.get("url")?.as_str(),
            name if is_mcp(name) => self.tool_input.get("url")?.as_str(),
            _ => None,
        }
    }

    /// Body the agent intends to write: `Write::content` /
    /// `Edit::new_string`, or the generic `content` field for `mcp__*`
    /// tool calls. Returns `None` for tools that don't write.
    pub fn write_payload(&self) -> Option<&str> {
        match self.tool_name.as_str() {
            "Write" => self.tool_input.get("content")?.as_str(),
            "Edit" => self.tool_input.get("new_string")?.as_str(),
            name if is_mcp(name) => self.tool_input.get("content")?.as_str(),
            _ => None,
        }
    }

    /// True when `tool_name` follows the Claude Code MCP convention
    /// `mcp__<server>__<tool>`. Used by `file_path` / `web_fetch_url` /
    /// `write_payload` to attempt generic key extraction without
    /// hard-coding specific server names.
    pub fn is_mcp_tool(&self) -> bool {
        is_mcp(&self.tool_name)
    }

    /// MCP server namespace (e.g. `github` for `mcp__github__list_files`).
    /// Returns `None` unless `is_mcp_tool()` would also return `true`.
    pub fn mcp_namespace(&self) -> Option<&str> {
        let (ns, _) = split_mcp(&self.tool_name)?;
        Some(ns)
    }

    /// MCP tool name within its server namespace (e.g.
    /// `create_or_update_file` for `mcp__github__create_or_update_file`).
    /// Returns `None` unless `is_mcp_tool()` would also return `true`.
    pub fn mcp_tool_name(&self) -> Option<&str> {
        let (_, tool) = split_mcp(&self.tool_name)?;
        Some(tool)
    }
}

fn split_mcp(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("mcp__")?;
    let (ns, tool) = rest.split_once("__")?;
    if ns.is_empty() || tool.is_empty() {
        None
    } else {
        Some((ns, tool))
    }
}

fn is_mcp(name: &str) -> bool {
    split_mcp(name).is_some()
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

    #[test]
    fn is_mcp_tool_recognises_canonical_form() {
        let parsed: HookInput =
            serde_json::from_str(r#"{"tool_name":"mcp__github__list_issues","tool_input":{}}"#)
                .expect("parse");
        assert!(parsed.is_mcp_tool());
        assert_eq!(parsed.mcp_namespace(), Some("github"));
        assert_eq!(parsed.mcp_tool_name(), Some("list_issues"));
    }

    #[test]
    fn is_mcp_tool_rejects_partial_or_malformed_names() {
        for bad in ["mcp_", "mcp__", "mcp__only", "mcp__server__", "mcp____tool"] {
            let parsed = HookInput {
                tool_name: bad.into(),
                tool_input: serde_json::json!({}),
            };
            assert!(!parsed.is_mcp_tool(), "{bad} should not be MCP");
            assert_eq!(parsed.mcp_namespace(), None, "{bad}");
            assert_eq!(parsed.mcp_tool_name(), None, "{bad}");
        }
    }

    #[test]
    fn mcp_file_path_reads_top_level_path_key() {
        let parsed: HookInput = serde_json::from_str(
            r#"{"tool_name":"mcp__github__create_or_update_file","tool_input":{"path":".claude/settings.json"}}"#,
        )
        .expect("parse");
        assert_eq!(parsed.file_path(), Some(".claude/settings.json"));
    }

    #[test]
    fn mcp_url_reads_top_level_url_key() {
        let parsed: HookInput = serde_json::from_str(
            r#"{"tool_name":"mcp__fetch__fetch","tool_input":{"url":"https://example.com/x"}}"#,
        )
        .expect("parse");
        assert_eq!(parsed.web_fetch_url(), Some("https://example.com/x"));
    }

    #[test]
    fn mcp_write_payload_reads_top_level_content_key() {
        let parsed: HookInput = serde_json::from_str(
            r#"{"tool_name":"mcp__filesystem__write_file","tool_input":{"path":"/tmp/x","content":"hi"}}"#,
        )
        .expect("parse");
        assert_eq!(parsed.write_payload(), Some("hi"));
        assert_eq!(parsed.file_path(), Some("/tmp/x"));
    }

    #[test]
    fn mcp_accessors_return_none_for_non_string_or_missing_fields() {
        let parsed = HookInput {
            tool_name: "mcp__filesystem__write_file".into(),
            tool_input: serde_json::json!({"path": 123, "content": 42, "url": false}),
        };
        assert!(parsed.file_path().is_none());
        assert!(parsed.web_fetch_url().is_none());
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
    }
}
