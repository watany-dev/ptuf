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
}
