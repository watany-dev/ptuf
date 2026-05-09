//! Kiro CLI adapter — input normaliser.
//!
//! Kiro's `preToolUse` hook delivers a payload of the shape:
//!
//! ```json
//! {
//!   "hook_event_name": "preToolUse",
//!   "cwd": "...",
//!   "session_id": "...",
//!   "tool_name": "shell|read|write|webFetch|@server/tool|...",
//!   "tool_input": { ... }
//! }
//! ```
//!
//! Tool names use a different vocabulary than Claude Code's canonical
//! form (`Bash`, `Read`, `Write`, `WebFetch`, `mcp__server__tool`). This
//! module rewrites the tool name and the relevant `tool_input` keys so
//! the engine sees a single canonical shape regardless of agent.
//!
//! Unknown / unmapped tools fall through with their raw name; the
//! engine's MCP / generic-key extractors then handle them best-effort.

use serde_json::{Map, Value};

use super::input_helpers::take_first_string;
use crate::hook_input::HookInput;

/// Normalise a Kiro stdin body into a [`HookInput`].
pub(super) fn parse(body: &str) -> Result<HookInput, KiroInputError> {
    if body.trim().is_empty() {
        return Err(KiroInputError::Empty);
    }
    let value: Value = serde_json::from_str(body).map_err(KiroInputError::Json)?;
    let Value::Object(mut map) = value else {
        return Err(KiroInputError::NotAnObject);
    };

    if let Some(event) = map.get("hook_event_name").and_then(Value::as_str)
        && event != "preToolUse"
    {
        return Err(KiroInputError::UnsupportedEvent(event.to_string()));
    }

    let raw_name = map
        .remove("tool_name")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(KiroInputError::MissingToolName)?;
    let raw_input = map.remove("tool_input").unwrap_or(Value::Null);
    let args = match raw_input {
        Value::Object(m) => m,
        Value::Null => Map::new(),
        other => {
            let mut m = Map::new();
            m.insert("raw".into(), other);
            m
        },
    };

    let (tool_name, tool_input) = normalize(raw_name, args);
    Ok(HookInput {
        tool_name,
        tool_input,
    })
}

/// Reasons a Kiro payload failed to normalise. Every variant maps to
/// `core.engine.invalid-payload` at the CLI boundary so Kiro stays
/// fail-closed (exit 2 + stderr reason).
#[derive(Debug)]
pub(super) enum KiroInputError {
    Empty,
    Json(serde_json::Error),
    NotAnObject,
    MissingToolName,
    UnsupportedEvent(String),
}

impl std::fmt::Display for KiroInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "hook payload is empty"),
            Self::Json(err) => write!(f, "hook payload is not valid JSON ({err})"),
            Self::NotAnObject => write!(f, "hook payload must be a JSON object"),
            Self::MissingToolName => write!(f, "hook payload is missing tool_name field"),
            Self::UnsupportedEvent(name) => {
                write!(
                    f,
                    "unsupported hook_event_name: {name} (expected preToolUse)"
                )
            },
        }
    }
}

fn normalize(raw_name: String, args: Map<String, Value>) -> (String, Value) {
    match raw_name.as_str() {
        "shell" | "execute_bash" | "execute_cmd" => ("Bash".into(), reshape_bash(args)),
        "read" | "fs_read" | "fsRead" => ("Read".into(), reshape_path(args)),
        "write" | "fs_write" | "fsWrite" => ("Write".into(), reshape_write(args)),
        "web_fetch" | "webFetch" => ("WebFetch".into(), Value::Object(args)),
        _ => {
            if let Some(canonical) = normalize_at_mcp(&raw_name) {
                (canonical, Value::Object(args))
            } else {
                (raw_name, Value::Object(args))
            }
        },
    }
}

/// `@server/tool` → `mcp__server__tool`. Three or more segments collapse
/// extra slashes into underscores: `@a/b/c` → `mcp__a__b_c`. Empty
/// segments cause this helper to return `None` so the caller keeps the
/// raw name.
fn normalize_at_mcp(name: &str) -> Option<String> {
    let rest = name.strip_prefix('@')?;
    let mut parts = rest.split('/');
    let server = parts.next()?;
    let tool = parts.next()?;
    if server.is_empty() || tool.is_empty() {
        return None;
    }
    let mut tool_full = String::from(tool);
    for extra in parts {
        if extra.is_empty() {
            return None;
        }
        tool_full.push('_');
        tool_full.push_str(extra);
    }
    Some(format!("mcp__{server}__{tool_full}"))
}

fn reshape_bash(mut args: Map<String, Value>) -> Value {
    if args
        .get("command")
        .is_none_or(|v| v.as_str().is_none_or(str::is_empty))
        && let Some(cmd) = take_first_string(&mut args, &["cmd", "script"])
    {
        args.insert("command".into(), Value::String(cmd));
    }
    Value::Object(args)
}

fn reshape_path(mut args: Map<String, Value>) -> Value {
    if args
        .get("file_path")
        .is_none_or(|v| v.as_str().is_none_or(str::is_empty))
        && let Some(path) = first_path(&args)
    {
        args.insert("file_path".into(), Value::String(path));
    }
    Value::Object(args)
}

fn reshape_write(mut args: Map<String, Value>) -> Value {
    if args
        .get("file_path")
        .is_none_or(|v| v.as_str().is_none_or(str::is_empty))
        && let Some(path) = first_path(&args)
    {
        args.insert("file_path".into(), Value::String(path));
    }
    if args.get("content").is_none_or(|v| v.as_str().is_none())
        && let Some(content) = take_first_string(&mut args, &["text", "new_content"])
    {
        args.insert("content".into(), Value::String(content));
    }
    Value::Object(args)
}

/// Path lookup priority: `path` → `paths[0]` → `operations[0].path` →
/// `files[0].path` → `items[0].path`. Non-destructive — arrays stay in
/// place so `collect_event_paths` can iterate them later.
fn first_path(args: &Map<String, Value>) -> Option<String> {
    if let Some(s) = args.get("path").and_then(Value::as_str) {
        return Some(s.to_string());
    }
    if let Some(arr) = args.get("paths").and_then(Value::as_array)
        && let Some(first) = arr.first().and_then(Value::as_str)
    {
        return Some(first.to_string());
    }
    for key in ["operations", "files", "items"] {
        if let Some(arr) = args.get(key).and_then(Value::as_array)
            && let Some(first) = arr.first().and_then(|item| item.get("path"))
            && let Some(s) = first.as_str()
        {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kiro_shell_normalizes_to_bash() {
        let body = r#"{"hook_event_name":"preToolUse","tool_name":"shell","tool_input":{"command":"ls -la"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("ls -la"));
    }

    #[test]
    fn kiro_execute_bash_alias() {
        let body = r#"{"tool_name":"execute_bash","tool_input":{"command":"pwd"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("pwd"));
    }

    #[test]
    fn kiro_execute_cmd_alias() {
        let body = r#"{"tool_name":"execute_cmd","tool_input":{"command":"whoami"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("whoami"));
    }

    #[test]
    fn kiro_command_priority_keeps_command_when_present() {
        let body = r#"{"tool_name":"shell","tool_input":{"command":"true","cmd":"false"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.bash_command(), Some("true"));
    }

    #[test]
    fn kiro_command_priority_promotes_cmd_then_script() {
        let body = r#"{"tool_name":"shell","tool_input":{"cmd":"ls","script":"pwd"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.bash_command(), Some("ls"));

        let body = r#"{"tool_name":"shell","tool_input":{"script":"pwd"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.bash_command(), Some("pwd"));
    }

    #[test]
    fn kiro_read_operations_path_is_extracted() {
        let body = r#"{"tool_name":"read","tool_input":{"operations":[{"path":"/tmp/a"},{"path":"/tmp/b"}]}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.file_path(), Some("/tmp/a"));
        let event = input.event();
        assert_eq!(event.paths, vec!["/tmp/a", "/tmp/b"]);
    }

    #[test]
    fn kiro_read_paths_array_is_extracted() {
        let body = r#"{"tool_name":"fs_read","tool_input":{"paths":["/tmp/x","/tmp/y"]}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.file_path(), Some("/tmp/x"));
    }

    #[test]
    fn kiro_write_text_field_normalizes_to_content() {
        let body = r#"{"tool_name":"write","tool_input":{"file_path":"/tmp/f","text":"hello"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Write");
        assert_eq!(input.file_path(), Some("/tmp/f"));
        assert_eq!(input.write_payload(), Some("hello"));
    }

    #[test]
    fn kiro_write_new_content_is_promoted_when_text_absent() {
        let body =
            r#"{"tool_name":"fs_write","tool_input":{"file_path":"/tmp/f","new_content":"hi"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Write");
        assert_eq!(input.write_payload(), Some("hi"));
    }

    #[test]
    fn kiro_mcp_at_form_normalizes() {
        let body = r#"{"tool_name":"@postgres/query","tool_input":{"sql":"select 1"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__postgres__query");
        assert!(input.is_mcp_tool());
    }

    #[test]
    fn kiro_mcp_three_segment() {
        let body = r#"{"tool_name":"@a/b/c","tool_input":{}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__a__b_c");
    }

    #[test]
    fn kiro_mcp_empty_segment_falls_through() {
        let body = r#"{"tool_name":"@server/","tool_input":{}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "@server/");
    }

    #[test]
    fn kiro_unknown_tool_passes_through() {
        let body = r#"{"tool_name":"taskRun","tool_input":{"goal":"x"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "taskRun");
    }

    #[test]
    fn kiro_unsupported_event_is_rejected() {
        let body = r#"{"hook_event_name":"postToolUse","tool_name":"shell","tool_input":{}}"#;
        assert!(matches!(
            parse(body),
            Err(KiroInputError::UnsupportedEvent(_))
        ));
    }

    #[test]
    fn kiro_invalid_json_is_rejected() {
        assert!(matches!(parse("not-json"), Err(KiroInputError::Json(_))));
    }

    #[test]
    fn kiro_empty_body_is_rejected() {
        assert!(matches!(parse(""), Err(KiroInputError::Empty)));
        assert!(matches!(parse("   \n"), Err(KiroInputError::Empty)));
    }

    #[test]
    fn kiro_array_payload_is_rejected() {
        assert!(matches!(parse("[]"), Err(KiroInputError::NotAnObject)));
    }

    #[test]
    fn kiro_missing_tool_name_is_rejected() {
        assert!(matches!(
            parse(r#"{"tool_input":{}}"#),
            Err(KiroInputError::MissingToolName)
        ));
    }

    #[test]
    fn kiro_webfetch_alias_normalises() {
        let body = r#"{"tool_name":"webFetch","tool_input":{"url":"https://x"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "WebFetch");
        assert_eq!(input.web_fetch_url(), Some("https://x"));
    }

    #[test]
    fn kiro_null_tool_input_is_object() {
        let body = r#"{"tool_name":"shell","tool_input":null}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert!(input.tool_input.is_object());
    }

    #[test]
    fn kiro_non_object_tool_input_falls_back_to_raw() {
        let body = r#"{"tool_name":"taskRun","tool_input":42}"#;
        let input = parse(body).unwrap();
        assert_eq!(
            input.tool_input.get("raw").and_then(Value::as_i64),
            Some(42)
        );
    }

    #[test]
    fn kiro_input_error_display_covers_all_variants() {
        let bad = serde_json::from_str::<Value>("nope").unwrap_err();
        assert!(format!("{}", KiroInputError::Empty).contains("empty"));
        assert!(format!("{}", KiroInputError::Json(bad)).contains("not valid JSON"));
        assert!(format!("{}", KiroInputError::NotAnObject).contains("JSON object"));
        assert!(format!("{}", KiroInputError::MissingToolName).contains("tool_name"));
        assert!(
            format!("{}", KiroInputError::UnsupportedEvent("postToolUse".into()))
                .contains("postToolUse")
        );
    }
}
