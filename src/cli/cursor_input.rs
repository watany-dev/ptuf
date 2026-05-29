//! Cursor adapter — input normaliser.
//!
//! Cursor's agent loop invokes ptuf as a `preToolUse` hook (and the
//! event-specific `beforeShellExecution` / `beforeReadFile` /
//! `beforeMCPExecution` variants) just before it executes an agent
//! *tool* call. Each event carries a payload of roughly the shape:
//!
//! ```json
//! {
//!   "hook_event_name": "preToolUse",
//!   "tool_name": "Shell|Read|Write|Edit|WebFetch|MCP|...",
//!   "tool_input": { ... },
//!   "cwd": "...",
//!   "conversation_id": "..."
//! }
//! ```
//!
//! camelCase (`hookEventName` / `toolName` / `toolInput`) is accepted as
//! an equivalent spelling. The event-specific shapes carry their
//! payload at the top level (e.g. `beforeShellExecution` puts `command`
//! on the root object), so every field lookup falls back from
//! `tool_input` to the root payload.
//!
//! Tool names are rewritten to Claude Code's canonical vocabulary
//! (`Bash`, `Read`, `Write`, `Edit`, `WebFetch`, `mcp__server__tool`)
//! so the engine sees a single shape regardless of agent. Unknown tools
//! fall through with their raw name; the engine's MCP / generic-key
//! extractors then handle them best-effort.
//!
//! This module only guards hook-driven agent *tool* execution. Cursor's
//! Tab completion, manual edits, and manually typed terminal commands
//! never reach a hook and are therefore out of ptuf's scope.

use serde_json::{Map, Value};

use crate::hook_input::HookInput;

/// Normalise a Cursor stdin body into a [`HookInput`].
pub(super) fn parse(body: &str) -> Result<HookInput, CursorInputError> {
    if body.trim().is_empty() {
        return Err(CursorInputError::Empty);
    }
    let value: Value = serde_json::from_str(body).map_err(CursorInputError::Json)?;
    let Value::Object(mut map) = value else {
        return Err(CursorInputError::NotAnObject);
    };

    let event = map
        .remove("hook_event_name")
        .or_else(|| map.remove("hookEventName"))
        .and_then(|v| v.as_str().map(str::to_owned));

    let raw_input = map
        .remove("tool_input")
        .or_else(|| map.remove("toolInput"))
        .unwrap_or(Value::Null);
    let args = decode_args(raw_input);

    let (tool_name, tool_input) = match event.as_deref().unwrap_or("preToolUse") {
        "preToolUse" => {
            let raw_name = map
                .remove("tool_name")
                .or_else(|| map.remove("toolName"))
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or(CursorInputError::MissingToolName)?;
            normalize(&raw_name, args, &map)
        },
        "beforeShellExecution" => ("Bash".to_string(), reshape_bash(args, &map)),
        "beforeReadFile" => ("Read".to_string(), reshape_path(args, &map)),
        "beforeMCPExecution" => {
            let name = mcp_name(&map, &args).ok_or(CursorInputError::MissingToolName)?;
            (name, Value::Object(args))
        },
        other => return Err(CursorInputError::UnsupportedEvent(other.to_string())),
    };

    Ok(HookInput {
        tool_name,
        tool_input,
    })
}

/// Reasons a Cursor payload failed to normalise. Every variant maps to
/// `core.engine.invalid-payload` at the CLI boundary so Cursor stays
/// fail-closed (exit 2 + `permission:deny` JSON). The enum only exists
/// to make stderr messages actionable.
#[derive(Debug)]
pub(super) enum CursorInputError {
    Empty,
    Json(serde_json::Error),
    NotAnObject,
    MissingToolName,
    UnsupportedEvent(String),
}

impl std::fmt::Display for CursorInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "hook payload is empty"),
            Self::Json(err) => write!(f, "hook payload is not valid JSON ({err})"),
            Self::NotAnObject => write!(f, "hook payload must be a JSON object"),
            Self::MissingToolName => write!(f, "hook payload is missing tool_name field"),
            Self::UnsupportedEvent(name) => write!(
                f,
                "unsupported hook_event_name: {name} (expected preToolUse / \
                 beforeShellExecution / beforeReadFile / beforeMCPExecution)"
            ),
        }
    }
}

fn normalize(
    raw_name: &str,
    args: Map<String, Value>,
    root: &Map<String, Value>,
) -> (String, Value) {
    match raw_name {
        "Shell" | "Bash" | "shell" | "bash" => ("Bash".into(), reshape_bash(args, root)),
        "Read" | "ReadFile" | "read" => ("Read".into(), reshape_path(args, root)),
        "Write" | "write" => ("Write".into(), reshape_write(args, root)),
        "Edit" | "edit" => ("Edit".into(), reshape_edit(args, root)),
        "WebFetch" | "Fetch" | "fetch" | "web_fetch" => ("WebFetch".into(), Value::Object(args)),
        "MCP" | "mcp" => {
            let name = mcp_name(root, &args).unwrap_or_else(|| "mcp__server__tool".to_string());
            (name, Value::Object(args))
        },
        other => {
            if let Some(canonical) = normalize_at_mcp(other) {
                (canonical, Value::Object(args))
            } else {
                (other.to_string(), Value::Object(args))
            }
        },
    }
}

/// Decode the `tool_input` field. Object → object; JSON-encoded object
/// string → re-parsed object; any other string → `{"text": "<raw>"}`;
/// null → empty object; anything else → `{"text": <value>}`. We never
/// panic or surface a parse error here — invalid args degrade to a
/// generic input the engine evaluates best-effort.
fn decode_args(raw: Value) -> Map<String, Value> {
    match raw {
        Value::Object(map) => map,
        Value::String(s) => {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&s) {
                map
            } else {
                let mut m = Map::new();
                m.insert("text".into(), Value::String(s));
                m
            }
        },
        Value::Null => Map::new(),
        other => {
            let mut m = Map::new();
            m.insert("text".into(), other);
            m
        },
    }
}

/// `@server/tool` → `mcp__server__tool`. Mirrors
/// `kiro_input::normalize_at_mcp`: three or more segments collapse extra
/// slashes into underscores (`@a/b/c` → `mcp__a__b_c`); empty segments
/// return `None` so the caller keeps the raw name.
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

/// Build `mcp__<server>__<tool>` from `metadata.server` / `tool_name`
/// (or their root / args fallbacks). Whitespace, `/`, and `.` in either
/// segment are normalised to `_` so the result is a valid MCP name.
fn mcp_name(root: &Map<String, Value>, args: &Map<String, Value>) -> Option<String> {
    let metadata = root.get("metadata").and_then(Value::as_object);
    let candidates = [metadata, Some(root), Some(args)];
    let server = find_str(&candidates, &["server", "server_name", "serverName"])?;
    let tool = find_str(&candidates, &["tool_name", "toolName", "tool", "name"])?;
    Some(format!(
        "mcp__{}__{}",
        sanitize_mcp_segment(&server),
        sanitize_mcp_segment(&tool)
    ))
}

fn sanitize_mcp_segment(segment: &str) -> String {
    segment
        .chars()
        .map(|c| {
            if c.is_whitespace() || c == '/' || c == '.' {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// First non-empty string value for any of `keys`, scanning each map in
/// `maps` order. `None` entries (e.g. a missing `metadata` object) are
/// skipped.
fn find_str(maps: &[Option<&Map<String, Value>>], keys: &[&str]) -> Option<String> {
    for map in maps.iter().flatten() {
        for key in keys {
            if let Some(s) = map.get(*key).and_then(Value::as_str)
                && !s.is_empty()
            {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// First non-empty string for any of `keys`, scanning `args` then
/// `root`. Used for the scalar `command` / `content` fallbacks where the
/// canonical key may live in `tool_input` or on the root payload.
fn first_string(
    args: &Map<String, Value>,
    root: &Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    for map in [args, root] {
        for key in keys {
            if let Some(s) = map.get(*key).and_then(Value::as_str)
                && !s.is_empty()
            {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Path lookup priority across `args` then `root`: `file_path` → `path`
/// → `paths[0]` → `files[0].path`. Arrays stay in place so the engine's
/// `collect_event_paths` can iterate them later.
fn find_path(args: &Map<String, Value>, root: &Map<String, Value>) -> Option<String> {
    for map in [args, root] {
        if let Some(s) = map
            .get("file_path")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            return Some(s.to_string());
        }
        if let Some(s) = map
            .get("path")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            return Some(s.to_string());
        }
        if let Some(arr) = map.get("paths").and_then(Value::as_array)
            && let Some(first) = arr.first().and_then(Value::as_str)
        {
            return Some(first.to_string());
        }
        if let Some(arr) = map.get("files").and_then(Value::as_array)
            && let Some(first) = arr.first().and_then(|item| item.get("path"))
            && let Some(s) = first.as_str()
        {
            return Some(s.to_string());
        }
    }
    None
}

fn reshape_bash(mut args: Map<String, Value>, root: &Map<String, Value>) -> Value {
    if args
        .get("command")
        .is_none_or(|v| v.as_str().is_none_or(str::is_empty))
        && let Some(cmd) = first_string(&args, root, &["command", "cmd", "script"])
    {
        args.insert("command".into(), Value::String(cmd));
    }
    Value::Object(args)
}

fn reshape_path(mut args: Map<String, Value>, root: &Map<String, Value>) -> Value {
    if args
        .get("file_path")
        .is_none_or(|v| v.as_str().is_none_or(str::is_empty))
        && let Some(path) = find_path(&args, root)
    {
        args.insert("file_path".into(), Value::String(path));
    }
    Value::Object(args)
}

fn reshape_write(mut args: Map<String, Value>, root: &Map<String, Value>) -> Value {
    if args
        .get("file_path")
        .is_none_or(|v| v.as_str().is_none_or(str::is_empty))
        && let Some(path) = find_path(&args, root)
    {
        args.insert("file_path".into(), Value::String(path));
    }
    if args.get("content").is_none_or(|v| v.as_str().is_none())
        && let Some(content) = first_string(&args, root, &["content", "text", "new_content"])
    {
        args.insert("content".into(), Value::String(content));
    }
    Value::Object(args)
}

fn reshape_edit(mut args: Map<String, Value>, root: &Map<String, Value>) -> Value {
    if args
        .get("file_path")
        .is_none_or(|v| v.as_str().is_none_or(str::is_empty))
        && let Some(path) = find_path(&args, root)
    {
        args.insert("file_path".into(), Value::String(path));
    }
    if args.get("old_string").is_none_or(|v| v.as_str().is_none())
        && let Some(old) = first_string(&args, root, &["old_string", "oldText", "old"])
    {
        args.insert("old_string".into(), Value::String(old));
    }
    if args.get("new_string").is_none_or(|v| v.as_str().is_none())
        && let Some(new) = first_string(&args, root, &["new_string", "newText", "new"])
    {
        args.insert("new_string".into(), Value::String(new));
    }
    Value::Object(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_shell_normalizes_to_bash() {
        let body = r#"{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"rm -rf /"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("rm -rf /"));
    }

    #[test]
    fn cursor_bash_alias_is_accepted() {
        let body = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("ls"));
    }

    #[test]
    fn cursor_camel_case_envelope_is_accepted() {
        let body = r#"{"hookEventName":"preToolUse","toolName":"Read","toolInput":{"path":"/etc/passwd"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.file_path(), Some("/etc/passwd"));
    }

    #[test]
    fn cursor_read_promotes_path_to_file_path() {
        let body = r#"{"tool_name":"ReadFile","tool_input":{"path":"/tmp/x"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.file_path(), Some("/tmp/x"));
    }

    #[test]
    fn cursor_read_uses_paths_array_when_path_absent() {
        let body = r#"{"tool_name":"Read","tool_input":{"paths":["/tmp/a","/tmp/b"]}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.file_path(), Some("/tmp/a"));
    }

    #[test]
    fn cursor_write_path_and_content_normalise() {
        let body = r#"{"tool_name":"Write","tool_input":{"path":"/tmp/f","text":"hello"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Write");
        assert_eq!(input.file_path(), Some("/tmp/f"));
        assert_eq!(input.write_payload(), Some("hello"));
    }

    #[test]
    fn cursor_edit_old_and_new_string_normalise() {
        let body = r#"{"tool_name":"Edit","tool_input":{"file_path":"/tmp/f","oldText":"a","newText":"b"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Edit");
        assert_eq!(input.file_path(), Some("/tmp/f"));
        assert_eq!(input.write_payload(), Some("b"));
        assert_eq!(
            input.tool_input.get("old_string").and_then(Value::as_str),
            Some("a"),
        );
    }

    #[test]
    fn cursor_webfetch_alias_normalises() {
        let body = r#"{"tool_name":"Fetch","tool_input":{"url":"https://x"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "WebFetch");
        assert_eq!(input.web_fetch_url(), Some("https://x"));
    }

    #[test]
    fn cursor_mcp_from_metadata_builds_canonical_name() {
        let body = r#"{"tool_name":"MCP","metadata":{"server":"github","tool_name":"create_issue"},"tool_input":{"title":"x"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__github__create_issue");
        assert!(input.is_mcp_tool());
    }

    #[test]
    fn cursor_mcp_at_form_normalises() {
        let body = r#"{"tool_name":"@postgres/query","tool_input":{"sql":"select 1"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__postgres__query");
    }

    #[test]
    fn cursor_mcp_sanitises_segments() {
        let body = r#"{"tool_name":"MCP","metadata":{"server":"my server","tool_name":"a/b.c"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__my_server__a_b_c");
    }

    #[test]
    fn cursor_tool_input_json_string_is_parsed() {
        let body = r#"{"tool_name":"Bash","tool_input":"{\"command\":\"whoami\"}"}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("whoami"));
    }

    #[test]
    fn cursor_non_json_tool_input_string_is_kept_as_text() {
        let body = r#"{"tool_name":"taskRun","tool_input":"not-json"}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "taskRun");
        assert_eq!(
            input.tool_input.get("text").and_then(Value::as_str),
            Some("not-json"),
        );
    }

    #[test]
    fn cursor_before_shell_execution_reads_root_command() {
        let body = r#"{"hook_event_name":"beforeShellExecution","command":"rm -rf /"}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("rm -rf /"));
    }

    #[test]
    fn cursor_before_read_file_reads_root_path() {
        let body = r#"{"hook_event_name":"beforeReadFile","path":"/etc/shadow"}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.file_path(), Some("/etc/shadow"));
    }

    #[test]
    fn cursor_before_mcp_execution_builds_name() {
        let body = r#"{"hook_event_name":"beforeMCPExecution","metadata":{"server":"github","tool_name":"create_issue"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__github__create_issue");
    }

    #[test]
    fn cursor_unknown_tool_passes_through() {
        let body = r#"{"tool_name":"taskRun","tool_input":{"goal":"x"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "taskRun");
    }

    #[test]
    fn cursor_unsupported_event_is_rejected() {
        let body = r#"{"hook_event_name":"afterFileEdit","tool_name":"Write","tool_input":{}}"#;
        assert!(matches!(
            parse(body),
            Err(CursorInputError::UnsupportedEvent(_))
        ));
    }

    #[test]
    fn cursor_empty_body_is_rejected() {
        assert!(matches!(parse(""), Err(CursorInputError::Empty)));
        assert!(matches!(parse("   \n"), Err(CursorInputError::Empty)));
    }

    #[test]
    fn cursor_invalid_json_is_rejected() {
        assert!(matches!(parse("not-json"), Err(CursorInputError::Json(_))));
    }

    #[test]
    fn cursor_array_payload_is_rejected() {
        assert!(matches!(parse("[]"), Err(CursorInputError::NotAnObject)));
    }

    #[test]
    fn cursor_pretooluse_missing_tool_name_is_rejected() {
        assert!(matches!(
            parse(r#"{"tool_input":{}}"#),
            Err(CursorInputError::MissingToolName)
        ));
    }

    #[test]
    fn cursor_before_mcp_execution_missing_server_is_rejected() {
        let body = r#"{"hook_event_name":"beforeMCPExecution","tool_input":{}}"#;
        assert!(matches!(
            parse(body),
            Err(CursorInputError::MissingToolName)
        ));
    }

    #[test]
    fn cursor_mcp_without_metadata_falls_back_to_placeholder() {
        let body = r#"{"tool_name":"MCP","tool_input":{}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__server__tool");
    }

    #[test]
    fn cursor_input_error_display_covers_all_variants() {
        let bad = serde_json::from_str::<Value>("nope").unwrap_err();
        assert!(format!("{}", CursorInputError::Empty).contains("empty"));
        assert!(format!("{}", CursorInputError::Json(bad)).contains("not valid JSON"));
        assert!(format!("{}", CursorInputError::NotAnObject).contains("JSON object"));
        assert!(format!("{}", CursorInputError::MissingToolName).contains("tool_name"));
        assert!(
            format!(
                "{}",
                CursorInputError::UnsupportedEvent("afterFileEdit".into())
            )
            .contains("afterFileEdit")
        );
    }

    use crate::testing::proptest::arbitrary_utf8_bytes;
    use proptest::prelude::*;

    proptest! {
        // parse() is total over arbitrary input strings: it returns
        // Ok(HookInput) or one of the structured CursorInputError
        // variants and never panics. Drives the fail-closed contract at
        // the adapter boundary.
        #[test]
        fn pbt_parse_is_total_on_arbitrary_utf8(bytes in arbitrary_utf8_bytes()) {
            let body = String::from_utf8_lossy(&bytes);
            let _ = parse(&body);
        }

        // Envelope shapes outside the documented contract must produce a
        // structured error, never a half-populated HookInput.
        #[test]
        fn pbt_invalid_envelope_returns_err(
            body in prop_oneof![
                Just("null".to_string()),
                Just("true".to_string()),
                Just("0".to_string()),
                Just("\"x\"".to_string()),
                Just("[]".to_string()),
                Just(r#"[{"tool_name":"Shell"}]"#.to_string()),
                Just(r#"{"tool_input":{}}"#.to_string()),
                Just(r#"{"hook_event_name":"afterFileEdit","tool_name":"Write"}"#.to_string()),
                Just(r#"{"hook_event_name":"stop"}"#.to_string()),
            ],
        ) {
            match parse(&body) {
                Err(
                    CursorInputError::NotAnObject
                    | CursorInputError::MissingToolName
                    | CursorInputError::UnsupportedEvent(_),
                ) => {},
                other => prop_assert!(
                    false,
                    "expected NotAnObject / MissingToolName / UnsupportedEvent for body {body:?}, got {other:?}",
                ),
            }
        }
    }
}
