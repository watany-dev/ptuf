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

use super::input_helpers::{
    InputError, decode_args, first_non_empty, hook_input, normalize_at_mcp, take_first_string,
};
use crate::hook_input::HookInput;

/// Hook events this adapter understands, quoted verbatim in
/// [`InputError::UnsupportedEvent`].
const CURSOR_EVENTS: &str =
    "preToolUse / beforeShellExecution / beforeReadFile / beforeMCPExecution";

/// Normalise a Cursor stdin body into a [`HookInput`]. Every failure
/// maps to `core.engine.invalid-payload` at the CLI boundary so Cursor
/// stays fail-closed (exit 2 + `permission:deny` JSON).
pub(super) fn parse(body: &str) -> Result<HookInput, InputError> {
    let mut map = super::input_helpers::parse_object(body)?;

    let event = take_first_string(&mut map, &["hook_event_name", "hookEventName"]);

    let raw_input = map
        .remove("tool_input")
        .or_else(|| map.remove("toolInput"))
        .unwrap_or(Value::Null);
    let args = decode_args(raw_input, "text");

    let (tool_name, tool_input) = match event.as_deref().unwrap_or("preToolUse") {
        "preToolUse" => {
            let raw_name = take_first_string(&mut map, &["tool_name", "toolName"])
                .ok_or(InputError::MissingToolName)?;
            normalize(&raw_name, args, &map)
        },
        "beforeShellExecution" => ("Bash".to_string(), reshape_bash(args, &map)),
        "beforeReadFile" => ("Read".to_string(), reshape_path(args, &map)),
        "beforeMCPExecution" => {
            let name = mcp_name(&map, &args).ok_or(InputError::MissingToolName)?;
            (name, Value::Object(args))
        },
        other => {
            return Err(InputError::UnsupportedEvent {
                field: "hook_event_name",
                name: Some(other.to_string()),
                expected: CURSOR_EVENTS,
            });
        },
    };

    Ok(hook_input(tool_name, tool_input))
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

/// Build `mcp__<server>__<tool>` from `metadata.server` / `tool_name`
/// (or their root / args fallbacks). Whitespace, `/`, and `.` in either
/// segment are normalised to `_` so the result is a valid MCP name.
fn mcp_name(root: &Map<String, Value>, args: &Map<String, Value>) -> Option<String> {
    let metadata = root.get("metadata").and_then(Value::as_object);
    let candidates = [metadata, Some(root), Some(args)];
    let server = first_non_empty(&candidates, &["server", "server_name", "serverName"])?;
    let tool = first_non_empty(&candidates, &["tool_name", "toolName", "tool", "name"])?;
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

/// Whether `args[key]` should be backfilled from a fallback. Always true
/// when the key is absent or non-string. `treat_empty_as_missing` also
/// backfills an empty string (used for `command` / `file_path`, where an
/// empty value is useless), while `content` / `old_string` / `new_string`
/// keep an existing empty string as an intentional value.
fn needs_fill(args: &Map<String, Value>, key: &str, treat_empty_as_missing: bool) -> bool {
    args.get(key).is_none_or(|v| match v.as_str() {
        None => true,
        Some(s) => treat_empty_as_missing && s.is_empty(),
    })
}

fn reshape_bash(mut args: Map<String, Value>, root: &Map<String, Value>) -> Value {
    if needs_fill(&args, "command", true)
        && let Some(cmd) =
            first_non_empty(&[Some(&args), Some(root)], &["command", "cmd", "script"])
    {
        args.insert("command".into(), Value::String(cmd));
    }
    Value::Object(args)
}

fn reshape_path(mut args: Map<String, Value>, root: &Map<String, Value>) -> Value {
    if needs_fill(&args, "file_path", true)
        && let Some(path) = find_path(&args, root)
    {
        args.insert("file_path".into(), Value::String(path));
    }
    Value::Object(args)
}

fn reshape_write(mut args: Map<String, Value>, root: &Map<String, Value>) -> Value {
    if needs_fill(&args, "file_path", true)
        && let Some(path) = find_path(&args, root)
    {
        args.insert("file_path".into(), Value::String(path));
    }
    if needs_fill(&args, "content", false)
        && let Some(content) = first_non_empty(
            &[Some(&args), Some(root)],
            &["content", "text", "new_content"],
        )
    {
        args.insert("content".into(), Value::String(content));
    }
    Value::Object(args)
}

fn reshape_edit(mut args: Map<String, Value>, root: &Map<String, Value>) -> Value {
    if needs_fill(&args, "file_path", true)
        && let Some(path) = find_path(&args, root)
    {
        args.insert("file_path".into(), Value::String(path));
    }
    if needs_fill(&args, "old_string", false)
        && let Some(old) = first_non_empty(
            &[Some(&args), Some(root)],
            &["old_string", "oldText", "old"],
        )
    {
        args.insert("old_string".into(), Value::String(old));
    }
    if needs_fill(&args, "new_string", false)
        && let Some(new) = first_non_empty(
            &[Some(&args), Some(root)],
            &["new_string", "newText", "new"],
        )
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
            Err(InputError::UnsupportedEvent { .. })
        ));
    }

    #[test]
    fn cursor_empty_body_is_rejected() {
        assert!(matches!(parse(""), Err(InputError::Empty)));
        assert!(matches!(parse("   \n"), Err(InputError::Empty)));
    }

    #[test]
    fn cursor_invalid_json_is_rejected() {
        assert!(matches!(parse("not-json"), Err(InputError::Json(_))));
    }

    #[test]
    fn cursor_array_payload_is_rejected() {
        assert!(matches!(parse("[]"), Err(InputError::NotAnObject)));
    }

    #[test]
    fn cursor_pretooluse_missing_tool_name_is_rejected() {
        assert!(matches!(
            parse(r#"{"tool_input":{}}"#),
            Err(InputError::MissingToolName)
        ));
    }

    #[test]
    fn cursor_before_mcp_execution_missing_server_is_rejected() {
        let body = r#"{"hook_event_name":"beforeMCPExecution","tool_input":{}}"#;
        assert!(matches!(parse(body), Err(InputError::MissingToolName)));
    }

    #[test]
    fn cursor_mcp_without_metadata_falls_back_to_placeholder() {
        let body = r#"{"tool_name":"MCP","tool_input":{}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__server__tool");
    }

    #[test]
    fn cursor_null_tool_input_decodes_to_empty_object() {
        let body = r#"{"tool_name":"Shell","tool_input":null}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert!(input.tool_input.as_object().unwrap().is_empty());
    }

    #[test]
    fn cursor_non_object_tool_input_wraps_as_text() {
        let body = r#"{"tool_name":"Shell","tool_input":42}"#;
        let input = parse(body).unwrap();
        assert_eq!(
            input.tool_input.get("text").and_then(|v| v.as_i64()),
            Some(42)
        );
    }

    #[test]
    fn cursor_read_uses_files_array_when_path_absent() {
        let body = r#"{"tool_name":"Read","tool_input":{"files":[{"path":"/tmp/from-files"}]}}"#;
        let input = parse(body).unwrap();
        assert_eq!(
            input.tool_input.get("file_path").and_then(|v| v.as_str()),
            Some("/tmp/from-files")
        );
    }

    #[test]
    fn cursor_mcp_server_name_alias_is_accepted() {
        let body =
            r#"{"tool_name":"MCP","tool_input":{},"server_name":"my_srv","toolName":"ping"}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__my_srv__ping");
    }

    #[test]
    fn cursor_at_mcp_with_extra_segments_collapses_underscores() {
        let body = r#"{"tool_name":"@acme/pkg/sub/tool","tool_input":{}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__acme__pkg_sub_tool");
    }

    use crate::testing::proptest::arbitrary_utf8_bytes;
    use proptest::prelude::*;

    proptest! {
        // parse() is total over arbitrary input strings: it returns
        // Ok(HookInput) or one of the structured InputError
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
                    InputError::NotAnObject
                    | InputError::MissingToolName
                    | InputError::UnsupportedEvent { .. },
                ) => {},
                other => prop_assert!(
                    false,
                    "expected NotAnObject / MissingToolName / UnsupportedEvent for body {body:?}, got {other:?}",
                ),
            }
        }
    }
}
