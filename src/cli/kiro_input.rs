//! Kiro CLI adapter — input normaliser for both hook generations.
//!
//! Every Kiro `PreToolUse` hook receives a payload of the shape:
//!
//! ```json
//! {
//!   "hook_event_name": "preToolUse" | "PreToolUse",
//!   "cwd": "...",
//!   "session_id": "...",
//!   "tool_name": "...",
//!   "tool_input": { ... }
//! }
//! ```
//!
//! The two engine generations differ in the event spelling and in the
//! tool vocabulary:
//!
//! - **v2** (CLI 2.x / the V2 and Classic engines) sends camelCase
//!   `preToolUse` and CLI 2.x tool names (`shell`, `execute_bash`,
//!   `fs_read`, `fs_write`, `@server/tool`, …).
//! - **v3** (the V3 engine) sends PascalCase `PreToolUse` and the V3
//!   built-in tool IDs (`execute_bash`, `read_file`, `fs_write`,
//!   `str_replace`, `delete_file`, `mcp_<server>_<tool>`, …).
//!
//! The event spelling identifies the engine that fired the hook, so it —
//! not the adapter token the hook line was installed with — picks the
//! vocabulary. That keeps an install guarding after the engine underneath
//! it changes: the V3 engine still runs legacy agent-profile hooks (it
//! accepts the camelCase trigger as an alias) but sends them the V3
//! payload, and a pre-versioning `ptuf hook kiro` line now resolves to
//! the v3 adapter while a V2 engine keeps feeding it v2 payloads. The
//! adapter token only decides how a payload *without* an event name is
//! read.
//!
//! Tool names are rewritten to Claude Code's canonical form (`Bash`,
//! `Read`, `Write`, `Edit`, `WebFetch`, `mcp__server__tool`) together
//! with the relevant `tool_input` keys, so the engine sees a single
//! canonical shape regardless of agent. Unknown / unmapped tools fall
//! through with their raw name; the engine's MCP / generic-key extractors
//! then handle them best-effort.

use serde_json::{Map, Value};

use super::input_helpers::{
    InputError, decode_args, first_string, hook_input, normalize_at_mcp, take_first_string,
};
use crate::hook_input::HookInput;

/// Event spelling of the v2 engines (camelCase trigger names).
const V2_EVENT: &str = "preToolUse";

/// Event spelling of the V3 engine (PascalCase trigger names).
const V3_EVENT: &str = "PreToolUse";

/// Both spellings, for the rejection message.
const EXPECTED_EVENTS: &str = "PreToolUse or preToolUse";

/// Which Kiro tool vocabulary a payload speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Generation {
    V2,
    V3,
}

/// Normalise a stdin body for `ptuf hook kiro-v2`. A payload without
/// `hook_event_name` is read with the CLI 2.x vocabulary.
pub(super) fn parse(body: &str) -> Result<HookInput, InputError> {
    parse_as(body, Generation::V2)
}

/// Normalise a stdin body for `ptuf hook kiro-v3`. A payload without
/// `hook_event_name` is read with the V3 vocabulary.
pub(super) fn parse_v3(body: &str) -> Result<HookInput, InputError> {
    parse_as(body, Generation::V3)
}

/// Every failure maps to `core.engine.invalid-payload` at the CLI
/// boundary so Kiro stays fail-closed (exit 2 + stderr reason).
fn parse_as(body: &str, fallback: Generation) -> Result<HookInput, InputError> {
    let mut map = super::input_helpers::parse_object(body)?;

    let generation = match map.get("hook_event_name").and_then(Value::as_str) {
        None => fallback,
        Some(V2_EVENT) => Generation::V2,
        Some(V3_EVENT) => Generation::V3,
        Some(event) => {
            return Err(InputError::UnsupportedEvent {
                field: "hook_event_name",
                name: Some(event.to_string()),
                expected: EXPECTED_EVENTS,
            });
        },
    };

    let raw_name =
        take_first_string(&mut map, &["tool_name"]).ok_or(InputError::MissingToolName)?;
    let args = decode_args(map.remove("tool_input").unwrap_or(Value::Null), "raw");

    let (tool_name, tool_input) = match generation {
        Generation::V2 => normalize_v2(raw_name, args),
        Generation::V3 => normalize_v3(raw_name, args),
    };
    Ok(hook_input(tool_name, tool_input))
}

fn normalize_v2(raw_name: String, args: Map<String, Value>) -> (String, Value) {
    match raw_name.as_str() {
        "shell" | "execute_bash" | "execute_cmd" => ("Bash".into(), reshape_bash(args)),
        "read" | "fs_read" | "fsRead" => ("Read".into(), reshape_path(args)),
        "write" | "fs_write" | "fsWrite" => ("Write".into(), reshape_write(args)),
        "web_fetch" | "webFetch" => ("WebFetch".into(), Value::Object(args)),
        _ => (
            normalize_at_mcp(&raw_name).unwrap_or(raw_name),
            Value::Object(args),
        ),
    }
}

/// V3 built-in tool IDs, per the V3 tool catalog
/// (<https://kiro.dev/docs/tools/>). Argument names follow the input
/// schemas the V3 engine validates tool calls against: `path` + `text`
/// for `fs_write` / `fs_append`, `path` + `oldStr` / `newStr` for
/// `str_replace`, `targetFile` for `delete_file`.
fn normalize_v3(raw_name: String, args: Map<String, Value>) -> (String, Value) {
    match raw_name.as_str() {
        // `execute_pwsh` is the Windows variant of the same tool; the
        // command string is still the thing the shell rules inspect.
        "execute_bash" | "execute_pwsh" => ("Bash".into(), reshape_bash(args)),
        "read_file" => ("Read".into(), reshape_path(args)),
        "fs_write" | "fs_append" => ("Write".into(), reshape_write(args)),
        "str_replace" => ("Edit".into(), reshape_str_replace(args)),
        // Deleting a file is a destructive write to that path: surface
        // it as `Write` so path-based rules (self-protection, sensitive
        // files) see the target. There is no content to scan.
        "delete_file" => ("Write".into(), reshape_delete(args)),
        "web_fetch" => ("WebFetch".into(), Value::Object(args)),
        // Read-only discovery tools with no `Read` equivalent. Routing
        // them through the MCP namespace lets the generic `path`
        // extractor see `list_directory`'s target.
        "list_directory" | "file_search" | "grep_search" => {
            (format!("mcp__kiro__{raw_name}"), Value::Object(args))
        },
        _ => (
            normalize_mcp_id(&raw_name).unwrap_or(raw_name),
            Value::Object(args),
        ),
    }
}

/// Map a V3 MCP tool ID (`mcp_<server>_<tool>`) to
/// `mcp__<server>__<tool>`.
///
/// The V3 engine builds the ID by joining server and tool with `_`,
/// replacing whitespace and `-` with `_`, stripping other punctuation,
/// lowercasing, and truncating to 64 characters. That is lossy: the
/// boundary between server and tool cannot be recovered when the server
/// name itself contains `_` or `-`. The split is taken at the first `_`,
/// which is exact for single-word server names; for the rest the
/// namespace is a prefix of the real server name. Generic argument
/// extraction (`path` / `url` / `content`) is unaffected either way.
fn normalize_mcp_id(name: &str) -> Option<String> {
    let rest = name.strip_prefix("mcp_")?;
    let (server, tool) = rest.split_once('_')?;
    if server.is_empty() || tool.is_empty() {
        return None;
    }
    Some(format!("mcp__{server}__{tool}"))
}

fn reshape_bash(mut args: Map<String, Value>) -> Value {
    if needs_string(&args, "command")
        && let Some(cmd) = take_first_string(&mut args, &["cmd", "script"])
    {
        args.insert("command".into(), Value::String(cmd));
    }
    Value::Object(args)
}

fn reshape_path(mut args: Map<String, Value>) -> Value {
    if needs_string(&args, "file_path")
        && let Some(path) = first_path(&args)
    {
        args.insert("file_path".into(), Value::String(path));
    }
    Value::Object(args)
}

fn reshape_write(mut args: Map<String, Value>) -> Value {
    if needs_string(&args, "file_path")
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

/// `str_replace` carries `path` / `oldStr` / `newStr`; fill the canonical
/// `Edit` keys (`file_path` / `old_string` / `new_string`). The path is
/// copied so audit records keep the agent's own key; the edit strings are
/// moved, as `reshape_write` does with `text`, so a large edit is not held
/// twice.
fn reshape_str_replace(mut args: Map<String, Value>) -> Value {
    if needs_string(&args, "file_path")
        && let Some(path) = first_string(&args, &["path"])
    {
        args.insert("file_path".into(), Value::String(path));
    }
    for (from, to) in [("oldStr", "old_string"), ("newStr", "new_string")] {
        if needs_string(&args, to)
            && let Some(value) = take_first_string(&mut args, &[from])
        {
            args.insert(to.into(), Value::String(value));
        }
    }
    Value::Object(args)
}

/// `delete_file` names its target `targetFile`.
fn reshape_delete(mut args: Map<String, Value>) -> Value {
    if needs_string(&args, "file_path")
        && let Some(path) = first_string(&args, &["targetFile"])
    {
        args.insert("file_path".into(), Value::String(path));
    }
    Value::Object(args)
}

/// `key` is absent, non-string, or empty.
fn needs_string(args: &Map<String, Value>, key: &str) -> bool {
    args.get(key)
        .is_none_or(|v| v.as_str().is_none_or(str::is_empty))
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
    fn kiro_mcp_empty_extra_segment_falls_through() {
        let body = r#"{"tool_name":"@a/b/","tool_input":{}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "@a/b/");
    }

    #[test]
    fn kiro_read_path_field_is_promoted_to_file_path() {
        let body = r#"{"tool_name":"read","tool_input":{"path":"/tmp/single"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.file_path(), Some("/tmp/single"));
    }

    #[test]
    fn kiro_read_with_no_path_leaves_file_path_unset() {
        let body = r#"{"tool_name":"read","tool_input":{}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.file_path(), None);
    }

    #[test]
    fn kiro_write_uses_paths_array_when_file_path_absent() {
        let body = r#"{"tool_name":"fs_write","tool_input":{"paths":["/tmp/w"],"text":"hi"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Write");
        assert_eq!(input.file_path(), Some("/tmp/w"));
        assert_eq!(input.write_payload(), Some("hi"));
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
            Err(InputError::UnsupportedEvent { .. })
        ));
    }

    #[test]
    fn kiro_invalid_json_is_rejected() {
        assert!(matches!(parse("not-json"), Err(InputError::Json(_))));
    }

    #[test]
    fn kiro_empty_body_is_rejected() {
        assert!(matches!(parse(""), Err(InputError::Empty)));
        assert!(matches!(parse("   \n"), Err(InputError::Empty)));
    }

    #[test]
    fn kiro_array_payload_is_rejected() {
        assert!(matches!(parse("[]"), Err(InputError::NotAnObject)));
    }

    #[test]
    fn kiro_missing_tool_name_is_rejected() {
        assert!(matches!(
            parse(r#"{"tool_input":{}}"#),
            Err(InputError::MissingToolName)
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

    // --- Kiro CLI v3 ---------------------------------------------------
    //
    // Payload shapes below follow the V3 engine: `hook_event_name` is the
    // PascalCase trigger, `tool_name` the internal tool ID, and
    // `tool_input` the arguments as validated by that tool's schema.

    fn v3(tool: &str, input: &str) -> HookInput {
        let body = format!(
            r#"{{"session_id":"s","hook_event_name":"PreToolUse","cwd":"/repo","tool_name":"{tool}","tool_input":{input}}}"#
        );
        parse_v3(&body).unwrap()
    }

    #[test]
    fn kiro_v3_execute_bash_and_pwsh_normalize_to_bash() {
        for tool in ["execute_bash", "execute_pwsh"] {
            let input = v3(
                tool,
                r#"{"command":"rm -rf /","description":"x","cwd":null}"#,
            );
            assert_eq!(input.tool_name, "Bash", "{tool}");
            assert_eq!(input.bash_command(), Some("rm -rf /"));
        }
    }

    #[test]
    fn kiro_v3_read_file_promotes_path() {
        let input = v3(
            "read_file",
            r#"{"path":"/repo/.env","offset":0,"limit":10}"#,
        );
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.file_path(), Some("/repo/.env"));
    }

    #[test]
    fn kiro_v3_fs_write_and_fs_append_normalize_to_write() {
        for tool in ["fs_write", "fs_append"] {
            let input = v3(
                tool,
                r#"{"path":"/repo/a.txt","text":"AKIA0000000000000000"}"#,
            );
            assert_eq!(input.tool_name, "Write", "{tool}");
            assert_eq!(input.file_path(), Some("/repo/a.txt"));
            assert_eq!(input.write_payload(), Some("AKIA0000000000000000"));
        }
    }

    #[test]
    fn kiro_v3_str_replace_normalizes_to_edit() {
        let input = v3(
            "str_replace",
            r#"{"path":"/repo/a.rs","oldStr":"old","newStr":"new","replace_all":false}"#,
        );
        assert_eq!(input.tool_name, "Edit");
        assert_eq!(input.file_path(), Some("/repo/a.rs"));
        assert_eq!(input.write_payload(), Some("new"));
        assert_eq!(
            input.tool_input.get("old_string").and_then(Value::as_str),
            Some("old")
        );
    }

    #[test]
    fn kiro_v3_str_replace_keeps_canonical_keys_when_present() {
        let input = v3(
            "str_replace",
            r#"{"path":"/a","file_path":"/b","newStr":"x","new_string":"y"}"#,
        );
        assert_eq!(input.file_path(), Some("/b"));
        assert_eq!(input.write_payload(), Some("y"));
    }

    #[test]
    fn kiro_v3_delete_file_surfaces_target_as_write_path() {
        let input = v3(
            "delete_file",
            r#"{"explanation":"cleanup","targetFile":"/repo/.kiro/hooks/ptuf.json"}"#,
        );
        assert_eq!(input.tool_name, "Write");
        assert_eq!(input.file_path(), Some("/repo/.kiro/hooks/ptuf.json"));
        assert_eq!(input.write_payload(), None);
    }

    #[test]
    fn kiro_v3_web_fetch_normalizes() {
        let input = v3(
            "web_fetch",
            r#"{"url":"https://example.com","mode":"full"}"#,
        );
        assert_eq!(input.tool_name, "WebFetch");
        assert_eq!(input.web_fetch_url(), Some("https://example.com"));
    }

    #[test]
    fn kiro_v3_discovery_tools_route_through_mcp_namespace() {
        let input = v3("list_directory", r#"{"path":"/home/u/.ssh","depth":1}"#);
        assert_eq!(input.tool_name, "mcp__kiro__list_directory");
        assert_eq!(input.file_path(), Some("/home/u/.ssh"));
        assert_eq!(
            v3("grep_search", r#"{"query":"x"}"#).tool_name,
            "mcp__kiro__grep_search"
        );
        assert_eq!(
            v3("file_search", r#"{"query":"x"}"#).tool_name,
            "mcp__kiro__file_search"
        );
    }

    #[test]
    fn kiro_v3_mcp_tool_id_normalizes() {
        let input = v3("mcp_postgres_query", r#"{"sql":"select 1"}"#);
        assert_eq!(input.tool_name, "mcp__postgres__query");
        assert_eq!(input.mcp_namespace(), Some("postgres"));
        assert_eq!(input.mcp_tool_name(), Some("query"));
        assert_eq!(
            v3("mcp_github_create_or_update_file", "{}").tool_name,
            "mcp__github__create_or_update_file"
        );
    }

    #[test]
    fn kiro_v3_malformed_mcp_ids_fall_through() {
        for raw in ["mcp_", "mcp_server", "mcp__tool", "mcp_server_"] {
            assert_eq!(v3(raw, "{}").tool_name, raw);
        }
    }

    #[test]
    fn kiro_v3_unknown_tool_passes_through() {
        assert_eq!(
            v3("remote_web_search", r#"{"query":"x"}"#).tool_name,
            "remote_web_search"
        );
        // CLI 2.x names are not V3 IDs.
        assert_eq!(v3("shell", r#"{"command":"ls"}"#).tool_name, "shell");
    }

    #[test]
    fn kiro_v3_without_event_name_reads_v3_vocabulary() {
        let input = parse_v3(r#"{"tool_name":"read_file","tool_input":{"path":"/x"}}"#).unwrap();
        assert_eq!(input.tool_name, "Read");
        // ...whereas the v2 adapter reads the same body with CLI 2.x names.
        let input = parse(r#"{"tool_name":"read_file","tool_input":{"path":"/x"}}"#).unwrap();
        assert_eq!(input.tool_name, "read_file");
    }

    /// The V3 engine runs legacy agent-profile hooks too, sending them the
    /// V3 payload: a `kiro-v2` install keeps guarding after the engine
    /// upgrade instead of failing closed on every call.
    #[test]
    fn kiro_v2_adapter_reads_v3_engine_payloads() {
        let body = r#"{"hook_event_name":"PreToolUse","tool_name":"str_replace","tool_input":{"path":"/a","newStr":"n"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Edit");
        assert_eq!(input.file_path(), Some("/a"));
    }

    /// A pre-versioning `ptuf hook kiro` line now resolves to the v3
    /// adapter, but under the V2 engine it still receives v2 payloads.
    #[test]
    fn kiro_v3_adapter_reads_v2_engine_payloads() {
        let body =
            r#"{"hook_event_name":"preToolUse","tool_name":"shell","tool_input":{"command":"ls"}}"#;
        let input = parse_v3(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("ls"));
    }

    #[test]
    fn kiro_v3_rejects_non_pre_tool_use_events() {
        for event in ["PostToolUse", "SessionStart", "Stop", "pretooluse", ""] {
            let body = format!(r#"{{"hook_event_name":"{event}","tool_name":"execute_bash"}}"#);
            match parse_v3(&body) {
                Err(err @ InputError::UnsupportedEvent { .. }) => assert_eq!(
                    err.to_string(),
                    format!(
                        "unsupported hook_event_name: {event} (expected PreToolUse or preToolUse)"
                    )
                ),
                other => panic!("{event}: expected UnsupportedEvent, got {other:?}"),
            }
        }
    }

    use crate::testing::proptest::arbitrary_utf8_bytes;
    use proptest::prelude::*;

    proptest! {
        // parse() is total over arbitrary input strings: it returns
        // Ok(HookInput) or one of the structured InputError variants
        // and never panics. Drives the fail-closed contract at the
        // adapter boundary.
        #[test]
        fn pbt_parse_is_total_on_arbitrary_utf8(bytes in arbitrary_utf8_bytes()) {
            let body = String::from_utf8_lossy(&bytes);
            let _ = parse(&body);
            let _ = parse_v3(&body);
        }

        // Envelope shapes outside the documented `{ hook_event_name?,
        // tool_name, tool_input? }` contract must produce a structured
        // error, never a half-populated HookInput. Includes the
        // `hook_event_name != preToolUse` branch which Copilot does not
        // have.
        #[test]
        fn pbt_invalid_envelope_returns_err(
            body in prop_oneof![
                Just("null".to_string()),
                Just("true".to_string()),
                Just("false".to_string()),
                Just("0".to_string()),
                Just("\"x\"".to_string()),
                Just("[]".to_string()),
                Just(r#"[{"tool_name":"shell"}]"#.to_string()),
                Just("{}".to_string()),
                Just(r#"{"tool_input":{}}"#.to_string()),
                Just(r#"{"hook_event_name":"postToolUse","tool_name":"shell"}"#.to_string()),
                Just(r#"{"hook_event_name":"sessionStart","tool_name":"shell"}"#.to_string()),
                Just(r#"{"hook_event_name":"PostToolUse","tool_name":"execute_bash"}"#.to_string()),
            ],
        ) {
            for result in [parse(&body), parse_v3(&body)] {
                match result {
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
}
