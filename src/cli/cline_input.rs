//! Cline adapter — input normaliser.
//!
//! Cline's `PreToolUse` file hook delivers a payload wrapped in a
//! `hookName` envelope. Two payload shapes are accepted:
//!
//! - SDK / CLI file-hook form: `hookName: "tool_call"` plus a
//!   `tool_call` object (`{ id, name, input }`).
//! - legacy extension form: `hookName: "PreToolUse"` plus a
//!   `preToolUse` object (`{ toolName, parameters }`).
//!
//! When both `tool_call` and `preToolUse` are present, `tool_call` is
//! always preferred. The tool name and the relevant input keys are
//! rewritten so the engine sees a single canonical shape regardless of
//! the agent (`Bash`, `Read`, `Edit`, `Write`, `WebFetch`, `apply_patch`,
//! `mcp__server__tool`). Unknown / unmapped tools fall through with their
//! raw name; the engine's MCP / generic-key extractors then handle them
//! best-effort.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::hook_input::HookInput;

#[derive(Debug, Deserialize)]
struct ClinePayload {
    #[serde(rename = "hookName")]
    hook_name: Option<String>,

    #[serde(default)]
    tool_call: Option<ClineToolCall>,

    #[serde(rename = "preToolUse")]
    pre_tool_use: Option<ClinePreToolUse>,
}

#[derive(Debug, Deserialize)]
struct ClineToolCall {
    id: Option<String>,
    name: String,
    #[serde(default)]
    input: Value,
}

#[derive(Debug, Deserialize)]
struct ClinePreToolUse {
    #[serde(rename = "toolName")]
    tool_name: String,
    #[serde(default)]
    parameters: Value,
}

/// Normalise a Cline stdin body into a [`HookInput`].
///
/// `tool_call` is preferred whenever present; the legacy `preToolUse`
/// object is only consulted when `tool_call` is absent.
pub(super) fn parse(body: &str) -> Result<HookInput, ClineInputError> {
    if body.trim().is_empty() {
        return Err(ClineInputError::Empty);
    }
    let payload: ClinePayload = serde_json::from_str(body).map_err(ClineInputError::Json)?;

    if let Some(call) = payload.tool_call {
        if payload.hook_name.as_deref() != Some("tool_call") {
            return Err(ClineInputError::UnsupportedHookName(payload.hook_name));
        }
        return build(&call.name, call.input, call.id.as_deref());
    }

    if let Some(pre) = payload.pre_tool_use {
        if !matches!(
            payload.hook_name.as_deref(),
            Some("PreToolUse" | "tool_call")
        ) {
            return Err(ClineInputError::UnsupportedHookName(payload.hook_name));
        }
        return build(&pre.tool_name, pre.parameters, None);
    }

    Err(ClineInputError::MissingToolCall)
}

fn build(raw_name: &str, raw_input: Value, id: Option<&str>) -> Result<HookInput, ClineInputError> {
    if raw_name.trim().is_empty() {
        return Err(ClineInputError::EmptyToolName);
    }
    Ok(normalize_call(raw_name, raw_input, id))
}

/// Reasons a Cline payload failed to normalise. Every variant maps to
/// `core.engine.invalid-payload` at the CLI boundary; the Cline adapter
/// surfaces the failure as a `cancel: true` JSON object at exit `0`.
#[derive(Debug)]
pub(super) enum ClineInputError {
    Empty,
    Json(serde_json::Error),
    UnsupportedHookName(Option<String>),
    MissingToolCall,
    EmptyToolName,
}

impl std::fmt::Display for ClineInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "hook payload is empty"),
            Self::Json(err) => write!(f, "hook payload is not valid JSON ({err})"),
            Self::UnsupportedHookName(Some(name)) => {
                write!(
                    f,
                    "unsupported hookName: {name} (expected tool_call or PreToolUse)"
                )
            },
            Self::UnsupportedHookName(None) => {
                write!(f, "missing hookName (expected tool_call or PreToolUse)")
            },
            Self::MissingToolCall => {
                write!(f, "hook payload has neither tool_call nor preToolUse")
            },
            Self::EmptyToolName => write!(f, "hook payload tool name is empty"),
        }
    }
}

/// Build a canonical [`HookInput`] from a raw Cline tool name + input.
///
/// The `id` is the SDK-form `tool_call.id`; the legacy `preToolUse` form
/// has none, so `_cline_tool_call_id` is only attached for SDK payloads.
fn normalize_call(raw_name: &str, raw_input: Value, id: Option<&str>) -> HookInput {
    let mut args = to_args_map(raw_input);

    let tool_name = match raw_name {
        "use_mcp_tool" => normalize_mcp_tool(&mut args),
        "access_mcp_resource" => normalize_mcp_resource(&mut args),
        "execute_command" | "run_command" | "run_commands" | "bash" => {
            normalize_command(&mut args);
            "Bash".to_string()
        },
        "read_file" | "read_files" => {
            normalize_path(&mut args);
            "Read".to_string()
        },
        "editor" | "replace_in_file" | "edit_file" => {
            normalize_path(&mut args);
            "Edit".to_string()
        },
        "write_file" => {
            normalize_path(&mut args);
            "Write".to_string()
        },
        "apply_patch" => {
            normalize_patch(&mut args);
            "apply_patch".to_string()
        },
        "fetch_web" | "fetch_web_content" | "web_fetch" => {
            normalize_url(&mut args);
            "WebFetch".to_string()
        },
        other => normalize_by_fields(other, &mut args),
    };

    args.insert(
        "_cline_tool_name".into(),
        Value::String(raw_name.to_string()),
    );
    if let Some(id) = id {
        args.insert("_cline_tool_call_id".into(), Value::String(id.to_string()));
    }

    HookInput {
        tool_name,
        tool_input: Value::Object(args),
    }
}

/// Coerce a Cline `input` / `parameters` value into a key/value map.
/// Objects pass through; `null` becomes an empty map; anything else is
/// preserved under a `raw` key so the engine can still inspect it.
fn to_args_map(raw: Value) -> Map<String, Value> {
    match raw {
        Value::Object(map) => map,
        Value::Null => Map::new(),
        other => {
            let mut m = Map::new();
            m.insert("raw".into(), other);
            m
        },
    }
}

/// Classify an unknown tool by its input fields (`§5.1` fallbacks):
/// a command-shaped payload is `Bash`, a URL-shaped one is `WebFetch`,
/// and a content+path payload is `Write`. Otherwise the raw name stands.
fn normalize_by_fields(raw_name: &str, args: &mut Map<String, Value>) -> String {
    if has_command(args) {
        normalize_command(args);
        return "Bash".to_string();
    }
    if has_url(args) {
        normalize_url(args);
        return "WebFetch".to_string();
    }
    if has_content_and_path(args) {
        normalize_path(args);
        return "Write".to_string();
    }
    raw_name.to_string()
}

/// `use_mcp_tool` → `mcp__<server>__<tool>`. The MCP `arguments` payload
/// is merged up into the tool input; `server_name` / `tool_name` are
/// kept. When the server or tool name is missing the raw name stands.
fn normalize_mcp_tool(args: &mut Map<String, Value>) -> String {
    let server = string_field(args, "server_name");
    let tool = string_field(args, "tool_name");
    merge_arguments(args);
    match (server, tool) {
        (Some(server), Some(tool)) if !server.is_empty() && !tool.is_empty() => {
            format!("mcp__{server}__{tool}")
        },
        _ => "use_mcp_tool".to_string(),
    }
}

/// `access_mcp_resource` → `mcp__<server>__access_resource`. As with
/// `use_mcp_tool`, the `arguments` payload is merged up. When the server
/// name is missing the raw name stands.
fn normalize_mcp_resource(args: &mut Map<String, Value>) -> String {
    let server = string_field(args, "server_name");
    merge_arguments(args);
    match server {
        Some(server) if !server.is_empty() => format!("mcp__{server}__access_resource"),
        _ => "access_mcp_resource".to_string(),
    }
}

/// Merge an MCP `arguments` payload up into the tool input. An object is
/// flattened (existing keys win); a JSON-encoded string is decoded and
/// flattened when it parses to an object, and otherwise left untouched.
fn merge_arguments(args: &mut Map<String, Value>) {
    let inner = match args.remove("arguments") {
        Some(Value::Object(obj)) => Some(obj),
        Some(Value::String(s)) => {
            if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&s) {
                Some(obj)
            } else {
                args.insert("arguments".into(), Value::String(s));
                None
            }
        },
        Some(other) => {
            args.insert("arguments".into(), other);
            None
        },
        None => None,
    };
    if let Some(inner) = inner {
        for (key, value) in inner {
            args.entry(key).or_insert(value);
        }
    }
}

/// Promote a Cline command alias into the canonical `command` key.
/// Priority: existing non-empty `command` → `cmd` / `shellCommand` →
/// newline-joined `commands[]`. Original keys are preserved.
fn normalize_command(args: &mut Map<String, Value>) {
    let has_command = args
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if has_command {
        return;
    }
    if let Some(cmd) = first_string(args, &["cmd", "shellCommand"]) {
        args.insert("command".into(), Value::String(cmd));
        return;
    }
    if let Some(joined) = join_commands(args) {
        args.insert("command".into(), Value::String(joined));
    }
}

fn join_commands(args: &Map<String, Value>) -> Option<String> {
    let arr = args.get("commands")?.as_array()?;
    let parts: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

/// Promote a Cline path alias into the canonical `file_path` key.
/// Priority: `file_path` → `filePath` → `path` → `absolutePath` →
/// `relativePath`. Original keys are preserved.
fn normalize_path(args: &mut Map<String, Value>) {
    if let Some(path) = first_string(
        args,
        &[
            "file_path",
            "filePath",
            "path",
            "absolutePath",
            "relativePath",
        ],
    ) {
        args.insert("file_path".into(), Value::String(path));
    }
}

/// Promote a Cline URL alias into the canonical `url` key.
/// Priority: `url` → `uri` → `href`. Original keys are preserved.
fn normalize_url(args: &mut Map<String, Value>) {
    if let Some(url) = first_string(args, &["url", "uri", "href"]) {
        args.insert("url".into(), Value::String(url));
    }
}

fn normalize_patch(args: &mut Map<String, Value>) {
    if let Some(body) = first_string(args, &["command", "patchText", "patch", "content"]) {
        args.insert("command".into(), Value::String(body));
    }
}

fn has_command(args: &Map<String, Value>) -> bool {
    ["command", "cmd", "shellCommand", "commands"]
        .iter()
        .any(|key| args.contains_key(*key))
}

fn has_url(args: &Map<String, Value>) -> bool {
    ["url", "uri", "href"]
        .iter()
        .any(|key| args.contains_key(*key))
}

fn has_content_and_path(args: &Map<String, Value>) -> bool {
    args.contains_key("content")
        && [
            "file_path",
            "filePath",
            "path",
            "absolutePath",
            "relativePath",
        ]
        .iter()
        .any(|key| args.contains_key(*key))
}

/// Return the first key in `keys` whose value is a JSON string, without
/// removing it — Cline normalisation keeps the original alias keys so
/// audit records still show the agent's raw payload.
fn first_string(args: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = args.get(*key).and_then(Value::as_str) {
            return Some(s.to_string());
        }
    }
    None
}

fn string_field(args: &Map<String, Value>, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cline_sdk_tool_call_command_normalizes_to_bash() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": {
                "id": "c1",
                "name": "run_commands",
                "input": { "command": "rm -rf /" }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input["command"], "rm -rf /");
        assert_eq!(input.tool_input["_cline_tool_name"], "run_commands");
        assert_eq!(input.tool_input["_cline_tool_call_id"], "c1");
    }

    #[test]
    fn cline_legacy_pretooluse_normalizes_to_bash() {
        let body = r#"{
            "hookName": "PreToolUse",
            "preToolUse": {
                "toolName": "execute_command",
                "parameters": { "command": "rm -rf /" }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input["command"], "rm -rf /");
        assert_eq!(input.tool_input["_cline_tool_name"], "execute_command");
        assert!(input.tool_input.get("_cline_tool_call_id").is_none());
    }

    #[test]
    fn cline_tool_call_is_preferred_over_pretooluse() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "id": "c1", "name": "run_commands", "input": { "command": "a" } },
            "preToolUse": { "toolName": "execute_command", "parameters": { "command": "b" } }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.bash_command(), Some("a"));
    }

    #[test]
    fn cline_read_files_file_path_normalizes_to_read() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "id": "c1", "name": "read_files", "input": { "filePath": ".env" } }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.tool_input["file_path"], ".env");
        assert_eq!(input.tool_input["filePath"], ".env");
    }

    #[test]
    fn cline_mcp_tool_normalizes_to_mcp_name() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": {
                "name": "use_mcp_tool",
                "input": {
                    "server_name": "github",
                    "tool_name": "create_or_update_file",
                    "arguments": { "path": ".env", "content": "SECRET=..." }
                }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__github__create_or_update_file");
        assert_eq!(input.tool_input["path"], ".env");
        assert_eq!(input.tool_input["content"], "SECRET=...");
        assert!(input.tool_input.get("arguments").is_none());
        assert!(input.tool_input.get("_cline_tool_call_id").is_none());
    }

    #[test]
    fn cline_mcp_arguments_json_string_is_decoded() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": {
                "name": "use_mcp_tool",
                "input": {
                    "server_name": "github",
                    "tool_name": "push_files",
                    "arguments": "{\"path\":\"/tmp/x\"}"
                }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__github__push_files");
        assert_eq!(input.tool_input["path"], "/tmp/x");
    }

    #[test]
    fn cline_mcp_arguments_non_json_string_is_kept() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": {
                "name": "use_mcp_tool",
                "input": { "server_name": "s", "tool_name": "t", "arguments": "not-json" }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__s__t");
        assert_eq!(input.tool_input["arguments"], "not-json");
    }

    #[test]
    fn cline_access_mcp_resource_normalizes_to_access_resource() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": {
                "name": "access_mcp_resource",
                "input": { "server_name": "files", "uri": "file:///etc/passwd" }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__files__access_resource");
    }

    #[test]
    fn cline_commands_array_is_newline_joined() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": {
                "name": "run_commands",
                "input": { "commands": ["npm install", "npm test"] }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("npm install\nnpm test"));
    }

    #[test]
    fn cline_write_file_normalizes_to_write() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": {
                "name": "write_file",
                "input": { "path": "/tmp/x", "content": "AKIA..." }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Write");
        assert_eq!(input.file_path(), Some("/tmp/x"));
        assert_eq!(input.write_payload(), Some("AKIA..."));
    }

    #[test]
    fn cline_apply_patch_normalizes_patch_body_to_command() {
        let patch = "*** Begin Patch\n*** Add File: src/x\n+hello\n*** End Patch\n";
        let body = format!(
            r#"{{
            "hookName": "tool_call",
            "tool_call": {{ "name": "apply_patch", "input": {{ "patch": {patch_json} }} }}
        }}"#,
            patch_json = serde_json::to_string(patch).unwrap(),
        );
        let input = parse(&body).unwrap();
        assert_eq!(input.tool_name, "apply_patch");
        assert_eq!(input.tool_input["command"], patch);
        assert_eq!(input.tool_input["patch"], patch);
    }

    #[test]
    fn cline_web_fetch_normalizes_to_webfetch() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "name": "fetch_web", "input": { "uri": "https://x" } }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "WebFetch");
        assert_eq!(input.web_fetch_url(), Some("https://x"));
    }

    #[test]
    fn cline_unknown_tool_with_command_field_falls_back_to_bash() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "name": "mystery_runner", "input": { "command": "rm -rf /" } }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("rm -rf /"));
    }

    #[test]
    fn cline_unknown_tool_without_signals_keeps_raw_name() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "name": "list_files", "input": { "depth": 2 } }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "list_files");
        assert_eq!(input.tool_input["_cline_tool_name"], "list_files");
    }

    #[test]
    fn cline_non_object_input_falls_back_to_raw() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "name": "weird", "input": 42 }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "weird");
        assert_eq!(input.tool_input["raw"], 42);
    }

    #[test]
    fn cline_missing_input_is_accepted() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "name": "run_commands" }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert!(input.tool_input.is_object());
    }

    #[test]
    fn cline_empty_body_is_rejected() {
        assert!(matches!(parse(""), Err(ClineInputError::Empty)));
        assert!(matches!(parse("   \n"), Err(ClineInputError::Empty)));
    }

    #[test]
    fn cline_invalid_json_is_rejected() {
        assert!(matches!(parse("not-json"), Err(ClineInputError::Json(_))));
    }

    #[test]
    fn cline_missing_tool_call_is_rejected() {
        let body = r#"{"hookName":"tool_call"}"#;
        assert!(matches!(parse(body), Err(ClineInputError::MissingToolCall)));
    }

    #[test]
    fn cline_unsupported_hook_name_is_rejected() {
        let body = r#"{"hookName":"sessionStart","tool_call":{"name":"bash","input":{}}}"#;
        assert!(matches!(
            parse(body),
            Err(ClineInputError::UnsupportedHookName(Some(_)))
        ));
    }

    #[test]
    fn cline_missing_hook_name_with_tool_call_is_rejected() {
        let body = r#"{"tool_call":{"name":"bash","input":{}}}"#;
        assert!(matches!(
            parse(body),
            Err(ClineInputError::UnsupportedHookName(None))
        ));
    }

    #[test]
    fn cline_legacy_pretooluse_rejects_wrong_hook_name() {
        let body =
            r#"{"hookName":"sessionStart","preToolUse":{"toolName":"bash","parameters":{}}}"#;
        assert!(matches!(
            parse(body),
            Err(ClineInputError::UnsupportedHookName(_))
        ));
    }

    #[test]
    fn cline_empty_tool_name_is_rejected() {
        let body = r#"{"hookName":"tool_call","tool_call":{"name":"   ","input":{}}}"#;
        assert!(matches!(parse(body), Err(ClineInputError::EmptyToolName)));
    }

    #[test]
    fn cline_array_payload_is_rejected() {
        assert!(matches!(parse("[]"), Err(ClineInputError::Json(_))));
    }

    #[test]
    fn cline_input_error_display_covers_all_variants() {
        let bad = serde_json::from_str::<Value>("nope").unwrap_err();
        assert!(format!("{}", ClineInputError::Empty).contains("empty"));
        assert!(format!("{}", ClineInputError::Json(bad)).contains("not valid JSON"));
        assert!(
            format!("{}", ClineInputError::UnsupportedHookName(Some("x".into())))
                .contains("unsupported hookName")
        );
        assert!(
            format!("{}", ClineInputError::UnsupportedHookName(None)).contains("missing hookName")
        );
        assert!(format!("{}", ClineInputError::MissingToolCall).contains("neither tool_call"));
        assert!(format!("{}", ClineInputError::EmptyToolName).contains("tool name is empty"));
    }

    #[test]
    fn cline_command_alias_cmd_is_promoted() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "name": "run_commands", "input": { "cmd": "ls -la" } }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("ls -la"));
    }

    #[test]
    fn cline_command_alias_shell_command_is_promoted() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "name": "bash", "input": { "shellCommand": "whoami" } }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("whoami"));
    }

    #[test]
    fn cline_empty_commands_array_leaves_command_unset() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "name": "run_commands", "input": { "commands": [] } }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert!(input.tool_input.get("command").is_none());
    }

    #[test]
    fn cline_mcp_tool_without_server_keeps_raw_name() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": {
                "name": "use_mcp_tool",
                "input": { "tool_name": "t", "arguments": { "path": ".env" } }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "use_mcp_tool");
        // arguments are still merged up even when the MCP name cannot be built.
        assert_eq!(input.tool_input["path"], ".env");
    }

    #[test]
    fn cline_mcp_resource_without_server_keeps_raw_name() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "name": "access_mcp_resource", "input": { "uri": "x" } }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "access_mcp_resource");
    }

    #[test]
    fn cline_mcp_arguments_non_object_value_is_kept() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": {
                "name": "use_mcp_tool",
                "input": { "server_name": "s", "tool_name": "t", "arguments": [1, 2] }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__s__t");
        assert_eq!(input.tool_input["arguments"], serde_json::json!([1, 2]));
    }

    #[test]
    fn cline_unknown_tool_with_url_field_falls_back_to_webfetch() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": { "name": "mystery_fetcher", "input": { "href": "https://x" } }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "WebFetch");
        assert_eq!(input.web_fetch_url(), Some("https://x"));
    }

    #[test]
    fn cline_unknown_tool_with_content_and_path_falls_back_to_write() {
        let body = r#"{
            "hookName": "tool_call",
            "tool_call": {
                "name": "mystery_writer",
                "input": { "absolutePath": "/tmp/x", "content": "data" }
            }
        }"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Write");
        assert_eq!(input.file_path(), Some("/tmp/x"));
        assert_eq!(input.write_payload(), Some("data"));
    }

    use crate::testing::proptest::arbitrary_utf8_bytes;
    use proptest::prelude::*;

    proptest! {
        // parse() is total over arbitrary input strings: it returns
        // Ok(HookInput) or one of the structured ClineInputError variants
        // and never panics. Drives the fail-closed contract at the
        // adapter boundary.
        #[test]
        fn pbt_parse_is_total_on_arbitrary_utf8(bytes in arbitrary_utf8_bytes()) {
            let body = String::from_utf8_lossy(&bytes);
            let _ = parse(&body);
        }

        // Envelope shapes outside the documented `{ hookName, tool_call |
        // preToolUse }` contract must produce a structured error, never a
        // half-populated HookInput.
        #[test]
        fn pbt_invalid_envelope_returns_err(
            body in prop_oneof![
                Just("null".to_string()),
                Just("true".to_string()),
                Just("0".to_string()),
                Just("\"x\"".to_string()),
                Just("[]".to_string()),
                Just("{}".to_string()),
                Just(r#"{"hookName":"tool_call"}"#.to_string()),
                Just(r#"{"tool_call":{"name":"bash","input":{}}}"#.to_string()),
                Just(r#"{"hookName":"weird","tool_call":{"name":"bash","input":{}}}"#.to_string()),
                Just(r#"{"hookName":"tool_call","tool_call":{"name":"","input":{}}}"#.to_string()),
            ],
        ) {
            match parse(&body) {
                Err(
                    ClineInputError::Empty
                    | ClineInputError::Json(_)
                    | ClineInputError::UnsupportedHookName(_)
                    | ClineInputError::MissingToolCall
                    | ClineInputError::EmptyToolName,
                ) => {},
                other => prop_assert!(
                    false,
                    "expected a structured error for body {body:?}, got {other:?}",
                ),
            }
        }
    }

    #[test]
    fn cline_apply_patch_pem_body_denies_via_engine() {
        use crate::config::Config;
        use crate::decision::DecisionKind;
        use crate::engine::Engine;
        use crate::plugin::PluginSet;

        let pem = "-----BEGIN RSA PRIVATE KEY-----\nX\n-----END RSA PRIVATE KEY-----";
        let patch = format!("*** Begin Patch\n*** Add File: src/notes.md\n+{pem}\n*** End Patch\n");
        let body = format!(
            r#"{{
            "hookName": "tool_call",
            "tool_call": {{ "name": "apply_patch", "input": {{ "patch": {patch_json} }} }}
        }}"#,
            patch_json = serde_json::to_string(&patch).unwrap(),
        );
        let input = parse(&body).unwrap();
        let engine = Engine::with_components(Config::default(), PluginSet::new());
        let decision = engine.decide(&input).decision;
        assert_eq!(decision.kind(), DecisionKind::Deny, "got {decision:?}");
    }
}
