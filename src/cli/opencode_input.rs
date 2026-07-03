//! OpenCode adapter — input normaliser.
//!
//! OpenCode's TypeScript plugin forwards raw tool-call events to
//! `ptuf hook opencode`. This module rewrites OpenCode's native tool
//! vocabulary into the canonical names the policy engine expects (`Bash`,
//! `Read`, `mcp__opencode__grep`, …) before evaluation.

use serde_json::{Map, Value};

use crate::hook_input::HookInput;

/// Normalise an OpenCode stdin body into a [`HookInput`].
pub(super) fn parse(body: &str) -> Result<HookInput, OpencodeInputError> {
    if body.trim().is_empty() {
        return Err(OpencodeInputError::Empty);
    }
    let value: Value = serde_json::from_str(body).map_err(OpencodeInputError::Json)?;
    let Value::Object(mut map) = value else {
        return Err(OpencodeInputError::NotAnObject);
    };

    let raw_name = map
        .remove("tool_name")
        .or_else(|| map.remove("toolName"))
        .or_else(|| map.remove("name"))
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(OpencodeInputError::MissingToolName)?;
    if raw_name.trim().is_empty() {
        return Err(OpencodeInputError::EmptyToolName);
    }

    let raw_input = map
        .remove("tool_input")
        .or_else(|| map.remove("toolInput"))
        .unwrap_or(Value::Null);
    let args = decode_tool_input(raw_input)?;

    let (tool_name, tool_input) = normalize(&raw_name, args);

    Ok(HookInput {
        tool_name,
        tool_input,
    })
}

/// Reasons an OpenCode payload failed to normalise.
#[derive(Debug)]
pub(super) enum OpencodeInputError {
    Empty,
    Json(serde_json::Error),
    NotAnObject,
    MissingToolName,
    EmptyToolName,
    ToolInputNotObject,
}

impl std::fmt::Display for OpencodeInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "hook payload is empty"),
            Self::Json(err) => write!(f, "hook payload is not valid JSON ({err})"),
            Self::NotAnObject => write!(f, "hook payload must be a JSON object"),
            Self::MissingToolName => write!(f, "hook payload is missing tool_name field"),
            Self::EmptyToolName => write!(f, "hook payload tool_name must not be empty"),
            Self::ToolInputNotObject => write!(f, "hook payload tool_input must be a JSON object"),
        }
    }
}

fn normalize(raw_name: &str, mut args: Map<String, Value>) -> (String, Value) {
    // Only the native-vocabulary match is case-insensitive; passthrough
    // and sanitize keep the caller's original casing so MCP tool names
    // stay byte-identical for user plugin DSL matching and audit logs.
    let lowered = raw_name.to_ascii_lowercase();
    match lowered.as_str() {
        "bash" => ("Bash".into(), Value::Object(args)),
        "read" => ("Read".into(), reshape_path(&mut args)),
        "write" => ("Write".into(), reshape_path(&mut args)),
        "edit" => ("Edit".into(), reshape_edit(&mut args)),
        "patch" => ("apply_patch".into(), reshape_patch(&mut args)),
        "webfetch" => ("WebFetch".into(), Value::Object(args)),
        "grep" => ("mcp__opencode__grep".into(), Value::Object(args)),
        "glob" => ("mcp__opencode__glob".into(), Value::Object(args)),
        "list" => ("mcp__opencode__list".into(), Value::Object(args)),
        "todowrite" | "todoread" | "task" => {
            (format!("mcp__opencode__{lowered}"), Value::Object(args))
        },
        _ if raw_name.starts_with("mcp__") => (raw_name.to_string(), Value::Object(args)),
        _ => {
            let sanitized = sanitize_tool_name(raw_name);
            (format!("mcp__opencode__{sanitized}"), Value::Object(args))
        },
    }
}

fn sanitize_tool_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

fn decode_tool_input(raw: Value) -> Result<Map<String, Value>, OpencodeInputError> {
    match raw {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(Map::new()),
        _ => Err(OpencodeInputError::ToolInputNotObject),
    }
}

/// First usable string among `keys` in priority order, without consuming
/// any original key (§7: duplicate into canonical keys, keep originals).
fn first_string(args: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| args.get(*k).and_then(Value::as_str).map(str::to_owned))
}

/// Insert `value` under `key` unless a string already occupies it —
/// non-string occupants are overwritten so the canonical key the engine
/// reads always holds the normalised string.
fn upsert_string(args: &mut Map<String, Value>, key: &str, value: &str) {
    if !args.get(key).is_some_and(Value::is_string) {
        args.insert(key.to_string(), Value::String(value.to_owned()));
    }
}

fn reshape_path(args: &mut Map<String, Value>) -> Value {
    if let Some(path) = first_string(args, &["file_path", "filePath", "path"]) {
        upsert_string(args, "file_path", &path);
        upsert_string(args, "filePath", &path);
    }
    Value::Object(args.clone())
}

fn reshape_edit(args: &mut Map<String, Value>) -> Value {
    reshape_path(args);
    if let Some(old) = first_string(args, &["old_string", "oldString", "old"]) {
        upsert_string(args, "old_string", &old);
        upsert_string(args, "oldString", &old);
    }
    if let Some(new) = first_string(args, &["new_string", "newString", "new"]) {
        upsert_string(args, "new_string", &new);
        upsert_string(args, "newString", &new);
    }
    if let Some(replace_all) = args.get("replaceAll").and_then(Value::as_bool) {
        args.entry("replace_all".to_string())
            .or_insert_with(|| Value::Bool(replace_all));
    }
    Value::Object(args.clone())
}

fn reshape_patch(args: &mut Map<String, Value>) -> Value {
    if let Some(body) = first_string(args, &["command", "patchText", "patch", "content"]) {
        upsert_string(args, "command", &body);
    }
    Value::Object(args.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::engine::Engine;
    use crate::facts::path::extract_all;
    use crate::plugin::PluginSet;

    #[test]
    fn opencode_bash_normalizes_to_bash_with_command() {
        let body = r#"{"tool_name":"bash","tool_input":{"command":"rm -rf /","timeout":30}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("rm -rf /"));
    }

    #[test]
    fn opencode_read_duplicates_file_path_to_file_path() {
        let secret = "dotenv";
        let body = format!(r#"{{"tool_name":"read","tool_input":{{"filePath":"{secret}"}}}}"#);
        let input = parse(&body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.tool_input["file_path"], secret);
    }

    #[test]
    fn opencode_grep_maps_to_mcp_opencode_grep() {
        let body = r#"{"tool_name":"grep","tool_input":{"pattern":"secret","path":"src"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__opencode__grep");
        assert!(input.is_mcp_tool());
    }

    #[test]
    fn opencode_patch_copies_body_to_command_for_apply_patch_paths() {
        let patch = "*** Begin Patch\n*** Update File: secrets.txt\n+API_KEY=leak\n*** End Patch\n";
        let body = format!(
            r#"{{"tool_name":"patch","tool_input":{{"patchText":{patch_json}}}}}"#,
            patch_json = serde_json::to_string(patch).unwrap()
        );
        let input = parse(&body).unwrap();
        assert_eq!(input.tool_name, "apply_patch");
        assert_eq!(input.tool_input["command"], patch);
        let paths = extract_all(&input);
        assert!(paths.iter().any(|p| p.raw.as_str() == "secrets.txt"));
    }

    #[test]
    fn opencode_native_tools_map_to_canonical_names() {
        let cases = [
            ("glob", "mcp__opencode__glob"),
            ("list", "mcp__opencode__list"),
            ("todowrite", "mcp__opencode__todowrite"),
            ("webfetch", "WebFetch"),
            ("Bash", "Bash"),
            ("Write", "Write"),
        ];
        for (raw, expected) in cases {
            let body = format!(r#"{{"tool_name":"{raw}","tool_input":{{}}}}"#);
            assert_eq!(parse(&body).unwrap().tool_name, expected, "raw={raw}");
        }
    }

    #[test]
    fn opencode_unknown_tool_sanitizes_and_accepts_case_insensitive_names() {
        assert_eq!(
            parse(r#"{"tool_name":"my-tool@v2","tool_input":{}}"#)
                .unwrap()
                .tool_name,
            "mcp__opencode__my_tool_v2"
        );
        assert_eq!(
            parse(r#"{"tool_name":"bash","tool_input":{"command":"ls"}}"#)
                .unwrap()
                .tool_name,
            "Bash"
        );
    }

    #[test]
    fn opencode_fail_closed_on_invalid_payload() {
        assert!(matches!(parse(""), Err(OpencodeInputError::Empty)));
        assert!(matches!(parse("{"), Err(OpencodeInputError::Json(_))));
        assert!(matches!(parse("[]"), Err(OpencodeInputError::NotAnObject)));
        assert!(matches!(
            parse(r#"{"tool_input":{}}"#),
            Err(OpencodeInputError::MissingToolName)
        ));
        assert!(matches!(
            parse(r#"{"tool_name":"","tool_input":{}}"#),
            Err(OpencodeInputError::EmptyToolName)
        ));
        assert!(matches!(
            parse(r#"{"tool_name":"bash","tool_input":"x"}"#),
            Err(OpencodeInputError::ToolInputNotObject)
        ));
    }

    #[test]
    fn opencode_bash_rm_rf_denies_via_engine() {
        let body = r#"{"tool_name":"bash","tool_input":{"command":"rm -rf /"}}"#;
        let input = parse(body).unwrap();
        let engine = Engine::with_components(Config::default(), PluginSet::new());
        assert!(matches!(
            engine.decide(&input).decision,
            crate::Decision::Deny { .. }
        ));
    }

    #[test]
    fn opencode_edit_and_write_normalization() {
        let write = parse(r#"{"tool_name":"write","tool_input":{"filePath":"a.txt"}}"#).unwrap();
        assert_eq!(write.tool_name, "Write");
        assert_eq!(write.tool_input["file_path"], "a.txt");

        let edit = parse(
            r#"{"tool_name":"edit","tool_input":{"filePath":"a.rs","oldString":"x","newString":"y","replaceAll":true}}"#,
        )
        .unwrap();
        assert_eq!(edit.tool_name, "Edit");
        assert_eq!(edit.tool_input["old_string"], "x");
        assert_eq!(edit.tool_input["new_string"], "y");
        assert_eq!(edit.tool_input["replace_all"], true);
    }

    #[test]
    fn opencode_todoread_and_task_map_to_mcp() {
        for raw in ["todoread", "task"] {
            let body = format!(r#"{{"tool_name":"{raw}","tool_input":{{}}}}"#);
            assert_eq!(
                parse(&body).unwrap().tool_name,
                format!("mcp__opencode__{raw}"),
            );
        }
    }

    #[test]
    fn opencode_existing_mcp_prefix_passthrough() {
        let input = parse(r#"{"tool_name":"mcp__custom__tool","tool_input":{}}"#).unwrap();
        assert_eq!(input.tool_name, "mcp__custom__tool");
    }

    #[test]
    fn opencode_mcp_passthrough_and_sanitize_preserve_original_case() {
        // Passthrough keeps the server/tool segments byte-identical so a
        // user plugin DSL match on the exact MCP name cannot silently miss.
        let input = parse(r#"{"tool_name":"mcp__My_Server__Tool","tool_input":{}}"#).unwrap();
        assert_eq!(input.tool_name, "mcp__My_Server__Tool");

        // Unknown tools keep their casing inside the sanitized suffix.
        let input = parse(r#"{"tool_name":"MyTool","tool_input":{}}"#).unwrap();
        assert_eq!(input.tool_name, "mcp__opencode__MyTool");

        // The passthrough prefix check itself is case-sensitive: an
        // uppercase MCP__ name is treated as an unknown tool.
        let input = parse(r#"{"tool_name":"MCP__x__y","tool_input":{}}"#).unwrap();
        assert_eq!(input.tool_name, "mcp__opencode__MCP__x__y");
    }

    #[test]
    fn opencode_sanitize_empty_tool_name_becomes_unknown() {
        let input = parse(r#"{"tool_name":"---","tool_input":{}}"#).unwrap();
        assert_eq!(input.tool_name, "mcp__opencode__unknown");
    }

    #[test]
    fn opencode_accepts_tool_name_aliases_and_tool_input_object() {
        let input = parse(r#"{"toolName":"bash","toolInput":{"command":"ls"}}"#).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("ls"));
    }

    #[test]
    fn opencode_patch_accepts_content_field() {
        let patch = "*** Begin Patch\n*** End Patch\n";
        let body = format!(
            r#"{{"tool_name":"patch","tool_input":{{"content":{patch_json}}}}}"#,
            patch_json = serde_json::to_string(patch).unwrap()
        );
        let input = parse(&body).unwrap();
        assert_eq!(input.tool_name, "apply_patch");
        assert_eq!(input.tool_input["command"], patch);
    }

    #[test]
    fn opencode_reshape_duplicates_into_canonical_keys_and_keeps_originals() {
        // §7: aliases are duplicated into the canonical keys the engine
        // reads, while the caller's original keys stay in place.
        let read = parse(r#"{"tool_name":"read","tool_input":{"path":".env"}}"#).unwrap();
        assert_eq!(read.tool_input["file_path"], ".env");
        assert_eq!(read.tool_input["filePath"], ".env");
        assert_eq!(read.tool_input["path"], ".env");

        let edit =
            parse(r#"{"tool_name":"edit","tool_input":{"path":"a.rs","old":"x","new":"y"}}"#)
                .unwrap();
        assert_eq!(edit.tool_input["old_string"], "x");
        assert_eq!(edit.tool_input["old"], "x");
        assert_eq!(edit.tool_input["new_string"], "y");
        assert_eq!(edit.tool_input["new"], "y");
        assert_eq!(edit.tool_input["path"], "a.rs");

        let patch = parse(r#"{"tool_name":"patch","tool_input":{"patchText":"P"}}"#).unwrap();
        assert_eq!(patch.tool_input["command"], "P");
        assert_eq!(patch.tool_input["patchText"], "P");
    }

    #[test]
    fn opencode_reshape_overwrites_non_string_canonical_key() {
        // Adversarial shadowing: a non-string occupant of the canonical key
        // must not mask the alias value the engine needs to inspect.
        let read =
            parse(r#"{"tool_name":"read","tool_input":{"file_path":123,"path":".env"}}"#).unwrap();
        assert_eq!(read.tool_input["file_path"], ".env");
        assert_eq!(read.tool_input["path"], ".env");
    }

    #[test]
    fn opencode_input_error_display_covers_variants() {
        let cases: Vec<OpencodeInputError> = vec![
            OpencodeInputError::Empty,
            OpencodeInputError::NotAnObject,
            OpencodeInputError::MissingToolName,
            OpencodeInputError::EmptyToolName,
            OpencodeInputError::ToolInputNotObject,
            OpencodeInputError::Json(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
        ];
        for err in cases {
            assert!(!err.to_string().is_empty());
        }
    }

    use crate::testing::proptest::arbitrary_utf8_bytes;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pbt_parse_is_total_on_arbitrary_utf8(bytes in arbitrary_utf8_bytes()) {
            let body = String::from_utf8_lossy(&bytes);
            let _ = parse(&body);
        }

        #[test]
        fn pbt_invalid_envelope_returns_err(
            body in prop_oneof![
                Just("null".to_string()),
                Just("true".to_string()),
                Just("0".to_string()),
                Just("\"x\"".to_string()),
                Just("[]".to_string()),
                Just(r#"{"tool_input":{}}"#.to_string()),
                Just(r#"{"tool_name":"","tool_input":{}}"#.to_string()),
                Just(r#"{"tool_name":"bash","tool_input":"x"}"#.to_string()),
            ],
        ) {
            match parse(&body) {
                Err(
                    OpencodeInputError::Empty
                    | OpencodeInputError::NotAnObject
                    | OpencodeInputError::MissingToolName
                    | OpencodeInputError::EmptyToolName
                    | OpencodeInputError::ToolInputNotObject
                    | OpencodeInputError::Json(_),
                ) => {},
                other => prop_assert!(
                    false,
                    "expected structured error for body {body:?}, got {other:?}",
                ),
            }
        }
    }
}
