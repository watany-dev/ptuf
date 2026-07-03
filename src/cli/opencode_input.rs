//! OpenCode adapter — input normaliser.
//!
//! OpenCode's TypeScript plugin forwards raw tool-call events to
//! `ptuf hook opencode`. This module rewrites OpenCode's native tool
//! vocabulary into the canonical names the policy engine expects (`Bash`,
//! `Read`, `mcp__opencode__grep`, …) before evaluation.

use serde_json::{Map, Value};

use super::input_helpers::take_first_string;
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
    match raw_name.to_ascii_lowercase().as_str() {
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
            let canonical = raw_name.to_ascii_lowercase();
            (format!("mcp__opencode__{canonical}"), Value::Object(args))
        },
        other if other.starts_with("mcp__") => (other.to_string(), Value::Object(args)),
        other => {
            let sanitized = sanitize_tool_name(other);
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

fn reshape_path(args: &mut Map<String, Value>) -> Value {
    if let Some(path) = take_first_string(args, &["file_path", "filePath", "path"]) {
        args.entry("file_path".to_string())
            .or_insert_with(|| Value::String(path.clone()));
        args.entry("filePath".to_string())
            .or_insert_with(|| Value::String(path));
    }
    Value::Object(args.clone())
}

fn reshape_edit(args: &mut Map<String, Value>) -> Value {
    reshape_path(args);
    if let Some(old) = take_first_string(args, &["old_string", "oldString", "old"]) {
        args.entry("old_string".to_string())
            .or_insert_with(|| Value::String(old.clone()));
        args.entry("oldString".to_string())
            .or_insert_with(|| Value::String(old));
    }
    if let Some(new) = take_first_string(args, &["new_string", "newString", "new"]) {
        args.entry("new_string".to_string())
            .or_insert_with(|| Value::String(new.clone()));
        args.entry("newString".to_string())
            .or_insert_with(|| Value::String(new));
    }
    if let Some(replace_all) = args.get("replaceAll").and_then(Value::as_bool) {
        args.entry("replace_all".to_string())
            .or_insert_with(|| Value::Bool(replace_all));
    }
    Value::Object(args.clone())
}

fn reshape_patch(args: &mut Map<String, Value>) -> Value {
    if let Some(body) = take_first_string(args, &["command", "patchText", "patch", "content"]) {
        args.entry("command".to_string())
            .or_insert_with(|| Value::String(body));
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
