//! Pi Coding Agent adapter — input normaliser.
//!
//! Pi's TypeScript extension forwards raw tool-call events to
//! `ptuf hook pi`. This module rewrites Pi's native tool vocabulary into
//! the canonical names the policy engine expects (`Bash`, `Read`,
//! `mcp__pi__grep`, …) before evaluation.

use serde_json::{Map, Value};

use super::input_helpers::{
    InputError, decode_args, hook_input, sanitize_tool_name, take_first_string,
};
use crate::hook_input::HookInput;

/// Normalise a Pi stdin body into a [`HookInput`].
pub(super) fn parse(body: &str) -> Result<HookInput, InputError> {
    let mut map = super::input_helpers::parse_object(body)?;

    let raw_name = take_first_string(&mut map, &["tool_name", "toolName", "name"])
        .ok_or(InputError::MissingToolName)?;

    let raw_input = map
        .remove("tool_input")
        .or_else(|| map.remove("toolInput"))
        .unwrap_or(Value::Null);
    let args = decode_args(raw_input, "text");

    let (tool_name, tool_input) = normalize(&raw_name, args);

    Ok(hook_input(tool_name, tool_input))
}

fn normalize(raw_name: &str, mut args: Map<String, Value>) -> (String, Value) {
    match raw_name {
        "bash" => ("Bash".into(), Value::Object(args)),
        "read" => ("Read".into(), reshape_path(&mut args)),
        "write" => ("Write".into(), reshape_path(&mut args)),
        "edit" => ("Edit".into(), reshape_edit(&mut args)),
        "grep" => ("mcp__pi__grep".into(), Value::Object(args)),
        "find" => ("mcp__pi__find".into(), Value::Object(args)),
        "ls" => ("mcp__pi__ls".into(), Value::Object(args)),
        "fetch" | "web_fetch" => ("WebFetch".into(), Value::Object(args)),
        other => {
            let sanitized = sanitize_tool_name(other);
            (format!("mcp__pi__{sanitized}"), Value::Object(args))
        },
    }
}

fn reshape_path(args: &mut Map<String, Value>) -> Value {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    if let Some(path) = path {
        args.entry("file_path".to_string())
            .or_insert_with(|| Value::String(path));
    }
    Value::Object(args.clone())
}

fn reshape_edit(args: &mut Map<String, Value>) -> Value {
    reshape_path(args);
    if let Some(edits) = args.get("edits").and_then(Value::as_array) {
        let joined: Vec<&str> = edits
            .iter()
            .filter_map(|edit| {
                edit.get("newText")
                    .or_else(|| edit.get("new_text"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            })
            .collect();
        if !joined.is_empty() {
            args.insert("new_string".into(), Value::String(joined.join("\n")));
        }
    }
    Value::Object(args.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::engine::Engine;
    use crate::plugin::PluginSet;

    #[test]
    fn pi_bash_normalizes_to_bash_with_command() {
        let body = r#"{"tool_name":"bash","tool_input":{"command":"rm -rf /","timeout":30}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("rm -rf /"));
    }

    #[test]
    fn pi_read_duplicates_path_to_file_path() {
        let dotenv = ".env";
        let body = format!(r#"{{"tool_name":"read","tool_input":{{"path":"{dotenv}"}}}}"#);
        let input = parse(&body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.tool_input["file_path"], dotenv);
    }

    #[test]
    fn pi_grep_maps_to_mcp_pi_grep() {
        let body = r#"{"tool_name":"grep","tool_input":{"pattern":"secret","path":"src"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "mcp__pi__grep");
        assert!(input.is_mcp_tool());
    }

    #[test]
    fn pi_bash_rm_rf_denies_via_engine() {
        let body = r#"{"tool_name":"bash","tool_input":{"command":"rm -rf /"}}"#;
        let input = parse(body).unwrap();
        let engine = Engine::with_components(Config::default(), PluginSet::new());
        assert!(matches!(
            engine.decide(&input).decision,
            crate::Decision::Deny { .. }
        ));
    }

    #[test]
    fn pi_fail_closed_on_empty_invalid_and_missing_fields() {
        assert!(matches!(parse(""), Err(InputError::Empty)));
        assert!(matches!(parse("{"), Err(InputError::Json(_))));
        assert!(matches!(parse("[]"), Err(InputError::NotAnObject)));
        assert!(matches!(
            parse(r#"{"tool_input":{}}"#),
            Err(InputError::MissingToolName)
        ));
    }

    #[test]
    fn pi_write_and_edit_normalization() {
        let write = parse(r#"{"tool_name":"write","tool_input":{"path":"a.txt"}}"#).unwrap();
        assert_eq!(write.tool_name, "Write");
        assert_eq!(write.tool_input["file_path"], "a.txt");

        let edit = parse(
            r#"{"tool_name":"edit","tool_input":{"path":"a.rs","edits":[{"newText":"x"},{"new_text":"y"}]}}"#,
        )
        .unwrap();
        assert_eq!(edit.tool_name, "Edit");
        assert_eq!(edit.tool_input["new_string"], "x\ny");
    }

    #[test]
    fn pi_find_ls_and_fetch_map_to_canonical_tools() {
        assert_eq!(
            parse(r#"{"tool_name":"find","tool_input":{"path":"."}}"#)
                .unwrap()
                .tool_name,
            "mcp__pi__find"
        );
        assert_eq!(
            parse(r#"{"tool_name":"ls","tool_input":{"path":"."}}"#)
                .unwrap()
                .tool_name,
            "mcp__pi__ls"
        );
        assert_eq!(
            parse(r#"{"tool_name":"fetch","tool_input":{"url":"https://x"}}"#)
                .unwrap()
                .tool_name,
            "WebFetch"
        );
        assert_eq!(
            parse(r#"{"tool_name":"web_fetch","tool_input":{"url":"https://x"}}"#)
                .unwrap()
                .tool_name,
            "WebFetch"
        );
    }

    #[test]
    fn pi_unknown_tool_sanitizes_and_accepts_name_aliases() {
        assert_eq!(
            parse(r#"{"tool_name":"my-tool@v2","tool_input":{}}"#)
                .unwrap()
                .tool_name,
            "mcp__pi__my_tool_v2"
        );
        assert_eq!(
            parse(r#"{"tool_name":"!!!","tool_input":{}}"#)
                .unwrap()
                .tool_name,
            "mcp__pi__unknown"
        );
        assert_eq!(
            parse(r#"{"toolName":"bash","tool_input":{"command":"ls"}}"#)
                .unwrap()
                .tool_name,
            "Bash"
        );
        assert_eq!(
            parse(r#"{"name":"bash","tool_input":{"command":"ls"}}"#)
                .unwrap()
                .tool_name,
            "Bash"
        );
    }

    #[test]
    fn pi_decode_args_handles_string_and_scalar_fallbacks() {
        let from_obj = parse(r#"{"tool_name":"bash","tool_input":{"command":"ls"}}"#).unwrap();
        assert_eq!(from_obj.bash_command(), Some("ls"));

        let from_json_str =
            parse(r#"{"tool_name":"bash","tool_input":"{\"command\":\"ls\"}"}"#).unwrap();
        assert_eq!(from_json_str.bash_command(), Some("ls"));

        let from_plain_str = parse(r#"{"tool_name":"bash","tool_input":"plain-text"}"#).unwrap();
        assert_eq!(from_plain_str.tool_input["text"], "plain-text");

        let from_null = parse(r#"{"tool_name":"bash"}"#).unwrap();
        assert!(from_null.tool_input.as_object().unwrap().is_empty());

        let from_number = parse(r#"{"tool_name":"bash","tool_input":42}"#).unwrap();
        assert_eq!(from_number.tool_input["text"], 42);
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
            ],
        ) {
            match parse(&body) {
                Err(
                    InputError::Empty
                    | InputError::NotAnObject
                    | InputError::MissingToolName
                    | InputError::Json(_),
                ) => {},
                other => prop_assert!(
                    false,
                    "expected structured error for body {body:?}, got {other:?}",
                ),
            }
        }
    }
}
