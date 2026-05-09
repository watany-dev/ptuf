//! GitHub Copilot adapter — input normalizer.
//!
//! Copilot's `preToolUse` hook may deliver either of two payload shapes:
//!
//! - `{"toolName":"bash","toolArgs":"{\"command\":\"...\"}"}` — the
//!   documented Copilot CLI form. `toolArgs` may be a JSON-encoded
//!   string, a JSON object, or absent.
//! - `{"tool_name":"Bash","tool_input":{...}}` — the VS Code /
//!   ptuf-native shape, accepted for compatibility.
//!
//! Both are normalised to [`HookInput`] (snake_case + Claude-style tool
//! names) so the engine sees a single shape regardless of agent. Tool
//! names are mapped per `docs/design/cli-and-hooks.md` and the Copilot
//! adapter design (`bash`→`Bash`, `view`→`Read`, `edit`→`Edit`,
//! `create`→`Write`, `web_fetch`→`WebFetch`, `powershell`→`Bash` with a
//! `shell` hint). Unknown tools fall through with their raw name; the
//! engine's MCP / generic-key extractors then handle them best-effort.

use serde_json::{Map, Value};

use crate::hook_input::HookInput;

/// Normalise a Copilot stdin body into a [`HookInput`].
///
/// Returns `Ok(None)` when the JSON parses but contains neither a
/// `tool_name` nor a `toolName` field — callers should fail-closed via
/// `core.engine.invalid-payload` in that case so the engine never sees a
/// half-populated input.
pub(super) fn parse(body: &str) -> Result<HookInput, ParseProblem> {
    let value: Value = serde_json::from_str(body).map_err(ParseProblem::InvalidJson)?;
    let Value::Object(mut map) = value else {
        return Err(ParseProblem::NotAnObject);
    };

    if let Some(tool_name) = map
        .get("tool_name")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        let tool_input = map.remove("tool_input").unwrap_or(Value::Null);
        return Ok(HookInput {
            tool_name,
            tool_input,
        });
    }

    if let Some(tool_name) = map
        .get("toolName")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        let raw_args = map.remove("toolArgs").unwrap_or(Value::Null);
        let (mapped_name, mapped_args) = map_tool(&tool_name, raw_args);
        return Ok(HookInput {
            tool_name: mapped_name,
            tool_input: mapped_args,
        });
    }

    Err(ParseProblem::MissingToolName)
}

/// Reasons a Copilot payload failed to normalise. The CLI maps every
/// variant onto `core.engine.invalid-payload` so Copilot fail-closed
/// stays exit-0 + bare deny JSON; this enum only exists to make stderr
/// messages actionable.
#[derive(Debug)]
pub(super) enum ParseProblem {
    InvalidJson(serde_json::Error),
    NotAnObject,
    MissingToolName,
}

impl std::fmt::Display for ParseProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(err) => write!(f, "hook payload is not valid JSON ({err})"),
            Self::NotAnObject => write!(f, "hook payload must be a JSON object"),
            Self::MissingToolName => {
                write!(f, "hook payload is missing tool_name / toolName field")
            },
        }
    }
}

fn map_tool(raw_name: &str, raw_args: Value) -> (String, Value) {
    let args_object = decode_args(raw_args);
    match raw_name {
        "bash" => ("Bash".into(), Value::Object(args_object)),
        "powershell" => {
            let mut obj = args_object;
            obj.entry("shell".to_string())
                .or_insert_with(|| Value::String("powershell".into()));
            ("Bash".into(), Value::Object(obj))
        },
        "view" => ("Read".into(), reshape_path(args_object)),
        "edit" => ("Edit".into(), reshape_edit(args_object)),
        "create" => ("Write".into(), reshape_create(args_object)),
        "web_fetch" => ("WebFetch".into(), Value::Object(args_object)),
        other => (other.to_string(), Value::Object(args_object)),
    }
}

/// Decode the `toolArgs` field. Object → object; JSON-encoded string →
/// re-parsed object (falls back to `{"raw": "..."}` for non-JSON
/// strings); anything else → empty object. We never panic or surface a
/// parse error here — invalid args degrade to a generic input that the
/// engine evaluates as best-effort.
fn decode_args(raw: Value) -> Map<String, Value> {
    match raw {
        Value::Object(map) => map,
        Value::String(s) => {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&s) {
                map
            } else {
                let mut m = Map::new();
                m.insert("raw".to_string(), Value::String(s));
                m
            }
        },
        Value::Null => Map::new(),
        other => {
            let mut m = Map::new();
            m.insert("raw".to_string(), other);
            m
        },
    }
}

fn reshape_path(mut args: Map<String, Value>) -> Value {
    if let Some(path) = take_first_string(&mut args, &["file_path", "filePath", "path"]) {
        args.insert("file_path".into(), Value::String(path));
    }
    Value::Object(args)
}

fn reshape_edit(mut args: Map<String, Value>) -> Value {
    if let Some(path) = take_first_string(&mut args, &["file_path", "filePath", "path"]) {
        args.insert("file_path".into(), Value::String(path));
    }
    if let Some(new_string) = take_first_string(&mut args, &["new_string", "newString", "content"])
    {
        args.insert("new_string".into(), Value::String(new_string));
    }
    Value::Object(args)
}

fn reshape_create(mut args: Map<String, Value>) -> Value {
    if let Some(path) = take_first_string(&mut args, &["file_path", "filePath", "path"]) {
        args.insert("file_path".into(), Value::String(path));
    }
    if let Some(content) = take_first_string(&mut args, &["content"]) {
        args.insert("content".into(), Value::String(content));
    }
    Value::Object(args)
}

fn take_first_string(args: &mut Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(Value::String(s)) = args.remove(*key) {
            return Some(s);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_bash_maps_to_bash_with_command() {
        let body = r#"{"toolName":"bash","toolArgs":"{\"command\":\"rm -rf /\"}"}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("rm -rf /"));
    }

    #[test]
    fn camel_bash_with_object_args_is_accepted() {
        let body = r#"{"toolName":"bash","toolArgs":{"command":"ls"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("ls"));
    }

    #[test]
    fn snake_payload_is_accepted() {
        let body = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("ls"));
    }

    #[test]
    fn view_maps_to_read_path() {
        let body = r#"{"toolName":"view","toolArgs":{"filePath":"/etc/passwd"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.file_path(), Some("/etc/passwd"));
    }

    #[test]
    fn create_maps_to_write_with_content() {
        let body = r#"{"toolName":"create","toolArgs":{"path":"/tmp/x","content":"AKIA..."}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Write");
        assert_eq!(input.file_path(), Some("/tmp/x"));
        assert_eq!(input.write_payload(), Some("AKIA..."));
    }

    #[test]
    fn edit_maps_to_edit_with_new_string() {
        let body = r#"{"toolName":"edit","toolArgs":{"filePath":"/tmp/x","newString":"hi"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Edit");
        assert_eq!(input.file_path(), Some("/tmp/x"));
        assert_eq!(input.write_payload(), Some("hi"));
    }

    #[test]
    fn web_fetch_maps_to_webfetch() {
        let body = r#"{"toolName":"web_fetch","toolArgs":{"url":"https://x"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "WebFetch");
        assert_eq!(input.web_fetch_url(), Some("https://x"));
    }

    #[test]
    fn powershell_maps_to_bash_with_shell_hint() {
        let body = r#"{"toolName":"powershell","toolArgs":{"command":"Get-Item /"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.bash_command(), Some("Get-Item /"));
        assert_eq!(
            input.tool_input.get("shell").and_then(Value::as_str),
            Some("powershell"),
        );
    }

    #[test]
    fn unknown_tool_passes_through_without_panic() {
        let body = r#"{"toolName":"task","toolArgs":{"goal":"do something"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "task");
        assert!(input.tool_input.is_object());
    }

    #[test]
    fn non_json_args_string_is_kept_as_raw() {
        let body = r#"{"toolName":"bash","toolArgs":"not-json"}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(
            input.tool_input.get("raw").and_then(Value::as_str),
            Some("not-json"),
        );
    }

    #[test]
    fn missing_tool_name_is_an_error() {
        let body = r#"{"toolArgs":{}}"#;
        assert!(matches!(parse(body), Err(ParseProblem::MissingToolName)));
    }

    #[test]
    fn invalid_json_is_an_error() {
        assert!(matches!(
            parse("not-json"),
            Err(ParseProblem::InvalidJson(_))
        ));
    }

    #[test]
    fn array_payload_is_rejected() {
        assert!(matches!(parse("[]"), Err(ParseProblem::NotAnObject)));
    }

    #[test]
    fn parse_problem_display_invalid_json_mentions_json() {
        let err = serde_json::from_str::<Value>("nope").unwrap_err();
        let s = format!("{}", ParseProblem::InvalidJson(err));
        assert!(s.contains("not valid JSON"));
    }

    #[test]
    fn parse_problem_display_not_an_object_mentions_object() {
        let s = format!("{}", ParseProblem::NotAnObject);
        assert!(s.contains("must be a JSON object"));
    }

    #[test]
    fn parse_problem_display_missing_tool_name_mentions_field() {
        let s = format!("{}", ParseProblem::MissingToolName);
        assert!(s.contains("missing tool_name"));
    }

    #[test]
    fn camel_bash_with_null_args_is_accepted() {
        let body = r#"{"toolName":"bash","toolArgs":null}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert!(input.tool_input.is_object());
    }

    #[test]
    fn camel_bash_with_missing_args_is_accepted() {
        let body = r#"{"toolName":"bash"}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert!(input.tool_input.is_object());
    }

    #[test]
    fn camel_bash_with_bool_args_is_kept_as_raw() {
        let body = r#"{"toolName":"bash","toolArgs":true}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(
            input.tool_input.get("raw").and_then(Value::as_bool),
            Some(true),
        );
    }

    #[test]
    fn view_without_path_field_passes_through_unchanged() {
        let body = r#"{"toolName":"view","toolArgs":{"other":"x"}}"#;
        let input = parse(body).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert!(input.tool_input.get("file_path").is_none());
        assert_eq!(
            input.tool_input.get("other").and_then(Value::as_str),
            Some("x"),
        );
    }
}
