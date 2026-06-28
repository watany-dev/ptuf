//! Pi Coding Agent adapter — input normaliser.
//!
//! Pi's TypeScript extension forwards raw tool-call events to
//! `ptuf hook pi`. This module rewrites Pi's native tool vocabulary into
//! the canonical names the policy engine expects (`Bash`, `Read`,
//! `mcp__pi__grep`, …) before evaluation.

use serde_json::{Map, Value};

use crate::hook_input::HookInput;

/// Normalise a Pi stdin body into a [`HookInput`].
pub(super) fn parse(body: &str) -> Result<HookInput, PiInputError> {
    if body.trim().is_empty() {
        return Err(PiInputError::Empty);
    }
    let value: Value = serde_json::from_str(body).map_err(PiInputError::Json)?;
    let Value::Object(mut map) = value else {
        return Err(PiInputError::NotAnObject);
    };

    let raw_name = map
        .remove("tool_name")
        .or_else(|| map.remove("toolName"))
        .or_else(|| map.remove("name"))
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(PiInputError::MissingToolName)?;

    let raw_input = map
        .remove("tool_input")
        .or_else(|| map.remove("toolInput"))
        .unwrap_or(Value::Null);
    let args = decode_args(raw_input);

    let (tool_name, tool_input) = normalize(&raw_name, args);

    Ok(HookInput {
        tool_name,
        tool_input,
    })
}

/// Reasons a Pi payload failed to normalise.
#[derive(Debug)]
pub(super) enum PiInputError {
    Empty,
    Json(serde_json::Error),
    NotAnObject,
    MissingToolName,
}

impl std::fmt::Display for PiInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "hook payload is empty"),
            Self::Json(err) => write!(f, "hook payload is not valid JSON ({err})"),
            Self::NotAnObject => write!(f, "hook payload must be a JSON object"),
            Self::MissingToolName => write!(f, "hook payload is missing tool_name field"),
        }
    }
}

fn normalize(raw_name: &str, mut args: Map<String, Value>) -> (String, Value) {
    match raw_name {
        "bash" => ("Bash".into(), reshape_bash(&args)),
        "read" => ("Read".into(), reshape_path(&mut args)),
        "write" => ("Write".into(), reshape_path(&mut args)),
        "edit" => ("Edit".into(), reshape_edit(&mut args)),
        "grep" => ("mcp__pi__grep".into(), Value::Object(args.clone())),
        "find" => ("mcp__pi__find".into(), Value::Object(args.clone())),
        "ls" => ("mcp__pi__ls".into(), Value::Object(args.clone())),
        "fetch" | "web_fetch" => ("WebFetch".into(), Value::Object(args.clone())),
        other => {
            let sanitized = sanitize_tool_name(other);
            (format!("mcp__pi__{sanitized}"), Value::Object(args.clone()))
        },
    }
}

/// Mirror Pi extension `sanitizeToolName`: non-alphanumeric → `_`, trim `_`,
/// empty → `unknown`.
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

fn reshape_bash(args: &Map<String, Value>) -> Value {
    Value::Object(args.clone())
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
}
