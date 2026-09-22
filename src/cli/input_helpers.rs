//! Shared plumbing for the agent-specific input adapters.
//!
//! Every adapter (`copilot_input`, `kiro_input`, `cline_input`,
//! `cursor_input`, `pi_input`, `opencode_input`) turns one vendor's hook
//! payload into the canonical [`HookInput`]. The vendor shapes differ,
//! but the failure modes and the JSON spelunking do not, so both live
//! here rather than being re-derived per adapter.

use serde_json::{Map, Value};

use crate::hook_input::HookInput;

/// Why a hook payload could not be normalised into a [`HookInput`].
///
/// One enum for every adapter: `cli::run` maps all of them onto
/// `core.engine.invalid-payload` and renders them through [`Display`],
/// so the only thing a variant has to do is make stderr actionable.
#[derive(Debug)]
pub(super) enum InputError {
    /// Nothing (or only whitespace) arrived on stdin.
    Empty,
    /// The body is not JSON.
    Json(serde_json::Error),
    /// The body is JSON but not a top-level object.
    NotAnObject,
    /// No tool-name field under any of the adapter's accepted keys.
    MissingToolName,
    /// A tool-name field that is present but blank.
    EmptyToolName,
    /// A `tool_input` the adapter refuses to coerce.
    ToolInputNotObject,
    /// A hook event / envelope name the adapter does not handle.
    /// `field` is the payload key it was read from (`hook_event_name`,
    /// `hookName`, …) and `expected` lists what would have been
    /// accepted; `name` is `None` when the key was absent entirely.
    UnsupportedEvent {
        field: &'static str,
        name: Option<String>,
        expected: &'static str,
    },
    /// An adapter-specific structural requirement the payload missed.
    /// Carries the whole message because there is exactly one such
    /// requirement per adapter and no shared vocabulary for them.
    Malformed(&'static str),
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "hook payload is empty"),
            Self::Json(err) => write!(f, "hook payload is not valid JSON ({err})"),
            Self::NotAnObject => write!(f, "hook payload must be a JSON object"),
            Self::MissingToolName => write!(f, "hook payload is missing tool_name field"),
            Self::EmptyToolName => write!(f, "hook payload tool_name must not be empty"),
            Self::ToolInputNotObject => write!(f, "hook payload tool_input must be a JSON object"),
            Self::UnsupportedEvent {
                field,
                name: Some(name),
                expected,
            } => write!(f, "unsupported {field}: {name} (expected {expected})"),
            Self::UnsupportedEvent {
                field,
                name: None,
                expected,
            } => write!(f, "missing {field} (expected {expected})"),
            Self::Malformed(msg) => write!(f, "{msg}"),
        }
    }
}

/// Reject a blank body, parse it as JSON, and require a top-level
/// object. The prologue every adapter that speaks a flat object shape
/// starts with.
pub(super) fn parse_object(body: &str) -> Result<Map<String, Value>, InputError> {
    if body.trim().is_empty() {
        return Err(InputError::Empty);
    }
    let value: Value = serde_json::from_str(body).map_err(InputError::Json)?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(InputError::NotAnObject),
    }
}

/// Build the canonical [`HookInput`] from an already-normalised pair.
pub(super) fn hook_input(tool_name: String, tool_input: Value) -> HookInput {
    HookInput {
        tool_name,
        tool_input,
    }
}

/// Remove the first key in `keys` whose value is a JSON string and
/// return the owned string. Used to promote alias keys (`cmd`/`script`
/// → `command`, `toolName` → `tool_name`) into the canonical shape the
/// engine consumes.
pub(super) fn take_first_string(args: &mut Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(Value::String(s)) = args.remove(*key) {
            return Some(s);
        }
    }
    None
}

/// First key in `keys` holding a JSON string, left in place — adapters
/// duplicate values into canonical keys while keeping the agent's
/// original payload visible in audit records.
pub(super) fn first_string(args: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| args.get(*k).and_then(Value::as_str).map(str::to_owned))
}

/// First key in `keys` holding a *non-empty* JSON string, scanning
/// `maps` in order. Used where the canonical key may live in
/// `tool_input`, on the root payload, or in a `metadata` sub-object.
pub(super) fn first_non_empty(
    maps: &[Option<&Map<String, Value>>],
    keys: &[&str],
) -> Option<String> {
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

/// Coerce a tool-input value into a key/value map. Objects pass
/// through, `null` becomes empty, a JSON-encoded object string is
/// decoded, and anything else is preserved under `fallback_key` so the
/// engine can still inspect it rather than seeing an empty payload.
pub(super) fn decode_args(raw: Value, fallback_key: &str) -> Map<String, Value> {
    let under_fallback = |value: Value| {
        let mut m = Map::new();
        m.insert(fallback_key.to_string(), value);
        m
    };
    match raw {
        Value::Object(map) => map,
        Value::Null => Map::new(),
        Value::String(s) => match serde_json::from_str::<Value>(&s) {
            Ok(Value::Object(map)) => map,
            _ => under_fallback(Value::String(s)),
        },
        other => under_fallback(other),
    }
}

/// Map an agent tool name onto something the engine's MCP matcher and
/// the plugin DSL can key on: every character outside `[A-Za-z0-9_]`
/// becomes `_`, and a name that reduces to nothing becomes `unknown`.
pub(super) fn sanitize_tool_name(name: &str) -> String {
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

/// `@server/tool` → `mcp__server__tool`. Three or more segments
/// collapse the extra slashes into underscores (`@a/b/c` →
/// `mcp__a__b_c`); an empty segment returns `None` so the caller keeps
/// the raw name rather than inventing an MCP identity.
pub(super) fn normalize_at_mcp(name: &str) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_object_rejects_blank_json_and_non_objects() {
        assert!(matches!(parse_object("   "), Err(InputError::Empty)));
        assert!(matches!(parse_object("{"), Err(InputError::Json(_))));
        assert!(matches!(parse_object("[]"), Err(InputError::NotAnObject)));
        parse_object(r#"{"a":1}"#).expect("object body");
    }

    #[test]
    fn display_covers_every_variant() {
        let err = serde_json::from_str::<Value>("{").expect_err("invalid json");
        for (err, needle) in [
            (InputError::Empty, "is empty"),
            (InputError::Json(err), "not valid JSON"),
            (InputError::NotAnObject, "must be a JSON object"),
            (InputError::MissingToolName, "missing tool_name"),
            (InputError::EmptyToolName, "must not be empty"),
            (
                InputError::ToolInputNotObject,
                "tool_input must be a JSON object",
            ),
            (
                InputError::UnsupportedEvent {
                    field: "hook_event_name",
                    name: Some("postToolUse".into()),
                    expected: "preToolUse",
                },
                "unsupported hook_event_name: postToolUse (expected preToolUse)",
            ),
            (
                InputError::UnsupportedEvent {
                    field: "hookName",
                    name: None,
                    expected: "tool_call or PreToolUse",
                },
                "missing hookName (expected tool_call or PreToolUse)",
            ),
            (InputError::Malformed("no envelope"), "no envelope"),
        ] {
            let rendered = format!("{err}");
            assert!(rendered.contains(needle), "{rendered:?} lacks {needle:?}");
        }
    }

    #[test]
    fn decode_args_coerces_every_json_shape() {
        assert!(decode_args(Value::Null, "raw").is_empty());
        assert_eq!(
            decode_args(serde_json::json!({"command": "ls"}), "raw")["command"],
            "ls"
        );
        assert_eq!(
            decode_args(Value::String(r#"{"command":"ls"}"#.into()), "raw")["command"],
            "ls"
        );
        assert_eq!(
            decode_args(Value::String("hi".into()), "text")["text"],
            "hi"
        );
        assert_eq!(decode_args(serde_json::json!(42), "raw")["raw"], 42);
    }

    #[test]
    fn sanitize_tool_name_folds_to_mcp_safe_identifiers() {
        assert_eq!(sanitize_tool_name("web-fetch.v2"), "web_fetch_v2");
        assert_eq!(sanitize_tool_name("___"), "unknown");
        assert_eq!(sanitize_tool_name(""), "unknown");
    }

    #[test]
    fn normalize_at_mcp_requires_two_non_empty_segments() {
        assert_eq!(
            normalize_at_mcp("@srv/tool").as_deref(),
            Some("mcp__srv__tool")
        );
        assert_eq!(normalize_at_mcp("@a/b/c").as_deref(), Some("mcp__a__b_c"));
        assert!(normalize_at_mcp("@srv/").is_none());
        assert!(normalize_at_mcp("@srv").is_none());
        assert!(normalize_at_mcp("srv/tool").is_none());
        assert!(normalize_at_mcp("@a//c").is_none());
    }

    #[test]
    fn string_lookups_respect_emptiness_and_ownership() {
        let mut args: Map<String, Value> =
            serde_json::from_str(r#"{"a":"","b":"x","n":1}"#).expect("json");
        assert_eq!(first_string(&args, &["n", "a", "b"]).as_deref(), Some(""));
        assert_eq!(
            first_non_empty(&[Some(&args)], &["a", "b"]).as_deref(),
            Some("x")
        );
        assert_eq!(first_non_empty(&[None, Some(&args)], &["z"]), None);
        assert_eq!(
            take_first_string(&mut args, &["n", "b"]).as_deref(),
            Some("x")
        );
        assert!(!args.contains_key("b"));
    }
}
