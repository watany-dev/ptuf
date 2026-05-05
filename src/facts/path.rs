//! `Read` / `Edit` / `Write` `file_path` extraction with `~` expansion.
//!
//! Expansion uses the [`crate::config::scope::EnvLookup`] trait so tests
//! can inject a hermetic `HOME` (and the production path delegates to
//! [`crate::config::scope::SystemEnv`]).

use std::path::{Path, PathBuf};

use crate::config::scope::{EnvLookup, SystemEnv};
use crate::hook_input::HookInput;

/// Tools whose payload exposes a `file_path` field that ptuf inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathTool {
    Read,
    Edit,
    Write,
    ApplyPatch,
    /// Any `mcp__<server>__<tool>` call that exposed a top-level
    /// `path` string. Treated like a write-capable tool by self-protection
    /// rules so MCP-driven edits cannot bypass the file allowlist.
    Mcp,
}

/// File-path fact derived from a `Read`/`Edit`/`Write` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePath {
    pub tool: PathTool,
    /// The string exactly as it appeared in `tool_input.file_path`.
    pub raw: String,
    /// `~` / `$HOME` / `${HOME}` expanded against the supplied env.
    /// Falls back to `raw` when `HOME` is unset.
    pub absolute: PathBuf,
}

/// Expand `~` / `$HOME` forms and, when requested, resolve a relative
/// path against `base_dir`.
pub(crate) fn resolve_with_env(raw: &str, base_dir: Option<&Path>, env: &dyn EnvLookup) -> PathBuf {
    let expanded = expand_home(raw, env);
    if expanded.is_relative()
        && let Some(base) = base_dir
    {
        return base.join(expanded);
    }
    expanded
}

/// Build all visible [`FilePath`]s using the supplied env lookup. The
/// `facts::extract` default path uses [`SystemEnv`]; tests inject a
/// `MapEnv` to verify `~` expansion deterministically.
///
/// MCP tool calls (`mcp__<server>__<tool>`) are normalised on generic
/// path carriers, including `path`, `paths[]`, `files[].path`, and
/// `items[].path`.
pub fn extract_all_with_env(input: &HookInput, env: &dyn EnvLookup) -> Vec<FilePath> {
    let (tool, values): (PathTool, Vec<String>) = match input.tool_name.as_str() {
        "Read" | "Edit" | "Write" => {
            let tool = match input.tool_name.as_str() {
                "Read" => PathTool::Read,
                "Edit" => PathTool::Edit,
                _ => PathTool::Write,
            };
            let values = input
                .tool_input
                .get("file_path")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .into_iter()
                .collect();
            (tool, values)
        }
        "apply_patch" => {
            let values = input
                .tool_input
                .get("command")
                .and_then(serde_json::Value::as_str)
                .map(collect_apply_patch_paths)
                .unwrap_or_default();
            (PathTool::ApplyPatch, values)
        }
        _ if input.is_mcp_tool() => (PathTool::Mcp, collect_mcp_paths(&input.tool_input)),
        _ => return Vec::new(),
    };
    values
        .into_iter()
        .map(|raw| FilePath {
            tool,
            absolute: resolve_with_env(&raw, None, env),
            raw,
        })
        .collect()
}

/// Compatibility helper: extract the first visible path with the supplied env.
pub fn extract_with_env(input: &HookInput, env: &dyn EnvLookup) -> Option<FilePath> {
    extract_all_with_env(input, env).into_iter().next()
}

/// Convenience: extract the first visible path using the production
/// environment.
pub fn extract(input: &HookInput) -> Option<FilePath> {
    extract_all_with_env(input, &SystemEnv).into_iter().next()
}

/// Convenience: extract every visible path using the production environment.
pub fn extract_all(input: &HookInput) -> Vec<FilePath> {
    extract_all_with_env(input, &SystemEnv)
}

fn collect_mcp_paths(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    push_string(value.get("path"), &mut out);
    for key in ["files", "items"] {
        if let Some(items) = value.get(key).and_then(serde_json::Value::as_array) {
            for item in items {
                push_string(item.get("path"), &mut out);
            }
        }
    }
    if let Some(paths) = value.get("paths").and_then(serde_json::Value::as_array) {
        for item in paths {
            push_string(Some(item), &mut out);
        }
    }
    out
}

fn collect_apply_patch_paths(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in command.lines() {
        for prefix in [
            "*** Add File: ",
            "*** Update File: ",
            "*** Delete File: ",
            "*** Move to: ",
        ] {
            if let Some(path) = line.strip_prefix(prefix) {
                let trimmed = path.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
                break;
            }
        }
    }
    out
}

fn push_string(value: Option<&serde_json::Value>, out: &mut Vec<String>) {
    if let Some(raw) = value.and_then(serde_json::Value::as_str) {
        out.push(raw.to_string());
    }
}

fn expand_home(raw: &str, env: &dyn EnvLookup) -> PathBuf {
    let Some(home_os) = env.var_os("HOME") else {
        return PathBuf::from(raw);
    };
    let home = PathBuf::from(home_os);
    if let Some(rest) = raw.strip_prefix("~/") {
        return home.join(rest);
    }
    if raw == "~" {
        return home;
    }
    if let Some(rest) = raw.strip_prefix("$HOME/") {
        return home.join(rest);
    }
    if raw == "$HOME" {
        return home;
    }
    if let Some(rest) = raw.strip_prefix("${HOME}/") {
        return home.join(rest);
    }
    if raw == "${HOME}" {
        return home;
    }
    PathBuf::from(raw)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;

    struct MapEnv(HashMap<String, OsString>);

    impl MapEnv {
        fn with_home(home: &str) -> Self {
            let mut m = HashMap::new();
            m.insert("HOME".to_string(), OsString::from(home));
            Self(m)
        }
        fn empty() -> Self {
            Self(HashMap::new())
        }
    }

    impl EnvLookup for MapEnv {
        fn var_os(&self, key: &str) -> Option<OsString> {
            self.0.get(key).cloned()
        }
    }

    fn input(tool: &str, file_path: serde_json::Value) -> HookInput {
        HookInput {
            tool_name: tool.into(),
            tool_input: serde_json::json!({ "file_path": file_path }),
        }
    }

    #[test]
    fn extracts_read_file_path() {
        let i = input("Read", serde_json::json!("/tmp/x.txt"));
        let fp = extract_with_env(&i, &MapEnv::with_home("/h")).unwrap();
        assert_eq!(fp.tool, PathTool::Read);
        assert_eq!(fp.raw, "/tmp/x.txt");
        assert_eq!(fp.absolute, PathBuf::from("/tmp/x.txt"));
    }

    #[test]
    fn extracts_edit_and_write() {
        let e = input("Edit", serde_json::json!("/etc/hosts"));
        let w = input("Write", serde_json::json!("/etc/hosts"));
        assert_eq!(
            extract_with_env(&e, &MapEnv::with_home("/h")).unwrap().tool,
            PathTool::Edit
        );
        assert_eq!(
            extract_with_env(&w, &MapEnv::with_home("/h")).unwrap().tool,
            PathTool::Write
        );
    }

    #[test]
    fn returns_none_for_unknown_tool() {
        let i = input("Bash", serde_json::json!("/x"));
        assert!(extract_with_env(&i, &MapEnv::with_home("/h")).is_none());
    }

    #[test]
    fn returns_none_when_field_missing_or_non_string() {
        let i = HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({}),
        };
        assert!(extract_with_env(&i, &MapEnv::with_home("/h")).is_none());
        let j = input("Read", serde_json::json!(123));
        assert!(extract_with_env(&j, &MapEnv::with_home("/h")).is_none());
    }

    #[test]
    fn expands_tilde_to_home() {
        let i = input("Read", serde_json::json!("~/.ssh/id_rsa"));
        let fp = extract_with_env(&i, &MapEnv::with_home("/home/me")).unwrap();
        assert_eq!(fp.absolute, PathBuf::from("/home/me/.ssh/id_rsa"));
    }

    #[test]
    fn expands_lone_tilde() {
        let i = input("Read", serde_json::json!("~"));
        let fp = extract_with_env(&i, &MapEnv::with_home("/home/me")).unwrap();
        assert_eq!(fp.absolute, PathBuf::from("/home/me"));
    }

    #[test]
    fn expands_home_envvar_forms() {
        for raw in ["$HOME/.ssh/id", "${HOME}/.ssh/id"] {
            let i = input("Read", serde_json::json!(raw));
            let fp = extract_with_env(&i, &MapEnv::with_home("/h")).unwrap();
            assert_eq!(fp.absolute, PathBuf::from("/h/.ssh/id"));
        }
    }

    #[test]
    fn lone_home_envvar_expands() {
        for raw in ["$HOME", "${HOME}"] {
            let i = input("Read", serde_json::json!(raw));
            let fp = extract_with_env(&i, &MapEnv::with_home("/h")).unwrap();
            assert_eq!(fp.absolute, PathBuf::from("/h"));
        }
    }

    #[test]
    fn falls_back_to_raw_when_home_unset() {
        let i = input("Read", serde_json::json!("~/.ssh/id"));
        let fp = extract_with_env(&i, &MapEnv::empty()).unwrap();
        assert_eq!(fp.absolute, PathBuf::from("~/.ssh/id"));
    }

    #[test]
    fn extract_uses_system_env_lookup() {
        // Just exercise the production path: should not panic and
        // should treat an absolute path as identity.
        let i = input("Read", serde_json::json!("/tmp/sample"));
        let fp = extract(&i).unwrap();
        assert_eq!(fp.raw, "/tmp/sample");
    }

    #[test]
    fn extract_mcp_tool_uses_top_level_path_key() {
        let i = HookInput {
            tool_name: "mcp__github__create_or_update_file".into(),
            tool_input: serde_json::json!({"path": ".claude/settings.json"}),
        };
        let fp = extract_with_env(&i, &MapEnv::with_home("/h")).expect("path");
        assert_eq!(fp.tool, PathTool::Mcp);
        assert_eq!(fp.raw, ".claude/settings.json");
    }

    #[test]
    fn extract_all_collects_nested_mcp_paths() {
        let i = HookInput {
            tool_name: "mcp__github__push_files".into(),
            tool_input: serde_json::json!({
                "files": [{"path": "~/.claude/settings.json"}, {"path": "/tmp/a"}],
                "items": [{"path": "/tmp/b"}],
                "paths": ["/tmp/c"]
            }),
        };
        let paths = extract_all_with_env(&i, &MapEnv::with_home("/h"));
        let raws: Vec<_> = paths.iter().map(|p| p.raw.as_str()).collect();
        assert_eq!(
            raws,
            vec!["~/.claude/settings.json", "/tmp/a", "/tmp/b", "/tmp/c"]
        );
    }

    #[test]
    fn extract_mcp_tool_returns_none_when_path_missing() {
        let i = HookInput {
            tool_name: "mcp__filesystem__write_file".into(),
            tool_input: serde_json::json!({"content": "hi"}),
        };
        assert!(extract_with_env(&i, &MapEnv::with_home("/h")).is_none());
    }

    #[test]
    fn extract_mcp_tool_returns_none_when_path_is_not_string() {
        let i = HookInput {
            tool_name: "mcp__filesystem__write_file".into(),
            tool_input: serde_json::json!({"path": 7}),
        };
        assert!(extract_with_env(&i, &MapEnv::with_home("/h")).is_none());
    }

    #[test]
    fn extract_apply_patch_collects_add_update_delete_and_move_paths() {
        let i = HookInput {
            tool_name: "apply_patch".into(),
            tool_input: serde_json::json!({
                "command": "\
            *** Begin Patch\n\
            *** Add File: new.txt\n\
            *** Update File: old.txt\n\
            *** Move to: renamed.txt\n\
            *** Delete File: gone.txt\n\
            *** End Patch\n"
            }),
        };
        let paths = extract_all_with_env(&i, &MapEnv::with_home("/h"));
        let raws: Vec<_> = paths.iter().map(|p| p.raw.as_str()).collect();
        assert_eq!(raws, vec!["new.txt", "old.txt", "renamed.txt", "gone.txt"]);
        assert!(paths.iter().all(|p| p.tool == PathTool::ApplyPatch));
    }

    #[test]
    fn extract_apply_patch_ignores_malformed_lines() {
        let i = HookInput {
            tool_name: "apply_patch".into(),
            tool_input: serde_json::json!({
                "command": "*** Begin Patch\n*** Update File:\n*** Move to: \n*** End Patch\n"
            }),
        };
        assert!(extract_all_with_env(&i, &MapEnv::with_home("/h")).is_empty());
    }

    #[test]
    fn extract_mcp_tool_expands_home_in_raw_path() {
        let i = HookInput {
            tool_name: "mcp__filesystem__read_file".into(),
            tool_input: serde_json::json!({"path": "~/.aws/credentials"}),
        };
        let fp = extract_with_env(&i, &MapEnv::with_home("/home/me")).expect("path");
        assert_eq!(fp.absolute, PathBuf::from("/home/me/.aws/credentials"));
    }

    use crate::testing::proptest::{file_path, richer_hook_input};
    use proptest::prelude::*;

    proptest! {
        // The extractor never panics for arbitrary HookInput shapes.
        #[test]
        fn pbt_extract_never_panics(i in richer_hook_input()) {
            let _ = extract_with_env(&i, &MapEnv::with_home("/h"));
            let _ = extract(&i);
        }

        // Tools other than Read/Edit/Write/MCP always yield None, even with
        // a file_path field present. The regex `[A-Z][A-Za-z]{0,8}` only
        // produces uppercase-leading names, so `mcp__*` is excluded by
        // construction and we don't need an extra prop_assume for it.
        #[test]
        fn pbt_non_path_tool_yields_none(
            tool in "[A-Z][A-Za-z]{0,8}",
            fp in file_path(),
        ) {
            prop_assume!(!matches!(tool.as_str(), "Read" | "Edit" | "Write"));
            let i = HookInput {
                tool_name: tool,
                tool_input: serde_json::json!({ "file_path": fp }),
            };
            prop_assert!(extract_with_env(&i, &MapEnv::with_home("/h")).is_none());
        }

        // Read/Edit/Write tools with a string file_path always extract,
        // and the .raw field round-trips the input verbatim.
        #[test]
        fn pbt_path_tool_round_trips_raw(
            tool in proptest::sample::select(&["Read", "Edit", "Write"][..]),
            fp in file_path(),
        ) {
            let i = HookInput {
                tool_name: tool.to_string(),
                tool_input: serde_json::json!({ "file_path": fp.clone() }),
            };
            let out = extract_with_env(&i, &MapEnv::with_home("/h")).expect("path");
            prop_assert_eq!(out.raw, fp);
        }

        // Absolute paths (starting with `/`) are returned identically as
        // the absolute form — `~`/`$HOME` expansion is a no-op for them.
        #[test]
        fn pbt_absolute_paths_are_identity(
            tool in proptest::sample::select(&["Read", "Edit", "Write"][..]),
            tail in "[a-zA-Z0-9_./-]{0,20}",
        ) {
            let raw = format!("/{tail}");
            let i = HookInput {
                tool_name: tool.to_string(),
                tool_input: serde_json::json!({ "file_path": raw.clone() }),
            };
            let out = extract_with_env(&i, &MapEnv::with_home("/h")).expect("path");
            prop_assert_eq!(out.absolute, PathBuf::from(raw));
        }

        // `~/` prefix always expands to `<home>/...` when HOME is set.
        #[test]
        fn pbt_tilde_prefix_expands_to_home(
            tail in "[a-zA-Z0-9_./-]{0,20}",
            home in "/(?:home|h)/[a-z0-9_]{1,8}",
        ) {
            let raw = format!("~/{tail}");
            let i = HookInput {
                tool_name: "Read".into(),
                tool_input: serde_json::json!({ "file_path": raw }),
            };
            let env = MapEnv::with_home(&home);
            let out = extract_with_env(&i, &env).expect("path");
            prop_assert_eq!(out.absolute, PathBuf::from(home).join(tail));
        }

        // When HOME is unset, ~ paths fall back to the raw form rather
        // than panicking or producing a partial expansion.
        #[test]
        fn pbt_no_home_falls_back_to_raw(tail in "[a-zA-Z0-9_./-]{0,20}") {
            let raw = format!("~/{tail}");
            let i = HookInput {
                tool_name: "Read".into(),
                tool_input: serde_json::json!({ "file_path": raw.clone() }),
            };
            let out = extract_with_env(&i, &MapEnv::empty()).expect("path");
            prop_assert_eq!(out.absolute, PathBuf::from(raw));
        }
    }
}
