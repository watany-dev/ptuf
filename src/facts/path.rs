//! `Read` / `Edit` / `Write` `file_path` extraction with `~` expansion.
//!
//! Expansion uses the [`crate::config::scope::EnvLookup`] trait so tests
//! can inject a hermetic `HOME` (and the production path delegates to
//! [`crate::config::scope::SystemEnv`]).

use std::path::PathBuf;

use crate::config::scope::{EnvLookup, SystemEnv};
use crate::hook_input::HookInput;

/// Tools whose payload exposes a `file_path` field that ptuf inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathTool {
    Read,
    Edit,
    Write,
}

impl PathTool {
    fn from_tool_name(name: &str) -> Option<Self> {
        match name {
            "Read" => Some(Self::Read),
            "Edit" => Some(Self::Edit),
            "Write" => Some(Self::Write),
            _ => None,
        }
    }
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

/// Build a [`FilePath`] using the supplied env lookup. The `facts::extract`
/// default path uses [`SystemEnv`]; tests inject a `MapEnv` to verify
/// `~` expansion deterministically.
pub fn extract_with_env(input: &HookInput, env: &dyn EnvLookup) -> Option<FilePath> {
    let tool = PathTool::from_tool_name(&input.tool_name)?;
    let raw = input.tool_input.get("file_path")?.as_str()?.to_string();
    let absolute = expand_home(&raw, env);
    Some(FilePath {
        tool,
        raw,
        absolute,
    })
}

/// Convenience: extract using the production environment.
pub fn extract(input: &HookInput) -> Option<FilePath> {
    extract_with_env(input, &SystemEnv)
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

    use crate::testing::proptest::{file_path, richer_hook_input};
    use proptest::prelude::*;

    proptest! {
        // The extractor never panics for arbitrary HookInput shapes.
        #[test]
        fn pbt_extract_never_panics(i in richer_hook_input()) {
            let _ = extract_with_env(&i, &MapEnv::with_home("/h"));
            let _ = extract(&i);
        }

        // Tools other than Read/Edit/Write always yield None, even with
        // a file_path field present.
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
