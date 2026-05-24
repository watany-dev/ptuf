//! `ptuf init codex` — idempotently register a `PreToolUse` hook in
//! Codex's repo-local or explicit hook/config files.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use toml_edit::{DocumentMut, Item, Table, value};

use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

/// Matcher we install for the first-class Codex adapter.
pub const DEFAULT_MATCHER: &str = "Bash|apply_patch|mcp__.*";

/// Trailing tokens that identify a ptuf Codex `PreToolUse` hook.
pub(crate) const COMMAND_TAIL: &[&str] = &["hook", "codex"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPaths {
    pub root: Option<PathBuf>,
    pub hooks_path: PathBuf,
    pub config_path: PathBuf,
}

/// Default user-level Codex hooks path (`$HOME/.codex/hooks.json`).
pub fn default_home_hooks_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".codex/hooks.json"))
}

/// Default user-level Codex config path (`$HOME/.codex/config.toml`).
pub fn default_home_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".codex/config.toml"))
}

/// Try `std::env::current_exe()`. Falls back to the literal `"ptuf"`.
pub fn detect_binary() -> String {
    super::detect_binary_impl()
}

pub fn resolve_paths(start: Option<&Path>) -> Result<TargetPaths, InitError> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    resolve_paths_with(start, home.as_deref())
}

pub(crate) fn resolve_paths_with(
    start: Option<&Path>,
    home: Option<&Path>,
) -> Result<TargetPaths, InitError> {
    if let Some(root) = start.and_then(crate::config::repo::discover) {
        return Ok(TargetPaths {
            root: Some(root.clone()),
            hooks_path: root.join(".codex/hooks.json"),
            config_path: root.join(".codex/config.toml"),
        });
    }
    let home = home.ok_or(InitError::RepoRootNotFound)?;
    Ok(TargetPaths {
        root: None,
        hooks_path: home.join(".codex/hooks.json"),
        config_path: home.join(".codex/config.toml"),
    })
}

pub fn install(
    targets: &TargetPaths,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} hook codex");
    let mut hooks_root = read_hooks(&targets.hooks_path)?;
    let mut config = read_config(&targets.config_path)?;

    let mut hooks_changed = false;
    if !has_existing_hook(&hooks_root) {
        append_hook(&mut hooks_root, &targets.hooks_path, &command)?;
        hooks_changed = true;
    }

    let config_changed = ensure_hooks_enabled(&mut config);
    let status = if !hooks_changed && !config_changed {
        InstallStatus::AlreadyPresent
    } else if dry_run {
        InstallStatus::WouldInstall
    } else {
        if hooks_changed {
            write_json_atomically(&targets.hooks_path, &hooks_root)?;
        }
        if config_changed {
            write_toml_atomically(&targets.config_path, &config)?;
        }
        InstallStatus::Installed
    };

    Ok(InstallOutcome {
        status,
        agent: "codex",
        paths: vec![
            InstallPath {
                label: "hooks",
                path: targets.hooks_path.clone(),
            },
            InstallPath {
                label: "config",
                path: targets.config_path.clone(),
            },
        ],
        matcher: DEFAULT_MATCHER.to_string(),
        command,
    })
}

fn read_hooks(path: &Path) -> Result<Value, InitError> {
    match fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(json!({})),
        Ok(s) => serde_json::from_str(&s).map_err(|e| InitError::Json {
            path: path.to_path_buf(),
            message: e.to_string(),
        }),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(InitError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

fn read_config(path: &Path) -> Result<DocumentMut, InitError> {
    match fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(DocumentMut::new()),
        Ok(s) => s.parse::<DocumentMut>().map_err(|e| InitError::Toml {
            path: path.to_path_buf(),
            message: e.to_string(),
        }),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(DocumentMut::new()),
        Err(e) => Err(InitError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

pub(crate) fn command_invokes_ptuf_hook(cmd: &str) -> bool {
    super::command_invokes_ptuf_hook(cmd, COMMAND_TAIL)
}

pub(crate) fn pre_tool_use_commands(root: &Value) -> Vec<String> {
    let Some(arr) = root.pointer("/hooks/PreToolUse").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut commands = Vec::new();
    for entry in arr {
        commands.extend(entry_commands(entry));
    }
    commands
}

pub(crate) fn entry_commands(entry: &Value) -> Vec<String> {
    let Some(hooks) = entry.get("hooks").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut commands = Vec::new();
    for hook in hooks {
        if let Some(cmd) = hook.get("command").and_then(Value::as_str) {
            commands.push(cmd.to_string());
        }
    }
    commands
}

fn has_existing_hook(root: &Value) -> bool {
    pre_tool_use_commands(root)
        .iter()
        .any(|cmd| command_invokes_ptuf_hook(cmd))
}

fn append_hook(root: &mut Value, hooks_path: &Path, command: &str) -> Result<(), InitError> {
    if !root.is_object() {
        return Err(InitError::Schema {
            path: hooks_path.to_path_buf(),
            message: "top-level value must be a JSON object".into(),
        });
    }

    let hooks = root
        .as_object_mut()
        .and_then(|m| {
            m.entry("hooks")
                .or_insert_with(|| json!({}))
                .as_object_mut()
        })
        .ok_or_else(|| InitError::Schema {
            path: hooks_path.to_path_buf(),
            message: "`hooks` must be an object".into(),
        })?;

    let pre_tool_use = hooks
        .entry("PreToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| InitError::Schema {
            path: hooks_path.to_path_buf(),
            message: "`hooks.PreToolUse` must be an array".into(),
        })?;

    pre_tool_use.push(json!({
        "matcher": DEFAULT_MATCHER,
        "hooks": [{
            "type": "command",
            "command": command,
        }],
    }));
    Ok(())
}

fn ensure_hooks_enabled(doc: &mut DocumentMut) -> bool {
    if !doc.as_table().contains_key("features") || doc["features"].as_table_like_mut().is_none() {
        doc["features"] = Item::Table(Table::new());
    }
    let mut changed = false;
    if let Some(features) = doc["features"].as_table_like_mut() {
        // Codex deprecated `codex_hooks` in favor of `hooks`; strip the legacy
        // key so re-running `init` silences the upstream warning.
        if features.remove("codex_hooks").is_some() {
            changed = true;
        }
        let already_enabled =
            features.get("hooks").and_then(toml_edit::Item::as_bool) == Some(true);
        if !already_enabled {
            features.insert("hooks", value(true));
            changed = true;
        }
    }
    changed
}

fn write_json_atomically(path: &Path, value: &Value) -> Result<(), InitError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| InitError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let mut body = serde_json::to_string_pretty(value).map_err(|e| InitError::Schema {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    body.push('\n');

    let tmp = sibling_temp_path(path);
    crate::init::write_secure(&tmp, body.as_bytes()).map_err(|e| InitError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| InitError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

fn write_toml_atomically(path: &Path, doc: &DocumentMut) -> Result<(), InitError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| InitError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let tmp = sibling_temp_path(path);
    crate::init::write_secure(&tmp, doc.to_string().as_bytes()).map_err(|e| InitError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| InitError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

fn sibling_temp_path(path: &Path) -> PathBuf {
    super::sibling_install_tmp_path(path, "hooks.json")
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::init::command_executable;

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-init-codex-{}-{}-{}",
            tag,
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn resolve_paths_uses_repo_root_when_discovered() {
        let dir = workdir("resolve-repo");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let paths = resolve_paths_with(Some(dir.as_path()), None).unwrap();
        assert_eq!(paths.hooks_path, dir.join(".codex/hooks.json"));
        assert_eq!(paths.config_path, dir.join(".codex/config.toml"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_paths_falls_back_to_home_when_no_repo_root() {
        let home = workdir("resolve-home");
        let outside = workdir("resolve-outside");
        let paths = resolve_paths_with(Some(outside.as_path()), Some(home.as_path())).unwrap();
        assert_eq!(paths.hooks_path, home.join(".codex/hooks.json"));
        assert_eq!(paths.config_path, home.join(".codex/config.toml"));
        let _ = fs::remove_dir_all(&home);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn resolve_paths_errors_when_no_repo_and_home_unset() {
        let outside = workdir("resolve-no-home");
        let err = resolve_paths_with(Some(outside.as_path()), None).unwrap_err();
        assert!(matches!(err, InitError::RepoRootNotFound));
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn installs_missing_hooks_and_config_files() {
        let dir = workdir("install");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        let outcome = install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        assert!(read(&targets.hooks_path).contains("\"PreToolUse\""));
        assert!(read(&targets.hooks_path).contains(DEFAULT_MATCHER));
        let doc = read(&targets.config_path).parse::<DocumentMut>().unwrap();
        let features = doc["features"].as_table_like().unwrap();
        assert_eq!(
            features.get("hooks").and_then(|item| item.as_bool()),
            Some(true)
        );
        assert!(!features.contains_key("codex_hooks"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_idempotent_when_hook_and_feature_already_exist() {
        let dir = workdir("idempotent");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&json!({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": DEFAULT_MATCHER,
                        "hooks": [{
                            "type": "command",
                            "command": "/x/ptuf hook codex"
                        }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(&targets.config_path, "[features]\nhooks = true\n").unwrap();
        let before_hooks = read(&targets.hooks_path);
        let before_config = read(&targets.config_path);
        let outcome = install(&targets, "/y/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(before_hooks, read(&targets.hooks_path));
        assert_eq!(before_config, read(&targets.config_path));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_reports_changes_without_writing() {
        let dir = workdir("dry-run");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        let outcome = install(&targets, "/usr/local/bin/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!targets.hooks_path.exists());
        assert!(!targets.config_path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_updates_feature_flag_without_rewriting_valid_hook() {
        let dir = workdir("feature-only");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&json!({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": DEFAULT_MATCHER,
                        "hooks": [{
                            "type": "command",
                            "command": "/x/ptuf hook codex"
                        }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(&targets.config_path, "[features]\ncodex_hooks = false\n").unwrap();
        let before_hooks = read(&targets.hooks_path);
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        assert_eq!(before_hooks, read(&targets.hooks_path));
        let doc = read(&targets.config_path).parse::<DocumentMut>().unwrap();
        let features = doc["features"].as_table_like().unwrap();
        assert_eq!(
            features.get("hooks").and_then(|item| item.as_bool()),
            Some(true)
        );
        assert!(!features.contains_key("codex_hooks"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_preserves_inline_feature_table_entries() {
        let dir = workdir("inline-features");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&json!({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": DEFAULT_MATCHER,
                        "hooks": [{
                            "type": "command",
                            "command": "/x/ptuf hook codex"
                        }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &targets.config_path,
            "features = { approval_policy = true, codex_hooks = false }\n",
        )
        .unwrap();

        let outcome = install(&targets, "/x/ptuf", false).unwrap();

        assert_eq!(outcome.status, InstallStatus::Installed);
        let doc = read(&targets.config_path).parse::<DocumentMut>().unwrap();
        let features = doc["features"].as_table_like().unwrap();
        assert_eq!(
            features
                .get("approval_policy")
                .and_then(|item| item.as_bool()),
            Some(true)
        );
        assert_eq!(
            features.get("hooks").and_then(|item| item.as_bool()),
            Some(true)
        );
        assert!(!features.contains_key("codex_hooks"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_invalid_hooks_json() {
        let dir = workdir("bad-hooks");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, "{not json").unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Json { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    // A malformed hooks.json must remain untouched byte-for-byte after
    // install fails — the writer does not partially overwrite.
    #[test]
    fn install_does_not_overwrite_invalid_hooks_json() {
        let dir = workdir("bad-hooks-untouched");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        let before = "{not json";
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, before).unwrap();
        let _ = install(&targets, "/x/ptuf", false);
        let after = fs::read_to_string(&targets.hooks_path).unwrap();
        assert_eq!(after, before, "hooks.json was modified despite Err");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_invalid_config_toml() {
        let dir = workdir("bad-config");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.config_path.parent().unwrap()).unwrap();
        fs::write(&targets.config_path, "[features\ncodex_hooks = true").unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Toml { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    // Same non-destructive invariant for config.toml.
    #[test]
    fn install_does_not_overwrite_invalid_config_toml() {
        let dir = workdir("bad-config-untouched");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        let before = "[features\ncodex_hooks = true";
        fs::create_dir_all(targets.config_path.parent().unwrap()).unwrap();
        fs::write(&targets.config_path, before).unwrap();
        let _ = install(&targets, "/x/ptuf", false);
        let after = fs::read_to_string(&targets.config_path).unwrap();
        assert_eq!(after, before, "config.toml was modified despite Err");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn command_invokes_ptuf_hook_matches_trailing_tokens() {
        assert!(command_invokes_ptuf_hook("/x/ptuf hook codex"));
        assert!(command_invokes_ptuf_hook("ptuf hook codex   "));
        assert!(!command_invokes_ptuf_hook(
            "ptuf hook claude-code pre-tool-use"
        ));
    }

    #[test]
    fn default_home_hooks_path_ends_with_codex_when_home_is_set() {
        if let Some(path) = default_home_hooks_path() {
            assert!(path.ends_with(".codex/hooks.json"));
        }
    }

    #[test]
    fn default_home_config_path_ends_with_codex_when_home_is_set() {
        if let Some(path) = default_home_config_path() {
            assert!(path.ends_with(".codex/config.toml"));
        }
    }

    #[test]
    fn command_executable_returns_first_token_or_none() {
        assert_eq!(command_executable("/x/ptuf hook codex"), Some("/x/ptuf"));
        assert_eq!(command_executable(""), None);
    }

    #[test]
    fn entry_commands_returns_empty_when_hooks_key_is_missing() {
        let entry = json!({ "matcher": DEFAULT_MATCHER });
        assert!(entry_commands(&entry).is_empty());
    }

    #[test]
    fn entry_commands_returns_empty_when_hooks_is_not_an_array() {
        let entry = json!({ "matcher": DEFAULT_MATCHER, "hooks": "not-an-array" });
        assert!(entry_commands(&entry).is_empty());
    }

    #[test]
    fn empty_hooks_file_is_treated_as_empty_object() {
        let dir = workdir("empty-hooks");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, "").unwrap();
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&targets.hooks_path)).unwrap();
        assert!(after.pointer("/hooks/PreToolUse").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_config_file_is_treated_as_empty_document() {
        let dir = workdir("empty-config");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.config_path.parent().unwrap()).unwrap();
        fs::write(&targets.config_path, "").unwrap();
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let doc = read(&targets.config_path).parse::<DocumentMut>().unwrap();
        let features = doc["features"].as_table_like().unwrap();
        assert_eq!(
            features.get("hooks").and_then(|item| item.as_bool()),
            Some(true)
        );
        assert!(!features.contains_key("codex_hooks"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_reports_io_error_when_hooks_path_is_a_directory() {
        let dir = workdir("hooks-is-dir");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join("hooks-as-dir"),
            config_path: dir.join("config.toml"),
        };
        fs::create_dir_all(&targets.hooks_path).unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Io { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_reports_io_error_when_config_path_is_a_directory() {
        let dir = workdir("config-is-dir");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join("hooks.json"),
            config_path: dir.join("config-as-dir"),
        };
        fs::create_dir_all(&targets.config_path).unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Io { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_top_level_is_not_object() {
        let dir = workdir("non-object-hooks");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, "[]").unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Schema { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_hooks_value_is_wrong_type() {
        let dir = workdir("hooks-wrong-type");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, r#"{"hooks": 42}"#).unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        match err {
            InitError::Schema { message, .. } => {
                assert!(message.contains("hooks"), "got: {message}");
            },
            other => panic!("unexpected: {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_pre_tool_use_is_wrong_type() {
        let dir = workdir("pretooluse-wrong-type");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.hooks_path,
            r#"{"hooks": {"PreToolUse": "not-an-array"}}"#,
        )
        .unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        match err {
            InitError::Schema { message, .. } => {
                assert!(message.contains("PreToolUse"), "got: {message}");
            },
            other => panic!("unexpected: {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_appends_when_a_different_matcher_already_exists() {
        let dir = workdir("append-matcher");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        let preset = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "/usr/bin/something-else" }
                        ]
                    }
                ]
            }
        });
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&preset).unwrap(),
        )
        .unwrap();
        let outcome = install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&targets.hooks_path)).unwrap();
        let arr = after
            .pointer("/hooks/PreToolUse")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(arr.len(), 2, "existing entry preserved, ours appended");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn already_present_detection_ignores_unrelated_command_strings() {
        let dir = workdir("unrelated-cmd");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        let preset = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "/x/something-else --flag" },
                            { "type": "command", "command": "echo hi" }
                        ]
                    }
                ]
            }
        });
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&preset).unwrap(),
        )
        .unwrap();
        let outcome = install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&targets.hooks_path)).unwrap();
        let arr = after
            .pointer("/hooks/PreToolUse")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(arr.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_preserves_unknown_keys_in_hooks_and_config() {
        let dir = workdir("preserve-keys");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        let preset = json!({
            "model": "gpt-codex",
            "extras": { "deep": { "value": 42 } }
        });
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&preset).unwrap(),
        )
        .unwrap();
        fs::write(
            &targets.config_path,
            "[other]\nkeep = \"me\"\n\n[features]\napproval_policy = true\n",
        )
        .unwrap();
        install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        let after_hooks: Value = serde_json::from_str(&read(&targets.hooks_path)).unwrap();
        assert_eq!(
            after_hooks.get("model").and_then(Value::as_str),
            Some("gpt-codex")
        );
        assert_eq!(
            after_hooks
                .pointer("/extras/deep/value")
                .and_then(Value::as_i64),
            Some(42)
        );
        let after_config = read(&targets.config_path).parse::<DocumentMut>().unwrap();
        assert_eq!(
            after_config["other"]["keep"].as_str(),
            Some("me"),
            "unrelated [other] table must survive"
        );
        let features = after_config["features"].as_table_like().unwrap();
        assert_eq!(
            features
                .get("approval_policy")
                .and_then(|item| item.as_bool()),
            Some(true)
        );
        assert_eq!(
            features.get("hooks").and_then(|item| item.as_bool()),
            Some(true)
        );
        assert!(!features.contains_key("codex_hooks"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sibling_temp_path_uses_default_filename_when_input_has_none() {
        let p = Path::new("/");
        let tmp = sibling_temp_path(p);
        assert!(
            tmp.to_string_lossy().contains("hooks.json.ptuf."),
            "missing file_name must default to hooks.json: {tmp:?}"
        );
    }

    #[test]
    fn write_json_atomically_returns_io_err_when_parent_is_a_regular_file() {
        let dir = workdir("write-json-blocker");
        let blocker = dir.join("blocker");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("sub/hooks.json");
        let err = write_json_atomically(&path, &json!({})).unwrap_err();
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_toml_atomically_returns_io_err_when_parent_is_a_regular_file() {
        let dir = workdir("write-toml-blocker");
        let blocker = dir.join("blocker");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("sub/config.toml");
        let err = write_toml_atomically(&path, &DocumentMut::new()).unwrap_err();
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_json_atomically_propagates_rename_error_when_target_is_a_directory() {
        let dir = workdir("write-json-rename-dir");
        let target = dir.join("hooks.json");
        fs::create_dir_all(&target).unwrap();
        let err =
            write_json_atomically(&target, &json!({})).expect_err("rename onto dir must fail");
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_json_atomically_propagates_write_error_when_temp_path_is_a_directory() {
        let dir = workdir("write-json-tmp-collision");
        let target = dir.join("hooks.json");
        let collision = dir.join(format!("hooks.json.ptuf.{}.tmp", std::process::id()));
        fs::create_dir_all(&collision).unwrap();
        let err = write_json_atomically(&target, &json!({})).expect_err("write onto dir must fail");
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_toml_atomically_propagates_rename_error_when_target_is_a_directory() {
        let dir = workdir("write-toml-rename-dir");
        let target = dir.join("config.toml");
        fs::create_dir_all(&target).unwrap();
        let err = write_toml_atomically(&target, &DocumentMut::new())
            .expect_err("rename onto dir must fail");
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_toml_atomically_propagates_write_error_when_temp_path_is_a_directory() {
        let dir = workdir("write-toml-tmp-collision");
        let target = dir.join("config.toml");
        let collision = dir.join(format!("config.toml.ptuf.{}.tmp", std::process::id()));
        fs::create_dir_all(&collision).unwrap();
        let err = write_toml_atomically(&target, &DocumentMut::new())
            .expect_err("write onto dir must fail");
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_writes_hooks_and_config_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workdir("perm-codex");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let targets = resolve_paths_with(Some(dir.as_path()), None).unwrap();
        install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        for p in [&targets.hooks_path, &targets.config_path] {
            let mode = fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} must be 0600", p.display());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_migrates_legacy_codex_hooks_key() {
        let dir = workdir("migrate-legacy");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&json!({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": DEFAULT_MATCHER,
                        "hooks": [{
                            "type": "command",
                            "command": "/x/ptuf hook codex"
                        }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(&targets.config_path, "[features]\ncodex_hooks = true\n").unwrap();
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let doc = read(&targets.config_path).parse::<DocumentMut>().unwrap();
        let features = doc["features"].as_table_like().unwrap();
        assert_eq!(
            features.get("hooks").and_then(|item| item.as_bool()),
            Some(true)
        );
        assert!(
            !features.contains_key("codex_hooks"),
            "legacy codex_hooks key must be removed"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_idempotent_when_new_hooks_key_already_true() {
        let dir = workdir("idempotent-new-key");
        let targets = TargetPaths {
            root: Some(dir.clone()),
            hooks_path: dir.join(".codex/hooks.json"),
            config_path: dir.join(".codex/config.toml"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&json!({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": DEFAULT_MATCHER,
                        "hooks": [{
                            "type": "command",
                            "command": "/x/ptuf hook codex"
                        }]
                    }]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(&targets.config_path, "[features]\nhooks = true\n").unwrap();
        let before_hooks = read(&targets.hooks_path);
        let before_config = read(&targets.config_path);
        let outcome = install(&targets, "/y/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(before_hooks, read(&targets.hooks_path));
        assert_eq!(before_config, read(&targets.config_path));
        let _ = fs::remove_dir_all(&dir);
    }
}
