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
    std::env::current_exe()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| "ptuf".to_string())
}

pub fn resolve_paths(
    start: Option<&Path>,
    root: Option<&Path>,
    hooks_path: Option<&Path>,
    config_path: Option<&Path>,
) -> Result<TargetPaths, InitError> {
    let discovered_root = root
        .map(Path::to_path_buf)
        .or_else(|| start.and_then(crate::config::repo::discover));

    let hooks_path = match (hooks_path, discovered_root.as_ref(), config_path) {
        (Some(path), _, _) => path.to_path_buf(),
        (None, Some(root), _) => root.join(".codex/hooks.json"),
        (None, None, Some(config)) => sibling_path(config, "hooks.json"),
        (None, None, None) => return Err(InitError::RepoRootNotFound),
    };
    let config_path = match (config_path, discovered_root.as_ref(), hooks_path.parent()) {
        (Some(path), _, _) => path.to_path_buf(),
        (None, Some(root), _) => root.join(".codex/config.toml"),
        (None, None, Some(parent)) => parent.join("config.toml"),
        (None, None, None) => PathBuf::from("config.toml"),
    };

    Ok(TargetPaths {
        root: discovered_root,
        hooks_path,
        config_path,
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
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let n = tokens.len();
    if n < COMMAND_TAIL.len() {
        return false;
    }
    tokens[n - COMMAND_TAIL.len()..] == *COMMAND_TAIL
}

pub(crate) fn command_executable(cmd: &str) -> Option<&str> {
    cmd.split_whitespace().next()
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
    let Some(features) = doc["features"].as_table_like_mut() else {
        return false;
    };
    let already_enabled = features.get("codex_hooks").and_then(|item| item.as_bool()) == Some(true);
    if already_enabled {
        return false;
    }
    features.insert("codex_hooks", value(true));
    true
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
    fs::write(&tmp, body.as_bytes()).map_err(|e| InitError::Io {
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
    fs::write(&tmp, doc.to_string().as_bytes()).map_err(|e| InitError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| InitError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

fn sibling_temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("hooks.json"));
    name.push(format!(".ptuf.{}.tmp", std::process::id()));
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

fn sibling_path(path: &Path, file_name: &str) -> PathBuf {
    path.parent()
        .map(|parent| parent.join(file_name))
        .unwrap_or_else(|| PathBuf::from(file_name))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

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
    fn resolve_paths_prefers_root_defaults() {
        let root = PathBuf::from("/repo");
        let paths = resolve_paths(None, Some(&root), None, None).unwrap();
        assert_eq!(paths.hooks_path, PathBuf::from("/repo/.codex/hooks.json"));
        assert_eq!(paths.config_path, PathBuf::from("/repo/.codex/config.toml"));
    }

    #[test]
    fn resolve_paths_can_derive_from_explicit_hooks_path() {
        let paths =
            resolve_paths(None, None, Some(Path::new("/repo/.codex/hooks.json")), None).unwrap();
        assert_eq!(paths.config_path, PathBuf::from("/repo/.codex/config.toml"));
    }

    #[test]
    fn resolve_paths_requires_root_or_explicit_target() {
        let err = resolve_paths(None, None, None, None).unwrap_err();
        assert!(matches!(err, InitError::RepoRootNotFound));
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
        assert!(read(&targets.config_path).contains("codex_hooks = true"));
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
        fs::write(&targets.config_path, "[features]\ncodex_hooks = true\n").unwrap();
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
        assert!(read(&targets.config_path).contains("codex_hooks = true"));
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
            features.get("codex_hooks").and_then(|item| item.as_bool()),
            Some(true)
        );
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

    #[test]
    fn command_invokes_ptuf_hook_matches_trailing_tokens() {
        assert!(command_invokes_ptuf_hook("/x/ptuf hook codex"));
        assert!(command_invokes_ptuf_hook("ptuf hook codex   "));
        assert!(!command_invokes_ptuf_hook(
            "ptuf hook claude-code pre-tool-use"
        ));
    }
}
