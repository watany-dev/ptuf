//! `ptuf init cursor` — idempotently register a `preToolUse` hook in
//! Cursor's `.cursor/hooks.json` file.
//!
//! Unlike the Copilot adapter (which always targets a repo-local
//! `.github/hooks/ptuf.json`), Cursor supports both a repo-local scope
//! (`<repo>/.cursor/hooks.json`, the default) and a user-global scope
//! (`$HOME/.cursor/hooks.json`). The `--scope` / `--root` / `--hooks`
//! flags select between them; see [`CursorInitOptions`].

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

/// Matcher recorded in [`InstallOutcome`] and written to the hook entry.
/// Cursor matches the agent tool name against this regex before invoking
/// the hook; the alternation covers ptuf's canonical tool vocabulary plus
/// the `mcp__*` family.
pub const DEFAULT_MATCHER: &str = "Shell|Bash|Read|ReadFile|Write|Edit|MCP|WebFetch|Fetch|mcp__.*";

/// Default repo-relative (and home-relative) path for the Cursor hook
/// file.
pub const DEFAULT_HOOKS_PATH: &str = ".cursor/hooks.json";

/// Default timeout we record on the hook entry. Cursor may abort the
/// tool call if the hook does not respond within this many seconds.
pub const DEFAULT_TIMEOUT_SEC: u64 = 10;

/// Trailing tokens (split on whitespace) that mark a `command` field as
/// a ptuf Cursor `preToolUse` hook.
pub(crate) const COMMAND_TAIL: &[&str] = &["hook", "cursor"];

/// Which `.cursor/hooks.json` file `ptuf init cursor` should patch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CursorScope {
    /// `<repo>/.cursor/hooks.json`, discovered from the cwd (or `--root`).
    #[default]
    Local,
    /// `$HOME/.cursor/hooks.json`.
    Global,
}

/// Cursor-specific `ptuf init cursor` flags.
///
/// `--hooks <path>` takes precedence over everything (patch that exact
/// file). Otherwise `--scope global` patches `$HOME/.cursor/hooks.json`
/// and `--scope local` (default) patches `<repo>/.cursor/hooks.json`,
/// using `--root <path>` as the repo-discovery start directory when set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CursorInitOptions {
    pub scope: CursorScope,
    pub root: Option<PathBuf>,
    pub hooks: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPaths {
    pub root: PathBuf,
    pub hooks_path: PathBuf,
}

/// Try `std::env::current_exe()`. Falls back to the literal `"ptuf"`.
pub fn detect_binary() -> String {
    super::detect_binary_impl()
}

/// Resolve the `.cursor/hooks.json` target for the requested scope.
///
/// Reads `$HOME` from the environment and delegates to
/// `resolve_paths_with` so the resolution logic stays testable without
/// touching the real environment.
pub fn resolve_paths(
    start: Option<&Path>,
    options: &CursorInitOptions,
) -> Result<TargetPaths, InitError> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    resolve_paths_with(start, home.as_deref(), options)
}

fn resolve_paths_with(
    start: Option<&Path>,
    home: Option<&Path>,
    options: &CursorInitOptions,
) -> Result<TargetPaths, InitError> {
    if let Some(hooks_path) = options.hooks.as_ref() {
        let root = hooks_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        return Ok(TargetPaths {
            root,
            hooks_path: hooks_path.clone(),
        });
    }

    match options.scope {
        CursorScope::Global => {
            let home = home.ok_or(InitError::HomeNotSet)?;
            let root = home.to_path_buf();
            let hooks_path = root.join(DEFAULT_HOOKS_PATH);
            Ok(TargetPaths { root, hooks_path })
        },
        CursorScope::Local => {
            let discover_start = options.root.as_deref().or(start);
            let root = discover_start
                .and_then(crate::config::repo::discover)
                .ok_or(InitError::RepoRootNotFound)?;
            let hooks_path = root.join(DEFAULT_HOOKS_PATH);
            Ok(TargetPaths { root, hooks_path })
        },
    }
}

pub fn install(
    targets: &TargetPaths,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} hook cursor");
    let mut root = read_hooks(&targets.hooks_path)?;
    let before = root.clone();

    ensure_version(&mut root, &targets.hooks_path)?;
    let had_existing = normalise_existing_hooks(&mut root, &command);
    if !had_existing {
        append_hook(&mut root, &targets.hooks_path, &command)?;
    }

    let status = if root == before {
        InstallStatus::AlreadyPresent
    } else if dry_run {
        InstallStatus::WouldInstall
    } else {
        write_json_atomically(&targets.hooks_path, &root)?;
        InstallStatus::Installed
    };

    Ok(InstallOutcome {
        status,
        agent: "cursor",
        paths: vec![InstallPath {
            label: "hooks",
            path: targets.hooks_path.clone(),
        }],
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

pub(crate) fn command_invokes_ptuf_hook(cmd: &str) -> bool {
    super::command_invokes_ptuf_hook(cmd, COMMAND_TAIL)
}

#[cfg(test)]
pub(crate) fn pre_tool_use_commands(root: &Value) -> Vec<String> {
    let Some(arr) = root.pointer("/hooks/preToolUse").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut commands = Vec::new();
    for entry in arr {
        commands.extend(entry_commands(entry));
    }
    commands
}

/// Extract the `command` string field from a Cursor hook entry.
#[cfg(test)]
pub(crate) fn entry_commands(entry: &Value) -> Vec<String> {
    let mut commands = Vec::new();
    if let Some(s) = entry.get("command").and_then(Value::as_str) {
        commands.push(s.to_string());
    }
    commands
}

fn normalise_existing_hooks(root: &mut Value, command: &str) -> bool {
    let Some(arr) = root
        .pointer_mut("/hooks/preToolUse")
        .and_then(Value::as_array_mut)
    else {
        return false;
    };

    let mut found = false;
    for entry in arr {
        let Some(existing_command) = entry.get("command").and_then(Value::as_str) else {
            continue;
        };
        if !command_invokes_ptuf_hook(existing_command) {
            continue;
        }
        found = true;
        if let Some(map) = entry.as_object_mut() {
            map.insert("type".into(), json!("command"));
            map.insert("command".into(), json!(command));
            map.insert("matcher".into(), json!(DEFAULT_MATCHER));
            map.insert("timeout".into(), json!(DEFAULT_TIMEOUT_SEC));
            map.insert("failClosed".into(), json!(true));
        }
    }
    found
}

fn ensure_version(root: &mut Value, hooks_path: &Path) -> Result<(), InitError> {
    let Some(map) = root.as_object_mut() else {
        return Err(InitError::Schema {
            path: hooks_path.to_path_buf(),
            message: "top-level value must be a JSON object".into(),
        });
    };
    match map.get("version") {
        None => {
            map.insert("version".to_string(), json!(1));
            Ok(())
        },
        Some(v) if v == &json!(1) => Ok(()),
        Some(other) => Err(InitError::Schema {
            path: hooks_path.to_path_buf(),
            message: format!("`version` must be 1 (found {other})"),
        }),
    }
}

fn append_hook(root: &mut Value, hooks_path: &Path, command: &str) -> Result<(), InitError> {
    let map = root.as_object_mut().ok_or_else(|| InitError::Schema {
        path: hooks_path.to_path_buf(),
        message: "top-level value must be a JSON object".into(),
    })?;

    let hooks = ensure_object(map, "hooks").ok_or_else(|| InitError::Schema {
        path: hooks_path.to_path_buf(),
        message: "`hooks` must be an object".into(),
    })?;

    let pre_tool_use = ensure_array(hooks, "preToolUse").ok_or_else(|| InitError::Schema {
        path: hooks_path.to_path_buf(),
        message: "`hooks.preToolUse` must be an array".into(),
    })?;

    pre_tool_use.push(json!({
        "type": "command",
        "command": command,
        "matcher": DEFAULT_MATCHER,
        "timeout": DEFAULT_TIMEOUT_SEC,
        "failClosed": true,
    }));
    Ok(())
}

fn ensure_object<'a>(
    map: &'a mut Map<String, Value>,
    key: &str,
) -> Option<&'a mut Map<String, Value>> {
    map.entry(key.to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
}

fn ensure_array<'a>(map: &'a mut Map<String, Value>, key: &str) -> Option<&'a mut Vec<Value>> {
    map.entry(key.to_string())
        .or_insert_with(|| json!([]))
        .as_array_mut()
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

fn sibling_temp_path(path: &Path) -> PathBuf {
    super::sibling_install_tmp_path(path, "hooks.json")
}

#[cfg(test)]
mod tests {

    use super::*;

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-init-cursor-{}-{}-{}",
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
    fn resolve_paths_local_requires_repo_root() {
        let err = resolve_paths_with(None, None, &CursorInitOptions::default()).unwrap_err();
        assert!(matches!(err, InitError::RepoRootNotFound));
    }

    #[test]
    fn resolve_paths_local_uses_discovered_repo_root() {
        let dir = workdir("resolve-local");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let targets =
            resolve_paths_with(Some(dir.as_path()), None, &CursorInitOptions::default()).unwrap();
        assert_eq!(targets.hooks_path, dir.join(".cursor/hooks.json"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_paths_root_override_takes_priority_over_start() {
        let dir = workdir("resolve-root-override");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let options = CursorInitOptions {
            root: Some(dir.clone()),
            ..CursorInitOptions::default()
        };
        // start is a bogus path with no repo; --root must win.
        let targets = resolve_paths_with(Some(Path::new("/nonexistent")), None, &options).unwrap();
        assert_eq!(targets.hooks_path, dir.join(".cursor/hooks.json"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_paths_global_requires_home() {
        let options = CursorInitOptions {
            scope: CursorScope::Global,
            ..CursorInitOptions::default()
        };
        let err = resolve_paths_with(None, None, &options).unwrap_err();
        assert!(matches!(err, InitError::HomeNotSet));
    }

    #[test]
    fn resolve_paths_global_uses_home_cursor_dir() {
        let home = workdir("resolve-global");
        let options = CursorInitOptions {
            scope: CursorScope::Global,
            ..CursorInitOptions::default()
        };
        let targets = resolve_paths_with(None, Some(home.as_path()), &options).unwrap();
        assert_eq!(targets.hooks_path, home.join(".cursor/hooks.json"));
        assert_eq!(targets.root, home);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn resolve_paths_hooks_override_wins_over_scope() {
        let dir = workdir("resolve-hooks-override");
        let explicit = dir.join("custom/place/hooks.json");
        let options = CursorInitOptions {
            scope: CursorScope::Global,
            root: Some(PathBuf::from("/ignored")),
            hooks: Some(explicit.clone()),
        };
        // Even with no HOME and Global scope, the explicit path is used.
        let targets = resolve_paths_with(None, None, &options).unwrap();
        assert_eq!(targets.hooks_path, explicit);
        assert_eq!(targets.root, dir.join("custom/place"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_paths_hooks_override_without_parent_uses_dot_root() {
        let options = CursorInitOptions {
            hooks: Some(PathBuf::from("hooks.json")),
            ..CursorInitOptions::default()
        };
        let targets = resolve_paths_with(None, None, &options).unwrap();
        assert_eq!(targets.root, PathBuf::from("."));
        assert_eq!(targets.hooks_path, PathBuf::from("hooks.json"));
    }

    #[test]
    fn installs_missing_hooks_file() {
        let dir = workdir("install");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        let outcome = install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = read(&targets.hooks_path);
        assert!(body.contains("\"preToolUse\""));
        assert!(body.contains("/usr/local/bin/ptuf hook cursor"));
        assert!(body.contains("\"type\": \"command\""));
        assert!(body.contains("\"failClosed\": true"));
        assert!(body.contains("\"timeout\": 10"));
        assert!(body.contains("\"version\": 1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_idempotent_when_hook_already_exists() {
        let dir = workdir("idempotent");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        install(&targets, "/x/ptuf", false).unwrap();
        let before = read(&targets.hooks_path);
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(before, read(&targets.hooks_path));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_updates_existing_ptuf_hook_to_recommended_values() {
        let dir = workdir("update-existing");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        let preset = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [{
                    "type": "command",
                    "command": "/old/ptuf hook cursor",
                    "matcher": "Shell",
                    "timeout": 1,
                    "failClosed": false,
                    "keep": "me",
                }]
            }
        });
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&preset).unwrap(),
        )
        .unwrap();

        let outcome = install(&targets, "/new/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&targets.hooks_path)).unwrap();
        let entry = after
            .pointer("/hooks/preToolUse/0")
            .and_then(Value::as_object)
            .unwrap();
        assert_eq!(
            entry.get("command").and_then(Value::as_str),
            Some("/new/ptuf hook cursor")
        );
        assert_eq!(
            entry.get("matcher").and_then(Value::as_str),
            Some(DEFAULT_MATCHER)
        );
        assert_eq!(
            entry.get("timeout").and_then(Value::as_u64),
            Some(DEFAULT_TIMEOUT_SEC)
        );
        assert_eq!(entry.get("failClosed").and_then(Value::as_bool), Some(true));
        assert_eq!(entry.get("keep").and_then(Value::as_str), Some("me"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_reports_existing_hook_update_without_writing() {
        let dir = workdir("dry-run-update");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.hooks_path,
            r#"{"version":1,"hooks":{"preToolUse":[{"command":"/old/ptuf hook cursor"}]}}"#,
        )
        .unwrap();
        let before = read(&targets.hooks_path);

        let outcome = install(&targets, "/new/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert_eq!(read(&targets.hooks_path), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_reports_changes_without_writing() {
        let dir = workdir("dry-run");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        let outcome = install(&targets, "/usr/local/bin/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!targets.hooks_path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_appends_when_unrelated_entry_exists() {
        let dir = workdir("append");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        let preset = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [{
                    "type": "command",
                    "command": "/usr/bin/something-else",
                }]
            }
        });
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&preset).unwrap(),
        )
        .unwrap();
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&targets.hooks_path)).unwrap();
        let arr = after
            .pointer("/hooks/preToolUse")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(arr.len(), 2, "existing entry preserved, ours appended");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_preserves_unknown_keys() {
        let dir = workdir("preserve-keys");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        let preset = json!({
            "version": 1,
            "extras": { "deep": { "value": 42 } },
        });
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&preset).unwrap(),
        )
        .unwrap();
        install(&targets, "/x/ptuf", false).unwrap();
        let after: Value = serde_json::from_str(&read(&targets.hooks_path)).unwrap();
        assert_eq!(
            after.pointer("/extras/deep/value").and_then(Value::as_i64),
            Some(42)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_supplies_version_when_missing() {
        let dir = workdir("version-default");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, "{}").unwrap();
        install(&targets, "/x/ptuf", false).unwrap();
        let after: Value = serde_json::from_str(&read(&targets.hooks_path)).unwrap();
        assert_eq!(after.get("version").and_then(Value::as_i64), Some(1));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_unsupported_version() {
        let dir = workdir("bad-version");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, r#"{"version": 2}"#).unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        match err {
            InitError::Schema { message, .. } => {
                assert!(message.contains("version"), "got: {message}");
            },
            other => panic!("unexpected: {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_invalid_hooks_json() {
        let dir = workdir("bad-hooks");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, "{not json").unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Json { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_does_not_overwrite_invalid_hooks_json() {
        let dir = workdir("bad-hooks-untouched");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
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
    fn install_rejects_when_top_level_is_not_object() {
        let dir = workdir("non-object");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, "[]").unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Schema { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_pre_tool_use_is_wrong_type() {
        let dir = workdir("pretool-wrong-type");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.hooks_path,
            r#"{"version": 1, "hooks": {"preToolUse": "not-an-array"}}"#,
        )
        .unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        match err {
            InitError::Schema { message, .. } => {
                assert!(message.contains("preToolUse"), "got: {message}");
            },
            other => panic!("unexpected: {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_hooks_is_wrong_type() {
        let dir = workdir("hooks-wrong-type");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, r#"{"version": 1, "hooks": 42}"#).unwrap();
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
    fn empty_hooks_file_is_treated_as_empty_object() {
        let dir = workdir("empty-hooks");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".cursor/hooks.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, "").unwrap();
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&targets.hooks_path)).unwrap();
        assert!(after.pointer("/hooks/preToolUse").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn command_invokes_ptuf_hook_matches_trailing_tokens() {
        assert!(command_invokes_ptuf_hook("/x/ptuf hook cursor"));
        assert!(command_invokes_ptuf_hook("ptuf hook cursor   "));
        assert!(!command_invokes_ptuf_hook("ptuf hook copilot"));
        assert!(!command_invokes_ptuf_hook("ptuf"));
    }

    #[test]
    fn entry_commands_collects_command_field() {
        let entry = json!({
            "type": "command",
            "command": "ptuf hook cursor",
        });
        let cmds = entry_commands(&entry);
        assert_eq!(cmds, vec!["ptuf hook cursor".to_string()]);
    }

    #[test]
    fn entry_commands_returns_empty_when_no_command_field() {
        let entry = json!({ "type": "command", "timeout": 10 });
        assert!(entry_commands(&entry).is_empty());
    }

    #[test]
    fn pre_tool_use_commands_returns_empty_when_array_missing() {
        let root = json!({ "version": 1 });
        assert!(pre_tool_use_commands(&root).is_empty());
    }

    #[test]
    fn append_hook_rejects_non_object_root_directly() {
        let mut root = json!([]);
        let path = Path::new("dummy.json");
        let err = append_hook(&mut root, path, "ptuf hook cursor").unwrap_err();
        assert!(matches!(err, InitError::Schema { .. }));
    }

    #[test]
    fn install_returns_io_error_when_hooks_path_is_a_directory() {
        let dir = workdir("hooks-is-dir");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join("hooks-as-dir"),
        };
        fs::create_dir_all(&targets.hooks_path).unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Io { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_writes_hooks_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workdir("perm-cursor");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let targets =
            resolve_paths_with(Some(dir.as_path()), None, &CursorInitOptions::default()).unwrap();
        install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        let mode = fs::metadata(&targets.hooks_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "fresh hooks JSON must be owner-only");
        let _ = fs::remove_dir_all(&dir);
    }
}
