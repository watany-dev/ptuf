//! `ptuf init copilot` — idempotently register a `preToolUse` hook in
//! GitHub Copilot's repo-local `.github/hooks/ptuf.json` file.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

/// Matcher recorded in [`InstallOutcome`] for the rendered summary.
/// Copilot's preToolUse hook does not actually use a regex matcher —
/// the matching is implicit via tool name passed in stdin — but we
/// surface a stable string here so the `render_install_outcome`
/// formatter has something descriptive to show.
pub const DEFAULT_MATCHER: &str = "*";

/// Default repo-relative path for the Copilot hook file.
pub const DEFAULT_HOOKS_PATH: &str = ".github/hooks/ptuf.json";

/// Default timeout we record on the hook entry. Copilot may abort the
/// tool call if the hook does not respond within this many seconds.
pub const DEFAULT_TIMEOUT_SEC: u64 = 10;

/// Trailing tokens (split on whitespace) that mark a `bash` /
/// `powershell` command field as a ptuf Copilot `preToolUse` hook.
pub(crate) const COMMAND_TAIL: &[&str] = &["hook", "copilot"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPaths {
    pub root: PathBuf,
    pub hooks_path: PathBuf,
}

/// Try `std::env::current_exe()`. Falls back to the literal `"ptuf"`.
pub fn detect_binary() -> String {
    super::detect_binary_impl()
}

/// Resolve `<repo>/.github/hooks/ptuf.json` from the discovered repo
/// root. Returns [`InitError::RepoRootNotFound`] when the caller is not
/// inside a git working tree.
pub fn resolve_paths(start: Option<&Path>) -> Result<TargetPaths, InitError> {
    let root = start
        .and_then(crate::config::repo::discover)
        .ok_or(InitError::RepoRootNotFound)?;
    let hooks_path = root.join(DEFAULT_HOOKS_PATH);
    Ok(TargetPaths { root, hooks_path })
}

pub fn install(
    targets: &TargetPaths,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} hook copilot");
    let mut root = read_hooks(&targets.hooks_path)?;

    let already_present = has_existing_hook(&root);
    let status = if already_present {
        InstallStatus::AlreadyPresent
    } else {
        ensure_version(&mut root, &targets.hooks_path)?;
        append_hook(&mut root, &targets.hooks_path, &command)?;
        if dry_run {
            InstallStatus::WouldInstall
        } else {
            write_json_atomically(&targets.hooks_path, &root)?;
            InstallStatus::Installed
        }
    };

    Ok(InstallOutcome {
        status,
        agent: "copilot",
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
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let n = tokens.len();
    if n < COMMAND_TAIL.len() {
        return false;
    }
    tokens[n - COMMAND_TAIL.len()..] == *COMMAND_TAIL
}

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

/// Extract every command-string field from a Copilot hook entry. Both
/// `bash` and `powershell` fields are inspected because verify must
/// accept either as evidence of an installed hook.
pub(crate) fn entry_commands(entry: &Value) -> Vec<String> {
    let mut commands = Vec::new();
    if let Some(s) = entry.get("bash").and_then(Value::as_str) {
        commands.push(s.to_string());
    }
    if let Some(s) = entry.get("powershell").and_then(Value::as_str) {
        commands.push(s.to_string());
    }
    commands
}

fn has_existing_hook(root: &Value) -> bool {
    pre_tool_use_commands(root)
        .iter()
        .any(|cmd| command_invokes_ptuf_hook(cmd))
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
        "bash": command,
        "powershell": command,
        "timeoutSec": DEFAULT_TIMEOUT_SEC,
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
    super::sibling_install_tmp_path(path, "ptuf.json")
}

#[cfg(test)]
mod tests {

    use super::*;

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-init-copilot-{}-{}-{}",
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
    fn resolve_paths_requires_repo_root() {
        let err = resolve_paths(None).unwrap_err();
        assert!(matches!(err, InitError::RepoRootNotFound));
    }

    #[test]
    fn installs_missing_hooks_file() {
        let dir = workdir("install");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".github/hooks/ptuf.json"),
        };
        let outcome = install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = read(&targets.hooks_path);
        assert!(body.contains("\"preToolUse\""));
        assert!(body.contains("/usr/local/bin/ptuf hook copilot"));
        assert!(body.contains("\"timeoutSec\": 10"));
        assert!(body.contains("\"version\": 1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_idempotent_when_hook_already_exists() {
        let dir = workdir("idempotent");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".github/hooks/ptuf.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.hooks_path,
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "hooks": {
                    "preToolUse": [{
                        "bash": "/x/ptuf hook copilot",
                        "powershell": "/x/ptuf hook copilot",
                        "timeoutSec": 10,
                    }],
                },
            }))
            .unwrap(),
        )
        .unwrap();
        let before = read(&targets.hooks_path);
        let outcome = install(&targets, "/y/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(before, read(&targets.hooks_path));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_reports_changes_without_writing() {
        let dir = workdir("dry-run");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".github/hooks/ptuf.json"),
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
            hooks_path: dir.join(".github/hooks/ptuf.json"),
        };
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        let preset = json!({
            "version": 1,
            "hooks": {
                "preToolUse": [{
                    "bash": "/usr/bin/something-else",
                    "timeoutSec": 5,
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
            hooks_path: dir.join(".github/hooks/ptuf.json"),
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
            hooks_path: dir.join(".github/hooks/ptuf.json"),
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
            hooks_path: dir.join(".github/hooks/ptuf.json"),
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
            hooks_path: dir.join(".github/hooks/ptuf.json"),
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
            hooks_path: dir.join(".github/hooks/ptuf.json"),
        };
        let before = "{not json";
        fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        fs::write(&targets.hooks_path, before).unwrap();
        let _ = install(&targets, "/x/ptuf", false);
        let after = fs::read_to_string(&targets.hooks_path).unwrap();
        assert_eq!(after, before, "ptuf.json was modified despite Err");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_top_level_is_not_object() {
        let dir = workdir("non-object");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".github/hooks/ptuf.json"),
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
            hooks_path: dir.join(".github/hooks/ptuf.json"),
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
            hooks_path: dir.join(".github/hooks/ptuf.json"),
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
    fn install_reports_io_error_when_hooks_path_is_a_directory() {
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

    #[test]
    fn empty_hooks_file_is_treated_as_empty_object() {
        let dir = workdir("empty-hooks");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".github/hooks/ptuf.json"),
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
        assert!(command_invokes_ptuf_hook("/x/ptuf hook copilot"));
        assert!(command_invokes_ptuf_hook("ptuf hook copilot   "));
        assert!(!command_invokes_ptuf_hook("ptuf hook codex"));
        assert!(!command_invokes_ptuf_hook("ptuf"));
    }

    #[test]
    fn entry_commands_collects_bash_and_powershell() {
        let entry = json!({
            "bash": "ptuf hook copilot",
            "powershell": "ptuf hook copilot",
            "timeoutSec": 10,
        });
        let cmds = entry_commands(&entry);
        assert_eq!(cmds.len(), 2);
    }

    #[test]
    fn entry_commands_returns_empty_when_no_command_fields() {
        let entry = json!({ "timeoutSec": 10 });
        assert!(entry_commands(&entry).is_empty());
    }

    #[test]
    fn pre_tool_use_commands_returns_empty_when_array_missing() {
        let root = json!({ "version": 1 });
        assert!(pre_tool_use_commands(&root).is_empty());
    }

    #[test]
    fn sibling_temp_path_uses_default_filename_when_input_has_none() {
        let p = Path::new("/");
        let tmp = sibling_temp_path(p);
        assert!(
            tmp.to_string_lossy().contains("ptuf.json.ptuf."),
            "missing file_name must default to ptuf.json: {tmp:?}"
        );
    }

    #[test]
    fn install_returns_io_error_when_parent_directory_cannot_be_created() {
        let dir = workdir("io-parent");
        let blocker = dir.join("blocker");
        fs::write(&blocker, "not a directory").unwrap();
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: blocker.join("ptuf.json"),
        };
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(
            matches!(err, InitError::Io { .. }),
            "expected IO error when parent path is a regular file, got: {err:?}",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_hook_rejects_non_object_root_directly() {
        // ensure_version catches non-objects before append_hook in the normal
        // install flow, so we call append_hook directly to reach the
        // ok_or_else closure body.
        let mut root = json!([]);
        let path = Path::new("dummy.json");
        let err = append_hook(&mut root, path, "ptuf hook copilot").unwrap_err();
        assert!(matches!(err, InitError::Schema { .. }));
    }

    #[test]
    fn install_returns_schema_error_when_hooks_file_is_non_object_json() {
        let dir = workdir("schema-non-object");
        let targets = TargetPaths {
            root: dir.clone(),
            hooks_path: dir.join(".github/hooks/ptuf.json"),
        };
        std::fs::create_dir_all(targets.hooks_path.parent().unwrap()).unwrap();
        // Valid JSON but not a JSON object — triggers the append_hook
        // schema error path (lines 166-168).
        fs::write(&targets.hooks_path, r#""not-an-object""#).unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(
            matches!(err, InitError::Schema { .. }),
            "expected Schema error for non-object JSON, got: {err:?}",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_writes_hooks_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workdir("perm-copilot");
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::create_dir_all(dir.join(".github")).unwrap();
        let targets = resolve_paths(Some(dir.as_path())).unwrap();
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
