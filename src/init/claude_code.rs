//! `ptuf init claude-code` — idempotently register a `PreToolUse` hook
//! entry in `~/.claude/settings.json`
//! (`docs/design/cli-and-hooks.md:48-74`).
//!
//! The strategy is conservative: parse the existing settings as a
//! `serde_json::Value` so unknown keys round-trip, look for any
//! `hooks.PreToolUse[].hooks[].command` whose tail matches our hook
//! invocation, and only append a new matcher entry when no such hook
//! already exists. Writes go through an atomic temp + rename so a
//! crash can never leave a half-written `settings.json`.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::{InitError, InstallOutcome, InstallStatus};

/// Matcher we install in the new entry — covers every tool ptuf can
/// actually evaluate plus all MCP tools.
pub const DEFAULT_MATCHER: &str = "Bash|Read|Edit|Write|WebFetch|mcp__.*";

/// Trailing tokens (split on whitespace) that mark a `command` field
/// as a ptuf PreToolUse hook. We compare token-by-token instead of
/// checking a string suffix so we don't depend on the on-disk
/// binary name (e.g. test binaries are named `ptuf-<hash>`).
pub(crate) const COMMAND_TAIL: &[&str] = &["hook", "claude-code", "pre-tool-use"];

/// Default settings file path (`$HOME/.claude/settings.json`). Returns
/// `None` when `$HOME` is unset; callers should map that to
/// [`InitError::HomeNotSet`].
pub fn default_settings_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".claude/settings.json"))
}

/// Try `std::env::current_exe()`. Falls back to the literal `"ptuf"`
/// so the resulting hook entry is still useful when invoked from a
/// CI container without a stable absolute path.
pub fn detect_binary() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| "ptuf".to_string())
}

/// Install (or report a planned install for `dry_run = true`) the
/// Claude Code PreToolUse hook entry.
pub fn install(
    settings_path: &Path,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} hook claude-code pre-tool-use");
    let mut root = read_settings(settings_path)?;

    if has_existing_hook(&root) {
        return Ok(InstallOutcome {
            status: InstallStatus::AlreadyPresent,
            settings_path: settings_path.to_path_buf(),
            matcher: DEFAULT_MATCHER.to_string(),
            command,
        });
    }

    append_hook(&mut root, settings_path, &command)?;

    if dry_run {
        return Ok(InstallOutcome {
            status: InstallStatus::WouldInstall,
            settings_path: settings_path.to_path_buf(),
            matcher: DEFAULT_MATCHER.to_string(),
            command,
        });
    }

    write_atomically(settings_path, &root)?;

    Ok(InstallOutcome {
        status: InstallStatus::Installed,
        settings_path: settings_path.to_path_buf(),
        matcher: DEFAULT_MATCHER.to_string(),
        command,
    })
}

fn read_settings(path: &Path) -> Result<Value, InitError> {
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

fn has_existing_hook(root: &Value) -> bool {
    pre_tool_use_commands(root)
        .iter()
        .any(|cmd| command_invokes_ptuf_hook(cmd))
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

fn append_hook(root: &mut Value, settings_path: &Path, command: &str) -> Result<(), InitError> {
    if !root.is_object() {
        return Err(InitError::Schema {
            path: settings_path.to_path_buf(),
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
            path: settings_path.to_path_buf(),
            message: "`hooks` must be an object".into(),
        })?;

    let pre_tool_use = hooks
        .entry("PreToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| InitError::Schema {
            path: settings_path.to_path_buf(),
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

fn write_atomically(path: &Path, value: &Value) -> Result<(), InitError> {
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

fn sibling_temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("settings.json"));
    name.push(format!(".ptuf.{}.tmp", std::process::id()));
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-init-{}-{}-{}",
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
    fn installs_into_missing_file_and_creates_parent_dir() {
        let dir = workdir("missing");
        let path = dir.join("nested/settings.json");
        let outcome = install(&path, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = read(&path);
        assert!(body.contains("\"PreToolUse\""));
        assert!(body.contains(DEFAULT_MATCHER));
        assert!(body.contains("/usr/local/bin/ptuf hook claude-code pre-tool-use"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_idempotent_when_entry_exists() {
        let dir = workdir("idempotent");
        let path = dir.join("settings.json");
        let preset = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "/some/where/ptuf hook claude-code pre-tool-use" }
                        ]
                    }
                ]
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&preset).unwrap()).unwrap();
        let before = read(&path);
        let outcome = install(&path, "/different/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(before, read(&path), "file must not have been rewritten");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_appends_when_a_different_matcher_already_exists() {
        let dir = workdir("append");
        let path = dir.join("settings.json");
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
        fs::write(&path, serde_json::to_string_pretty(&preset).unwrap()).unwrap();
        let outcome = install(&path, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&path)).unwrap();
        let arr = after
            .pointer("/hooks/PreToolUse")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(arr.len(), 2, "existing entry preserved, ours appended");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_invalid_json_without_overwriting() {
        let dir = workdir("bad-json");
        let path = dir.join("settings.json");
        fs::write(&path, "{not json").unwrap();
        let err = install(&path, "/x/ptuf", false).unwrap_err();
        match err {
            InitError::Json { .. } => {}
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(read(&path), "{not json", "file untouched");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_top_level_is_not_object() {
        let dir = workdir("non-object");
        let path = dir.join("settings.json");
        fs::write(&path, "[]").unwrap();
        let err = install(&path, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Schema { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_pre_tool_use_is_wrong_type() {
        let dir = workdir("wrong-type");
        let path = dir.join("settings.json");
        fs::write(&path, r#"{"hooks": {"PreToolUse": "not-an-array"}}"#).unwrap();
        let err = install(&path, "/x/ptuf", false).unwrap_err();
        match err {
            InitError::Schema { message, .. } => {
                assert!(message.contains("PreToolUse"), "got: {message}");
            }
            other => panic!("unexpected: {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_hooks_value_is_wrong_type() {
        let dir = workdir("hooks-wrong-type");
        let path = dir.join("settings.json");
        fs::write(&path, r#"{"hooks": 42}"#).unwrap();
        let err = install(&path, "/x/ptuf", false).unwrap_err();
        match err {
            InitError::Schema { message, .. } => {
                assert!(message.contains("hooks"), "got: {message}");
            }
            other => panic!("unexpected: {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_does_not_write_when_install_would_happen() {
        let dir = workdir("dry-run-install");
        let path = dir.join("settings.json");
        let outcome = install(&path, "/usr/local/bin/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!path.exists(), "dry-run must not create file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_reports_already_present_without_writing() {
        let dir = workdir("dry-run-present");
        let path = dir.join("settings.json");
        let preset = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "/x/ptuf hook claude-code pre-tool-use" }
                        ]
                    }
                ]
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&preset).unwrap()).unwrap();
        let before = read(&path);
        let outcome = install(&path, "/y/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(before, read(&path));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_file_is_treated_as_empty_object() {
        let dir = workdir("empty-file");
        let path = dir.join("settings.json");
        fs::write(&path, "").unwrap();
        let outcome = install(&path, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&path)).unwrap();
        assert!(after.pointer("/hooks/PreToolUse").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_binary_returns_a_non_empty_string() {
        let s = detect_binary();
        assert!(!s.is_empty());
    }

    #[test]
    fn default_settings_path_ends_with_claude_settings_when_home_is_set() {
        if let Some(path) = default_settings_path() {
            assert!(path.ends_with(".claude/settings.json"));
        }
        // We cannot mutate $HOME under #![forbid(unsafe_code)]; the
        // None branch is exercised via the CLI integration test below
        // by passing a preset settings path directly.
    }

    #[test]
    fn already_present_detection_ignores_unrelated_command_strings() {
        let dir = workdir("unrelated-cmd");
        let path = dir.join("settings.json");
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
        fs::write(&path, serde_json::to_string_pretty(&preset).unwrap()).unwrap();
        let outcome = install(&path, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&path)).unwrap();
        let arr = after
            .pointer("/hooks/PreToolUse")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(arr.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn already_present_detection_handles_command_with_trailing_whitespace() {
        let dir = workdir("trailing-ws");
        let path = dir.join("settings.json");
        let preset = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "/x/ptuf hook claude-code pre-tool-use   " }
                        ]
                    }
                ]
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&preset).unwrap()).unwrap();
        let outcome = install(&path, "/y/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn entry_commands_returns_empty_when_hooks_key_is_missing() {
        // The `Some(hooks) = entry.get("hooks").and_then(as_array) else
        // { return Vec::new(); }` early-return arm is otherwise only
        // reachable through full settings parsing.
        let entry = json!({ "matcher": "Bash" });
        assert!(entry_commands(&entry).is_empty());
    }

    #[test]
    fn entry_commands_returns_empty_when_hooks_is_not_an_array() {
        let entry = json!({ "matcher": "Bash", "hooks": "not-an-array" });
        assert!(entry_commands(&entry).is_empty());
    }

    #[test]
    fn command_executable_returns_first_token_or_none() {
        assert_eq!(command_executable("/x/ptuf hook"), Some("/x/ptuf"));
        assert_eq!(command_executable(""), None);
    }

    #[test]
    fn read_settings_reports_io_error_when_path_is_a_directory() {
        // Reading a directory as a file produces an IoError that is
        // not NotFound — exercises the Err arm of read_settings.
        let dir = workdir("read-dir-as-file");
        let err = install(&dir, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Io { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_preserves_unknown_keys_in_settings() {
        let dir = workdir("preserve-keys");
        let path = dir.join("settings.json");
        let preset = json!({
            "model": "claude-opus-4-7",
            "extras": { "deep": { "value": 42 } }
        });
        fs::write(&path, serde_json::to_string_pretty(&preset).unwrap()).unwrap();
        install(&path, "/usr/local/bin/ptuf", false).unwrap();
        let after: Value = serde_json::from_str(&read(&path)).unwrap();
        assert_eq!(
            after.get("model").and_then(Value::as_str),
            Some("claude-opus-4-7")
        );
        assert_eq!(
            after.pointer("/extras/deep/value").and_then(Value::as_i64),
            Some(42)
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
