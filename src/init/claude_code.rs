//! `ptuf init claude-code` — idempotently register a `PreToolUse` hook
//! entry in `~/.claude/settings.json`
//! (`docs/design/cli-and-hooks.md:48-74`).
//!
//! The strategy is conservative: parse the existing settings as a
//! `serde_json::Value` so unknown keys round-trip, look for any
//! `hooks.PreToolUse[].hooks[]` payload carrying ptuf's stable marker
//! (or an older command tail-only entry), and only append a new matcher
//! entry when no such hook already exists. Writes go through an atomic
//! temp + rename so a crash can never leave a half-written
//! `settings.json`.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::json;
use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

/// Basename used for the sibling temp file when the destination path
/// carries no file name of its own (see
/// [`sibling_install_tmp_path`](super::sibling_install_tmp_path)).
const TMP_BASENAME: &str = "settings.json";

/// Matcher we install in the new entry — covers every tool ptuf can
/// actually evaluate plus all MCP tools.
pub const DEFAULT_MATCHER: &str = "Bash|Read|Edit|Write|WebFetch|mcp__.*";

/// Stable marker written into hook payloads so future command-line flag
/// changes do not affect idempotency detection.
pub(crate) const HOOK_NAME: &str = "ptuf";

/// Trailing tokens (split on whitespace) that mark a `command` field
/// as a ptuf PreToolUse hook. We compare token-by-token instead of
/// checking a string suffix so we don't depend on the on-disk
/// binary name (e.g. test binaries are named `ptuf-<hash>`).
pub(crate) const COMMAND_TAIL: &[&str] = &["hook", "claude-code"];

/// Default settings file path (`$HOME/.claude/settings.json`). Returns
/// `None` when `$HOME` is unset; callers should map that to
/// [`InitError::HomeNotSet`].
pub fn default_settings_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".claude/settings.json"))
}

/// Install (or report a planned install for `dry_run = true`) the
/// Claude Code PreToolUse hook entry.
pub fn install(
    settings_path: &Path,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} hook claude-code");
    let mut root = json::read_object(settings_path)?;

    if has_existing_hook(&root) {
        return Ok(InstallOutcome {
            status: InstallStatus::AlreadyPresent,
            agent: "claude-code",
            paths: vec![InstallPath {
                label: "settings",
                path: settings_path.to_path_buf(),
            }],
            matcher: DEFAULT_MATCHER.to_string(),
            command,
        });
    }

    append_hook(&mut root, settings_path, &command)?;

    if dry_run {
        return Ok(InstallOutcome {
            status: InstallStatus::WouldInstall,
            agent: "claude-code",
            paths: vec![InstallPath {
                label: "settings",
                path: settings_path.to_path_buf(),
            }],
            matcher: DEFAULT_MATCHER.to_string(),
            command,
        });
    }

    super::write_install_json(settings_path, &root, TMP_BASENAME)?;

    Ok(InstallOutcome {
        status: InstallStatus::Installed,
        agent: "claude-code",
        paths: vec![InstallPath {
            label: "settings",
            path: settings_path.to_path_buf(),
        }],
        matcher: DEFAULT_MATCHER.to_string(),
        command,
    })
}

fn has_existing_hook(root: &Value) -> bool {
    pre_tool_use_hooks(root).into_iter().any(hook_invokes_ptuf)
}

fn hook_invokes_ptuf(hook: &Value) -> bool {
    hook.get("name").and_then(Value::as_str) == Some(HOOK_NAME)
        || hook
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(command_invokes_ptuf_hook)
}

pub(crate) fn command_invokes_ptuf_hook(cmd: &str) -> bool {
    super::command_invokes_ptuf_hook(cmd, COMMAND_TAIL)
}

pub(crate) fn pre_tool_use_commands(root: &Value) -> Vec<String> {
    pre_tool_use_hooks(root)
        .iter()
        .filter_map(|hook| hook.get("command").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

pub(crate) fn pre_tool_use_hooks(root: &Value) -> Vec<&Value> {
    let Some(arr) = root.pointer("/hooks/PreToolUse").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut hooks = Vec::new();
    for entry in arr {
        hooks.extend(entry_hooks(entry));
    }
    hooks
}

pub(crate) fn entry_hooks(entry: &Value) -> Vec<&Value> {
    let Some(hooks) = entry.get("hooks").and_then(Value::as_array) else {
        return Vec::new();
    };
    hooks.iter().collect()
}

fn append_hook(root: &mut Value, settings_path: &Path, command: &str) -> Result<(), InitError> {
    json::hook_array(root, settings_path, "PreToolUse")?.push(json!({
        "matcher": DEFAULT_MATCHER,
        "hooks": [{
            "name": HOOK_NAME,
            "type": "command",
            "command": command,
        }],
    }));
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::fs;

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
        assert!(body.contains("\"name\": \"ptuf\""));
        assert!(body.contains("/usr/local/bin/ptuf hook claude-code"));
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
                            { "type": "command", "command": "/some/where/ptuf hook claude-code" }
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
    fn install_is_idempotent_when_ptuf_marker_exists() {
        let dir = workdir("idempotent-marker");
        let path = dir.join("settings.json");
        let preset = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "name": HOOK_NAME,
                                "type": "command",
                                "command": "/some/where/ptuf hook claude-code --future-flag"
                            }
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
            InitError::Json { .. } => {},
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
            },
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
            },
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
                            { "type": "command", "command": "/x/ptuf hook claude-code" }
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
                            { "type": "command", "command": "/x/ptuf hook claude-code   " }
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
    fn entry_hooks_returns_empty_when_hooks_key_is_missing() {
        let entry = json!({ "matcher": "Bash" });
        assert!(entry_hooks(&entry).is_empty());
    }

    #[test]
    fn entry_hooks_returns_empty_when_hooks_is_not_an_array() {
        let entry = json!({ "matcher": "Bash", "hooks": "not-an-array" });
        assert!(entry_hooks(&entry).is_empty());
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

    #[test]
    fn install_returns_io_err_when_parent_is_a_regular_file() {
        let dir = workdir("parent-blocker");
        let blocker = dir.join("blocker");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("settings.json");
        let err = install(&path, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Io { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_writes_settings_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workdir("perm-fresh");
        let path = dir.join("settings.json");
        install(&path, "/usr/local/bin/ptuf", false).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "fresh settings.json must be owner-only");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_tightens_mode_when_existing_file_was_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workdir("perm-tighten");
        let path = dir.join("settings.json");
        fs::write(&path, "{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        install(&path, "/usr/local/bin/ptuf", false).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "re-install must tighten an existing 0644 file");
        let _ = fs::remove_dir_all(&dir);
    }
}
