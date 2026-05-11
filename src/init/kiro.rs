//! `ptuf init kiro` — idempotently register a `preToolUse` hook entry
//! in a Kiro CLI agent config (`<repo>/.kiro/agents/<name>.json` when
//! the caller is inside a repo, otherwise `$HOME/.kiro/agents/<name>.json`).
//!
//! The Kiro agent file is a JSON document whose `hooks.preToolUse`
//! array carries `{matcher, command, timeout_ms, cache_ttl_seconds}`
//! entries. We append a single entry whose `command` invokes `<ptuf>
//! hook kiro`, leaving every other field of the file untouched. A
//! second invocation detects the existing entry by matching the
//! trailing `["hook", "kiro"]` tokens of `command` and returns
//! [`InstallStatus::AlreadyPresent`] without rewriting the file.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

/// Default Kiro agent name. Mirrors the agent file's `name` field and
/// the file stem (`<name>.json`).
pub const DEFAULT_AGENT_NAME: &str = "ptuf-guarded";

/// Matcher recorded in [`InstallOutcome`] and in the appended hook entry.
pub const DEFAULT_MATCHER: &str = "*";

/// Default timeout the hook entry advertises to Kiro. Kiro may abort
/// the tool call if ptuf does not respond within this many ms.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// Default cache TTL in seconds. `0` disables caching so every
/// PreToolUse event is re-evaluated by ptuf.
pub const DEFAULT_CACHE_TTL_SECONDS: u64 = 0;

/// Trailing tokens (split on whitespace) that mark a `command` field as
/// a ptuf Kiro `preToolUse` hook.
pub(crate) const COMMAND_TAIL: &[&str] = &["hook", "kiro"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPaths {
    pub agent_config_path: PathBuf,
}

/// Try `std::env::current_exe()`. Falls back to the literal `"ptuf"`.
pub fn detect_binary() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| "ptuf".to_string())
}

/// Resolve the agent-config path Kiro should be configured against.
///
/// Prefers the repo-local `<repo>/.kiro/agents/ptuf-guarded.json` when
/// the caller is inside a git working tree; otherwise falls back to
/// `$HOME/.kiro/agents/ptuf-guarded.json`. Returns
/// [`InitError::RepoRootNotFound`] when neither is available.
pub fn resolve_paths(start: Option<&Path>) -> Result<TargetPaths, InitError> {
    let file_name = format!("{DEFAULT_AGENT_NAME}.json");
    if let Some(root) = start.and_then(crate::config::repo::discover) {
        return Ok(TargetPaths {
            agent_config_path: root.join(".kiro/agents").join(&file_name),
        });
    }
    let home = std::env::var_os("HOME").ok_or(InitError::RepoRootNotFound)?;
    Ok(TargetPaths {
        agent_config_path: PathBuf::from(home).join(".kiro/agents").join(&file_name),
    })
}

pub fn install(
    targets: &TargetPaths,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} hook kiro");
    let mut root = read_agent_config(&targets.agent_config_path)?;

    let already_present = has_existing_hook(&root);
    let status = if already_present {
        InstallStatus::AlreadyPresent
    } else {
        append_hook(&mut root, &targets.agent_config_path, &command)?;
        if dry_run {
            InstallStatus::WouldInstall
        } else {
            write_json_atomically(&targets.agent_config_path, &root)?;
            InstallStatus::Installed
        }
    };

    Ok(InstallOutcome {
        status,
        agent: "kiro",
        paths: vec![InstallPath {
            label: "agent",
            path: targets.agent_config_path.clone(),
        }],
        matcher: DEFAULT_MATCHER.to_string(),
        command,
    })
}

/// Read the agent config from disk, or build a fresh default skeleton
/// when the file is missing / empty.
fn read_agent_config(path: &Path) -> Result<Value, InitError> {
    match fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(default_agent_skeleton()),
        Ok(s) => serde_json::from_str(&s).map_err(|e| InitError::Json {
            path: path.to_path_buf(),
            message: e.to_string(),
        }),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(default_agent_skeleton()),
        Err(e) => Err(InitError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

/// Default JSON skeleton written when no agent config exists yet.
fn default_agent_skeleton() -> Value {
    json!({
        "name": DEFAULT_AGENT_NAME,
        "description": "Kiro CLI agent guarded by ptuf PreToolUse policy.",
        "tools": ["*"],
        "includeMcpJson": true,
    })
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

pub(crate) fn command_invokes_ptuf_hook(cmd: &str) -> bool {
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let n = tokens.len();
    if n < COMMAND_TAIL.len() {
        return false;
    }
    tokens[n - COMMAND_TAIL.len()..] == *COMMAND_TAIL
}

/// Read the single `command` field on a Kiro `preToolUse` entry. The
/// helper exists for symmetry with the other adapters.
pub(crate) fn entry_commands(entry: &Value) -> Vec<String> {
    entry
        .get("command")
        .and_then(Value::as_str)
        .map(|s| vec![s.to_string()])
        .unwrap_or_default()
}

fn has_existing_hook(root: &Value) -> bool {
    root.pointer("/hooks/preToolUse")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(entry_commands)
        .any(|cmd| command_invokes_ptuf_hook(&cmd))
}

fn append_hook(root: &mut Value, agent_path: &Path, command: &str) -> Result<(), InitError> {
    let Some(map) = root.as_object_mut() else {
        return Err(InitError::Schema {
            path: agent_path.to_path_buf(),
            message: "top-level value must be a JSON object".into(),
        });
    };

    let hooks = ensure_object(map, "hooks").ok_or_else(|| InitError::Schema {
        path: agent_path.to_path_buf(),
        message: "`hooks` must be an object".into(),
    })?;

    let pre_tool_use = ensure_array(hooks, "preToolUse").ok_or_else(|| InitError::Schema {
        path: agent_path.to_path_buf(),
        message: "`hooks.preToolUse` must be an array".into(),
    })?;

    pre_tool_use.push(json!({
        "matcher": DEFAULT_MATCHER,
        "command": command,
        "timeout_ms": DEFAULT_TIMEOUT_MS,
        "cache_ttl_seconds": DEFAULT_CACHE_TTL_SECONDS,
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
    let mut name = path.file_name().map_or_else(
        || std::ffi::OsString::from("agent.json"),
        std::ffi::OsStr::to_os_string,
    );
    name.push(format!(".ptuf.{}.tmp", std::process::id()));
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-init-kiro-{}-{}-{}",
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
    fn install_creates_new_local_config_with_default_template() {
        let dir = workdir("install-local");
        let targets = TargetPaths {
            agent_config_path: dir.join(".kiro/agents/ptuf-guarded.json"),
        };
        let outcome = install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = read(&targets.agent_config_path);
        assert!(body.contains("\"name\": \"ptuf-guarded\""));
        assert!(body.contains("\"includeMcpJson\": true"));
        assert!(body.contains("/usr/local/bin/ptuf hook kiro"));
        assert!(body.contains("\"timeout_ms\": 10000"));
        assert!(body.contains("\"cache_ttl_seconds\": 0"));
        assert!(body.contains("\"matcher\": \"*\""));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_idempotent_when_ptuf_hook_already_present() {
        let dir = workdir("idempotent");
        let targets = TargetPaths {
            agent_config_path: dir.join(".kiro/agents/ptuf-guarded.json"),
        };
        fs::create_dir_all(targets.agent_config_path.parent().unwrap()).unwrap();
        let preset = json!({
            "name": "ptuf-guarded",
            "tools": ["*"],
            "hooks": {
                "preToolUse": [{
                    "matcher": "*",
                    "command": "/x/ptuf hook kiro",
                    "timeout_ms": 10_000,
                    "cache_ttl_seconds": 0,
                }],
            },
        });
        fs::write(
            &targets.agent_config_path,
            serde_json::to_string_pretty(&preset).unwrap(),
        )
        .unwrap();
        let before = read(&targets.agent_config_path);
        let outcome = install(&targets, "/y/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(before, read(&targets.agent_config_path));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_appends_when_unrelated_entry_exists() {
        let dir = workdir("append");
        let targets = TargetPaths {
            agent_config_path: dir.join(".kiro/agents/ptuf-guarded.json"),
        };
        fs::create_dir_all(targets.agent_config_path.parent().unwrap()).unwrap();
        let preset = json!({
            "name": "ptuf-guarded",
            "hooks": {
                "preToolUse": [{
                    "matcher": "*",
                    "command": "/usr/bin/something-else",
                    "timeout_ms": 5000,
                }],
            },
        });
        fs::write(
            &targets.agent_config_path,
            serde_json::to_string_pretty(&preset).unwrap(),
        )
        .unwrap();
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&targets.agent_config_path)).unwrap();
        let arr = after
            .pointer("/hooks/preToolUse")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(arr.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_preserves_unknown_top_level_keys() {
        let dir = workdir("preserve-keys");
        let targets = TargetPaths {
            agent_config_path: dir.join(".kiro/agents/ptuf-guarded.json"),
        };
        fs::create_dir_all(targets.agent_config_path.parent().unwrap()).unwrap();
        let preset = json!({
            "name": "ptuf-guarded",
            "model": "claude-sonnet-4-6",
            "temperature": 0.2,
            "extras": { "deep": { "value": 42 } },
        });
        fs::write(
            &targets.agent_config_path,
            serde_json::to_string_pretty(&preset).unwrap(),
        )
        .unwrap();
        install(&targets, "/x/ptuf", false).unwrap();
        let after: Value = serde_json::from_str(&read(&targets.agent_config_path)).unwrap();
        assert_eq!(
            after.get("model").and_then(Value::as_str),
            Some("claude-sonnet-4-6")
        );
        assert_eq!(
            after.pointer("/extras/deep/value").and_then(Value::as_i64),
            Some(42)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_returns_would_install_without_creating_file() {
        let dir = workdir("dry-run");
        let targets = TargetPaths {
            agent_config_path: dir.join(".kiro/agents/ptuf-guarded.json"),
        };
        let outcome = install(&targets, "/usr/local/bin/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!targets.agent_config_path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_returns_init_error_json_for_invalid_file() {
        let dir = workdir("bad-json");
        let targets = TargetPaths {
            agent_config_path: dir.join(".kiro/agents/ptuf-guarded.json"),
        };
        fs::create_dir_all(targets.agent_config_path.parent().unwrap()).unwrap();
        let before = "{not json";
        fs::write(&targets.agent_config_path, before).unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Json { .. }));
        let after = fs::read_to_string(&targets.agent_config_path).unwrap();
        assert_eq!(after, before, "agent config was modified despite Err");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_top_level_is_not_object() {
        let dir = workdir("non-object");
        let targets = TargetPaths {
            agent_config_path: dir.join(".kiro/agents/ptuf-guarded.json"),
        };
        fs::create_dir_all(targets.agent_config_path.parent().unwrap()).unwrap();
        fs::write(&targets.agent_config_path, "[]").unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Schema { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_hooks_is_wrong_type() {
        let dir = workdir("hooks-wrong-type");
        let targets = TargetPaths {
            agent_config_path: dir.join(".kiro/agents/ptuf-guarded.json"),
        };
        fs::create_dir_all(targets.agent_config_path.parent().unwrap()).unwrap();
        fs::write(&targets.agent_config_path, r#"{"name": "x", "hooks": 42}"#).unwrap();
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
        let dir = workdir("pretool-wrong-type");
        let targets = TargetPaths {
            agent_config_path: dir.join(".kiro/agents/ptuf-guarded.json"),
        };
        fs::create_dir_all(targets.agent_config_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.agent_config_path,
            r#"{"name": "x", "hooks": {"preToolUse": "nope"}}"#,
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
    fn empty_file_is_treated_as_default_skeleton() {
        let dir = workdir("empty");
        let targets = TargetPaths {
            agent_config_path: dir.join(".kiro/agents/ptuf-guarded.json"),
        };
        fs::create_dir_all(targets.agent_config_path.parent().unwrap()).unwrap();
        fs::write(&targets.agent_config_path, "").unwrap();
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&targets.agent_config_path)).unwrap();
        assert_eq!(
            after.get("name").and_then(Value::as_str),
            Some("ptuf-guarded")
        );
        assert!(after.pointer("/hooks/preToolUse").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_reports_io_error_when_path_is_a_directory() {
        let dir = workdir("path-is-dir");
        let targets = TargetPaths {
            agent_config_path: dir.join("agent-as-dir"),
        };
        fs::create_dir_all(&targets.agent_config_path).unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Io { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn command_invokes_ptuf_hook_matches_trailing_tokens() {
        assert!(command_invokes_ptuf_hook("/x/ptuf hook kiro"));
        assert!(command_invokes_ptuf_hook("ptuf hook kiro   "));
        assert!(!command_invokes_ptuf_hook("ptuf hook codex"));
        assert!(!command_invokes_ptuf_hook("ptuf"));
    }

    #[test]
    fn detect_binary_returns_a_non_empty_string() {
        assert!(!detect_binary().is_empty());
    }

    #[test]
    fn sibling_temp_path_uses_default_filename_when_input_has_none() {
        let p = Path::new("/");
        let tmp = sibling_temp_path(p);
        assert!(
            tmp.to_string_lossy().contains("agent.json.ptuf."),
            "missing file_name must default to agent.json: {tmp:?}"
        );
    }

    #[test]
    fn sibling_temp_path_falls_back_to_bare_filename_when_no_parent() {
        let bare = Path::new("agent.json");
        let tmp = sibling_temp_path(bare);
        assert!(
            tmp.parent()
                .map(Path::as_os_str)
                .unwrap_or_default()
                .is_empty(),
            "no-parent input must yield no-parent temp path: {tmp:?}"
        );
        assert!(tmp.to_string_lossy().contains("agent.json.ptuf."));
    }
}
