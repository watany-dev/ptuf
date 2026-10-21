//! `ptuf init kiro-v3` — register a `PreToolUse` hook for Kiro CLI v3.
//!
//! Kiro CLI v3 loads standalone hook documents from `.kiro/hooks/*.json`
//! in the workspace and from `~/.kiro/hooks/*.json` globally; both sets
//! run side by side and apply to every agent profile
//! (<https://kiro.dev/docs/hooks/>). Each document is versioned:
//!
//! ```json
//! {
//!   "version": "v1",
//!   "hooks": [
//!     {
//!       "name": "ptuf",
//!       "trigger": "PreToolUse",
//!       "matcher": "*",
//!       "action": { "type": "command", "command": "<ptuf> hook kiro-v3" },
//!       "timeout": 30
//!     }
//!   ]
//! }
//! ```
//!
//! The adapter owns a single file, `ptuf.json`, in the selected scope:
//! `~/.kiro/hooks/ptuf.json` by default (one file guards every
//! workspace), or `<repo>/.kiro/hooks/ptuf.json` with `--scope local` /
//! `--workspace-only`. Unlike the v2 adapter it never touches agent
//! profiles, so agent JSON written by the user or by `/upgrade-agent`
//! stays as it is.
//!
//! Re-running is idempotent: an existing entry whose command ends in
//! `hook kiro-v3` (or the unversioned `hook kiro` that a hand-written
//! entry may carry) is normalised in place to the canonical entry — so a
//! disabled or retargeted ptuf hook is restored — and any other hook the
//! user put in the same file is preserved.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::json;
use super::kiro::{KiroInitOptions, ScopeFilter};
use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

/// Basename used for the sibling temp file when the destination path
/// carries no file name of its own (see
/// [`sibling_install_tmp_path`](super::sibling_install_tmp_path)).
const TMP_BASENAME: &str = "ptuf.json";

/// Directory, relative to the scope root (`<repo>` or `$HOME`), that
/// Kiro CLI v3 scans for standalone hook documents.
pub(crate) const HOOKS_DIR: &str = ".kiro/hooks";

/// File name of the hook document this adapter manages.
pub(crate) const HOOK_FILE_NAME: &str = "ptuf.json";

/// Schema version of the standalone hook document format.
pub(crate) const DOCUMENT_VERSION: &str = "v1";

/// `name` of the managed hook entry (required by the v1 schema).
pub(crate) const HOOK_NAME: &str = "ptuf";

/// Trigger name of the managed hook entry (PascalCase, as the v1 schema
/// asks for newly written documents).
pub(crate) const TRIGGER: &str = "PreToolUse";

/// Matcher written to the hook entry: the V3 wildcard selector, so every
/// built-in and MCP tool call reaches ptuf. Omitting the matcher would
/// also match everything, but Kiro logs a warning for that case.
pub(crate) const DEFAULT_MATCHER: &str = "*";

/// Command timeout in seconds. Kiro treats a timed-out hook as a
/// non-blocking failure, so this is generous compared with ptuf's
/// typical latency.
pub(crate) const DEFAULT_TIMEOUT_SEC: u64 = 30;

/// Trailing tokens of the `command` this adapter writes, and the marker
/// for an entry it already owns. Pinned to the versioned token so an
/// installed hook never drifts with the floating `kiro` alias.
pub(crate) const COMMAND_TAIL: &[&str] = &["hook", "kiro-v3"];

/// Trailing tokens of the unversioned spelling. Recognised (and
/// rewritten to [`COMMAND_TAIL`]) so a hand-written entry is not
/// duplicated.
pub(crate) const LEGACY_COMMAND_TAIL: &[&str] = &["hook", "kiro"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetPaths {
    pub hooks_path: PathBuf,
    pub label: &'static str,
}

/// Resolve the hook document for the requested scope. Reads `$HOME` from
/// the environment and delegates to [`resolve_paths_with`].
pub(crate) fn resolve_paths(
    start: Option<&Path>,
    options: &KiroInitOptions,
) -> Result<TargetPaths, InitError> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    resolve_paths_with(start, home.as_deref(), options)
}

/// `ScopeFilter::WorkspaceOnly` (`--scope local` / `--workspace-only`)
/// targets the repository discovered from `--root` or `start`; every
/// other filter targets `$HOME`. The default (`ScopeFilter::Both`) is
/// global because a single global document already guards every
/// workspace, and installing both would run ptuf twice per tool call.
pub(crate) fn resolve_paths_with(
    start: Option<&Path>,
    home: Option<&Path>,
    options: &KiroInitOptions,
) -> Result<TargetPaths, InitError> {
    match options.scope {
        ScopeFilter::WorkspaceOnly => {
            let discover_start = options.root.as_deref().or(start);
            let repo = discover_start
                .and_then(crate::config::repo::discover)
                .ok_or(InitError::RepoRootNotFound)?;
            Ok(TargetPaths {
                hooks_path: repo.join(HOOKS_DIR).join(HOOK_FILE_NAME),
                label: "workspace-hooks",
            })
        },
        ScopeFilter::GlobalOnly | ScopeFilter::Both => {
            let home = home.ok_or(InitError::HomeNotSet)?;
            Ok(TargetPaths {
                hooks_path: home.join(HOOKS_DIR).join(HOOK_FILE_NAME),
                label: "global-hooks",
            })
        },
    }
}

pub(crate) fn install(
    targets: &TargetPaths,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} {}", COMMAND_TAIL.join(" "));
    let path = &targets.hooks_path;
    let mut root = json::read_object(path)?;
    let before = root.clone();

    let hooks = document_hooks(&mut root, path)?;
    let mut found = false;
    for entry in hooks.iter_mut() {
        if entry_command(entry).is_some_and(is_ptuf_command) {
            found = true;
            *entry = canonical_entry(&command);
        }
    }
    if !found {
        hooks.push(canonical_entry(&command));
    }

    let status = if root == before {
        InstallStatus::AlreadyPresent
    } else if dry_run {
        InstallStatus::WouldInstall
    } else {
        super::write_install_json(path, &root, TMP_BASENAME)?;
        InstallStatus::Installed
    };

    Ok(InstallOutcome {
        status,
        agent: "kiro",
        paths: vec![InstallPath {
            label: targets.label,
            path: path.clone(),
        }],
        matcher: DEFAULT_MATCHER.to_string(),
        command,
    })
}

/// Validate the document envelope (`version: "v1"`, `hooks: [...]`),
/// filling in whichever of the two is missing, and return the hook
/// array. Any other `version` is a schema the installer does not know.
fn document_hooks<'a>(root: &'a mut Value, path: &Path) -> Result<&'a mut Vec<Value>, InitError> {
    let map = root
        .as_object_mut()
        .ok_or_else(|| schema(path, "top-level value must be a JSON object"))?;
    match map.get("version") {
        None => {
            map.insert("version".into(), json!(DOCUMENT_VERSION));
        },
        Some(v) if v == DOCUMENT_VERSION => {},
        Some(other) => {
            return Err(schema(
                path,
                &format!("`version` must be \"{DOCUMENT_VERSION}\" (found {other})"),
            ));
        },
    }
    json::ensure_array(map, "hooks").ok_or_else(|| schema(path, "`hooks` must be an array"))
}

fn canonical_entry(command: &str) -> Value {
    json!({
        "name": HOOK_NAME,
        "description": "ptuf PreToolUse guardrail (managed by `ptuf init kiro-v3`).",
        "trigger": TRIGGER,
        "matcher": DEFAULT_MATCHER,
        "action": { "type": "command", "command": command },
        "timeout": DEFAULT_TIMEOUT_SEC,
        "enabled": true,
    })
}

/// `action.command` of a v1 hook entry, if it is a command action.
fn entry_command(entry: &Value) -> Option<&str> {
    entry.pointer("/action/command").and_then(Value::as_str)
}

fn is_ptuf_command(cmd: &str) -> bool {
    command_invokes_ptuf_hook(cmd) || super::command_invokes_ptuf_hook(cmd, LEGACY_COMMAND_TAIL)
}

/// Whether `cmd` is a ptuf Kiro v3 hook command in the versioned form.
pub(crate) fn command_invokes_ptuf_hook(cmd: &str) -> bool {
    super::command_invokes_ptuf_hook(cmd, COMMAND_TAIL)
}

/// Commands of every `PreToolUse` command hook in a v3 hook array — a
/// standalone document's `hooks` or an agent profile's inline `hooks`
/// array. The camelCase `preToolUse` trigger is accepted too because
/// Kiro treats it as an alias.
pub(crate) fn pre_tool_use_commands(root: &Value) -> Vec<String> {
    let Some(arr) = root.get("hooks").and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter(|entry| {
            entry
                .get("trigger")
                .and_then(Value::as_str)
                .is_some_and(|t| t == TRIGGER || t == "preToolUse")
        })
        .filter_map(entry_command)
        .map(str::to_string)
        .collect()
}

fn schema(path: &Path, message: &str) -> InitError {
    InitError::Schema {
        path: path.to_path_buf(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-init-kiro-v3-{}-{}-{}",
            tag,
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    fn opts(scope: ScopeFilter) -> KiroInitOptions {
        KiroInitOptions {
            scope,
            ..KiroInitOptions::default()
        }
    }

    fn target(path: PathBuf) -> TargetPaths {
        TargetPaths {
            hooks_path: path,
            label: "global-hooks",
        }
    }

    #[test]
    fn resolve_defaults_to_global_hooks_dir() {
        let home = workdir("resolve-global");
        let t = resolve_paths_with(None, Some(&home), &opts(ScopeFilter::Both)).unwrap();
        assert_eq!(t.hooks_path, home.join(".kiro/hooks/ptuf.json"));
        assert_eq!(t.label, "global-hooks");
        let t = resolve_paths_with(None, Some(&home), &opts(ScopeFilter::GlobalOnly)).unwrap();
        assert_eq!(t.hooks_path, home.join(".kiro/hooks/ptuf.json"));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn resolve_global_requires_home() {
        let err = resolve_paths_with(None, None, &opts(ScopeFilter::Both)).unwrap_err();
        assert!(matches!(err, InitError::HomeNotSet));
    }

    #[test]
    fn resolve_workspace_uses_discovered_repo() {
        let repo = workdir("resolve-local");
        fs::create_dir_all(repo.join(".git")).unwrap();
        let t = resolve_paths_with(Some(&repo), None, &opts(ScopeFilter::WorkspaceOnly)).unwrap();
        assert_eq!(t.hooks_path, repo.join(".kiro/hooks/ptuf.json"));
        assert_eq!(t.label, "workspace-hooks");
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn resolve_workspace_prefers_root_override() {
        let repo = workdir("resolve-root");
        fs::create_dir_all(repo.join(".git")).unwrap();
        let options = KiroInitOptions {
            scope: ScopeFilter::WorkspaceOnly,
            root: Some(repo.clone()),
            ..KiroInitOptions::default()
        };
        let t = resolve_paths_with(None, None, &options).unwrap();
        assert_eq!(t.hooks_path, repo.join(".kiro/hooks/ptuf.json"));
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn resolve_workspace_requires_repo() {
        let err = resolve_paths_with(None, None, &opts(ScopeFilter::WorkspaceOnly)).unwrap_err();
        assert!(matches!(err, InitError::RepoRootNotFound));
    }

    #[test]
    fn install_creates_v1_document() {
        let dir = workdir("create");
        let path = dir.join(".kiro/hooks/ptuf.json");
        let outcome = install(&target(path.clone()), "/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        assert_eq!(outcome.agent, "kiro");
        assert_eq!(outcome.command, "/bin/ptuf hook kiro-v3");
        assert_eq!(outcome.matcher, "*");
        let doc = read_json(&path);
        assert_eq!(
            doc,
            json!({
                "version": "v1",
                "hooks": [{
                    "name": "ptuf",
                    "description": "ptuf PreToolUse guardrail (managed by `ptuf init kiro-v3`).",
                    "trigger": "PreToolUse",
                    "matcher": "*",
                    "action": { "type": "command", "command": "/bin/ptuf hook kiro-v3" },
                    "timeout": 30,
                    "enabled": true,
                }],
            })
        );
        assert_eq!(pre_tool_use_commands(&doc), vec!["/bin/ptuf hook kiro-v3"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_idempotent() {
        let dir = workdir("idempotent");
        let path = dir.join("ptuf.json");
        install(&target(path.clone()), "/bin/ptuf", false).unwrap();
        let first = fs::read_to_string(&path).unwrap();
        let outcome = install(&target(path.clone()), "/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(fs::read_to_string(&path).unwrap(), first);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_restores_disabled_or_legacy_entry_in_place() {
        let dir = workdir("normalise");
        let path = dir.join("ptuf.json");
        fs::write(
            &path,
            r#"{"version":"v1","hooks":[
                {"name":"lint","trigger":"PostToolUse","action":{"type":"command","command":"npm run lint"}},
                {"name":"old","trigger":"preToolUse","matcher":"shell","enabled":false,
                 "action":{"type":"command","command":"/old/ptuf hook kiro"}}
            ]}"#,
        )
        .unwrap();
        let outcome = install(&target(path.clone()), "/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let doc = read_json(&path);
        let hooks = doc["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 2, "no duplicate entry: {hooks:?}");
        assert_eq!(hooks[0]["name"], "lint");
        assert_eq!(hooks[1], canonical_entry("/bin/ptuf hook kiro-v3"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_does_not_write() {
        let dir = workdir("dry-run");
        let path = dir.join("ptuf.json");
        let outcome = install(&target(path.clone()), "/bin/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_unknown_version_and_bad_shapes() {
        let dir = workdir("schema");
        let path = dir.join("ptuf.json");
        for body in [
            r#"{"version":"v2","hooks":[]}"#,
            r#"{"version":1,"hooks":[]}"#,
            r#"{"version":"v1","hooks":{}}"#,
            "[]",
        ] {
            fs::write(&path, body).unwrap();
            let err = install(&target(path.clone()), "/bin/ptuf", false).unwrap_err();
            assert!(matches!(err, InitError::Schema { .. }), "{body}: {err:?}");
            assert_eq!(fs::read_to_string(&path).unwrap(), body, "file untouched");
        }
        fs::write(&path, "{not json").unwrap();
        assert!(matches!(
            install(&target(path.clone()), "/bin/ptuf", false),
            Err(InitError::Json { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_tool_use_commands_reads_inline_profile_hooks() {
        let profile = json!({
            "name": "dev",
            "hooks": [
                {"name": "a", "trigger": "SessionStart", "action": {"type": "command", "command": "git status"}},
                {"name": "b", "trigger": "PreToolUse", "action": {"type": "command", "command": "/x/guard.sh"}},
                {"name": "c", "trigger": "preToolUse", "action": {"type": "command", "command": "/y/ptuf hook kiro-v3"}},
                {"name": "d", "trigger": "PreToolUse", "action": {"type": "agent", "prompt": "check"}},
            ],
        });
        assert_eq!(
            pre_tool_use_commands(&profile),
            vec!["/x/guard.sh", "/y/ptuf hook kiro-v3"]
        );
        // The legacy object form is not an array and yields nothing here.
        assert!(pre_tool_use_commands(&json!({"hooks": {"preToolUse": []}})).is_empty());
    }

    #[test]
    fn command_marker_matches_only_versioned_tail() {
        assert!(command_invokes_ptuf_hook("/usr/bin/ptuf hook kiro-v3"));
        assert!(!command_invokes_ptuf_hook("/usr/bin/ptuf hook kiro-v2"));
        assert!(!command_invokes_ptuf_hook("/usr/bin/ptuf hook kiro"));
        assert!(is_ptuf_command("/usr/bin/ptuf hook kiro"));
        assert!(!is_ptuf_command("/usr/bin/ptuf hook kiro-v2"));
    }
}
