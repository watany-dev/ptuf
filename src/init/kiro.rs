//! `ptuf init kiro` — register a `preToolUse` hook in Kiro CLI agent
//! configs.
//!
//! Default mode (`KiroMode::PatchExisting`) patches *every* `*.json`
//! agent file under `<repo>/.kiro/agents/` and `$HOME/.kiro/agents/`
//! so the guardrail fires no matter which agent the user selects.
//! Legacy single-file behavior — creating a dedicated
//! `ptuf-guarded.json` and leaving everything else untouched — is
//! preserved under `KiroMode::NewAgent`.
//!
//! Each patched agent file is a JSON document whose `hooks.preToolUse`
//! array carries `{matcher, command, timeout_ms, cache_ttl_seconds}`
//! entries. We append a single entry whose `command` invokes `<ptuf>
//! hook kiro`, leaving every other field of the file untouched. A
//! second invocation detects the existing entry by matching the
//! trailing `["hook", "kiro"]` tokens of `command` and skips the
//! rewrite.
//!
//! The function `read_default_agent` reads `<scope>/.kiro/settings/cli.json`
//! and treats the *flat* top-level key `"chat.defaultAgent"` (as used in
//! the aws-samples Kiro examples) as the name of the user's default
//! agent. If that key references an agent file that does not exist in
//! the same scope, `resolve_paths` returns an `InitError::Schema` so
//! the install fails closed.
//!
//! When the default mode encounters a scope with no `*.json` files
//! and no `settings/cli.json` reference, a fresh `agents/default.json`
//! is synthesized in the highest-priority scope (workspace > home).
//! Non-JSON agent files (`*.md`, in particular) are listed in the
//! `KiroInstallExtras::skipped_non_json_agents` report but never
//! touched.
//!
//! Mid-loop write failures in default mode interact with the snapshot
//! capture / restore machinery in `src/init/mod.rs`. Each individual
//! file write is atomic (temp + rename). With `--verify` (the
//! default), the caller captures a snapshot of every target before
//! the loop runs and restores on verify failure. With `--no-verify`,
//! no snapshot is captured, so a crash mid-loop can leave earlier
//! files patched while later files remain untouched; no individual
//! file is ever torn.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

/// Agent name used by `KiroMode::NewAgent` (the legacy single-file path).
/// Mirrors the agent file's `name` field and the file stem
/// (`<name>.json`).
pub const DEFAULT_AGENT_NAME: &str = "ptuf-guarded";

/// Agent name used by `KiroMode::PatchExisting` when the target
/// `agents/` directory is empty (no `*.json` files and no
/// `settings/cli.json` reference). A fresh `agents/default.json` is
/// synthesized so Kiro's own default-named agent is guarded.
pub const FALLBACK_AGENT_NAME: &str = "default";

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

/// Flat top-level key inside `<scope>/.kiro/settings/cli.json` that
/// names the default agent. Kiro stores this as a dotted key on the
/// root object (not a nested `chat.defaultAgent` path).
const CHAT_DEFAULT_AGENT_KEY: &str = "chat.defaultAgent";

/// Whether the resolved agent path lives under the workspace
/// (`<repo>/.kiro/`) or under the user's home (`$HOME/.kiro/`).
/// Used by reporting and by per-scope default-agent resolution
/// (workspace `settings/cli.json` only governs workspace agents).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Workspace,
    Home,
}

impl Scope {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Workspace => "workspace-agent",
            Self::Home => "home-agent",
        }
    }

    pub(crate) fn short(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Home => "home",
        }
    }
}

/// One Kiro agent file resolved for patching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedAgent {
    pub scope: Scope,
    pub path: PathBuf,
}

/// Per-scope summary of which agent the user has marked as their
/// default (via `<scope>/.kiro/settings/cli.json`). The install loop
/// fails early via `InitError::Schema` when the referenced JSON is
/// missing, so any report that survives to the CLI dispatcher is
/// covered by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KiroDefaultAgentReport {
    pub scope: Scope,
    pub agent_name: String,
}

/// Adapter-specific reporting carried back to the CLI dispatcher via
/// the internal `AdapterRunReport`. Patched / written paths are not
/// duplicated here — they live in `InstallOutcome.paths` already.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct KiroInstallExtras {
    /// Number of files that already carried a ptuf hook entry and
    /// were left untouched.
    pub already_present_count: usize,
    /// Per-scope `chat.defaultAgent` results.
    pub default_agents: Vec<KiroDefaultAgentReport>,
    /// `*.md` (and other non-JSON) agent files seen but not modified.
    pub skipped_non_json_agents: Vec<PathBuf>,
}

/// Resolved set of agent JSON files to patch.
///
/// The struct itself is `pub` so it can flow between the `pub fn
/// resolve_paths` and `pub fn install` entry points as an opaque
/// handle, but its fields reference `pub(crate)` types and are not
/// part of the public API surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPaths {
    pub(crate) agent_config_paths: Vec<ResolvedAgent>,
    /// `*.md` agent files seen but intentionally skipped — reported
    /// to the user so they know we noticed them.
    pub(crate) skipped_non_json: Vec<PathBuf>,
    /// Per-scope default-agent metadata derived from
    /// `settings/cli.json`. Populated even when the agent JSON file
    /// itself is also in `agent_config_paths` (the two are joined
    /// later via stem comparison).
    pub(crate) default_agent_names: Vec<KiroDefaultAgentReport>,
}

/// Default mode picks every existing agent JSON file; legacy mode
/// keeps the single `ptuf-guarded.json` filename.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KiroMode {
    #[default]
    PatchExisting,
    NewAgent,
}

/// Restrict which scopes are considered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScopeFilter {
    #[default]
    Both,
    WorkspaceOnly,
    GlobalOnly,
}

/// Options threaded from the CLI parser through to `resolve_paths`
/// and `install`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KiroInitOptions {
    pub mode: KiroMode,
    pub scope: ScopeFilter,
}

/// Try `std::env::current_exe()`. Falls back to the literal `"ptuf"`.
pub fn detect_binary() -> String {
    super::detect_binary_impl()
}

/// Production entry: resolve every agent-config path to patch.
///
/// Reads the user's home directory from `$HOME` and delegates to
/// `resolve_paths_with`. Tests use `resolve_paths_with` directly so
/// they can inject a tempdir without mutating process env (forbidden
/// by `unsafe_code = "forbid"`).
pub fn resolve_paths(
    start: Option<&Path>,
    opts: &KiroInitOptions,
) -> Result<TargetPaths, InitError> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    resolve_paths_with(start, home.as_deref(), opts)
}

/// Resolve every agent-config path the install loop should consider.
///
/// In `KiroMode::PatchExisting` (default), enumerates `*.json` files
/// in `<repo>/.kiro/agents/` and/or `<home>/.kiro/agents/` (subject to
/// `ScopeFilter`), reads each scope's `chat.defaultAgent`, and
/// synthesizes a `default.json` placeholder if both scopes are empty
/// or the lone selected scope is empty.
///
/// In `KiroMode::NewAgent`, returns the single legacy
/// `<scope>/.kiro/agents/ptuf-guarded.json` path so the caller stays
/// backwards-compatible.
///
/// `start` is a path inside the workspace (typically `cwd`); the
/// workspace root is discovered upward from it. `home` is the user's
/// home directory (production passes `$HOME`, tests inject a
/// tempdir).
///
/// Returns `InitError::RepoRootNotFound` / `InitError::HomeNotSet`
/// when the requested scope is unavailable, and `InitError::Schema`
/// when `chat.defaultAgent` references a missing agent file.
pub(crate) fn resolve_paths_with(
    start: Option<&Path>,
    home: Option<&Path>,
    opts: &KiroInitOptions,
) -> Result<TargetPaths, InitError> {
    let workspace_root = start.and_then(crate::config::repo::discover);
    let home_root: Option<PathBuf> = home.map(Path::to_path_buf);

    let (use_workspace, use_home) = match opts.scope {
        ScopeFilter::WorkspaceOnly => {
            if workspace_root.is_none() {
                return Err(InitError::RepoRootNotFound);
            }
            (true, false)
        },
        ScopeFilter::GlobalOnly => {
            if home_root.is_none() {
                return Err(InitError::HomeNotSet);
            }
            (false, true)
        },
        ScopeFilter::Both => {
            if workspace_root.is_none() && home_root.is_none() {
                return Err(InitError::RepoRootNotFound);
            }
            (workspace_root.is_some(), home_root.is_some())
        },
    };

    if matches!(opts.mode, KiroMode::NewAgent) {
        return resolve_new_agent_path(
            workspace_root.as_deref(),
            home_root.as_deref(),
            use_workspace,
            use_home,
        );
    }

    let mut agents: Vec<ResolvedAgent> = Vec::new();
    let mut skipped: Vec<PathBuf> = Vec::new();
    let mut defaults: Vec<KiroDefaultAgentReport> = Vec::new();

    let mut scopes: Vec<(Scope, PathBuf)> = Vec::new();
    if use_workspace && let Some(root) = workspace_root.as_deref() {
        scopes.push((Scope::Workspace, root.join(".kiro")));
    }
    if use_home && let Some(root) = home_root.as_deref() {
        scopes.push((Scope::Home, root.join(".kiro")));
    }

    for (scope, kiro_dir) in &scopes {
        let agents_dir = kiro_dir.join("agents");
        let (mut json_files, mut md_files) = enumerate_agents(&agents_dir)?;
        json_files.sort();
        md_files.sort();
        skipped.append(&mut md_files);

        let settings_dir = kiro_dir.join("settings");
        let default_name = read_default_agent(&settings_dir)?;

        if let Some(name) = default_name.as_deref() {
            let referenced = agents_dir.join(format!("{name}.json"));
            let present_in_scope = json_files.iter().any(|p| p == &referenced);
            if !present_in_scope {
                return Err(InitError::Schema {
                    path: settings_dir.join("cli.json"),
                    message: format!(
                        "`{CHAT_DEFAULT_AGENT_KEY}`=\"{name}\" referenced but {} not found",
                        referenced.display()
                    ),
                });
            }
            defaults.push(KiroDefaultAgentReport {
                scope: *scope,
                agent_name: name.to_string(),
            });
        }

        for path in json_files {
            agents.push(ResolvedAgent {
                scope: *scope,
                path,
            });
        }
    }

    if agents.is_empty() {
        let Some((scope, kiro_dir)) = scopes.first() else {
            return Err(InitError::RepoRootNotFound);
        };
        let fallback = kiro_dir
            .join("agents")
            .join(format!("{FALLBACK_AGENT_NAME}.json"));
        agents.push(ResolvedAgent {
            scope: *scope,
            path: fallback,
        });
    }

    Ok(TargetPaths {
        agent_config_paths: agents,
        skipped_non_json: skipped,
        default_agent_names: defaults,
    })
}

fn resolve_new_agent_path(
    workspace_root: Option<&Path>,
    home_root: Option<&Path>,
    use_workspace: bool,
    use_home: bool,
) -> Result<TargetPaths, InitError> {
    let file_name = format!("{DEFAULT_AGENT_NAME}.json");
    let (scope, base) = if use_workspace && let Some(root) = workspace_root {
        (Scope::Workspace, root.to_path_buf())
    } else if use_home && let Some(root) = home_root {
        (Scope::Home, root.to_path_buf())
    } else {
        return Err(InitError::RepoRootNotFound);
    };
    Ok(TargetPaths {
        agent_config_paths: vec![ResolvedAgent {
            scope,
            path: base.join(".kiro/agents").join(file_name),
        }],
        skipped_non_json: Vec::new(),
        default_agent_names: Vec::new(),
    })
}

/// Enumerate `<agents_dir>/*` into `(json_files, non_json_files)`.
/// A missing directory yields two empty vecs. Both vectors are
/// returned unsorted; the caller sorts the slices it cares about
/// using `Path::cmp` (workspace and home agents live in different
/// parent dirs so a `PathBuf` sort still groups them correctly).
fn enumerate_agents(agents_dir: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>), InitError> {
    let entries = match fs::read_dir(agents_dir) {
        Ok(it) => it,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => {
            return Err(InitError::Io {
                path: agents_dir.to_path_buf(),
                source: e,
            });
        },
    };
    let mut json_files = Vec::new();
    let mut other_files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| InitError::Io {
            path: agents_dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| InitError::Io {
            path: path.clone(),
            source: e,
        })?;
        if !ft.is_file() {
            continue;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("json") => json_files.push(path),
            _ => other_files.push(path),
        }
    }
    Ok((json_files, other_files))
}

/// Read `<settings_dir>/cli.json` and extract the flat top-level key
/// `"chat.defaultAgent"`. Returns `Ok(None)` for missing file /
/// missing key / non-string value; returns `InitError::Json` only on
/// JSON parse failure.
fn read_default_agent(settings_dir: &Path) -> Result<Option<String>, InitError> {
    let path = settings_dir.join("cli.json");
    let body = match fs::read_to_string(&path) {
        Ok(s) if s.trim().is_empty() => return Ok(None),
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(InitError::Io {
                path: path.clone(),
                source: e,
            });
        },
    };
    let value: Value = serde_json::from_str(&body).map_err(|e| InitError::Json {
        path: path.clone(),
        message: e.to_string(),
    })?;
    let Some(obj) = value.as_object() else {
        return Ok(None);
    };
    Ok(obj
        .get(CHAT_DEFAULT_AGENT_KEY)
        .and_then(Value::as_str)
        .map(str::to_string))
}

/// Install the ptuf `preToolUse` hook into every resolved agent file.
///
/// Returns `InstallStatus::AlreadyPresent` only when *every* target
/// already carries a ptuf entry; if any target needs a write, the
/// outcome reports `Installed` (or `WouldInstall` under `--dry-run`).
///
/// This is the public entry point; the kiro-specific reporting
/// (`KiroInstallExtras`) is dropped on the floor. CLI dispatchers that
/// need the extras call `install_with_report` instead.
pub fn install(
    targets: &TargetPaths,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let (outcome, _) = install_with_report(targets, ptuf_binary, dry_run)?;
    Ok(outcome)
}

/// Internal entry that returns both the canonical `InstallOutcome` and
/// the kiro-specific `KiroInstallExtras`. Used by the CLI dispatcher to
/// surface per-scope default-agent / skipped-non-json reporting without
/// widening `InstallOutcome`'s public surface.
pub(crate) fn install_with_report(
    targets: &TargetPaths,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<(InstallOutcome, KiroInstallExtras), InitError> {
    let command = format!("{ptuf_binary} hook kiro");
    let mut paths: Vec<InstallPath> = Vec::with_capacity(targets.agent_config_paths.len());
    let mut already_present_count = 0_usize;

    for agent in &targets.agent_config_paths {
        let per_file = install_one_file(&agent.path, &command, dry_run)?;
        if per_file.already_present {
            already_present_count += 1;
        }
        paths.push(InstallPath {
            label: agent.scope.label(),
            path: agent.path.clone(),
        });
    }

    let installed_count = paths.len() - already_present_count;
    let status = if installed_count == 0 {
        InstallStatus::AlreadyPresent
    } else if dry_run {
        InstallStatus::WouldInstall
    } else {
        InstallStatus::Installed
    };

    let extras = KiroInstallExtras {
        already_present_count,
        default_agents: targets.default_agent_names.clone(),
        skipped_non_json_agents: targets.skipped_non_json.clone(),
    };

    Ok((
        InstallOutcome {
            status,
            agent: "kiro",
            paths,
            matcher: DEFAULT_MATCHER.to_string(),
            command,
        },
        extras,
    ))
}

struct PerFileResult {
    already_present: bool,
}

fn install_one_file(path: &Path, command: &str, dry_run: bool) -> Result<PerFileResult, InitError> {
    let mut root = read_agent_config(path)?;
    if has_existing_hook(&root) {
        return Ok(PerFileResult {
            already_present: true,
        });
    }
    append_hook(&mut root, path, command)?;
    if !dry_run {
        write_json_atomically(path, &root)?;
    }
    Ok(PerFileResult {
        already_present: false,
    })
}

/// Read the agent config from disk, or build a fresh default skeleton
/// when the file is missing / empty. The skeleton's `name` field is
/// derived from the file stem so synthesized `default.json` files
/// announce `"name": "default"` rather than `"ptuf-guarded"`.
fn read_agent_config(path: &Path) -> Result<Value, InitError> {
    match fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => {
            Ok(default_agent_skeleton(stem_or(path, DEFAULT_AGENT_NAME)))
        },
        Ok(s) => serde_json::from_str(&s).map_err(|e| InitError::Json {
            path: path.to_path_buf(),
            message: e.to_string(),
        }),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            Ok(default_agent_skeleton(stem_or(path, DEFAULT_AGENT_NAME)))
        },
        Err(e) => Err(InitError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

fn stem_or<'a>(path: &'a Path, fallback: &'a str) -> &'a str {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(fallback)
}

/// Default JSON skeleton written when no agent config exists yet.
fn default_agent_skeleton(name: &str) -> Value {
    json!({
        "name": name,
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
    super::sibling_install_tmp_path(path, "agent.json")
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

    fn single_target(path: PathBuf) -> TargetPaths {
        TargetPaths {
            agent_config_paths: vec![ResolvedAgent {
                scope: Scope::Workspace,
                path,
            }],
            skipped_non_json: Vec::new(),
            default_agent_names: Vec::new(),
        }
    }

    fn install_and_extras(
        targets: &TargetPaths,
        bin: &str,
        dry_run: bool,
    ) -> (InstallOutcome, KiroInstallExtras) {
        install_with_report(targets, bin, dry_run).unwrap()
    }

    #[test]
    fn install_creates_new_local_config_with_default_template() {
        let dir = workdir("install-local");
        let path = dir.join(".kiro/agents/ptuf-guarded.json");
        let targets = single_target(path.clone());
        let outcome = install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = read(&path);
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
        let path = dir.join(".kiro/agents/ptuf-guarded.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
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
        fs::write(&path, serde_json::to_string_pretty(&preset).unwrap()).unwrap();
        let before = read(&path);
        let targets = single_target(path.clone());
        let (outcome, extras) = install_and_extras(&targets, "/y/ptuf", false);
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(before, read(&path));
        assert_eq!(extras.already_present_count, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_appends_when_unrelated_entry_exists() {
        let dir = workdir("append");
        let path = dir.join(".kiro/agents/ptuf-guarded.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
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
        fs::write(&path, serde_json::to_string_pretty(&preset).unwrap()).unwrap();
        let targets = single_target(path.clone());
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&path)).unwrap();
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
        let path = dir.join(".kiro/agents/ptuf-guarded.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let preset = json!({
            "name": "ptuf-guarded",
            "model": "claude-sonnet-4-6",
            "temperature": 0.2,
            "extras": { "deep": { "value": 42 } },
        });
        fs::write(&path, serde_json::to_string_pretty(&preset).unwrap()).unwrap();
        let targets = single_target(path.clone());
        install(&targets, "/x/ptuf", false).unwrap();
        let after: Value = serde_json::from_str(&read(&path)).unwrap();
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
        let path = dir.join(".kiro/agents/ptuf-guarded.json");
        let targets = single_target(path.clone());
        let outcome = install(&targets, "/usr/local/bin/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_returns_init_error_json_for_invalid_file() {
        let dir = workdir("bad-json");
        let path = dir.join(".kiro/agents/ptuf-guarded.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let before = "{not json";
        fs::write(&path, before).unwrap();
        let targets = single_target(path.clone());
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Json { .. }));
        let after = fs::read_to_string(&path).unwrap();
        assert_eq!(after, before, "agent config was modified despite Err");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_top_level_is_not_object() {
        let dir = workdir("non-object");
        let path = dir.join(".kiro/agents/ptuf-guarded.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "[]").unwrap();
        let targets = single_target(path.clone());
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Schema { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_when_hooks_is_wrong_type() {
        let dir = workdir("hooks-wrong-type");
        let path = dir.join(".kiro/agents/ptuf-guarded.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, r#"{"name": "x", "hooks": 42}"#).unwrap();
        let targets = single_target(path.clone());
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
        let path = dir.join(".kiro/agents/ptuf-guarded.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, r#"{"name": "x", "hooks": {"preToolUse": "nope"}}"#).unwrap();
        let targets = single_target(path.clone());
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
        let path = dir.join(".kiro/agents/ptuf-guarded.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "").unwrap();
        let targets = single_target(path.clone());
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let after: Value = serde_json::from_str(&read(&path)).unwrap();
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
        let path = dir.join("agent-as-dir");
        fs::create_dir_all(&path).unwrap();
        let targets = single_target(path);
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
    fn sibling_temp_path_uses_default_filename_when_input_has_none() {
        let p = Path::new("/");
        let tmp = sibling_temp_path(p);
        assert!(
            tmp.to_string_lossy().contains("agent.json.ptuf."),
            "missing file_name must default to agent.json: {tmp:?}"
        );
    }

    #[test]
    fn write_json_atomically_propagates_dir_creation_error() {
        let dir = workdir("write-json-dir-fail");
        let blocker = dir.join("blocker");
        fs::write(&blocker, "not-a-dir").expect("write blocker");
        let target = blocker.join("nested").join("target.json");
        let err = write_json_atomically(&target, &json!({"x": 1}))
            .expect_err("must fail when parent can't be created");
        assert!(
            matches!(err, InitError::Io { .. }),
            "expected Io, got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_json_atomically_propagates_write_error_when_tmp_is_a_directory() {
        let dir = workdir("write-tmp-blocked");
        let target = dir.join("ptuf-guarded.json");
        let collision = dir.join(format!("ptuf-guarded.json.ptuf.{}.tmp", std::process::id()));
        fs::create_dir_all(&collision).unwrap();
        let targets = single_target(target);
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(
            matches!(err, InitError::Io { .. }),
            "expected Io, got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_json_atomically_propagates_rename_error_when_target_is_a_directory() {
        let dir = workdir("rename-blocked");
        let target = dir.join("target");
        fs::create_dir_all(&target).unwrap();
        let err = write_json_atomically(&target, &json!({"x": 1}))
            .expect_err("rename onto dir must fail");
        assert!(
            matches!(err, InitError::Io { .. }),
            "expected Io, got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_paths_falls_back_to_home_when_outside_git_tree() {
        let opts = KiroInitOptions::default();
        let result = resolve_paths_with(
            Some(Path::new("/nonexistent-definitely-not-git")),
            None,
            &opts,
        );
        match result {
            Ok(t) => {
                assert!(!t.agent_config_paths.is_empty());
                assert!(
                    t.agent_config_paths
                        .iter()
                        .all(|a| a.path.to_string_lossy().contains(".kiro/agents")),
                    "expected kiro paths, got {:?}",
                    t.agent_config_paths
                );
            },
            Err(InitError::RepoRootNotFound) => {},
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn pre_tool_use_commands_extracts_all_commands() {
        let root = json!({
            "hooks": {
                "preToolUse": [
                    { "command": "/x/ptuf hook kiro" },
                    { "command": "/y/ptuf hook kiro" },
                ]
            }
        });
        let cmds = pre_tool_use_commands(&root);
        assert_eq!(cmds, vec!["/x/ptuf hook kiro", "/y/ptuf hook kiro"]);
    }

    #[test]
    fn pre_tool_use_commands_returns_empty_when_key_missing() {
        assert!(pre_tool_use_commands(&json!({})).is_empty());
        assert!(pre_tool_use_commands(&json!({ "hooks": {} })).is_empty());
        assert!(
            pre_tool_use_commands(&json!({ "hooks": { "preToolUse": "not-array" } })).is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_writes_agent_config_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workdir("perm-kiro");
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::create_dir_all(dir.join(".kiro/agents")).unwrap();
        let opts = KiroInitOptions {
            mode: KiroMode::NewAgent,
            scope: ScopeFilter::WorkspaceOnly,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), None, &opts).unwrap();
        let outcome = install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        assert!(matches!(outcome.status, InstallStatus::Installed));
        let written_path = &targets.agent_config_paths[0].path;
        let mode = fs::metadata(written_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "fresh agent config must be owner-only");
        let _ = fs::remove_dir_all(&dir);
    }

    // ─────────── new-mode (PatchExisting) behavior ───────────

    /// Repository-rooted fixture: `<root>/.git`, `<root>/.kiro/agents/`,
    /// `<root>/.kiro/settings/`. Returns the root path.
    fn workspace_fixture(tag: &str) -> PathBuf {
        let dir = workdir(tag);
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::create_dir_all(dir.join(".kiro/agents")).unwrap();
        fs::create_dir_all(dir.join(".kiro/settings")).unwrap();
        dir
    }

    fn write_minimal_agent(path: &Path, name: &str) {
        let body = json!({"name": name, "tools": ["*"]});
        fs::write(path, serde_json::to_string_pretty(&body).unwrap()).unwrap();
    }

    #[test]
    fn patch_existing_patches_every_json_in_workspace_agents_dir() {
        let dir = workspace_fixture("patch-existing");
        let a = dir.join(".kiro/agents/alpha.json");
        let b = dir.join(".kiro/agents/beta.json");
        write_minimal_agent(&a, "alpha");
        write_minimal_agent(&b, "beta");

        let opts = KiroInitOptions {
            mode: KiroMode::PatchExisting,
            scope: ScopeFilter::WorkspaceOnly,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), None, &opts).unwrap();
        assert_eq!(targets.agent_config_paths.len(), 2);
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);

        for agent_path in [&a, &b] {
            let parsed: Value = serde_json::from_str(&read(agent_path)).unwrap();
            let arr = parsed
                .pointer("/hooks/preToolUse")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("missing preToolUse in {agent_path:?}"));
            assert_eq!(arr.len(), 1, "{agent_path:?}");
            assert_eq!(
                arr[0].get("command").and_then(Value::as_str),
                Some("/x/ptuf hook kiro"),
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn patch_existing_skips_md_agents() {
        let dir = workspace_fixture("skip-md");
        let json_path = dir.join(".kiro/agents/default.json");
        let md_path = dir.join(".kiro/agents/default.md");
        write_minimal_agent(&json_path, "default");
        fs::write(&md_path, "# system prompt").unwrap();

        let opts = KiroInitOptions {
            mode: KiroMode::PatchExisting,
            scope: ScopeFilter::WorkspaceOnly,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), None, &opts).unwrap();
        assert_eq!(targets.agent_config_paths.len(), 1);
        assert_eq!(targets.skipped_non_json, vec![md_path.clone()]);

        let (_outcome, extras) = install_and_extras(&targets, "/x/ptuf", false);
        assert_eq!(extras.skipped_non_json_agents, vec![md_path.clone()]);
        // .md file must be untouched
        assert_eq!(fs::read_to_string(&md_path).unwrap(), "# system prompt");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn patch_existing_fails_when_default_agent_missing() {
        let dir = workspace_fixture("default-missing");
        fs::write(
            dir.join(".kiro/settings/cli.json"),
            r#"{"chat.defaultAgent":"architect"}"#,
        )
        .unwrap();
        // architect.json deliberately absent. Add some other agent so the
        // directory isn't empty.
        write_minimal_agent(&dir.join(".kiro/agents/other.json"), "other");

        let opts = KiroInitOptions {
            mode: KiroMode::PatchExisting,
            scope: ScopeFilter::WorkspaceOnly,
        };
        let err = resolve_paths_with(Some(dir.as_path()), None, &opts).unwrap_err();
        match err {
            InitError::Schema { path, message } => {
                assert!(path.ends_with("cli.json"), "got: {path:?}");
                assert!(message.contains("chat.defaultAgent"), "got: {message}");
                assert!(message.contains("architect"), "got: {message}");
            },
            other => panic!("expected Schema, got: {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn patch_existing_creates_default_json_when_empty() {
        let dir = workspace_fixture("synth-default");
        // agents/ exists but is empty; no settings/cli.json
        let opts = KiroInitOptions {
            mode: KiroMode::PatchExisting,
            scope: ScopeFilter::WorkspaceOnly,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), None, &opts).unwrap();
        assert_eq!(targets.agent_config_paths.len(), 1);
        assert!(
            targets.agent_config_paths[0]
                .path
                .ends_with(".kiro/agents/default.json")
        );

        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let path = &targets.agent_config_paths[0].path;
        let parsed: Value = serde_json::from_str(&read(path)).unwrap();
        assert_eq!(parsed.get("name").and_then(Value::as_str), Some("default"));
        assert!(parsed.pointer("/hooks/preToolUse").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn patch_existing_marks_default_agent_covered_when_present() {
        let dir = workspace_fixture("default-covered");
        write_minimal_agent(&dir.join(".kiro/agents/architect.json"), "architect");
        fs::write(
            dir.join(".kiro/settings/cli.json"),
            r#"{"chat.defaultAgent":"architect"}"#,
        )
        .unwrap();
        let opts = KiroInitOptions {
            mode: KiroMode::PatchExisting,
            scope: ScopeFilter::WorkspaceOnly,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), None, &opts).unwrap();
        assert_eq!(targets.agent_config_paths.len(), 1);
        let (_outcome, extras) = install_and_extras(&targets, "/x/ptuf", false);
        assert_eq!(extras.default_agents.len(), 1);
        assert_eq!(extras.default_agents[0].agent_name, "architect");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn workspace_only_scope_skips_home() {
        let dir = workspace_fixture("workspace-only");
        write_minimal_agent(&dir.join(".kiro/agents/alpha.json"), "alpha");

        let home = workdir("workspace-only-home");
        fs::create_dir_all(home.join(".kiro/agents")).unwrap();
        write_minimal_agent(&home.join(".kiro/agents/beta.json"), "beta");

        let opts = KiroInitOptions {
            mode: KiroMode::PatchExisting,
            scope: ScopeFilter::WorkspaceOnly,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), Some(home.as_path()), &opts).unwrap();
        assert_eq!(targets.agent_config_paths.len(), 1);
        assert!(targets.agent_config_paths[0].path.starts_with(&dir));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn global_only_scope_skips_workspace() {
        let dir = workspace_fixture("global-only-ws");
        write_minimal_agent(&dir.join(".kiro/agents/alpha.json"), "alpha");

        let home = workdir("global-only-home");
        fs::create_dir_all(home.join(".kiro/agents")).unwrap();
        write_minimal_agent(&home.join(".kiro/agents/beta.json"), "beta");

        let opts = KiroInitOptions {
            mode: KiroMode::PatchExisting,
            scope: ScopeFilter::GlobalOnly,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), Some(home.as_path()), &opts).unwrap();
        assert_eq!(targets.agent_config_paths.len(), 1);
        assert!(targets.agent_config_paths[0].path.starts_with(&home));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn patch_existing_covers_workspace_and_home() {
        let dir = workspace_fixture("ws-and-home");
        write_minimal_agent(&dir.join(".kiro/agents/alpha.json"), "alpha");
        let home = workdir("ws-and-home-home");
        fs::create_dir_all(home.join(".kiro/agents")).unwrap();
        write_minimal_agent(&home.join(".kiro/agents/beta.json"), "beta");

        let opts = KiroInitOptions {
            mode: KiroMode::PatchExisting,
            scope: ScopeFilter::Both,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), Some(home.as_path()), &opts).unwrap();
        assert_eq!(targets.agent_config_paths.len(), 2);
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        for p in [
            dir.join(".kiro/agents/alpha.json"),
            home.join(".kiro/agents/beta.json"),
        ] {
            let parsed: Value = serde_json::from_str(&read(&p)).unwrap();
            assert!(
                parsed
                    .pointer("/hooks/preToolUse")
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.len() == 1),
                "missing patched hook in {p:?}",
            );
        }
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn new_agent_mode_keeps_legacy_filename() {
        let dir = workspace_fixture("new-agent-legacy");
        let opts = KiroInitOptions {
            mode: KiroMode::NewAgent,
            scope: ScopeFilter::WorkspaceOnly,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), None, &opts).unwrap();
        assert_eq!(targets.agent_config_paths.len(), 1);
        assert!(
            targets.agent_config_paths[0]
                .path
                .ends_with(".kiro/agents/ptuf-guarded.json")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn existing_ptuf_guarded_json_is_idempotent_on_repatch() {
        let dir = workspace_fixture("repatch-legacy");
        // First install in legacy mode
        let opts_legacy = KiroInitOptions {
            mode: KiroMode::NewAgent,
            scope: ScopeFilter::WorkspaceOnly,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), None, &opts_legacy).unwrap();
        install(&targets, "/x/ptuf", false).unwrap();

        // Now re-run in default (PatchExisting) mode — the existing
        // ptuf-guarded.json must be detected by tail-token matching
        // and reported as AlreadyPresent.
        let opts_default = KiroInitOptions {
            mode: KiroMode::PatchExisting,
            scope: ScopeFilter::WorkspaceOnly,
        };
        let targets2 = resolve_paths_with(Some(dir.as_path()), None, &opts_default).unwrap();
        let (outcome, extras) = install_and_extras(&targets2, "/x/ptuf", false);
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(extras.already_present_count, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_default_agent_returns_none_when_settings_missing() {
        let dir = workdir("default-no-settings");
        // No `cli.json` written, no directory either.
        let opt = read_default_agent(&dir.join("settings")).unwrap();
        assert!(opt.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_default_agent_returns_none_when_key_absent() {
        let dir = workdir("default-key-absent");
        let settings_dir = dir.join("settings");
        fs::create_dir_all(&settings_dir).unwrap();
        fs::write(settings_dir.join("cli.json"), r#"{"other":"value"}"#).unwrap();
        assert!(read_default_agent(&settings_dir).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_default_agent_returns_value_when_set() {
        let dir = workdir("default-set");
        let settings_dir = dir.join("settings");
        fs::create_dir_all(&settings_dir).unwrap();
        fs::write(
            settings_dir.join("cli.json"),
            r#"{"chat.defaultAgent":"architect","other":42}"#,
        )
        .unwrap();
        assert_eq!(
            read_default_agent(&settings_dir).unwrap().as_deref(),
            Some("architect")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_default_agent_rejects_invalid_json() {
        let dir = workdir("default-bad-json");
        let settings_dir = dir.join("settings");
        fs::create_dir_all(&settings_dir).unwrap();
        fs::write(settings_dir.join("cli.json"), "{not json").unwrap();
        let err = read_default_agent(&settings_dir).unwrap_err();
        assert!(matches!(err, InitError::Json { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enumerate_agents_returns_sorted_split() {
        let dir = workdir("enum-agents");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("b.json"), "{}").unwrap();
        fs::write(dir.join("a.json"), "{}").unwrap();
        fs::write(dir.join("c.md"), "# x").unwrap();
        let (mut jsons, mut others) = enumerate_agents(&dir).unwrap();
        jsons.sort();
        others.sort();
        assert!(jsons[0].ends_with("a.json"));
        assert!(jsons[1].ends_with("b.json"));
        assert_eq!(others.len(), 1);
        assert!(others[0].ends_with("c.md"));
        let _ = fs::remove_dir_all(&dir);
    }
}
