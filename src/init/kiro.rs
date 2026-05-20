//! `ptuf init kiro` — patch every Kiro CLI custom-agent JSON so the
//! `preToolUse` hook routes through `ptuf hook kiro`, then verify that
//! Kiro CLI's effective default agent is among the protected ones.
//!
//! The earlier implementation created a single `ptuf-guarded.json` and
//! treated success as "we wrote a file somewhere". That left the
//! built-in `kiro_default` agent (and any pre-existing user custom
//! agent) unprotected. The new flow enumerates `*.json` under workspace
//! and global agents directories, adds a `FullCoverage` entry to each
//! existing agent, and consults `<global_root>/settings/cli.json`'s
//! `chat.defaultAgent` to decide whether the effective default is
//! actually covered.
//!
//! The detailed behavior — flag matrix, JSON shape rules, coverage
//! tri-state, fallback skeleton, failure conditions — is documented in
//! `docs/design/kiro-cli.md` and the changelog entry for this revision.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

/// Legacy default agent name kept for `--new-agent` compatibility.
pub const LEGACY_AGENT_NAME: &str = "ptuf-guarded";

/// Custom agent name written when callers ask for a fallback default
/// (`--set-default default` with no existing custom agents).
pub const FALLBACK_DEFAULT_AGENT_NAME: &str = "default";

/// Matcher used on the inserted `preToolUse` entry. `"*"` matches every
/// built-in tool and every MCP tool per the Kiro CLI hook spec, which
/// `docs/design/kiro-cli.md` summarises.
pub const DEFAULT_MATCHER: &str = "*";

/// Default timeout the hook entry advertises to Kiro CLI.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// Default cache TTL; `0` disables caching so every PreToolUse event is
/// re-evaluated by ptuf.
pub const DEFAULT_CACHE_TTL_SECONDS: u64 = 0;

/// Kiro CLI's built-in default agent. Not a file on disk; cannot be
/// patched.
pub const BUILTIN_DEFAULT_AGENT: &str = "kiro_default";

/// Trailing tokens (split on whitespace) that mark a `command` field as
/// a ptuf Kiro `preToolUse` hook. Tolerant of leading shell-quoted
/// binary paths.
pub(crate) const COMMAND_TAIL: &[&str] = &["hook", "kiro"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KiroScope {
    Workspace,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KiroPatchAction {
    /// Existing file already carries a `FullCoverage` ptuf entry.
    AlreadyFullCoverage,
    /// Existing file carries a narrow-matcher ptuf entry; we append a
    /// new `matcher: "*"` entry alongside it.
    AddedFullCoverageBecauseNarrow,
    /// Existing file has no ptuf entry; we appended a `FullCoverage`
    /// one.
    AppendedFullCoverage,
    /// File did not exist; we wrote a fresh fallback skeleton.
    CreatedFallbackSkeleton,
    /// File contained invalid JSON; left untouched.
    FailInvalidJson { detail: String },
    /// JSON shape was valid but incompatible with the patch.
    FailUnsupportedShape { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KiroAgentTarget {
    pub name: String,
    pub path: PathBuf,
    pub scope: KiroScope,
    pub is_effective_default: bool,
    pub action: KiroPatchAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAgentSource {
    /// `chat.defaultAgent` was not present in `<global_root>/settings/cli.json`;
    /// Kiro CLI falls back to the built-in `kiro_default`.
    BuiltinFallback,
    /// `<global_root>/settings/cli.json`'s `chat.defaultAgent`.
    GlobalSetting,
    /// `--set-default` overrode the setting during this run.
    CliFlag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultAgentFailureReason {
    BuiltinDefaultUncovered,
    DefaultAgentJsonNotFound { name: String },
    InvalidDefaultAgentJson { path: PathBuf, detail: String },
    UnsupportedDefaultAgentJsonShape { path: PathBuf, detail: String },
    PatchFailed { path: PathBuf, detail: String },
    NoAgentsAndNoSetDefault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultAgentStatus {
    pub setting_value: Option<String>,
    pub source: DefaultAgentSource,
    pub resolved_agent_path: Option<PathBuf>,
    pub covered: bool,
    pub failure_reason: Option<DefaultAgentFailureReason>,
}

/// Observed `<repo>/.kiro/settings/cli.json`. Diagnostic only — workspace
/// settings are *not* authoritative for `chat.defaultAgent` per the Kiro
/// CLI docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedWorkspaceSettings {
    pub path: PathBuf,
    pub chat_default_agent: Option<String>,
}

/// Caller-supplied behavior knobs derived from `ptuf init kiro` flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KiroOptions {
    /// `--new-agent`: legacy `ptuf-guarded.json` mode.
    pub new_agent: bool,
    /// `--set-default <name>`: pin `chat.defaultAgent` after patching.
    pub set_default: Option<String>,
    /// `--workspace-only`: skip global agents and global settings.
    pub workspace_only: bool,
    /// `--global`: skip workspace agents.
    pub global_only: bool,
}

#[derive(Debug, Clone)]
pub struct KiroInstallPlan {
    pub workspace_agents_dir: Option<PathBuf>,
    pub global_agents_dir: Option<PathBuf>,
    pub global_settings_path: Option<PathBuf>,
    pub observed_workspace_settings: Option<ObservedWorkspaceSettings>,
    pub targets: Vec<KiroAgentTarget>,
    pub default_agent: DefaultAgentStatus,
    pub skipped_non_json: Vec<PathBuf>,
    pub warnings: Vec<String>,
    pub options: KiroOptions,
    pub binary_command: String,
}

impl KiroInstallPlan {
    /// Every file that may be opened for read or write during install,
    /// so the caller can snapshot them for rollback.
    pub fn snapshot_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self.targets.iter().map(|t| t.path.clone()).collect();
        if let Some(p) = &self.global_settings_path {
            paths.push(p.clone());
        }
        paths.sort();
        paths.dedup();
        paths
    }
}

/// Final report consumed by CLI text/JSON renderers and by `verify`.
#[derive(Debug, Clone)]
pub struct KiroReport {
    pub global_root: Option<PathBuf>,
    pub workspace_agents_dir: Option<PathBuf>,
    pub global_agents_dir: Option<PathBuf>,
    pub global_settings_path: Option<PathBuf>,
    pub observed_workspace_settings: Option<ObservedWorkspaceSettings>,
    pub targets: Vec<KiroAgentTarget>,
    pub default_agent: DefaultAgentStatus,
    pub skipped_non_json: Vec<PathBuf>,
    pub warnings: Vec<String>,
    /// Whether `<global_root>/settings/cli.json` was updated this run.
    pub set_default_applied: Option<String>,
    /// True iff `init kiro` should report failure.
    pub overall_failure: bool,
}

impl KiroReport {
    pub fn patched_agent_count(&self) -> usize {
        self.targets
            .iter()
            .filter(|t| {
                matches!(
                    t.action,
                    KiroPatchAction::AppendedFullCoverage
                        | KiroPatchAction::AddedFullCoverageBecauseNarrow
                        | KiroPatchAction::CreatedFallbackSkeleton
                )
            })
            .count()
    }

    pub fn already_full_coverage_count(&self) -> usize {
        self.targets
            .iter()
            .filter(|t| matches!(t.action, KiroPatchAction::AlreadyFullCoverage))
            .count()
    }

    pub fn narrow_coverage_repaired_count(&self) -> usize {
        self.targets
            .iter()
            .filter(|t| matches!(t.action, KiroPatchAction::AddedFullCoverageBecauseNarrow))
            .count()
    }

    pub fn patched_agent_paths(&self) -> Vec<&Path> {
        self.targets
            .iter()
            .filter(|t| {
                matches!(
                    t.action,
                    KiroPatchAction::AppendedFullCoverage
                        | KiroPatchAction::AddedFullCoverageBecauseNarrow
                        | KiroPatchAction::CreatedFallbackSkeleton
                )
            })
            .map(|t| t.path.as_path())
            .collect()
    }

    pub fn failed_target_paths(&self) -> Vec<&KiroAgentTarget> {
        self.targets
            .iter()
            .filter(|t| {
                matches!(
                    t.action,
                    KiroPatchAction::FailInvalidJson { .. }
                        | KiroPatchAction::FailUnsupportedShape { .. }
                )
            })
            .collect()
    }
}

/// `std::env` accessor split out so tests can inject `HOME` / `KIRO_HOME`.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    pub home: Option<PathBuf>,
    pub kiro_home: Option<PathBuf>,
}

impl Environment {
    pub fn from_process() -> Self {
        Self {
            home: std::env::var_os("HOME").map(PathBuf::from),
            kiro_home: std::env::var_os("KIRO_HOME").map(PathBuf::from),
        }
    }
}

/// Try `std::env::current_exe()`. Falls back to the literal `"ptuf"`.
pub fn detect_binary() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| "ptuf".to_string())
}

/// POSIX-safe single-quoting. Always wraps the input in single quotes —
/// callers must rely on `shell_quote(...) + " hook kiro"` producing a
/// well-formed command line regardless of what characters appear in
/// `s` (spaces, `'`, `$`, etc.).
pub(crate) fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

fn build_command(ptuf_binary: &str) -> String {
    format!("{} hook kiro", shell_quote(ptuf_binary))
}

/// Resolve `<global_root>` per the Kiro CLI convention:
/// `KIRO_HOME` if set, else `$HOME/.kiro`.
pub fn resolve_global_root(env: &Environment) -> Option<PathBuf> {
    if let Some(p) = &env.kiro_home {
        return Some(p.clone());
    }
    env.home.as_ref().map(|h| h.join(".kiro"))
}

fn workspace_root(cwd: Option<&Path>) -> Option<PathBuf> {
    cwd.and_then(crate::config::repo::discover)
}

/// Build a [`KiroInstallPlan`] describing every file that would be
/// touched and how the effective default agent resolves. Does no I/O
/// beyond reading existing files.
pub fn plan(
    cwd: Option<&Path>,
    env: &Environment,
    options: &KiroOptions,
    ptuf_binary: &str,
) -> Result<KiroInstallPlan, InitError> {
    let binary_command = build_command(ptuf_binary);

    let workspace_root = if options.global_only {
        None
    } else {
        workspace_root(cwd)
    };
    let global_root = if options.workspace_only {
        None
    } else {
        resolve_global_root(env)
    };

    if workspace_root.is_none() && global_root.is_none() {
        return Err(InitError::RepoRootNotFound);
    }

    let workspace_agents_dir = workspace_root.as_ref().map(|r| r.join(".kiro/agents"));
    let global_agents_dir = global_root.as_ref().map(|r| r.join("agents"));
    let global_settings_path = global_root.as_ref().map(|r| r.join("settings/cli.json"));
    let observed_workspace_settings = workspace_root
        .as_ref()
        .map(|r| r.join(".kiro/settings/cli.json"))
        .and_then(read_workspace_settings_diag);

    let mut targets: Vec<KiroAgentTarget> = Vec::new();
    let mut skipped_non_json: Vec<PathBuf> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if options.new_agent {
        // Legacy --new-agent: explicit ptuf-guarded.json target.
        let scope_dir = workspace_agents_dir
            .as_ref()
            .or(global_agents_dir.as_ref())
            .cloned();
        if let Some(dir) = scope_dir {
            let scope = if workspace_agents_dir
                .as_ref()
                .is_some_and(|w| *w == dir.clone())
            {
                KiroScope::Workspace
            } else {
                KiroScope::Global
            };
            let path = dir.join(format!("{LEGACY_AGENT_NAME}.json"));
            let action = classify_target_action(&path);
            targets.push(KiroAgentTarget {
                name: LEGACY_AGENT_NAME.to_string(),
                path,
                scope,
                is_effective_default: false,
                action,
            });
        }
    } else {
        // Default flow: enumerate every *.json under workspace and global agents dirs.
        if let Some(dir) = &workspace_agents_dir {
            enumerate_agents(
                dir,
                KiroScope::Workspace,
                &mut targets,
                &mut skipped_non_json,
            );
        }
        if let Some(dir) = &global_agents_dir {
            enumerate_agents(dir, KiroScope::Global, &mut targets, &mut skipped_non_json);
        }
    }

    // Resolve effective default agent.
    let setting_value = global_settings_path
        .as_deref()
        .and_then(read_chat_default_agent);

    // `--set-default` overrides what the setting says.
    let (chosen_default, default_source) = match (&options.set_default, &setting_value) {
        (Some(name), _) => (Some(name.clone()), DefaultAgentSource::CliFlag),
        (None, Some(v)) => (Some(v.clone()), DefaultAgentSource::GlobalSetting),
        (None, None) => (None, DefaultAgentSource::BuiltinFallback),
    };

    let mut default_agent = DefaultAgentStatus {
        setting_value: setting_value.clone(),
        source: default_source,
        resolved_agent_path: None,
        covered: false,
        failure_reason: None,
    };

    match chosen_default.as_deref() {
        None => {
            // built-in default; not patchable.
            default_agent.failure_reason = Some(DefaultAgentFailureReason::BuiltinDefaultUncovered);
        },
        Some(BUILTIN_DEFAULT_AGENT) => {
            default_agent.failure_reason = Some(DefaultAgentFailureReason::BuiltinDefaultUncovered);
        },
        Some(name) => {
            // Find the agent JSON; workspace precedes global.
            let workspace_candidate = workspace_agents_dir
                .as_ref()
                .map(|d| d.join(format!("{name}.json")));
            let global_candidate = global_agents_dir
                .as_ref()
                .map(|d| d.join(format!("{name}.json")));

            let mut resolved: Option<PathBuf> = None;
            if let Some(p) = workspace_candidate.as_ref()
                && p.is_file()
            {
                resolved = Some(p.clone());
            }
            if resolved.is_none()
                && let Some(p) = global_candidate.as_ref()
                && p.is_file()
            {
                resolved = Some(p.clone());
            }

            // local/global precedence warning.
            if let (Some(w), Some(g)) = (workspace_candidate.as_ref(), global_candidate.as_ref())
                && w.is_file()
                && g.is_file()
            {
                warnings.push(format!(
                    "kiro: both workspace and global agents/{name}.json exist; workspace takes precedence"
                ));
            }

            if let Some(p) = resolved {
                mark_effective_default(&mut targets, &p);
                default_agent.resolved_agent_path = Some(p);
            } else if options.set_default.is_some() && name == FALLBACK_DEFAULT_AGENT_NAME {
                // We will create a fallback default.json. Decide where:
                // prefer global so the change persists across workspaces.
                let dest_dir = if let Some(g) = &global_agents_dir {
                    Some((g.clone(), KiroScope::Global))
                } else {
                    workspace_agents_dir
                        .as_ref()
                        .map(|w| (w.clone(), KiroScope::Workspace))
                };
                if let Some((dir, scope)) = dest_dir {
                    let path = dir.join(format!("{FALLBACK_DEFAULT_AGENT_NAME}.json"));
                    // Only add if we didn't already enumerate it.
                    let already = targets.iter().any(|t| t.path == path);
                    if already {
                        mark_effective_default(&mut targets, &path);
                    } else {
                        targets.push(KiroAgentTarget {
                            name: FALLBACK_DEFAULT_AGENT_NAME.to_string(),
                            path: path.clone(),
                            scope,
                            is_effective_default: true,
                            action: KiroPatchAction::CreatedFallbackSkeleton,
                        });
                    }
                    default_agent.resolved_agent_path = Some(path);
                } else {
                    default_agent.failure_reason =
                        Some(DefaultAgentFailureReason::DefaultAgentJsonNotFound {
                            name: name.to_string(),
                        });
                }
            } else {
                default_agent.failure_reason =
                    Some(DefaultAgentFailureReason::DefaultAgentJsonNotFound {
                        name: name.to_string(),
                    });
            }
        },
    }

    // Edge case: 0 enumerated agents, no --set-default → cannot succeed
    // because we have nothing to patch and the built-in default is
    // unprotectable.
    if !options.new_agent
        && targets.is_empty()
        && options.set_default.is_none()
        && default_agent.failure_reason.is_none()
    {
        default_agent.failure_reason = Some(DefaultAgentFailureReason::NoAgentsAndNoSetDefault);
    }

    if let Some(diag) = &observed_workspace_settings {
        warnings.push(format!(
            "kiro: observed workspace settings at {} (chat.defaultAgent={}); not authoritative",
            diag.path.display(),
            diag.chat_default_agent.as_deref().unwrap_or("<unset>")
        ));
    }

    Ok(KiroInstallPlan {
        workspace_agents_dir,
        global_agents_dir,
        global_settings_path,
        observed_workspace_settings,
        targets,
        default_agent,
        skipped_non_json,
        warnings,
        options: options.clone(),
        binary_command,
    })
}

fn read_chat_default_agent(path: &Path) -> Option<String> {
    let body = fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&body).ok()?;
    value
        .pointer("/chat/defaultAgent")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn read_workspace_settings_diag(path: PathBuf) -> Option<ObservedWorkspaceSettings> {
    if !path.is_file() {
        return None;
    }
    let chat_default_agent = read_chat_default_agent(&path);
    Some(ObservedWorkspaceSettings {
        path,
        chat_default_agent,
    })
}

fn enumerate_agents(
    dir: &Path,
    scope: KiroScope,
    targets: &mut Vec<KiroAgentTarget>,
    skipped_non_json: &mut Vec<PathBuf>,
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !file_type.is_file() {
            continue;
        }
        let stem = match path.file_stem().and_then(std::ffi::OsStr::to_str) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let extension = path.extension().and_then(std::ffi::OsStr::to_str);
        if extension != Some("json") {
            if extension.is_some() {
                skipped_non_json.push(path.clone());
            }
            continue;
        }
        let action = classify_target_action(&path);
        targets.push(KiroAgentTarget {
            name: stem,
            path,
            scope,
            is_effective_default: false,
            action,
        });
    }
    targets.sort_by(|a, b| a.path.cmp(&b.path));
    skipped_non_json.sort();
}

fn classify_target_action(path: &Path) -> KiroPatchAction {
    match read_agent_doc(path) {
        Ok(None) => KiroPatchAction::CreatedFallbackSkeleton,
        Ok(Some(value)) => match coverage(&value) {
            Coverage::Full => KiroPatchAction::AlreadyFullCoverage,
            Coverage::Narrow => KiroPatchAction::AddedFullCoverageBecauseNarrow,
            Coverage::None => match check_patchable_shape(&value) {
                Ok(()) => KiroPatchAction::AppendedFullCoverage,
                Err(detail) => KiroPatchAction::FailUnsupportedShape { detail },
            },
        },
        Err(InitError::Json { message, .. }) => {
            KiroPatchAction::FailInvalidJson { detail: message }
        },
        Err(InitError::Io { source, .. }) => KiroPatchAction::FailInvalidJson {
            detail: source.to_string(),
        },
        Err(other) => KiroPatchAction::FailInvalidJson {
            detail: other.to_string(),
        },
    }
}

fn read_agent_doc(path: &Path) -> Result<Option<Value>, InitError> {
    match fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(None),
        Ok(s) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|e| InitError::Json {
                path: path.to_path_buf(),
                message: e.to_string(),
            }),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(InitError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

fn check_patchable_shape(root: &Value) -> Result<(), String> {
    if !root.is_object() {
        return Err("top-level value must be a JSON object".into());
    }
    if let Some(hooks) = root.get("hooks")
        && !hooks.is_object()
    {
        return Err("`hooks` must be an object".into());
    }
    if let Some(arr) = root.pointer("/hooks/preToolUse")
        && !arr.is_array()
    {
        return Err("`hooks.preToolUse` must be an array".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    None,
    Narrow,
    Full,
}

fn coverage(root: &Value) -> Coverage {
    let Some(arr) = root.pointer("/hooks/preToolUse").and_then(Value::as_array) else {
        return Coverage::None;
    };
    let mut best = Coverage::None;
    for entry in arr {
        let Some(cmd) = entry.get("command").and_then(Value::as_str) else {
            continue;
        };
        if !command_invokes_ptuf_hook(cmd) {
            continue;
        }
        let matcher = entry.get("matcher").and_then(Value::as_str);
        let is_full = matches!(matcher, None | Some("*"));
        if is_full {
            return Coverage::Full;
        }
        best = Coverage::Narrow;
    }
    best
}

fn mark_effective_default(targets: &mut [KiroAgentTarget], path: &Path) {
    for t in targets.iter_mut() {
        t.is_effective_default = t.path == path;
    }
}

/// Apply the plan to disk (or compute a dry-run summary). Always
/// returns the `InstallOutcome` so the CLI can render the standard
/// `ptuf init` summary text; the rich Kiro report rides along in
/// `InstallOutcome::kiro_report`.
pub fn install(plan: &KiroInstallPlan, dry_run: bool) -> Result<InstallOutcome, InitError> {
    let mut report = KiroReport {
        global_root: plan
            .global_settings_path
            .as_ref()
            .and_then(|p| p.parent().and_then(|p| p.parent()).map(Path::to_path_buf)),
        workspace_agents_dir: plan.workspace_agents_dir.clone(),
        global_agents_dir: plan.global_agents_dir.clone(),
        global_settings_path: plan.global_settings_path.clone(),
        observed_workspace_settings: plan.observed_workspace_settings.clone(),
        targets: plan.targets.clone(),
        default_agent: plan.default_agent.clone(),
        skipped_non_json: plan.skipped_non_json.clone(),
        warnings: plan.warnings.clone(),
        set_default_applied: None,
        overall_failure: false,
    };

    // Patch each agent file.
    for target in &mut report.targets {
        match &target.action {
            KiroPatchAction::AlreadyFullCoverage => {},
            KiroPatchAction::FailInvalidJson { .. }
            | KiroPatchAction::FailUnsupportedShape { .. } => {
                // Leave the file untouched but record the failure.
            },
            KiroPatchAction::AppendedFullCoverage
            | KiroPatchAction::AddedFullCoverageBecauseNarrow => {
                if !dry_run
                    && let Err(err) = patch_existing_agent(&target.path, &plan.binary_command)
                {
                    target.action = KiroPatchAction::FailUnsupportedShape {
                        detail: err.to_string(),
                    };
                }
            },
            KiroPatchAction::CreatedFallbackSkeleton => {
                if !dry_run
                    && let Err(err) =
                        create_fallback_agent(&target.path, &target.name, &plan.binary_command)
                {
                    target.action = KiroPatchAction::FailUnsupportedShape {
                        detail: err.to_string(),
                    };
                }
            },
        }
    }

    // Apply --set-default to global settings (if applicable).
    if let Some(name) = &plan.options.set_default
        && let Some(settings_path) = &plan.global_settings_path
    {
        if !dry_run {
            write_chat_default_agent(settings_path, name)?;
        }
        report.set_default_applied = Some(name.clone());
        // Re-resolve coverage now that default is set.
        report.default_agent.setting_value = Some(name.clone());
        report.default_agent.source = DefaultAgentSource::CliFlag;
    }

    // Compute final default-agent coverage. `--new-agent` is the legacy
    // single-file mode; we skip the default-agent coverage check there
    // because the caller has explicitly opted into the old behavior.
    if plan.options.new_agent {
        report.default_agent.failure_reason = None;
        report.default_agent.covered = false;
    } else {
        finalize_default_coverage(&mut report);
    }

    let install_status = derive_install_status(&report, dry_run);
    let install_paths = build_install_paths(&report);

    Ok(InstallOutcome {
        status: install_status,
        agent: "kiro",
        paths: install_paths,
        matcher: DEFAULT_MATCHER.to_string(),
        command: plan.binary_command.clone(),
        kiro_report: Some(report),
    })
}

fn finalize_default_coverage(report: &mut KiroReport) {
    let Some(resolved) = report.default_agent.resolved_agent_path.clone() else {
        // No file → covered=false; ensure a failure reason is set.
        if report.default_agent.failure_reason.is_none() {
            report.default_agent.failure_reason =
                Some(DefaultAgentFailureReason::BuiltinDefaultUncovered);
        }
        report.default_agent.covered = false;
        report.overall_failure = true;
        return;
    };

    let Some(target) = report.targets.iter().find(|t| t.path == resolved) else {
        report.default_agent.covered = false;
        report.default_agent.failure_reason =
            Some(DefaultAgentFailureReason::DefaultAgentJsonNotFound {
                name: resolved
                    .file_stem()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or("")
                    .to_string(),
            });
        report.overall_failure = true;
        return;
    };

    match &target.action {
        KiroPatchAction::AlreadyFullCoverage
        | KiroPatchAction::AppendedFullCoverage
        | KiroPatchAction::AddedFullCoverageBecauseNarrow
        | KiroPatchAction::CreatedFallbackSkeleton => {
            report.default_agent.covered = true;
            report.default_agent.failure_reason = None;
        },
        KiroPatchAction::FailInvalidJson { detail } => {
            report.default_agent.covered = false;
            report.default_agent.failure_reason =
                Some(DefaultAgentFailureReason::InvalidDefaultAgentJson {
                    path: target.path.clone(),
                    detail: detail.clone(),
                });
            report.overall_failure = true;
        },
        KiroPatchAction::FailUnsupportedShape { detail } => {
            report.default_agent.covered = false;
            report.default_agent.failure_reason = Some(
                DefaultAgentFailureReason::UnsupportedDefaultAgentJsonShape {
                    path: target.path.clone(),
                    detail: detail.clone(),
                },
            );
            report.overall_failure = true;
        },
    }

    // Even when the effective default is covered, fail-overall if any other
    // failure reason is present. Failures on non-default targets only
    // surface as warnings — they don't block init by themselves.
    if let Some(reason) = report.default_agent.failure_reason.as_ref() {
        match reason {
            DefaultAgentFailureReason::PatchFailed { .. }
            | DefaultAgentFailureReason::BuiltinDefaultUncovered
            | DefaultAgentFailureReason::DefaultAgentJsonNotFound { .. }
            | DefaultAgentFailureReason::InvalidDefaultAgentJson { .. }
            | DefaultAgentFailureReason::UnsupportedDefaultAgentJsonShape { .. }
            | DefaultAgentFailureReason::NoAgentsAndNoSetDefault => {
                report.overall_failure = true;
            },
        }
    }
}

fn derive_install_status(report: &KiroReport, dry_run: bool) -> InstallStatus {
    let any_change = report.targets.iter().any(|t| {
        matches!(
            t.action,
            KiroPatchAction::AppendedFullCoverage
                | KiroPatchAction::AddedFullCoverageBecauseNarrow
                | KiroPatchAction::CreatedFallbackSkeleton
        )
    }) || report.set_default_applied.is_some();
    if !any_change {
        return InstallStatus::AlreadyPresent;
    }
    if dry_run {
        InstallStatus::WouldInstall
    } else {
        InstallStatus::Installed
    }
}

fn build_install_paths(report: &KiroReport) -> Vec<InstallPath> {
    let mut paths: Vec<InstallPath> = report
        .targets
        .iter()
        .map(|t| InstallPath {
            label: scope_label(t.scope),
            path: t.path.clone(),
        })
        .collect();
    if report.set_default_applied.is_some()
        && let Some(p) = &report.global_settings_path
    {
        paths.push(InstallPath {
            label: "settings",
            path: p.clone(),
        });
    }
    paths
}

fn scope_label(scope: KiroScope) -> &'static str {
    match scope {
        KiroScope::Workspace => "workspace-agent",
        KiroScope::Global => "global-agent",
    }
}

fn patch_existing_agent(path: &Path, command: &str) -> Result<(), InitError> {
    let mut root = read_agent_doc(path)?.unwrap_or_else(default_agent_skeleton_for_existing);
    if !root.is_object() {
        return Err(InitError::Schema {
            path: path.to_path_buf(),
            message: "top-level value must be a JSON object".into(),
        });
    }
    let map = root.as_object_mut().ok_or_else(|| InitError::Schema {
        path: path.to_path_buf(),
        message: "top-level value must be a JSON object".into(),
    })?;

    let hooks = ensure_object_field(map, "hooks").ok_or_else(|| InitError::Schema {
        path: path.to_path_buf(),
        message: "`hooks` must be an object".into(),
    })?;
    let pre_tool_use =
        ensure_array_field(hooks, "preToolUse").ok_or_else(|| InitError::Schema {
            path: path.to_path_buf(),
            message: "`hooks.preToolUse` must be an array".into(),
        })?;

    if pre_tool_use_has_full_coverage(pre_tool_use) {
        return Ok(());
    }

    pre_tool_use.push(hook_entry(command));
    write_json_atomically(path, &root)
}

fn create_fallback_agent(path: &Path, name: &str, command: &str) -> Result<(), InitError> {
    let value = fallback_default_skeleton(name, command);
    write_json_atomically(path, &value)
}

fn write_chat_default_agent(path: &Path, agent_name: &str) -> Result<(), InitError> {
    let mut value: Value = match fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => json!({}),
        Ok(s) => serde_json::from_str(&s).map_err(|e| InitError::Json {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?,
        Err(e) if e.kind() == ErrorKind::NotFound => json!({}),
        Err(e) => {
            return Err(InitError::Io {
                path: path.to_path_buf(),
                source: e,
            });
        },
    };
    let map = value.as_object_mut().ok_or_else(|| InitError::Schema {
        path: path.to_path_buf(),
        message: "top-level value must be a JSON object".into(),
    })?;
    let chat = ensure_object_field(map, "chat").ok_or_else(|| InitError::Schema {
        path: path.to_path_buf(),
        message: "`chat` must be an object".into(),
    })?;
    chat.insert(
        "defaultAgent".to_string(),
        Value::String(agent_name.to_string()),
    );
    write_json_atomically(path, &value)
}

fn pre_tool_use_has_full_coverage(arr: &[Value]) -> bool {
    for entry in arr {
        let Some(cmd) = entry.get("command").and_then(Value::as_str) else {
            continue;
        };
        if !command_invokes_ptuf_hook(cmd) {
            continue;
        }
        let matcher = entry.get("matcher").and_then(Value::as_str);
        if matches!(matcher, None | Some("*")) {
            return true;
        }
    }
    false
}

fn hook_entry(command: &str) -> Value {
    json!({
        "matcher": DEFAULT_MATCHER,
        "command": command,
        "timeout_ms": DEFAULT_TIMEOUT_MS,
        "cache_ttl_seconds": DEFAULT_CACHE_TTL_SECONDS,
    })
}

fn default_agent_skeleton_for_existing() -> Value {
    json!({
        "name": LEGACY_AGENT_NAME,
        "description": "Kiro CLI agent guarded by ptuf PreToolUse policy.",
        "tools": ["*"],
        "includeMcpJson": true,
    })
}

fn fallback_default_skeleton(name: &str, command: &str) -> Value {
    json!({
        "name": name,
        "description": "Default Kiro CLI agent guarded by ptuf PreToolUse policy.",
        "tools": ["*"],
        "includeMcpJson": true,
        "resources": [
            "skill://.kiro/skills/*/SKILL.md",
            "skill://~/.kiro/skills/*/SKILL.md",
        ],
        "hooks": {
            "preToolUse": [hook_entry(command)],
        },
    })
}

pub(crate) fn command_invokes_ptuf_hook(cmd: &str) -> bool {
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let n = tokens.len();
    if n < COMMAND_TAIL.len() {
        return false;
    }
    tokens[n - COMMAND_TAIL.len()..] == *COMMAND_TAIL
}

/// Back-compat helper retained for `self_paths.rs`. Returns every
/// `command` string from `hooks.preToolUse[]`.
pub(crate) fn pre_tool_use_commands(root: &Value) -> Vec<String> {
    let Some(arr) = root.pointer("/hooks/preToolUse").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in arr {
        if let Some(s) = entry.get("command").and_then(Value::as_str) {
            out.push(s.to_string());
        }
    }
    out
}

fn ensure_object_field<'a>(
    map: &'a mut Map<String, Value>,
    key: &str,
) -> Option<&'a mut Map<String, Value>> {
    map.entry(key.to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
}

fn ensure_array_field<'a>(
    map: &'a mut Map<String, Value>,
    key: &str,
) -> Option<&'a mut Vec<Value>> {
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

    fn touch(path: &Path, body: &str) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn agent_doc_with_matcher(matcher: Option<&str>, cmd: &str) -> String {
        let entry = if let Some(m) = matcher {
            json!({"matcher": m, "command": cmd})
        } else {
            json!({"command": cmd})
        };
        serde_json::to_string_pretty(&json!({
            "name": "x",
            "hooks": {"preToolUse": [entry]},
        }))
        .unwrap()
    }

    #[test]
    fn shell_quote_handles_spaces_and_quotes() {
        assert_eq!(shell_quote("/usr/local/bin/ptuf"), "'/usr/local/bin/ptuf'");
        assert_eq!(
            shell_quote("/Applications/My Tools/ptuf"),
            "'/Applications/My Tools/ptuf'"
        );
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn resolve_global_root_prefers_kiro_home_when_set() {
        let env = Environment {
            home: Some(PathBuf::from("/h")),
            kiro_home: Some(PathBuf::from("/k")),
        };
        assert_eq!(resolve_global_root(&env), Some(PathBuf::from("/k")));
    }

    #[test]
    fn resolve_global_root_falls_back_to_home_dot_kiro() {
        let env = Environment {
            home: Some(PathBuf::from("/h")),
            kiro_home: None,
        };
        assert_eq!(resolve_global_root(&env), Some(PathBuf::from("/h/.kiro")));
    }

    #[test]
    fn coverage_full_when_matcher_omitted() {
        let v: Value = serde_json::from_str(&agent_doc_with_matcher(
            None,
            "'/usr/local/bin/ptuf' hook kiro",
        ))
        .unwrap();
        assert_eq!(coverage(&v), Coverage::Full);
    }

    #[test]
    fn coverage_full_when_matcher_is_star() {
        let v: Value = serde_json::from_str(&agent_doc_with_matcher(
            Some("*"),
            "'/usr/local/bin/ptuf' hook kiro",
        ))
        .unwrap();
        assert_eq!(coverage(&v), Coverage::Full);
    }

    #[test]
    fn coverage_narrow_when_matcher_is_specific_tool() {
        let v: Value = serde_json::from_str(&agent_doc_with_matcher(
            Some("fs_write"),
            "'/usr/local/bin/ptuf' hook kiro",
        ))
        .unwrap();
        assert_eq!(coverage(&v), Coverage::Narrow);
    }

    #[test]
    fn coverage_none_when_command_is_not_ptuf() {
        let v: Value = serde_json::from_str(&agent_doc_with_matcher(
            Some("*"),
            "/usr/bin/something-else",
        ))
        .unwrap();
        assert_eq!(coverage(&v), Coverage::None);
    }

    #[test]
    fn plan_enumerates_workspace_agents_and_resolves_default() {
        let dir = workdir("plan-enumerate");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let agents = dir.join(".kiro/agents");
        fs::create_dir_all(&agents).unwrap();
        touch(&agents.join("architect.json"), r#"{"name": "architect"}"#);
        touch(&agents.join("reviewer.json"), r#"{"name": "reviewer"}"#);
        touch(&agents.join("notes.md"), "# not an agent");

        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        fs::write(
            home.join(".kiro/settings/cli.json"),
            r#"{"chat": {"defaultAgent": "architect"}}"#,
        )
        .unwrap();

        let env = Environment {
            home: Some(home.clone()),
            kiro_home: None,
        };
        let plan = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions::default(),
            "/usr/local/bin/ptuf",
        )
        .unwrap();

        assert_eq!(plan.targets.len(), 2);
        let names: Vec<_> = plan.targets.iter().map(|t| t.name.clone()).collect();
        assert!(names.contains(&"architect".to_string()));
        assert!(names.contains(&"reviewer".to_string()));
        // workspace agents dir takes precedence; architect resolved there.
        let arch = plan.targets.iter().find(|t| t.name == "architect").unwrap();
        assert!(arch.is_effective_default);
        assert!(matches!(arch.action, KiroPatchAction::AppendedFullCoverage));
        // .md was skipped.
        assert_eq!(plan.skipped_non_json.len(), 1);
        assert!(
            plan.skipped_non_json[0]
                .to_string_lossy()
                .ends_with("notes.md")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_writes_full_coverage_entry_to_existing_agent() {
        let dir = workdir("install-existing");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let agents = dir.join(".kiro/agents");
        fs::create_dir_all(&agents).unwrap();
        let arch = agents.join("architect.json");
        touch(&arch, r#"{"name": "architect"}"#);

        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        fs::write(
            home.join(".kiro/settings/cli.json"),
            r#"{"chat": {"defaultAgent": "architect"}}"#,
        )
        .unwrap();

        let env = Environment {
            home: Some(home),
            kiro_home: None,
        };
        let p = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions::default(),
            "/usr/local/bin/ptuf",
        )
        .unwrap();
        let outcome = install(&p, false).unwrap();
        let report = outcome.kiro_report.expect("report");
        assert!(!report.overall_failure, "report: {report:?}");
        assert!(report.default_agent.covered);

        let body = fs::read_to_string(&arch).unwrap();
        let parsed: Value = serde_json::from_str(&body).unwrap();
        let arr = parsed
            .pointer("/hooks/preToolUse")
            .and_then(Value::as_array)
            .expect("array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "*");
        assert!(arr[0]["command"].as_str().unwrap().contains("hook kiro"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_keeps_narrow_entry_and_appends_full_coverage() {
        let dir = workdir("install-narrow");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let agents = dir.join(".kiro/agents");
        fs::create_dir_all(&agents).unwrap();
        let arch = agents.join("architect.json");
        touch(
            &arch,
            r#"{"name":"x","hooks":{"preToolUse":[{"matcher":"fs_write","command":"'/usr/local/bin/ptuf' hook kiro"}]}}"#,
        );
        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        fs::write(
            home.join(".kiro/settings/cli.json"),
            r#"{"chat": {"defaultAgent": "architect"}}"#,
        )
        .unwrap();

        let env = Environment {
            home: Some(home),
            kiro_home: None,
        };
        let p = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions::default(),
            "/usr/local/bin/ptuf",
        )
        .unwrap();
        let outcome = install(&p, false).unwrap();
        let report = outcome.kiro_report.unwrap();
        assert_eq!(report.narrow_coverage_repaired_count(), 1);
        assert!(report.default_agent.covered);

        let body = fs::read_to_string(&arch).unwrap();
        let parsed: Value = serde_json::from_str(&body).unwrap();
        let arr = parsed
            .pointer("/hooks/preToolUse")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(
            arr.len(),
            2,
            "narrow entry must be kept and a star entry appended"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_no_op_when_already_full_coverage() {
        let dir = workdir("install-already-full");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let agents = dir.join(".kiro/agents");
        fs::create_dir_all(&agents).unwrap();
        let arch = agents.join("architect.json");
        touch(
            &arch,
            r#"{"name":"x","hooks":{"preToolUse":[{"command":"'/usr/local/bin/ptuf' hook kiro"}]}}"#,
        );
        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        fs::write(
            home.join(".kiro/settings/cli.json"),
            r#"{"chat": {"defaultAgent": "architect"}}"#,
        )
        .unwrap();

        let env = Environment {
            home: Some(home),
            kiro_home: None,
        };
        let p = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions::default(),
            "/usr/local/bin/ptuf",
        )
        .unwrap();
        let before = fs::read_to_string(&arch).unwrap();
        let outcome = install(&p, false).unwrap();
        let after = fs::read_to_string(&arch).unwrap();
        assert_eq!(before, after);
        let report = outcome.kiro_report.unwrap();
        assert_eq!(report.already_full_coverage_count(), 1);
        assert!(report.default_agent.covered);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_fails_when_builtin_default_is_uncovered() {
        let dir = workdir("install-builtin-default");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let agents = dir.join(".kiro/agents");
        fs::create_dir_all(&agents).unwrap();
        touch(&agents.join("architect.json"), r#"{"name":"architect"}"#);
        // settings/cli.json has no chat.defaultAgent.
        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        fs::write(home.join(".kiro/settings/cli.json"), r#"{"chat": {}}"#).unwrap();

        let env = Environment {
            home: Some(home),
            kiro_home: None,
        };
        let p = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions::default(),
            "/usr/local/bin/ptuf",
        )
        .unwrap();
        let outcome = install(&p, false).unwrap();
        let report = outcome.kiro_report.unwrap();
        assert!(report.overall_failure);
        assert!(matches!(
            report.default_agent.failure_reason,
            Some(DefaultAgentFailureReason::BuiltinDefaultUncovered)
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_creates_fallback_default_when_set_default_default() {
        let dir = workdir("install-fallback-default");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/agents")).unwrap();
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        let env = Environment {
            home: Some(home.clone()),
            kiro_home: None,
        };
        let p = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions {
                set_default: Some("default".to_string()),
                ..KiroOptions::default()
            },
            "/usr/local/bin/ptuf",
        )
        .unwrap();
        let outcome = install(&p, false).unwrap();
        let report = outcome.kiro_report.unwrap();
        let default_path = home.join(".kiro/agents/default.json");
        assert!(default_path.is_file());
        assert!(report.default_agent.covered);
        assert_eq!(report.set_default_applied.as_deref(), Some("default"));
        // ptuf-guarded.json must NOT have been created.
        assert!(!home.join(".kiro/agents/ptuf-guarded.json").exists());
        // chat.defaultAgent updated in settings.
        let body = fs::read_to_string(home.join(".kiro/settings/cli.json")).unwrap();
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["chat"]["defaultAgent"], "default");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_records_invalid_json_targets_as_failure_on_default() {
        let dir = workdir("install-invalid-json");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let agents = dir.join(".kiro/agents");
        fs::create_dir_all(&agents).unwrap();
        let broken = agents.join("broken.json");
        touch(&broken, "{not json");
        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        fs::write(
            home.join(".kiro/settings/cli.json"),
            r#"{"chat": {"defaultAgent": "broken"}}"#,
        )
        .unwrap();
        let env = Environment {
            home: Some(home),
            kiro_home: None,
        };
        let p = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions::default(),
            "/usr/local/bin/ptuf",
        )
        .unwrap();
        let before = fs::read_to_string(&broken).unwrap();
        let outcome = install(&p, false).unwrap();
        let after = fs::read_to_string(&broken).unwrap();
        assert_eq!(before, after, "broken.json must not be modified");
        let report = outcome.kiro_report.unwrap();
        assert!(report.overall_failure);
        assert!(matches!(
            report.default_agent.failure_reason,
            Some(DefaultAgentFailureReason::InvalidDefaultAgentJson { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_agent_mode_targets_only_ptuf_guarded() {
        let dir = workdir("new-agent");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let agents = dir.join(".kiro/agents");
        fs::create_dir_all(&agents).unwrap();
        touch(&agents.join("architect.json"), r#"{"name":"architect"}"#);
        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        let env = Environment {
            home: Some(home),
            kiro_home: None,
        };
        let p = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions {
                new_agent: true,
                ..KiroOptions::default()
            },
            "/usr/local/bin/ptuf",
        )
        .unwrap();
        // Only ptuf-guarded.json should be in targets.
        assert_eq!(p.targets.len(), 1);
        assert_eq!(p.targets[0].name, LEGACY_AGENT_NAME);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_with_new_agent_and_set_default_writes_settings() {
        let dir = workdir("new-agent-set-default");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/agents")).unwrap();
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        let env = Environment {
            home: Some(home.clone()),
            kiro_home: None,
        };
        let p = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions {
                new_agent: true,
                set_default: Some("ptuf-guarded".to_string()),
                ..KiroOptions::default()
            },
            "/usr/local/bin/ptuf",
        )
        .unwrap();
        let outcome = install(&p, false).unwrap();
        let report = outcome.kiro_report.unwrap();
        // ptuf-guarded.json gets created (workspace scope).
        let pg = dir.join(".kiro/agents/ptuf-guarded.json");
        assert!(pg.is_file());
        assert_eq!(report.set_default_applied.as_deref(), Some("ptuf-guarded"));
        let body = fs::read_to_string(home.join(".kiro/settings/cli.json")).unwrap();
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["chat"]["defaultAgent"], "ptuf-guarded");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn workspace_only_ignores_global() {
        let dir = workdir("workspace-only");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let agents = dir.join(".kiro/agents");
        fs::create_dir_all(&agents).unwrap();
        touch(&agents.join("architect.json"), r#"{"name":"architect"}"#);

        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/agents")).unwrap();
        touch(
            &home.join(".kiro/agents/global-other.json"),
            r#"{"name":"global-other"}"#,
        );
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        fs::write(
            home.join(".kiro/settings/cli.json"),
            r#"{"chat":{"defaultAgent":"architect"}}"#,
        )
        .unwrap();

        let env = Environment {
            home: Some(home),
            kiro_home: None,
        };
        let p = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions {
                workspace_only: true,
                ..KiroOptions::default()
            },
            "/usr/local/bin/ptuf",
        )
        .unwrap();
        assert!(p.global_agents_dir.is_none());
        assert!(p.global_settings_path.is_none());
        assert!(p.targets.iter().all(|t| t.scope == KiroScope::Workspace));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_tool_use_commands_back_compat_returns_command_strings() {
        let root = json!({
            "hooks": {
                "preToolUse": [
                    {"command": "'/x/ptuf' hook kiro"},
                    {"command": "/y/ptuf hook kiro"},
                ]
            }
        });
        let cmds = pre_tool_use_commands(&root);
        assert_eq!(cmds.len(), 2);
        assert!(cmds[0].contains("hook kiro"));
    }

    #[test]
    fn command_invokes_ptuf_hook_matches_trailing_tokens() {
        assert!(command_invokes_ptuf_hook("/x/ptuf hook kiro"));
        assert!(command_invokes_ptuf_hook("'/usr/local/bin/ptuf' hook kiro"));
        assert!(command_invokes_ptuf_hook("ptuf hook kiro   "));
        assert!(!command_invokes_ptuf_hook("ptuf hook codex"));
        assert!(!command_invokes_ptuf_hook("ptuf"));
    }

    #[test]
    fn observed_workspace_settings_is_diagnostic_only() {
        let dir = workdir("workspace-settings-diag");
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::create_dir_all(dir.join(".kiro/settings")).unwrap();
        fs::write(
            dir.join(".kiro/settings/cli.json"),
            r#"{"chat":{"defaultAgent":"workspace-only-agent"}}"#,
        )
        .unwrap();
        let agents = dir.join(".kiro/agents");
        fs::create_dir_all(&agents).unwrap();
        touch(&agents.join("architect.json"), r#"{"name":"architect"}"#);

        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro/settings")).unwrap();
        fs::write(
            home.join(".kiro/settings/cli.json"),
            r#"{"chat":{"defaultAgent":"architect"}}"#,
        )
        .unwrap();
        let env = Environment {
            home: Some(home),
            kiro_home: None,
        };
        let p = plan(
            Some(dir.as_path()),
            &env,
            &KiroOptions::default(),
            "/usr/local/bin/ptuf",
        )
        .unwrap();
        // workspace settings observed but NOT used for resolution.
        assert!(p.observed_workspace_settings.is_some());
        // architect (from global settings) is the effective default.
        assert!(
            p.targets
                .iter()
                .any(|t| t.name == "architect" && t.is_effective_default)
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
