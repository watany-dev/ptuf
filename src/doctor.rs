//! `ptuf doctor` — diagnostic report rendered as plain text.
//!
//! Each section can independently report ✓ (ok), ⚠ (warning that
//! does not fail the run), or ✗ (failure). The CLI exits 1 when at
//! least one ✗ surfaced, otherwise 0
//! (`docs/design/cli-and-hooks.md:23-36`).
//!
//! [`Report::gather`] takes every external dependency as a parameter
//! so tests can drive every render arm without touching real env
//! state. [`render_doctor`] performs the production discovery (current
//! exe, repo root, default scope layout, default Claude settings path)
//! and feeds the result to [`Report::gather`] + [`Report::render`].

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use crate::config::scope::Layout;
use crate::config::{self, Config, ConfigError};
use crate::init::{claude_code, codex};
use crate::plugin::{self, PluginError};

/// Schema version for `doctor --json` output. Bumped only on
/// incompatible field changes; additive fields keep version 1.
pub const DOCTOR_JSON_SCHEMA_VERSION: u32 = 1;

/// Fully-built diagnostic report.
pub struct Report {
    pub binary: BinaryInfo,
    pub project: ProjectInfo,
    pub layout: Layout,
    pub config: ConfigStatus,
    pub plugins: Vec<PluginStatus>,
    pub claude: ClaudeStatus,
    pub codex: CodexStatus,
}

/// Information about the running binary.
pub struct BinaryInfo {
    pub path: Option<PathBuf>,
    pub version: &'static str,
}

/// Project-scope discovery result.
pub struct ProjectInfo {
    pub repo_root: Option<PathBuf>,
}

/// Layered configuration load outcome.
pub enum ConfigStatus {
    Loaded(Config),
    Failed(ConfigError),
}

/// Per-plugin load outcome.
pub enum PluginStatus {
    Loaded {
        path: PathBuf,
        name: String,
        version: String,
        rule_count: usize,
    },
    Failed {
        path: PathBuf,
        error: PluginError,
    },
}

/// Claude Code integration check.
pub struct ClaudeStatus {
    /// The path we inspected (`None` when `$HOME` is unset).
    pub settings_path: Option<PathBuf>,
    pub state: ClaudeState,
}

/// Codex integration check.
pub struct CodexStatus {
    pub config_path: Option<PathBuf>,
    pub hooks_path: Option<PathBuf>,
    pub state: CodexState,
}

pub struct CodexPaths {
    pub config_path: Option<PathBuf>,
    pub hooks_path: Option<PathBuf>,
}

pub enum ClaudeState {
    /// `$HOME` is unset, so we never tried to read any path.
    HomeNotSet,
    /// Settings file does not exist on disk.
    Missing,
    /// File present, parses, ptuf hook entry registered.
    HookRegistered { matcher: Option<String> },
    /// File present and parses but no ptuf hook is registered.
    HookMissing,
    /// File present but JSON is invalid or has the wrong shape.
    InvalidJson(String),
    /// I/O error reading the file.
    Io(String),
}

pub enum CodexState {
    HomeNotSet,
    ConfigMissing,
    HooksMissing,
    HooksDisabled,
    HookRegistered { matcher: Option<String> },
    HookMissing,
    InvalidConfig(String),
    InvalidHooks(String),
    Io(String),
}

impl Report {
    /// Build a report from already-resolved inputs.
    ///
    /// The caller is responsible for discovering everything (binary
    /// path, repo root, layout, claude settings path); this keeps the
    /// function pure and trivially testable.
    pub fn gather(
        binary_path: Option<PathBuf>,
        repo_root: Option<PathBuf>,
        layout: Layout,
        claude_settings_path: Option<PathBuf>,
    ) -> Self {
        let codex_paths = repo_root.as_ref().map_or(
            CodexPaths {
                config_path: None,
                hooks_path: None,
            },
            |root| CodexPaths {
                config_path: Some(root.join(".codex/config.toml")),
                hooks_path: Some(root.join(".codex/hooks.json")),
            },
        );
        Self::gather_with_codex(
            binary_path,
            repo_root,
            layout,
            claude_settings_path,
            codex_paths,
        )
    }

    pub fn gather_with_codex(
        binary_path: Option<PathBuf>,
        repo_root: Option<PathBuf>,
        layout: Layout,
        claude_settings_path: Option<PathBuf>,
        codex_paths: CodexPaths,
    ) -> Self {
        let config_status = match config::load_with_layout(layout.clone()) {
            Ok(c) => ConfigStatus::Loaded(c),
            Err(e) => ConfigStatus::Failed(e),
        };

        let plugin_paths: Vec<PathBuf> = match &config_status {
            ConfigStatus::Loaded(c) => c.plugin_paths.clone(),
            ConfigStatus::Failed(_) => Vec::new(),
        };
        let plugins = plugin_paths.into_iter().map(plugin_status_for).collect();

        let claude = build_claude_status(claude_settings_path.as_deref());
        let codex = build_codex_status(
            codex_paths.config_path.as_deref(),
            codex_paths.hooks_path.as_deref(),
        );

        Self {
            binary: BinaryInfo {
                path: binary_path,
                version: env!("CARGO_PKG_VERSION"),
            },
            project: ProjectInfo { repo_root },
            layout,
            config: config_status,
            plugins,
            claude: ClaudeStatus {
                settings_path: claude_settings_path,
                state: claude,
            },
            codex: CodexStatus {
                config_path: codex_paths.config_path,
                hooks_path: codex_paths.hooks_path,
                state: codex,
            },
        }
    }

    /// `true` when at least one section reports ✗.
    pub fn has_failure(&self) -> bool {
        if matches!(self.config, ConfigStatus::Failed(_)) {
            return true;
        }
        if self
            .plugins
            .iter()
            .any(|p| matches!(p, PluginStatus::Failed { .. }))
        {
            return true;
        }
        matches!(
            self.claude.state,
            ClaudeState::InvalidJson(_) | ClaudeState::Io(_)
        ) || matches!(
            self.codex.state,
            CodexState::InvalidConfig(_) | CodexState::InvalidHooks(_) | CodexState::Io(_)
        )
    }

    /// Render the report to `w`. Returns the number of bytes written
    /// for symmetry with other `render_*` helpers; callers that just
    /// want exit-code semantics use [`Self::has_failure`].
    pub fn render<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "ptuf doctor")?;
        writeln!(w)?;
        self.render_binary(w)?;
        self.render_project(w)?;
        self.render_effective_config(w)?;
        self.render_plugins(w)?;
        self.render_claude(w)?;
        self.render_codex(w)?;
        Ok(())
    }

    fn render_binary<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "Binary")?;
        match &self.binary.path {
            Some(p) => writeln!(w, "  ✓ {}  (version {})", p.display(), self.binary.version)?,
            None => writeln!(
                w,
                "  ⚠ binary path unavailable (version {})",
                self.binary.version
            )?,
        }
        writeln!(w)?;
        Ok(())
    }

    fn render_project<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "Project")?;
        match &self.project.repo_root {
            Some(p) => writeln!(w, "  ✓ repository root: {}", p.display())?,
            None => writeln!(w, "  ⚠ no repository root detected (run from a git repo)")?,
        }
        match &self.config {
            ConfigStatus::Loaded(_) => {
                let layers = self.layout.ordered_paths();
                let present = layers.iter().filter(|p| p.is_file()).count();
                writeln!(
                    w,
                    "  ✓ config layers loaded ({} scopes considered, {} file{} present)",
                    layers.len(),
                    present,
                    if present == 1 { "" } else { "s" }
                )?;
                for path in &layers {
                    let label = if path.is_file() {
                        "loaded"
                    } else {
                        "not found"
                    };
                    writeln!(w, "       {:<60} ({label})", path.display().to_string())?;
                }
            }
            ConfigStatus::Failed(err) => {
                writeln!(w, "  ✗ config load failed: {err}")?;
            }
        }
        writeln!(w)?;
        Ok(())
    }

    fn render_effective_config<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "Effective config")?;
        match &self.config {
            ConfigStatus::Loaded(c) => {
                writeln!(w, "  mode:        {}", mode_label(c.mode))?;
                writeln!(w, "  failClosed:  {}", c.fail_closed)?;
                let audit_path = crate::config::resolved_audit_path(c)
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(disabled)".to_string());
                writeln!(w, "  audit.path:  {audit_path}")?;
            }
            ConfigStatus::Failed(_) => {
                writeln!(w, "  ✗ unavailable (see Project section)")?;
            }
        }
        writeln!(w)?;
        Ok(())
    }

    fn render_plugins<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "Plugins ({})", self.plugins.len())?;
        if self.plugins.is_empty() {
            writeln!(w, "  (no plugin_paths configured)")?;
        }
        for status in &self.plugins {
            match status {
                PluginStatus::Loaded {
                    path,
                    name,
                    version,
                    rule_count,
                } => writeln!(
                    w,
                    "  ✓ {}  ({name} {version}, {rule_count} rule{})",
                    path.display(),
                    if *rule_count == 1 { "" } else { "s" }
                )?,
                PluginStatus::Failed { path, error } => {
                    writeln!(w, "  ✗ {}: {error}", path.display())?;
                }
            }
        }
        writeln!(w)?;
        Ok(())
    }

    fn render_claude<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "Claude Code integration")?;
        match (&self.claude.settings_path, &self.claude.state) {
            (None, _) | (_, ClaudeState::HomeNotSet) => {
                writeln!(
                    w,
                    "  ⚠ $HOME not set; cannot locate ~/.claude/settings.json"
                )?;
            }
            (Some(path), ClaudeState::Missing) => {
                writeln!(
                    w,
                    "  ⚠ {} not present (run `ptuf init claude-code`)",
                    path.display()
                )?;
            }
            (Some(path), ClaudeState::HookRegistered { matcher }) => {
                writeln!(w, "  ✓ {} present", path.display())?;
                let matcher = matcher
                    .as_deref()
                    .map(|m| format!(" (matcher: {m:?})"))
                    .unwrap_or_default();
                writeln!(w, "  ✓ ptuf hook registered{matcher}")?;
            }
            (Some(path), ClaudeState::HookMissing) => {
                writeln!(w, "  ✓ {} present", path.display())?;
                writeln!(
                    w,
                    "  ⚠ no ptuf hook registered (run `ptuf init claude-code`)"
                )?;
            }
            (Some(path), ClaudeState::InvalidJson(msg)) => {
                writeln!(w, "  ✗ {} invalid JSON: {msg}", path.display())?;
            }
            (Some(path), ClaudeState::Io(msg)) => {
                writeln!(w, "  ✗ {} unreadable: {msg}", path.display())?;
            }
        }
        Ok(())
    }

    fn render_codex<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w)?;
        writeln!(w, "Codex integration")?;
        match (
            &self.codex.config_path,
            &self.codex.hooks_path,
            &self.codex.state,
        ) {
            (_, _, CodexState::HomeNotSet) => {
                writeln!(
                    w,
                    "  ⚠ $HOME not set and no repository root detected; cannot locate Codex hook files"
                )?;
            }
            (Some(config_path), _, CodexState::ConfigMissing) => {
                writeln!(
                    w,
                    "  ⚠ {} not present (run `ptuf init codex`)",
                    config_path.display()
                )?;
            }
            (_, Some(hooks_path), CodexState::HooksMissing) => {
                writeln!(
                    w,
                    "  ⚠ {} not present (run `ptuf init codex`)",
                    hooks_path.display()
                )?;
            }
            (Some(config_path), Some(hooks_path), CodexState::HooksDisabled) => {
                writeln!(w, "  ✓ {} present", config_path.display())?;
                writeln!(w, "  ✓ {} present", hooks_path.display())?;
                writeln!(
                    w,
                    "  ⚠ features.codex_hooks is disabled (run `ptuf init codex`)"
                )?;
            }
            (Some(config_path), Some(hooks_path), CodexState::HookRegistered { matcher }) => {
                writeln!(w, "  ✓ {} present", config_path.display())?;
                writeln!(w, "  ✓ {} present", hooks_path.display())?;
                let matcher = matcher
                    .as_deref()
                    .map(|m| format!(" (matcher: {m:?})"))
                    .unwrap_or_default();
                writeln!(w, "  ✓ ptuf hook registered{matcher}")?;
            }
            (Some(config_path), Some(hooks_path), CodexState::HookMissing) => {
                writeln!(w, "  ✓ {} present", config_path.display())?;
                writeln!(w, "  ✓ {} present", hooks_path.display())?;
                writeln!(w, "  ⚠ no ptuf hook registered (run `ptuf init codex`)")?;
            }
            (Some(config_path), _, CodexState::InvalidConfig(msg)) => {
                writeln!(w, "  ✗ {} invalid TOML: {msg}", config_path.display())?;
            }
            (_, Some(hooks_path), CodexState::InvalidHooks(msg)) => {
                writeln!(w, "  ✗ {} invalid JSON: {msg}", hooks_path.display())?;
            }
            (Some(config_path), _, CodexState::Io(msg)) => {
                writeln!(w, "  ✗ {} unreadable: {msg}", config_path.display())?;
            }
            (_, Some(hooks_path), CodexState::Io(msg)) => {
                writeln!(w, "  ✗ {} unreadable: {msg}", hooks_path.display())?;
            }
            _ => {}
        }
        Ok(())
    }
}

fn mode_label(mode: config::Mode) -> &'static str {
    match mode {
        config::Mode::Enforce => "enforce",
        config::Mode::Monitor => "monitor",
        config::Mode::Observe => "observe",
    }
}

fn plugin_status_for(path: PathBuf) -> PluginStatus {
    match plugin::load_path(&path) {
        Ok(loaded) => PluginStatus::Loaded {
            path,
            name: loaded.name,
            version: loaded.version,
            rule_count: loaded.rules.len(),
        },
        Err(error) => PluginStatus::Failed { path, error },
    }
}

fn build_claude_status(path: Option<&Path>) -> ClaudeState {
    let Some(path) = path else {
        return ClaudeState::HomeNotSet;
    };
    let body = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ClaudeState::Missing,
        Err(e) => return ClaudeState::Io(e.to_string()),
    };
    if body.trim().is_empty() {
        return ClaudeState::HookMissing;
    }
    let value: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return ClaudeState::InvalidJson(e.to_string()),
    };
    let Some(arr) = value.pointer("/hooks/PreToolUse").and_then(Value::as_array) else {
        return ClaudeState::HookMissing;
    };
    for entry in arr {
        let commands = crate::init::claude_code::entry_commands(entry);
        if commands
            .iter()
            .any(|cmd| crate::init::claude_code::command_invokes_ptuf_hook(cmd))
        {
            let matcher = entry
                .get("matcher")
                .and_then(Value::as_str)
                .map(str::to_string);
            return ClaudeState::HookRegistered { matcher };
        }
    }
    ClaudeState::HookMissing
}

fn build_codex_status(config_path: Option<&Path>, hooks_path: Option<&Path>) -> CodexState {
    let (Some(config_path), Some(hooks_path)) = (config_path, hooks_path) else {
        return CodexState::HomeNotSet;
    };

    let config_body = match fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return CodexState::ConfigMissing,
        Err(e) => return CodexState::Io(e.to_string()),
    };
    let config_doc = match config_body.parse::<toml_edit::DocumentMut>() {
        Ok(doc) => doc,
        Err(e) => return CodexState::InvalidConfig(e.to_string()),
    };

    let hooks_enabled = config_doc["features"]
        .as_table_like()
        .and_then(|table| table.get("codex_hooks"))
        .and_then(|item| item.as_bool())
        == Some(true);
    if !hooks_enabled {
        return CodexState::HooksDisabled;
    }

    let hooks_body = match fs::read_to_string(hooks_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return CodexState::HooksMissing,
        Err(e) => return CodexState::Io(e.to_string()),
    };
    let hooks_value: Value = match serde_json::from_str(&hooks_body) {
        Ok(v) => v,
        Err(e) => return CodexState::InvalidHooks(e.to_string()),
    };

    let Some(arr) = hooks_value
        .pointer("/hooks/PreToolUse")
        .and_then(Value::as_array)
    else {
        return CodexState::HookMissing;
    };
    for entry in arr {
        let commands = crate::init::codex::entry_commands(entry);
        if commands
            .iter()
            .any(|cmd| crate::init::codex::command_invokes_ptuf_hook(cmd))
        {
            let matcher = entry
                .get("matcher")
                .and_then(Value::as_str)
                .map(str::to_string);
            return CodexState::HookRegistered { matcher };
        }
    }
    CodexState::HookMissing
}

/// Production entry point: discover everything from the live process
/// environment and write the rendered report to `stdout`.
pub fn render_doctor<W: Write>(stdout: &mut W) -> std::io::Result<bool> {
    let report = gather_live_report();
    report.render(stdout)?;
    Ok(report.has_failure())
}

/// JSON variant of [`render_doctor`]. Writes a stable, machine-readable
/// `JsonReport` to `stdout` (`docs/design/cli-and-hooks.md`).
pub fn render_doctor_json<W: Write>(stdout: &mut W) -> std::io::Result<bool> {
    let report = gather_live_report();
    let json = report.to_json();
    serde_json::to_writer_pretty(&mut *stdout, &json).map_err(std::io::Error::other)?;
    writeln!(stdout)?;
    Ok(report.has_failure())
}

fn gather_live_report() -> Report {
    let binary_path = std::env::current_exe().ok();
    let cwd = std::env::current_dir().ok();
    let repo_root = cwd.as_deref().and_then(crate::config::repo::discover);
    let layout = config::scope::default_layout(repo_root.as_deref());
    let claude_settings_path = claude_code::default_settings_path();
    let codex_paths = if let Some(root) = repo_root.as_ref() {
        CodexPaths {
            config_path: Some(root.join(".codex/config.toml")),
            hooks_path: Some(root.join(".codex/hooks.json")),
        }
    } else {
        CodexPaths {
            config_path: codex::default_home_config_path(),
            hooks_path: codex::default_home_hooks_path(),
        }
    };
    Report::gather_with_codex(
        binary_path,
        repo_root,
        layout,
        claude_settings_path,
        codex_paths,
    )
}

/// Shadow types whose only job is to give the doctor report a stable
/// JSON shape without forcing `Serialize` onto `Config`, `PluginError`,
/// or `Layout`.
#[derive(Debug, Serialize)]
pub struct JsonReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub binary: JsonBinary,
    pub project: JsonProject,
    #[serde(rename = "configLayers")]
    pub config_layers: Vec<JsonConfigLayer>,
    pub config: JsonConfig,
    pub plugins: Vec<JsonPlugin>,
    pub claude: JsonClaude,
    pub codex: JsonCodex,
    #[serde(rename = "hasFailure")]
    pub has_failure: bool,
}

#[derive(Debug, Serialize)]
pub struct JsonBinary {
    pub path: Option<String>,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct JsonProject {
    #[serde(rename = "repoRoot")]
    pub repo_root: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JsonConfigLayer {
    pub layer: &'static str,
    pub path: String,
    pub present: bool,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum JsonConfig {
    Loaded {
        loaded: bool, // always true; kept for explicit shape
        mode: &'static str,
        #[serde(rename = "failClosed")]
        fail_closed: bool,
        #[serde(rename = "auditPath")]
        audit_path: Option<String>,
    },
    Failed {
        loaded: bool, // always false
        error: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum JsonPlugin {
    Loaded {
        loaded: bool, // always true
        path: String,
        name: String,
        version: String,
        #[serde(rename = "ruleCount")]
        rule_count: usize,
    },
    Failed {
        loaded: bool, // always false
        path: String,
        error: String,
    },
}

#[derive(Debug, Serialize)]
pub struct JsonClaude {
    #[serde(rename = "settingsPath")]
    pub settings_path: Option<String>,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JsonCodex {
    #[serde(rename = "configPath")]
    pub config_path: Option<String>,
    #[serde(rename = "hooksPath")]
    pub hooks_path: Option<String>,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Report {
    /// Build the JSON projection of this report. Pure transformation;
    /// no I/O, no environment lookups.
    pub fn to_json(&self) -> JsonReport {
        let has_failure = self.has_failure();
        JsonReport {
            schema_version: DOCTOR_JSON_SCHEMA_VERSION,
            binary: JsonBinary {
                path: self.binary.path.as_ref().map(|p| p.display().to_string()),
                version: self.binary.version,
            },
            project: JsonProject {
                repo_root: self
                    .project
                    .repo_root
                    .as_ref()
                    .map(|p| p.display().to_string()),
            },
            config_layers: build_config_layers(&self.layout),
            config: match &self.config {
                ConfigStatus::Loaded(c) => JsonConfig::Loaded {
                    loaded: true,
                    mode: mode_label(c.mode),
                    fail_closed: c.fail_closed,
                    audit_path: crate::config::resolved_audit_path(c)
                        .as_ref()
                        .map(|p| p.display().to_string()),
                },
                ConfigStatus::Failed(err) => JsonConfig::Failed {
                    loaded: false,
                    error: err.to_string(),
                },
            },
            plugins: self
                .plugins
                .iter()
                .map(|p| match p {
                    PluginStatus::Loaded {
                        path,
                        name,
                        version,
                        rule_count,
                    } => JsonPlugin::Loaded {
                        loaded: true,
                        path: path.display().to_string(),
                        name: name.clone(),
                        version: version.clone(),
                        rule_count: *rule_count,
                    },
                    PluginStatus::Failed { path, error } => JsonPlugin::Failed {
                        loaded: false,
                        path: path.display().to_string(),
                        error: error.to_string(),
                    },
                })
                .collect(),
            claude: build_json_claude(&self.claude),
            codex: build_json_codex(&self.codex),
            has_failure,
        }
    }
}

fn build_config_layers(layout: &Layout) -> Vec<JsonConfigLayer> {
    let mut out = Vec::with_capacity(4);
    let entries: [(&'static str, Option<&PathBuf>); 4] = [
        ("system", layout.system.as_ref()),
        ("user", layout.user.as_ref()),
        ("project", layout.project.as_ref()),
        ("projectLocal", layout.project_local.as_ref()),
    ];
    for (layer, path) in entries {
        if let Some(p) = path {
            out.push(JsonConfigLayer {
                layer,
                path: p.display().to_string(),
                present: p.is_file(),
            });
        }
    }
    out
}

fn build_json_claude(status: &ClaudeStatus) -> JsonClaude {
    let settings_path = status
        .settings_path
        .as_ref()
        .map(|p| p.display().to_string());
    let (state, matcher, error) = match &status.state {
        ClaudeState::HomeNotSet => ("homeNotSet", None, None),
        ClaudeState::Missing => ("missing", None, None),
        ClaudeState::HookRegistered { matcher } => ("hookRegistered", matcher.clone(), None),
        ClaudeState::HookMissing => ("hookMissing", None, None),
        ClaudeState::InvalidJson(msg) => ("invalidJson", None, Some(msg.clone())),
        ClaudeState::Io(msg) => ("io", None, Some(msg.clone())),
    };
    JsonClaude {
        settings_path,
        state,
        matcher,
        error,
    }
}

fn build_json_codex(status: &CodexStatus) -> JsonCodex {
    let config_path = status.config_path.as_ref().map(|p| p.display().to_string());
    let hooks_path = status.hooks_path.as_ref().map(|p| p.display().to_string());
    let (state, matcher, error) = match &status.state {
        CodexState::HomeNotSet => ("homeNotSet", None, None),
        CodexState::ConfigMissing => ("configMissing", None, None),
        CodexState::HooksMissing => ("hooksMissing", None, None),
        CodexState::HooksDisabled => ("hooksDisabled", None, None),
        CodexState::HookRegistered { matcher } => ("hookRegistered", matcher.clone(), None),
        CodexState::HookMissing => ("hookMissing", None, None),
        CodexState::InvalidConfig(msg) => ("invalidConfig", None, Some(msg.clone())),
        CodexState::InvalidHooks(msg) => ("invalidHooks", None, Some(msg.clone())),
        CodexState::Io(msg) => ("io", None, Some(msg.clone())),
    };
    JsonCodex {
        config_path,
        hooks_path,
        state,
        matcher,
        error,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::fs;

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-doctor-{}-{}-{}",
            tag,
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn render(report: &Report) -> String {
        let mut buf = Vec::new();
        report.render(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn renders_every_section_with_clean_layout() {
        let dir = workdir("clean");
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, "mode: enforce\n").unwrap();
        let layout = Layout {
            system: Some(dir.join("etc/policy.yaml")),
            user: Some(dir.join("home/.config/ptuf/config.yaml")),
            project: Some(proj.clone()),
            project_local: Some(dir.join(".ptuf.local.yaml")),
        };
        let report = Report::gather(
            Some(PathBuf::from("/usr/local/bin/ptuf")),
            Some(dir.clone()),
            layout,
            Some(dir.join("missing-claude.json")),
        );
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("ptuf doctor"));
        assert!(s.contains("Binary"));
        assert!(s.contains("/usr/local/bin/ptuf"));
        assert!(s.contains("Project"));
        assert!(s.contains("repository root"));
        assert!(s.contains("Effective config"));
        assert!(s.contains("mode:"));
        assert!(s.contains("Plugins"));
        assert!(s.contains("Claude Code integration"));
        assert!(s.contains("Codex integration"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn flags_invalid_yaml_in_config_layer_as_failure() {
        let dir = workdir("bad-yaml");
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, "mode: enforce\n  bad: : :\n").unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        assert!(report.has_failure());
        let s = render(&report);
        assert!(s.contains("✗"));
        assert!(s.contains("config load failed"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn binary_unknown_falls_back_to_warning() {
        let report = Report::gather(None, None, Layout::default(), None);
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("⚠ binary path unavailable"));
    }

    #[test]
    fn no_repo_root_warns_but_does_not_fail() {
        let report = Report::gather(
            Some(PathBuf::from("/x/ptuf")),
            None,
            Layout::default(),
            None,
        );
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("⚠ no repository root detected"));
    }

    #[test]
    fn plugin_load_failure_is_a_section_failure() {
        let dir = workdir("bad-plugin");
        let proj = dir.join(".ptuf.yaml");
        let plugin = dir.join("nope.yaml");
        fs::write(&proj, format!("plugins:\n  - path: {}\n", plugin.display())).unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        assert!(report.has_failure());
        let s = render(&report);
        assert!(s.contains("Plugins (1)"));
        assert!(s.contains("nope.yaml"));
        assert!(s.contains("✗"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plugin_loaded_renders_with_name_and_rule_count() {
        let dir = workdir("good-plugin");
        let plugin = dir.join("ok.yaml");
        fs::write(
            &plugin,
            r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
  version: 1.0.0
rules:
  - id: pack.demo.rule1
    severity: low
    defaultDecision: deny
    when:
      tool: Bash
    reason: r
"#,
        )
        .unwrap();
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, format!("plugins:\n  - path: {}\n", plugin.display())).unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("✓"));
        assert!(s.contains("pack.demo"));
        assert!(s.contains("1.0.0"));
        assert!(s.contains("1 rule"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn claude_settings_missing_is_warning_not_failure() {
        let dir = workdir("claude-missing");
        let path = dir.join("settings.json");
        let report = Report::gather(None, None, Layout::default(), Some(path.clone()));
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("⚠"));
        assert!(s.contains("not present"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn claude_settings_with_invalid_json_is_failure() {
        let dir = workdir("claude-bad");
        let path = dir.join("settings.json");
        fs::write(&path, "{not json").unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        assert!(report.has_failure());
        let s = render(&report);
        assert!(s.contains("invalid JSON"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn claude_settings_with_hook_missing_warns() {
        let dir = workdir("claude-no-hook");
        let path = dir.join("settings.json");
        fs::write(&path, r#"{"hooks":{"PreToolUse":[]}}"#).unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("no ptuf hook registered"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn claude_settings_with_hook_registered_is_ok_and_shows_matcher() {
        let dir = workdir("claude-good");
        let path = dir.join("settings.json");
        fs::write(
            &path,
            r#"{
              "hooks": {
                "PreToolUse": [
                  {
                    "matcher": "Bash|Read|Edit|Write|WebFetch|mcp__.*",
                    "hooks": [
                      { "type": "command", "command": "/usr/local/bin/ptuf hook claude-code" }
                    ]
                  }
                ]
              }
            }"#,
        )
        .unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("ptuf hook registered"));
        assert!(s.contains("matcher:"));
        assert!(s.contains("Bash|Read|Edit|Write|WebFetch|mcp__.*"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn claude_home_not_set_warns() {
        let report = Report::gather(None, None, Layout::default(), None);
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("$HOME not set"));
    }

    #[test]
    fn codex_home_not_set_warns() {
        assert!(matches!(
            build_codex_status(None, None),
            CodexState::HomeNotSet
        ));
    }

    #[test]
    fn codex_config_missing_state_is_detected() {
        let dir = workdir("codex-config-missing");
        let state = build_codex_status(
            Some(&dir.join("config.toml")),
            Some(&dir.join("hooks.json")),
        );
        assert!(matches!(state, CodexState::ConfigMissing));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_hooks_missing_state_is_detected() {
        let dir = workdir("codex-hooks-missing");
        fs::write(dir.join("config.toml"), "[features]\ncodex_hooks = true\n").unwrap();
        let state = build_codex_status(
            Some(&dir.join("config.toml")),
            Some(&dir.join("hooks.json")),
        );
        assert!(matches!(state, CodexState::HooksMissing));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_hooks_disabled_state_is_detected() {
        let dir = workdir("codex-disabled");
        fs::write(dir.join("config.toml"), "[features]\ncodex_hooks = false\n").unwrap();
        fs::write(dir.join("hooks.json"), r#"{"hooks":{"PreToolUse":[]}}"#).unwrap();
        let state = build_codex_status(
            Some(&dir.join("config.toml")),
            Some(&dir.join("hooks.json")),
        );
        assert!(matches!(state, CodexState::HooksDisabled));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_hooks_disabled_does_not_parse_hooks_file() {
        let dir = workdir("codex-disabled-invalid-hooks");
        fs::write(dir.join("config.toml"), "[features]\ncodex_hooks = false\n").unwrap();
        fs::write(dir.join("hooks.json"), "{not json").unwrap();
        let state = build_codex_status(
            Some(&dir.join("config.toml")),
            Some(&dir.join("hooks.json")),
        );
        assert!(matches!(state, CodexState::HooksDisabled));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_hook_registered_state_is_detected_with_matcher() {
        let dir = workdir("codex-hook-registered");
        fs::write(dir.join("config.toml"), "[features]\ncodex_hooks = true\n").unwrap();
        fs::write(
            dir.join("hooks.json"),
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|apply_patch|mcp__.*","hooks":[{"type":"command","command":"ptuf hook codex"}]}]}}"#,
        )
        .unwrap();
        let state = build_codex_status(
            Some(&dir.join("config.toml")),
            Some(&dir.join("hooks.json")),
        );
        assert!(matches!(
            state,
            CodexState::HookRegistered { matcher: Some(ref matcher) }
                if matcher == "Bash|apply_patch|mcp__.*"
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_hook_missing_state_is_detected() {
        let dir = workdir("codex-hook-missing");
        fs::write(dir.join("config.toml"), "[features]\ncodex_hooks = true\n").unwrap();
        fs::write(
            dir.join("hooks.json"),
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other hook"}]}]}}"#,
        )
        .unwrap();
        let state = build_codex_status(
            Some(&dir.join("config.toml")),
            Some(&dir.join("hooks.json")),
        );
        assert!(matches!(state, CodexState::HookMissing));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_invalid_config_state_is_failure() {
        let dir = workdir("codex-invalid-config");
        fs::write(dir.join("config.toml"), "[features\ncodex_hooks = true").unwrap();
        let state = build_codex_status(
            Some(&dir.join("config.toml")),
            Some(&dir.join("hooks.json")),
        );
        assert!(matches!(state, CodexState::InvalidConfig(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_invalid_hooks_state_is_failure() {
        let dir = workdir("codex-invalid-hooks");
        fs::write(dir.join("config.toml"), "[features]\ncodex_hooks = true\n").unwrap();
        fs::write(dir.join("hooks.json"), "{not json").unwrap();
        let state = build_codex_status(
            Some(&dir.join("config.toml")),
            Some(&dir.join("hooks.json")),
        );
        assert!(matches!(state, CodexState::InvalidHooks(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_io_state_is_failure() {
        let dir = workdir("codex-io");
        fs::create_dir_all(dir.join("config.toml")).unwrap();
        let state = build_codex_status(
            Some(&dir.join("config.toml")),
            Some(&dir.join("hooks.json")),
        );
        assert!(matches!(state, CodexState::Io(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_doctor_writes_report_for_live_environment() {
        let mut buf = Vec::new();
        let _failure = render_doctor(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("ptuf doctor"));
        assert!(s.contains("Binary"));
        assert!(s.contains("Project"));
    }

    #[test]
    fn mode_label_covers_all_variants() {
        assert_eq!(mode_label(config::Mode::Enforce), "enforce");
        assert_eq!(mode_label(config::Mode::Monitor), "monitor");
        assert_eq!(mode_label(config::Mode::Observe), "observe");
    }

    #[test]
    fn empty_settings_file_treated_as_hook_missing() {
        let dir = workdir("empty");
        let path = dir.join("settings.json");
        fs::write(&path, "").unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("no ptuf hook registered"));
        let _ = fs::remove_dir_all(&dir);
    }

    fn to_json_value(report: &Report) -> serde_json::Value {
        serde_json::to_value(report.to_json()).unwrap()
    }

    #[test]
    fn json_report_advertises_schema_version_one() {
        let report = Report::gather(None, None, Layout::default(), None);
        let v = to_json_value(&report);
        assert_eq!(v["schemaVersion"], 1);
        assert!(v["codex"]["state"].is_string());
    }

    #[test]
    fn json_report_includes_binary_path_and_version_when_known() {
        let report = Report::gather(
            Some(PathBuf::from("/usr/local/bin/ptuf")),
            None,
            Layout::default(),
            None,
        );
        let v = to_json_value(&report);
        assert_eq!(v["binary"]["path"], "/usr/local/bin/ptuf");
        assert!(v["binary"]["version"].is_string());
    }

    #[test]
    fn json_report_emits_null_binary_path_when_unknown() {
        let report = Report::gather(None, None, Layout::default(), None);
        let v = to_json_value(&report);
        assert!(v["binary"]["path"].is_null());
    }

    #[test]
    fn json_report_drops_unset_layout_entries_but_keeps_set_ones() {
        let dir = workdir("json-layers");
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, "mode: enforce\n").unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj.clone()),
            project_local: Some(dir.join(".ptuf.local.yaml")),
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        let v = to_json_value(&report);
        let layers = v["configLayers"].as_array().unwrap();
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0]["layer"], "project");
        assert_eq!(layers[0]["present"], true);
        assert_eq!(layers[1]["layer"], "projectLocal");
        assert_eq!(layers[1]["present"], false);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_report_serialises_loaded_config_with_mode_and_audit() {
        let dir = workdir("json-cfg");
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, "mode: monitor\nfailClosed: false\n").unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        let v = to_json_value(&report);
        assert_eq!(v["config"]["loaded"], true);
        assert_eq!(v["config"]["mode"], "monitor");
        assert_eq!(v["config"]["failClosed"], false);
        assert_eq!(
            v["config"]["auditPath"],
            crate::config::default_audit_path()
                .map(|p| serde_json::Value::String(p.display().to_string()))
                .unwrap_or(serde_json::Value::Null)
        );
        assert_eq!(v["hasFailure"], false);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_report_serialises_failed_config_with_error_string() {
        let dir = workdir("json-bad-cfg");
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, "mode: enforce\n  bad: : :\n").unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        let v = to_json_value(&report);
        assert_eq!(v["config"]["loaded"], false);
        assert!(v["config"]["error"].is_string());
        assert_eq!(v["hasFailure"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_report_serialises_loaded_plugin_entry() {
        let dir = workdir("json-plugin");
        let plugin = dir.join("ok.yaml");
        fs::write(
            &plugin,
            r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
  version: 1.0.0
rules:
  - id: pack.demo.rule1
    severity: low
    defaultDecision: deny
    when:
      tool: Bash
    reason: r
"#,
        )
        .unwrap();
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, format!("plugins:\n  - path: {}\n", plugin.display())).unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        let v = to_json_value(&report);
        let plugins = v["plugins"].as_array().unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0]["loaded"], true);
        assert_eq!(plugins[0]["name"], "pack.demo");
        assert_eq!(plugins[0]["version"], "1.0.0");
        assert_eq!(plugins[0]["ruleCount"], 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_report_serialises_failed_plugin_entry() {
        let dir = workdir("json-bad-plugin");
        let proj = dir.join(".ptuf.yaml");
        let plugin = dir.join("nope.yaml");
        fs::write(&proj, format!("plugins:\n  - path: {}\n", plugin.display())).unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        let v = to_json_value(&report);
        let plugins = v["plugins"].as_array().unwrap();
        assert_eq!(plugins[0]["loaded"], false);
        assert!(plugins[0]["error"].is_string());
        assert_eq!(v["hasFailure"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_claude_state_home_not_set_omits_optional_fields() {
        let report = Report::gather(None, None, Layout::default(), None);
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "homeNotSet");
        assert!(v["claude"]["settingsPath"].is_null());
        assert!(v["claude"].get("matcher").is_none());
        assert!(v["claude"].get("error").is_none());
    }

    #[test]
    fn json_claude_state_missing_omits_matcher_and_error() {
        let dir = workdir("json-claude-missing");
        let path = dir.join("settings.json");
        let report = Report::gather(None, None, Layout::default(), Some(path.clone()));
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "missing");
        assert_eq!(v["claude"]["settingsPath"], path.display().to_string());
        assert!(v["claude"].get("matcher").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_claude_state_hook_registered_includes_matcher() {
        let dir = workdir("json-claude-good");
        let path = dir.join("settings.json");
        fs::write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|Read|Edit|Write|WebFetch|mcp__.*","hooks":[{"type":"command","command":"ptuf hook claude-code"}]}]}}"#,
        )
        .unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "hookRegistered");
        assert_eq!(
            v["claude"]["matcher"],
            "Bash|Read|Edit|Write|WebFetch|mcp__.*"
        );
        assert!(v["claude"].get("error").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_claude_state_hook_missing_state_string() {
        let dir = workdir("json-claude-no-hook");
        let path = dir.join("settings.json");
        fs::write(&path, r#"{"hooks":{"PreToolUse":[]}}"#).unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "hookMissing");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_claude_state_invalid_json_carries_error() {
        let dir = workdir("json-claude-bad");
        let path = dir.join("settings.json");
        fs::write(&path, "{not json").unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "invalidJson");
        assert!(v["claude"]["error"].is_string());
        assert_eq!(v["hasFailure"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_codex_state_home_not_set_omits_optional_fields() {
        let report = Report::gather(None, None, Layout::default(), None);
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "homeNotSet");
        assert!(v["codex"]["configPath"].is_null());
        assert!(v["codex"]["hooksPath"].is_null());
        assert!(v["codex"].get("matcher").is_none());
        assert!(v["codex"].get("error").is_none());
    }

    #[test]
    fn json_codex_state_hook_registered_includes_matcher() {
        let dir = workdir("json-codex-good");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features]\ncodex_hooks = true\n").unwrap();
        fs::write(
            &hooks_path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|apply_patch|mcp__.*","hooks":[{"type":"command","command":"ptuf hook codex"}]}]}}"#,
        )
        .unwrap();
        let report = Report::gather_with_codex(
            None,
            None,
            Layout::default(),
            None,
            CodexPaths {
                config_path: Some(config_path.clone()),
                hooks_path: Some(hooks_path.clone()),
            },
        );
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "hookRegistered");
        assert_eq!(v["codex"]["configPath"], config_path.display().to_string());
        assert_eq!(v["codex"]["hooksPath"], hooks_path.display().to_string());
        assert_eq!(v["codex"]["matcher"], "Bash|apply_patch|mcp__.*");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_codex_state_invalid_config_carries_error() {
        let dir = workdir("json-codex-bad");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features\ncodex_hooks = true").unwrap();
        let report = Report::gather_with_codex(
            None,
            None,
            Layout::default(),
            None,
            CodexPaths {
                config_path: Some(config_path),
                hooks_path: Some(hooks_path),
            },
        );
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "invalidConfig");
        assert!(v["codex"]["error"].is_string());
        assert_eq!(v["hasFailure"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_doctor_json_writes_pretty_json_with_trailing_newline() {
        let mut buf = Vec::new();
        let _failure = render_doctor_json(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.ends_with('\n'));
        let value: serde_json::Value =
            serde_json::from_str(s.trim_end()).expect("must be valid JSON");
        assert_eq!(value["schemaVersion"], 1);
    }

    fn report_with_codex_paths(
        config_path: Option<PathBuf>,
        hooks_path: Option<PathBuf>,
    ) -> Report {
        Report::gather_with_codex(
            None,
            None,
            Layout::default(),
            None,
            CodexPaths {
                config_path,
                hooks_path,
            },
        )
    }

    #[test]
    fn codex_render_home_not_set_emits_warning() {
        let report = report_with_codex_paths(None, None);
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("$HOME not set and no repository root detected"));
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "homeNotSet");
    }

    #[test]
    fn codex_render_hooks_missing_emits_warning() {
        let dir = workdir("render-codex-hooks-missing");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features]\ncodex_hooks = true\n").unwrap();
        let report = report_with_codex_paths(Some(config_path), Some(hooks_path.clone()));
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains(&hooks_path.display().to_string()));
        assert!(s.contains("not present"));
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "hooksMissing");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_render_hooks_disabled_emits_warning() {
        let dir = workdir("render-codex-hooks-disabled");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features]\ncodex_hooks = false\n").unwrap();
        fs::write(&hooks_path, r#"{"hooks":{"PreToolUse":[]}}"#).unwrap();
        let report = report_with_codex_paths(Some(config_path), Some(hooks_path));
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("features.codex_hooks is disabled"));
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "hooksDisabled");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_render_hook_registered_renders_matcher() {
        let dir = workdir("render-codex-hook-registered");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features]\ncodex_hooks = true\n").unwrap();
        fs::write(
            &hooks_path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|apply_patch|mcp__.*","hooks":[{"type":"command","command":"ptuf hook codex"}]}]}}"#,
        )
        .unwrap();
        let report = report_with_codex_paths(Some(config_path), Some(hooks_path));
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("ptuf hook registered"));
        assert!(s.contains("Bash|apply_patch|mcp__.*"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_render_hook_registered_omits_matcher_when_absent() {
        let dir = workdir("render-codex-hook-registered-no-matcher");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features]\ncodex_hooks = true\n").unwrap();
        fs::write(
            &hooks_path,
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"ptuf hook codex"}]}]}}"#,
        )
        .unwrap();
        let report = report_with_codex_paths(Some(config_path), Some(hooks_path));
        let s = render(&report);
        assert!(s.contains("ptuf hook registered"));
        assert!(!s.contains("matcher:"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_render_hook_missing_emits_warning() {
        let dir = workdir("render-codex-hook-missing");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features]\ncodex_hooks = true\n").unwrap();
        fs::write(
            &hooks_path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other hook"}]}]}}"#,
        )
        .unwrap();
        let report = report_with_codex_paths(Some(config_path), Some(hooks_path));
        assert!(!report.has_failure());
        let s = render(&report);
        assert!(s.contains("no ptuf hook registered"));
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "hookMissing");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_render_hook_missing_when_pre_tool_use_array_absent() {
        let dir = workdir("render-codex-hook-missing-no-pre-tool-use");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features]\ncodex_hooks = true\n").unwrap();
        fs::write(&hooks_path, r#"{"hooks":{}}"#).unwrap();
        let report = report_with_codex_paths(Some(config_path), Some(hooks_path));
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "hookMissing");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_render_invalid_config_is_failure() {
        let dir = workdir("render-codex-invalid-config");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features\ncodex_hooks = true").unwrap();
        let report = report_with_codex_paths(Some(config_path), Some(hooks_path));
        assert!(report.has_failure());
        let s = render(&report);
        assert!(s.contains("invalid TOML"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_render_invalid_hooks_is_failure() {
        let dir = workdir("render-codex-invalid-hooks");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features]\ncodex_hooks = true\n").unwrap();
        fs::write(&hooks_path, "{not json").unwrap();
        let report = report_with_codex_paths(Some(config_path), Some(hooks_path));
        assert!(report.has_failure());
        let s = render(&report);
        assert!(s.contains("invalid JSON"));
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "invalidHooks");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_render_io_for_config_is_failure() {
        let dir = workdir("render-codex-io-config");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::create_dir_all(&config_path).unwrap();
        let report = report_with_codex_paths(Some(config_path), Some(hooks_path));
        assert!(report.has_failure());
        let s = render(&report);
        assert!(s.contains("unreadable"));
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "io");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_render_io_for_hooks_is_failure() {
        let dir = workdir("render-codex-io-hooks");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features]\ncodex_hooks = true\n").unwrap();
        fs::create_dir_all(&hooks_path).unwrap();
        let report = report_with_codex_paths(Some(config_path), Some(hooks_path));
        assert!(report.has_failure());
        let s = render(&report);
        // The first matching arm in render_codex prints config_path,
        // since config_path is `Some` here. We just assert the failure
        // string surfaces; arm-with-only-hooks-path is unreachable in
        // practice because build_codex_status returns HomeNotSet when
        // either path is None.
        assert!(s.contains("unreadable"));
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "io");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn claude_settings_io_state_when_path_is_a_directory() {
        let dir = workdir("claude-io");
        let path = dir.join("settings.json");
        fs::create_dir_all(&path).unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        assert!(report.has_failure());
        let s = render(&report);
        assert!(s.contains("unreadable"));
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "io");
        let _ = fs::remove_dir_all(&dir);
    }
}
