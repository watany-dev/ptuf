//! Configuration model for ptuf.
//!
//! [`Config`] is the resolved view applied at runtime. Each policy
//! scope (`/etc/ptuf`, `~/.config/ptuf`, `<repo>/.ptuf.yaml`,
//! `<repo>/.ptuf.local.yaml`) deserialises into a [`schema::RawConfig`]
//! whose fields are all optional; [`merge::merge`] folds those layers
//! (lowest first) into a single [`Config`].
//!
//! [`load_for`] orchestrates the layered load: it walks the documented
//! scope order, parses each YAML that exists via [`yaml`] and discards
//! missing scopes silently. Errors carry the offending path so that
//! `failClosed` mode can surface them to the user.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::decision::{DecisionKind, Severity};
use crate::plugin::dsl::WhenNode;

pub mod merge;
pub mod repo;
pub mod schema;
pub mod scope;
pub mod yaml;

/// Operating mode for the engine.
///
/// `Enforce` (default) honours `Decision::Deny` as a blocking deny.
/// `Monitor` demotes denies to `Monitor` so that the hook never blocks
/// the agent but still records the event. `Observe` is a v0.3 stretch
/// goal — for v0.2 it behaves identically to `Monitor` but is
/// preserved as a distinct variant so that downstream callers can
/// branch on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Enforce,
    Monitor,
    Observe,
}

/// Resolved runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    pub fail_closed: bool,
    /// Per-pack overrides keyed by pack name (`core.network`).
    /// A rule whose id starts with `<pack>.` inherits the pack toggle.
    pub pack_overrides: BTreeMap<String, PackOverride>,
    /// Per-rule overrides keyed by exact rule id. These are applied by
    /// the engine after a rule fires so `hardDeny` / `overridable`
    /// metadata can be enforced against the concrete rule.
    pub rule_overrides: BTreeMap<String, RuleOverride>,
    /// Time-bound exceptions; later commits gate them by `expires_at`.
    pub allowlists: Vec<Allowlist>,
    /// Filesystem paths of `apiVersion: ptuf.dev/v1, kind: Plugin`
    /// YAML files that the engine should load. Lower scopes are
    /// listed first; the engine loads them in order.
    pub plugin_paths: Vec<PathBuf>,
    pub audit: AuditConfig,
    /// Branch names / glob patterns considered "protected" by
    /// `core.project_hygiene`. Default: `main`, `master`, `release/*`.
    /// A higher scope's value replaces lower scopes wholesale rather
    /// than merging, so projects can override the default cleanly.
    pub protected_branches: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        let mut pack_overrides: BTreeMap<String, PackOverride> = BTreeMap::new();
        // core.project_hygiene is opt-in: lock-mismatch / protected
        // branch denials would derail dev flows for projects that have
        // not opted into them.
        pack_overrides.insert(
            "core.project_hygiene".to_string(),
            PackOverride {
                enabled: Some(false),
            },
        );
        Self {
            mode: Mode::default(),
            fail_closed: true,
            pack_overrides,
            rule_overrides: BTreeMap::new(),
            allowlists: Vec::new(),
            plugin_paths: Vec::new(),
            audit: AuditConfig::default(),
            protected_branches: vec!["main".into(), "master".into(), "release/*".into()],
        }
    }
}

/// Per-pack overlay applied on top of a pack's static defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackOverride {
    /// `Some(false)` disables every rule in this pack, `Some(true)`
    /// re-enables a pack that an outer scope disabled. `None` leaves
    /// the pack's default in place.
    pub enabled: Option<bool>,
}

/// Per-rule overlay applied after a rule has matched.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleOverride {
    pub enabled: Option<bool>,
    pub decision: Option<DecisionKind>,
    pub severity: Option<Severity>,
}

/// Time-bound exception scoped to one or more rule ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    pub id: String,
    pub rule_ids: Vec<String>,
    pub when: Option<WhenNode>,
    pub expires_at: Option<String>,
    pub reason: Option<String>,
}

/// Audit-sink configuration. Enabled audit with an absent path writes
/// to the documented default path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    pub enabled: bool,
    pub path: Option<PathBuf>,
    /// Record allow decisions. Defaults to `false` to keep the audit
    /// volume manageable.
    pub include_allowed: bool,
    /// Record deny decisions. Defaults to `true`.
    pub include_denied: bool,
    /// Strict redaction is the only supported mode in v0.2; the field
    /// is kept so the schema does not break when a future release
    /// introduces less aggressive policies.
    pub redaction: RedactionMode,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            include_allowed: false,
            include_denied: true,
            redaction: RedactionMode::default(),
        }
    }
}

/// Redaction strength. Only `Strict` is honoured today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedactionMode {
    #[default]
    Strict,
    /// Disabled — the user must opt in explicitly. Audit consumers
    /// should treat this as a self-inflicted risk.
    Off,
}

/// Documented default audit path (`$HOME/.local/share/ptuf/audit.jsonl`).
pub fn default_audit_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".local/share/ptuf/audit.jsonl"))
}

/// Resolved audit path after applying defaulting and `enabled`.
pub fn resolved_audit_path(config: &Config) -> Option<PathBuf> {
    if !config.audit.enabled {
        return None;
    }
    config.audit.path.clone().or_else(default_audit_path)
}

/// Errors raised while loading the layered policy.
#[derive(Debug)]
pub enum ConfigError {
    Io { path: PathBuf, source: io::Error },
    Yaml { path: PathBuf, message: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, source } => {
                write!(f, "failed to read {}: {}", path.display(), source)
            }
            ConfigError::Yaml { path, message } => {
                write!(f, "failed to parse {}: {}", path.display(), message)
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io { source, .. } => Some(source),
            ConfigError::Yaml { .. } => None,
        }
    }
}

/// Walk the layered scope chain and merge each existing YAML into a
/// final [`Config`].
///
/// `repo_root` is the discovered project root (typically the closest
/// ancestor containing a `.git` directory or file). When `None`, only
/// the system / user scopes are considered.
///
/// `home_dir` and `etc_dir` overrides exist for testability — production
/// callers pass the real `$HOME` and `/etc/ptuf` paths via
/// [`scope::default_layout`].
pub fn load_for(repo_root: Option<&Path>) -> Result<Config, ConfigError> {
    load_with_layout(scope::default_layout(repo_root))
}

/// Load configuration given an explicit [`scope::Layout`]. Used by the
/// public [`load_for`] helper as well as by integration tests that
/// inject fixture directories.
pub fn load_with_layout(layout: scope::Layout) -> Result<Config, ConfigError> {
    let mut layers = Vec::new();
    for path in layout.ordered_paths() {
        if !path.is_file() {
            continue;
        }
        let raw = yaml::load_path(&path)?;
        layers.push(raw);
    }
    Ok(merge::merge(layers))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn config_error_display_io_includes_path_and_source() {
        let err = ConfigError::Io {
            path: PathBuf::from("/etc/ptuf/policy.yaml"),
            source: io::Error::other("nope"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/etc/ptuf/policy.yaml"));
        assert!(msg.contains("nope"));
    }

    #[test]
    fn config_error_display_yaml_includes_path_and_message() {
        let err = ConfigError::Yaml {
            path: PathBuf::from("/repo/.ptuf.yaml"),
            message: "bad indent".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/repo/.ptuf.yaml"));
        assert!(msg.contains("bad indent"));
    }

    #[test]
    fn config_error_source_returns_io_for_io_variant() {
        let err = ConfigError::Io {
            path: PathBuf::from("/x"),
            source: io::Error::other("boom"),
        };
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_some());
    }

    #[test]
    fn config_error_source_returns_none_for_yaml_variant() {
        let err = ConfigError::Yaml {
            path: PathBuf::from("/x"),
            message: "broken".into(),
        };
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn load_with_layout_reads_existing_files_and_merges() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-config-load-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let user = dir.join("user.yaml");
        std::fs::write(&user, "mode: monitor\n").expect("write");

        let layout = scope::Layout {
            system: None,
            user: Some(user.clone()),
            project: None,
            project_local: None,
        };
        let config = load_with_layout(layout).expect("load");
        assert_eq!(config.mode, Mode::Monitor);

        let _ = std::fs::remove_file(&user);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_with_layout_with_no_files_returns_default_config() {
        let layout = scope::Layout {
            system: Some(PathBuf::from("/nonexistent/does-not-exist.yaml")),
            user: None,
            project: None,
            project_local: None,
        };
        let config = load_with_layout(layout).expect("load");
        assert_eq!(config, Config::default());
    }
}
