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
    /// Time-bound exceptions; later commits gate them by `expires_at`.
    pub allowlists: Vec<Allowlist>,
    pub audit: AuditConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            fail_closed: true,
            pack_overrides: BTreeMap::new(),
            allowlists: Vec::new(),
            audit: AuditConfig::default(),
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

/// Time-bound exception scoped to one or more rule ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    pub id: String,
    pub rule_ids: Vec<String>,
    pub expires_at: Option<String>,
    pub reason: Option<String>,
}

/// Audit-sink configuration. Absent path means audit is disabled.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditConfig {
    pub path: Option<PathBuf>,
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
