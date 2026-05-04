//! Configuration model for ptuf.
//!
//! [`Config`] is the resolved view applied at runtime. Each policy
//! scope (`/etc/ptuf`, `~/.config/ptuf`, `<repo>/.ptuf.yaml`,
//! `<repo>/.ptuf.local.yaml`) deserialises into a [`schema::RawConfig`]
//! whose fields are all optional; [`merge::merge`] then folds those
//! layers (lowest first) into a single [`Config`].
//!
//! YAML loading and scope path resolution live in subsequent commits.
//! This module only owns the in-memory shape and merge logic so that
//! later commits can plug a YAML parser in without disturbing rule
//! evaluation.

use std::collections::BTreeMap;
use std::path::PathBuf;

pub mod merge;
pub mod schema;

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
    /// Per-rule overrides keyed by rule id (`core.network.remote-script-pipe`).
    pub rule_overrides: BTreeMap<String, RuleOverride>,
    /// Time-bound exceptions; later commits gate them by `expires_at`.
    pub allowlists: Vec<Allowlist>,
    pub audit: AuditConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            fail_closed: true,
            rule_overrides: BTreeMap::new(),
            allowlists: Vec::new(),
            audit: AuditConfig::default(),
        }
    }
}

/// Per-rule overlay applied on top of a rule's static defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleOverride {
    /// `Some(false)` disables the rule, `Some(true)` re-enables one
    /// that an outer scope disabled. `None` leaves the rule's default
    /// in place.
    pub enabled: Option<bool>,
}

/// Time-bound exception scoped to one or more rule ids.
///
/// `expires_at` is stored as the raw RFC3339 string; the engine checks
/// it against the current time at evaluation, not at merge time.
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
