//! Engine ties [`Config`] to rule evaluation.
//!
//! The pure [`decide`](crate::decide) function is preserved for
//! backward compatibility — it builds a default-configuration engine
//! on the fly. Callers that want to honour user policy (config scope
//! merge, `mode: monitor` demotion, future plugin loading and audit)
//! construct an [`Engine`] once and reuse it.

use std::path::Path;

use crate::config::{self, Config, ConfigError, Mode, PackOverride};
use crate::decision::{Decision, aggregate};
use crate::facts;
use crate::hook_input::HookInput;
use crate::rules::{self, ConfigRule};

/// Resolved engine ready to evaluate hook payloads.
pub struct Engine {
    config: Config,
}

/// Result of [`Engine::decide`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The decision after pack-override filtering, aggregation, and
    /// mode-based demotion.
    pub decision: Decision,
    /// The mode that was in effect when the outcome was produced.
    /// Useful for audit records and the `mode_demoted` flag.
    pub mode: Mode,
    /// `true` when the pre-demotion decision was a `Deny` but `mode`
    /// turned it into a `Monitor`. Audit consumers surface this.
    pub mode_demoted: bool,
}

/// Errors raised while building an engine. Currently a thin wrapper
/// over [`ConfigError`]; later commits add plugin / audit init paths.
#[derive(Debug)]
pub enum EngineError {
    Config(ConfigError),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Config(e) => write!(f, "engine: {e}"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EngineError::Config(e) => Some(e),
        }
    }
}

impl From<ConfigError> for EngineError {
    fn from(value: ConfigError) -> Self {
        EngineError::Config(value)
    }
}

impl Engine {
    /// Build an engine using the merged configuration discovered for
    /// `repo_root` (or no project scope when `None`).
    pub fn new(repo_root: Option<&Path>) -> Result<Self, EngineError> {
        Ok(Self {
            config: config::load_for(repo_root)?,
        })
    }

    /// Build an engine from an explicit config — used by tests and by
    /// the backward-compatible [`crate::decide`] shim.
    pub fn with_config(config: Config) -> Self {
        Self { config }
    }

    /// Read-only view of the merged configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Evaluate a single hook payload.
    pub fn decide(&self, input: &HookInput) -> Outcome {
        let facts = facts::extract(input);
        let decisions: Vec<Decision> = rules::iter()
            .filter(|rule| !is_pack_disabled(*rule, &self.config))
            .filter_map(|rule| rule.evaluate(&facts, input))
            .collect();
        let raw = aggregate(decisions);
        let demoted_decision = demote_for_mode(raw.clone(), self.config.mode);
        let mode_demoted = matches!(raw, Decision::Deny { .. })
            && matches!(demoted_decision, Decision::Monitor { .. });
        Outcome {
            decision: demoted_decision,
            mode: self.config.mode,
            mode_demoted,
        }
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::with_config(Config::default())
    }
}

fn is_pack_disabled(rule: &(dyn ConfigRule + Sync), config: &Config) -> bool {
    if rule.hard_deny() {
        return false;
    }
    let id = rule.id();
    config
        .pack_overrides
        .iter()
        .any(|(pack, overlay)| pack_disabled(overlay) && rule_matches_pack(id, pack))
}

fn pack_disabled(overlay: &PackOverride) -> bool {
    overlay.enabled == Some(false)
}

fn rule_matches_pack(rule_id: &str, pack: &str) -> bool {
    rule_id == pack || rule_id.starts_with(&format!("{pack}."))
}

fn demote_for_mode(decision: Decision, mode: Mode) -> Decision {
    if matches!(mode, Mode::Monitor | Mode::Observe)
        && let Decision::Deny { rule_id, .. } = decision
    {
        return Decision::Monitor { rule_id };
    }
    decision
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PackOverride;
    use serde_json::json;

    fn bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": cmd }),
        }
    }

    fn engine_with(cfg: Config) -> Engine {
        Engine::with_config(cfg)
    }

    #[test]
    fn default_engine_returns_allow_for_safe_command() {
        let outcome = Engine::default().decide(&bash("ls"));
        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.mode, Mode::Enforce);
        assert!(!outcome.mode_demoted);
    }

    #[test]
    fn default_engine_denies_destructive_rm() {
        let outcome = Engine::default().decide(&bash("rm -rf /"));
        assert!(matches!(outcome.decision, Decision::Deny { .. }));
        assert!(!outcome.mode_demoted);
    }

    #[test]
    fn monitor_mode_demotes_deny_to_monitor() {
        let cfg = Config {
            mode: Mode::Monitor,
            ..Config::default()
        };
        let outcome = engine_with(cfg).decide(&bash("rm -rf /"));
        assert!(matches!(outcome.decision, Decision::Monitor { .. }));
        assert!(outcome.mode_demoted);
    }

    #[test]
    fn observe_mode_also_demotes_deny() {
        let cfg = Config {
            mode: Mode::Observe,
            ..Config::default()
        };
        let outcome = engine_with(cfg).decide(&bash("rm -rf /"));
        assert!(matches!(outcome.decision, Decision::Monitor { .. }));
        assert!(outcome.mode_demoted);
    }

    #[test]
    fn monitor_mode_leaves_allow_unchanged() {
        let cfg = Config {
            mode: Mode::Monitor,
            ..Config::default()
        };
        let outcome = engine_with(cfg).decide(&bash("ls"));
        assert_eq!(outcome.decision, Decision::Allow);
        assert!(!outcome.mode_demoted);
    }

    #[test]
    fn pack_disable_is_ignored_for_hard_deny_rules() {
        let mut cfg = Config::default();
        cfg.pack_overrides.insert(
            "core.filesystem".into(),
            PackOverride {
                enabled: Some(false),
            },
        );
        let outcome = engine_with(cfg).decide(&bash("rm -rf /"));
        assert!(matches!(outcome.decision, Decision::Deny { .. }));
    }

    #[test]
    fn rule_matches_pack_uses_dot_boundary() {
        assert!(rule_matches_pack(
            "core.network.remote-script-pipe",
            "core.network"
        ));
        assert!(rule_matches_pack("core.network", "core.network"));
        assert!(!rule_matches_pack("core.networking.x", "core.network"));
        assert!(!rule_matches_pack("foo.core.network.x", "core.network"));
    }

    #[test]
    fn engine_exposes_its_config() {
        let cfg = Config {
            mode: Mode::Monitor,
            ..Config::default()
        };
        let engine = engine_with(cfg);
        assert_eq!(engine.config().mode, Mode::Monitor);
    }
}
