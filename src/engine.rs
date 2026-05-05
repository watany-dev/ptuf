//! Engine ties [`Config`] to rule evaluation.
//!
//! The pure [`decide`](crate::decide) function is preserved for
//! backward compatibility — it builds a default-configuration engine
//! on the fly. Callers that want to honour user policy (config scope
//! merge, `mode: monitor` demotion, future plugin loading and audit)
//! construct an [`Engine`] once and reuse it.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::audit::record::AuditRecord;
use crate::audit::time::parse_rfc3339_to_secs;
use crate::audit::{AuditSink, JsonlSink, NoopSink, redact_strict};
use crate::config::{self, Allowlist, Config, ConfigError, Mode, PackOverride, RedactionMode};
use crate::decision::{Decision, DecisionKind, Severity, aggregate};
use crate::facts;
use crate::facts::project::ProjectFacts;
use crate::hook_input::HookInput;
use crate::plugin::{PluginError, PluginSet};
use crate::rules::{self, ConfigRule};
use crate::self_paths::ProtectedPaths;

/// Resolved engine ready to evaluate hook payloads.
pub struct Engine {
    config: Config,
    plugins: PluginSet,
    audit_sink: Box<dyn AuditSink>,
    audit_warning: Option<String>,
    repo_root: Option<PathBuf>,
    protected: ProtectedPaths,
    /// Adapter that constructed this engine — surfaced in audit
    /// records as the `agent` field. Defaults to `"unknown"`.
    agent: &'static str,
    /// Cached `name@version` for every loaded plugin in load order.
    /// Built once at constructor time so audit records do not pay a
    /// formatting cost per `decide` call.
    plugin_versions: Vec<String>,
    /// Project-level facts (lock-file kinds, current branch, protected
    /// flag) collected once at construction so per-decide evaluation
    /// stays I/O-free.
    project_facts: ProjectFacts,
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
    /// Allowlist `id` whose suppression caused the outcome to be
    /// `Allow` instead of a deny / ask / monitor. Only populated on
    /// `Allow` decisions; always `None` otherwise. When multiple
    /// allowlists hit, the first one wins.
    pub allowlist_id: Option<String>,
}

/// Errors raised while building an engine.
#[derive(Debug)]
pub enum EngineError {
    Config(ConfigError),
    Plugin(PluginError),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Config(e) => write!(f, "engine: {e}"),
            EngineError::Plugin(e) => write!(f, "engine: {e}"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EngineError::Config(e) => Some(e),
            EngineError::Plugin(e) => Some(e),
        }
    }
}

impl From<ConfigError> for EngineError {
    fn from(value: ConfigError) -> Self {
        EngineError::Config(value)
    }
}

impl From<PluginError> for EngineError {
    fn from(value: PluginError) -> Self {
        EngineError::Plugin(value)
    }
}

impl Engine {
    /// Build an engine using the merged configuration discovered for
    /// `repo_root` (or no project scope when `None`) and load every
    /// plugin referenced by the merged config. The audit sink is wired
    /// from `config.audit.path`; failure to open the sink is reported
    /// as a `[NoopSink]` fallback rather than aborting engine startup.
    pub fn new(repo_root: Option<&Path>) -> Result<Self, EngineError> {
        let config = config::load_for(repo_root)?;
        let mut plugins = PluginSet::new();
        plugins.load_paths(&config.plugin_paths)?;
        let (audit_sink, audit_warning) = audit_sink_from_config(&config);
        let protected = ProtectedPaths::collect(repo_root, &config);
        let plugin_versions = compute_plugin_versions(&plugins);
        let project_facts = facts::project::collect(repo_root, &config.protected_branches);
        Ok(Self {
            config,
            plugins,
            audit_sink,
            audit_warning,
            repo_root: repo_root.map(Path::to_path_buf),
            protected,
            agent: "unknown",
            plugin_versions,
            project_facts,
        })
    }

    /// CWD-derived constructor used by the CLI entry points.
    /// Walks the repo root via `git`-like discovery before loading
    /// scoped policy. Errors propagate so the caller can fail-closed.
    pub fn for_cwd() -> Result<Self, EngineError> {
        let cwd = std::env::current_dir().ok();
        Self::for_path_opt(cwd.as_deref())
    }

    /// Test-friendly variant of [`Self::for_cwd`]. `start = None`
    /// builds the engine without a project scope.
    pub fn for_path_opt(start: Option<&Path>) -> Result<Self, EngineError> {
        let repo_root = start.and_then(crate::config::repo::discover);
        Self::new(repo_root.as_deref())
    }

    /// Build an engine from an explicit config — used by tests and by
    /// the backward-compatible [`crate::decide`] shim. Plugins listed
    /// in the config are loaded eagerly.
    pub fn with_config(config: Config) -> Result<Self, EngineError> {
        let mut plugins = PluginSet::new();
        plugins.load_paths(&config.plugin_paths)?;
        let (audit_sink, audit_warning) = audit_sink_from_config(&config);
        let protected = ProtectedPaths::collect(None, &config);
        let plugin_versions = compute_plugin_versions(&plugins);
        let project_facts = facts::project::collect(None, &config.protected_branches);
        Ok(Self {
            config,
            plugins,
            audit_sink,
            audit_warning,
            repo_root: None,
            protected,
            agent: "unknown",
            plugin_versions,
            project_facts,
        })
    }

    /// Build an engine from the supplied components. Used by tests
    /// that need to inject a hand-built [`PluginSet`] without going
    /// through the YAML loader.
    pub(crate) fn with_components(config: Config, plugins: PluginSet) -> Self {
        let protected = ProtectedPaths::collect(None, &config);
        let plugin_versions = compute_plugin_versions(&plugins);
        let project_facts = facts::project::collect(None, &config.protected_branches);
        Self {
            config,
            plugins,
            audit_sink: Box::new(NoopSink),
            audit_warning: None,
            repo_root: None,
            protected,
            agent: "unknown",
            plugin_versions,
            project_facts,
        }
    }

    /// Replace the audit sink. Returned `Self` keeps the builder
    /// pattern terse for tests and integration code that constructs
    /// an engine without a sink and attaches a
    /// [`crate::audit::MemorySink`] (or any other implementor of
    /// [`AuditSink`]) afterwards.
    pub fn with_audit_sink(mut self, sink: Box<dyn AuditSink>) -> Self {
        self.audit_sink = sink;
        self.audit_warning = None;
        self
    }

    /// Override the engine's recorded project root. Useful for tests
    /// that construct an engine directly without going through
    /// [`Engine::new`].
    pub fn with_repo_root(mut self, repo_root: Option<PathBuf>) -> Self {
        self.repo_root = repo_root;
        self
    }

    /// Tag this engine with the adapter that produced the request
    /// (`claude-code` / `cli`). Surfaces in audit records
    /// as the `agent` field. Defaults to `"unknown"`.
    pub fn with_agent(mut self, agent: &'static str) -> Self {
        self.agent = agent;
        self
    }

    /// Read-only view of the merged configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Read-only view of the loaded plugin set.
    pub fn plugins(&self) -> &PluginSet {
        &self.plugins
    }

    /// Warning captured while initialising the audit sink, if any.
    /// CLI callers surface this on stderr; library callers can ignore
    /// it and keep best-effort audit semantics.
    pub fn audit_warning(&self) -> Option<&str> {
        self.audit_warning.as_deref()
    }

    /// Evaluate a single hook payload.
    pub fn decide(&self, input: &HookInput) -> Outcome {
        let mut facts = facts::extract(input);
        facts.protected = self
            .protected
            .classify_input_with_paths(input, &facts.paths);
        facts.project = self.project_facts.clone();
        let now = SystemTime::now();
        let allowlist_ctx = AllowlistContext {
            facts: &facts,
            input,
            config: &self.config,
            now,
        };
        let mut allowlist_hits: Vec<&str> = Vec::new();
        let mut decisions: Vec<Decision> = Vec::new();
        for rule in rules::iter() {
            if is_pack_disabled(rule, &self.config) {
                continue;
            }
            if let Some(d) = rule.evaluate(&facts, input)
                && let Some(d) = apply_rule_override(rule, d, &self.config)
            {
                if let Some(id) = allowlist_hit_for(rule, &d, &allowlist_ctx) {
                    allowlist_hits.push(id);
                } else {
                    decisions.push(d);
                }
            }
        }
        for plugin_rule in self.plugins.rules() {
            let rule = plugin_rule as &(dyn ConfigRule + Sync);
            if is_pack_disabled(rule, &self.config) {
                continue;
            }
            if let Some(d) = rule.evaluate(&facts, input)
                && let Some(d) = apply_rule_override(rule, d, &self.config)
            {
                if let Some(id) = allowlist_hit_for(rule, &d, &allowlist_ctx) {
                    allowlist_hits.push(id);
                } else {
                    decisions.push(d);
                }
            }
        }
        let raw = aggregate(decisions);
        let demoted_decision = demote_for_mode(raw.clone(), self.config.mode);
        let mode_demoted = matches!(raw, Decision::Deny { .. })
            && matches!(demoted_decision, Decision::Monitor { .. });
        let allowlist_id = if matches!(demoted_decision, Decision::Allow) {
            allowlist_hits.first().map(|id| (*id).to_string())
        } else {
            None
        };
        let outcome = Outcome {
            decision: demoted_decision,
            mode: self.config.mode,
            mode_demoted,
            allowlist_id,
        };
        self.record_audit(input, &outcome);
        outcome
    }

    /// Look up the severity of a rule by id across builtin and plugin
    /// rules. Used when assembling audit records.
    fn severity_for(&self, rule_id: &str) -> Option<Severity> {
        for r in rules::iter() {
            if r.id() == rule_id {
                return Some(effective_severity(r, &self.config));
            }
        }
        for r in self.plugins.rules() {
            if (r as &(dyn ConfigRule + Sync)).id() == rule_id {
                return Some(effective_severity(
                    r as &(dyn ConfigRule + Sync),
                    &self.config,
                ));
            }
        }
        None
    }

    fn record_audit(&self, input: &HookInput, outcome: &Outcome) {
        if !should_record(&outcome.decision, &self.config) {
            return;
        }
        let raw_command = input
            .bash_command()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("(tool={})", input.tool_name));
        let command_redacted = match self.config.audit.redaction {
            RedactionMode::Strict => redact_strict(&raw_command),
            RedactionMode::Off => raw_command,
        };
        let severity = outcome
            .decision
            .rule_id()
            .and_then(|id| self.severity_for(id));
        let record = AuditRecord::build(
            std::time::SystemTime::now(),
            &outcome.decision,
            outcome.mode,
            outcome.mode_demoted,
            input,
            self.repo_root.as_deref(),
            severity,
            command_redacted,
            outcome.allowlist_id.clone(),
            self.agent,
            self.plugin_versions.clone(),
        );
        let _ = self.audit_sink.record(&record);
    }
}

/// Format the loaded plugin set as a stable `name@version` list. Used
/// once per engine constructor and cached on the [`Engine`] so audit
/// records do not pay a formatting cost per `decide` call.
fn compute_plugin_versions(plugins: &PluginSet) -> Vec<String> {
    plugins
        .plugins
        .iter()
        .map(|p| format!("{}@{}", p.name, p.version))
        .collect()
}

fn audit_sink_from_config(config: &Config) -> (Box<dyn AuditSink>, Option<String>) {
    if !config.audit.enabled {
        return (Box::new(NoopSink), None);
    }
    let Some(path) = config::resolved_audit_path(config) else {
        return (
            Box::new(NoopSink),
            Some("ptuf: audit is enabled but $HOME is not set; audit disabled".into()),
        );
    };
    match JsonlSink::open(&path) {
        Ok(s) => (Box::new(s), None),
        Err(err) => (
            Box::new(NoopSink),
            Some(format!("ptuf: {err}; audit disabled")),
        ),
    }
}

fn should_record(decision: &Decision, config: &Config) -> bool {
    match decision {
        Decision::Allow => config.audit.include_allowed,
        Decision::Deny { .. } => config.audit.include_denied,
        Decision::Monitor { .. } | Decision::Ask { .. } => true,
    }
}

impl Default for Engine {
    fn default() -> Self {
        // `Config::default()` lists no plugins, so this cannot fail.
        Self::with_components(Config::default(), PluginSet::new())
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

fn apply_rule_override(
    rule: &(dyn ConfigRule + Sync),
    decision: Decision,
    config: &Config,
) -> Option<Decision> {
    let Some(overlay) = config.rule_overrides.get(rule.id()) else {
        return Some(decision);
    };
    if overlay.enabled == Some(false) && rule.overridable() && !rule.hard_deny() {
        return None;
    }
    let Some(kind) = overlay.decision else {
        return Some(decision);
    };
    if !override_allowed(rule, decision.kind(), kind) {
        return Some(decision);
    }
    Some(decision_with_kind(decision, kind))
}

fn override_allowed(rule: &(dyn ConfigRule + Sync), from: DecisionKind, to: DecisionKind) -> bool {
    if rule.overridable() && !rule.hard_deny() {
        return true;
    }
    decision_rank(to) >= decision_rank(from)
}

fn decision_rank(kind: DecisionKind) -> u8 {
    match kind {
        DecisionKind::Allow => 0,
        DecisionKind::Monitor => 1,
        DecisionKind::Ask => 2,
        DecisionKind::Deny => 3,
    }
}

fn decision_with_kind(decision: Decision, kind: DecisionKind) -> Decision {
    let rule_id = decision.rule_id().unwrap_or("").to_string();
    let reason = decision
        .reason()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Blocked by ptuf rule {rule_id}."));
    match kind {
        DecisionKind::Allow => Decision::Allow,
        DecisionKind::Monitor => Decision::Monitor { rule_id },
        DecisionKind::Ask => Decision::Ask { rule_id, reason },
        DecisionKind::Deny => Decision::Deny { rule_id, reason },
    }
}

fn effective_severity(rule: &(dyn ConfigRule + Sync), config: &Config) -> Severity {
    let Some(overlay) = config.rule_overrides.get(rule.id()) else {
        return rule.severity();
    };
    match overlay.severity {
        Some(severity) if rule.overridable() && !rule.hard_deny() => severity,
        _ => rule.severity(),
    }
}

struct AllowlistContext<'a> {
    facts: &'a facts::Facts,
    input: &'a HookInput,
    config: &'a Config,
    now: SystemTime,
}

/// First non-expired allowlist entry that covers the rule, returned
/// by id. `hardDeny` rules ignore allowlist entries entirely
/// (`docs/design/config-and-plugins.md:89`). Returns `None` when no
/// allowlist entry applies.
fn allowlist_hit_for<'a>(
    rule: &(dyn ConfigRule + Sync),
    decision: &Decision,
    ctx: &'a AllowlistContext<'_>,
) -> Option<&'a str> {
    if rule.hard_deny() {
        return None;
    }
    if matches!(decision, Decision::Allow) {
        return None;
    }
    let id = rule.id();
    ctx.config
        .allowlists
        .iter()
        .find(|entry| allowlist_covers(entry, id, ctx))
        .map(|entry| entry.id.as_str())
}

fn allowlist_covers(entry: &Allowlist, rule_id: &str, ctx: &AllowlistContext<'_>) -> bool {
    if !entry.rule_ids.iter().any(|r| r == rule_id) {
        return false;
    }
    let not_expired = match &entry.expires_at {
        None => true,
        Some(s) => match parse_rfc3339_to_secs(s) {
            Some(expiry) => ctx
                .now
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() < expiry)
                .unwrap_or(true),
            None => false,
        },
    };
    if !not_expired {
        return false;
    }
    entry
        .when
        .as_ref()
        .is_none_or(|when| crate::plugin::dsl::evaluate(when, ctx.facts, ctx.input))
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
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::audit::MemorySink;
    use crate::config::PackOverride;
    use serde_json::json;
    use std::sync::Arc;

    fn bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": cmd }),
        }
    }

    fn engine_with(cfg: Config) -> Engine {
        Engine::with_components(cfg, PluginSet::new())
    }

    /// Wrap a shared `MemorySink` so the test can both inject it into
    /// the engine and inspect the captured records afterwards.
    struct SharedMemorySink(Arc<MemorySink>);

    impl AuditSink for SharedMemorySink {
        fn record(&self, record: &AuditRecord) -> Result<(), crate::audit::AuditError> {
            self.0.record(record)
        }
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

    #[test]
    fn plugin_rule_fires_alongside_builtins() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      all:
        - tool: Bash
        - shell.argv:
            headAny: [curl]
    reason: curl is forbidden
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let engine = Engine::with_components(Config::default(), set);
        let outcome = engine.decide(&bash("curl https://example.com"));
        match outcome.decision {
            Decision::Deny { rule_id, .. } => assert_eq!(rule_id, "pack.demo.no-curl"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn audit_sink_receives_deny_record_with_severity_and_redacted_command() {
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_denied = true;
        let engine = engine_with(cfg).with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("rm -rf / && export GITHUB_TOKEN=ghp_ABCDEFGHIJ12345"));
        let recs = captured.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, "deny");
        assert_eq!(recs[0].severity, Some("critical"));
        assert_eq!(
            recs[0].rule_id.as_deref(),
            Some("core.filesystem.destructive-rm")
        );
        assert!(!recs[0].command_redacted.contains("ghp_ABCDEFGHIJ"));
    }

    #[test]
    fn audit_skips_allow_when_include_allowed_is_false() {
        let captured = Arc::new(MemorySink::new());
        let cfg = Config::default();
        let engine = engine_with(cfg).with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("ls"));
        assert!(captured.records().is_empty());
    }

    #[test]
    fn audit_records_allow_when_include_allowed_is_true() {
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_allowed = true;
        let engine = engine_with(cfg).with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("ls"));
        let recs = captured.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, "allow");
        assert!(recs[0].rule_id.is_none());
    }

    #[test]
    fn audit_skips_deny_when_include_denied_is_false() {
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_denied = false;
        let engine = engine_with(cfg).with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("rm -rf /"));
        assert!(captured.records().is_empty());
    }

    #[test]
    fn audit_record_for_monitor_demoted_deny_carries_mode_demoted_flag() {
        let captured = Arc::new(MemorySink::new());
        let cfg = Config {
            mode: Mode::Monitor,
            ..Config::default()
        };
        let engine = engine_with(cfg).with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("rm -rf /"));
        let recs = captured.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, "monitor");
        assert!(recs[0].mode_demoted);
        assert_eq!(recs[0].mode, "monitor");
    }

    #[test]
    fn audit_records_repo_root_when_engine_carries_one() {
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_allowed = true;
        let engine = engine_with(cfg)
            .with_audit_sink(Box::new(SharedMemorySink(captured.clone())))
            .with_repo_root(Some(PathBuf::from("/repo/example")));
        let _ = engine.decide(&bash("ls"));
        let recs = captured.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].project_root.as_deref(), Some("/repo/example"));
    }

    #[test]
    fn audit_record_uses_redaction_off_when_configured() {
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.redaction = RedactionMode::Off;
        let engine = engine_with(cfg).with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("rm -rf / && TOKEN=abcdef"));
        let recs = captured.records();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].command_redacted.contains("TOKEN=abcdef"));
    }

    #[test]
    fn engine_with_config_uses_noop_sink_when_audit_path_is_unset() {
        let cfg = Config::default();
        let engine = Engine::with_config(cfg).expect("with_config");
        // No assertion beyond "doesn't panic" — the engine is now
        // fully constructed and decides cleanly.
        let _ = engine.decide(&bash("ls"));
    }

    #[test]
    fn allowlist_entry_does_not_suppress_hard_deny_builtin() {
        let mut cfg = Config::default();
        cfg.allowlists.push(Allowlist {
            id: "ignore-fs".into(),
            rule_ids: vec!["core.filesystem.destructive-rm".into()],
            when: None,
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            reason: None,
        });
        let outcome = engine_with(cfg).decide(&bash("rm -rf /"));
        assert!(matches!(outcome.decision, Decision::Deny { .. }));
    }

    #[test]
    fn allowlist_entry_suppresses_overridable_plugin_rule() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let mut cfg = Config::default();
        cfg.allowlists.push(Allowlist {
            id: "ignore-curl".into(),
            rule_ids: vec!["pack.demo.no-curl".into()],
            when: None,
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            reason: None,
        });
        let engine = Engine::with_components(cfg, set);
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert_eq!(outcome.decision, Decision::Allow);
    }

    #[test]
    fn expired_allowlist_entry_is_ignored() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let mut cfg = Config::default();
        cfg.allowlists.push(Allowlist {
            id: "expired".into(),
            rule_ids: vec!["pack.demo.no-curl".into()],
            when: None,
            expires_at: Some("2000-01-01T00:00:00Z".into()),
            reason: None,
        });
        let engine = Engine::with_components(cfg, set);
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert!(matches!(outcome.decision, Decision::Deny { .. }));
    }

    #[test]
    fn allowlist_without_expiry_suppresses_indefinitely() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let mut cfg = Config::default();
        cfg.allowlists.push(Allowlist {
            id: "forever".into(),
            rule_ids: vec!["pack.demo.no-curl".into()],
            when: None,
            expires_at: None,
            reason: None,
        });
        let engine = Engine::with_components(cfg, set);
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert_eq!(outcome.decision, Decision::Allow);
    }

    #[test]
    fn allowlist_when_must_match_to_suppress() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use serde_yaml_ng::Value as YamlValue;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let when: YamlValue =
            serde_yaml_ng::from_str("shell.argv:\n  headAny: [wget]\n").expect("parse when");
        let mut cfg = Config::default();
        cfg.allowlists.push(Allowlist {
            id: "wget-only".into(),
            rule_ids: vec!["pack.demo.no-curl".into()],
            when: Some(crate::plugin::dsl::compile(&when).expect("compile when")),
            expires_at: None,
            reason: None,
        });
        let engine = Engine::with_components(cfg, set);
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert!(matches!(outcome.decision, Decision::Deny { .. }));
    }

    #[test]
    fn malformed_expiry_is_treated_as_already_expired() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let mut cfg = Config::default();
        cfg.allowlists.push(Allowlist {
            id: "garbage".into(),
            rule_ids: vec!["pack.demo.no-curl".into()],
            when: None,
            expires_at: Some("not-a-timestamp".into()),
            reason: None,
        });
        let engine = Engine::with_components(cfg, set);
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert!(matches!(outcome.decision, Decision::Deny { .. }));
    }

    #[test]
    fn allowlist_with_unrelated_rule_id_is_ignored() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let mut cfg = Config::default();
        cfg.allowlists.push(Allowlist {
            id: "unrelated".into(),
            rule_ids: vec!["some.other.rule".into()],
            when: None,
            expires_at: None,
            reason: None,
        });
        let engine = Engine::with_components(cfg, set);
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert!(matches!(outcome.decision, Decision::Deny { .. }));
    }

    #[test]
    fn engine_error_display_and_source_for_config_variant() {
        let cfg_err = ConfigError::Io {
            path: PathBuf::from("/etc/ptuf/policy.yaml"),
            source: std::io::Error::other("nope"),
        };
        let eng: EngineError = cfg_err.into();
        let msg = format!("{eng}");
        assert!(msg.starts_with("engine: "));
        assert!(msg.contains("policy.yaml"));
        let dyn_err: &dyn std::error::Error = &eng;
        assert!(dyn_err.source().is_some());
    }

    #[test]
    fn engine_error_display_and_source_for_plugin_variant() {
        let plug_err = PluginError::Io {
            path: PathBuf::from("/tmp/pack.yaml"),
            source: std::io::Error::other("nope"),
        };
        let eng: EngineError = plug_err.into();
        let msg = format!("{eng}");
        assert!(msg.starts_with("engine: "));
        let dyn_err: &dyn std::error::Error = &eng;
        assert!(dyn_err.source().is_some());
    }

    #[test]
    fn engine_new_succeeds_with_no_repo_root() {
        // No PTUF_CONFIG_DIR / PTUF_ETC_DIR fixtures in this process,
        // so the loader walks the empty default layout and yields the
        // builtin Config — exercising the Engine::new happy path.
        let engine = Engine::new(None).expect("default-environment engine");
        assert_eq!(engine.config().mode, Mode::Enforce);
        assert!(engine.plugins().rules().count() == 0);
    }

    #[test]
    fn engine_with_config_opens_jsonl_sink_when_audit_path_is_set() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-engine-jsonl-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        let mut cfg = Config::default();
        cfg.audit.path = Some(path.clone());
        let engine = Engine::with_config(cfg).expect("with_config");
        let _ = engine.decide(&bash("rm -rf /"));
        let body = std::fs::read_to_string(&path).expect("read audit log");
        assert!(body.contains("\"decision\":\"deny\""));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn engine_with_config_falls_back_to_noop_when_jsonl_open_fails() {
        // /proc/<unwritable>/audit.jsonl cannot be created; the engine
        // must still construct successfully (NoopSink fallback) so the
        // hook never blocks tool execution due to audit issues.
        let mut cfg = Config::default();
        cfg.audit.path = Some(PathBuf::from("/proc/this-cannot-be-created/audit.jsonl"));
        let engine = Engine::with_config(cfg).expect("with_config never aborts on audit open");
        assert!(engine.audit_warning().is_some());
        let outcome = engine.decide(&bash("ls"));
        assert_eq!(outcome.decision, Decision::Allow);
    }

    #[test]
    fn audit_record_carries_agent_set_via_with_agent_builder() {
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_denied = true;
        let engine = engine_with(cfg)
            .with_audit_sink(Box::new(SharedMemorySink(captured.clone())))
            .with_agent("claude-code");
        let _ = engine.decide(&bash("rm -rf /"));
        let recs = captured.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].agent, "claude-code");
        assert_eq!(recs[0].schema_version, 1);
    }

    #[test]
    fn audit_record_carries_default_unknown_agent_when_unset() {
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_denied = true;
        let engine = engine_with(cfg).with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("rm -rf /"));
        let recs = captured.records();
        assert_eq!(recs[0].agent, "unknown");
    }

    #[test]
    fn audit_record_carries_plugin_versions_for_loaded_plugins() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
  version: 1.2.3
rules:
  - id: pack.demo.allow-only
    severity: low
    defaultDecision: deny
    when:
      tool: Bash
      shell.argv:
        headAny: [curl]
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_allowed = true;
        let engine = Engine::with_components(cfg, set)
            .with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("ls"));
        let recs = captured.records();
        assert_eq!(recs[0].plugin_versions, vec!["pack.demo@1.2.3".to_string()]);
    }

    #[test]
    fn outcome_allowlist_id_set_when_allow_came_from_allowlist() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let mut cfg = Config::default();
        cfg.allowlists.push(Allowlist {
            id: "approved-curl".into(),
            rule_ids: vec!["pack.demo.no-curl".into()],
            when: None,
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            reason: None,
        });
        let engine = Engine::with_components(cfg, set);
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.allowlist_id.as_deref(), Some("approved-curl"));
    }

    #[test]
    fn outcome_allowlist_id_none_when_no_rule_was_suppressed() {
        let outcome = Engine::default().decide(&bash("ls"));
        assert!(outcome.allowlist_id.is_none());
    }

    #[test]
    fn outcome_allowlist_id_none_when_decision_is_deny() {
        // hardDeny rules ignore allowlists entirely; even with a
        // matching allowlist entry the outcome stays deny and
        // allowlist_id stays None.
        let mut cfg = Config::default();
        cfg.allowlists.push(Allowlist {
            id: "ignore-fs".into(),
            rule_ids: vec!["core.filesystem.destructive-rm".into()],
            when: None,
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            reason: None,
        });
        let outcome = engine_with(cfg).decide(&bash("rm -rf /"));
        assert!(matches!(outcome.decision, Decision::Deny { .. }));
        assert!(outcome.allowlist_id.is_none());
    }

    #[test]
    fn audit_record_carries_allowlist_id_when_allow_came_from_allowlist() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let mut cfg = Config::default();
        cfg.audit.include_allowed = true;
        cfg.allowlists.push(Allowlist {
            id: "approved-curl".into(),
            rule_ids: vec!["pack.demo.no-curl".into()],
            when: None,
            expires_at: None,
            reason: None,
        });
        let captured = Arc::new(MemorySink::new());
        let engine = Engine::with_components(cfg, set)
            .with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("curl https://example.com"));
        let recs = captured.records();
        assert_eq!(recs[0].decision, "allow");
        assert_eq!(recs[0].allowlist_id.as_deref(), Some("approved-curl"));
    }

    #[test]
    fn audit_record_severity_is_none_when_decision_carries_unknown_rule_id() {
        // Engine::severity_for walks builtin and plugin rules; when the
        // id is absent (e.g. a synthetic Decision::Monitor), it must
        // return None and the audit record reflects that.
        let captured = Arc::new(MemorySink::new());
        let engine = engine_with(Config::default())
            .with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        // Drive a Monitor outcome with an unknown rule id by placing it
        // through a plugin allowlist + monitor mode would be complex;
        // instead, exercise severity_for directly via the public API.
        assert!(engine.severity_for("nonexistent.rule").is_none());
    }

    use crate::testing::proptest::{decision, hook_input};
    use proptest::prelude::*;

    fn mode_strategy() -> impl Strategy<Value = Mode> {
        prop_oneof![
            Just(Mode::Enforce),
            Just(Mode::Monitor),
            Just(Mode::Observe),
        ]
    }

    fn demoting_mode() -> impl Strategy<Value = Mode> {
        prop_oneof![Just(Mode::Monitor), Just(Mode::Observe)]
    }

    fn non_deny_decision() -> impl Strategy<Value = Decision> {
        use crate::testing::proptest::{reason_text, rule_id};
        prop_oneof![
            Just(Decision::Allow),
            rule_id().prop_map(|rule_id| Decision::Monitor { rule_id }),
            (rule_id(), reason_text())
                .prop_map(|(rule_id, reason)| Decision::Ask { rule_id, reason }),
        ]
    }

    proptest! {
        // Enforce never demotes anything.
        #[test]
        fn pbt_enforce_is_identity(d in decision()) {
            let out = demote_for_mode(d.clone(), Mode::Enforce);
            prop_assert_eq!(out, d);
        }

        // Allow / Monitor / Ask are unaffected by Monitor and Observe.
        #[test]
        fn pbt_monitor_observe_only_touch_deny(d in non_deny_decision(), mode in demoting_mode()) {
            let out = demote_for_mode(d.clone(), mode);
            prop_assert_eq!(out, d);
        }

        // Deny under Monitor / Observe ⇒ Monitor with same rule_id.
        #[test]
        fn pbt_deny_demotes_to_monitor_preserving_rule_id(
            id in crate::testing::proptest::rule_id(),
            reason in crate::testing::proptest::reason_text(),
            mode in demoting_mode(),
        ) {
            let d = Decision::Deny {
                rule_id: id.clone(),
                reason,
            };
            let out = demote_for_mode(d, mode);
            prop_assert_eq!(out, Decision::Monitor { rule_id: id });
        }

        // Demotion never strengthens the decision (severity does not grow).
        #[test]
        fn pbt_demote_never_increases_severity(d in decision(), mode in mode_strategy()) {
            let raw = d.clone();
            let out = demote_for_mode(d, mode);
            prop_assert!(out.severity() <= raw.severity());
        }

        // The default-engine end-to-end pipeline must not panic.
        #[test]
        fn pbt_default_engine_decide_never_panics(input in hook_input()) {
            let _ = Engine::default().decide(&input);
        }

        // Default engine runs in Enforce mode and never reports a demotion.
        #[test]
        fn pbt_default_engine_never_demotes(input in hook_input()) {
            let outcome = Engine::default().decide(&input);
            prop_assert_eq!(outcome.mode, Mode::Enforce);
            prop_assert!(!outcome.mode_demoted);
        }

        // Under Monitor mode, the outcome decision is never Deny, and
        // mode_demoted iff the same input under Enforce produced Deny.
        #[test]
        fn pbt_monitor_mode_demotion_flag_matches_enforce_baseline(input in hook_input()) {
            let baseline = Engine::default().decide(&input).decision;
            let cfg = Config {
                mode: Mode::Monitor,
                ..Config::default()
            };
            let monitored = engine_with(cfg).decide(&input);
            let monitored_is_deny = matches!(monitored.decision, Decision::Deny { .. });
            prop_assert!(!monitored_is_deny);
            let baseline_was_deny = matches!(baseline, Decision::Deny { .. });
            prop_assert_eq!(monitored.mode_demoted, baseline_was_deny);
        }

        // Default engine on richer hook inputs (Bash + Read/Edit/Write +
        // WebFetch + arbitrary tools) never panics and never demotes.
        #[test]
        fn pbt_default_engine_never_panics_on_richer_inputs(
            input in crate::testing::proptest::richer_hook_input(),
        ) {
            let outcome = Engine::default().decide(&input);
            prop_assert!(!outcome.mode_demoted);
        }

        // Allowlisting an overridable builtin rule must suppress that
        // rule's contribution; if it was the sole non-Allow decision,
        // the outcome flips back to Allow. `force-push-with-lease` is
        // overridable (hard_deny == false); `force-push` itself is not.
        #[test]
        fn pbt_allowlist_suppresses_overridable_git_rule(_dummy in 0u8..=0u8) {
            let mut cfg = Config::default();
            cfg.allowlists.push(Allowlist {
                id: "pbt-test".into(),
                rule_ids: vec!["core.git.force-push-with-lease".into()],
                when: None,
                expires_at: None,
                reason: None,
            });
            let outcome = engine_with(cfg)
                .decide(&bash("git push --force-with-lease origin main"));
            // Without allowlist this would be Deny; with allowlist it
            // should fall through to Allow (no other rule matches).
            prop_assert_eq!(outcome.decision, Decision::Allow);
        }

        // Disabling an overridable pack via pack_overrides has the same
        // effect as the allowlist for the same rule.
        #[test]
        fn pbt_pack_override_suppresses_overridable_git_pack(_dummy in 0u8..=0u8) {
            let mut cfg = Config::default();
            cfg.pack_overrides.insert(
                "core.git.force-push-with-lease".into(),
                PackOverride { enabled: Some(false) },
            );
            let outcome = engine_with(cfg)
                .decide(&bash("git push --force-with-lease origin main"));
            prop_assert_eq!(outcome.decision, Decision::Allow);
        }

        // Hard-deny rules ignore both pack overrides and allowlists.
        // `core.filesystem.destructive-rm` is hard-deny, so disabling
        // its pack and allowlisting its id must not let it through.
        #[test]
        fn pbt_hard_deny_ignores_pack_and_allowlist(_dummy in 0u8..=0u8) {
            let mut cfg = Config::default();
            cfg.pack_overrides.insert(
                "core.filesystem".into(),
                PackOverride { enabled: Some(false) },
            );
            cfg.allowlists.push(Allowlist {
                id: "pbt-test".into(),
                rule_ids: vec!["core.filesystem.destructive-rm".into()],
                when: None,
                expires_at: None,
                reason: None,
            });
            let outcome = engine_with(cfg).decide(&bash("rm -rf /"));
            let is_deny = matches!(outcome.decision, Decision::Deny { .. });
            prop_assert!(is_deny);
        }

        // Expired allowlists do not suppress: an `expiresAt` in the past
        // (year 2000) leaves the rule effective.
        #[test]
        fn pbt_expired_allowlist_does_not_suppress(_dummy in 0u8..=0u8) {
            let mut cfg = Config::default();
            cfg.allowlists.push(Allowlist {
                id: "pbt-test".into(),
                rule_ids: vec!["core.git.force-push-with-lease".into()],
                when: None,
                expires_at: Some("2000-01-01T00:00:00Z".into()),
                reason: None,
            });
            let outcome = engine_with(cfg)
                .decide(&bash("git push --force-with-lease origin main"));
            // The rule must still fire — exact decision shape depends on
            // its default (Ask in this case), but it must not be Allow.
            let is_allow = outcome.decision == Decision::Allow;
            prop_assert!(!is_allow);
        }

        // Observe mode never produces a Deny on any input.
        #[test]
        fn pbt_observe_mode_never_denies(input in hook_input()) {
            let cfg = Config { mode: Mode::Observe, ..Config::default() };
            let outcome = engine_with(cfg).decide(&input);
            let is_deny = matches!(outcome.decision, Decision::Deny { .. });
            prop_assert!(!is_deny);
        }

        // The audited record's command_redacted is exactly redact_strict
        // applied to the raw bash command for Bash inputs.
        #[test]
        fn pbt_audit_redaction_matches_redact_strict(cmd in crate::testing::proptest::bash_command()) {
            let captured = Arc::new(MemorySink::new());
            let cfg = Config {
                audit: crate::config::AuditConfig {
                    include_allowed: true,
                    ..Config::default().audit
                },
                ..Config::default()
            };
            let engine = engine_with(cfg)
                .with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
            let _ = engine.decide(&bash(&cmd));
            let recs = captured.records();
            prop_assert!(!recs.is_empty(), "expected at least one audit record");
            let expected = redact_strict(&cmd);
            prop_assert_eq!(&recs[0].command_redacted, &expected);
        }
    }

    #[test]
    fn plugin_pack_can_be_disabled_via_config() {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let mut cfg = Config::default();
        cfg.pack_overrides.insert(
            "pack.demo".into(),
            PackOverride {
                enabled: Some(false),
            },
        );
        let engine = Engine::with_components(cfg, set);
        let outcome = engine.decide(&bash("ls"));
        assert_eq!(outcome.decision, Decision::Allow);
    }

    #[test]
    fn self_protection_fires_when_input_targets_protected_path() {
        #![allow(clippy::expect_used)]
        use crate::self_paths::ProtectedPaths;
        use std::path::PathBuf;

        let plugin_path = PathBuf::from("/tmp/ptuf-test-plugin.yaml");
        let mut cfg = Config::default();
        cfg.plugin_paths.push(plugin_path.clone());
        let mut engine = Engine::with_components(cfg, PluginSet::new());
        // Inject a deterministic protected set rather than relying on
        // process state.
        engine.protected = ProtectedPaths {
            repo_root: None,
            binary: None,
            configs: Vec::new(),
            plugins: vec![plugin_path.clone()],
            claude_settings: Vec::new(),
            codex_settings: Vec::new(),
            hook_scripts: Vec::new(),
        };
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({ "file_path": plugin_path }),
        };
        let outcome = engine.decide(&input);
        match &outcome.decision {
            Decision::Deny { rule_id, .. } => {
                assert_eq!(rule_id, "core.self_protection.plugin");
            }
            other => panic!("expected deny from self_protection, got {other:?}"),
        }
    }

    /// Helper: build a one-rule plugin set with a `tool: Bash` matcher
    /// so engine tests can exercise rule_overrides paths against an
    /// overridable (non-hard-deny) rule.
    fn plugin_set_with_bash_deny() -> PluginSet {
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        set
    }

    #[test]
    fn rule_override_with_enabled_false_suppresses_overridable_plugin_rule() {
        // overlay { enabled: Some(false) } with no decision must drop
        // the rule's contribution entirely → engine.rs:408-409.
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            crate::config::RuleOverride {
                enabled: Some(false),
                decision: None,
                severity: None,
            },
        );
        let engine = Engine::with_components(cfg, plugin_set_with_bash_deny());
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert_eq!(outcome.decision, Decision::Allow);
    }

    #[test]
    fn rule_override_without_decision_leaves_decision_unchanged() {
        // overlay { enabled: Some(true), decision: None } must hit the
        // "decision is None" arm and leave the original deny in place
        // → engine.rs:411-412.
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            crate::config::RuleOverride {
                enabled: Some(true),
                decision: None,
                severity: None,
            },
        );
        let engine = Engine::with_components(cfg, plugin_set_with_bash_deny());
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert!(
            matches!(outcome.decision, Decision::Deny { .. }),
            "expected Deny, got {:?}",
            outcome.decision
        );
    }

    #[test]
    fn rule_override_changes_overridable_deny_to_monitor() {
        // overlay { decision: Monitor } against an overridable plugin
        // rule must produce a Decision::Monitor with the same rule_id
        // → engine.rs:417, 436-444 (decision_with_kind Monitor arm).
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            crate::config::RuleOverride {
                enabled: None,
                decision: Some(DecisionKind::Monitor),
                severity: None,
            },
        );
        let engine = Engine::with_components(cfg, plugin_set_with_bash_deny());
        let outcome = engine.decide(&bash("curl https://example.com"));
        match outcome.decision {
            Decision::Monitor { rule_id } => {
                assert_eq!(rule_id, "pack.demo.no-curl");
            }
            other => panic!("expected Monitor, got {other:?}"),
        }
    }

    #[test]
    fn rule_override_changes_overridable_deny_to_ask() {
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            crate::config::RuleOverride {
                enabled: None,
                decision: Some(DecisionKind::Ask),
                severity: None,
            },
        );
        let engine = Engine::with_components(cfg, plugin_set_with_bash_deny());
        let outcome = engine.decide(&bash("curl https://example.com"));
        match outcome.decision {
            Decision::Ask { rule_id, reason } => {
                assert_eq!(rule_id, "pack.demo.no-curl");
                assert!(reason.contains("nope"));
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn rule_override_changes_overridable_deny_to_allow() {
        // Hits the DecisionKind::Allow arm of decision_with_kind.
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            crate::config::RuleOverride {
                enabled: None,
                decision: Some(DecisionKind::Allow),
                severity: None,
            },
        );
        let engine = Engine::with_components(cfg, plugin_set_with_bash_deny());
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert_eq!(outcome.decision, Decision::Allow);
    }

    #[test]
    fn rule_override_attempts_to_weaken_hard_deny_are_blocked() {
        // Hard-deny rules must ignore overlay attempts to weaken them.
        // `core.filesystem.destructive-rm` is hard_deny; trying to demote
        // it to Monitor must not change the outcome (stays Deny). Hits
        // override_allowed false branch → engine.rs:414-415, 420-424.
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "core.filesystem.destructive-rm".into(),
            crate::config::RuleOverride {
                enabled: None,
                decision: Some(DecisionKind::Monitor),
                severity: None,
            },
        );
        let outcome = engine_with(cfg).decide(&bash("rm -rf /"));
        assert!(
            matches!(outcome.decision, Decision::Deny { .. }),
            "hard_deny must ignore weakening overlay, got {:?}",
            outcome.decision
        );
    }

    #[test]
    fn rule_override_strengthens_overridable_to_higher_kind_via_rank_check() {
        // For an overridable rule, override_allowed always returns true,
        // so any kind change is honoured. This complements the
        // hard-deny test above and pins the `decision_rank` ordering.
        let mut cfg = Config::default();
        // Plugin defaultDecision is deny; promote to Ask (lower rank).
        // The override is allowed because the rule is overridable.
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            crate::config::RuleOverride {
                enabled: None,
                decision: Some(DecisionKind::Ask),
                severity: None,
            },
        );
        let engine = Engine::with_components(cfg, plugin_set_with_bash_deny());
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert!(matches!(outcome.decision, Decision::Ask { .. }));
    }

    #[test]
    fn rule_override_severity_propagates_to_audit_record() {
        // overlay { severity: High } on an overridable rule must surface
        // in the audit record → engine.rs:454-456 (effective_severity
        // overlay match arm).
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_denied = true;
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            crate::config::RuleOverride {
                enabled: None,
                decision: None,
                severity: Some(Severity::High),
            },
        );
        let engine = Engine::with_components(cfg, plugin_set_with_bash_deny())
            .with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("curl https://example.com"));
        let recs = captured.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].severity, Some("high"));
    }

    #[test]
    fn rule_override_severity_is_ignored_for_hard_deny_rule() {
        // For a hard_deny rule the severity overlay must NOT replace
        // the rule's own severity (engine.rs:454-456 fallthrough arm).
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_denied = true;
        cfg.rule_overrides.insert(
            "core.filesystem.destructive-rm".into(),
            crate::config::RuleOverride {
                enabled: None,
                decision: None,
                severity: Some(Severity::Low),
            },
        );
        let engine = engine_with(cfg).with_audit_sink(Box::new(SharedMemorySink(captured.clone())));
        let _ = engine.decide(&bash("rm -rf /"));
        let recs = captured.records();
        assert_eq!(recs.len(), 1);
        // Built-in destructive-rm rule advertises Critical; the overlay
        // is ignored because the rule is hard_deny.
        assert_eq!(recs[0].severity, Some("critical"));
    }

    #[test]
    fn engine_with_disabled_audit_uses_noop_sink_and_no_warning() {
        // config.audit.enabled = false short-circuits to NoopSink with
        // no warning → engine.rs:357.
        let mut cfg = Config::default();
        cfg.audit.enabled = false;
        cfg.audit.include_denied = true;
        let engine = Engine::with_config(cfg).expect("with_config");
        assert!(engine.audit_warning().is_none());
        // Even include_denied = true cannot produce records when the
        // sink is the NoopSink — exercising the early-return branch.
        let _ = engine.decide(&bash("rm -rf /"));
    }

    #[test]
    fn rule_override_changes_overridable_to_deny_keeps_default_reason() {
        // Promoting an overridable plugin Ask/Monitor rule to Deny
        // exercises the Deny arm of decision_with_kind (lines 446).
        // Build a plugin whose defaultDecision is Ask, then overlay it
        // to Deny.
        #![allow(clippy::expect_used)]
        use crate::plugin::load_str;
        use std::path::Path;

        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.ask-curl
    severity: medium
    defaultDecision: ask
    when:
      tool: Bash
    reason: confirm
"#;
        let plugin = load_str(Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.ask-curl".into(),
            crate::config::RuleOverride {
                enabled: None,
                decision: Some(DecisionKind::Deny),
                severity: None,
            },
        );
        let engine = Engine::with_components(cfg, set);
        let outcome = engine.decide(&bash("curl https://example.com"));
        match outcome.decision {
            Decision::Deny { rule_id, reason } => {
                assert_eq!(rule_id, "pack.demo.ask-curl");
                assert!(reason.contains("confirm"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }
}
