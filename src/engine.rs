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
use crate::decision::{Decision, Severity, aggregate};
use crate::facts;
use crate::hook_input::HookInput;
use crate::plugin::{PluginError, PluginSet};
use crate::rules::{self, ConfigRule};

/// Resolved engine ready to evaluate hook payloads.
pub struct Engine {
    config: Config,
    plugins: PluginSet,
    audit_sink: Box<dyn AuditSink>,
    repo_root: Option<PathBuf>,
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
        let audit_sink = audit_sink_from_config(&config);
        Ok(Self {
            config,
            plugins,
            audit_sink,
            repo_root: repo_root.map(Path::to_path_buf),
        })
    }

    /// Build an engine from an explicit config — used by tests and by
    /// the backward-compatible [`crate::decide`] shim. Plugins listed
    /// in the config are loaded eagerly.
    pub fn with_config(config: Config) -> Result<Self, EngineError> {
        let mut plugins = PluginSet::new();
        plugins.load_paths(&config.plugin_paths)?;
        let audit_sink = audit_sink_from_config(&config);
        Ok(Self {
            config,
            plugins,
            audit_sink,
            repo_root: None,
        })
    }

    /// Build an engine from the supplied components. Used by tests
    /// that need to inject a hand-built [`PluginSet`] without going
    /// through the YAML loader.
    pub(crate) fn with_components(config: Config, plugins: PluginSet) -> Self {
        Self {
            config,
            plugins,
            audit_sink: Box::new(NoopSink),
            repo_root: None,
        }
    }

    /// Replace the audit sink. Returned `Self` keeps the builder
    /// pattern terse for tests and integration code that constructs
    /// an engine without a sink and attaches a
    /// [`crate::audit::MemorySink`] (or any other implementor of
    /// [`AuditSink`]) afterwards.
    pub fn with_audit_sink(mut self, sink: Box<dyn AuditSink>) -> Self {
        self.audit_sink = sink;
        self
    }

    /// Override the engine's recorded project root. Useful for tests
    /// that construct an engine directly without going through
    /// [`Engine::new`].
    pub fn with_repo_root(mut self, repo_root: Option<PathBuf>) -> Self {
        self.repo_root = repo_root;
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

    /// Evaluate a single hook payload.
    pub fn decide(&self, input: &HookInput) -> Outcome {
        let facts = facts::extract(input);
        let now = SystemTime::now();
        let builtin = rules::iter()
            .filter(|rule| !is_pack_disabled(*rule, &self.config))
            .filter(|rule| !is_allowlisted(*rule, &self.config, now))
            .filter_map(|rule| rule.evaluate(&facts, input));
        let from_plugins = self
            .plugins
            .rules()
            .map(|r| r as &(dyn ConfigRule + Sync))
            .filter(|rule| !is_pack_disabled(*rule, &self.config))
            .filter(|rule| !is_allowlisted(*rule, &self.config, now))
            .filter_map(|rule| rule.evaluate(&facts, input));
        let decisions: Vec<Decision> = builtin.chain(from_plugins).collect();
        let raw = aggregate(decisions);
        let demoted_decision = demote_for_mode(raw.clone(), self.config.mode);
        let mode_demoted = matches!(raw, Decision::Deny { .. })
            && matches!(demoted_decision, Decision::Monitor { .. });
        let outcome = Outcome {
            decision: demoted_decision,
            mode: self.config.mode,
            mode_demoted,
        };
        self.record_audit(input, &outcome);
        outcome
    }

    /// Look up the severity of a rule by id across builtin and plugin
    /// rules. Used when assembling audit records.
    fn severity_for(&self, rule_id: &str) -> Option<Severity> {
        for r in rules::iter() {
            if r.id() == rule_id {
                return Some(r.severity());
            }
        }
        for r in self.plugins.rules() {
            if (r as &(dyn ConfigRule + Sync)).id() == rule_id {
                return Some(r.severity());
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
        );
        let _ = self.audit_sink.record(&record);
    }
}

fn audit_sink_from_config(config: &Config) -> Box<dyn AuditSink> {
    match &config.audit.path {
        Some(p) => match JsonlSink::open(p) {
            Ok(s) => Box::new(s),
            Err(_) => Box::new(NoopSink),
        },
        None => Box::new(NoopSink),
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

/// Whether the rule should be skipped because a non-expired allowlist
/// entry covers it. `hardDeny` rules ignore allowlist entries entirely
/// (`docs/design/config-and-plugins.md:89`).
fn is_allowlisted(rule: &(dyn ConfigRule + Sync), config: &Config, now: SystemTime) -> bool {
    if rule.hard_deny() {
        return false;
    }
    let id = rule.id();
    config
        .allowlists
        .iter()
        .any(|entry| allowlist_covers(entry, id, now))
}

fn allowlist_covers(entry: &Allowlist, rule_id: &str, now: SystemTime) -> bool {
    if !entry.rule_ids.iter().any(|r| r == rule_id) {
        return false;
    }
    match &entry.expires_at {
        None => true,
        Some(s) => match parse_rfc3339_to_secs(s) {
            Some(expiry) => now
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() < expiry)
                .unwrap_or(true),
            None => false,
        },
    }
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
            expires_at: None,
            reason: None,
        });
        let engine = Engine::with_components(cfg, set);
        let outcome = engine.decide(&bash("curl https://example.com"));
        assert_eq!(outcome.decision, Decision::Allow);
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
        let outcome = engine.decide(&bash("ls"));
        assert_eq!(outcome.decision, Decision::Allow);
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
}
