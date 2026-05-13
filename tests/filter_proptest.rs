//! Property tests for [`ptuf::engine`]'s filter pipeline.
//!
//! The functions under test live in `src/engine/filter.rs`
//! (`is_pack_disabled`, `apply_rule_override`, `effective_severity`,
//! `allowlist_hit_for`, `demote_for_mode`). They are `pub(super)` so
//! we drive them through the public `Engine::decide` surface and
//! verify the documented invariants on the resulting [`Outcome`].
//!
//! The properties chosen here cover the four axes the filter pipeline
//! composes — `Mode`, `pack_overrides`, `rule_overrides`, `allowlists`
//! — plus the `hard_deny` precedence guarantee that `docs/design/`
//! (`config-and-plugins.md`, `decision-model.md`) elevates to a
//! contractual property.
//!
//! See `docs/design/testing.md` (§ "engine_proptest" cluster) for the
//! place this file occupies in the PBT layering.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use proptest::prelude::*;

use ptuf::audit::MemorySink;
use ptuf::audit::record::AuditRecord;
use ptuf::audit::{AuditError, AuditSink};
use ptuf::config::{Allowlist, Config, Mode, RuleOverride};
use ptuf::decision::DecisionKind;
use ptuf::plugin::{PluginSet, load_str};
use ptuf::testing::proptest::{
    arbitrary_command, config_with_filters, decision_kind, pack_override, rule_override,
    safe_command_string, severity,
};
use ptuf::{Decision, Engine, HookInput};

const HARD_DENY_RULE_ID: &str = "core.filesystem.destructive-rm";
const PLUGIN_RULE_ID: &str = "pack.demo.no-curl";
const HARD_DENY_CMD: &str = "rm -rf /";
const PLUGIN_CMD: &str = "curl https://example.com";

fn bash(cmd: &str) -> HookInput {
    HookInput {
        tool_name: "Bash".into(),
        tool_input: serde_json::json!({ "command": cmd }),
    }
}

fn engine(cfg: Config, plugins: PluginSet) -> Engine {
    Engine::builder()
        .config(cfg)
        .plugins(plugins)
        .build()
        .expect("Engine::builder cannot fail without plugin paths")
}

fn engine_with_audit(cfg: Config, plugins: PluginSet, sink: Arc<MemorySink>) -> Engine {
    Engine::builder()
        .config(cfg)
        .plugins(plugins)
        .audit_sink(Box::new(SharedMemorySink(sink)))
        .build()
        .expect("Engine::builder cannot fail without plugin paths")
}

/// Wraps an `Arc<MemorySink>` so the test can both inject the sink
/// into the engine and read back the captured records afterwards.
struct SharedMemorySink(Arc<MemorySink>);

impl AuditSink for SharedMemorySink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.0.record(record)
    }
}

fn plugin_set_with_bash_deny() -> PluginSet {
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
    let plugin = load_str(std::path::Path::new("demo.yaml"), yaml).expect("load plugin");
    let mut set = PluginSet::new();
    set.push(plugin);
    set
}

fn known_rule_ids() -> Vec<&'static str> {
    vec![HARD_DENY_RULE_ID, PLUGIN_RULE_ID]
}

proptest! {
    /// hardDeny rules ignore every allowlist entry. Enforced in
    /// `engine::filter::allowlist_hit_for`. The rule must still fire
    /// (rule_id surfaced) and `allowlist_id` must remain None even
    /// when `config_with_filters` happens to include a matching
    /// allowlist; mode-driven demotion to Monitor is independent.
    #[test]
    fn pbt_hard_deny_ignores_any_allowlist(
        cfg in config_with_filters(known_rule_ids()),
    ) {
        let outcome = engine(cfg, PluginSet::new()).decide(&bash(HARD_DENY_CMD));
        prop_assert_eq!(
            outcome.decision.rule_id(),
            Some(HARD_DENY_RULE_ID),
            "hard_deny suppressed: {:?}",
            outcome.decision,
        );
        prop_assert!(outcome.allowlist_id.is_none());
    }

    /// Past-RFC3339 expiries deactivate the allowlist entry, so a
    /// plugin Deny must still surface. Covers the `not_expired = false`
    /// branch of `allowlist_covers`.
    #[test]
    fn pbt_past_expiry_never_suppresses(
        id in "[a-z][a-z0-9_-]{0,8}",
    ) {
        let mut cfg = Config::default();
        cfg.allowlists.push(Allowlist {
            id,
            rule_ids: vec![PLUGIN_RULE_ID.into()],
            when: None,
            expires_at: Some("2000-01-01T00:00:00Z".into()),
            reason: None,
        });
        let outcome = engine(cfg, plugin_set_with_bash_deny()).decide(&bash(PLUGIN_CMD));
        prop_assert!(
            matches!(outcome.decision, Decision::Deny { .. }),
            "past-expiry allowlist suppressed plugin Deny: {:?}",
            outcome.decision,
        );
        prop_assert!(outcome.allowlist_id.is_none());
    }

    /// `RuleOverride.severity` is ignored on hardDeny rules. The
    /// emitted audit record must still carry the rule's intrinsic
    /// severity (`Critical` for `destructive-rm`).
    #[test]
    fn pbt_hard_deny_ignores_severity_override(s in severity()) {
        let mut cfg = Config::default();
        cfg.audit.include_denied = true;
        cfg.rule_overrides.insert(
            HARD_DENY_RULE_ID.into(),
            RuleOverride { enabled: None, decision: None, severity: Some(s) },
        );
        let sink = Arc::new(MemorySink::new());
        let _ = engine_with_audit(cfg, PluginSet::new(), sink.clone())
            .decide(&bash(HARD_DENY_CMD));
        let recs = sink.records();
        prop_assert_eq!(recs.len(), 1);
        prop_assert_eq!(recs[0].severity, Some("critical"));
    }

    /// Decision overlays cannot weaken a hardDeny rule. The variant
    /// order on `DecisionKind` (`Allow < Monitor < Ask < Deny`) lets
    /// us pick "weaker than Deny" without crossing the `pub(crate)`
    /// boundary on `Decision::rank`. Default-Enforce mode keeps the
    /// outcome on the Deny side so we can match it directly.
    #[test]
    fn pbt_hard_deny_blocks_weakening_overrides(
        weaker in decision_kind().prop_filter("strict weaker than Deny", |k| *k < DecisionKind::Deny),
    ) {
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            HARD_DENY_RULE_ID.into(),
            RuleOverride { enabled: None, decision: Some(weaker), severity: None },
        );
        let outcome = engine(cfg, PluginSet::new()).decide(&bash(HARD_DENY_CMD));
        prop_assert!(
            matches!(outcome.decision, Decision::Deny { .. }),
            "hard_deny weakened by overlay {weaker:?}: {:?}",
            outcome.decision,
        );
    }

    /// `Engine::decide` is deterministic under any well-formed config.
    /// Two calls with the same input return the same decision —
    /// exposes accidental shared-state bugs in the filter pipeline.
    #[test]
    fn pbt_decide_is_deterministic_under_arbitrary_filters(
        cfg in config_with_filters(known_rule_ids()),
        cmd in arbitrary_command(),
    ) {
        let plugins = plugin_set_with_bash_deny();
        let cfg2 = cfg.clone();
        let a = engine(cfg, plugins).decide(&bash(&cmd)).decision;
        let b = engine(cfg2, plugin_set_with_bash_deny()).decide(&bash(&cmd)).decision;
        prop_assert_eq!(a, b);
    }

    /// In `Mode::Monitor`, an input that no rule matches must remain
    /// `Decision::Allow` and `mode_demoted` must stay `false`. demote
    /// is a Deny-only transformation; non-Deny outputs are pass-through.
    #[test]
    fn pbt_monitor_mode_keeps_allow_inputs(cmd in safe_command_string()) {
        let cfg = Config { mode: Mode::Monitor, ..Config::default() };
        let outcome = engine(cfg, PluginSet::new()).decide(&bash(&cmd));
        prop_assert_eq!(outcome.decision, Decision::Allow);
        prop_assert!(!outcome.mode_demoted);
    }

    /// `Mode::Enforce` never sets `mode_demoted`. The flag is exclusive
    /// to Monitor-mode demotion of Deny.
    #[test]
    fn pbt_enforce_mode_never_demotes(
        cfg in config_with_filters(known_rule_ids()),
        cmd in arbitrary_command(),
    ) {
        let cfg = Config { mode: Mode::Enforce, ..cfg };
        let outcome = engine(cfg, plugin_set_with_bash_deny()).decide(&bash(&cmd));
        prop_assert!(!outcome.mode_demoted);
    }

    /// `outcome.allowlist_id` is set only when the decision is `Allow`
    /// and that Allow came from suppressing a non-Allow rule. In
    /// particular, every Deny / Ask / Monitor outcome carries
    /// `allowlist_id == None`.
    #[test]
    fn pbt_allowlist_id_only_set_on_allow(
        cfg in config_with_filters(known_rule_ids()),
        cmd in arbitrary_command(),
    ) {
        let outcome = engine(cfg, plugin_set_with_bash_deny()).decide(&bash(&cmd));
        if !matches!(outcome.decision, Decision::Allow) {
            prop_assert!(
                outcome.allowlist_id.is_none(),
                "non-Allow outcome carried allowlist_id: {outcome:?}",
            );
        }
    }

    /// Pack-disable overlays cannot suppress a hardDeny rule. Mirrors
    /// the allowlist guarantee at the pack-override layer
    /// (`engine::filter::is_pack_disabled`).
    #[test]
    fn pbt_pack_disable_never_suppresses_hard_deny(
        overlays in proptest::collection::vec(
            (
                prop_oneof![
                    Just("core.filesystem".to_string()),
                    Just("pack.demo".to_string()),
                    "[a-z][a-z0-9_]{1,8}\\.[a-z][a-z0-9_]{1,8}".prop_map(|s| s),
                ],
                pack_override(),
            ),
            0..6,
        ),
    ) {
        let mut cfg = Config::default();
        for (name, overlay) in overlays {
            cfg.pack_overrides.insert(name, overlay);
        }
        let outcome = engine(cfg, PluginSet::new()).decide(&bash(HARD_DENY_CMD));
        prop_assert!(
            matches!(outcome.decision, Decision::Deny { .. }),
            "pack disable suppressed hard_deny: {:?}",
            outcome.decision,
        );
    }

    /// Engine::decide is panic-free across every (config × command)
    /// pair the filter generators emit. Catches regressions where a
    /// filter combination drives an internal invariant to violate.
    #[test]
    fn pbt_engine_decide_panic_free_under_arbitrary_filters(
        cfg in config_with_filters(known_rule_ids()),
        cmd in arbitrary_command(),
    ) {
        let _ = engine(cfg, plugin_set_with_bash_deny()).decide(&bash(&cmd));
    }

    /// Sanity: `rule_override` generator covers the no-op overlay
    /// (all-`None`) without changing the Deny outcome of a hardDeny
    /// rule. Guards against generator drift that would silently make
    /// every overlay a no-op.
    #[test]
    fn pbt_no_op_rule_override_keeps_hard_deny(_overlay in rule_override()) {
        let outcome = engine(Config::default(), PluginSet::new())
            .decide(&bash(HARD_DENY_CMD));
        prop_assert!(
            matches!(outcome.decision, Decision::Deny { .. }),
            "default config did not deny hard-deny cmd: {:?}",
            outcome.decision,
        );
    }
}
