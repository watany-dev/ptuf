//! Pre/post-evaluation rule filters used by [`super::Engine::decide`].
//!
//! Three concerns live here:
//!
//! - **pack overrides** — drop a rule before evaluating it if the pack
//!   it belongs to was disabled (`pack_overrides`)
//! - **rule overrides** — apply per-rule `enabled` / `decision` /
//!   `severity` overlays after the rule produced a `Decision`
//! - **allowlists** — suppress a non-`Allow` decision when a matching
//!   `allowlists[]` entry covers the rule under the current facts
//! - **mode demotion** — turn a `Deny` into `Monitor` when running in
//!   `Mode::Monitor`
//!
//! All public items are `pub(super)` and only callable from
//! `super::Engine`.

use std::time::SystemTime;

use crate::audit::time::parse_rfc3339_to_secs;
use crate::config::{Allowlist, Config, Mode, PackOverride};
use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts;
use crate::hook_input::HookInput;
use crate::rules::ConfigRule;

pub(super) fn is_pack_disabled(rule: &(dyn ConfigRule + Sync), config: &Config) -> bool {
    if rule.hard_deny() {
        return false;
    }
    let id = rule.id();
    config
        .pack_overrides
        .iter()
        .any(|(pack, overlay)| pack_disabled(overlay) && rule_matches_pack(id, pack))
}

pub(super) fn apply_rule_override(
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
        .map_or_else(|| format!("Blocked by ptuf rule {rule_id}."), str::to_owned);
    match kind {
        DecisionKind::Allow => Decision::Allow,
        DecisionKind::Monitor => Decision::Monitor { rule_id },
        DecisionKind::Ask => Decision::Ask { rule_id, reason },
        DecisionKind::Deny => Decision::Deny { rule_id, reason },
    }
}

pub(super) fn effective_severity(rule: &(dyn ConfigRule + Sync), config: &Config) -> Severity {
    let Some(overlay) = config.rule_overrides.get(rule.id()) else {
        return rule.severity();
    };
    match overlay.severity {
        Some(severity) if rule.overridable() && !rule.hard_deny() => severity,
        _ => rule.severity(),
    }
}

pub(super) struct AllowlistContext<'a> {
    pub(super) facts: &'a facts::Facts,
    pub(super) input: &'a HookInput,
    pub(super) config: &'a Config,
    pub(super) now: SystemTime,
}

/// First non-expired allowlist entry that covers the rule, returned
/// by id. `hardDeny` rules ignore allowlist entries entirely
/// (`docs/design/config-and-plugins.md:89`). Returns `None` when no
/// allowlist entry applies.
pub(super) fn allowlist_hit_for<'a>(
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

pub(super) fn demote_for_mode(decision: Decision, mode: Mode) -> Decision {
    if matches!(mode, Mode::Monitor)
        && let Decision::Deny { rule_id, .. } = decision
    {
        return Decision::Monitor { rule_id };
    }
    decision
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use crate::audit::MemorySink;
    use crate::config::{Allowlist, Config, Mode, PackOverride, RuleOverride};
    use crate::decision::{Decision, DecisionKind, Severity};
    use crate::plugin::{PluginSet, load_str};

    use super::super::Engine;
    use super::super::test_support::{
        SharedMemorySink, bash, engine_with, plugin_set_with_bash_deny,
    };
    use super::*;

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
        use serde_yaml_ng::Value as YamlValue;

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
    fn outcome_allowlist_id_set_when_allow_came_from_allowlist() {
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
        let outcome = engine_with(Config::default()).decide(&bash("ls"));
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
    fn plugin_pack_can_be_disabled_via_config() {
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
    fn rule_override_with_enabled_false_suppresses_overridable_plugin_rule() {
        // overlay { enabled: Some(false) } with no decision must drop
        // the rule's contribution entirely.
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            RuleOverride {
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
        // "decision is None" arm and leave the original deny in place.
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            RuleOverride {
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
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            RuleOverride {
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
            },
            other => panic!("expected Monitor, got {other:?}"),
        }
    }

    #[test]
    fn rule_override_changes_overridable_deny_to_ask() {
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            RuleOverride {
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
            },
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn rule_override_changes_overridable_deny_to_allow() {
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            RuleOverride {
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
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "core.filesystem.destructive-rm".into(),
            RuleOverride {
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
        // so any kind change is honoured.
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            RuleOverride {
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
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_denied = true;
        cfg.rule_overrides.insert(
            "pack.demo.no-curl".into(),
            RuleOverride {
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
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_denied = true;
        cfg.rule_overrides.insert(
            "core.filesystem.destructive-rm".into(),
            RuleOverride {
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
    fn rule_override_changes_overridable_to_deny_keeps_default_reason() {
        // Promoting an overridable plugin Ask rule to Deny exercises the
        // Deny arm of decision_with_kind.
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
        let plugin = load_str(std::path::Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let mut cfg = Config::default();
        cfg.rule_overrides.insert(
            "pack.demo.ask-curl".into(),
            RuleOverride {
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
            },
            other => panic!("expected Deny, got {other:?}"),
        }
    }
}
