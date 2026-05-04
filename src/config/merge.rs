//! Scope merge: fold a vector of [`RawConfig`] layers (lowest first)
//! into a single [`Config`].
//!
//! Merge rules:
//! * Scalars (`mode`, `fail_closed`, `audit.path`): later layers'
//!   `Some(_)` wins.
//! * `rule_overrides`: union by rule id; for the same rule id the
//!   later layer's [`RuleOverride`] wins for any `Some(_)` field.
//! * `allowlists`: concatenate in scope order so audit can attribute a
//!   match to the layer that contributed it.
//!
//! `hardDeny` / `overridable` enforcement happens at engine evaluation
//! time, not in merge — the engine inspects the rule's static metadata
//! and refuses `Disable` overrides for `hardDeny: true` rules.

use super::schema::RawConfig;
use super::{Config, RuleOverride};

/// Fold `layers` into a final [`Config`]. Layers are applied in the
/// order they appear (so `layers[0]` is the lowest-priority scope).
pub fn merge(layers: Vec<RawConfig>) -> Config {
    let mut acc = Config::default();
    for layer in layers {
        apply(&mut acc, layer);
    }
    acc
}

fn apply(acc: &mut Config, layer: RawConfig) {
    if let Some(mode) = layer.mode {
        acc.mode = mode;
    }
    if let Some(fc) = layer.fail_closed {
        acc.fail_closed = fc;
    }
    for (rule_id, overlay) in layer.rule_overrides {
        let entry = acc.rule_overrides.entry(rule_id).or_default();
        merge_rule_override(entry, overlay);
    }
    acc.allowlists.extend(layer.allowlists);
    if let Some(path) = layer.audit.path {
        acc.audit.path = Some(path);
    }
}

fn merge_rule_override(into: &mut RuleOverride, from: RuleOverride) {
    if from.enabled.is_some() {
        into.enabled = from.enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::super::schema::{RawAudit, RawConfig};
    use super::super::{Allowlist, Config, Mode, RuleOverride};
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn raw() -> RawConfig {
        RawConfig::default()
    }

    fn override_for(rule: &str, enabled: bool) -> (String, RuleOverride) {
        (
            rule.to_string(),
            RuleOverride {
                enabled: Some(enabled),
            },
        )
    }

    #[test]
    fn merge_of_no_layers_yields_defaults() {
        let cfg = merge(Vec::new());
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.mode, Mode::Enforce);
        assert!(cfg.fail_closed);
        assert!(cfg.rule_overrides.is_empty());
        assert!(cfg.allowlists.is_empty());
        assert!(cfg.audit.path.is_none());
    }

    #[test]
    fn later_layer_wins_for_scalar_fields() {
        let lower = RawConfig {
            mode: Some(Mode::Enforce),
            fail_closed: Some(true),
            ..raw()
        };
        let higher = RawConfig {
            mode: Some(Mode::Monitor),
            fail_closed: Some(false),
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        assert_eq!(cfg.mode, Mode::Monitor);
        assert!(!cfg.fail_closed);
    }

    #[test]
    fn unset_scalars_in_higher_layer_do_not_clobber_lower() {
        let lower = RawConfig {
            mode: Some(Mode::Monitor),
            fail_closed: Some(false),
            ..raw()
        };
        let higher = RawConfig::default();
        let cfg = merge(vec![lower, higher]);
        assert_eq!(cfg.mode, Mode::Monitor);
        assert!(!cfg.fail_closed);
    }

    #[test]
    fn rule_overrides_are_merged_per_rule_id() {
        let lower = RawConfig {
            rule_overrides: BTreeMap::from([override_for(
                "core.network.remote-script-pipe",
                false,
            )]),
            ..raw()
        };
        let higher = RawConfig {
            rule_overrides: BTreeMap::from([override_for("core.filesystem.destructive-rm", true)]),
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        assert_eq!(cfg.rule_overrides.len(), 2);
        assert_eq!(
            cfg.rule_overrides
                .get("core.network.remote-script-pipe")
                .and_then(|o| o.enabled),
            Some(false)
        );
        assert_eq!(
            cfg.rule_overrides
                .get("core.filesystem.destructive-rm")
                .and_then(|o| o.enabled),
            Some(true)
        );
    }

    #[test]
    fn rule_override_higher_layer_overrides_lower_for_same_id() {
        let rule = "core.secrets.sensitive-path-to-network";
        let lower = RawConfig {
            rule_overrides: BTreeMap::from([override_for(rule, false)]),
            ..raw()
        };
        let higher = RawConfig {
            rule_overrides: BTreeMap::from([override_for(rule, true)]),
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        assert_eq!(
            cfg.rule_overrides.get(rule).and_then(|o| o.enabled),
            Some(true)
        );
    }

    #[test]
    fn rule_override_higher_layer_with_none_does_not_clobber() {
        let rule = "core.network.remote-script-pipe";
        let lower = RawConfig {
            rule_overrides: BTreeMap::from([override_for(rule, false)]),
            ..raw()
        };
        let higher = RawConfig {
            rule_overrides: BTreeMap::from([(rule.to_string(), RuleOverride::default())]),
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        assert_eq!(
            cfg.rule_overrides.get(rule).and_then(|o| o.enabled),
            Some(false)
        );
    }

    #[test]
    fn allowlists_concatenate_in_scope_order() {
        let lower_entry = Allowlist {
            id: "lower".into(),
            rule_ids: vec!["a".into()],
            expires_at: None,
            reason: None,
        };
        let higher_entry = Allowlist {
            id: "higher".into(),
            rule_ids: vec!["b".into()],
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            reason: Some("local override".into()),
        };
        let cfg = merge(vec![
            RawConfig {
                allowlists: vec![lower_entry.clone()],
                ..raw()
            },
            RawConfig {
                allowlists: vec![higher_entry.clone()],
                ..raw()
            },
        ]);
        assert_eq!(cfg.allowlists, vec![lower_entry, higher_entry]);
    }

    #[test]
    fn audit_path_picks_highest_set_value() {
        let cfg = merge(vec![
            RawConfig {
                audit: RawAudit {
                    path: Some(PathBuf::from("/tmp/lower.jsonl")),
                },
                ..raw()
            },
            RawConfig::default(),
            RawConfig {
                audit: RawAudit {
                    path: Some(PathBuf::from("/tmp/higher.jsonl")),
                },
                ..raw()
            },
        ]);
        assert_eq!(cfg.audit.path, Some(PathBuf::from("/tmp/higher.jsonl")));
    }

    #[test]
    fn audit_path_unset_in_top_does_not_clobber_lower_set_value() {
        let cfg = merge(vec![
            RawConfig {
                audit: RawAudit {
                    path: Some(PathBuf::from("/tmp/lower.jsonl")),
                },
                ..raw()
            },
            RawConfig::default(),
        ]);
        assert_eq!(cfg.audit.path, Some(PathBuf::from("/tmp/lower.jsonl")));
    }
}
