//! Scope merge: fold a vector of [`RawConfig`] layers (lowest first)
//! into a single [`Config`].
//!
//! Merge rules:
//! * Scalars (`mode`, `fail_closed`, `readonly`, `audit.enabled`, `audit.path`): later layers'
//!   `Some(_)` wins.
//! * `pack_overrides`: union by pack name; for the same name the later
//!   layer's [`PackOverride`] wins for any `Some(_)` field.
//! * `allowlists`: concatenate in scope order so audit can attribute a
//!   match to the layer that contributed it.
//! * `PTUF_READONLY=1|true|on` appends a synthetic top layer that sets
//!   `readonly: true` only — falsy / unset values do not create a layer,
//!   so the env can strengthen but never weaken a config `readonly: true`.
//!
//! `hardDeny` / `overridable` enforcement happens at engine evaluation
//! time, not in merge — the engine inspects the rule's static metadata
//! and refuses `Disable` overrides for `hardDeny: true` rules.

use super::schema::{MergeLayer, RawConfig};
use super::scope::{EnvLookup, SystemEnv};
use super::{Config, PackOverride, RuleOverride};

/// Fold `layers` into a final [`Config`]. Layers are applied in the
/// order they appear (so `layers[0]` is the lowest-priority scope).
/// Resolves `PTUF_READONLY` from the process environment.
pub fn merge(layers: Vec<RawConfig>) -> Config {
    merge_with_env(layers, &SystemEnv)
}

/// Like [`merge`] but resolves `PTUF_READONLY` via `env` (tests inject
/// an in-memory `EnvLookup`).
pub fn merge_with_env(layers: Vec<RawConfig>, env: &dyn EnvLookup) -> Config {
    let mut layers = layers;
    if env_readonly_enabled(env) {
        layers.push(RawConfig {
            readonly: Some(true),
            ..RawConfig::default()
        });
    }
    let mut acc = Config::default();
    for layer in layers {
        apply(&mut acc, layer.into_merge_layer());
    }
    acc
}

/// `true` when `PTUF_READONLY` is one of `1` / `true` / `on` (ASCII
/// case-insensitive for the word forms). Any other value — including
/// `0` / `false` / `off` — leaves the env layer out so it cannot demote
/// a config-file `readonly: true`.
pub(crate) fn env_readonly_enabled(env: &dyn EnvLookup) -> bool {
    let Some(raw) = env.var_os("PTUF_READONLY") else {
        return false;
    };
    let value = raw.to_string_lossy();
    matches!(
        value.as_ref(),
        "1" | "true" | "TRUE" | "True" | "on" | "ON" | "On"
    )
}

fn apply(acc: &mut Config, layer: MergeLayer) {
    if let Some(mode) = layer.mode {
        acc.mode = mode;
    }
    if let Some(fc) = layer.fail_closed {
        acc.fail_closed = fc;
    }
    if let Some(ro) = layer.readonly {
        acc.readonly = ro;
    }
    for (pack, overlay) in layer.pack_overrides {
        let entry = acc.pack_overrides.entry(pack).or_default();
        merge_pack_override(entry, overlay);
    }
    for (rule, overlay) in layer.rule_overrides {
        let entry = acc.rule_overrides.entry(rule).or_default();
        merge_rule_override(entry, overlay);
    }
    acc.allowlists.extend(layer.allowlists);
    acc.plugin_paths.extend(layer.plugin_paths);
    if let Some(enabled) = layer.audit_enabled {
        acc.audit.enabled = enabled;
    }
    if let Some(path) = layer.audit_path {
        acc.audit.path = Some(path);
    }
    if let Some(b) = layer.audit_include_allowed {
        acc.audit.include_allowed = b;
    }
    if let Some(b) = layer.audit_include_denied {
        acc.audit.include_denied = b;
    }
    if let Some(r) = layer.audit_redaction {
        acc.audit.redaction = r;
    }
    if let Some(branches) = layer.protected_branches {
        acc.protected_branches = branches;
    }
    if let Some(ws) = layer.additional_workspaces {
        acc.additional_workspaces = ws;
    }
}

fn merge_pack_override(into: &mut PackOverride, from: PackOverride) {
    if from.enabled.is_some() {
        into.enabled = from.enabled;
    }
}

fn merge_rule_override(into: &mut RuleOverride, from: RuleOverride) {
    if from.enabled.is_some() {
        into.enabled = from.enabled;
    }
    if from.decision.is_some() {
        into.decision = from.decision;
    }
    if from.severity.is_some() {
        into.severity = from.severity;
    }
}

#[cfg(test)]
mod tests {
    use super::super::schema::{
        RawAllowlist, RawAllowlistApplies, RawAudit, RawConfig, RawPack, RawPluginRef,
    };
    use super::super::{Allowlist, Mode};
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn raw() -> RawConfig {
        RawConfig::default()
    }

    fn pack(enabled: bool) -> RawPack {
        RawPack {
            enabled: Some(enabled),
            protected_branches: None,
            additional_workspaces: None,
        }
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
    fn pack_overrides_are_merged_per_name() {
        let lower = RawConfig {
            packs: BTreeMap::from([("core.network".to_string(), pack(false))]),
            ..raw()
        };
        let higher = RawConfig {
            packs: BTreeMap::from([("core.filesystem".to_string(), pack(true))]),
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        // 2 explicit overrides + 2 built-in defaults
        // (core.project_hygiene, core.workspace).
        assert_eq!(cfg.pack_overrides.len(), 4);
        assert_eq!(
            cfg.pack_overrides
                .get("core.network")
                .and_then(|o| o.enabled),
            Some(false)
        );
        assert_eq!(
            cfg.pack_overrides
                .get("core.filesystem")
                .and_then(|o| o.enabled),
            Some(true)
        );
    }

    #[test]
    fn pack_override_higher_layer_overrides_lower_for_same_name() {
        let lower = RawConfig {
            packs: BTreeMap::from([("core.secrets".to_string(), pack(false))]),
            ..raw()
        };
        let higher = RawConfig {
            packs: BTreeMap::from([("core.secrets".to_string(), pack(true))]),
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        assert_eq!(
            cfg.pack_overrides
                .get("core.secrets")
                .and_then(|o| o.enabled),
            Some(true)
        );
    }

    #[test]
    fn pack_override_higher_layer_with_none_does_not_clobber() {
        let lower = RawConfig {
            packs: BTreeMap::from([("core.network".to_string(), pack(false))]),
            ..raw()
        };
        let higher = RawConfig {
            packs: BTreeMap::from([("core.network".to_string(), RawPack::default())]),
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        assert_eq!(
            cfg.pack_overrides
                .get("core.network")
                .and_then(|o| o.enabled),
            Some(false)
        );
    }

    #[test]
    fn allowlists_concatenate_in_scope_order() {
        let lower_entry = RawAllowlist {
            id: "lower".into(),
            applies_to: RawAllowlistApplies {
                rules: vec!["a".into()],
            },
            when: None,
            expires_at: None,
            reason: None,
        };
        let higher_entry = RawAllowlist {
            id: "higher".into(),
            applies_to: RawAllowlistApplies {
                rules: vec!["b".into()],
            },
            when: None,
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
        assert_eq!(
            cfg.allowlists,
            vec![Allowlist::from(lower_entry), Allowlist::from(higher_entry)]
        );
    }

    #[test]
    fn audit_path_picks_highest_set_value() {
        let cfg = merge(vec![
            RawConfig {
                audit: RawAudit {
                    path: Some(PathBuf::from("/tmp/lower.jsonl")),
                    ..Default::default()
                },
                ..raw()
            },
            RawConfig::default(),
            RawConfig {
                audit: RawAudit {
                    path: Some(PathBuf::from("/tmp/higher.jsonl")),
                    ..Default::default()
                },
                ..raw()
            },
        ]);
        assert_eq!(cfg.audit.path, Some(PathBuf::from("/tmp/higher.jsonl")));
    }

    #[test]
    fn plugin_paths_concatenate_across_layers_and_skip_disabled() {
        let lower = RawConfig {
            plugins: vec![RawPluginRef {
                path: PathBuf::from("/etc/p1.yaml"),
                enabled: None,
            }],
            ..raw()
        };
        let higher = RawConfig {
            plugins: vec![
                RawPluginRef {
                    path: PathBuf::from("/home/p2.yaml"),
                    enabled: Some(true),
                },
                RawPluginRef {
                    path: PathBuf::from("/home/p3.yaml"),
                    enabled: Some(false),
                },
            ],
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        assert_eq!(
            cfg.plugin_paths,
            vec![
                PathBuf::from("/etc/p1.yaml"),
                PathBuf::from("/home/p2.yaml"),
            ]
        );
    }

    #[test]
    fn audit_flags_and_redaction_merge_with_later_layer_wins() {
        use super::super::RedactionMode;
        let lower = RawConfig {
            audit: RawAudit {
                enabled: Some(false),
                include_allowed: Some(true),
                include_denied: Some(false),
                redaction: Some(RedactionMode::Strict),
                ..Default::default()
            },
            ..raw()
        };
        let higher = RawConfig {
            audit: RawAudit {
                enabled: Some(true),
                include_allowed: Some(false),
                include_denied: None,
                redaction: Some(RedactionMode::Off),
                ..Default::default()
            },
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        assert!(cfg.audit.enabled);
        assert!(!cfg.audit.include_allowed);
        assert!(!cfg.audit.include_denied);
        assert!(matches!(cfg.audit.redaction, RedactionMode::Off));
    }

    #[test]
    fn rule_overrides_merge_per_rule_id() {
        use super::super::schema::RawRuleOverride;
        let lower = RawConfig {
            rules: BTreeMap::from([(
                "core.git.reset-hard".into(),
                RawRuleOverride {
                    enabled: Some(true),
                    decision: Some(crate::decision::DecisionKind::Ask),
                    severity: None,
                },
            )]),
            ..raw()
        };
        let higher = RawConfig {
            rules: BTreeMap::from([(
                "core.git.reset-hard".into(),
                RawRuleOverride {
                    enabled: None,
                    decision: Some(crate::decision::DecisionKind::Deny),
                    severity: Some(crate::decision::Severity::Critical),
                },
            )]),
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        let overlay = cfg
            .rule_overrides
            .get("core.git.reset-hard")
            .expect("overlay");
        assert_eq!(overlay.enabled, Some(true));
        assert_eq!(overlay.decision, Some(crate::decision::DecisionKind::Deny));
        assert_eq!(overlay.severity, Some(crate::decision::Severity::Critical));
    }

    #[test]
    fn audit_path_unset_in_top_does_not_clobber_lower_set_value() {
        let cfg = merge(vec![
            RawConfig {
                audit: RawAudit {
                    path: Some(PathBuf::from("/tmp/lower.jsonl")),
                    ..Default::default()
                },
                ..raw()
            },
            RawConfig::default(),
        ]);
        assert_eq!(cfg.audit.path, Some(PathBuf::from("/tmp/lower.jsonl")));
    }

    #[test]
    fn readonly_last_write_wins_across_layers() {
        use super::super::scope::MapEnv;
        let empty = MapEnv::new(&[]);
        let cfg = merge_with_env(
            vec![
                RawConfig {
                    readonly: Some(false),
                    ..raw()
                },
                RawConfig {
                    readonly: Some(true),
                    ..raw()
                },
            ],
            &empty,
        );
        assert!(cfg.readonly);
        let cfg = merge_with_env(
            vec![
                RawConfig {
                    readonly: Some(true),
                    ..raw()
                },
                RawConfig {
                    readonly: Some(false),
                    ..raw()
                },
            ],
            &empty,
        );
        assert!(!cfg.readonly);
    }

    #[test]
    fn ptuf_readonly_env_strengthens_only() {
        use super::super::scope::MapEnv;
        // env=1 turns false → true
        let cfg = merge_with_env(
            vec![RawConfig {
                readonly: Some(false),
                ..raw()
            }],
            &MapEnv::new(&[("PTUF_READONLY", "1")]),
        );
        assert!(cfg.readonly);
        // env=0 cannot demote config true
        let cfg = merge_with_env(
            vec![RawConfig {
                readonly: Some(true),
                ..raw()
            }],
            &MapEnv::new(&[("PTUF_READONLY", "0")]),
        );
        assert!(cfg.readonly);
        // env=false cannot demote
        let cfg = merge_with_env(
            vec![RawConfig {
                readonly: Some(true),
                ..raw()
            }],
            &MapEnv::new(&[("PTUF_READONLY", "false")]),
        );
        assert!(cfg.readonly);
        // env=true also strengthens
        let cfg = merge_with_env(vec![raw()], &MapEnv::new(&[("PTUF_READONLY", "true")]));
        assert!(cfg.readonly);
        let cfg = merge_with_env(vec![raw()], &MapEnv::new(&[("PTUF_READONLY", "on")]));
        assert!(cfg.readonly);
    }

    use proptest::collection::{btree_map, vec};
    use proptest::prelude::*;

    fn opt_bool() -> impl Strategy<Value = Option<bool>> {
        prop_oneof![Just(None), Just(Some(true)), Just(Some(false))]
    }

    fn mode_strategy() -> impl Strategy<Value = Option<Mode>> {
        prop_oneof![
            Just(None),
            Just(Some(Mode::Enforce)),
            Just(Some(Mode::Monitor))
        ]
    }

    fn raw_pack_strategy() -> impl Strategy<Value = RawPack> {
        opt_bool().prop_map(|enabled| RawPack {
            enabled,
            protected_branches: None,
            additional_workspaces: None,
        })
    }

    fn raw_allowlist_strategy() -> impl Strategy<Value = RawAllowlist> {
        ("[a-z]{1,8}", vec("[a-z.]{1,12}", 0..3)).prop_map(|(id, rules)| RawAllowlist {
            id,
            applies_to: RawAllowlistApplies { rules },
            when: None,
            expires_at: None,
            reason: None,
        })
    }

    fn raw_plugin_ref_strategy() -> impl Strategy<Value = RawPluginRef> {
        ("/[a-z]{1,8}\\.yaml", opt_bool()).prop_map(|(path, enabled)| RawPluginRef {
            path: PathBuf::from(path),
            enabled,
        })
    }

    fn raw_config_strategy() -> impl Strategy<Value = RawConfig> {
        (
            mode_strategy(),
            opt_bool(),
            btree_map("[a-z.]{1,12}", raw_pack_strategy(), 0..3),
            vec(raw_allowlist_strategy(), 0..3),
            vec(raw_plugin_ref_strategy(), 0..3),
        )
            .prop_map(
                |(mode, fail_closed, packs, allowlists, plugins)| RawConfig {
                    version: None,
                    mode,
                    fail_closed,
                    readonly: None,
                    packs,
                    rules: BTreeMap::new(),
                    allowlists,
                    plugins,
                    audit: RawAudit::default(),
                },
            )
    }

    proptest! {
        // Appending a fully-default layer contributes nothing: every
        // scalar is `None` and every map/list empty, so the fold is a
        // noop regardless of the layers below it.
        #[test]
        fn pbt_merge_append_default_layer_is_noop(
            layers in vec(raw_config_strategy(), 0..5),
        ) {
            let baseline = merge(layers.clone());
            let mut extended = layers;
            extended.push(RawConfig::default());
            prop_assert_eq!(merge(extended), baseline);
        }

        // Prepending a default layer is likewise a noop: it only ever
        // sees the pristine `Config::default()` accumulator.
        #[test]
        fn pbt_merge_prepend_default_layer_is_noop(
            layers in vec(raw_config_strategy(), 0..5),
        ) {
            let baseline = merge(layers.clone());
            let mut extended = vec![RawConfig::default()];
            extended.extend(layers);
            prop_assert_eq!(merge(extended), baseline);
        }

        // Scalars are last-write-wins: the merged value is the last
        // layer that set `Some`, falling back to the builtin default.
        #[test]
        fn pbt_merge_scalars_are_last_write_wins(
            layers in vec(raw_config_strategy(), 0..5),
        ) {
            use super::super::scope::MapEnv;
            let cfg = merge_with_env(layers.clone(), &MapEnv::new(&[]));
            let expected_mode = layers
                .iter()
                .rev()
                .find_map(|l| l.mode)
                .unwrap_or(Mode::Enforce);
            let expected_fail_closed = layers
                .iter()
                .rev()
                .find_map(|l| l.fail_closed)
                .unwrap_or(true);
            let expected_readonly = layers.iter().rev().find_map(|l| l.readonly).unwrap_or(false);
            prop_assert_eq!(cfg.mode, expected_mode);
            prop_assert_eq!(cfg.fail_closed, expected_fail_closed);
            prop_assert_eq!(cfg.readonly, expected_readonly);
        }

        // Allowlists concatenate in scope order across every layer.
        #[test]
        fn pbt_merge_allowlists_concatenate_in_scope_order(
            layers in vec(raw_config_strategy(), 0..5),
        ) {
            let cfg = merge(layers.clone());
            let expected: Vec<Allowlist> = layers
                .into_iter()
                .flat_map(|l| l.allowlists.into_iter().map(Allowlist::from))
                .collect();
            prop_assert_eq!(cfg.allowlists, expected);
        }

        // Plugin paths concatenate in scope order, keeping only refs
        // that are enabled (absent `enabled` defaults to enabled).
        #[test]
        fn pbt_merge_plugin_paths_concatenate_enabled_only(
            layers in vec(raw_config_strategy(), 0..5),
        ) {
            let cfg = merge(layers.clone());
            let expected: Vec<PathBuf> = layers
                .into_iter()
                .flat_map(|l| {
                    l.plugins
                        .into_iter()
                        .filter(|p| p.enabled.unwrap_or(true))
                        .map(|p| p.path)
                })
                .collect();
            prop_assert_eq!(cfg.plugin_paths, expected);
        }
    }
}
