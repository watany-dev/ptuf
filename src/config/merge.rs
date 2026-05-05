//! Scope merge: fold a vector of [`RawConfig`] layers (lowest first)
//! into a single [`Config`].
//!
//! Merge rules:
//! * Scalars (`mode`, `fail_closed`, `audit.path`): later layers'
//!   `Some(_)` wins.
//! * `pack_overrides`: union by pack name; for the same name the later
//!   layer's [`PackOverride`] wins for any `Some(_)` field.
//! * `allowlists`: concatenate in scope order so audit can attribute a
//!   match to the layer that contributed it.
//!
//! `hardDeny` / `overridable` enforcement happens at engine evaluation
//! time, not in merge — the engine inspects the rule's static metadata
//! and refuses `Disable` overrides for `hardDeny: true` rules.

use super::schema::{MergeLayer, RawConfig};
use super::{Config, PackOverride};

/// Fold `layers` into a final [`Config`]. Layers are applied in the
/// order they appear (so `layers[0]` is the lowest-priority scope).
pub fn merge(layers: Vec<RawConfig>) -> Config {
    let mut acc = Config::default();
    for layer in layers {
        apply(&mut acc, layer.into_merge_layer());
    }
    acc
}

fn apply(acc: &mut Config, layer: MergeLayer) {
    if let Some(mode) = layer.mode {
        acc.mode = mode;
    }
    if let Some(fc) = layer.fail_closed {
        acc.fail_closed = fc;
    }
    for (pack, overlay) in layer.pack_overrides {
        let entry = acc.pack_overrides.entry(pack).or_default();
        merge_pack_override(entry, overlay);
    }
    acc.allowlists.extend(layer.allowlists);
    acc.plugin_paths.extend(layer.plugin_paths);
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
}

fn merge_pack_override(into: &mut PackOverride, from: PackOverride) {
    if from.enabled.is_some() {
        into.enabled = from.enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::super::schema::{RawAllowlist, RawAllowlistApplies, RawAudit, RawConfig, RawPack};
    use super::super::{Allowlist, Config, Mode};
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
        }
    }

    #[test]
    fn merge_of_no_layers_yields_defaults() {
        let cfg = merge(Vec::new());
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.mode, Mode::Enforce);
        assert!(cfg.fail_closed);
        // Builtin default disables `core.project_hygiene` (opt-in pack);
        // anything beyond that comes from explicit YAML.
        assert_eq!(cfg.pack_overrides.len(), 1);
        assert_eq!(
            cfg.pack_overrides
                .get("core.project_hygiene")
                .and_then(|o| o.enabled),
            Some(false),
        );
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
        // 2 explicit overrides + 1 built-in default for core.project_hygiene.
        assert_eq!(cfg.pack_overrides.len(), 3);
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
            expires_at: None,
            reason: None,
        };
        let higher_entry = RawAllowlist {
            id: "higher".into(),
            applies_to: RawAllowlistApplies {
                rules: vec!["b".into()],
            },
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
        use super::super::schema::RawPluginRef;
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
                include_allowed: Some(true),
                include_denied: Some(false),
                redaction: Some(RedactionMode::Strict),
                ..Default::default()
            },
            ..raw()
        };
        let higher = RawConfig {
            audit: RawAudit {
                include_allowed: Some(false),
                include_denied: None,
                redaction: Some(RedactionMode::Off),
                ..Default::default()
            },
            ..raw()
        };
        let cfg = merge(vec![lower, higher]);
        assert!(!cfg.audit.include_allowed);
        assert!(!cfg.audit.include_denied);
        assert!(matches!(cfg.audit.redaction, RedactionMode::Off));
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
}
