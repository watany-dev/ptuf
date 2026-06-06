//! Layered, optional-field shapes used during scope merge.
//!
//! `RawConfig` mirrors [`Config`](super::Config) but every scalar is
//! `Option<T>` so the merge step can distinguish "this layer
//! explicitly set X" from "this layer left X to whatever is below".
//! Maps and lists carry the layer's own contributions and merge by
//! keyed-overwrite / concatenation respectively.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
use serde_yaml_ng::Value;

use super::{Allowlist, Mode, PackOverride, RedactionMode, RuleOverride};

/// Single-scope view of the user's policy. All scalars are optional;
/// missing fields defer to the layer below.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawConfig {
    /// Currently always `1`. Reserved for future incompatible breaks.
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub mode: Option<Mode>,
    #[serde(default)]
    pub fail_closed: Option<bool>,
    #[serde(default)]
    pub packs: BTreeMap<String, RawPack>,
    #[serde(default)]
    pub rules: BTreeMap<String, RawRuleOverride>,
    #[serde(default)]
    pub allowlists: Vec<RawAllowlist>,
    #[serde(default)]
    pub plugins: Vec<RawPluginRef>,
    #[serde(default)]
    pub audit: RawAudit,
}

impl RawConfig {
    /// Move the YAML-shape RawConfig fields into the merge-shape
    /// fields used by [`merge::merge`](super::merge::merge). The two
    /// forms differ only in nesting; this conversion is purely a
    /// rename.
    pub(super) fn into_merge_layer(self) -> MergeLayer {
        let protected_branches = self
            .packs
            .get("core.project_hygiene")
            .and_then(|p| p.protected_branches.clone());
        let additional_workspaces = self
            .packs
            .get("core.workspace")
            .and_then(|p| p.additional_workspaces.clone());
        MergeLayer {
            mode: self.mode,
            fail_closed: self.fail_closed,
            pack_overrides: self
                .packs
                .into_iter()
                .map(|(k, v)| (k, PackOverride { enabled: v.enabled }))
                .collect(),
            rule_overrides: self.rules.into_iter().map(|(k, v)| (k, v.into())).collect(),
            allowlists: self.allowlists.into_iter().map(Into::into).collect(),
            plugin_paths: self
                .plugins
                .into_iter()
                .filter(|p| p.enabled.unwrap_or(true))
                .map(|p| p.path)
                .collect(),
            audit_path: self.audit.path,
            audit_enabled: self.audit.enabled,
            audit_include_allowed: self.audit.include_allowed,
            audit_include_denied: self.audit.include_denied,
            audit_redaction: self.audit.redaction,
            protected_branches,
            additional_workspaces,
        }
    }
}

/// Per-pack toggle parsed from `packs: { <name>: { enabled: ... } }`.
///
/// `protected_branches` is consumed only by `core.project_hygiene` and
/// `additional_workspaces` only by `core.workspace`; other packs ignore
/// them. Keeping these on the shared `RawPack` keeps the YAML schema
/// flat (one entry per pack) without a per-pack subtype.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawPack {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub protected_branches: Option<Vec<String>>,
    #[serde(default)]
    pub additional_workspaces: Option<Vec<String>>,
}

/// Per-rule override parsed from `rules: { <rule-id>: { ... } }`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawRuleOverride {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub decision: Option<crate::decision::DecisionKind>,
    #[serde(default)]
    pub severity: Option<crate::decision::Severity>,
}

impl From<RawRuleOverride> for RuleOverride {
    fn from(value: RawRuleOverride) -> Self {
        Self {
            enabled: value.enabled,
            decision: value.decision,
            severity: value.severity,
        }
    }
}

/// Reference to a plugin YAML on disk. `enabled: false` keeps the
/// reference around (handy for project-local overrides) but skips the
/// load.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawPluginRef {
    pub path: PathBuf,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Layer-local audit overlay.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawAudit {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub include_allowed: Option<bool>,
    #[serde(default)]
    pub include_denied: Option<bool>,
    #[serde(default)]
    pub redaction: Option<RedactionMode>,
}

/// YAML-shape allowlist entry. `appliesTo.rules` is the list of rule
/// ids the entry applies to.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawAllowlist {
    pub id: String,
    #[serde(default)]
    pub applies_to: RawAllowlistApplies,
    #[serde(default)]
    pub when: Option<Value>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAllowlistApplies {
    #[serde(default)]
    pub rules: Vec<String>,
}

impl From<RawAllowlist> for Allowlist {
    fn from(value: RawAllowlist) -> Self {
        Self {
            id: value.id,
            rule_ids: value.applies_to.rules,
            when: value
                .when
                .as_ref()
                .and_then(|v| crate::plugin::dsl::compile(v).ok()),
            expires_at: value.expires_at,
            reason: value.reason,
        }
    }
}

/// The struct-level shape that [`merge::merge`](super::merge::merge)
/// consumes. Crate-private; the public façade is [`RawConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct MergeLayer {
    pub mode: Option<Mode>,
    pub fail_closed: Option<bool>,
    pub pack_overrides: BTreeMap<String, PackOverride>,
    pub rule_overrides: BTreeMap<String, RuleOverride>,
    pub allowlists: Vec<Allowlist>,
    pub plugin_paths: Vec<PathBuf>,
    pub audit_enabled: Option<bool>,
    pub audit_path: Option<PathBuf>,
    pub audit_include_allowed: Option<bool>,
    pub audit_include_denied: Option<bool>,
    pub audit_redaction: Option<RedactionMode>,
    pub protected_branches: Option<Vec<String>>,
    pub additional_workspaces: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for RedactionMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.as_str() {
            "strict" => Ok(Self::Strict),
            "off" => Ok(Self::Off),
            other => Err(serde::de::Error::unknown_variant(other, &["strict", "off"])),
        }
    }
}

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.as_str() {
            "enforce" => Ok(Self::Enforce),
            "monitor" => Ok(Self::Monitor),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["enforce", "monitor"],
            )),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn enum_variants_parse_from_yaml_strings() {
        let cases: &[(&str, &str)] = &[
            ("strict", "RedactionMode"),
            ("off", "RedactionMode"),
            ("enforce", "Mode"),
            ("monitor", "Mode"),
        ];
        for (raw, kind) in cases {
            match *kind {
                "RedactionMode" => {
                    let v: RedactionMode = serde_yaml_ng::from_str(raw).expect("parse");
                    if *raw == "strict" {
                        assert_eq!(v, RedactionMode::Strict);
                    } else if *raw == "off" {
                        assert_eq!(v, RedactionMode::Off);
                    } else {
                        panic!("unexpected redaction raw={raw}");
                    }
                },
                "Mode" => {
                    let v: Mode = serde_yaml_ng::from_str(raw).expect("parse");
                    if *raw == "enforce" {
                        assert_eq!(v, Mode::Enforce);
                    } else if *raw == "monitor" {
                        assert_eq!(v, Mode::Monitor);
                    } else {
                        panic!("unexpected mode raw={raw}");
                    }
                },
                _ => panic!("unknown kind {kind}"),
            }
        }
    }

    #[test]
    fn redaction_mode_rejects_unknown_variant() {
        let err = serde_yaml_ng::from_str::<RedactionMode>("loose")
            .expect_err("unknown variant must fail");
        let msg = err.to_string();
        assert!(msg.contains("loose"), "unexpected message: {msg}");
    }

    #[test]
    fn raw_config_conversions_pass_fields_through() {
        let allow_raw = RawAllowlist {
            id: "x".into(),
            applies_to: RawAllowlistApplies {
                rules: vec!["r1".into(), "r2".into()],
            },
            when: None,
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            reason: Some("ok".into()),
        };
        let a: Allowlist = allow_raw.into();
        assert_eq!(a.id, "x");
        assert_eq!(a.rule_ids, vec!["r1".to_string(), "r2".to_string()]);
        assert_eq!(a.expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert_eq!(a.reason.as_deref(), Some("ok"));

        let override_raw = RawRuleOverride {
            enabled: Some(false),
            decision: Some(crate::decision::DecisionKind::Monitor),
            severity: Some(crate::decision::Severity::Low),
        };
        let overlay: RuleOverride = override_raw.into();
        assert_eq!(overlay.enabled, Some(false));
        assert_eq!(
            overlay.decision,
            Some(crate::decision::DecisionKind::Monitor)
        );
        assert_eq!(overlay.severity, Some(crate::decision::Severity::Low));
    }

    #[test]
    fn mode_rejects_unknown_variant() {
        let err = serde_yaml_ng::from_str::<Mode>("yolo").expect_err("unknown variant must fail");
        let msg = err.to_string();
        assert!(msg.contains("yolo"), "unexpected message: {msg}");
    }

    #[test]
    fn mode_rejects_removed_observe_variant() {
        let err =
            serde_yaml_ng::from_str::<Mode>("observe").expect_err("observe is not a known mode");
        let msg = err.to_string();
        assert!(msg.contains("observe"), "unexpected message: {msg}");
    }

    #[test]
    fn raw_allowlist_into_allowlist_passes_fields_through() {
        let raw = RawAllowlist {
            id: "x".into(),
            applies_to: RawAllowlistApplies {
                rules: vec!["r1".into(), "r2".into()],
            },
            when: None,
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            reason: Some("ok".into()),
        };
        let a: Allowlist = raw.into();
        assert_eq!(a.id, "x");
        assert_eq!(a.rule_ids, vec!["r1".to_string(), "r2".to_string()]);
        assert_eq!(a.expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert_eq!(a.reason.as_deref(), Some("ok"));
    }

    #[test]
    fn into_merge_layer_drops_disabled_plugins() {
        let raw = RawConfig {
            plugins: vec![
                RawPluginRef {
                    path: PathBuf::from("/a.yaml"),
                    enabled: Some(true),
                },
                RawPluginRef {
                    path: PathBuf::from("/b.yaml"),
                    enabled: Some(false),
                },
                RawPluginRef {
                    path: PathBuf::from("/c.yaml"),
                    enabled: None,
                },
            ],
            ..Default::default()
        };
        let layer = raw.into_merge_layer();
        assert_eq!(
            layer.plugin_paths,
            vec![PathBuf::from("/a.yaml"), PathBuf::from("/c.yaml")]
        );
    }
}
