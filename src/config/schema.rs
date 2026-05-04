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

use super::{Allowlist, Mode, PackOverride, RedactionMode};

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
        MergeLayer {
            mode: self.mode,
            fail_closed: self.fail_closed,
            pack_overrides: self
                .packs
                .into_iter()
                .map(|(k, v)| (k, PackOverride { enabled: v.enabled }))
                .collect(),
            allowlists: self.allowlists.into_iter().map(Into::into).collect(),
            plugin_paths: self
                .plugins
                .into_iter()
                .filter(|p| p.enabled.unwrap_or(true))
                .map(|p| p.path)
                .collect(),
            audit_path: self.audit.path,
            audit_include_allowed: self.audit.include_allowed,
            audit_include_denied: self.audit.include_denied,
            audit_redaction: self.audit.redaction,
        }
    }
}

/// Per-pack toggle parsed from `packs: { <name>: { enabled: ... } }`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawPack {
    #[serde(default)]
    pub enabled: Option<bool>,
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
        Allowlist {
            id: value.id,
            rule_ids: value.applies_to.rules,
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
    pub allowlists: Vec<Allowlist>,
    pub plugin_paths: Vec<PathBuf>,
    pub audit_path: Option<PathBuf>,
    pub audit_include_allowed: Option<bool>,
    pub audit_include_denied: Option<bool>,
    pub audit_redaction: Option<RedactionMode>,
}

impl<'de> Deserialize<'de> for RedactionMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.as_str() {
            "strict" => Ok(RedactionMode::Strict),
            "off" => Ok(RedactionMode::Off),
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
            "enforce" => Ok(Mode::Enforce),
            "monitor" => Ok(Mode::Monitor),
            "observe" => Ok(Mode::Observe),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["enforce", "monitor", "observe"],
            )),
        }
    }
}
