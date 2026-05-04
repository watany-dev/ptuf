//! Layered (Optional-field) shapes used during scope merge.
//!
//! `RawConfig` mirrors [`Config`](super::Config) but every scalar is
//! `Option<T>` so the merge step can distinguish "this layer
//! explicitly set X" from "this layer left X to whatever is below".
//! Maps and lists carry the layer's own contributions and merge by
//! keyed-overwrite / concatenation respectively.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::{Allowlist, Mode, RuleOverride};

/// Single-scope view of the user's policy. All scalars are optional;
/// missing fields defer to the layer below.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawConfig {
    pub mode: Option<Mode>,
    pub fail_closed: Option<bool>,
    pub rule_overrides: BTreeMap<String, RuleOverride>,
    pub allowlists: Vec<Allowlist>,
    pub audit: RawAudit,
}

/// Layer-local audit overlay.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawAudit {
    pub path: Option<PathBuf>,
}
