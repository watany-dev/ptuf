//! Shared test helpers for the engine submodule.
//!
//! Visible to `engine`'s descendants (`builder`, `filter`, and the
//! `tests` block inside `mod.rs`). Compiled only under `#[cfg(test)]`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use serde_json::json;

use crate::audit::record::AuditRecord;
use crate::audit::writer::WriteError;
use crate::audit::{AuditError, AuditSink, MemorySink};
use crate::config::Config;
use crate::hook_input::HookInput;
use crate::plugin::{PluginSet, load_str};

use super::Engine;

pub(super) fn bash(cmd: &str) -> HookInput {
    HookInput {
        tool_name: "Bash".into(),
        tool_input: json!({ "command": cmd }),
    }
}

pub(super) fn engine_with(cfg: Config) -> Engine {
    Engine::with_components(cfg, PluginSet::new())
}

/// Wrap a shared `MemorySink` so a test can both inject it into the
/// engine and inspect the captured records afterwards.
pub(super) struct SharedMemorySink(pub(super) Arc<MemorySink>);

impl AuditSink for SharedMemorySink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.0.record(record)
    }
}

/// Test double that always rejects writes — used to exercise the
/// `record_audit` error capture path without involving the filesystem.
pub(super) struct FailingSink;

impl AuditSink for FailingSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Err(AuditError::Write(WriteError::Io(std::io::Error::other(
            "disk full",
        ))))
    }
}

/// One-rule plugin set with a `tool: Bash` matcher so engine tests can
/// exercise `rule_overrides` paths against an overridable
/// (non-hard-deny) rule.
pub(super) fn plugin_set_with_bash_deny() -> PluginSet {
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
