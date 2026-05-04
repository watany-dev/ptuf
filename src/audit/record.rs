//! In-memory representation of one audit log entry.
//!
//! `AuditRecord` mirrors the JSON schema in `docs/design/audit.md:14-46`.
//! `severity` is serialised as the lowercase enum spelling
//! (`info` / `low` / `medium` / `high` / `critical`).
//!
//! `schemaVersion` is always emitted (currently `1`) so JSONL consumers
//! can negotiate forward-compatible parsers. `agent` (e.g. `claude-code`),
//! `pluginVersions` (`name@version`), and `allowlistId` (only when an
//! `Allow` decision came from a non-expired allowlist hit) are populated
//! by the engine layer.

use std::path::Path;
use std::time::SystemTime;

use serde::Serialize;

use super::time as audit_time;
use crate::Decision;
use crate::config::Mode;
use crate::decision::Severity;
use crate::hook_input::HookInput;

/// Schema version of the audit record. Bumped only on incompatible
/// changes; additive fields keep version `1`.
pub const AUDIT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub timestamp: String,
    pub event: &'static str,
    pub tool: String,
    pub decision: &'static str,
    #[serde(rename = "ruleId", skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<&'static str>,
    #[serde(rename = "commandRedacted")]
    pub command_redacted: String,
    #[serde(rename = "projectRoot", skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    pub mode: &'static str,
    /// `true` when the engine demoted a `Deny` decision to `Monitor`
    /// because the policy mode was `monitor` or `observe`.
    #[serde(rename = "modeDemoted", skip_serializing_if = "is_false")]
    pub mode_demoted: bool,
    /// Allowlist `id` whose suppression turned a would-be Deny / Ask /
    /// Monitor into an `Allow`. Only set on `Allow` outcomes; `None`
    /// otherwise. When multiple allowlist entries hit, the first one
    /// wins (insertion order from the merged config).
    #[serde(rename = "allowlistId", skip_serializing_if = "Option::is_none")]
    pub allowlist_id: Option<String>,
    /// Adapter that produced the decision (`claude-code` / `cli` /
    /// `compat`). `unknown` for direct library callers that never
    /// configured one.
    pub agent: &'static str,
    /// `name@version` for every loaded plugin in load order. Empty
    /// vec is omitted from the serialised form.
    #[serde(rename = "pluginVersions", skip_serializing_if = "Vec::is_empty")]
    pub plugin_versions: Vec<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl AuditRecord {
    /// Build an `AuditRecord` for the supplied decision/input pair.
    /// The caller is responsible for redacting `command_redacted`
    /// before the record reaches the sink — keeping the redactor
    /// outside this constructor lets tests inject untouched commands
    /// and check the writer/sink in isolation.
    ///
    /// `agent` should be a stable adapter name (`claude-code` / `cli`
    /// / `compat`); use `"unknown"` for embedded library callers that
    /// have not configured one. `plugin_versions` is the engine's
    /// cached `name@version` list; an empty vec is omitted from JSON.
    /// `allowlist_id` should be `Some` only on `Allow` outcomes that
    /// were produced by a non-expired allowlist hit.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        timestamp: SystemTime,
        decision: &Decision,
        mode: Mode,
        mode_demoted: bool,
        input: &HookInput,
        project_root: Option<&Path>,
        severity: Option<Severity>,
        command_redacted: String,
        allowlist_id: Option<String>,
        agent: &'static str,
        plugin_versions: Vec<String>,
    ) -> Self {
        let rule_id = decision.rule_id().map(str::to_owned);
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            timestamp: audit_time::rfc3339_utc(timestamp),
            event: "PreToolUse",
            tool: input.tool_name.clone(),
            decision: decision_label(decision),
            rule_id,
            severity: severity.map(severity_label),
            command_redacted,
            project_root: project_root.and_then(|p| p.to_str().map(str::to_owned)),
            mode: mode_label(mode),
            mode_demoted,
            allowlist_id,
            agent,
            plugin_versions,
        }
    }
}

fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Monitor { .. } => "monitor",
        Decision::Ask { .. } => "ask",
        Decision::Deny { .. } => "deny",
    }
}

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Enforce => "enforce",
        Mode::Monitor => "monitor",
        Mode::Observe => "observe",
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    fn input(tool: &str, cmd: &str) -> HookInput {
        HookInput {
            tool_name: tool.into(),
            tool_input: json!({ "command": cmd }),
        }
    }

    #[test]
    fn builds_deny_record_with_severity_and_rule_id() {
        let decision = Decision::Deny {
            rule_id: "r.x".into(),
            reason: "blocked".into(),
        };
        let r = AuditRecord::build(
            UNIX_EPOCH + Duration::from_secs(1_704_067_200),
            &decision,
            Mode::Enforce,
            false,
            &input("Bash", "ls"),
            Some(&PathBuf::from("/repo")),
            Some(Severity::Critical),
            "ls".into(),
            None,
            "claude-code",
            Vec::new(),
        );
        assert_eq!(r.schema_version, 1);
        assert_eq!(r.timestamp, "2024-01-01T00:00:00Z");
        assert_eq!(r.event, "PreToolUse");
        assert_eq!(r.tool, "Bash");
        assert_eq!(r.decision, "deny");
        assert_eq!(r.rule_id.as_deref(), Some("r.x"));
        assert_eq!(r.severity, Some("critical"));
        assert_eq!(r.command_redacted, "ls");
        assert_eq!(r.project_root.as_deref(), Some("/repo"));
        assert_eq!(r.mode, "enforce");
        assert!(!r.mode_demoted);
        assert!(r.allowlist_id.is_none());
        assert_eq!(r.agent, "claude-code");
        assert!(r.plugin_versions.is_empty());
    }

    #[test]
    fn allow_record_omits_rule_id_and_severity() {
        let r = AuditRecord::build(
            UNIX_EPOCH,
            &Decision::Allow,
            Mode::Enforce,
            false,
            &input("Bash", "ls"),
            None,
            None,
            "ls".into(),
            None,
            "cli",
            Vec::new(),
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("\"ruleId\""));
        assert!(!json.contains("\"severity\""));
        assert!(!json.contains("\"projectRoot\""));
        assert!(!json.contains("\"modeDemoted\""));
        assert!(!json.contains("\"allowlistId\""));
        assert!(!json.contains("\"pluginVersions\""));
        assert!(json.contains("\"schemaVersion\":1"));
        assert!(json.contains("\"agent\":\"cli\""));
        assert!(json.contains("\"decision\":\"allow\""));
    }

    #[test]
    fn monitor_demote_flag_serialises_when_true() {
        let r = AuditRecord::build(
            UNIX_EPOCH,
            &Decision::Monitor {
                rule_id: "r".into(),
            },
            Mode::Monitor,
            true,
            &input("Bash", "ls"),
            None,
            Some(Severity::High),
            "ls".into(),
            None,
            "claude-code",
            Vec::new(),
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"modeDemoted\":true"));
        assert!(json.contains("\"mode\":\"monitor\""));
    }

    #[test]
    fn observe_mode_serialises_as_observe() {
        let r = AuditRecord::build(
            UNIX_EPOCH,
            &Decision::Allow,
            Mode::Observe,
            false,
            &input("Bash", "ls"),
            None,
            None,
            "ls".into(),
            None,
            "claude-code",
            Vec::new(),
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"mode\":\"observe\""));
    }

    #[test]
    fn ask_decision_serialises_as_ask_label() {
        let r = AuditRecord::build(
            UNIX_EPOCH,
            &Decision::Ask {
                rule_id: "r".into(),
                reason: "?".into(),
            },
            Mode::Enforce,
            false,
            &input("Bash", "ls"),
            None,
            Some(Severity::Medium),
            "ls".into(),
            None,
            "claude-code",
            Vec::new(),
        );
        assert_eq!(r.decision, "ask");
        assert_eq!(r.severity, Some("medium"));
    }

    #[test]
    fn allowlist_id_is_serialised_when_set() {
        let r = AuditRecord::build(
            UNIX_EPOCH,
            &Decision::Allow,
            Mode::Enforce,
            false,
            &input("Bash", "ls"),
            None,
            None,
            "ls".into(),
            Some("approved-hotfix".into()),
            "claude-code",
            Vec::new(),
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"allowlistId\":\"approved-hotfix\""));
    }

    #[test]
    fn plugin_versions_serialise_as_name_at_version_list() {
        let r = AuditRecord::build(
            UNIX_EPOCH,
            &Decision::Allow,
            Mode::Enforce,
            false,
            &input("Bash", "ls"),
            None,
            None,
            "ls".into(),
            None,
            "cli",
            vec!["acme.security@0.1.0".into(), "core.demo@1.2.3".into()],
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"pluginVersions\":[\"acme.security@0.1.0\",\"core.demo@1.2.3\"]"));
    }

    #[test]
    fn agent_label_is_always_serialised() {
        let r = AuditRecord::build(
            UNIX_EPOCH,
            &Decision::Allow,
            Mode::Enforce,
            false,
            &input("Bash", "ls"),
            None,
            None,
            "ls".into(),
            None,
            "compat",
            Vec::new(),
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"agent\":\"compat\""));
    }

    #[test]
    fn severity_label_covers_each_variant() {
        assert_eq!(severity_label(Severity::Info), "info");
        assert_eq!(severity_label(Severity::Low), "low");
        assert_eq!(severity_label(Severity::Medium), "medium");
        assert_eq!(severity_label(Severity::High), "high");
        assert_eq!(severity_label(Severity::Critical), "critical");
    }
}
