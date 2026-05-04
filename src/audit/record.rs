//! In-memory representation of one audit log entry.
//!
//! `AuditRecord` mirrors the JSON schema in `docs/design/audit.md:14-46`.
//! `severity` is serialised as the lowercase enum spelling
//! (`info` / `low` / `medium` / `high` / `critical`).

use std::path::Path;
use std::time::SystemTime;

use serde::Serialize;

use super::time as audit_time;
use crate::Decision;
use crate::config::Mode;
use crate::decision::Severity;
use crate::hook_input::HookInput;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
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
    ) -> Self {
        let rule_id = decision.rule_id().map(str::to_owned);
        Self {
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
        );
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
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("\"ruleId\""));
        assert!(!json.contains("\"severity\""));
        assert!(!json.contains("\"projectRoot\""));
        assert!(!json.contains("\"modeDemoted\""));
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
        );
        assert_eq!(r.decision, "ask");
        assert_eq!(r.severity, Some("medium"));
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
