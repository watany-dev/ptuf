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
    /// because the policy mode was `monitor`.
    #[serde(rename = "modeDemoted", skip_serializing_if = "is_false")]
    pub mode_demoted: bool,
    /// Allowlist `id` whose suppression turned a would-be Deny / Ask /
    /// Monitor into an `Allow`. Only set on `Allow` outcomes; `None`
    /// otherwise. When multiple allowlist entries hit, the first one
    /// wins (insertion order from the merged config).
    #[serde(rename = "allowlistId", skip_serializing_if = "Option::is_none")]
    pub allowlist_id: Option<String>,
    /// Adapter that produced the decision (`claude-code` / `cli`).
    /// `unknown` for direct library callers that never configured one.
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
    /// Start building an audit record for the supplied decision/input pair.
    ///
    /// The caller is responsible for redacting `command_redacted`
    /// before the record reaches the sink — keeping the redactor
    /// outside the builder lets tests inject untouched commands
    /// and check the writer/sink in isolation.
    pub fn builder<'a>(
        decision: &'a Decision,
        input: &'a HookInput,
        command_redacted: String,
    ) -> AuditRecordBuilder<'a> {
        AuditRecordBuilder {
            decision,
            input,
            command_redacted,
            timestamp: None,
            mode: None,
            mode_demoted: false,
            project_root: None,
            severity: None,
            allowlist_id: None,
            agent: "unknown",
            plugin_versions: Vec::new(),
        }
    }
}

/// Builder for [`AuditRecord`].
pub struct AuditRecordBuilder<'a> {
    decision: &'a Decision,
    input: &'a HookInput,
    command_redacted: String,
    timestamp: Option<SystemTime>,
    mode: Option<Mode>,
    mode_demoted: bool,
    project_root: Option<&'a Path>,
    severity: Option<Severity>,
    allowlist_id: Option<String>,
    agent: &'static str,
    plugin_versions: Vec<String>,
}

impl<'a> AuditRecordBuilder<'a> {
    /// Set the record timestamp (required).
    pub fn timestamp(mut self, timestamp: SystemTime) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Set the policy mode (required).
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Set whether the engine demoted a `Deny` to `Monitor`.
    pub fn mode_demoted(mut self, mode_demoted: bool) -> Self {
        self.mode_demoted = mode_demoted;
        self
    }

    /// Set the project root path.
    pub fn project_root(mut self, project_root: Option<&'a Path>) -> Self {
        self.project_root = project_root;
        self
    }

    /// Set the rule severity.
    pub fn severity(mut self, severity: Option<Severity>) -> Self {
        self.severity = severity;
        self
    }

    /// Set the allowlist id for suppressed `Allow` outcomes.
    pub fn allowlist_id(mut self, allowlist_id: Option<String>) -> Self {
        self.allowlist_id = allowlist_id;
        self
    }

    /// Set the adapter name (`claude-code` / `cli`).
    pub fn agent(mut self, agent: &'static str) -> Self {
        self.agent = agent;
        self
    }

    /// Set loaded plugin versions as `name@version` strings.
    pub fn plugin_versions(mut self, plugin_versions: Vec<String>) -> Self {
        self.plugin_versions = plugin_versions;
        self
    }

    /// Finalise the builder.
    ///
    /// `agent` should be a stable adapter name (`claude-code` / `cli`);
    /// use `"unknown"` for embedded library callers that have not
    /// configured one. `plugin_versions` is the engine's
    /// cached `name@version` list; an empty vec is omitted from JSON.
    /// `allowlist_id` should be `Some` only on `Allow` outcomes that
    /// were produced by a non-expired allowlist hit.
    #[expect(
        clippy::expect_used,
        reason = "timestamp and mode are required builder fields; callers always set both"
    )]
    pub fn build(self) -> AuditRecord {
        let timestamp = self.timestamp.expect("timestamp is required");
        let mode = self.mode.expect("mode is required");
        let rule_id = self.decision.rule_id().map(str::to_owned);
        AuditRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            timestamp: audit_time::rfc3339_utc(timestamp),
            event: "PreToolUse",
            tool: self.input.tool_name.clone(),
            decision: decision_label(self.decision),
            rule_id,
            severity: self.severity.map(severity_label),
            command_redacted: self.command_redacted,
            project_root: self
                .project_root
                .and_then(|p| p.to_str().map(str::to_owned)),
            mode: mode_label(mode),
            mode_demoted: self.mode_demoted,
            allowlist_id: self.allowlist_id,
            agent: self.agent,
            plugin_versions: self.plugin_versions,
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

    fn test_builder<'a>(
        decision: &'a Decision,
        input: &'a HookInput,
        command_redacted: impl Into<String>,
    ) -> AuditRecordBuilder<'a> {
        AuditRecord::builder(decision, input, command_redacted.into())
            .timestamp(UNIX_EPOCH)
            .mode(Mode::Enforce)
    }

    // `Duration::from_secs(1_704_067_200)` is a Unix timestamp (the
    // start of 2024 UTC), not a duration in hours; rewriting it as
    // `from_hours(473352)` would erase the calendar semantics that the
    // assertion below relies on.
    #[allow(
        unknown_lints,
        clippy::duration_suboptimal_units,
        reason = "value is a Unix timestamp expressed in seconds, not a duration; lint name varies across clippy versions"
    )]
    #[test]
    fn builds_deny_record_with_severity_and_rule_id() {
        let decision = Decision::Deny {
            rule_id: "r.x".into(),
            reason: "blocked".into(),
        };
        let inp = input("Bash", "ls");
        let r = test_builder(&decision, &inp, "ls")
            .timestamp(UNIX_EPOCH + Duration::from_secs(1_704_067_200))
            .project_root(Some(&PathBuf::from("/repo")))
            .severity(Some(Severity::Critical))
            .agent("claude-code")
            .build();
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
        let inp = input("Bash", "ls");
        let r = test_builder(&Decision::Allow, &inp, "ls")
            .agent("cli")
            .build();
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
        let inp = input("Bash", "ls");
        let r = test_builder(
            &Decision::Monitor {
                rule_id: "r".into(),
            },
            &inp,
            "ls",
        )
        .mode(Mode::Monitor)
        .mode_demoted(true)
        .severity(Some(Severity::High))
        .agent("claude-code")
        .build();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"modeDemoted\":true"));
        assert!(json.contains("\"mode\":\"monitor\""));
    }

    #[test]
    fn ask_decision_serialises_as_ask_label() {
        let inp = input("Bash", "ls");
        let r = test_builder(
            &Decision::Ask {
                rule_id: "r".into(),
                reason: "?".into(),
            },
            &inp,
            "ls",
        )
        .severity(Some(Severity::Medium))
        .agent("claude-code")
        .build();
        assert_eq!(r.decision, "ask");
        assert_eq!(r.severity, Some("medium"));
    }

    #[test]
    fn allowlist_id_is_serialised_when_set() {
        let inp = input("Bash", "ls");
        let r = test_builder(&Decision::Allow, &inp, "ls")
            .allowlist_id(Some("approved-hotfix".into()))
            .agent("claude-code")
            .build();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"allowlistId\":\"approved-hotfix\""));
    }

    #[test]
    fn plugin_versions_serialise_as_name_at_version_list() {
        let inp = input("Bash", "ls");
        let r = test_builder(&Decision::Allow, &inp, "ls")
            .agent("cli")
            .plugin_versions(vec!["acme.security@0.1.0".into(), "core.demo@1.2.3".into()])
            .build();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"pluginVersions\":[\"acme.security@0.1.0\",\"core.demo@1.2.3\"]"));
    }

    #[test]
    fn agent_label_is_always_serialised() {
        let inp = input("Bash", "ls");
        let r = test_builder(&Decision::Allow, &inp, "ls")
            .agent("claude-code")
            .build();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"agent\":\"claude-code\""));
    }

    #[test]
    fn severity_label_covers_each_variant() {
        assert_eq!(severity_label(Severity::Info), "info");
        assert_eq!(severity_label(Severity::Low), "low");
        assert_eq!(severity_label(Severity::Medium), "medium");
        assert_eq!(severity_label(Severity::High), "high");
        assert_eq!(severity_label(Severity::Critical), "critical");
    }

    use crate::testing::proptest::{decision, mode, richer_hook_input, severity};
    use proptest::option;
    use proptest::prelude::*;

    proptest! {
        // build() must complete without panicking on every combination of
        // Decision / Mode / Severity / HookInput shape we generate.
        #[test]
        fn pbt_build_never_panics(
            decision in decision(),
            mode in mode(),
            mode_demoted in any::<bool>(),
            input in richer_hook_input(),
            severity in option::of(severity()),
            cmd in "[ -~]{0,40}",
        ) {
            let _ = test_builder(&decision, &input, cmd)
                .mode(mode)
                .mode_demoted(mode_demoted)
                .severity(severity)
                .build();
        }

        // The decision-label string is exactly one of the four documented
        // tags and matches the variant that produced it.
        #[test]
        fn pbt_decision_label_is_stable_and_exhaustive(d in decision()) {
            let label = decision_label(&d);
            prop_assert!(matches!(label, "allow" | "monitor" | "ask" | "deny"));
            let expected = match d {
                Decision::Allow => "allow",
                Decision::Monitor { .. } => "monitor",
                Decision::Ask { .. } => "ask",
                Decision::Deny { .. } => "deny",
            };
            prop_assert_eq!(label, expected);
        }

        // Mode label round-trips through the lowercase tag.
        #[test]
        fn pbt_mode_label_is_lowercase_tag(m in mode()) {
            let label = mode_label(m);
            prop_assert!(matches!(label, "enforce" | "monitor"));
            let expected = match m {
                Mode::Enforce => "enforce",
                Mode::Monitor => "monitor",
            };
            prop_assert_eq!(label, expected);
        }

        // Severity label round-trips through the lowercase tag.
        #[test]
        fn pbt_severity_label_is_lowercase_tag(s in severity()) {
            let label = severity_label(s);
            prop_assert!(matches!(label, "info" | "low" | "medium" | "high" | "critical"));
        }

        // The constructed record always carries the decision label of
        // the supplied decision and the tool name of the supplied input.
        #[test]
        fn pbt_record_mirrors_inputs(
            decision in decision(),
            mode in mode(),
            mode_demoted in any::<bool>(),
            input in richer_hook_input(),
            severity in option::of(severity()),
            cmd in "[ -~]{0,40}",
        ) {
            let r = test_builder(&decision, &input, cmd.clone())
                .mode(mode)
                .mode_demoted(mode_demoted)
                .severity(severity)
                .build();
            prop_assert_eq!(r.decision, decision_label(&decision));
            prop_assert_eq!(r.mode, mode_label(mode));
            prop_assert_eq!(&r.tool, &input.tool_name);
            prop_assert_eq!(r.command_redacted, cmd);
            prop_assert_eq!(r.event, "PreToolUse");
            prop_assert_eq!(r.mode_demoted, mode_demoted);
            // rule_id round-trips: only Allow has None.
            match decision {
                Decision::Allow => prop_assert!(r.rule_id.is_none()),
                _ => prop_assert!(r.rule_id.is_some()),
            }
        }

        // Serialising the record yields valid JSON containing the
        // documented top-level keys.
        #[test]
        fn pbt_record_serialises_to_object(
            decision in decision(),
            mode in mode(),
            mode_demoted in any::<bool>(),
            input in richer_hook_input(),
            severity in option::of(severity()),
            cmd in "[ -~]{0,40}",
        ) {
            let r = test_builder(&decision, &input, cmd)
                .mode(mode)
                .mode_demoted(mode_demoted)
                .severity(severity)
                .build();
            let v = serde_json::to_value(&r).expect("serialise");
            let obj = v.as_object().expect("top-level object");
            for k in ["timestamp", "event", "tool", "decision", "commandRedacted", "mode"] {
                prop_assert!(obj.contains_key(k), "missing key {k}");
            }
        }
    }
}
