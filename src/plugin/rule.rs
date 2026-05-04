//! Adapter that turns a parsed plugin rule into a [`ConfigRule`] the
//! engine can iterate alongside built-in rules.
//!
//! Every plugin rule carries its compiled `when:` AST plus the
//! `defaultDecision` it should emit when the AST evaluates to `true`.
//! `Allow` plugin rules contribute nothing to aggregation (they return
//! `None`), matching the documented semantics in
//! `docs/design/decision-model.md`.

use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::hook_input::HookInput;
use crate::reason;
use crate::rules::ConfigRule;

use super::dsl::{WhenNode, evaluate};
use super::schema::RawRule;

#[derive(Debug)]
pub struct PluginRule {
    id: String,
    severity: Severity,
    default_decision: DecisionKind,
    overridable: bool,
    hard_deny: bool,
    when: WhenNode,
    reason: String,
    remediation: Vec<String>,
}

impl PluginRule {
    /// Build a rule from its raw schema representation and a
    /// pre-compiled `when:` AST. The loader is the only caller in
    /// production code.
    pub fn from_raw(raw: RawRule, when: WhenNode) -> Self {
        Self {
            id: raw.id,
            severity: raw.severity,
            default_decision: raw.default_decision,
            overridable: raw.overridable.unwrap_or(true),
            hard_deny: raw.hard_deny.unwrap_or(false),
            when,
            reason: raw.reason,
            remediation: raw.remediation,
        }
    }

    fn formatted_reason(&self) -> String {
        let alts: Vec<&str> = self.remediation.iter().map(String::as_str).collect();
        reason::build(&self.id, &self.reason, &alts)
    }
}

impl ConfigRule for PluginRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn default_decision(&self) -> DecisionKind {
        self.default_decision
    }

    fn overridable(&self) -> bool {
        self.overridable
    }

    fn hard_deny(&self) -> bool {
        self.hard_deny
    }

    fn evaluate(&self, facts: &Facts, input: &HookInput) -> Option<Decision> {
        if !evaluate(&self.when, facts, input) {
            return None;
        }
        match self.default_decision {
            DecisionKind::Allow => None,
            DecisionKind::Monitor => Some(Decision::Monitor {
                rule_id: self.id.clone(),
            }),
            DecisionKind::Ask => Some(Decision::Ask {
                rule_id: self.id.clone(),
                reason: self.formatted_reason(),
            }),
            DecisionKind::Deny => Some(Decision::Deny {
                rule_id: self.id.clone(),
                reason: self.formatted_reason(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::facts;
    use serde_json::json;

    fn bash_input(cmd: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": cmd }),
        }
    }

    fn raw(id: &str, kind: DecisionKind) -> RawRule {
        RawRule {
            id: id.into(),
            title: String::new(),
            severity: Severity::Medium,
            default_decision: kind,
            overridable: None,
            hard_deny: None,
            when: serde_yaml_ng::Value::Null,
            reason: "blocked".into(),
            remediation: vec!["try again".into()],
            tests: Default::default(),
        }
    }

    #[test]
    fn deny_rule_emits_deny_decision_when_when_matches() {
        let rule = PluginRule::from_raw(
            raw("p.deny", DecisionKind::Deny),
            WhenNode::Tool("Bash".into()),
        );
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        let d = rule.evaluate(&facts, &input).expect("decision");
        match d {
            Decision::Deny { rule_id, reason } => {
                assert_eq!(rule_id, "p.deny");
                assert!(reason.contains("Blocked by ptuf rule p.deny"));
                assert!(reason.contains("try again"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn ask_rule_emits_ask_decision() {
        let rule = PluginRule::from_raw(
            raw("p.ask", DecisionKind::Ask),
            WhenNode::Tool("Bash".into()),
        );
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        let d = rule.evaluate(&facts, &input).expect("decision");
        assert!(matches!(d, Decision::Ask { .. }));
    }

    #[test]
    fn monitor_rule_emits_monitor_with_no_reason() {
        let rule = PluginRule::from_raw(
            raw("p.monitor", DecisionKind::Monitor),
            WhenNode::Tool("Bash".into()),
        );
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        let d = rule.evaluate(&facts, &input).expect("decision");
        match d {
            Decision::Monitor { rule_id } => assert_eq!(rule_id, "p.monitor"),
            other => panic!("expected Monitor, got {other:?}"),
        }
    }

    #[test]
    fn allow_rule_returns_none_to_skip_aggregation() {
        let rule = PluginRule::from_raw(
            raw("p.allow", DecisionKind::Allow),
            WhenNode::Tool("Bash".into()),
        );
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        assert!(rule.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn rule_returns_none_when_when_does_not_match() {
        let rule = PluginRule::from_raw(
            raw("p.x", DecisionKind::Deny),
            WhenNode::Tool("Read".into()),
        );
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        assert!(rule.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn defaults_overridable_true_and_hard_deny_false() {
        let rule = PluginRule::from_raw(
            raw("p.x", DecisionKind::Deny),
            WhenNode::Tool("Bash".into()),
        );
        assert!(rule.overridable());
        assert!(!rule.hard_deny());
    }

    #[test]
    fn explicit_hard_deny_and_overridable_are_honoured() {
        let mut r = raw("p.x", DecisionKind::Deny);
        r.overridable = Some(false);
        r.hard_deny = Some(true);
        let rule = PluginRule::from_raw(r, WhenNode::Tool("Bash".into()));
        assert!(!rule.overridable());
        assert!(rule.hard_deny());
    }
}
