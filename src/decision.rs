use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Monitor { rule_id: String },
    Ask { rule_id: String, reason: String },
    Deny { rule_id: String, reason: String },
}

/// Coarse risk grade attached to each rule. Used by plugin authors and
/// future audit log fields (`docs/design/config-and-plugins.md` §rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Variant tag of [`Decision`] without the carried payload. Lets a rule
/// declare its `defaultDecision` independently from the per-call
/// `rule_id` / `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionKind {
    Allow,
    Monitor,
    Ask,
    Deny,
}

impl Decision {
    /// Strictness ranking used by [`aggregate`].
    /// `allow=0 < monitor=1 < ask=2 < deny=3`.
    pub fn severity(&self) -> u8 {
        match self {
            Decision::Allow => 0,
            Decision::Monitor { .. } => 1,
            Decision::Ask { .. } => 2,
            Decision::Deny { .. } => 3,
        }
    }

    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Decision::Allow => None,
            Decision::Monitor { rule_id }
            | Decision::Ask { rule_id, .. }
            | Decision::Deny { rule_id, .. } => Some(rule_id.as_str()),
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Decision::Ask { reason, .. } | Decision::Deny { reason, .. } => Some(reason.as_str()),
            Decision::Allow | Decision::Monitor { .. } => None,
        }
    }

    /// Variant tag without the payload. Useful for matching against a
    /// rule's `defaultDecision`.
    pub fn kind(&self) -> DecisionKind {
        match self {
            Decision::Allow => DecisionKind::Allow,
            Decision::Monitor { .. } => DecisionKind::Monitor,
            Decision::Ask { .. } => DecisionKind::Ask,
            Decision::Deny { .. } => DecisionKind::Deny,
        }
    }
}

/// Aggregate multiple decisions according to `deny > ask > monitor > allow`.
/// An empty input yields [`Decision::Allow`].
pub fn aggregate<I>(decisions: I) -> Decision
where
    I: IntoIterator<Item = Decision>,
{
    decisions
        .into_iter()
        .max_by_key(|d| d.severity())
        .unwrap_or(Decision::Allow)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn deny(id: &str) -> Decision {
        Decision::Deny {
            rule_id: id.into(),
            reason: format!("blocked by {id}"),
        }
    }

    fn ask(id: &str) -> Decision {
        Decision::Ask {
            rule_id: id.into(),
            reason: format!("confirm for {id}"),
        }
    }

    fn monitor(id: &str) -> Decision {
        Decision::Monitor { rule_id: id.into() }
    }

    #[test]
    fn decision_serialises_allow() {
        let json = serde_json::to_string(&Decision::Allow).expect("serialise");
        assert_eq!(json, "{\"decision\":\"allow\"}");
    }

    #[test]
    fn decision_serialises_deny_with_rule_id_and_reason() {
        let json = serde_json::to_string(&deny("core.test")).expect("serialise");
        assert!(json.contains("\"decision\":\"deny\""));
        assert!(json.contains("\"rule_id\":\"core.test\""));
        assert!(json.contains("\"reason\":\"blocked by core.test\""));
    }

    #[test]
    fn decision_serialises_monitor_and_ask() {
        let m = serde_json::to_string(&monitor("core.m")).expect("serialise");
        assert!(m.contains("\"decision\":\"monitor\""));
        assert!(m.contains("\"rule_id\":\"core.m\""));

        let a = serde_json::to_string(&ask("core.a")).expect("serialise");
        assert!(a.contains("\"decision\":\"ask\""));
        assert!(a.contains("\"rule_id\":\"core.a\""));
        assert!(a.contains("\"reason\":\"confirm for core.a\""));
    }

    #[test]
    fn decision_round_trips_through_json() {
        for original in [
            Decision::Allow,
            monitor("core.m"),
            ask("core.a"),
            deny("core.d"),
        ] {
            let encoded = serde_json::to_string(&original).expect("encode");
            let decoded: Decision = serde_json::from_str(&encoded).expect("decode");
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn severity_is_monotonic() {
        assert!(Decision::Allow.severity() < monitor("x").severity());
        assert!(monitor("x").severity() < ask("x").severity());
        assert!(ask("x").severity() < deny("x").severity());
    }

    #[test]
    fn rule_id_and_reason_accessors() {
        assert_eq!(Decision::Allow.rule_id(), None);
        assert_eq!(Decision::Allow.reason(), None);
        assert_eq!(monitor("a.b").rule_id(), Some("a.b"));
        assert_eq!(monitor("a.b").reason(), None);
        assert_eq!(ask("a.b").rule_id(), Some("a.b"));
        assert_eq!(ask("a.b").reason(), Some("confirm for a.b"));
        assert_eq!(deny("a.b").rule_id(), Some("a.b"));
        assert_eq!(deny("a.b").reason(), Some("blocked by a.b"));
    }

    #[test]
    fn aggregate_empty_is_allow() {
        let empty: Vec<Decision> = Vec::new();
        assert_eq!(aggregate(empty), Decision::Allow);
    }

    #[test]
    fn severity_enum_orders_info_below_critical() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_serialises_lowercase() {
        let json = serde_json::to_string(&Severity::Critical).expect("serialise");
        assert_eq!(json, "\"critical\"");
        let parsed: Severity = serde_json::from_str("\"info\"").expect("parse");
        assert_eq!(parsed, Severity::Info);
    }

    #[test]
    fn decision_kind_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&DecisionKind::Deny).expect("serialise"),
            "\"deny\"",
        );
        let parsed: DecisionKind = serde_json::from_str("\"monitor\"").expect("parse");
        assert_eq!(parsed, DecisionKind::Monitor);
    }

    #[test]
    fn decision_kind_matches_variant() {
        assert_eq!(Decision::Allow.kind(), DecisionKind::Allow);
        assert_eq!(monitor("x").kind(), DecisionKind::Monitor);
        assert_eq!(ask("x").kind(), DecisionKind::Ask);
        assert_eq!(deny("x").kind(), DecisionKind::Deny);
    }

    #[test]
    fn aggregate_picks_most_restrictive() {
        let result = aggregate([Decision::Allow, monitor("m"), deny("d"), ask("a")]);
        assert_eq!(result, deny("d"));

        let result = aggregate([Decision::Allow, monitor("m"), ask("a")]);
        assert_eq!(result, ask("a"));

        let result = aggregate([Decision::Allow, monitor("m")]);
        assert_eq!(result, monitor("m"));

        let result = aggregate([Decision::Allow, Decision::Allow]);
        assert_eq!(result, Decision::Allow);
    }
}
