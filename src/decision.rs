use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Monitor { rule_id: String },
    Ask { rule_id: String, reason: String },
    Deny { rule_id: String, reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DecisionRank {
    Allow,
    Monitor,
    Ask,
    Deny,
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
    /// Strictness rank used by [`aggregate`].
    pub(crate) fn rank(&self) -> DecisionRank {
        match self {
            Decision::Allow => DecisionRank::Allow,
            Decision::Monitor { .. } => DecisionRank::Monitor,
            Decision::Ask { .. } => DecisionRank::Ask,
            Decision::Deny { .. } => DecisionRank::Deny,
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
        .max_by_key(|d| d.rank())
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
        assert!(Decision::Allow.rank() < monitor("x").rank());
        assert!(monitor("x").rank() < ask("x").rank());
        assert!(ask("x").rank() < deny("x").rank());
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

    use crate::testing::proptest::{decision, decision_kind, decision_list, severity};
    use proptest::prelude::*;

    proptest! {
        // Empty input is the unit element.
        #[test]
        fn pbt_aggregate_empty_is_allow(_dummy in 0u8..1) {
            prop_assert_eq!(aggregate(Vec::<Decision>::new()), Decision::Allow);
        }

        // A single-element aggregate is the element itself.
        #[test]
        fn pbt_aggregate_singleton_is_identity(d in decision()) {
            prop_assert_eq!(aggregate([d.clone()]), d);
        }

        // Idempotence: replicating the same decision does not change the result.
        #[test]
        fn pbt_aggregate_is_idempotent(d in decision(), n in 1usize..6) {
            let xs: Vec<Decision> = std::iter::repeat_n(d.clone(), n).collect();
            prop_assert_eq!(aggregate(xs), d);
        }

        // Associativity: aggregating a split list is the same as aggregating the whole.
        #[test]
        fn pbt_aggregate_is_associative(xs in decision_list(), ys in decision_list()) {
            let combined: Vec<Decision> = xs.iter().chain(ys.iter()).cloned().collect();
            let split = aggregate([aggregate(xs.clone()), aggregate(ys.clone())]);
            prop_assert_eq!(aggregate(combined), split);
        }

        // Commutativity: reversed input yields the same severity. Equality on
        // the full payload only holds when only one element shares the
        // maximum severity, so we compare severity (the ordering key) here.
        #[test]
        fn pbt_aggregate_is_severity_invariant_under_permutation(
            xs in decision_list(),
        ) {
            let mut reversed = xs.clone();
            reversed.reverse();
            prop_assert_eq!(aggregate(xs).rank(), aggregate(reversed).rank());
        }

        // Upper bound: the aggregated severity dominates every input.
        #[test]
        fn pbt_aggregate_is_upper_bound(xs in decision_list()) {
            let agg = aggregate(xs.clone());
            for x in &xs {
                prop_assert!(agg.rank() >= x.rank());
            }
        }

        // Severity ordering matches the documented hierarchy.
        #[test]
        fn pbt_severity_matches_kind_order(d in decision()) {
            let expected = match d.kind() {
                DecisionKind::Allow => DecisionRank::Allow,
                DecisionKind::Monitor => DecisionRank::Monitor,
                DecisionKind::Ask => DecisionRank::Ask,
                DecisionKind::Deny => DecisionRank::Deny,
            };
            prop_assert_eq!(d.rank(), expected);
        }

        // JSON round-trip stability for every variant.
        #[test]
        fn pbt_decision_round_trips_through_json(d in decision()) {
            let s = serde_json::to_string(&d).expect("serialise");
            let back: Decision = serde_json::from_str(&s).expect("deserialise");
            prop_assert_eq!(back, d);
        }

        // Severity enum round-trips and ordering is total.
        #[test]
        fn pbt_severity_round_trips(s in severity()) {
            let json = serde_json::to_string(&s).expect("serialise");
            let back: Severity = serde_json::from_str(&json).expect("deserialise");
            prop_assert_eq!(back, s);
        }

        // DecisionKind round-trips.
        #[test]
        fn pbt_decision_kind_round_trips(k in decision_kind()) {
            let json = serde_json::to_string(&k).expect("serialise");
            let back: DecisionKind = serde_json::from_str(&json).expect("deserialise");
            prop_assert_eq!(back, k);
        }

        // `kind()` matches the variant of the value it was extracted from.
        #[test]
        fn pbt_kind_matches_variant(d in decision()) {
            let expected = match &d {
                Decision::Allow => DecisionKind::Allow,
                Decision::Monitor { .. } => DecisionKind::Monitor,
                Decision::Ask { .. } => DecisionKind::Ask,
                Decision::Deny { .. } => DecisionKind::Deny,
            };
            prop_assert_eq!(d.kind(), expected);
        }
    }
}
