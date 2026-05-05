use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HookResponse {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: &'static str,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

pub mod claude_code {
    use super::{HookResponse, HookSpecificOutput};
    use crate::Decision;

    /// Build a Claude Code `hookSpecificOutput` response from a decision.
    /// Returns `None` for `Allow` and `Monitor`, since those produce no
    /// hook-protocol output.
    pub fn from_decision(decision: &Decision) -> Option<HookResponse> {
        let (verdict, reason) = match decision {
            Decision::Allow | Decision::Monitor { .. } => return None,
            Decision::Ask { reason, .. } => ("ask", reason.clone()),
            Decision::Deny { reason, .. } => ("deny", reason.clone()),
        };

        Some(HookResponse {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: verdict,
                permission_decision_reason: reason,
            },
        })
    }
}

pub mod codex {
    use super::{HookResponse, HookSpecificOutput};
    use crate::Decision;

    const ASK_UNAVAILABLE_NOTE: &str =
        "Codex PreToolUse cannot prompt interactively, so ptuf is blocking this request.";

    /// Build a Codex `hookSpecificOutput` response from a decision.
    /// `Ask` is mapped to a deny because Codex currently fails open on it.
    pub fn from_decision(decision: &Decision) -> Option<HookResponse> {
        let reason = match decision {
            Decision::Allow | Decision::Monitor { .. } => return None,
            Decision::Ask { reason, .. } => format!("{reason}\n\n{ASK_UNAVAILABLE_NOTE}"),
            Decision::Deny { reason, .. } => reason.clone(),
        };

        Some(HookResponse {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "deny",
                permission_decision_reason: reason,
            },
        })
    }

    pub fn deny_reason_for_ask(reason: &str) -> String {
        format!("{reason}\n\n{ASK_UNAVAILABLE_NOTE}")
    }
}

pub use claude_code::from_decision;

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::Decision;

    #[test]
    fn allow_produces_no_response() {
        assert!(claude_code::from_decision(&Decision::Allow).is_none());
        assert!(codex::from_decision(&Decision::Allow).is_none());
    }

    #[test]
    fn monitor_produces_no_response() {
        let d = Decision::Monitor {
            rule_id: "core.m".into(),
        };
        assert!(claude_code::from_decision(&d).is_none());
        assert!(codex::from_decision(&d).is_none());
    }

    #[test]
    fn claude_deny_serialises_expected_shape() {
        let d = Decision::Deny {
            rule_id: "core.x".into(),
            reason: "Blocked by ptuf rule core.x.\n".into(),
        };
        let resp = claude_code::from_decision(&d).expect("response");
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("\"hookSpecificOutput\""));
        assert!(json.contains("\"hookEventName\":\"PreToolUse\""));
        assert!(json.contains("\"permissionDecision\":\"deny\""));
        assert!(json.contains("\"permissionDecisionReason\":\"Blocked by ptuf rule core.x.\\n\""));
    }

    #[test]
    fn claude_ask_serialises_with_ask_verdict() {
        let d = Decision::Ask {
            rule_id: "core.a".into(),
            reason: "confirm please".into(),
        };
        let resp = claude_code::from_decision(&d).expect("response");
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("\"permissionDecision\":\"ask\""));
        assert!(json.contains("\"permissionDecisionReason\":\"confirm please\""));
    }

    #[test]
    fn codex_ask_serialises_as_deny_with_note() {
        let d = Decision::Ask {
            rule_id: "core.a".into(),
            reason: "confirm please".into(),
        };
        let resp = codex::from_decision(&d).expect("response");
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("\"permissionDecision\":\"deny\""));
        assert!(json.contains("Codex PreToolUse cannot prompt interactively"));
    }

    use crate::testing::proptest::{decision, reason_text, rule_id};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pbt_claude_allow_and_monitor_yield_none(rule_id in rule_id()) {
            let allow_response = claude_code::from_decision(&Decision::Allow);
            let monitor_response = claude_code::from_decision(&Decision::Monitor { rule_id });
            prop_assert!(allow_response.is_none());
            prop_assert!(monitor_response.is_none());
        }

        #[test]
        fn pbt_claude_ask_emits_ask_verdict(id in rule_id(), reason in reason_text()) {
            let d = Decision::Ask {
                rule_id: id,
                reason: reason.clone(),
            };
            let resp = claude_code::from_decision(&d).expect("ask emits a response");
            prop_assert_eq!(resp.hook_specific_output.permission_decision, "ask");
            prop_assert_eq!(resp.hook_specific_output.hook_event_name, "PreToolUse");
            prop_assert_eq!(resp.hook_specific_output.permission_decision_reason, reason);
        }

        #[test]
        fn pbt_codex_maps_ask_to_deny(id in rule_id(), reason in reason_text()) {
            let d = Decision::Ask {
                rule_id: id,
                reason: reason.clone(),
            };
            let resp = codex::from_decision(&d).expect("ask emits a response");
            prop_assert_eq!(resp.hook_specific_output.permission_decision, "deny");
            prop_assert!(resp.hook_specific_output.permission_decision_reason.contains(&reason));
        }

        #[test]
        fn pbt_deny_emits_deny_verdict_in_both_adapters(id in rule_id(), reason in reason_text()) {
            let d = Decision::Deny {
                rule_id: id,
                reason: reason.clone(),
            };
            let claude = claude_code::from_decision(&d).expect("deny emits a response");
            let codex = codex::from_decision(&d).expect("deny emits a response");
            prop_assert_eq!(claude.hook_specific_output.permission_decision, "deny");
            prop_assert_eq!(codex.hook_specific_output.permission_decision, "deny");
            prop_assert_eq!(claude.hook_specific_output.permission_decision_reason, reason.clone());
            prop_assert_eq!(codex.hook_specific_output.permission_decision_reason, reason);
        }

        #[test]
        fn pbt_response_presence_matches_variant(d in decision()) {
            let expects_response = matches!(d, Decision::Ask { .. } | Decision::Deny { .. });
            prop_assert_eq!(claude_code::from_decision(&d).is_some(), expects_response);
            prop_assert_eq!(codex::from_decision(&d).is_some(), expects_response);
        }
    }
}
