use serde::Serialize;

use crate::Decision;

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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn allow_produces_no_response() {
        assert!(from_decision(&Decision::Allow).is_none());
    }

    #[test]
    fn monitor_produces_no_response() {
        let d = Decision::Monitor {
            rule_id: "core.m".into(),
        };
        assert!(from_decision(&d).is_none());
    }

    #[test]
    fn deny_serialises_expected_shape() {
        let d = Decision::Deny {
            rule_id: "core.x".into(),
            reason: "Blocked by ptuf rule core.x.\n".into(),
        };
        let resp = from_decision(&d).expect("response");
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("\"hookSpecificOutput\""));
        assert!(json.contains("\"hookEventName\":\"PreToolUse\""));
        assert!(json.contains("\"permissionDecision\":\"deny\""));
        assert!(json.contains("\"permissionDecisionReason\":\"Blocked by ptuf rule core.x.\\n\""));
    }

    #[test]
    fn ask_serialises_with_ask_verdict() {
        let d = Decision::Ask {
            rule_id: "core.a".into(),
            reason: "confirm please".into(),
        };
        let resp = from_decision(&d).expect("response");
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("\"permissionDecision\":\"ask\""));
        assert!(json.contains("\"permissionDecisionReason\":\"confirm please\""));
    }
}
