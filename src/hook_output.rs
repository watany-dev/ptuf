use serde::Serialize;

/// Append a per-adapter "Ask is unavailable" note to a deny reason.
/// Adapters that cannot surface an interactive prompt (Codex, Copilot,
/// Kiro) demote `Ask` to `Deny` and use this helper to produce a
/// human-readable explanation.
fn append_demote_note(reason: &str, note: &str) -> String {
    format!("{reason}\n\n{note}")
}

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
    use super::{HookResponse, HookSpecificOutput, append_demote_note};
    use crate::Decision;

    const ASK_UNAVAILABLE_NOTE: &str =
        "Codex PreToolUse cannot prompt interactively, so ptuf is blocking this request.";

    /// Build a Codex `hookSpecificOutput` response from a decision.
    /// `Ask` is mapped to a deny because Codex currently fails open on it.
    pub fn from_decision(decision: &Decision) -> Option<HookResponse> {
        let reason = match decision {
            Decision::Allow | Decision::Monitor { .. } => return None,
            Decision::Ask { reason, .. } => deny_reason_for_ask(reason),
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
        append_demote_note(reason, ASK_UNAVAILABLE_NOTE)
    }
}

pub mod copilot {
    use serde::Serialize;

    use super::append_demote_note;
    use crate::Decision;

    /// Note appended to a deny reason whenever a Copilot `Ask` decision
    /// is demoted to `Deny`. Copilot hooks have no reliable interactive
    /// confirmation channel, so ptuf surfaces the demotion explicitly.
    const ASK_UNAVAILABLE_NOTE: &str = "GitHub Copilot hooks do not reliably process interactive ask decisions; ptuf is blocking this request instead.";

    /// Bare deny envelope expected by GitHub Copilot's `preToolUse` hook.
    /// Unlike Claude Code / Codex, Copilot does **not** wrap the body in
    /// `hookSpecificOutput` and treats non-zero exit codes as hook
    /// failures (skipping the response). The CLI therefore writes this
    /// JSON object directly and uses exit `0`, even for deny.
    #[derive(Debug, Serialize)]
    pub struct CopilotResponse {
        #[serde(rename = "permissionDecision")]
        pub permission_decision: &'static str,
        #[serde(rename = "permissionDecisionReason")]
        pub permission_decision_reason: String,
    }

    /// Build a Copilot deny envelope from a decision.
    /// Returns `None` for `Allow` and `Monitor` (Copilot, like the other
    /// adapters, emits no output for those). `Ask` is demoted to a deny
    /// because Copilot can't surface an interactive prompt reliably.
    pub fn from_decision(decision: &Decision) -> Option<CopilotResponse> {
        let reason = match decision {
            Decision::Allow | Decision::Monitor { .. } => return None,
            Decision::Ask { reason, .. } => deny_reason_for_ask(reason),
            Decision::Deny { reason, .. } => reason.clone(),
        };

        Some(CopilotResponse {
            permission_decision: "deny",
            permission_decision_reason: reason,
        })
    }

    pub fn deny_reason_for_ask(reason: &str) -> String {
        append_demote_note(reason, ASK_UNAVAILABLE_NOTE)
    }
}

pub mod kiro {
    use super::append_demote_note;

    /// Note appended to a deny reason whenever a Kiro `Ask` decision is
    /// demoted to `Deny`. Kiro's `preToolUse` hook protocol does not
    /// expose an interactive ask channel, so ptuf surfaces the demotion
    /// explicitly on stderr.
    const ASK_UNAVAILABLE_NOTE: &str = "Kiro CLI PreToolUse hooks do not define an interactive ask channel; ptuf is blocking this request instead.";

    pub fn deny_reason_for_ask(reason: &str) -> String {
        append_demote_note(reason, ASK_UNAVAILABLE_NOTE)
    }
}

pub mod cline {
    use serde::Serialize;

    use super::append_demote_note;
    use crate::Decision;

    /// Note appended to a deny reason whenever a Cline `Ask` decision is
    /// demoted to `Deny`. Cline `PreToolUse` file hooks have no reliable
    /// interactive review channel, so ptuf surfaces the demotion
    /// explicitly in the cancel JSON.
    const ASK_UNAVAILABLE_NOTE: &str = "Cline PreToolUse file hooks do not currently provide a uniformly reliable interactive review channel; ptuf is blocking this request instead.";

    /// Cline `PreToolUse` hook response. Allow / Monitor serialise to the
    /// bare `{}` object (every field skipped); deny / demoted-ask
    /// serialise to a `cancel: true` envelope. The renderer never emits
    /// `shouldContinue`, `review`, or `overrideInput`.
    #[derive(Debug, Serialize)]
    pub struct ClineResponse {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cancel: Option<bool>,

        #[serde(rename = "errorMessage", skip_serializing_if = "Option::is_none")]
        pub error_message: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        pub context: Option<String>,

        #[serde(
            rename = "contextModification",
            skip_serializing_if = "Option::is_none"
        )]
        pub context_modification: Option<String>,
    }

    impl ClineResponse {
        fn empty() -> Self {
            Self {
                cancel: None,
                error_message: None,
                context: None,
                context_modification: None,
            }
        }

        fn cancel(reason: String) -> Self {
            Self {
                cancel: Some(true),
                error_message: Some(reason.clone()),
                context: Some(reason.clone()),
                context_modification: Some(reason),
            }
        }
    }

    /// Build a Cline hook response from a decision. `Allow` / `Monitor`
    /// produce the empty `{}` object; `Deny` produces a cancel envelope;
    /// `Ask` is demoted to a cancel envelope with the demotion note.
    pub fn from_decision(decision: &Decision) -> ClineResponse {
        match decision {
            Decision::Allow | Decision::Monitor { .. } => ClineResponse::empty(),
            Decision::Ask { reason, .. } => ClineResponse::cancel(deny_reason_for_ask(reason)),
            Decision::Deny { reason, .. } => ClineResponse::cancel(reason.clone()),
        }
    }

    pub fn deny_reason_for_ask(reason: &str) -> String {
        append_demote_note(reason, ASK_UNAVAILABLE_NOTE)
    }
}

pub mod cursor {
    use serde::Serialize;

    use crate::Decision;

    /// Bare permission envelope expected by Cursor's `preToolUse` hook.
    /// Unlike Copilot / Codex / Kiro, Cursor exposes a genuine `ask`
    /// channel, so `Ask` is **not** demoted to `Deny`. The CLI writes this
    /// JSON object directly (no `hookSpecificOutput` wrapper); `deny`
    /// additionally exits 2 while `ask` exits 0.
    #[derive(Debug, Serialize)]
    pub struct CursorResponse {
        pub permission: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub user_message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub agent_message: Option<String>,
    }

    /// Build a Cursor permission envelope from a decision. Returns `None`
    /// for no decision. `Allow` / `Monitor` map to an explicit
    /// `permission: "allow"` because current Cursor treats empty stdout
    /// from a `failClosed` hook as invalid output. `Ask` maps to
    /// `permission: "ask"` and `Deny` to `permission: "deny"`; both carry
    /// the reason verbatim in `user_message` / `agent_message`.
    pub fn from_decision(decision: &Decision) -> CursorResponse {
        let (permission, reason) = match decision {
            Decision::Allow | Decision::Monitor { .. } => ("allow", None),
            Decision::Ask { reason, .. } => ("ask", Some(reason.clone())),
            Decision::Deny { reason, .. } => ("deny", Some(reason.clone())),
        };

        CursorResponse {
            permission,
            user_message: reason.clone(),
            agent_message: reason,
        }
    }
}

pub use claude_code::from_decision;

#[cfg(test)]
mod tests {

    use super::*;
    use crate::Decision;

    #[test]
    fn allow_produces_no_response() {
        assert!(claude_code::from_decision(&Decision::Allow).is_none());
        assert!(codex::from_decision(&Decision::Allow).is_none());
        assert!(copilot::from_decision(&Decision::Allow).is_none());
    }

    #[test]
    fn monitor_produces_no_response() {
        let d = Decision::Monitor {
            rule_id: "core.m".into(),
        };
        assert!(claude_code::from_decision(&d).is_none());
        assert!(codex::from_decision(&d).is_none());
        assert!(copilot::from_decision(&d).is_none());
    }

    #[test]
    fn copilot_deny_serialises_bare_envelope() {
        let d = Decision::Deny {
            rule_id: "core.x".into(),
            reason: "Blocked by ptuf rule core.x.\n".into(),
        };
        let resp = copilot::from_decision(&d).expect("response");
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(
            !json.contains("hookSpecificOutput"),
            "Copilot must not wrap response: {json}"
        );
        assert!(json.contains("\"permissionDecision\":\"deny\""));
        assert!(json.contains("\"permissionDecisionReason\":\"Blocked by ptuf rule core.x.\\n\""));
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
    fn kiro_deny_reason_for_ask_appends_note() {
        let s = kiro::deny_reason_for_ask("please confirm");
        assert!(s.starts_with("please confirm"));
        assert!(s.contains("Kiro CLI PreToolUse hooks do not define an interactive ask channel"));
    }

    #[test]
    fn cline_allow_outputs_empty_object() {
        let resp = cline::from_decision(&Decision::Allow);
        let json = serde_json::to_string(&resp).expect("serialise");
        assert_eq!(json, "{}");
    }

    #[test]
    fn cline_monitor_outputs_empty_object() {
        let d = Decision::Monitor {
            rule_id: "core.m".into(),
        };
        let resp = cline::from_decision(&d);
        let json = serde_json::to_string(&resp).expect("serialise");
        assert_eq!(json, "{}");
    }

    #[test]
    fn cline_deny_outputs_cancel_json() {
        let d = Decision::Deny {
            rule_id: "core.x".into(),
            reason: "blocked".into(),
        };
        let resp = cline::from_decision(&d);
        let json = serde_json::to_value(resp).expect("serialise");
        assert_eq!(json["cancel"], true);
        assert_eq!(json["errorMessage"], "blocked");
        assert_eq!(json["context"], "blocked");
        assert_eq!(json["contextModification"], "blocked");
        assert!(json.get("shouldContinue").is_none());
        assert!(json.get("review").is_none());
    }

    #[test]
    fn cline_ask_is_demoted_to_cancel() {
        let d = Decision::Ask {
            rule_id: "core.x".into(),
            reason: "confirm".into(),
        };
        let resp = cline::from_decision(&d);
        let json = serde_json::to_value(resp).expect("serialise");
        assert_eq!(json["cancel"], true);
        let msg = json["errorMessage"].as_str().expect("errorMessage string");
        assert!(msg.starts_with("confirm"));
        assert!(msg.contains("Cline PreToolUse file hooks"));
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

    #[test]
    fn cursor_allow_and_monitor_emit_explicit_allow() {
        let allow =
            serde_json::to_value(cursor::from_decision(&Decision::Allow)).expect("serialise allow");
        assert_eq!(allow["permission"], "allow");
        assert!(allow.get("user_message").is_none());
        assert!(allow.get("agent_message").is_none());

        let monitor = serde_json::to_value(cursor::from_decision(&Decision::Monitor {
            rule_id: "core.m".into(),
        }))
        .expect("serialise monitor");
        assert_eq!(monitor["permission"], "allow");
        assert!(monitor.get("user_message").is_none());
        assert!(monitor.get("agent_message").is_none());
    }

    #[test]
    fn cursor_deny_serialises_bare_permission_envelope() {
        let d = Decision::Deny {
            rule_id: "core.x".into(),
            reason: "blocked".into(),
        };
        let resp = cursor::from_decision(&d);
        let json = serde_json::to_value(&resp).expect("serialise");
        assert!(
            json.get("hookSpecificOutput").is_none(),
            "Cursor must not wrap response: {json}"
        );
        assert_eq!(json["permission"], "deny");
        assert_eq!(json["user_message"], "blocked");
        assert_eq!(json["agent_message"], "blocked");
    }

    #[test]
    fn cursor_ask_is_preserved_not_demoted() {
        let d = Decision::Ask {
            rule_id: "core.a".into(),
            reason: "confirm please".into(),
        };
        let resp = cursor::from_decision(&d);
        let json = serde_json::to_value(&resp).expect("serialise");
        assert_eq!(
            json["permission"], "ask",
            "Cursor has an ask channel; Ask must not demote to deny"
        );
        assert_eq!(json["user_message"], "confirm please");
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
            prop_assert_eq!(copilot::from_decision(&d).is_some(), expects_response);
        }

        #[test]
        fn pbt_copilot_maps_ask_to_deny(id in rule_id(), reason in reason_text()) {
            let d = Decision::Ask {
                rule_id: id,
                reason: reason.clone(),
            };
            let resp = copilot::from_decision(&d).expect("ask emits a response");
            prop_assert_eq!(resp.permission_decision, "deny");
            prop_assert!(resp.permission_decision_reason.contains(&reason));
        }

        #[test]
        fn pbt_copilot_deny_keeps_reason_verbatim(id in rule_id(), reason in reason_text()) {
            let d = Decision::Deny {
                rule_id: id,
                reason: reason.clone(),
            };
            let resp = copilot::from_decision(&d).expect("deny emits a response");
            prop_assert_eq!(resp.permission_decision, "deny");
            prop_assert_eq!(resp.permission_decision_reason, reason);
        }
    }
}
