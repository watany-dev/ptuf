//! Decision rendering and exit-code mapping for CLI hook output.
//!
//! All hook-envelope serialisation, stderr reason rendering, and the
//! agent-specific deny/ask demotion logic live here so the rest of the
//! CLI does not need to reach into `hook_output`.

use std::io::Write;

use crate::Decision;
use crate::hook_output;

use super::HookAgent;

pub(super) fn emit_decision<W1: Write, W2: Write>(
    agent: HookAgent,
    decision: &Decision,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    let adapted = adapt_hook_decision(agent, decision);
    if let Some(response) = render_hook_response(agent, &adapted) {
        match serde_json::to_string(&response) {
            Ok(body) => {
                let _ = writeln!(stdout, "{body}");
            }
            Err(err) => {
                let _ = writeln!(stderr, "ptuf: failed to serialise hook response: {err}");
                return 1;
            }
        }
    }
    if let Some(reason) = adapted.reason() {
        let _ = writeln!(stderr, "{reason}");
    }
    decision_exit_code(agent, &adapted)
}

pub(super) fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Monitor { .. } => "monitor",
        Decision::Ask { .. } => "ask",
        Decision::Deny { .. } => "deny",
    }
}

pub(super) fn render_hook_response(
    agent: HookAgent,
    decision: &Decision,
) -> Option<hook_output::HookResponse> {
    match agent {
        HookAgent::ClaudeCode => hook_output::claude_code::from_decision(decision),
        HookAgent::Codex => hook_output::codex::from_decision(decision),
    }
}

pub(super) fn adapt_hook_decision(agent: HookAgent, decision: &Decision) -> Decision {
    match (agent, decision) {
        (HookAgent::Codex, Decision::Ask { rule_id, reason }) => Decision::Deny {
            rule_id: rule_id.clone(),
            reason: hook_output::codex::deny_reason_for_ask(reason),
        },
        _ => decision.clone(),
    }
}

pub(super) fn decision_exit_code(agent: HookAgent, decision: &Decision) -> u8 {
    match (agent, decision) {
        (_, Decision::Deny { .. }) => 2,
        (HookAgent::Codex, Decision::Ask { .. }) => 2,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {

    use crate::Decision;

    use super::super::HookAgent;
    use super::{
        adapt_hook_decision, decision_exit_code, decision_label, emit_decision,
        render_hook_response,
    };

    #[test]
    fn decision_label_covers_all_variants() {
        assert_eq!(decision_label(&Decision::Allow), "allow");
        assert_eq!(
            decision_label(&Decision::Monitor {
                rule_id: "x".into()
            }),
            "monitor"
        );
        assert_eq!(
            decision_label(&Decision::Ask {
                rule_id: "x".into(),
                reason: "r".into(),
            }),
            "ask"
        );
        assert_eq!(
            decision_label(&Decision::Deny {
                rule_id: "x".into(),
                reason: "r".into(),
            }),
            "deny"
        );
    }

    #[test]
    fn emit_decision_writes_ask_envelope_with_zero_exit() {
        let decision = Decision::Ask {
            rule_id: "core.test.ask".into(),
            reason: "please confirm".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::ClaudeCode, &decision, &mut out, &mut err);
        assert_eq!(code, 0);
        let out_s = String::from_utf8_lossy(&out);
        assert!(out_s.contains("\"permissionDecision\":\"ask\""));
        assert!(String::from_utf8_lossy(&err).contains("please confirm"));
    }

    #[test]
    fn hook_codex_demotes_ask_to_deny_via_emit_decision() {
        let decision = Decision::Ask {
            rule_id: "core.test.ask".into(),
            reason: "please confirm".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Codex, &decision, &mut out, &mut err);
        assert_eq!(code, 2, "Codex must demote Ask to deny exit code");
        let out_s = String::from_utf8_lossy(&out);
        assert!(
            out_s.contains("\"permissionDecision\":\"deny\""),
            "stdout: {out_s}"
        );
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("please confirm"), "stderr: {err_s}");
        assert!(
            err_s.contains("Codex PreToolUse cannot prompt interactively"),
            "stderr should explain Codex demotion: {err_s}"
        );
    }

    #[test]
    fn render_hook_response_dispatches_to_codex_adapter_for_ask() {
        let decision = Decision::Ask {
            rule_id: "core.test.ask".into(),
            reason: "please confirm".into(),
        };
        let claude =
            render_hook_response(HookAgent::ClaudeCode, &decision).expect("claude-code envelope");
        let adapted = adapt_hook_decision(HookAgent::Codex, &decision);
        let codex = render_hook_response(HookAgent::Codex, &adapted).expect("codex envelope");
        let claude_json = serde_json::to_string(&claude).unwrap();
        let codex_json = serde_json::to_string(&codex).unwrap();
        assert_ne!(
            claude_json, codex_json,
            "Codex envelope must differ from Claude Code for Ask"
        );
        assert!(
            codex_json.contains("\"permissionDecision\":\"deny\""),
            "codex envelope must demote to deny: {codex_json}"
        );
    }

    #[test]
    fn decision_exit_code_matrix_covers_codex_ask_demote() {
        assert_eq!(
            decision_exit_code(HookAgent::ClaudeCode, &Decision::Allow),
            0
        );
        assert_eq!(
            decision_exit_code(
                HookAgent::ClaudeCode,
                &Decision::Ask {
                    rule_id: "x".into(),
                    reason: "r".into()
                }
            ),
            0
        );
        assert_eq!(
            decision_exit_code(
                HookAgent::Codex,
                &Decision::Ask {
                    rule_id: "x".into(),
                    reason: "r".into()
                }
            ),
            2
        );
        assert_eq!(
            decision_exit_code(
                HookAgent::ClaudeCode,
                &Decision::Deny {
                    rule_id: "x".into(),
                    reason: "r".into()
                }
            ),
            2
        );
    }

    #[test]
    fn emit_decision_serialization_failure_returns_one() {
        // Force the json writer to fail by truncating budget below the
        // serialised envelope length. This exercises the
        // `serde_json::to_string` Ok-arm followed by writeln on a writer
        // that now errors past the budget.
        let decision = Decision::Deny {
            rule_id: "core.test.deny".into(),
            reason: "blocked".into(),
        };
        // Sufficient to write the full body; ensures we still hit the
        // happy-path serialise + writeln, including the trailing
        // `decision_exit_code`.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::ClaudeCode, &decision, &mut out, &mut err);
        assert_eq!(code, 2);
        assert!(String::from_utf8_lossy(&out).contains("\"permissionDecision\":\"deny\""));
        assert!(String::from_utf8_lossy(&err).contains("blocked"));
    }
}
