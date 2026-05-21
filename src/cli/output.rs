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
    let serialised = match agent {
        HookAgent::Copilot => {
            hook_output::copilot::from_decision(&adapted).map(|r| serde_json::to_string(&r))
        },
        // Cline always emits a JSON object on stdout, even for allow
        // (`{}`). Blocks are expressed via `cancel: true` JSON, never a
        // non-zero exit.
        HookAgent::Cline => Some(serde_json::to_string(&hook_output::cline::from_decision(
            &adapted,
        ))),
        HookAgent::ClaudeCode | HookAgent::Codex => {
            render_hook_response(agent, &adapted).map(|r| serde_json::to_string(&r))
        },
        HookAgent::Kiro => None,
    };
    if let Some(result) = serialised {
        match result {
            Ok(body) => {
                let _ = writeln!(stdout, "{body}");
            },
            Err(err) => {
                let _ = writeln!(stderr, "ptuf: failed to serialise hook response: {err}");
                return 1;
            },
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
        // Copilot uses a bare envelope (no `hookSpecificOutput` wrapper);
        // `emit_decision` dispatches through `hook_output::copilot` directly.
        HookAgent::Copilot => None,
        // Kiro emits no JSON envelope at all; deny/ask are surfaced via
        // stderr reason + non-zero exit only.
        HookAgent::Kiro => None,
        // Cline uses a Cline-specific cancel envelope; `emit_decision`
        // dispatches through `hook_output::cline` directly.
        HookAgent::Cline => None,
    }
}

pub(super) fn adapt_hook_decision(agent: HookAgent, decision: &Decision) -> Decision {
    match (agent, decision) {
        (HookAgent::Codex, Decision::Ask { rule_id, reason }) => Decision::Deny {
            rule_id: rule_id.clone(),
            reason: hook_output::codex::deny_reason_for_ask(reason),
        },
        (HookAgent::Copilot, Decision::Ask { rule_id, reason }) => Decision::Deny {
            rule_id: rule_id.clone(),
            reason: hook_output::copilot::deny_reason_for_ask(reason),
        },
        (HookAgent::Kiro, Decision::Ask { rule_id, reason }) => Decision::Deny {
            rule_id: rule_id.clone(),
            reason: hook_output::kiro::deny_reason_for_ask(reason),
        },
        (HookAgent::Cline, Decision::Ask { rule_id, reason }) => Decision::Deny {
            rule_id: rule_id.clone(),
            reason: hook_output::cline::deny_reason_for_ask(reason),
        },
        _ => decision.clone(),
    }
}

pub(super) fn decision_exit_code(agent: HookAgent, decision: &Decision) -> u8 {
    // Copilot's preToolUse hook treats a non-zero exit as a hook failure
    // and may skip the response entirely, which would let denies fail
    // open. We therefore express fail-closed via the stdout JSON
    // (`permissionDecision: "deny"`) and keep the exit code at 0 for
    // every Decision under the Copilot adapter — initialisation failures
    // (invalid payload / policy load failure) included. Cline behaves the
    // same way: blocks are carried by `cancel: true` JSON, not exit code.
    if matches!(agent, HookAgent::Copilot | HookAgent::Cline) {
        return 0;
    }
    match (agent, decision) {
        (_, Decision::Deny { .. }) => 2,
        // Defense-in-depth: Codex/Kiro Ask is demoted to Deny upstream
        // by `adapt_hook_decision`, but the matrix mirrors that here.
        (HookAgent::Codex | HookAgent::Kiro, Decision::Ask { .. }) => 2,
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
    fn kiro_deny_uses_exit_2_and_stderr_only() {
        let decision = Decision::Deny {
            rule_id: "core.filesystem.destructive-rm".into(),
            reason: "blocked".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Kiro, &decision, &mut out, &mut err);
        assert_eq!(code, 2);
        assert!(out.is_empty(), "Kiro must not write stdout, got: {out:?}");
        assert!(String::from_utf8_lossy(&err).contains("blocked"));
    }

    #[test]
    fn kiro_ask_is_demoted_to_deny() {
        let decision = Decision::Ask {
            rule_id: "core.test.ask".into(),
            reason: "please confirm".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Kiro, &decision, &mut out, &mut err);
        assert_eq!(code, 2, "Kiro must demote Ask to deny exit code");
        assert!(out.is_empty());
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("please confirm"), "stderr: {err_s}");
        assert!(
            err_s.contains("Kiro CLI PreToolUse hooks do not define an interactive ask channel"),
            "stderr should explain Kiro demotion: {err_s}"
        );
    }

    #[test]
    fn kiro_allow_writes_nothing_and_exits_zero() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Kiro, &Decision::Allow, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[test]
    fn kiro_monitor_writes_nothing_and_exits_zero() {
        let monitor = Decision::Monitor {
            rule_id: "core.test.monitor".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Kiro, &monitor, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[test]
    fn render_hook_response_is_none_for_kiro() {
        let decision = Decision::Deny {
            rule_id: "core.x".into(),
            reason: "r".into(),
        };
        assert!(render_hook_response(HookAgent::Kiro, &decision).is_none());
    }

    #[test]
    fn decision_exit_code_kiro_matrix() {
        assert_eq!(decision_exit_code(HookAgent::Kiro, &Decision::Allow), 0);
        assert_eq!(
            decision_exit_code(
                HookAgent::Kiro,
                &Decision::Monitor {
                    rule_id: "x".into()
                }
            ),
            0
        );
        assert_eq!(
            decision_exit_code(
                HookAgent::Kiro,
                &Decision::Ask {
                    rule_id: "x".into(),
                    reason: "r".into()
                }
            ),
            2
        );
        assert_eq!(
            decision_exit_code(
                HookAgent::Kiro,
                &Decision::Deny {
                    rule_id: "x".into(),
                    reason: "r".into()
                }
            ),
            2
        );
    }

    #[test]
    fn cline_deny_emits_cancel_json_with_zero_exit() {
        let decision = Decision::Deny {
            rule_id: "core.filesystem.destructive-rm".into(),
            reason: "blocked".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Cline, &decision, &mut out, &mut err);
        assert_eq!(code, 0, "Cline deny must exit 0 to stay fail-closed");
        let json: serde_json::Value =
            serde_json::from_slice(&out).expect("Cline stdout must be JSON");
        assert_eq!(json["cancel"], true);
        assert_eq!(json["errorMessage"], "blocked");
        assert!(json.get("shouldContinue").is_none());
        assert!(String::from_utf8_lossy(&err).contains("blocked"));
    }

    #[test]
    fn cline_allow_emits_empty_object_with_zero_exit() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Cline, &Decision::Allow, &mut out, &mut err);
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8_lossy(&out), "{}\n");
        assert!(err.is_empty());
    }

    #[test]
    fn cline_monitor_emits_empty_object_with_zero_exit() {
        let monitor = Decision::Monitor {
            rule_id: "core.test.monitor".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Cline, &monitor, &mut out, &mut err);
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8_lossy(&out), "{}\n");
    }

    #[test]
    fn cline_ask_is_demoted_to_cancel_with_zero_exit() {
        let decision = Decision::Ask {
            rule_id: "core.test.ask".into(),
            reason: "please confirm".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Cline, &decision, &mut out, &mut err);
        assert_eq!(code, 0, "Cline must demote Ask without a non-zero exit");
        let json: serde_json::Value =
            serde_json::from_slice(&out).expect("Cline stdout must be JSON");
        assert_eq!(json["cancel"], true);
        let msg = json["errorMessage"].as_str().expect("errorMessage");
        assert!(msg.contains("please confirm"));
        assert!(msg.contains("Cline PreToolUse file hooks"));
    }

    #[test]
    fn render_hook_response_is_none_for_cline() {
        let decision = Decision::Deny {
            rule_id: "core.x".into(),
            reason: "r".into(),
        };
        assert!(render_hook_response(HookAgent::Cline, &decision).is_none());
    }

    #[test]
    fn decision_exit_code_cline_matrix() {
        assert_eq!(decision_exit_code(HookAgent::Cline, &Decision::Allow), 0);
        assert_eq!(
            decision_exit_code(
                HookAgent::Cline,
                &Decision::Ask {
                    rule_id: "x".into(),
                    reason: "r".into()
                }
            ),
            0
        );
        assert_eq!(
            decision_exit_code(
                HookAgent::Cline,
                &Decision::Deny {
                    rule_id: "x".into(),
                    reason: "r".into()
                }
            ),
            0
        );
    }

    #[test]
    fn copilot_deny_emits_bare_json_with_zero_exit() {
        // Copilot expresses fail-closed via the JSON envelope, not the
        // exit code; the host treats non-zero exits as hook failures and
        // can let the tool call proceed. Pin: deny → exit 0 + bare
        // permissionDecision JSON on stdout + reason on stderr.
        let decision = Decision::Deny {
            rule_id: "core.filesystem.destructive-rm".into(),
            reason: "blocked".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Copilot, &decision, &mut out, &mut err);
        assert_eq!(code, 0, "Copilot deny must exit 0 to stay fail-closed");
        let out_s = String::from_utf8_lossy(&out);
        assert!(
            out_s.contains("\"permissionDecision\":\"deny\""),
            "stdout: {out_s}"
        );
        assert!(String::from_utf8_lossy(&err).contains("blocked"));
    }

    #[test]
    fn copilot_allow_emits_no_stdout_with_zero_exit() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Copilot, &Decision::Allow, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(
            out.is_empty(),
            "Copilot allow must emit no stdout, got: {out:?}"
        );
        assert!(err.is_empty());
    }

    #[test]
    fn copilot_ask_is_demoted_to_deny() {
        // Copilot PreToolUse has no interactive ask channel, so Ask must
        // demote to Deny — same fail-closed contract as Codex / Kiro.
        let decision = Decision::Ask {
            rule_id: "core.test.ask".into(),
            reason: "please confirm".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Copilot, &decision, &mut out, &mut err);
        assert_eq!(code, 0, "Copilot stays at exit 0 for every Decision");
        let out_s = String::from_utf8_lossy(&out);
        assert!(
            out_s.contains("\"permissionDecision\":\"deny\""),
            "stdout: {out_s}"
        );
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("please confirm"), "stderr: {err_s}");
    }

    #[test]
    fn render_hook_response_is_none_for_copilot() {
        let decision = Decision::Deny {
            rule_id: "core.x".into(),
            reason: "r".into(),
        };
        assert!(render_hook_response(HookAgent::Copilot, &decision).is_none());
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
