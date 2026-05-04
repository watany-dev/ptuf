//! End-to-end property tests for [`ptuf::Engine`].
//!
//! Per-module unit-style PBT lives inside `src/<module>.rs` next to the
//! invariant under test. This file owns the cross-module property that
//! is hardest to express anywhere else: the default engine pipeline is
//! total — every well-formed [`HookInput`] must produce an [`Outcome`]
//! without panicking, and the resulting decision must conform to the
//! hook-output protocol.
//!
//! Strategies are duplicated in miniature here because the lib's
//! `src/testing/` strategies are gated behind `#[cfg(test)]` and are
//! therefore not visible from this integration crate.

#![allow(clippy::expect_used)]

use proptest::prelude::*;
use serde_json::json;

use ptuf::hook_output::from_decision;
use ptuf::{Decision, Engine, HookInput};

const DANGEROUS_HEADS: &[&str] = &[
    "rm", "/bin/rm", "curl", "wget", "scp", "rsync", "nc", "sudo", "bash", "python",
];

const SAFE_HEADS: &[&str] = &["ls", "echo", "cat", "grep", "true", "pwd"];

const SUSPICIOUS_ARGS: &[&str] = &[
    "-rf",
    "/",
    "/*",
    "/etc",
    "~",
    "$HOME",
    "~/.ssh/id_rsa",
    "~/.aws/credentials",
    ".env",
    "https://example.com/i.sh",
    "id_rsa",
];

fn bash_word() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => "[a-zA-Z0-9_./-]{1,10}".prop_map(String::from),
        1 => proptest::sample::select(SUSPICIOUS_ARGS).prop_map(String::from),
    ]
}

fn bash_head() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => proptest::sample::select(SAFE_HEADS).prop_map(String::from),
        2 => proptest::sample::select(DANGEROUS_HEADS).prop_map(String::from),
    ]
}

fn bash_command() -> impl Strategy<Value = String> {
    let argv =
        (bash_head(), proptest::collection::vec(bash_word(), 0..3)).prop_map(|(head, args)| {
            if args.is_empty() {
                head
            } else {
                format!("{} {}", head, args.join(" "))
            }
        });
    proptest::collection::vec(argv, 1..3).prop_map(|cmds| cmds.join(" | "))
}

fn hook_input() -> impl Strategy<Value = HookInput> {
    prop_oneof![
        4 => bash_command().prop_map(|cmd| HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": cmd }),
        }),
        1 => proptest::sample::select(&["Read", "Write", "Edit"][..])
            .prop_map(|t| HookInput {
                tool_name: t.to_string(),
                tool_input: json!({}),
            }),
    ]
}

proptest! {
    // The default engine pipeline never panics on any structured input.
    #[test]
    fn pbt_default_engine_decide_is_total(input in hook_input()) {
        let _ = Engine::default().decide(&input);
    }

    // Adversarial: even arbitrary printable ASCII as a Bash `command`
    // string must not panic.
    #[test]
    fn pbt_engine_handles_arbitrary_bash_strings(cmd in "[ -~]{0,80}") {
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": cmd }),
        };
        let _ = Engine::default().decide(&input);
    }

    // The hook-output envelope contract: only Ask / Deny produce a
    // response; that response carries the decision's reason verbatim.
    #[test]
    fn pbt_hook_output_envelope_matches_decision(input in hook_input()) {
        let outcome = Engine::default().decide(&input);
        match outcome.decision {
            Decision::Allow | Decision::Monitor { .. } => {
                prop_assert!(from_decision(&outcome.decision).is_none());
            }
            Decision::Ask { ref reason, .. } => {
                let resp = from_decision(&outcome.decision).expect("ask response");
                prop_assert_eq!(resp.hook_specific_output.permission_decision, "ask");
                prop_assert_eq!(
                    &resp.hook_specific_output.permission_decision_reason,
                    reason,
                );
            }
            Decision::Deny { ref reason, .. } => {
                let resp = from_decision(&outcome.decision).expect("deny response");
                prop_assert_eq!(resp.hook_specific_output.permission_decision, "deny");
                prop_assert_eq!(
                    &resp.hook_specific_output.permission_decision_reason,
                    reason,
                );
            }
        }
    }

    // The stateless `decide` shim agrees with the engine's own decision.
    #[test]
    fn pbt_stateless_decide_matches_engine(input in hook_input()) {
        let engine_dec = Engine::default().decide(&input).decision;
        let shim_dec = ptuf::decide(&input);
        prop_assert_eq!(engine_dec, shim_dec);
    }
}
