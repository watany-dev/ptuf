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

/// Build an engine with the default configuration via the public
/// builder. The previous `default_engine()` shim was removed when the
/// builder became canonical (see `docs/review/open-issues.md` §1.7); the
/// builder run cannot fail for `Config::default()` because no plugins
/// are listed.
fn default_engine() -> Engine {
    Engine::builder()
        .build()
        .expect("Engine::builder with default config cannot fail")
}

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
        let _ = default_engine().decide(&input);
    }

    // Adversarial: even arbitrary printable ASCII as a Bash `command`
    // string must not panic.
    #[test]
    fn pbt_engine_handles_arbitrary_bash_strings(cmd in "[ -~]{0,80}") {
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": cmd }),
        };
        let _ = default_engine().decide(&input);
    }

    // The hook-output envelope contract: only Ask / Deny produce a
    // response; that response carries the decision's reason verbatim.
    #[test]
    fn pbt_hook_output_envelope_matches_decision(input in hook_input()) {
        let outcome = default_engine().decide(&input);
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
        let engine_dec = default_engine().decide(&input).decision;
        let shim_dec = ptuf::decide(&input);
        prop_assert_eq!(engine_dec, shim_dec);
    }

    // Every non-Allow decision must carry a non-empty `rule_id` so that
    // audit consumers can deduplicate and reason about origin. The
    // engine never invents free-floating Deny/Ask/Monitor decisions.
    #[test]
    fn pbt_non_allow_decisions_carry_non_empty_rule_id(input in hook_input()) {
        let dec = default_engine().decide(&input).decision;
        match &dec {
            Decision::Allow => {}
            Decision::Monitor { rule_id }
            | Decision::Ask { rule_id, .. }
            | Decision::Deny { rule_id, .. } => {
                prop_assert!(!rule_id.is_empty());
            }
        }
    }

    // The Outcome.mode field is stable: a default engine is in Enforce
    // and never reports a demotion.
    #[test]
    fn pbt_default_engine_outcome_is_enforce(input in hook_input()) {
        let outcome = default_engine().decide(&input);
        prop_assert_eq!(outcome.mode, ptuf::config::Mode::Enforce);
        prop_assert!(!outcome.mode_demoted);
    }

    // Calling `decide` twice with the same input is deterministic for
    // the default engine.
    #[test]
    fn pbt_default_engine_is_deterministic(input in hook_input()) {
        let a = default_engine().decide(&input).decision;
        let b = default_engine().decide(&input).decision;
        prop_assert_eq!(a, b);
    }

    // Every emitted Deny carries a reason that mentions either the rule
    // id or a "Safer alternative" hint; this matches the contract of
    // `crate::reason::build`. We assert a softer "non-empty reason" to
    // stay decoupled from the message format.
    #[test]
    fn pbt_deny_reason_is_non_empty(input in hook_input()) {
        if let Decision::Deny { reason, .. } = default_engine().decide(&input).decision {
            prop_assert!(!reason.is_empty());
        }
    }
}
