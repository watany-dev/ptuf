//! Cross-rule integration property tests.
//!
//! Per-rule unit-style PBT lives next to each rule (`src/rules/<rule>.rs`).
//! `src/rules/mod.rs` already owns the basic `RULES` invariants
//! (panic-safety, Bash-only rules silent on non-Bash, rule_id known and
//! unique). This file extends that surface with two end-to-end shapes
//! that need both `safe_command_string()` and `bash_with_quoting()`
//! generators, and so are easier to host in one place than to scatter
//! across each rule module:
//!
//! 1. **Negative space**: a sampled-safe Bash command must never fire
//!    any built-in rule.
//! 2. **`Some(d)` provenance**: every decision returned by
//!    `evaluate_all` must carry a `rule_id` that matches one of the
//!    rules visible through `rules::iter()`, and the decision's
//!    `kind()` must be one of the kinds a rule can legally emit.
//!
//! Together these close the design-doc invariants under
//! `docs/design/testing.md` "組み込み rule (全件)" that the
//! per-module slices cannot easily express on their own.

#![allow(clippy::expect_used)]

use proptest::prelude::*;

use ptuf::HookInput;
use ptuf::decision::DecisionKind;
use ptuf::rules::{evaluate_all, iter};
use ptuf::testing::proptest::{bash_with_quoting, safe_command_string};

fn bash_input(command: String) -> HookInput {
    HookInput {
        tool_name: "Bash".into(),
        tool_input: serde_json::json!({ "command": command }),
    }
}

proptest! {
    // Negative space: a benign Bash command (head from `SAFE_HEADS`,
    // safe arg) must never trigger any built-in rule. This is the PBT
    // counterpart of `evaluate_all_returns_empty_for_safe_bash` in
    // `src/rules/mod.rs`.
    #[test]
    fn pbt_safe_bash_command_fires_no_rule(cmd in safe_command_string()) {
        let input = bash_input(cmd);
        let facts = ptuf::facts::extract(&input);
        let decisions = evaluate_all(&facts, &input);
        prop_assert!(
            decisions.is_empty(),
            "safe command produced decisions: {decisions:?}",
        );
    }

    // `Some(d)` provenance: every decision returned by `evaluate_all`
    // carries a `rule_id` that exists in `rules::iter()`, and the
    // decision's `kind()` is one a rule may legally emit
    // (Monitor / Ask / Deny — never Allow, since `ConfigRule::evaluate`
    // returns `None` for "no opinion").
    #[test]
    fn pbt_decisions_carry_known_rule_ids(cmd in bash_with_quoting()) {
        let input = bash_input(cmd);
        let facts = ptuf::facts::extract(&input);
        let known_ids: Vec<&str> = iter().map(|r| r.id()).collect();
        for d in evaluate_all(&facts, &input) {
            let id = d.rule_id().expect("non-Allow decision carries a rule_id");
            prop_assert!(
                known_ids.contains(&id),
                "unknown rule_id {id:?} (not in rules::iter())",
            );
            prop_assert!(
                !matches!(d.kind(), DecisionKind::Allow),
                "rule emitted Decision::Allow: {d:?}",
            );
        }
    }
}
