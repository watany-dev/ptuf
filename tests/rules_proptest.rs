//! Cross-rule integration property tests.
//!
//! Per-rule unit-style PBT lives next to each rule. This file hosts the
//! negative-space invariant that needs `safe_command_string()` together
//! with the full `RULES` slice.

#![allow(clippy::expect_used)]

use proptest::prelude::*;

use ptuf::HookInput;
use ptuf::rules::evaluate_all;
use ptuf::testing::proptest::{safe_command_string, safe_heads};

fn bash_input(command: String) -> HookInput {
    HookInput {
        tool_name: "Bash".into(),
        tool_input: serde_json::json!({ "command": command }),
    }
}

/// Drift detector: every head declared safe by `safe_command_string()`
/// must remain inert against every built-in rule. Adding a rule that
/// fires on `ls` / `echo` / etc. without removing the head from the
/// safe list would silently break the negative-space property below;
/// this example-based test catches the regression at the head level.
#[test]
fn safe_heads_never_fire_any_builtin_rule() {
    let suffixes = ["", " foo", " --help"];
    for head in safe_heads() {
        for suffix in suffixes {
            let cmd = format!("{head}{suffix}");
            let input = bash_input(cmd.clone());
            let facts = ptuf::facts::extract(&input);
            let decisions = evaluate_all(&facts, &input);
            assert!(
                decisions.is_empty(),
                "safe head `{head}` fired rules on `{cmd}`: {decisions:?}",
            );
        }
    }
}

proptest! {
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
}
