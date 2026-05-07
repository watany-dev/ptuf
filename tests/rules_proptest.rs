//! Cross-rule integration property tests.
//!
//! Per-rule unit-style PBT lives next to each rule. This file hosts the
//! negative-space invariant that needs `safe_command_string()` together
//! with the full `RULES` slice.

#![allow(clippy::expect_used)]

use proptest::prelude::*;

use ptuf::HookInput;
use ptuf::rules::evaluate_all;
use ptuf::testing::proptest::safe_command_string;

fn bash_input(command: String) -> HookInput {
    HookInput {
        tool_name: "Bash".into(),
        tool_input: serde_json::json!({ "command": command }),
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
