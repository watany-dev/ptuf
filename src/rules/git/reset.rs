//! `core.git.reset-hard` — `git reset --hard` discards uncommitted
//! work and rewrites HEAD without warning.

use crate::decision::{DecisionKind, Severity};
use crate::facts::shell::Argv;

use super::argv::{args_after_subcommand, git_subcommand};
use super::{GitRule, RuleSpec};

pub(super) fn matches_reset_hard(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("reset") {
        return false;
    }
    let rest = args_after_subcommand(argv, "reset");
    rest.contains(&"--hard")
}

const RESET_HARD: RuleSpec = RuleSpec {
    id: "core.git.reset-hard",
    severity: Severity::High,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_reset_hard,
    problem: "git reset --hard discards uncommitted changes and rewrites HEAD without warning.",
    alternatives: &[
        "Stash or commit the working tree first (git stash push -u).",
        "Use git reset --keep or git restore for a narrower change.",
        "Ask the user to confirm before throwing away local work.",
    ],
};

pub static RESET_HARD_RULE: GitRule = GitRule { spec: &RESET_HARD };
