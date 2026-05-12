//! `core.git.stash-clear` — `git stash clear` discards every stash
//! entry at once with no per-entry recovery.

use crate::decision::{DecisionKind, Severity};
use crate::facts::shell::Argv;

use super::argv::{args_after_subcommand, git_subcommand};
use super::{GitRule, RuleSpec};

pub(super) fn matches_stash_clear(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("stash") {
        return false;
    }
    let rest = args_after_subcommand(argv, "stash");
    rest.contains(&"clear")
}

const STASH_CLEAR: RuleSpec = RuleSpec {
    id: "core.git.stash-clear",
    severity: Severity::Medium,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_stash_clear,
    problem: "git stash clear deletes every stashed change at once with no per-entry recovery.",
    alternatives: &[
        "List stashes first with git stash list and drop entries individually.",
        "Apply or pop stashes that you still need before clearing.",
        "Ask the user before discarding all stashes.",
    ],
};

pub static STASH_CLEAR_RULE: GitRule = GitRule { spec: &STASH_CLEAR };
