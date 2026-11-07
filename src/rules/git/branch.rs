//! `core.git.branch-delete-force` — `git branch -D` (or `-d` with
//! `-f` / `--force`) force-deletes a branch even if it has unmerged
//! commits.

use crate::decision::{DecisionKind, Severity};
use crate::facts::shell::{Argv, short_flag_cluster_contains};

use super::argv::{args_after_subcommand, git_subcommand};
use super::{GitRule, RuleSpec};

pub(super) fn matches_branch_delete_force(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("branch") {
        return false;
    }
    let rest = args_after_subcommand(argv, "branch");
    let has = |long: &str, short: char| {
        rest.iter()
            .any(|a| *a == long || short_flag_cluster_contains(a, short))
    };
    // `-D` is shorthand for `--delete --force`; the two halves may also
    // be spelled separately (`-d -f`, `-df`, `--delete --force`).
    let capital_d = rest.iter().any(|a| short_flag_cluster_contains(a, 'D'));
    let delete = has("--delete", 'd');
    let force = has("--force", 'f');
    capital_d || (delete && force)
}

const BRANCH_DELETE_FORCE: RuleSpec = RuleSpec {
    id: "core.git.branch-delete-force",
    severity: Severity::High,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_branch_delete_force,
    problem: "git branch -D force-deletes a branch even if it has unmerged commits, which can \
         lose work that lives only on that branch.",
    alternatives: &[
        "Verify the branch is fully merged with git branch --merged.",
        "Use git branch -d to refuse deletion when commits would be lost.",
        "Ask the user before removing a branch with unmerged commits.",
    ],
};

pub(crate) static BRANCH_DELETE_FORCE_RULE: GitRule = GitRule {
    spec: &BRANCH_DELETE_FORCE,
};
