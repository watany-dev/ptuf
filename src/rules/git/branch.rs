//! `core.git.branch-delete-force` — `git branch -D` force-deletes a
//! branch even if it has unmerged commits.

use crate::decision::{DecisionKind, Severity};
use crate::facts::shell::Argv;

use super::argv::{args_after_subcommand, git_subcommand};
use super::{GitRule, RuleSpec};

pub(super) fn matches_branch_delete_force(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("branch") {
        return false;
    }
    let rest = args_after_subcommand(argv, "branch");
    rest.iter().any(|a| {
        *a == "-D"
            || (a.starts_with('-') && !a.starts_with("--") && a.contains('D'))
            || *a == "--delete=force"
    })
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

pub static BRANCH_DELETE_FORCE_RULE: GitRule = GitRule {
    spec: &BRANCH_DELETE_FORCE,
};
