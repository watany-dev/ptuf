//! `core.git.push-*` rules — guards against destructive variants of
//! `git push` (force, lease, mirror, delete-remote, force-if-includes).

use crate::decision::{DecisionKind, Severity};
use crate::facts::shell::Argv;

use super::argv::{args_after_subcommand, git_subcommand};
use super::{GitRule, RuleSpec};

/// Match `git push --force` / `git push -f` / `git push --force-with-lease`
/// while letting only `--force-with-lease` fall to the lease-specific rule.
///
/// Also catches refspecs prefixed with `+` (e.g. `git push origin +main:main`),
/// which is git's shell-quoting-friendly synonym for `--force`.
pub(super) fn matches_force_push(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("push") {
        return false;
    }
    let rest = args_after_subcommand(argv, "push");
    rest.iter().any(|a| {
        *a == "--force"
            || a.starts_with("--force=")
            || (a.starts_with('-')
                && !a.starts_with("--")
                && a.contains('f')
                && !a.contains("force-with-lease"))
            || (a.starts_with('+') && a.len() > 1)
    })
}

pub(super) fn matches_force_push_with_lease(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("push") {
        return false;
    }
    let rest = args_after_subcommand(argv, "push");
    rest.iter()
        .any(|a| *a == "--force-with-lease" || a.starts_with("--force-with-lease="))
}

pub(super) fn matches_push_mirror(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("push") {
        return false;
    }
    let rest = args_after_subcommand(argv, "push");
    rest.iter()
        .any(|a| *a == "--mirror" || a.starts_with("--mirror="))
}

pub(super) fn matches_push_delete_remote(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("push") {
        return false;
    }
    let rest = args_after_subcommand(argv, "push");
    rest.iter().any(|a| {
        *a == "--delete"
            || (a.starts_with('-') && !a.starts_with("--") && a.contains('d'))
            || (a.starts_with(':') && a.len() > 1)
    })
}

pub(super) fn matches_force_if_includes(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("push") {
        return false;
    }
    let rest = args_after_subcommand(argv, "push");
    rest.iter()
        .any(|a| *a == "--force-if-includes" || a.starts_with("--force-if-includes="))
}

const FORCE_PUSH: RuleSpec = RuleSpec {
    id: "core.git.force-push",
    severity: Severity::Critical,
    decision_kind: DecisionKind::Deny,
    hard_deny: true,
    matcher: matches_force_push,
    problem: "git push --force rewrites remote history and can destroy collaborators' work \
         beyond local recovery.",
    alternatives: &[
        "Use git push --force-with-lease to refuse the push if the remote has moved.",
        "Pull, rebase, and re-push with a regular fast-forward.",
        "Ask the user to confirm an explicit force push before running it.",
    ],
};

const FORCE_PUSH_WITH_LEASE: RuleSpec = RuleSpec {
    id: "core.git.force-push-with-lease",
    severity: Severity::High,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_force_push_with_lease,
    problem: "git push --force-with-lease still rewrites the remote branch and is destructive \
         when other collaborators rely on the previous tip.",
    alternatives: &[
        "Confirm with the user that the remote is yours alone before continuing.",
        "Prefer a regular fast-forward push if possible.",
    ],
};

const PUSH_MIRROR: RuleSpec = RuleSpec {
    id: "core.git.push-mirror",
    severity: Severity::High,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_push_mirror,
    problem: "git push --mirror overwrites every ref on the remote with whatever exists \
         locally, including deleted branches and tags — equivalent to a force push across \
         the entire repository.",
    alternatives: &[
        "Push only the refs you actually want with explicit refspecs (git push origin <branch>).",
        "If you really need a mirror sync, confirm with the user and verify the remote first.",
    ],
};

const PUSH_DELETE_REMOTE: RuleSpec = RuleSpec {
    id: "core.git.push-delete-remote",
    severity: Severity::High,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_push_delete_remote,
    problem: "git push --delete (or `:<ref>` refspec) removes a branch or tag on the remote, \
         which is destructive and can break collaborators if the ref is shared.",
    alternatives: &[
        "Confirm with the user that the remote ref is safe to remove.",
        "If the goal is to clean up a stale local branch, use git branch -d locally instead.",
    ],
};

const FORCE_IF_INCLUDES: RuleSpec = RuleSpec {
    id: "core.git.force-if-includes",
    severity: Severity::High,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_force_if_includes,
    problem: "git push --force-if-includes still rewrites the remote branch when the local \
         tip subsumes the remote, which can drop commits other collaborators expect to see.",
    alternatives: &[
        "Pull / rebase to incorporate the remote, then push normally.",
        "Confirm with the user that overwriting the remote tip is intended.",
    ],
};

pub static FORCE_PUSH_RULE: GitRule = GitRule { spec: &FORCE_PUSH };
pub static FORCE_PUSH_WITH_LEASE_RULE: GitRule = GitRule {
    spec: &FORCE_PUSH_WITH_LEASE,
};
pub static PUSH_MIRROR_RULE: GitRule = GitRule { spec: &PUSH_MIRROR };
pub static PUSH_DELETE_REMOTE_RULE: GitRule = GitRule {
    spec: &PUSH_DELETE_REMOTE,
};
pub static FORCE_IF_INCLUDES_RULE: GitRule = GitRule {
    spec: &FORCE_IF_INCLUDES,
};
