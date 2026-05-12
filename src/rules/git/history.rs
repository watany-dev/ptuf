//! History-destruction rules.
//!
//! - `core.git.update-ref-delete` — `git update-ref -d` bypasses the
//!   safety checks of `git branch -d` / `git tag -d`.
//! - `core.git.reflog-expire` — `git reflog delete` / `expire --expire=now`
//!   destroys the local recovery log.
//! - `core.git.gc-prune-now` — `git gc --prune=now` removes unreachable
//!   objects immediately, bypassing the grace window.

use crate::decision::{DecisionKind, Severity};
use crate::facts::shell::Argv;

use super::argv::{args_after_subcommand, git_subcommand};
use super::{GitRule, RuleSpec};

pub(super) fn matches_update_ref_delete(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("update-ref") {
        return false;
    }
    let rest = args_after_subcommand(argv, "update-ref");
    rest.iter().any(|a| *a == "-d" || *a == "--delete")
}

/// `git reflog delete <ref>` (always destructive) or `git reflog expire`
/// with an immediate-expiry flag. `reflog show --all` and similar
/// read-only operations are explicitly excluded.
pub(super) fn matches_reflog_expire(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("reflog") {
        return false;
    }
    let rest = args_after_subcommand(argv, "reflog");
    let sub = rest.iter().find(|a| !a.starts_with('-')).copied();
    match sub {
        Some("delete") => true,
        Some("expire") => rest.iter().any(|a| {
            *a == "--expire=now"
                || *a == "--expire=0"
                || *a == "--expire-unreachable=now"
                || *a == "--expire-unreachable=0"
        }),
        _ => false,
    }
}

/// `git gc --prune=now` or `--prune=all`. The default `--prune=2.weeks.ago`
/// (and any other dated value) is left alone because it cannot destroy
/// commits that are still recoverable through the reflog grace window.
pub(super) fn matches_gc_prune_now(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("gc") {
        return false;
    }
    let rest = args_after_subcommand(argv, "gc");
    rest.iter()
        .any(|a| *a == "--prune=now" || *a == "--prune=all")
}

const UPDATE_REF_DELETE: RuleSpec = RuleSpec {
    id: "core.git.update-ref-delete",
    severity: Severity::High,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_update_ref_delete,
    problem: "git update-ref -d forcibly removes a ref without any of the safety checks \
         that git branch / git tag apply, and bypasses pre-push hooks entirely.",
    alternatives: &[
        "Use git branch -d / git tag -d for normal deletion with merged-check.",
        "Confirm with the user before removing a low-level ref.",
    ],
};

const REFLOG_EXPIRE: RuleSpec = RuleSpec {
    id: "core.git.reflog-expire",
    severity: Severity::High,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_reflog_expire,
    problem: "git reflog delete / expire --expire=now destroys the local recovery log that \
         lets `git fsck --lost-found` and dated revisions reach orphaned commits.",
    alternatives: &[
        "Leave the reflog alone; entries expire on their own under git's grace window.",
        "If disk is the concern, run git gc without --prune=now so the grace window still applies.",
    ],
};

const GC_PRUNE_NOW: RuleSpec = RuleSpec {
    id: "core.git.gc-prune-now",
    severity: Severity::Medium,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_gc_prune_now,
    problem: "git gc --prune=now (or --prune=all) immediately removes unreachable objects \
         without the usual two-week grace window, making orphaned commits unrecoverable.",
    alternatives: &[
        "Run git gc without --prune=now to keep the grace window.",
        "If you really need to reclaim space, confirm with the user and verify nothing is dangling.",
    ],
};

pub static UPDATE_REF_DELETE_RULE: GitRule = GitRule {
    spec: &UPDATE_REF_DELETE,
};
pub static REFLOG_EXPIRE_RULE: GitRule = GitRule {
    spec: &REFLOG_EXPIRE,
};
pub static GC_PRUNE_NOW_RULE: GitRule = GitRule {
    spec: &GC_PRUNE_NOW,
};
