//! `core.git.remote-set-url` — silently re-points push/fetch traffic
//! and can redirect pushes to an attacker-controlled host.

use crate::decision::{DecisionKind, Severity};
use crate::facts::shell::Argv;

use super::argv::{args_after_subcommand, git_subcommand};
use super::{GitRule, RuleSpec};

pub(super) fn matches_remote_set_url(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("remote") {
        return false;
    }
    let rest = args_after_subcommand(argv, "remote");
    let mut iter = rest.iter().filter(|a| !a.starts_with('-'));
    iter.next() == Some(&"set-url")
}

const REMOTE_SET_URL: RuleSpec = RuleSpec {
    id: "core.git.remote-set-url",
    severity: Severity::Medium,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_remote_set_url,
    problem: "git remote set-url silently re-points push and fetch traffic, which can redirect \
         pushes to an attacker-controlled host.",
    alternatives: &[
        "Verify the new URL with the user before changing it.",
        "Inspect the change with git remote -v after running it.",
        "Use a separate remote name (git remote add) when the original should stay.",
    ],
};

pub static REMOTE_SET_URL_RULE: GitRule = GitRule {
    spec: &REMOTE_SET_URL,
};
