//! `core.git.clean-fdx` — `git clean -fdx` removes untracked and
//! ignored files (build artefacts, local secrets, editor state).

use crate::decision::{DecisionKind, Severity};
use crate::facts::shell::Argv;

use super::argv::{args_after_subcommand, git_subcommand};
use super::{GitRule, RuleSpec};

pub(super) fn matches_clean_fdx(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("clean") {
        return false;
    }
    let rest = args_after_subcommand(argv, "clean");
    let mut has_force = false;
    let mut has_dir = false;
    let mut has_ignored = false;
    let mut has_dry_run = false;

    for arg in rest {
        if arg == "--force" {
            has_force = true;
            continue;
        }
        if arg.starts_with("--") {
            continue;
        }
        let Some(body) = arg.strip_prefix('-') else {
            continue;
        };
        for flag in body.chars() {
            if flag == 'e' {
                break;
            }
            has_force |= flag == 'f';
            has_dir |= flag == 'd';
            has_ignored |= flag == 'x' || flag == 'X';
            has_dry_run |= flag == 'n';
        }
    }

    has_force && has_dir && has_ignored && !has_dry_run
}

const CLEAN_FDX: RuleSpec = RuleSpec {
    id: "core.git.clean-fdx",
    severity: Severity::High,
    decision_kind: DecisionKind::Ask,
    hard_deny: false,
    matcher: matches_clean_fdx,
    problem: "git clean -fdx removes every untracked and ignored file, including local-only \
         secrets, build artefacts, and editor state.",
    alternatives: &[
        "Run git clean -ndx first to preview what would be removed.",
        "Restrict cleaning to a specific path or pattern.",
        "Ask the user before deleting ignored files.",
    ],
};

pub static CLEAN_FDX_RULE: GitRule = GitRule { spec: &CLEAN_FDX };
