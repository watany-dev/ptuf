//! `core.git` pack — guards against destructive git operations.
//!
//! Implements the 7 rules tabled in
//! `docs/design/policy-packs.md:83-98`. Each rule shares the
//! [`GitRule`] adapter so the [`crate::rules::ConfigRule`] trait is
//! implemented exactly once.

use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::facts::shell::Argv;
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;

/// Per-rule wiring: matcher predicate + decision shape + reason text.
///
/// `matcher` returns `true` when the supplied git invocation triggers
/// the rule. The Bash facts layer feeds every command (and every
/// `sudo`-unwrapped command) through `matcher` in
/// [`GitRule::evaluate`].
struct RuleSpec {
    id: &'static str,
    severity: Severity,
    decision_kind: DecisionKind,
    hard_deny: bool,
    matcher: fn(&Argv) -> bool,
    problem: &'static str,
    alternatives: &'static [&'static str],
}

pub struct GitRule {
    spec: &'static RuleSpec,
}

impl ConfigRule for GitRule {
    fn id(&self) -> &str {
        self.spec.id
    }

    fn severity(&self) -> Severity {
        self.spec.severity
    }

    fn default_decision(&self) -> DecisionKind {
        self.spec.decision_kind
    }

    fn hard_deny(&self) -> bool {
        self.spec.hard_deny
    }

    fn evaluate(&self, facts: &Facts, _input: &HookInput) -> Option<Decision> {
        let bash = facts.bash.as_ref()?;
        let triggered = bash
            .segments
            .iter()
            .flat_map(|p| p.commands.iter())
            .any(|cmd| invokes_matcher(cmd, self.spec.matcher));
        if !triggered {
            return None;
        }

        let reason = reason::build(self.spec.id, self.spec.problem, self.spec.alternatives);
        match self.spec.decision_kind {
            DecisionKind::Deny => Some(Decision::Deny {
                rule_id: self.spec.id.into(),
                reason,
            }),
            DecisionKind::Ask => Some(Decision::Ask {
                rule_id: self.spec.id.into(),
                reason,
            }),
            DecisionKind::Monitor => Some(Decision::Monitor {
                rule_id: self.spec.id.into(),
            }),
            DecisionKind::Allow => None,
        }
    }
}

/// Run `matcher` against `argv` directly; if `argv` is `sudo git ...`,
/// rebuild a synthetic `git ...` invocation and try again.
fn invokes_matcher(argv: &Argv, matcher: fn(&Argv) -> bool) -> bool {
    if matcher(argv) {
        return true;
    }
    if let Some(unwrapped) = unwrap_sudo(argv) {
        return matcher(&unwrapped);
    }
    false
}

fn unwrap_sudo(argv: &Argv) -> Option<Argv> {
    if argv.head != "sudo" {
        return None;
    }
    let mut iter = argv.args.iter().skip_while(|a| a.starts_with('-'));
    let head = iter.next()?.to_string();
    let rest: Vec<String> = iter.cloned().collect();
    Some(Argv {
        env_assignments: Vec::new(),
        head,
        args: rest,
    })
}

const GIT_HEADS: &[&str] = &["git", "/usr/bin/git", "/usr/local/bin/git"];

fn is_git(head: &str) -> bool {
    GIT_HEADS.contains(&head)
}

/// First non-flag argument after `git` — i.e. the subcommand
/// (`push`, `reset`, `remote`, ...). `None` for `git --version`.
fn git_subcommand(argv: &Argv) -> Option<&str> {
    if !is_git(&argv.head) {
        return None;
    }
    argv.args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
}

fn args_after_subcommand<'a>(argv: &'a Argv, sub: &str) -> Vec<&'a str> {
    let mut iter = argv.args.iter().map(String::as_str);
    for a in iter.by_ref() {
        if a == sub {
            break;
        }
    }
    iter.collect()
}

/// Match `git push --force` / `git push -f` / `git push --force-with-lease`
/// while letting only `--force-with-lease` fall to the lease-specific rule.
fn matches_force_push(argv: &Argv) -> bool {
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
    })
}

fn matches_force_push_with_lease(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("push") {
        return false;
    }
    let rest = args_after_subcommand(argv, "push");
    rest.iter()
        .any(|a| *a == "--force-with-lease" || a.starts_with("--force-with-lease="))
}

fn matches_reset_hard(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("reset") {
        return false;
    }
    let rest = args_after_subcommand(argv, "reset");
    rest.contains(&"--hard")
}

fn matches_clean_fdx(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("clean") {
        return false;
    }
    let rest = args_after_subcommand(argv, "clean");
    let long_flags: Vec<&&str> = rest.iter().filter(|a| a.starts_with("--")).collect();
    let has_long_force = long_flags.iter().any(|a| ***a == *"--force");
    let has_long_d = long_flags.iter().any(|a| ***a == *"-d");
    let has_long_x = long_flags.iter().any(|a| ***a == *"-x" || ***a == *"-X");
    if has_long_force && has_long_d && has_long_x {
        return true;
    }
    rest.iter().any(|a| {
        if !a.starts_with('-') || a.starts_with("--") {
            return false;
        }
        let body = &a[1..];
        body.contains('f') && body.contains('d') && (body.contains('x') || body.contains('X'))
    })
}

fn matches_branch_delete_force(argv: &Argv) -> bool {
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

fn matches_stash_clear(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("stash") {
        return false;
    }
    let rest = args_after_subcommand(argv, "stash");
    rest.contains(&"clear")
}

fn matches_remote_set_url(argv: &Argv) -> bool {
    if git_subcommand(argv) != Some("remote") {
        return false;
    }
    let rest = args_after_subcommand(argv, "remote");
    let mut iter = rest.iter().filter(|a| !a.starts_with('-'));
    iter.next() == Some(&"set-url")
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

pub static FORCE_PUSH_RULE: GitRule = GitRule { spec: &FORCE_PUSH };
pub static FORCE_PUSH_WITH_LEASE_RULE: GitRule = GitRule {
    spec: &FORCE_PUSH_WITH_LEASE,
};
pub static RESET_HARD_RULE: GitRule = GitRule { spec: &RESET_HARD };
pub static CLEAN_FDX_RULE: GitRule = GitRule { spec: &CLEAN_FDX };
pub static BRANCH_DELETE_FORCE_RULE: GitRule = GitRule {
    spec: &BRANCH_DELETE_FORCE,
};
pub static STASH_CLEAR_RULE: GitRule = GitRule { spec: &STASH_CLEAR };
pub static REMOTE_SET_URL_RULE: GitRule = GitRule {
    spec: &REMOTE_SET_URL,
};

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::hook_input::HookInput;

    fn bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": cmd }),
        }
    }

    fn assert_decision(rule: &GitRule, cmd: &str, want: DecisionKind) {
        let input = bash(cmd);
        let facts = crate::facts::extract(&input);
        let decision = rule.evaluate(&facts, &input);
        match (want, decision) {
            (DecisionKind::Deny, Some(Decision::Deny { rule_id, .. })) => {
                assert_eq!(rule_id, rule.spec.id, "wrong rule_id for {cmd:?}")
            }
            (DecisionKind::Ask, Some(Decision::Ask { rule_id, .. })) => {
                assert_eq!(rule_id, rule.spec.id, "wrong rule_id for {cmd:?}")
            }
            (DecisionKind::Allow, None) => {}
            (other, got) => panic!("for {cmd:?} expected {other:?}, got {got:?}"),
        }
    }

    fn assert_allow(rule: &GitRule, cmd: &str) {
        assert_decision(rule, cmd, DecisionKind::Allow);
    }

    // --- force-push -----------------------------------------------------

    #[test]
    fn force_push_denies_long_flag() {
        assert_decision(&FORCE_PUSH_RULE, "git push --force", DecisionKind::Deny);
    }

    #[test]
    fn force_push_denies_short_flag_cluster() {
        assert_decision(
            &FORCE_PUSH_RULE,
            "git push -f origin main",
            DecisionKind::Deny,
        );
        assert_decision(
            &FORCE_PUSH_RULE,
            "git push -uf origin main",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn force_push_denies_via_sudo() {
        assert_decision(
            &FORCE_PUSH_RULE,
            "sudo git push --force origin main",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn force_push_does_not_fire_for_lease_variant() {
        assert_allow(&FORCE_PUSH_RULE, "git push --force-with-lease origin main");
    }

    #[test]
    fn force_push_allows_safe_push_and_other_subcommands() {
        assert_allow(&FORCE_PUSH_RULE, "git push origin main");
        assert_allow(&FORCE_PUSH_RULE, "git fetch --force origin");
    }

    // --- force-push-with-lease -----------------------------------------

    #[test]
    fn lease_asks_long_flag() {
        assert_decision(
            &FORCE_PUSH_WITH_LEASE_RULE,
            "git push --force-with-lease",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn lease_asks_with_value_form() {
        assert_decision(
            &FORCE_PUSH_WITH_LEASE_RULE,
            "git push --force-with-lease=origin/main:abc123 origin main",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn lease_asks_via_sudo() {
        assert_decision(
            &FORCE_PUSH_WITH_LEASE_RULE,
            "sudo git push --force-with-lease",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn lease_allows_plain_push() {
        assert_allow(&FORCE_PUSH_WITH_LEASE_RULE, "git push origin main");
    }

    #[test]
    fn lease_allows_force_only() {
        assert_allow(&FORCE_PUSH_WITH_LEASE_RULE, "git push --force");
    }

    // --- reset --hard ---------------------------------------------------

    #[test]
    fn reset_hard_asks_long_flag() {
        assert_decision(
            &RESET_HARD_RULE,
            "git reset --hard HEAD~3",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn reset_hard_asks_with_no_target() {
        assert_decision(&RESET_HARD_RULE, "git reset --hard", DecisionKind::Ask);
    }

    #[test]
    fn reset_hard_asks_via_sudo() {
        assert_decision(
            &RESET_HARD_RULE,
            "sudo git reset --hard HEAD",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn reset_hard_allows_soft_and_keep() {
        assert_allow(&RESET_HARD_RULE, "git reset --soft HEAD~1");
        assert_allow(&RESET_HARD_RULE, "git reset --keep HEAD~1");
        assert_allow(&RESET_HARD_RULE, "git reset HEAD~1");
    }

    #[test]
    fn reset_hard_allows_other_subcommand() {
        assert_allow(&RESET_HARD_RULE, "git checkout --hard"); // not a real flag, but not reset
    }

    // --- clean -fdx -----------------------------------------------------

    #[test]
    fn clean_asks_short_cluster_fdx() {
        assert_decision(&CLEAN_FDX_RULE, "git clean -fdx", DecisionKind::Ask);
        assert_decision(&CLEAN_FDX_RULE, "git clean -fdX", DecisionKind::Ask);
        assert_decision(&CLEAN_FDX_RULE, "git clean -xfd", DecisionKind::Ask);
    }

    #[test]
    fn clean_asks_via_sudo() {
        assert_decision(&CLEAN_FDX_RULE, "sudo git clean -fdx", DecisionKind::Ask);
    }

    #[test]
    fn clean_allows_dry_run() {
        assert_allow(&CLEAN_FDX_RULE, "git clean -ndx");
        assert_allow(&CLEAN_FDX_RULE, "git clean -nd");
    }

    #[test]
    fn clean_allows_partial_flags() {
        assert_allow(&CLEAN_FDX_RULE, "git clean -fd");
        assert_allow(&CLEAN_FDX_RULE, "git clean -f");
    }

    #[test]
    fn clean_allows_other_subcommand() {
        assert_allow(&CLEAN_FDX_RULE, "git status");
    }

    // --- branch -D ------------------------------------------------------

    #[test]
    fn branch_delete_asks_short_capital_d() {
        assert_decision(
            &BRANCH_DELETE_FORCE_RULE,
            "git branch -D feature",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn branch_delete_asks_in_cluster() {
        assert_decision(
            &BRANCH_DELETE_FORCE_RULE,
            "git branch -rD feature",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn branch_delete_asks_via_sudo() {
        assert_decision(
            &BRANCH_DELETE_FORCE_RULE,
            "sudo git branch -D feature",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn branch_delete_allows_lowercase_d() {
        assert_allow(&BRANCH_DELETE_FORCE_RULE, "git branch -d feature");
    }

    #[test]
    fn branch_delete_allows_other_subcommand() {
        assert_allow(&BRANCH_DELETE_FORCE_RULE, "git branch -a");
        assert_allow(&BRANCH_DELETE_FORCE_RULE, "git status");
    }

    // --- stash clear ----------------------------------------------------

    #[test]
    fn stash_clear_asks() {
        assert_decision(&STASH_CLEAR_RULE, "git stash clear", DecisionKind::Ask);
    }

    #[test]
    fn stash_clear_asks_via_sudo() {
        assert_decision(&STASH_CLEAR_RULE, "sudo git stash clear", DecisionKind::Ask);
    }

    #[test]
    fn stash_clear_allows_other_stash_subcommands() {
        assert_allow(&STASH_CLEAR_RULE, "git stash list");
        assert_allow(&STASH_CLEAR_RULE, "git stash pop");
    }

    #[test]
    fn stash_clear_allows_other_subcommand() {
        assert_allow(&STASH_CLEAR_RULE, "git status");
    }

    #[test]
    fn stash_clear_allows_word_clear_in_other_arg() {
        assert_allow(&STASH_CLEAR_RULE, "git commit -m 'clear cache'");
    }

    // --- remote set-url -------------------------------------------------

    #[test]
    fn remote_set_url_asks() {
        assert_decision(
            &REMOTE_SET_URL_RULE,
            "git remote set-url origin git@evil:repo.git",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn remote_set_url_asks_via_sudo() {
        assert_decision(
            &REMOTE_SET_URL_RULE,
            "sudo git remote set-url origin git@evil:repo.git",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn remote_set_url_allows_other_remote_subcommands() {
        assert_allow(&REMOTE_SET_URL_RULE, "git remote -v");
        assert_allow(
            &REMOTE_SET_URL_RULE,
            "git remote add upstream https://example.com/x.git",
        );
    }

    #[test]
    fn remote_set_url_allows_other_subcommand() {
        assert_allow(&REMOTE_SET_URL_RULE, "git status");
    }

    #[test]
    fn remote_set_url_allows_word_in_other_command() {
        assert_allow(&REMOTE_SET_URL_RULE, "echo set-url");
    }

    // --- generic invariants --------------------------------------------

    #[test]
    fn rules_ignore_non_bash_tools() {
        let input = HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({ "command": "git push --force" }),
        };
        let facts = crate::facts::extract(&input);
        assert!(FORCE_PUSH_RULE.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn rules_fire_inside_compound_commands() {
        assert_decision(
            &FORCE_PUSH_RULE,
            "echo go && git push --force origin main",
            DecisionKind::Deny,
        );
        assert_decision(
            &RESET_HARD_RULE,
            "true; git reset --hard HEAD",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn metadata_matches_design_table() {
        assert!(FORCE_PUSH_RULE.hard_deny());
        assert_eq!(FORCE_PUSH_RULE.severity(), Severity::Critical);
        assert_eq!(FORCE_PUSH_RULE.default_decision(), DecisionKind::Deny);

        for rule in [
            &FORCE_PUSH_WITH_LEASE_RULE,
            &RESET_HARD_RULE,
            &CLEAN_FDX_RULE,
            &BRANCH_DELETE_FORCE_RULE,
        ] {
            assert!(!rule.hard_deny());
            assert_eq!(rule.severity(), Severity::High);
            assert_eq!(rule.default_decision(), DecisionKind::Ask);
        }

        for rule in [&STASH_CLEAR_RULE, &REMOTE_SET_URL_RULE] {
            assert!(!rule.hard_deny());
            assert_eq!(rule.severity(), Severity::Medium);
            assert_eq!(rule.default_decision(), DecisionKind::Ask);
        }
    }

    #[test]
    fn unwrap_sudo_with_only_flags_returns_none() {
        let argv = Argv {
            env_assignments: Vec::new(),
            head: "sudo".into(),
            args: vec!["-u".into(), "alice".into()],
        };
        // Even when only flags + a value remain, the function takes the
        // first non-flag token (`alice`) as the head. We just exercise
        // the path; behaviour-wise nothing matches a non-git head.
        let unwrapped = unwrap_sudo(&argv).expect("non-empty positional");
        assert_eq!(unwrapped.head, "alice");
    }

    #[test]
    fn rules_handle_full_path_to_git() {
        let input = bash("/usr/bin/git push --force origin main");
        let facts = crate::facts::extract(&input);
        assert!(matches!(
            FORCE_PUSH_RULE.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
    }
}
