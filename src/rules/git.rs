//! `core.git` pack — guards against destructive git operations.
//!
//! Implements the 11 rules tabled in `docs/design/policy-packs.md`
//! (7 destructive-operation rules + 4 hook/signing bypass-blockers).
//! Each rule shares the [`GitRule`] adapter so the
//! [`crate::rules::ConfigRule`] trait is implemented exactly once.

use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::facts::shell::{Argv, unwrap_sudo};
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
            .commands()
            .into_iter()
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

const GIT_HEADS: &[&str] = &["git", "/usr/bin/git", "/usr/local/bin/git"];

fn is_git(head: &str) -> bool {
    GIT_HEADS.contains(&head)
}

/// First non-flag argument after `git` — i.e. the subcommand
/// (`push`, `reset`, `remote`, ...). `None` for `git --version`.
///
/// Skips git's value-taking global flags so that
/// `git -c core.hooksPath=/dev/null commit` resolves to `commit`, not to
/// the `-c`'s value.
fn git_subcommand(argv: &Argv) -> Option<&str> {
    if !is_git(&argv.head) {
        return None;
    }
    let mut iter = argv.args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-c" | "--config" | "-C" | "--git-dir" | "--work-tree" | "--namespace"
            | "--exec-path" | "--super-prefix" => {
                iter.next();
                continue;
            },
            s if s.starts_with("--config=")
                || s.starts_with("--git-dir=")
                || s.starts_with("--work-tree=")
                || s.starts_with("--namespace=")
                || s.starts_with("--exec-path=")
                || s.starts_with("--super-prefix=") =>
            {
                continue;
            },
            s if s.starts_with('-') => continue,
            s => return Some(s),
        }
    }
    None
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

/// Gather the values of git's `-c key=val` / `--config key=val` /
/// `--config=key=val` global options.
fn config_overrides(argv: &Argv) -> impl Iterator<Item = &str> + '_ {
    let mut iter = argv.args.iter();
    std::iter::from_fn(move || {
        while let Some(a) = iter.next() {
            match a.as_str() {
                "-c" | "--config" => {
                    if let Some(v) = iter.next() {
                        return Some(v.as_str());
                    }
                },
                s => {
                    if let Some(rest) = s.strip_prefix("--config=") {
                        return Some(rest);
                    }
                },
            }
        }
        None
    })
}

#[derive(Clone, Copy)]
enum BypassMatch {
    Any,
    Falsy,
    Truthy,
}

fn is_falsy(v: &str) -> bool {
    let v = v.trim();
    ["false", "no", "off", "0", ""]
        .iter()
        .any(|t| v.eq_ignore_ascii_case(t))
}

fn is_truthy(v: &str) -> bool {
    let v = v.trim();
    ["true", "yes", "on", "1"]
        .iter()
        .any(|t| v.eq_ignore_ascii_case(t))
}

fn bypass_value_matches(mode: BypassMatch, value: &str) -> bool {
    match mode {
        BypassMatch::Any => !value.trim().is_empty(),
        BypassMatch::Falsy => is_falsy(value),
        BypassMatch::Truthy => is_truthy(value),
    }
}

const NO_VERIFY_SUBCOMMANDS: &[&str] = &[
    "commit",
    "push",
    "merge",
    "rebase",
    "pull",
    "am",
    "cherry-pick",
    "revert",
    "fetch",
];

const NO_GPG_SIGN_SUBCOMMANDS: &[&str] = &[
    "commit",
    "merge",
    "rebase",
    "cherry-pick",
    "revert",
    "tag",
    "am",
    "pull",
];

const BYPASS_SCOPE_SUBCOMMANDS: &[&str] = &[
    "commit",
    "push",
    "merge",
    "rebase",
    "tag",
    "am",
    "cherry-pick",
    "revert",
    "pull",
];

const CONFIG_BYPASS_KEYS: &[(&str, BypassMatch)] = &[
    ("core.hookspath", BypassMatch::Any),
    ("commit.gpgsign", BypassMatch::Falsy),
    ("tag.gpgsign", BypassMatch::Falsy),
    ("merge.verifysignatures", BypassMatch::Falsy),
    ("transfer.fsckobjects", BypassMatch::Falsy),
    ("receive.fsckobjects", BypassMatch::Falsy),
    ("fetch.fsckobjects", BypassMatch::Falsy),
];

const ENV_BYPASS_KEYS: &[(&str, BypassMatch)] = &[
    ("HUSKY", BypassMatch::Falsy),
    ("LEFTHOOK", BypassMatch::Falsy),
    ("PRE_COMMIT_ALLOW_NO_CONFIG", BypassMatch::Truthy),
    ("SKIP", BypassMatch::Any),
    ("GIT_HOOK_SKIP", BypassMatch::Any),
    ("CORE_HOOKSPATH", BypassMatch::Any),
];

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

fn matches_no_verify(argv: &Argv) -> bool {
    let Some(sub) = git_subcommand(argv) else {
        return false;
    };
    if !NO_VERIFY_SUBCOMMANDS.contains(&sub) {
        return false;
    }
    let rest = args_after_subcommand(argv, sub);
    if rest.contains(&"--no-verify") {
        return true;
    }
    // `-n` only means no-verify on `git commit`. On `push`/`pull`/`merge`/
    // `rebase` it is `--dry-run` or `--no-stat`; on `tag` it sets the
    // displayed line count.
    if sub != "commit" {
        return false;
    }
    rest.iter().any(|a| {
        if !a.starts_with('-') || a.starts_with("--") {
            return false;
        }
        a[1..].contains('n')
    })
}

fn matches_no_gpg_sign(argv: &Argv) -> bool {
    let Some(sub) = git_subcommand(argv) else {
        return false;
    };
    if !NO_GPG_SIGN_SUBCOMMANDS.contains(&sub) {
        return false;
    }
    let rest = args_after_subcommand(argv, sub);
    rest.contains(&"--no-gpg-sign")
}

fn matches_config_override_bypass(argv: &Argv) -> bool {
    let Some(sub) = git_subcommand(argv) else {
        return false;
    };
    if !BYPASS_SCOPE_SUBCOMMANDS.contains(&sub) {
        return false;
    }
    for raw in config_overrides(argv) {
        let Some(eq) = raw.find('=') else {
            continue;
        };
        let key = raw[..eq].trim();
        let value = &raw[eq + 1..];
        for (target_key, mode) in CONFIG_BYPASS_KEYS {
            if key.eq_ignore_ascii_case(target_key) && bypass_value_matches(*mode, value) {
                return true;
            }
        }
    }
    false
}

fn matches_env_bypass(argv: &Argv) -> bool {
    let Some(sub) = git_subcommand(argv) else {
        return false;
    };
    if !BYPASS_SCOPE_SUBCOMMANDS.contains(&sub) {
        return false;
    }
    for ea in &argv.env_assignments {
        for (target, mode) in ENV_BYPASS_KEYS {
            if ea.key.eq_ignore_ascii_case(target) && bypass_value_matches(*mode, &ea.value) {
                return true;
            }
        }
    }
    false
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

const NO_VERIFY: RuleSpec = RuleSpec {
    id: "core.git.no-verify",
    severity: Severity::High,
    decision_kind: DecisionKind::Deny,
    hard_deny: false,
    matcher: matches_no_verify,
    problem: "git --no-verify (or `commit -n`) skips pre-commit, commit-msg, pre-push and \
         pre-rebase hooks, which are usually the project's first line of defence against \
         broken or unsigned commits.",
    alternatives: &[
        "Run the hooks once and fix the failures rather than bypassing them.",
        "If a hook is genuinely broken, fix it in the repo so the team benefits.",
        "If a hot-fix truly needs the bypass, allowlist this rule with an explicit expiresAt.",
    ],
};

const NO_GPG_SIGN: RuleSpec = RuleSpec {
    id: "core.git.no-gpg-sign",
    severity: Severity::Medium,
    decision_kind: DecisionKind::Deny,
    hard_deny: false,
    matcher: matches_no_gpg_sign,
    problem: "git --no-gpg-sign overrides a project- or user-level requirement to sign commits \
         and tags, producing artefacts that downstream verification will reject.",
    alternatives: &[
        "Make sure your signing key is configured (gpg.format / user.signingkey) and re-run.",
        "If signing is intentionally optional in this repo, drop commit.gpgsign from config rather than per-call --no-gpg-sign.",
    ],
};

const CONFIG_OVERRIDE_BYPASS: RuleSpec = RuleSpec {
    id: "core.git.config-override-bypass",
    severity: Severity::High,
    decision_kind: DecisionKind::Deny,
    hard_deny: false,
    matcher: matches_config_override_bypass,
    problem: "git -c <key>=<value> can disable hooks (core.hooksPath), turn off commit signing \
         (commit.gpgsign=false), or relax fsck checks for a single invocation, which is \
         almost always a bypass rather than a legitimate one-shot override.",
    alternatives: &[
        "Address the underlying check (fix the hook, install the signing key, etc.) instead.",
        "If the override is genuinely needed, set it in repo config explicitly so it is reviewable.",
        "Allowlist this rule with an expiry rather than embedding -c in scripts.",
    ],
};

const ENV_BYPASS: RuleSpec = RuleSpec {
    id: "core.git.env-bypass",
    severity: Severity::High,
    decision_kind: DecisionKind::Deny,
    hard_deny: false,
    matcher: matches_env_bypass,
    problem: "Inline environment assignments such as HUSKY=0, LEFTHOOK=0, or SKIP=<hook> in \
         front of a git command turn off the project's commit hooks for this single \
         invocation without leaving any trace in repo config.",
    alternatives: &[
        "Run the hooks and resolve the failures.",
        "If a hook is broken on your machine only, fix it locally instead of routinely setting HUSKY=0.",
        "Allowlist this rule with an expiry if a one-off bypass is genuinely warranted.",
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
pub static NO_VERIFY_RULE: GitRule = GitRule { spec: &NO_VERIFY };
pub static NO_GPG_SIGN_RULE: GitRule = GitRule { spec: &NO_GPG_SIGN };
pub static CONFIG_OVERRIDE_BYPASS_RULE: GitRule = GitRule {
    spec: &CONFIG_OVERRIDE_BYPASS,
};
pub static ENV_BYPASS_RULE: GitRule = GitRule { spec: &ENV_BYPASS };

#[cfg(test)]
mod tests {

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
            },
            (DecisionKind::Ask, Some(Decision::Ask { rule_id, .. })) => {
                assert_eq!(rule_id, rule.spec.id, "wrong rule_id for {cmd:?}")
            },
            (DecisionKind::Allow, None) => {},
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
    fn force_push_denies_via_sudo_user_option() {
        for cmd in [
            "sudo -u root git push --force origin main",
            "sudo -uroot git push --force origin main",
            "sudo --user root git push --force origin main",
            "sudo --user=root git push --force origin main",
            "sudo -E -u root -- git push --force origin main",
        ] {
            assert_decision(&FORCE_PUSH_RULE, cmd, DecisionKind::Deny);
        }
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
    fn clean_asks_split_short_flags() {
        assert_decision(&CLEAN_FDX_RULE, "git clean -f -d -x", DecisionKind::Ask);
        assert_decision(&CLEAN_FDX_RULE, "git clean -f -d -X", DecisionKind::Ask);
        assert_decision(
            &CLEAN_FDX_RULE,
            "git clean --force -d -x",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn clean_asks_when_exclude_pattern_contains_n() {
        assert_decision(
            &CLEAN_FDX_RULE,
            "git clean -fdx -enode_modules",
            DecisionKind::Ask,
        );
        assert_decision(
            &CLEAN_FDX_RULE,
            "git clean -fdx -e node_modules",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn clean_asks_via_sudo() {
        assert_decision(&CLEAN_FDX_RULE, "sudo git clean -fdx", DecisionKind::Ask);
    }

    #[test]
    fn clean_allows_dry_run() {
        assert_allow(&CLEAN_FDX_RULE, "git clean -ndx");
        assert_allow(&CLEAN_FDX_RULE, "git clean -nd");
        assert_allow(&CLEAN_FDX_RULE, "git clean -n -d -x");
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

    // --- no-verify ------------------------------------------------------

    #[test]
    fn no_verify_denies_long_flag_on_commit() {
        assert_decision(
            &NO_VERIFY_RULE,
            "git commit --no-verify -m fix",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn no_verify_denies_short_n_on_commit() {
        assert_decision(&NO_VERIFY_RULE, "git commit -n -m fix", DecisionKind::Deny);
    }

    #[test]
    fn no_verify_denies_short_cluster_with_n_on_commit() {
        assert_decision(&NO_VERIFY_RULE, "git commit -mn 'x'", DecisionKind::Deny);
    }

    #[test]
    fn no_verify_denies_amend_with_long_flag() {
        assert_decision(
            &NO_VERIFY_RULE,
            "git commit --amend --no-verify",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn no_verify_denies_on_push_long_flag() {
        assert_decision(
            &NO_VERIFY_RULE,
            "git push --no-verify origin main",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn no_verify_denies_on_merge_and_rebase() {
        assert_decision(
            &NO_VERIFY_RULE,
            "git merge --no-verify branch",
            DecisionKind::Deny,
        );
        assert_decision(
            &NO_VERIFY_RULE,
            "git rebase --no-verify main",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn no_verify_denies_via_sudo() {
        assert_decision(
            &NO_VERIFY_RULE,
            "sudo git commit --no-verify",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn no_verify_allows_push_dry_run_short_n() {
        assert_allow(&NO_VERIFY_RULE, "git push -n origin main");
    }

    #[test]
    fn no_verify_allows_tag_with_n_count() {
        assert_allow(&NO_VERIFY_RULE, "git tag -n10");
    }

    #[test]
    fn no_verify_allows_message_containing_phrase() {
        assert_allow(&NO_VERIFY_RULE, "git commit -m 'no-verify is great'");
    }

    #[test]
    fn no_verify_allows_safe_commit() {
        assert_allow(&NO_VERIFY_RULE, "git commit -m 'fix bug'");
    }

    #[test]
    fn no_verify_resolves_subcommand_after_global_dash_c() {
        // `-c key=val` must not be mistaken for the subcommand.
        assert_decision(
            &NO_VERIFY_RULE,
            "git -c color.ui=false commit --no-verify -m x",
            DecisionKind::Deny,
        );
    }

    // --- no-gpg-sign ----------------------------------------------------

    #[test]
    fn no_gpg_sign_denies_on_commit() {
        assert_decision(
            &NO_GPG_SIGN_RULE,
            "git commit --no-gpg-sign -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn no_gpg_sign_denies_on_tag() {
        assert_decision(
            &NO_GPG_SIGN_RULE,
            "git tag --no-gpg-sign v1.0",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn no_gpg_sign_denies_via_sudo() {
        assert_decision(
            &NO_GPG_SIGN_RULE,
            "sudo git commit --no-gpg-sign -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn no_gpg_sign_allows_safe_commit() {
        assert_allow(&NO_GPG_SIGN_RULE, "git commit -m x");
    }

    #[test]
    fn no_gpg_sign_allows_unrelated_subcommand() {
        assert_allow(&NO_GPG_SIGN_RULE, "git status");
    }

    // --- config-override-bypass -----------------------------------------

    #[test]
    fn config_override_denies_hookspath() {
        assert_decision(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "git -c core.hooksPath=/dev/null commit -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn config_override_denies_hookspath_via_long_form() {
        assert_decision(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "git --config=core.hooksPath=/dev/null commit -m x",
            DecisionKind::Deny,
        );
        assert_decision(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "git --config core.hooksPath=/dev/null commit",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn config_override_denies_commit_gpgsign_false() {
        assert_decision(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "git -c commit.gpgsign=false commit -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn config_override_denies_tag_gpgsign_zero() {
        assert_decision(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "git -c tag.gpgsign=0 tag v1",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn config_override_denies_quoted_with_spaces() {
        assert_decision(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "git -c 'core.hooksPath = /dev/null' commit -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn config_override_denies_uppercase_key() {
        assert_decision(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "git -c CORE.HOOKSPATH=/x commit -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn config_override_denies_via_sudo() {
        assert_decision(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "sudo git -c core.hooksPath=/dev/null commit -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn config_override_allows_harmless_keys() {
        assert_allow(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "git -c user.name=foo -c user.email=bar@example.com commit -m x",
        );
    }

    #[test]
    fn config_override_allows_truthy_gpgsign() {
        assert_allow(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "git -c commit.gpgsign=true commit -m x",
        );
    }

    #[test]
    fn config_override_allows_status_subcommand() {
        // scope-restricted: `status` has no hooks/signing impact.
        assert_allow(
            &CONFIG_OVERRIDE_BYPASS_RULE,
            "git -c core.hooksPath=/dev/null status",
        );
    }

    // --- env-bypass -----------------------------------------------------

    #[test]
    fn env_bypass_denies_husky_zero() {
        assert_decision(
            &ENV_BYPASS_RULE,
            "HUSKY=0 git commit -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn env_bypass_denies_lefthook_zero_on_push() {
        assert_decision(&ENV_BYPASS_RULE, "LEFTHOOK=0 git push", DecisionKind::Deny);
    }

    #[test]
    fn env_bypass_denies_pre_commit_allow_no_config() {
        assert_decision(
            &ENV_BYPASS_RULE,
            "PRE_COMMIT_ALLOW_NO_CONFIG=1 git commit -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn env_bypass_denies_skip_listed() {
        assert_decision(
            &ENV_BYPASS_RULE,
            "SKIP=eslint git commit -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn env_bypass_denies_multiple_envs() {
        assert_decision(
            &ENV_BYPASS_RULE,
            "HUSKY=0 LEFTHOOK=0 git commit -m x",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn env_bypass_allows_husky_truthy() {
        assert_allow(&ENV_BYPASS_RULE, "HUSKY=1 git commit -m x");
    }

    #[test]
    fn env_bypass_allows_unrelated_env() {
        assert_allow(&ENV_BYPASS_RULE, "PATH=/usr/bin git commit -m x");
        assert_allow(&ENV_BYPASS_RULE, "GIT_AUTHOR_NAME=foo git commit -m x");
    }

    #[test]
    fn env_bypass_allows_status_subcommand() {
        assert_allow(&ENV_BYPASS_RULE, "HUSKY=0 git status");
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

        for rule in [
            &NO_VERIFY_RULE,
            &CONFIG_OVERRIDE_BYPASS_RULE,
            &ENV_BYPASS_RULE,
        ] {
            assert!(!rule.hard_deny());
            assert_eq!(rule.severity(), Severity::High);
            assert_eq!(rule.default_decision(), DecisionKind::Deny);
        }

        assert!(!NO_GPG_SIGN_RULE.hard_deny());
        assert_eq!(NO_GPG_SIGN_RULE.severity(), Severity::Medium);
        assert_eq!(NO_GPG_SIGN_RULE.default_decision(), DecisionKind::Deny);
    }

    #[test]
    fn unwrap_sudo_with_only_flags_returns_none() {
        let argv = Argv {
            env_assignments: Vec::new(),
            head: "sudo".into(),
            args: vec!["-u".into(), "alice".into()],
            inner_argv: Vec::new(),
            inner_code: Vec::new(),
            inner_redirects: Vec::new(),
        };
        assert_eq!(unwrap_sudo(&argv), None);
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

    #[test]
    fn reset_hard_matches_inside_bash_dash_c() {
        let input = bash("bash -c 'git reset --hard HEAD~1'");
        let facts = crate::facts::extract(&input);
        assert!(matches!(
            RESET_HARD_RULE.evaluate(&facts, &input),
            Some(Decision::Ask { .. })
        ));
    }

    use crate::testing::proptest::{arbitrary_command, bash_command, non_bash_hook_input};
    use proptest::prelude::*;

    fn all_git_rules() -> [&'static GitRule; 11] {
        [
            &FORCE_PUSH_RULE,
            &FORCE_PUSH_WITH_LEASE_RULE,
            &RESET_HARD_RULE,
            &CLEAN_FDX_RULE,
            &BRANCH_DELETE_FORCE_RULE,
            &STASH_CLEAR_RULE,
            &REMOTE_SET_URL_RULE,
            &NO_VERIFY_RULE,
            &NO_GPG_SIGN_RULE,
            &CONFIG_OVERRIDE_BYPASS_RULE,
            &ENV_BYPASS_RULE,
        ]
    }

    proptest! {
        // None of the git rules ever fire on non-Bash tools, even when
        // the non-Bash payload sneakily carries a git-shaped command.
        #[test]
        fn pbt_git_rules_ignore_non_bash(input in non_bash_hook_input()) {
            let facts = crate::facts::extract(&input);
            for rule in all_git_rules() {
                prop_assert!(rule.evaluate(&facts, &input).is_none());
            }
        }

        // Adversarial: arbitrary bash strings must not panic any of the
        // matchers. The bash-facts layer already feeds `unwrap_sudo`.
        #[test]
        fn pbt_git_rules_never_panic_on_arbitrary_bash(cmd in arbitrary_command()) {
            let input = bash(&cmd);
            let facts = crate::facts::extract(&input);
            for rule in all_git_rules() {
                let _ = rule.evaluate(&facts, &input);
            }
        }

        // When a rule fires on a structured bash command, the resulting
        // decision's rule_id must exactly equal the static spec id, and
        // the decision shape must match `default_decision()`.
        #[test]
        fn pbt_git_rule_decision_shape_matches_spec(cmd in bash_command()) {
            let input = bash(&cmd);
            let facts = crate::facts::extract(&input);
            for rule in all_git_rules() {
                if let Some(d) = rule.evaluate(&facts, &input) {
                    prop_assert_eq!(d.rule_id(), Some(rule.spec.id));
                    let kind_matches = matches!(
                        (&d, rule.spec.decision_kind),
                        (Decision::Deny { .. }, DecisionKind::Deny)
                            | (Decision::Ask { .. }, DecisionKind::Ask)
                            | (Decision::Monitor { .. }, DecisionKind::Monitor)
                    );
                    prop_assert!(kind_matches, "decision shape mismatch: {d:?}");
                }
            }
        }

        // A bash command that has no `git` head anywhere can never fire
        // any of the git rules (the matchers all gate on
        // `is_git(head)`).
        #[test]
        fn pbt_no_git_head_no_fire(
            head in "[a-z][a-z0-9]{0,5}",
            args in proptest::collection::vec("[a-zA-Z0-9_./-]{1,8}", 0..3),
        ) {
            prop_assume!(!GIT_HEADS.contains(&head.as_str()) && head != "sudo");
            let cmd = if args.is_empty() {
                head
            } else {
                format!("{} {}", head, args.join(" "))
            };
            let input = bash(&cmd);
            let facts = crate::facts::extract(&input);
            for rule in all_git_rules() {
                prop_assert!(rule.evaluate(&facts, &input).is_none());
            }
        }

        // Force-push fires when `--force` appears, regardless of any
        // non-flag positional ref-spec arguments after it.
        #[test]
        fn pbt_force_push_fires_for_bare_force(
            extra in proptest::collection::vec("[a-zA-Z0-9_./]{1,8}", 0..3),
        ) {
            let cmd = format!("git push --force {}", extra.join(" "));
            let input = bash(&cmd);
            let facts = crate::facts::extract(&input);
            let force = FORCE_PUSH_RULE.evaluate(&facts, &input);
            let lease = FORCE_PUSH_WITH_LEASE_RULE.evaluate(&facts, &input);
            prop_assert!(force.is_some());
            prop_assert!(lease.is_none());
        }

        // Lease alone ⇒ lease fires, FORCE_PUSH does not — provided the
        // remaining arguments are non-flag positionals (a short-flag
        // cluster containing `f`, e.g. `-af`, legitimately counts as
        // `-f`/force).
        #[test]
        fn pbt_lease_alone_only_lease_fires(
            extra in proptest::collection::vec("[a-zA-Z0-9_./]{1,8}", 0..3),
        ) {
            let cmd = format!("git push --force-with-lease {}", extra.join(" "));
            let input = bash(&cmd);
            let facts = crate::facts::extract(&input);
            let force = FORCE_PUSH_RULE.evaluate(&facts, &input);
            let lease = FORCE_PUSH_WITH_LEASE_RULE.evaluate(&facts, &input);
            prop_assert!(force.is_none());
            prop_assert!(lease.is_some());
        }

        // `git push -n` is `--dry-run`, NOT `--no-verify`. The no-verify
        // rule must not fire as long as the rest of the args carry no
        // `--no-verify` literal (and no extra flag cluster contains `n`
        // accidentally — we only generate non-flag positionals to keep
        // this invariant tight).
        #[test]
        fn pbt_push_dry_run_never_fires_no_verify(
            extra in proptest::collection::vec("[a-zA-Z0-9_./]{1,8}", 0..3),
        ) {
            let cmd = format!("git push -n {}", extra.join(" "));
            let input = bash(&cmd);
            let facts = crate::facts::extract(&input);
            prop_assert!(NO_VERIFY_RULE.evaluate(&facts, &input).is_none());
        }

        // Random harmless `-c key=val` overrides (user.name / user.email
        // / color.ui …) must never trigger the config-override-bypass
        // rule, regardless of the count or order of the overrides.
        #[test]
        fn pbt_safe_config_keys_never_fire(
            keys in proptest::collection::vec(
                proptest::sample::select(
                    vec!["user.name", "user.email", "color.ui", "core.editor", "rerere.enabled"],
                ),
                0..4,
            ),
            value in "[a-zA-Z0-9._@/-]{1,12}",
        ) {
            let mut parts = vec!["git".to_string()];
            for k in &keys {
                parts.push("-c".to_string());
                parts.push(format!("{k}={value}"));
            }
            parts.push("commit".to_string());
            parts.push("-m".to_string());
            parts.push("ok".to_string());
            let cmd = parts.join(" ");
            let input = bash(&cmd);
            let facts = crate::facts::extract(&input);
            prop_assert!(CONFIG_OVERRIDE_BYPASS_RULE.evaluate(&facts, &input).is_none());
        }
    }
}
