//! `core.git` pack — guards against destructive git operations.
//!
//! Covers force-push variants, history rewrites, hook / signing / credential
//! bypasses, and env-var redirection. The authoritative rule list lives in
//! `docs/design/policy-packs.md`. Each rule shares the [`GitRule`] adapter
//! so the [`crate::rules::ConfigRule`] trait is implemented exactly once.

use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::facts::shell::{Argv, unwrap_prefix_wrapper};
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;

mod argv;
mod branch;
mod bypass;
mod clean;
mod env_redirect;
mod history;
mod push;
mod remote;
mod reset;
mod stash;

pub use branch::BRANCH_DELETE_FORCE_RULE;
pub use bypass::{CONFIG_OVERRIDE_BYPASS_RULE, ENV_BYPASS_RULE, NO_GPG_SIGN_RULE, NO_VERIFY_RULE};
pub use clean::CLEAN_FDX_RULE;
pub use env_redirect::{ENV_CREDENTIAL_HIJACK_RULE, ENV_PATH_REDIRECT_RULE};
pub use history::{GC_PRUNE_NOW_RULE, REFLOG_EXPIRE_RULE, UPDATE_REF_DELETE_RULE};
pub use push::{
    FORCE_IF_INCLUDES_RULE, FORCE_PUSH_RULE, FORCE_PUSH_WITH_LEASE_RULE, PUSH_DELETE_REMOTE_RULE,
    PUSH_MIRROR_RULE,
};
pub use remote::REMOTE_SET_URL_RULE;
pub use reset::RESET_HARD_RULE;
pub use stash::STASH_CLEAR_RULE;

/// Per-rule wiring: matcher predicate + decision shape + reason text.
///
/// `matcher` returns `true` when the supplied git invocation triggers
/// the rule. The Bash facts layer feeds every command (and every
/// `sudo`-unwrapped command) through `matcher` in
/// [`GitRule::evaluate`].
pub(super) struct RuleSpec {
    pub(super) id: &'static str,
    pub(super) severity: Severity,
    pub(super) decision_kind: DecisionKind,
    pub(super) hard_deny: bool,
    pub(super) matcher: fn(&Argv) -> bool,
    pub(super) problem: &'static str,
    pub(super) alternatives: &'static [&'static str],
}

pub struct GitRule {
    pub(super) spec: &'static RuleSpec,
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

/// Run `matcher` against `argv` directly; if `argv` is a privilege
/// wrapper such as `sudo git ...` — including nested forms like
/// `sudo doas git ...` — peel the wrappers one layer at a time and retry.
fn invokes_matcher(argv: &Argv, matcher: fn(&Argv) -> bool) -> bool {
    if matcher(argv) {
        return true;
    }
    let mut current = unwrap_prefix_wrapper(argv);
    while let Some(inner) = current {
        if matcher(&inner) {
            return true;
        }
        current = unwrap_prefix_wrapper(&inner);
    }
    false
}

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
    fn force_push_denies_via_nested_and_other_wrappers() {
        for cmd in [
            "doas git push --force origin main",
            "pkexec git push --force origin main",
            "run0 git push --force origin main",
            // nested prefix wrappers are peeled one layer at a time
            "sudo doas git push --force origin main",
            // `su -c` surfaces the inner git command via inner_argv
            "su -c 'git push --force origin main'",
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
    fn clean_asks_fdx_flag_variants() {
        for cmd in [
            "git clean -fdx",
            "git clean -fdX",
            "git clean -xfd",
            "git clean -f -d -x",
            "git clean -f -d -X",
            "git clean --force -d -x",
            "git clean -fdx -enode_modules",
            "git clean -fdx -e node_modules",
        ] {
            assert_decision(&CLEAN_FDX_RULE, cmd, DecisionKind::Ask);
        }
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
            &PUSH_MIRROR_RULE,
            &PUSH_DELETE_REMOTE_RULE,
            &FORCE_IF_INCLUDES_RULE,
            &UPDATE_REF_DELETE_RULE,
            &REFLOG_EXPIRE_RULE,
        ] {
            assert!(!rule.hard_deny());
            assert_eq!(rule.severity(), Severity::High);
            assert_eq!(rule.default_decision(), DecisionKind::Ask);
        }

        for rule in [&STASH_CLEAR_RULE, &REMOTE_SET_URL_RULE, &GC_PRUNE_NOW_RULE] {
            assert!(!rule.hard_deny());
            assert_eq!(rule.severity(), Severity::Medium);
            assert_eq!(rule.default_decision(), DecisionKind::Ask);
        }

        for rule in [
            &NO_VERIFY_RULE,
            &CONFIG_OVERRIDE_BYPASS_RULE,
            &ENV_BYPASS_RULE,
            &ENV_CREDENTIAL_HIJACK_RULE,
            &ENV_PATH_REDIRECT_RULE,
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
    fn unwrap_prefix_wrapper_with_only_flags_returns_none() {
        let argv = Argv {
            env_assignments: Vec::new(),
            head: "sudo".into(),
            args: vec!["-u".into(), "alice".into()],
            inner_argv: Vec::new(),
            inner_code: Vec::new(),
            inner_redirects: Vec::new(),
            subst_argv: Vec::new(),
        };
        assert_eq!(unwrap_prefix_wrapper(&argv), None);
    }

    #[test]
    fn rules_handle_full_path_to_git() {
        // Any invocation path must match on basename, not only the
        // hand-enumerated system installs.
        for cmd in [
            "/usr/bin/git push --force origin main",
            "/opt/homebrew/bin/git push --force origin main",
            "./git push --force origin main",
        ] {
            let input = bash(cmd);
            let facts = crate::facts::extract(&input);
            assert!(
                matches!(
                    FORCE_PUSH_RULE.evaluate(&facts, &input),
                    Some(Decision::Deny { .. })
                ),
                "expected deny for {cmd:?}",
            );
        }
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

    fn all_git_rules() -> [&'static GitRule; 19] {
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
            &PUSH_MIRROR_RULE,
            &PUSH_DELETE_REMOTE_RULE,
            &FORCE_IF_INCLUDES_RULE,
            &UPDATE_REF_DELETE_RULE,
            &REFLOG_EXPIRE_RULE,
            &GC_PRUNE_NOW_RULE,
            &ENV_CREDENTIAL_HIJACK_RULE,
            &ENV_PATH_REDIRECT_RULE,
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
        // matchers. The bash-facts layer already feeds
        // `unwrap_prefix_wrapper`.
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
            prop_assume!(!argv::GIT_HEADS.contains(&head.as_str()) && head != "sudo");
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

    // The static rule slice only uses Deny / Ask, so the Monitor and
    // Allow arms in `evaluate()` and the `-c`-with-no-value arm of
    // `config_overrides` are otherwise unreachable. Synthetic specs
    // exercise them without affecting any production behavior.
    static MONITOR_FORCE_PUSH_SPEC: RuleSpec = RuleSpec {
        id: "test.git.monitor",
        severity: Severity::Low,
        decision_kind: DecisionKind::Monitor,
        hard_deny: false,
        matcher: super::push::matches_force_push,
        problem: "synthetic monitor spec",
        alternatives: &[],
    };
    static ALLOW_FORCE_PUSH_SPEC: RuleSpec = RuleSpec {
        id: "test.git.allow",
        severity: Severity::Low,
        decision_kind: DecisionKind::Allow,
        hard_deny: false,
        matcher: super::push::matches_force_push,
        problem: "synthetic allow spec",
        alternatives: &[],
    };

    #[test]
    fn evaluate_emits_monitor_when_decision_kind_is_monitor() {
        let rule = GitRule {
            spec: &MONITOR_FORCE_PUSH_SPEC,
        };
        let input = bash("git push --force origin main");
        let facts = crate::facts::extract(&input);
        match rule.evaluate(&facts, &input) {
            Some(Decision::Monitor { rule_id }) => assert_eq!(rule_id, "test.git.monitor"),
            other => panic!("expected Monitor, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_returns_none_when_decision_kind_is_allow() {
        let rule = GitRule {
            spec: &ALLOW_FORCE_PUSH_SPEC,
        };
        let input = bash("git push --force origin main");
        let facts = crate::facts::extract(&input);
        assert!(rule.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn config_overrides_skip_dangling_dash_c_with_no_value() {
        // `git -c` with no following value would normally be rejected
        // by git itself, but the override iterator's loop must still
        // terminate cleanly when `iter.next()` returns None.
        let input = bash("git -c commit");
        let facts = crate::facts::extract(&input);
        // CONFIG_OVERRIDE_BYPASS_RULE inspects the override list; just
        // confirming evaluate doesn't panic exercises the `iter.next()
        // returned None` arm of `config_overrides`.
        let _ = CONFIG_OVERRIDE_BYPASS_RULE.evaluate(&facts, &input);
    }

    // --- force-push +refspec extension ----------------------------------

    #[test]
    fn force_push_denies_plus_refspec() {
        for cmd in [
            "git push origin +main:main",
            "git push origin +main",
            "git push origin +refs/heads/foo:refs/heads/foo",
            "git push o +a:b +c:d",
        ] {
            assert_decision(&FORCE_PUSH_RULE, cmd, DecisionKind::Deny);
        }
    }

    #[test]
    fn force_push_plus_refspec_via_sudo() {
        assert_decision(
            &FORCE_PUSH_RULE,
            "sudo git push origin +main:main",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn force_push_does_not_fire_on_bare_plus() {
        // A bare `+` is not a refspec; only `+name` matters.
        assert_allow(&FORCE_PUSH_RULE, "git push origin +");
    }

    // --- push-mirror ----------------------------------------------------

    #[test]
    fn push_mirror_asks_long_flag() {
        assert_decision(&PUSH_MIRROR_RULE, "git push --mirror", DecisionKind::Ask);
        assert_decision(
            &PUSH_MIRROR_RULE,
            "git push --mirror origin",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn push_mirror_allows_safe_push() {
        assert_allow(&PUSH_MIRROR_RULE, "git push origin main");
        assert_allow(&PUSH_MIRROR_RULE, "git push --tags origin");
    }

    #[test]
    fn push_mirror_via_sudo() {
        assert_decision(
            &PUSH_MIRROR_RULE,
            "sudo git push --mirror origin",
            DecisionKind::Ask,
        );
    }

    // --- push-delete-remote ---------------------------------------------

    #[test]
    fn push_delete_asks_long_flag() {
        assert_decision(
            &PUSH_DELETE_REMOTE_RULE,
            "git push --delete origin foo",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn push_delete_asks_short_flag() {
        assert_decision(
            &PUSH_DELETE_REMOTE_RULE,
            "git push -d origin foo",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn push_delete_asks_colon_refspec() {
        assert_decision(
            &PUSH_DELETE_REMOTE_RULE,
            "git push origin :foo",
            DecisionKind::Ask,
        );
        assert_decision(
            &PUSH_DELETE_REMOTE_RULE,
            "git push origin :refs/heads/foo",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn push_delete_allows_normal_push() {
        assert_allow(&PUSH_DELETE_REMOTE_RULE, "git push origin main");
        assert_allow(&PUSH_DELETE_REMOTE_RULE, "git push origin main:main");
    }

    // --- force-if-includes ----------------------------------------------

    #[test]
    fn force_if_includes_asks_long_flag() {
        assert_decision(
            &FORCE_IF_INCLUDES_RULE,
            "git push --force-if-includes",
            DecisionKind::Ask,
        );
        assert_decision(
            &FORCE_IF_INCLUDES_RULE,
            "git push --force-if-includes origin main",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn force_if_includes_does_not_fire_for_lease_or_force() {
        assert_allow(
            &FORCE_IF_INCLUDES_RULE,
            "git push --force-with-lease origin main",
        );
        assert_allow(&FORCE_IF_INCLUDES_RULE, "git push --force origin main");
        assert_allow(&FORCE_IF_INCLUDES_RULE, "git push origin main");
    }

    // --- update-ref-delete ----------------------------------------------

    #[test]
    fn update_ref_delete_asks_dash_d() {
        assert_decision(
            &UPDATE_REF_DELETE_RULE,
            "git update-ref -d refs/heads/foo",
            DecisionKind::Ask,
        );
        assert_decision(
            &UPDATE_REF_DELETE_RULE,
            "git update-ref --delete refs/heads/foo",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn update_ref_delete_allows_create_or_update() {
        assert_allow(
            &UPDATE_REF_DELETE_RULE,
            "git update-ref refs/heads/foo HEAD",
        );
        assert_allow(&UPDATE_REF_DELETE_RULE, "git update-ref --stdin");
    }

    // --- reflog-expire --------------------------------------------------

    #[test]
    fn reflog_expire_asks_expire_now() {
        for cmd in [
            "git reflog expire --expire=now --all",
            "git reflog expire --expire=0 --all",
            "git reflog expire --expire-unreachable=now --all",
        ] {
            assert_decision(&REFLOG_EXPIRE_RULE, cmd, DecisionKind::Ask);
        }
    }

    #[test]
    fn reflog_expire_asks_delete_subcommand() {
        assert_decision(
            &REFLOG_EXPIRE_RULE,
            "git reflog delete HEAD@{0}",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn reflog_expire_allows_read_only_ops() {
        assert_allow(&REFLOG_EXPIRE_RULE, "git reflog show --all");
        assert_allow(&REFLOG_EXPIRE_RULE, "git reflog");
        assert_allow(
            &REFLOG_EXPIRE_RULE,
            "git reflog expire --expire=2.weeks.ago",
        );
    }

    // --- gc-prune-now ---------------------------------------------------

    #[test]
    fn gc_prune_now_asks() {
        assert_decision(&GC_PRUNE_NOW_RULE, "git gc --prune=now", DecisionKind::Ask);
        assert_decision(&GC_PRUNE_NOW_RULE, "git gc --prune=all", DecisionKind::Ask);
        assert_decision(
            &GC_PRUNE_NOW_RULE,
            "git gc --aggressive --prune=now",
            DecisionKind::Ask,
        );
    }

    #[test]
    fn gc_prune_now_allows_safe_gc() {
        assert_allow(&GC_PRUNE_NOW_RULE, "git gc");
        assert_allow(&GC_PRUNE_NOW_RULE, "git gc --auto");
        assert_allow(&GC_PRUNE_NOW_RULE, "git gc --prune=2.weeks.ago");
    }

    // --- env-credential-hijack ------------------------------------------

    #[test]
    fn env_credential_hijack_denies_ssh_command_on_push() {
        assert_decision(
            &ENV_CREDENTIAL_HIJACK_RULE,
            "GIT_SSH_COMMAND='ssh -i /tmp/k' git push origin main",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn env_credential_hijack_denies_askpass_on_fetch() {
        assert_decision(
            &ENV_CREDENTIAL_HIJACK_RULE,
            "GIT_ASKPASS=/tmp/x git fetch origin",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn env_credential_hijack_denies_on_clone_and_ls_remote() {
        assert_decision(
            &ENV_CREDENTIAL_HIJACK_RULE,
            "GIT_SSH_COMMAND=x git clone git@example.com:foo/bar.git",
            DecisionKind::Deny,
        );
        assert_decision(
            &ENV_CREDENTIAL_HIJACK_RULE,
            "GIT_SSH=x git ls-remote origin",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn env_credential_hijack_silent_outside_network_scope() {
        // `git status` is not a network op; the env var should not fire.
        assert_allow(&ENV_CREDENTIAL_HIJACK_RULE, "GIT_SSH_COMMAND=x git status");
        assert_allow(&ENV_CREDENTIAL_HIJACK_RULE, "git push origin main");
    }

    // --- env-path-redirect ----------------------------------------------

    #[test]
    fn env_path_redirect_denies_git_dir() {
        assert_decision(
            &ENV_PATH_REDIRECT_RULE,
            "GIT_DIR=/tmp/x git log",
            DecisionKind::Deny,
        );
    }

    #[test]
    fn env_path_redirect_denies_config_overrides() {
        for cmd in [
            "GIT_CONFIG=/tmp/c git commit -m foo",
            "GIT_CONFIG_GLOBAL=/tmp/c git commit -m foo",
            "GIT_CONFIG_SYSTEM=/tmp/c git push",
            "GIT_WORK_TREE=/tmp/w git status",
            "GIT_OBJECT_DIRECTORY=/tmp/o git fsck",
            "GIT_INDEX_FILE=/tmp/i git diff",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES=/tmp/a git log",
        ] {
            assert_decision(&ENV_PATH_REDIRECT_RULE, cmd, DecisionKind::Deny);
        }
    }

    #[test]
    fn env_path_redirect_allows_unrelated_env() {
        assert_allow(&ENV_PATH_REDIRECT_RULE, "SOMETHING=1 git log");
        assert_allow(&ENV_PATH_REDIRECT_RULE, "git log");
    }

    #[test]
    fn env_path_redirect_silent_on_non_git_head() {
        // The redirect rule keys off git_subcommand(), so a non-git head
        // (even with the same env var) should not fire.
        assert_allow(&ENV_PATH_REDIRECT_RULE, "GIT_DIR=/tmp/x ls");
    }
}
