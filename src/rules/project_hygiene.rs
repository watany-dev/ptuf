//! `core.project_hygiene` v1 — keep dev workflow consistent with the
//! repository's declared shape.
//!
//! Two rule families are covered for v1:
//!
//! * `lock-mismatch-pnpm` / `lock-mismatch-uv`: refuse package-manager
//!   commands whose lock file does not match the one checked into the
//!   repository (`pnpm-lock.yaml` ⇒ deny `npm install` / `yarn install`,
//!   `uv.lock` ⇒ deny `pip install`).
//! * `protected-branch-destructive-git`: when the current branch matches
//!   `Config.protected_branches`, deny destructive git operations that
//!   `core.git` would otherwise merely ask about (`reset --hard`,
//!   `clean -fdx`, `branch -D`, `stash clear`). The `aggregate`
//!   `deny > ask > monitor > allow` ordering means the project_hygiene
//!   deny wins on protected branches and the original ask remains the
//!   feedback elsewhere.
//!
//! The pack ships disabled by default — projects must opt in via
//! `packs.core.project_hygiene.enabled: true`. See
//! `docs/design/policy-packs.md`.

use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::facts::project::LockKind;
use crate::facts::shell::{Argv, unwrap_prefix_wrapper};
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;

const PNPM_RULE_ID: &str = "core.project_hygiene.lock-mismatch-pnpm";
const UV_RULE_ID: &str = "core.project_hygiene.lock-mismatch-uv";
const PROTECTED_GIT_RULE_ID: &str = "core.project_hygiene.protected-branch-destructive-git";

pub struct LockMismatchPnpm;
pub struct LockMismatchUv;
pub struct ProtectedBranchDestructiveGit;

impl ConfigRule for LockMismatchPnpm {
    fn id(&self) -> &str {
        PNPM_RULE_ID
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn default_decision(&self) -> DecisionKind {
        DecisionKind::Deny
    }

    fn evaluate(&self, facts: &Facts, _input: &HookInput) -> Option<Decision> {
        if !facts.project.lock_files.contains(&LockKind::PnpmLock) {
            return None;
        }
        let bash = facts.bash.as_ref()?;
        let triggered = bash.commands().into_iter().any(is_npm_or_yarn_install);
        if !triggered {
            return None;
        }
        let reason = reason::build(
            PNPM_RULE_ID,
            "This repository uses pnpm-lock.yaml. Running npm install or yarn install \
             would write a different lock file and create dependency drift.",
            &[
                "Use pnpm install (or pnpm add <pkg>) instead.",
                "Remove pnpm-lock.yaml first if the project is intentionally migrating.",
            ],
        );
        Some(Decision::Deny {
            rule_id: PNPM_RULE_ID.into(),
            reason,
        })
    }
}

impl ConfigRule for LockMismatchUv {
    fn id(&self) -> &str {
        UV_RULE_ID
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn default_decision(&self) -> DecisionKind {
        DecisionKind::Deny
    }

    fn evaluate(&self, facts: &Facts, _input: &HookInput) -> Option<Decision> {
        if !facts.project.lock_files.contains(&LockKind::UvLock) {
            return None;
        }
        let bash = facts.bash.as_ref()?;
        let triggered = bash.commands().into_iter().any(is_pip_install);
        if !triggered {
            return None;
        }
        let reason = reason::build(
            UV_RULE_ID,
            "This repository uses uv.lock. Running pip install would bypass the uv \
             resolver and desynchronise the lock file.",
            &[
                "Use uv pip install or uv add <pkg> instead.",
                "Remove uv.lock first if the project is intentionally migrating away from uv.",
            ],
        );
        Some(Decision::Deny {
            rule_id: UV_RULE_ID.into(),
            reason,
        })
    }
}

impl ConfigRule for ProtectedBranchDestructiveGit {
    fn id(&self) -> &str {
        PROTECTED_GIT_RULE_ID
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn default_decision(&self) -> DecisionKind {
        DecisionKind::Deny
    }

    fn evaluate(&self, facts: &Facts, _input: &HookInput) -> Option<Decision> {
        if !facts.project.on_protected_branch {
            return None;
        }
        let bash = facts.bash.as_ref()?;
        let triggered = bash.commands().into_iter().any(invokes_destructive_git);
        if !triggered {
            return None;
        }
        let branch = facts.project.current_branch.as_deref().unwrap_or("");
        let problem = format!(
            "Destructive git operations are not allowed on protected branch {branch:?}. \
             core.git would normally ask, but project_hygiene escalates to deny on \
             protected branches to prevent accidental history rewrites."
        );
        let reason = reason::build(
            PROTECTED_GIT_RULE_ID,
            &problem,
            &[
                "Switch to a feature branch (git switch -c <branch>) before running this.",
                "Open a pull request rather than rewriting protected branch history directly.",
                "If the operation is genuinely required, allowlist the rule with an expiry.",
            ],
        );
        Some(Decision::Deny {
            rule_id: PROTECTED_GIT_RULE_ID.into(),
            reason,
        })
    }
}

const NPM_HEADS: &[&str] = &["npm", "/usr/bin/npm", "/usr/local/bin/npm"];
const YARN_HEADS: &[&str] = &["yarn", "/usr/bin/yarn", "/usr/local/bin/yarn"];
const PIP_HEADS: &[&str] = &[
    "pip",
    "pip3",
    "/usr/bin/pip",
    "/usr/local/bin/pip",
    "/usr/bin/pip3",
    "/usr/local/bin/pip3",
];
const GIT_HEADS: &[&str] = &["git", "/usr/bin/git", "/usr/local/bin/git"];

fn is_npm_or_yarn_install(argv: &Argv) -> bool {
    if let Some(unwrapped) = unwrap_prefix_wrapper(argv) {
        return is_npm_or_yarn_install(&unwrapped);
    }
    let head = argv.head.as_str();
    if NPM_HEADS.contains(&head) {
        return is_install_subcommand(argv, &["install", "i", "ci", "add"]);
    }
    if YARN_HEADS.contains(&head) {
        // `yarn` with no subcommand defaults to `yarn install`.
        return matches!(
            first_positional(argv),
            None | Some("install" | "add" | "ci")
        );
    }
    false
}

fn is_pip_install(argv: &Argv) -> bool {
    if let Some(unwrapped) = unwrap_prefix_wrapper(argv) {
        return is_pip_install(&unwrapped);
    }
    if !PIP_HEADS.contains(&argv.head.as_str()) {
        return false;
    }
    is_install_subcommand(argv, &["install"])
}

fn invokes_destructive_git(argv: &Argv) -> bool {
    if let Some(unwrapped) = unwrap_prefix_wrapper(argv) {
        return invokes_destructive_git(&unwrapped);
    }
    if !GIT_HEADS.contains(&argv.head.as_str()) {
        return false;
    }
    let sub = match first_positional(argv) {
        Some(s) => s,
        None => return false,
    };
    let rest: Vec<&str> = argv
        .args
        .iter()
        .map(String::as_str)
        .skip_while(|a| *a != sub)
        .skip(1)
        .collect();
    match sub {
        "reset" => rest.contains(&"--hard"),
        "clean" => has_clean_fdx(&rest),
        "branch" => rest.iter().any(|a| {
            *a == "-D"
                || (a.starts_with('-') && !a.starts_with("--") && a.contains('D'))
                || *a == "--delete=force"
        }),
        "stash" => rest.contains(&"clear"),
        _ => false,
    }
}

fn has_clean_fdx(rest: &[&str]) -> bool {
    let mut has_force = false;
    let mut has_dir = false;
    let mut has_ignored = false;
    let mut has_dry_run = false;

    for arg in rest {
        if *arg == "--force" {
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

fn is_install_subcommand(argv: &Argv, accepted: &[&str]) -> bool {
    match first_positional(argv) {
        Some(sub) => accepted.contains(&sub),
        None => false,
    }
}

fn first_positional(argv: &Argv) -> Option<&str> {
    argv.args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::facts::project::ProjectFacts;
    use crate::hook_input::HookInput;

    fn bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": cmd }),
        }
    }

    fn facts_with_project(input: &HookInput, project: ProjectFacts) -> Facts {
        let mut f = crate::facts::extract(input);
        f.project = project;
        f
    }

    fn pnpm_project() -> ProjectFacts {
        ProjectFacts {
            lock_files: vec![LockKind::PnpmLock],
            ..Default::default()
        }
    }

    fn uv_project() -> ProjectFacts {
        ProjectFacts {
            lock_files: vec![LockKind::UvLock],
            ..Default::default()
        }
    }

    fn protected_branch() -> ProjectFacts {
        ProjectFacts {
            current_branch: Some("main".into()),
            on_protected_branch: true,
            ..Default::default()
        }
    }

    // --- lock-mismatch-pnpm --------------------------------------------

    #[test]
    fn pnpm_denies_npm_install_when_pnpm_lock_present() {
        let input = bash("npm install lodash");
        let facts = facts_with_project(&input, pnpm_project());
        let result = LockMismatchPnpm.evaluate(&facts, &input);
        assert!(matches!(result, Some(Decision::Deny { .. })));
    }

    #[test]
    fn pnpm_denies_yarn_install_when_pnpm_lock_present() {
        for cmd in ["yarn install", "yarn", "yarn add lodash"] {
            let input = bash(cmd);
            let facts = facts_with_project(&input, pnpm_project());
            let result = LockMismatchPnpm.evaluate(&facts, &input);
            assert!(
                matches!(result, Some(Decision::Deny { .. })),
                "expected deny for {cmd:?}"
            );
        }
    }

    #[test]
    fn pnpm_denies_npm_ci_when_pnpm_lock_present() {
        let input = bash("npm ci");
        let facts = facts_with_project(&input, pnpm_project());
        let result = LockMismatchPnpm.evaluate(&facts, &input);
        assert!(matches!(result, Some(Decision::Deny { .. })));
    }

    #[test]
    fn pnpm_allows_npm_install_when_no_pnpm_lock() {
        let input = bash("npm install");
        let facts = facts_with_project(&input, ProjectFacts::default());
        assert!(LockMismatchPnpm.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn pnpm_allows_pnpm_install_even_with_pnpm_lock() {
        let input = bash("pnpm install");
        let facts = facts_with_project(&input, pnpm_project());
        assert!(LockMismatchPnpm.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn pnpm_allows_npm_run_command() {
        let input = bash("npm run build");
        let facts = facts_with_project(&input, pnpm_project());
        assert!(LockMismatchPnpm.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn pnpm_denies_via_sudo_wrapper() {
        let input = bash("sudo npm install");
        let facts = facts_with_project(&input, pnpm_project());
        assert!(matches!(
            LockMismatchPnpm.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
    }

    // --- lock-mismatch-uv ----------------------------------------------

    #[test]
    fn uv_denies_pip_install_when_uv_lock_present() {
        let input = bash("pip install requests");
        let facts = facts_with_project(&input, uv_project());
        let result = LockMismatchUv.evaluate(&facts, &input);
        assert!(matches!(result, Some(Decision::Deny { .. })));
    }

    #[test]
    fn uv_denies_pip3_install_when_uv_lock_present() {
        let input = bash("pip3 install requests");
        let facts = facts_with_project(&input, uv_project());
        assert!(matches!(
            LockMismatchUv.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn uv_allows_pip_install_when_no_uv_lock() {
        let input = bash("pip install requests");
        let facts = facts_with_project(&input, ProjectFacts::default());
        assert!(LockMismatchUv.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn uv_allows_uv_pip_install_even_with_uv_lock() {
        let input = bash("uv pip install requests");
        let facts = facts_with_project(&input, uv_project());
        assert!(LockMismatchUv.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn uv_allows_pip_uninstall() {
        let input = bash("pip uninstall requests");
        let facts = facts_with_project(&input, uv_project());
        assert!(LockMismatchUv.evaluate(&facts, &input).is_none());
    }

    // --- protected-branch-destructive-git -------------------------------

    #[test]
    fn protected_git_denies_reset_hard_on_protected_branch() {
        let input = bash("git reset --hard HEAD~1");
        let facts = facts_with_project(&input, protected_branch());
        let result = ProtectedBranchDestructiveGit.evaluate(&facts, &input);
        assert!(
            matches!(result, Some(Decision::Deny { rule_id, .. }) if rule_id == PROTECTED_GIT_RULE_ID)
        );
    }

    #[test]
    fn protected_git_denies_reset_hard_via_sudo_user_option() {
        let input = bash("sudo -u root git reset --hard HEAD~1");
        let facts = facts_with_project(&input, protected_branch());
        assert!(matches!(
            ProtectedBranchDestructiveGit.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn protected_git_denies_branch_force_delete_on_protected_branch() {
        let input = bash("git branch -D feature");
        let facts = facts_with_project(&input, protected_branch());
        assert!(matches!(
            ProtectedBranchDestructiveGit.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn protected_git_denies_stash_clear_on_protected_branch() {
        let input = bash("git stash clear");
        let facts = facts_with_project(&input, protected_branch());
        assert!(matches!(
            ProtectedBranchDestructiveGit.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn protected_git_allows_when_branch_is_not_protected() {
        let input = bash("git reset --hard HEAD~1");
        let facts = facts_with_project(&input, ProjectFacts::default());
        assert!(
            ProtectedBranchDestructiveGit
                .evaluate(&facts, &input)
                .is_none()
        );
    }

    #[test]
    fn protected_git_allows_safe_git_commands_on_protected_branch() {
        for cmd in [
            "git status",
            "git log",
            "git push origin main",
            "git reset --soft HEAD~1",
            "git branch -d feature",
        ] {
            let input = bash(cmd);
            let facts = facts_with_project(&input, protected_branch());
            assert!(
                ProtectedBranchDestructiveGit
                    .evaluate(&facts, &input)
                    .is_none(),
                "expected allow for {cmd:?}"
            );
        }
    }

    #[test]
    fn protected_git_denies_via_sudo() {
        let input = bash("sudo git reset --hard HEAD");
        let facts = facts_with_project(&input, protected_branch());
        assert!(matches!(
            ProtectedBranchDestructiveGit.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn protected_git_ignores_non_bash_tools() {
        let input = HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({ "command": "git reset --hard" }),
        };
        let facts = facts_with_project(&input, protected_branch());
        assert!(
            ProtectedBranchDestructiveGit
                .evaluate(&facts, &input)
                .is_none()
        );
    }

    // --- metadata invariants -------------------------------------------

    #[test]
    fn rules_default_to_high_severity_deny_overridable() {
        for rule in [
            &LockMismatchPnpm as &dyn ConfigRule,
            &LockMismatchUv as &dyn ConfigRule,
            &ProtectedBranchDestructiveGit as &dyn ConfigRule,
        ] {
            assert_eq!(rule.severity(), Severity::High);
            assert_eq!(rule.default_decision(), DecisionKind::Deny);
            assert!(rule.overridable());
            assert!(!rule.hard_deny());
        }
    }

    // --- private helper coverage ---------------------------------------

    #[test]
    fn uv_denies_pip_install_via_sudo_wrapper() {
        let input = bash("sudo pip install requests");
        let facts = facts_with_project(&input, uv_project());
        let result = LockMismatchUv.evaluate(&facts, &input);
        assert!(matches!(result, Some(Decision::Deny { .. })));
    }

    #[test]
    fn protected_branch_rule_does_not_fire_for_non_git_command() {
        let input = bash("rm somefile");
        let facts = facts_with_project(&input, protected_branch());
        assert!(
            ProtectedBranchDestructiveGit
                .evaluate(&facts, &input)
                .is_none()
        );
    }

    #[test]
    fn protected_branch_rule_does_not_fire_for_git_with_no_subcommand() {
        // `git` (just the bin) has no positional → first_positional()
        // returns None and `invokes_destructive_git` short-circuits.
        let input = bash("git");
        let facts = facts_with_project(&input, protected_branch());
        assert!(
            ProtectedBranchDestructiveGit
                .evaluate(&facts, &input)
                .is_none()
        );
    }

    #[test]
    fn protected_branch_rule_fires_for_git_clean_with_long_force_flag() {
        // `git clean --force -dx` exercises the `--force` long-flag arm
        // of `has_clean_fdx` (the short-flag cluster path is covered
        // separately by `clean_fdx_*` tests in `rules/git.rs`).
        let input = bash("git clean --force -dx");
        let facts = facts_with_project(&input, protected_branch());
        assert!(matches!(
            ProtectedBranchDestructiveGit.evaluate(&facts, &input),
            Some(Decision::Deny { .. }),
        ));
    }

    #[test]
    fn pnpm_does_not_fire_for_npm_with_no_subcommand() {
        // `npm` alone (no positional) → is_install_subcommand returns
        // false via the `None => false` arm.
        let input = bash("npm");
        let facts = facts_with_project(&input, pnpm_project());
        assert!(LockMismatchPnpm.evaluate(&facts, &input).is_none());
    }

    // --- PBT (minimal) -------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        // No protected branch ⇒ protected-branch rule never fires.
        #[test]
        fn pbt_protected_rule_silent_off_protected_branch(
            cmd in proptest::string::string_regex("git [a-z ]{0,40}").expect("regex"),
        ) {
            let input = bash(&cmd);
            let facts = facts_with_project(&input, ProjectFacts::default());
            prop_assert!(
                ProtectedBranchDestructiveGit
                    .evaluate(&facts, &input)
                    .is_none()
            );
        }

        // No lock files detected ⇒ lock-mismatch rules never fire.
        #[test]
        fn pbt_lock_rules_silent_when_no_lock(
            cmd in proptest::string::string_regex("(npm|yarn|pip|pip3) [a-z ]{0,40}").expect("regex"),
        ) {
            let input = bash(&cmd);
            let facts = facts_with_project(&input, ProjectFacts::default());
            prop_assert!(LockMismatchPnpm.evaluate(&facts, &input).is_none());
            prop_assert!(LockMismatchUv.evaluate(&facts, &input).is_none());
        }
    }
}
