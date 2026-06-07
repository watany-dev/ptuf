use crate::decision::{Decision, Severity};
use crate::facts::Facts;
use crate::facts::shell::{Argv, unwrap_privilege_wrapper};
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;

pub struct DestructiveRm;

const RULE_ID: &str = "core.filesystem.destructive-rm";

const RM_HEADS: &[&str] = &["rm", "/bin/rm", "/usr/bin/rm"];

const SYSTEM_ROOTS: &[&str] = &[
    "/etc", "/usr", "/var", "/bin", "/boot", "/lib", "/lib32", "/lib64", "/sbin", "/opt", "/root",
    "/sys", "/proc",
];

const HOME_TARGETS: &[&str] = &["~", "~/", "$HOME", "$HOME/", "${HOME}", "${HOME}/"];

impl ConfigRule for DestructiveRm {
    fn id(&self) -> &str {
        RULE_ID
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn hard_deny(&self) -> bool {
        true
    }

    fn evaluate(&self, facts: &Facts, _input: &HookInput) -> Option<Decision> {
        let bash = facts.bash.as_ref()?;
        let triggered = bash
            .commands()
            .into_iter()
            .any(is_destructive_rm_invocation);
        if !triggered {
            return None;
        }

        let reason = reason::build(
            RULE_ID,
            "The command recursively force-deletes a system, home, or root path. \
             This operation is unrecoverable and would destroy critical data.",
            &[
                "Target only specific subdirectories you intend to remove.",
                "Use a relative path scoped to the project tree.",
                "Ask the user to confirm before any recursive deletion.",
            ],
        );

        Some(Decision::Deny {
            rule_id: RULE_ID.into(),
            reason,
        })
    }
}

fn is_destructive_rm_invocation(argv: &Argv) -> bool {
    if let Some(inner) = unwrap_privilege_wrapper(argv) {
        return is_destructive_rm_invocation(&inner);
    }
    is_rm_head(&argv.head)
        && has_recursive_force_flag(argv)
        && argv.positional().any(is_destructive_target)
}

fn is_rm_head(head: &str) -> bool {
    RM_HEADS.contains(&head)
}

fn has_recursive_force_flag(argv: &Argv) -> bool {
    let flags: Vec<&str> = argv.flags().collect();
    has_recursive(&flags) && has_force(&flags)
}

fn has_recursive(flags: &[&str]) -> bool {
    flags.iter().any(|flag| {
        if *flag == "--recursive" {
            return true;
        }
        if flag.starts_with("--") {
            return false;
        }
        flag[1..].chars().any(|c| c == 'r' || c == 'R')
    })
}

fn has_force(flags: &[&str]) -> bool {
    flags.iter().any(|flag| {
        if *flag == "--force" {
            return true;
        }
        if flag.starts_with("--") {
            return false;
        }
        flag[1..].contains('f')
    })
}

fn is_destructive_target(arg: &str) -> bool {
    arg == "/"
        || arg == "/*"
        || HOME_TARGETS.contains(&arg)
        || SYSTEM_ROOTS
            .iter()
            .any(|root| arg == *root || arg.starts_with(&format!("{root}/")))
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

    fn assert_deny(cmd: &str) {
        let input = bash(cmd);
        let facts = crate::facts::extract(&input);
        let result = DestructiveRm.evaluate(&facts, &input);
        assert!(
            matches!(&result, Some(Decision::Deny { rule_id, .. }) if rule_id == RULE_ID),
            "expected deny for {cmd:?}, got {result:?}",
        );
    }

    fn assert_allow(cmd: &str) {
        let input = bash(cmd);
        let facts = crate::facts::extract(&input);
        let result = DestructiveRm.evaluate(&facts, &input);
        assert!(
            result.is_none(),
            "expected allow for {cmd:?}, got {result:?}"
        );
    }

    #[test]
    fn trait_metadata_is_stable() {
        let r = DestructiveRm;
        assert_eq!(r.id(), RULE_ID);
        assert_eq!(r.severity(), Severity::Critical);
        assert!(r.hard_deny());
    }

    #[test]
    fn denies_rm_rf_root() {
        assert_deny("rm -rf /");
    }

    #[test]
    fn denies_bash_dash_c_wrapped_rm() {
        assert_deny("bash -c 'rm -rf /'");
    }

    #[test]
    fn denies_find_exec_wrapped_rm() {
        assert_deny(r"find . -name tmp -exec rm -rf / \;");
    }

    #[test]
    fn denies_rm_rf_home_tilde() {
        assert_deny("rm -rf ~");
        assert_deny("rm -rf ~/");
    }

    #[test]
    fn denies_rm_rf_home_envvar() {
        assert_deny("rm -rf $HOME");
        assert_deny("rm -rf ${HOME}");
        assert_deny(r#"rm -rf "${HOME}""#);
        assert_deny("rm -rf '$HOME'");
    }

    #[test]
    fn denies_rm_rf_root_glob() {
        assert_deny("rm -rf /*");
    }

    #[test]
    fn denies_rm_rf_system_paths() {
        for path in [
            "/etc", "/usr", "/var", "/bin", "/boot", "/lib", "/lib32", "/lib64", "/sbin", "/opt",
            "/root", "/sys", "/proc",
        ] {
            assert_deny(&format!("rm -rf {path}"));
            assert_deny(&format!("rm -rf {path}/something"));
        }
    }

    #[test]
    fn allows_lookalike_system_paths() {
        // Each target shares a prefix with a SYSTEM_ROOTS entry but is
        // not itself a member or a `{root}/` subpath. The rule uses
        // `arg.starts_with(format!("{root}/"))` for the prefix branch,
        // so dropping the trailing `/` would falsely match these.
        assert_allow("rm -rf /etcd");
        assert_allow("rm -rf /var2");
        assert_allow("rm -rf /usr-local");
        assert_allow("rm -rf /root2");
        assert_allow("rm -rf /procfs");
        assert_allow("rm -rf /tmp");
        assert_allow("rm -rf /home/user/projects");
    }

    #[test]
    fn denies_when_one_of_multiple_targets_is_destructive() {
        assert_deny("rm -rf ./safe /etc");
        assert_deny("rm -rf /etc ./safe");
        assert_deny("rm -rf ./a ./b /usr ./c");
    }

    #[test]
    fn denies_home_targets_with_trailing_slash() {
        assert_deny("rm -rf $HOME/");
        assert_deny("rm -rf ${HOME}/");
    }

    #[test]
    fn denies_alternate_flag_orderings() {
        assert_deny("rm -fr /");
        assert_deny("rm -rfv /");
        assert_deny("rm -vrf /");
        assert_deny("rm --recursive --force /");
        assert_deny("rm --force --recursive /");
    }

    #[test]
    fn denies_separated_lowercase_short_flags() {
        assert_deny("rm -r -f /");
        assert_deny("rm -f -r /");
    }

    #[test]
    fn denies_uppercase_recursive_flag() {
        assert_deny("rm -Rf /");
        assert_deny("rm -fR /");
        assert_deny("rm -R -f /");
        assert_deny("rm -f -R /");
        assert_deny("rm -Rfv /etc");
        assert_deny("rm -vRf /etc");
        assert_deny("rm -fRv /");
        assert_deny("rm -vfR /");
    }

    #[test]
    fn denies_mixed_long_and_short_flags() {
        assert_deny("rm --recursive -f /");
        assert_deny("rm -r --force /");
        assert_deny("rm --force -r /");
        assert_deny("rm -R --force /usr");
        assert_deny("rm -f --recursive /");
        assert_deny("rm --force -R /");
    }

    #[test]
    fn denies_in_pipeline_or_compound() {
        assert_deny("echo go && rm -rf /");
        assert_deny("ls; rm -rf /etc");
        assert_deny("true || rm -rf /");
        assert_deny("cat foo | rm -rf /");
        assert_deny("rm -rf /etc | tee log");
    }

    #[test]
    fn denies_full_path_to_rm() {
        assert_deny("/bin/rm -rf /");
        assert_deny("/usr/bin/rm -rf /etc");
        assert_deny("/bin/rm -Rf /");
        assert_deny("/usr/bin/rm --recursive --force /");
    }

    #[test]
    fn denies_sudo_wrapped_rm() {
        assert_deny("sudo rm -rf /");
        // `sudo -u root` interposes a value-taking flag before `rm`;
        // unwrapping must skip the flag value, not stop at `root`.
        assert_deny("sudo -u root rm -rf /etc");
    }

    #[test]
    fn allows_safe_sudo_rm_invocations() {
        assert_allow("sudo rm file.txt");
        assert_allow("sudo");
    }

    #[test]
    fn allows_safe_rm_invocations() {
        assert_allow("rm file.txt");
        assert_allow("rm -r ./build");
        assert_allow("rm -rf ./build");
        assert_allow("rm -rf $HOME/scratch/foo");
        assert_allow("rm -rf ~/projects/myrepo/target");
        assert_allow("rm -Rf ./build");
        assert_allow("rm --recursive --force ./build");
    }

    #[test]
    fn allows_when_only_one_of_recursive_or_force_is_set() {
        assert_allow("rm -R /etc");
        assert_allow("rm -r /etc");
        assert_allow("rm --recursive /etc");
        assert_allow("rm -f /etc/passwd");
        assert_allow("rm --force /etc/passwd");
    }

    #[test]
    fn allows_non_bash_tools() {
        let input = HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({ "command": "rm -rf /" }),
        };
        let facts = crate::facts::extract(&input);
        assert!(DestructiveRm.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn allows_other_commands_with_rm_substring() {
        assert_allow("echo rm -rf / # not actually deleting");
    }

    use crate::testing::proptest::{arbitrary_command, bash_command, non_bash_hook_input};
    use proptest::prelude::*;

    fn evaluate_for(input: &HookInput) -> Option<Decision> {
        let facts = crate::facts::extract(input);
        DestructiveRm.evaluate(&facts, input)
    }

    proptest! {
        // Non-Bash tool ⇒ always None, regardless of payload contents.
        #[test]
        fn pbt_non_bash_yields_none(input in non_bash_hook_input()) {
            prop_assert!(evaluate_for(&input).is_none());
        }

        // Adversarial: never panics on any printable ASCII bash string.
        #[test]
        fn pbt_evaluate_never_panics(cmd in arbitrary_command()) {
            let input = bash(&cmd);
            let _ = evaluate_for(&input);
        }

        // When the rule fires, the result is always Deny with this rule's id.
        #[test]
        fn pbt_only_emits_deny_with_correct_id(cmd in bash_command()) {
            let input = bash(&cmd);
            if let Some(d) = evaluate_for(&input) {
                match d {
                    Decision::Deny { rule_id, .. } => prop_assert_eq!(rule_id, RULE_ID),
                    other => prop_assert!(
                        false,
                        "expected Deny, got {other:?}",
                    ),
                }
            }
        }

        // Negative space: commands whose argv head never matches an rm
        // binary cannot trigger this rule.
        #[test]
        fn pbt_no_rm_head_means_no_fire(
            head in "[a-z][a-z0-9]{0,5}",
            args in proptest::collection::vec("[a-zA-Z0-9_./-]{1,8}", 0..4),
        ) {
            prop_assume!(!RM_HEADS.contains(&head.as_str()));
            let cmd = if args.is_empty() {
                head
            } else {
                format!("{} {}", head, args.join(" "))
            };
            let input = bash(&cmd);
            prop_assert!(evaluate_for(&input).is_none());
        }

        // Positive space: any cartesian product of (rm head × recursive
        // form × force form × destructive target × flag order) must
        // produce a Deny. Guards against future helper refactors that
        // silently lose coverage on a corner of the matrix.
        #[test]
        fn pbt_all_destructive_combinations_deny(
            head_idx in 0usize..3,
            rec_idx in 0usize..3,
            force_idx in 0usize..2,
            target in prop_oneof![
                Just("/"),
                Just("/*"),
                Just("~"),
                Just("~/"),
                Just("$HOME"),
                Just("${HOME}"),
                Just("\"${HOME}\""),
                Just("'$HOME'"),
                Just("/etc"),
                Just("/usr"),
                Just("/var"),
                Just("/bin"),
                Just("/boot"),
                Just("/lib"),
                Just("/lib32"),
                Just("/lib64"),
                Just("/opt"),
                Just("/root"),
                Just("/sys"),
                Just("/proc"),
                Just("/usr/local-fake/junk"),
                Just("/proc/sys"),
                Just("/sbin"),
            ],
            rec_first in any::<bool>(),
        ) {
            let head = ["rm", "/bin/rm", "/usr/bin/rm"][head_idx];
            let rec = ["-r", "-R", "--recursive"][rec_idx];
            let force = ["-f", "--force"][force_idx];
            let cmd = if rec_first {
                format!("{head} {rec} {force} {target}")
            } else {
                format!("{head} {force} {rec} {target}")
            };
            let input = bash(&cmd);
            let result = evaluate_for(&input);
            prop_assert!(
                matches!(&result, Some(Decision::Deny { rule_id, .. }) if rule_id == RULE_ID),
                "expected deny for {cmd:?}, got {result:?}",
            );
        }

        // Bundled short flags (`-Rf`, `-fR`, verbose permutations) must
        // not slip past a refactor that only recognises separated tokens.
        #[test]
        fn pbt_bundled_destructive_flags_deny(
            head_idx in 0usize..3,
            bundle_idx in 0usize..8,
            target in prop_oneof![
                Just("/"),
                Just("/etc"),
                Just("~"),
                Just("$HOME"),
            ],
        ) {
            let head = ["rm", "/bin/rm", "/usr/bin/rm"][head_idx];
            let bundle = ["-Rf", "-fR", "-rfv", "-vRf", "-Rfv", "-fRv", "-vfR", "-fr"][bundle_idx];
            let cmd = format!("{head} {bundle} {target}");
            let input = bash(&cmd);
            let result = evaluate_for(&input);
            prop_assert!(
                matches!(&result, Some(Decision::Deny { rule_id, .. }) if rule_id == RULE_ID),
                "expected deny for {cmd:?}, got {result:?}",
            );
        }
    }
}
