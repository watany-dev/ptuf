use crate::decision::{Decision, Severity};
use crate::facts::Facts;
use crate::facts::shell::Argv;
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
    fn id(&self) -> &'static str {
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
            .segments
            .iter()
            .flat_map(|p| p.commands.iter())
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
    is_rm_head(&argv.head)
        && has_recursive_force_flag(argv)
        && argv.positional().any(is_destructive_target)
}

fn is_rm_head(head: &str) -> bool {
    RM_HEADS.contains(&head)
}

fn has_recursive_force_flag(argv: &Argv) -> bool {
    let flags: Vec<&str> = argv.flags().collect();
    if flags.contains(&"--recursive") && flags.contains(&"--force") {
        return true;
    }
    flags.iter().any(|flag| {
        if flag.starts_with("--") {
            return false;
        }
        let body = &flag[1..];
        body.contains('r') && body.contains('f')
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
    fn denies_rm_rf_root() {
        assert_deny("rm -rf /");
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
        for path in ["/etc", "/usr", "/var", "/bin", "/boot", "/sbin"] {
            assert_deny(&format!("rm -rf {path}"));
            assert_deny(&format!("rm -rf {path}/something"));
        }
    }

    #[test]
    fn denies_alternate_flag_orderings() {
        assert_deny("rm -fr /");
        assert_deny("rm -rfv /");
        assert_deny("rm -vrf /");
        assert_deny("rm --recursive --force /");
    }

    #[test]
    fn denies_in_pipeline_or_compound() {
        assert_deny("echo go && rm -rf /");
        assert_deny("ls; rm -rf /etc");
        assert_deny("true || rm -rf /");
    }

    #[test]
    fn denies_full_path_to_rm() {
        assert_deny("/bin/rm -rf /");
        assert_deny("/usr/bin/rm -rf /etc");
    }

    #[test]
    fn allows_safe_rm_invocations() {
        assert_allow("rm file.txt");
        assert_allow("rm -r ./build");
        assert_allow("rm -rf ./build");
        assert_allow("rm -rf $HOME/scratch/foo");
        assert_allow("rm -rf ~/projects/myrepo/target");
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
}
