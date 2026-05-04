use crate::decision::{Decision, Severity};
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;
use super::patterns::{DESTRUCTIVE_PATH, strip_quotes};

pub struct DestructiveRm;

const RULE_ID: &str = "core.filesystem.destructive-rm";

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

    fn evaluate(&self, input: &HookInput) -> Option<Decision> {
        let command = input.bash_command()?;
        let stripped = strip_quotes(command);
        if !contains_destructive_rm(&stripped) {
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

fn contains_destructive_rm(command: &str) -> bool {
    for segment in split_top_level(command) {
        let trimmed = segment.trim_start();
        let mut tokens = trimmed.split_whitespace();
        let head = match tokens.next() {
            Some(h) => h,
            None => continue,
        };
        if head != "rm" && head != "/bin/rm" && head != "/usr/bin/rm" {
            continue;
        }

        let rest_tokens: Vec<&str> = tokens.collect();
        if !has_recursive_force_flag(&rest_tokens) {
            continue;
        }

        let rest = rest_tokens.join(" ");
        let with_leading_space = format!(" {rest}");
        if DESTRUCTIVE_PATH.is_match(&with_leading_space) {
            return true;
        }
    }
    false
}

/// Split a command on top-level `;`, `&&`, `||`, `|` boundaries.
/// Naive: does not handle quoted separators, but quotes are stripped upstream.
fn split_top_level(command: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let bytes = command.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let two = if i + 1 < bytes.len() {
            &bytes[i..i + 2]
        } else {
            &[][..]
        };
        if two == b"&&" || two == b"||" {
            segments.push(&command[start..i]);
            i += 2;
            start = i;
            continue;
        }
        if c == b';' || c == b'|' {
            segments.push(&command[start..i]);
            i += 1;
            start = i;
            continue;
        }
        i += 1;
    }
    segments.push(&command[start..]);
    segments
}

fn has_recursive_force_flag(tokens: &[&str]) -> bool {
    if tokens.contains(&"--recursive") && tokens.contains(&"--force") {
        return true;
    }
    for tok in tokens {
        if !tok.starts_with('-') || tok.starts_with("--") {
            continue;
        }
        let body = &tok[1..];
        if body.contains('r') && body.contains('f') {
            return true;
        }
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

    fn assert_deny(cmd: &str) {
        let result = DestructiveRm.evaluate(&bash(cmd));
        assert!(
            matches!(&result, Some(Decision::Deny { rule_id, .. }) if rule_id == RULE_ID),
            "expected deny for {cmd:?}, got {result:?}",
        );
    }

    fn assert_allow(cmd: &str) {
        let result = DestructiveRm.evaluate(&bash(cmd));
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
        assert!(DestructiveRm.evaluate(&input).is_none());
    }

    #[test]
    fn allows_other_commands_with_rm_substring() {
        assert_allow("echo rm -rf / # not actually deleting");
        // The above tokenises with `echo` as head, so no destructive rm fires.
    }
}
