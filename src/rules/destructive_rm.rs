use crate::decision::{Decision, Severity};
use crate::facts::Facts;
use crate::facts::shell::{Argv, unwrap_all_prefix_wrappers};
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;

pub(crate) struct DestructiveRm;

const RULE_ID: &str = "core.filesystem.destructive-rm";

// Heads are compared by basename, so absolute and relative invocation
// paths (`/bin/rm`, `/usr/local/bin/rm`, `./rm`) match without enumeration.
const RM_HEADS: &[&str] = &["rm"];

/// Roots whose whole subtree is protected.
const SYSTEM_ROOTS: &[&str] = &[
    "/etc",
    "/usr",
    "/var",
    "/bin",
    "/boot",
    "/lib",
    "/lib32",
    "/lib64",
    "/sbin",
    "/opt",
    "/root",
    "/sys",
    "/proc",
    "/System",
    "/private/etc",
];

/// Roots protected only as a whole: their children are routine targets
/// (`/mnt/scratch/build`, `/private/var/folders/...` on macOS), but
/// removing the root itself wipes mounts, devices, or every user.
const EXACT_ROOTS: &[&str] = &[
    "/home",
    "/Users",
    "/srv",
    "/mnt",
    "/media",
    "/run",
    "/dev",
    "/Library",
    "/Applications",
    "/private",
    "/private/var",
    "/Volumes",
];

/// Parents of per-user homes: `/home/alice` (or a glob over the user
/// segment) is a whole home directory.
const HOME_PARENTS: &[&str] = &["/home", "/Users"];

/// Spellings of the invoking user's home. `~NAME` / `~+` / `~-` are
/// handled separately in [`home_rest`].
const HOME_PREFIXES: &[&str] = &["$HOME", "${HOME}"];

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
    let argv = unwrap_all_prefix_wrappers(argv);
    is_rm_head(argv.head_basename())
        && has_recursive_force_flag(&argv)
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
        if let Some(long) = flag.strip_prefix("--") {
            return is_long_prefix(long, "recursive");
        }
        flag[1..].chars().any(|c| c == 'r' || c == 'R')
    })
}

fn has_force(flags: &[&str]) -> bool {
    flags.iter().any(|flag| {
        if let Some(long) = flag.strip_prefix("--") {
            if let Some((name, value)) = long.split_once('=') {
                // `--interactive=never` suppresses prompts like `-f`.
                return is_long_prefix(name, "interactive")
                    && matches!(value, "never" | "no" | "none");
            }
            return is_long_prefix(long, "force");
        }
        flag[1..].contains('f')
    })
}

/// GNU getopt_long accepts any unambiguous prefix of a long option
/// (`--recursiv`, `--r`). Uniqueness is not checked: a prefix that GNU
/// would reject as ambiguous only errs toward deny.
fn is_long_prefix(given: &str, full: &str) -> bool {
    !given.is_empty() && full.starts_with(given)
}

fn is_destructive_target(arg: &str) -> bool {
    expansion_candidates(arg)
        .iter()
        .any(|candidate| is_destructive_literal(candidate))
}

fn is_destructive_literal(arg: &str) -> bool {
    if arg.contains("..") {
        return true;
    }
    let normalized = normalize_rm_target(arg);
    // Shell glob expansion cannot be resolved pre-execution; a glob in the
    // first path segment can match `/`, system roots, or their children.
    if first_segment_has_glob(&normalized) {
        return true;
    }
    if let Some(rest) = home_rest(&normalized) {
        // The home itself, or a glob over its direct children (`~/*`,
        // `~/.*`), empties the whole home directory.
        return rest.is_empty() || segment_has_glob(rest.split('/').next().unwrap_or(""));
    }
    if let Some(user) = HOME_PARENTS
        .iter()
        .find_map(|p| normalized.strip_prefix(p).and_then(|r| r.strip_prefix('/')))
        && !user.is_empty()
        && (!user.contains('/') || segment_has_glob(user.split('/').next().unwrap_or("")))
    {
        return true;
    }
    normalized == "/"
        || normalized == "/*"
        || EXACT_ROOTS.contains(&normalized.as_str())
        || SYSTEM_ROOTS
            .iter()
            .any(|root| normalized == *root || normalized.starts_with(&format!("{root}/")))
}

/// When `path` names a home directory (`~`, `~NAME`, `~+`, `~-`,
/// `$HOME`, `${HOME}`), the remainder after that prefix with its
/// leading `/` stripped (empty for the home itself).
fn home_rest(path: &str) -> Option<&str> {
    let rest = if let Some(after) = path.strip_prefix('~') {
        // `~NAME` is NAME's home; `~+` / `~-` are `$PWD` / `$OLDPWD`.
        let end = after.find('/').unwrap_or(after.len());
        let name = &after[..end];
        // (`-` is covered by the user-name character set.)
        let valid = name.is_empty()
            || name == "+"
            || name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if !valid {
            return None;
        }
        &after[end..]
    } else {
        HOME_PREFIXES.iter().find_map(|p| {
            path.strip_prefix(p)
                .filter(|r| r.is_empty() || r.starts_with('/'))
        })?
    };
    Some(rest.strip_prefix('/').unwrap_or(rest))
}

/// Literal targets a word may expand to once `${NAME<op>WORD}` runs:
/// the bare `${NAME}` form, plus `WORD` itself for the operators that
/// can substitute it (`-`, `=`, `+`, with or without `:`). `${HOME:?}`
/// and friends therefore compare as `${HOME}`.
fn expansion_candidates(arg: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut rest = arg;
    while let Some(start) = rest.find("${") {
        let (lit, after) = rest.split_at(start);
        for c in &mut out {
            c.push_str(lit);
        }
        let body_start = &after[2..];
        let Some(close) = body_start.find('}') else {
            rest = after;
            break;
        };
        let body = &body_start[..close];
        rest = &body_start[close + 1..];
        let name_len = body
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(body.len());
        let (name, op) = body.split_at(name_len);
        let base = format!("${{{name}}}");
        let op = op.strip_prefix(':').unwrap_or(op);
        let word = ['-', '=', '+'].iter().find_map(|c| op.strip_prefix(*c));
        let mut next = Vec::with_capacity(out.len() * 2);
        for c in &out {
            next.push(format!("{c}{base}"));
            if let Some(w) = word {
                next.push(format!("{c}{w}"));
            }
        }
        // Bound the fan-out for adversarial inputs; the first
        // candidates already cover the bare and substituted forms.
        next.truncate(16);
        out = next;
    }
    for c in &mut out {
        c.push_str(rest);
    }
    out
}

/// Returns true when `path` is absolute and its first segment contains shell
/// glob metacharacters (`*`, `?`, `[`). Second-segment globs such as `/tmp/*`
/// are excluded because they cannot expand to `/` or a system root prefix.
fn first_segment_has_glob(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    segment_has_glob(rest.split('/').next().unwrap_or(""))
}

fn segment_has_glob(segment: &str) -> bool {
    segment.contains(['*', '?', '['])
}

/// Collapse POSIX duplicate slashes, drop `.` segments (`/./etc` is
/// `/etc`), and trim a trailing `/` before comparing rm targets.
/// Parent-segment tokens are handled pessimistically by the caller
/// because the resolved path cannot be known pre-shell.
fn normalize_rm_target(arg: &str) -> String {
    let absolute = arg.starts_with('/');
    let segments: Vec<&str> = arg
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    let joined = segments.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        // `.` / `./` stays the current directory.
        arg.chars().take(1).collect()
    } else {
        joined
    }
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
    fn denies_absolute_and_relative_rm_heads() {
        // rm heads must match on basename, including install locations
        // outside the hand-enumerated /bin//usr/bin pair.
        assert_deny("/bin/rm -rf /");
        assert_deny("/usr/local/bin/rm -rf /etc");
        assert_deny("./rm -rf /");
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
    fn denies_first_segment_glob_on_absolute_paths() {
        assert_deny("rm -rf /e*");
        assert_deny("rm -rf /e?");
        assert_deny("rm -rf //e*");
        assert_deny("rm -rf /[a-z]*");
    }

    #[test]
    fn first_segment_has_glob_unit_cases() {
        assert!(first_segment_has_glob("/e*"));
        assert!(first_segment_has_glob("/e?"));
        assert!(!first_segment_has_glob("/tmp/*"));
        assert!(!first_segment_has_glob("build/*"));
    }

    #[test]
    fn allows_second_segment_glob() {
        assert_allow("rm -rf /tmp/*");
        assert_allow("rm -rf *.txt");
    }

    #[test]
    fn destructive_rm_normalizes_double_slash() {
        assert_deny("rm -rf //");
        assert_deny("rm -rf //etc");
        assert_deny("rm -rf /etc//");
        assert_deny("rm -rf ///usr/local");
    }

    #[test]
    fn destructive_rm_pessimistic_on_parent_segments() {
        assert_deny("rm -rf ./safe/../etc");
        assert_deny("rm -rf /tmp/foo/../etc/passwd");
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
    fn denies_dot_segments_in_system_paths() {
        assert_deny("rm -rf /./etc");
        assert_deny("rm -rf /./usr/lib");
        assert_deny("rm -rf /usr/./");
        assert_allow("rm -rf ./build");
        assert_allow("rm -rf .");
    }

    #[test]
    fn denies_globs_over_home_children() {
        for cmd in [
            "rm -rf ~/*",
            "rm -rf ~/.*",
            "rm -rf $HOME/*",
            r#"rm -rf "$HOME"/*"#,
            "rm -rf ${HOME}/*",
        ] {
            assert_deny(cmd);
        }
        assert_allow("rm -rf ~/.cache/*");
        assert_allow("rm -rf ~/projects/x");
    }

    #[test]
    // `${HOME:?}` is shell syntax, not a format string.
    #[allow(clippy::literal_string_with_formatting_args)]
    fn denies_parameter_expansion_operators() {
        for cmd in [
            "rm -rf ${HOME:?}",
            r#"rm -rf "${HOME:?}/""#,
            "rm -rf ${HOME%/}",
            "rm -rf ${X:-/}",
            "rm -rf ${X:=/etc}",
            "rm -rf ${X+/usr}",
        ] {
            assert_deny(cmd);
        }
        assert_allow("rm -rf ${BUILD_DIR:-./build}");
        assert_allow(r#"rm -rf "${TMPDIR:?}/foo""#);
    }

    #[test]
    fn denies_abbreviated_long_options_and_interactive_never() {
        assert_deny("rm --recursiv --forc /");
        assert_deny("rm --r --f /etc");
        assert_deny("rm -r --interactive=never /etc");
        assert_deny("rm -r --inter=no /etc");
        assert_allow("rm -r --interactive=always /etc");
        assert_allow("rm -r --verbose /etc");
    }

    #[test]
    fn denies_extra_roots_and_user_homes() {
        for path in [
            "/home",
            "/Users",
            "/srv",
            "/mnt",
            "/media",
            "/run",
            "/dev",
            "/Library",
            "/Applications",
            "/private",
            "/private/var",
            "/Volumes",
            "/System/Library",
            "/private/etc/hosts",
            "/home/alice",
            "/Users/bob/",
            "/home/*",
        ] {
            assert_deny(&format!("rm -rf {path}"));
        }
        assert_allow("rm -rf /home/alice/proj/target");
        assert_allow("rm -rf /mnt/scratch/build");
        assert_allow("rm -rf /private/var/folders/x");
        assert_allow("rm -rf /Library/Caches/foo");
    }

    #[test]
    fn denies_tilde_user_homes() {
        assert_deny("rm -rf ~root");
        assert_deny("rm -rf ~alice/");
        assert_deny("rm -rf ~+");
        assert_deny("rm -rf ~-");
        assert_allow("rm -rf ~alice/tmp");
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
                Just("/e*"),
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
