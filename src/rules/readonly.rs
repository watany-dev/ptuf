//! Forced readonly gate — engine-level, not a [`ConfigRule`].
//!
//! When `Config.readonly` is set, [`evaluate`] returns a High-severity
//! `Deny` for file writes, non-read MCP verbs, and bash commands that
//! are not on the pure-read allowlist. Pack disable / rule override /
//! allowlist never see these decisions: the engine synthesises them
//! *after* demotion (see `docs/adr/0009-readonly-mode-2026-07.md`).

use crate::decision::{Decision, Severity};
use crate::facts::Facts;
use crate::facts::shell::{Argv, Bash, Redirect, RedirectOp};
use crate::hook_input::HookInput;
use crate::reason;

use super::sensitive_bash_read::READER_HEADS;

pub const FILE_WRITE_RULE: &str = "core.readonly.file-write";
pub const BASH_WRITE_RULE: &str = "core.readonly.bash-write";
pub const MCP_WRITE_RULE: &str = "core.readonly.mcp-write";

const FILE_WRITERS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"];

/// MCP tool-name leading verbs treated as reads. Anything else is
/// denied (fail-closed). Underscore-split first segment of
/// [`HookInput::mcp_tool_name`].
const READ_VERBS: &[&str] = &[
    "get", "list", "read", "search", "fetch", "view", "describe", "show", "query", "status",
    "check", "find", "count", "watch", "download",
];

/// Extra pure-read heads on top of [`READER_HEADS`]. Shell wrappers
/// sit here so `bash.commands()` can inspect their payloads.
const READONLY_EXTRA_HEADS: &[&str] = &[
    "ls",
    "stat",
    "pwd",
    "echo",
    "printf",
    "which",
    "type",
    "rg",
    "jq",
    "diff",
    "du",
    "ps",
    "id",
    "whoami",
    "uname",
    "hostname",
    "date",
    "cal",
    "env",
    "printenv",
    "true",
    "false",
    "test",
    "[",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "find",
    "tree",
    "git",
    "cmp",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "cksum",
    "seq",
    "yes",
    "sleep",
    "expr",
    "bc",
    "fold",
    "fmt",
    "paste",
    "join",
    "comm",
    // shell / privilege wrappers (payload checked separately)
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "xargs",
    "eval",
    "exec",
    "sudo",
    "doas",
    "pkexec",
    "run0",
    "command",
    "su",
    "nice",
    "nohup",
    "time",
    "timeout",
];

// ponytail: first non-flag arg is the subcommand. branch/tag/stash/remote/
// config/reflog mutate with no flags — mini-parser if listing those is
// required. `git -C dir status` denies — git_subcommand() if global flags
// must pass.
const GIT_READ_SUBCOMMANDS: &[&str] = &[
    "status",
    "log",
    "show",
    "diff",
    "blame",
    "grep",
    "ls-files",
    "rev-parse",
];

/// Evaluate the readonly gate. Returns `Some(Deny)` when the input is
/// a write; `None` when it is a pure read (caller keeps the demoted
/// decision).
pub fn evaluate(facts: &Facts, input: &HookInput) -> Option<Decision> {
    if let Some(d) = evaluate_file(input) {
        return Some(d);
    }
    if input.is_mcp_tool() {
        return evaluate_mcp(input);
    }
    if input.tool_name == "Bash" {
        return evaluate_bash(facts, input);
    }
    None
}

/// Severity for `core.readonly.*` rule ids (not registered in RULES).
pub fn severity_for(rule_id: &str) -> Option<Severity> {
    if rule_id.starts_with("core.readonly.") {
        Some(Severity::High)
    } else {
        None
    }
}

fn evaluate_file(input: &HookInput) -> Option<Decision> {
    if input.is_mcp_tool() {
        return None;
    }
    let known_writer = FILE_WRITERS.contains(&input.tool_name.as_str());
    let has_payload = input.write_payload().is_some();
    if !known_writer && !has_payload {
        return None;
    }
    Some(deny(
        FILE_WRITE_RULE,
        "ptuf readonly mode blocks file-writing tools (Write / Edit / MultiEdit / NotebookEdit / apply_patch).",
    ))
}

fn evaluate_mcp(input: &HookInput) -> Option<Decision> {
    if input.write_payload().is_some() {
        return Some(deny(
            MCP_WRITE_RULE,
            "ptuf readonly mode blocks MCP tools that carry a write payload.",
        ));
    }
    let tool = input.mcp_tool_name().unwrap_or("");
    let verb = tool.split('_').next().unwrap_or(tool);
    if READ_VERBS.contains(&verb) {
        return None;
    }
    Some(deny(
        MCP_WRITE_RULE,
        &format!(
            "ptuf readonly mode blocks MCP tool `{tool}` — leading verb `{verb}` is not in the read-verb allowlist."
        ),
    ))
}

fn evaluate_bash(facts: &Facts, input: &HookInput) -> Option<Decision> {
    if input.bash_command().is_none() {
        return Some(deny(
            BASH_WRITE_RULE,
            "ptuf readonly mode blocks Bash calls with no inspectable command.",
        ));
    }
    let Some(bash) = facts.bash.as_ref() else {
        return Some(deny(
            BASH_WRITE_RULE,
            "ptuf readonly mode blocks Bash calls that failed to parse.",
        ));
    };
    if is_opaque(bash) {
        return Some(deny(
            BASH_WRITE_RULE,
            "ptuf readonly mode blocks opaque Bash (process substitution, unreparsed command substitution, or unreadable wrapper payload).",
        ));
    }
    if has_write_redirect(bash) {
        return Some(deny(
            BASH_WRITE_RULE,
            "ptuf readonly mode blocks Bash redirects that write to a file (>, >>, 2>, &>).",
        ));
    }
    for argv in bash.commands() {
        if let Some(reason) = head_denied(argv) {
            return Some(deny(BASH_WRITE_RULE, &reason));
        }
    }
    None
}

fn is_opaque(bash: &Bash) -> bool {
    if bash.has_process_substitution {
        return true;
    }
    if bash.has_command_substitution && !has_any_subst_argv(bash) {
        return true;
    }
    bash.segments
        .iter()
        .flat_map(|p| &p.commands)
        .any(argv_opaque_tree)
}

fn argv_opaque_tree(argv: &Argv) -> bool {
    if !argv.inner_code.is_empty() && argv.inner_argv.is_empty() {
        return true;
    }
    argv.inner_argv.iter().any(argv_opaque_tree) || argv.subst_argv.iter().any(argv_opaque_tree)
}

fn has_any_subst_argv(bash: &Bash) -> bool {
    bash.segments
        .iter()
        .flat_map(|p| &p.commands)
        .any(argv_has_subst)
}

fn argv_has_subst(argv: &Argv) -> bool {
    !argv.subst_argv.is_empty() || argv.inner_argv.iter().any(argv_has_subst)
}

fn has_write_redirect(bash: &Bash) -> bool {
    for pipe in &bash.segments {
        if redirects_write(&pipe.redirects) {
            return true;
        }
        for argv in &pipe.commands {
            if argv_has_write_redirect(argv) {
                return true;
            }
        }
    }
    false
}

fn argv_has_write_redirect(argv: &Argv) -> bool {
    if redirects_write(&argv.inner_redirects) {
        return true;
    }
    argv.inner_argv.iter().any(argv_has_write_redirect)
        || argv.subst_argv.iter().any(argv_has_write_redirect)
}

fn redirects_write(redirects: &[Redirect]) -> bool {
    redirects.iter().any(|r| {
        matches!(
            r.op,
            RedirectOp::Stdout | RedirectOp::StdoutAppend | RedirectOp::Stderr | RedirectOp::Merge
        )
    })
}

fn is_readonly_head(head: &str) -> bool {
    READER_HEADS.contains(&head) || READONLY_EXTRA_HEADS.contains(&head)
}

fn head_denied(argv: &Argv) -> Option<String> {
    let head = argv.head_basename();
    // Shell wrappers (bash/sh/xargs/…) sit on READONLY_EXTRA_HEADS;
    // their payloads are already flattened into bash.commands().
    if !is_readonly_head(head) {
        return Some(format!(
            "ptuf readonly mode blocks command `{head}` — not on the pure-read allowlist."
        ));
    }
    if let Some(msg) = flag_guard(argv) {
        return Some(msg);
    }
    if head == "git" {
        let sub = argv.positional().next().unwrap_or("");
        if !GIT_READ_SUBCOMMANDS.contains(&sub) {
            return Some(format!(
                "ptuf readonly mode blocks `git {sub}` — not a pure-read git subcommand."
            ));
        }
    }
    None
}

fn flag_guard(argv: &Argv) -> Option<String> {
    let head = argv.head_basename();
    match head {
        "sed" => {
            for flag in argv.flags() {
                if flag == "-i"
                    || (flag.starts_with("-i") && !flag.starts_with("--"))
                    || flag == "--in-place"
                    || flag.starts_with("--in-place=")
                {
                    return Some(
                        "ptuf readonly mode blocks `sed -i` / `--in-place` (in-place edit).".into(),
                    );
                }
            }
        },
        "dd" => {
            for arg in &argv.args {
                if arg.starts_with("of=") {
                    return Some("ptuf readonly mode blocks `dd of=` (write destination).".into());
                }
            }
        },
        "sort" => {
            for arg in &argv.args {
                if arg == "-o" || arg == "--output" {
                    return Some("ptuf readonly mode blocks `sort -o` (write destination).".into());
                }
                if let Some(rest) = arg.strip_prefix("--output=")
                    && !rest.is_empty()
                {
                    return Some(
                        "ptuf readonly mode blocks `sort --output=` (write destination).".into(),
                    );
                }
            }
        },
        "find" => {
            for arg in &argv.args {
                if arg == "-delete" || arg == "-exec" || arg == "-execdir" || arg == "-ok" {
                    return Some(format!(
                        "ptuf readonly mode blocks `find {arg}` (mutates or runs a command)."
                    ));
                }
            }
        },
        _ => {},
    }
    None
}

fn deny(rule_id: &str, problem: &str) -> Decision {
    Decision::Deny {
        rule_id: rule_id.into(),
        reason: reason::build(
            rule_id,
            problem,
            &[
                "Ask a human to run `ptuf readonly off` in a terminal (outside the agent hook).",
                "Or unset `PTUF_READONLY` if it was set in the environment.",
            ],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook_input::HookInput;
    use serde_json::json;

    fn bash(cmd: &str) -> (Facts, HookInput) {
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": cmd }),
        };
        let facts = crate::facts::extract(&input);
        (facts, input)
    }

    fn assert_allow_bash(cmd: &str) {
        let (facts, input) = bash(cmd);
        let got = evaluate(&facts, &input);
        assert!(got.is_none(), "expected allow for `{cmd}`, got {got:?}");
    }

    fn assert_deny_bash(cmd: &str, rule: &str) {
        let (facts, input) = bash(cmd);
        let d = evaluate(&facts, &input).unwrap_or_else(|| panic!("expected deny for `{cmd}`"));
        assert_eq!(d.rule_id(), Some(rule), "cmd={cmd}");
    }

    #[test]
    fn tee_is_not_a_readonly_head() {
        assert!(!is_readonly_head("tee"));
        for h in READER_HEADS {
            assert!(is_readonly_head(h), "READER_HEADS `{h}` must stay allowed");
        }
    }

    #[test]
    fn allows_pure_reads() {
        for cmd in [
            "cat f",
            "git status",
            "sed s/x/y/ f",
            "ls | head",
            "ls -la",
            "rg TODO",
            "jq . package.json",
            "diff a b",
            "echo hello",
            "printf '%s' hi",
            "pwd",
            "stat f",
            "which ls",
            "du -sh .",
            "ps aux",
            "git log --oneline -5",
            "git show HEAD",
            "git diff",
            "git blame f",
            "git grep foo",
            "git ls-files",
            "git rev-parse HEAD",
            "bash -lc 'cat f'",
            "cat < f",
            "sed --include=*.c s/x/y/ f",
        ] {
            assert_allow_bash(cmd);
        }
    }

    #[test]
    fn denies_flag_guard_and_empty_git() {
        for cmd in [
            "sort --output=out in",
            "find . -exec echo {} +",
            "find . -ok echo {} +",
            "sed --in-place s/x/y/ f",
            "echo x 2> err",
            "git",
        ] {
            assert_deny_bash(cmd, BASH_WRITE_RULE);
        }
    }

    #[test]
    fn denies_bash_without_command_and_unknown_mcp_verb() {
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({}),
        };
        let facts = crate::facts::extract(&input);
        let d = evaluate(&facts, &input).expect("deny empty bash");
        assert_eq!(d.rule_id(), Some(BASH_WRITE_RULE));

        let input = HookInput {
            tool_name: "mcp__fs__create_file".into(),
            tool_input: json!({}),
        };
        let facts = crate::facts::extract(&input);
        let d = evaluate(&facts, &input).expect("deny mcp write verb");
        assert_eq!(d.rule_id(), Some(MCP_WRITE_RULE));
    }

    #[test]
    fn denies_unparsed_bash_and_allows_reparsed_subst() {
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": "cat f" }),
        };
        let facts = crate::facts::Facts::default();
        let d = evaluate(&facts, &input).expect("deny unparsed bash");
        assert_eq!(d.rule_id(), Some(BASH_WRITE_RULE));
        assert_allow_bash("echo $(cat f)");
        assert_deny_bash("eval \"$cmd\"", BASH_WRITE_RULE);
    }

    #[test]
    fn denies_opaque_command_subst_and_unparsed_wrapper_payload() {
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": "echo x" }),
        };
        let mut facts = crate::facts::extract(&input);
        if let Some(bash) = facts.bash.as_mut() {
            bash.has_command_substitution = true;
            for pipe in &mut bash.segments {
                for argv in &mut pipe.commands {
                    argv.subst_argv.clear();
                }
            }
        }
        let d = evaluate(&facts, &input).expect("deny unreparsed subst");
        assert_eq!(d.rule_id(), Some(BASH_WRITE_RULE));

        let mut facts = crate::facts::extract(&input);
        if let Some(bash) = facts.bash.as_mut() {
            bash.has_command_substitution = false;
            bash.has_process_substitution = false;
            for pipe in &mut bash.segments {
                for argv in &mut pipe.commands {
                    argv.inner_code = vec!["opaque".into()];
                    argv.inner_argv.clear();
                    argv.subst_argv.clear();
                }
            }
        }
        let d = evaluate(&facts, &input).expect("deny opaque wrapper");
        assert_eq!(d.rule_id(), Some(BASH_WRITE_RULE));
    }

    #[test]
    fn denies_writers() {
        for cmd in [
            "echo x > f",
            "bash -lc 'echo x>f'",
            "sed -i s/x/y/ f",
            "sed --in-place=.bak s/x/y/ f",
            "dd of=f",
            "tee g",
            "find . -delete",
            "git push",
            "git branch new-feature",
            "git tag v1.0",
            "git stash",
            "git remote -v",
            "git config --get user.name",
            "git reflog",
            "git ls-tree HEAD",
            "git help status",
            "git version",
            "git describe",
            "git --version",
            "git -C . status",
            "mkdir x",
            "cargo build",
            "ptuf readonly off",
            "npm test",
            "sort -o out in",
            "cat f | tee g",
            "python -c 'open(\"f\",\"w\")'",
            "rm f",
            "touch f",
            "cp a b",
            "mv a b",
        ] {
            assert_deny_bash(cmd, BASH_WRITE_RULE);
        }
    }

    #[test]
    fn denies_opaque_subst() {
        // Process substitution
        assert_deny_bash("cat <(echo hi)", BASH_WRITE_RULE);
    }

    #[test]
    fn denies_file_tools() {
        for tool in FILE_WRITERS {
            let input = HookInput {
                tool_name: (*tool).into(),
                tool_input: json!({ "file_path": "f", "content": "x", "new_string": "x" }),
            };
            let facts = crate::facts::extract(&input);
            let d = evaluate(&facts, &input).expect("deny");
            assert_eq!(d.rule_id(), Some(FILE_WRITE_RULE));
        }
        // Read / Glob pass
        for tool in ["Read", "Glob", "Grep"] {
            let input = HookInput {
                tool_name: tool.into(),
                tool_input: json!({ "file_path": "f", "pattern": "x" }),
            };
            let facts = crate::facts::extract(&input);
            assert!(evaluate(&facts, &input).is_none());
        }
    }

    #[test]
    fn mcp_read_verbs_allowed_write_denied() {
        let input = HookInput {
            tool_name: "mcp__fs__list_files".into(),
            tool_input: json!({}),
        };
        let facts = crate::facts::extract(&input);
        assert!(evaluate(&facts, &input).is_none());

        let input = HookInput {
            tool_name: "mcp__fs__write_file".into(),
            tool_input: json!({}),
        };
        let facts = crate::facts::extract(&input);
        let d = evaluate(&facts, &input).expect("deny");
        assert_eq!(d.rule_id(), Some(MCP_WRITE_RULE));

        let input = HookInput {
            tool_name: "mcp__fs__get_thing".into(),
            tool_input: json!({ "content": "payload" }),
        };
        let facts = crate::facts::extract(&input);
        let d = evaluate(&facts, &input).expect("deny payload");
        assert_eq!(d.rule_id(), Some(MCP_WRITE_RULE));
    }

    #[test]
    fn severity_for_readonly_prefix() {
        assert_eq!(severity_for(FILE_WRITE_RULE), Some(Severity::High));
        assert_eq!(severity_for("core.filesystem.x"), None);
    }
}
