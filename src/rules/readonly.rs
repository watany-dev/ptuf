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

#[cfg(test)]
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

/// Pure-read command heads allowed under readonly. Includes
/// [`READER_HEADS`] plus inspection / formatting utilities and shell
/// container heads whose payloads are inspected via [`Bash::commands`].
const READONLY_HEADS: &[&str] = &[
    // READER_HEADS (keep in sync — duplicated so the const can stay a
    // single slice for `contains` without heap allocation).
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "view",
    "bat",
    "xxd",
    "od",
    "hexdump",
    "strings",
    "base64",
    "base32",
    "grep",
    "egrep",
    "fgrep",
    "awk",
    "gawk",
    "mawk",
    "sed",
    "cut",
    "tr",
    "sort",
    "uniq",
    "wc",
    "nl",
    "tac",
    "rev",
    "column",
    "file",
    "dd",
    "source",
    ".",
    // pure-read extras
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

const GIT_READ_SUBCOMMANDS: &[&str] = &[
    "status",
    "log",
    "show",
    "diff",
    "blame",
    "grep",
    "ls-files",
    "ls-tree",
    "rev-parse",
    "rev-list",
    "describe",
    "branch",
    "tag",
    "remote",
    "config",
    "help",
    "version",
    "whatchanged",
    "shortlog",
    "name-rev",
    "cat-file",
    "check-ignore",
    "check-attr",
    "ls-remote",
    "for-each-ref",
    "symbolic-ref",
    "reflog",
    "stash", // `stash list` only — guarded below
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

fn head_denied(argv: &Argv) -> Option<String> {
    let head = argv.head_basename();
    // Shell wrappers (bash/sh/xargs/…) sit on READONLY_HEADS; their
    // payloads are already flattened into bash.commands().
    if !READONLY_HEADS.contains(&head) {
        return Some(format!(
            "ptuf readonly mode blocks command `{head}` — not on the pure-read allowlist."
        ));
    }
    if let Some(msg) = flag_guard(argv) {
        return Some(msg);
    }
    if head == "git" {
        return git_denied(argv);
    }
    None
}

fn flag_guard(argv: &Argv) -> Option<String> {
    let head = argv.head_basename();
    match head {
        "sed" => {
            for flag in argv.flags() {
                if flag == "-i"
                    || flag.starts_with("-i")
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

fn git_denied(argv: &Argv) -> Option<String> {
    let sub = argv
        .args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("");
    if sub.is_empty() {
        // bare `git` — harmless help path
        return None;
    }
    if !GIT_READ_SUBCOMMANDS.contains(&sub) {
        return Some(format!(
            "ptuf readonly mode blocks `git {sub}` — only read-oriented git subcommands are allowed."
        ));
    }
    // `git stash` without `list` / `show` mutates; allow list/show only.
    if sub == "stash" {
        let action = argv
            .args
            .iter()
            .skip_while(|a| a.as_str() != "stash")
            .nth(1)
            .map(String::as_str)
            .unwrap_or("push");
        if !matches!(action, "list" | "show" | "-l" | "--list") {
            return Some(
                "ptuf readonly mode blocks mutating `git stash` (only `list` / `show` allowed)."
                    .into(),
            );
        }
    }
    // `git branch` / `git tag` / `git remote` / `git config` without
    // mutating flags are treated as read; mutating forms (-d/-D/-m, add,
    // set-url, --unset, …) are denied.
    if matches!(sub, "branch" | "tag") {
        for flag in argv.flags() {
            if matches!(
                flag,
                "-d" | "-D"
                    | "-m"
                    | "-M"
                    | "--delete"
                    | "--move"
                    | "-c"
                    | "-C"
                    | "--copy"
                    | "-f"
                    | "--force"
            ) {
                return Some(format!(
                    "ptuf readonly mode blocks mutating `git {sub} {flag}`."
                ));
            }
        }
    }
    if sub == "remote" {
        let action = argv
            .args
            .iter()
            .skip_while(|a| a.as_str() != "remote")
            .nth(1)
            .map(String::as_str)
            .unwrap_or("");
        if matches!(
            action,
            "add" | "remove" | "rm" | "set-url" | "rename" | "prune" | "set-branches" | "set-head"
        ) {
            return Some(format!("ptuf readonly mode blocks `git remote {action}`."));
        }
    }
    if sub == "config" {
        for flag in argv.flags() {
            if matches!(
                flag,
                "--unset" | "--unset-all" | "--remove-section" | "--add" | "--replace-all"
            ) {
                return Some(format!("ptuf readonly mode blocks `git config {flag}`."));
            }
        }
        // `git config <key> <value>` writes; bare `git config <key>` reads.
        let after: Vec<_> = argv
            .args
            .iter()
            .skip_while(|a| a.as_str() != "config")
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .collect();
        if after.len() >= 2 {
            return Some("ptuf readonly mode blocks `git config <key> <value>` writes.".into());
        }
    }
    if sub == "reflog" {
        let action = argv
            .args
            .iter()
            .skip_while(|a| a.as_str() != "reflog")
            .nth(1)
            .map(String::as_str)
            .unwrap_or("show");
        if matches!(action, "expire" | "delete") {
            return Some(format!("ptuf readonly mode blocks `git reflog {action}`."));
        }
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
    fn reader_heads_subset_of_readonly_heads() {
        for h in READER_HEADS {
            assert!(
                READONLY_HEADS.contains(h),
                "READER_HEADS entry `{h}` missing from READONLY_HEADS"
            );
        }
        assert!(!READONLY_HEADS.contains(&"tee"));
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
        ] {
            assert_allow_bash(cmd);
        }
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
