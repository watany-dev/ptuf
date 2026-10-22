//! Codex `apply_patch` command parsing helpers.

use crate::facts::shell::{self, Bash, RedirectOp};

/// Command heads Codex intercepts from the shell and runs as its
/// internal `apply_patch` (`apply_patch <<'EOF' … EOF`, `apply_patch '…'`).
const SHELL_HEADS: &[&str] = &["apply_patch", "applypatch"];

/// Cheap pre-filter so callers only parse a Bash line when it can
/// possibly invoke the shell-level `apply_patch`.
pub(crate) fn may_invoke_from_shell(command: &str) -> bool {
    SHELL_HEADS.iter().any(|h| command.contains(h))
}

/// Patch bodies handed to a shell-level `apply_patch` / `applypatch`:
/// the first positional argument plus every heredoc body in the same
/// pipeline (or inner shell code). Over-collecting heredocs is
/// harmless: a body without `***` markers yields no paths.
pub(crate) fn bash_bodies(bash: &Bash) -> Vec<String> {
    let mut out = Vec::new();
    for pipe in &bash.segments {
        let mut cmds = Vec::new();
        for c in &pipe.commands {
            c.collect_commands(&mut cmds);
        }
        let mut hit = false;
        for c in &cmds {
            let argv = shell::unwrap_all_prefix_wrappers(c);
            if SHELL_HEADS.contains(&argv.head_basename()) {
                hit = true;
                if let Some(first) = argv.args.iter().find(|a| !a.starts_with('-')) {
                    out.push(first.clone());
                }
            }
        }
        if !hit {
            continue;
        }
        let heredocs = pipe
            .redirects
            .iter()
            .chain(cmds.iter().flat_map(|c| c.inner_redirects.iter()))
            .filter(|r| r.op == RedirectOp::Heredoc)
            .map(|r| r.target.clone());
        out.extend(heredocs);
    }
    out
}

const PATH_PREFIXES: &[&str] = &[
    "*** Add File: ",
    "*** Update File: ",
    "*** Delete File: ",
    "*** Move to: ",
];

/// Extract destination paths from a Codex-style `apply_patch` command.
pub(crate) fn paths(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in command.lines() {
        // Codex matches hunk headers on trimmed lines.
        let line = line.trim();
        for prefix in PATH_PREFIXES {
            if let Some(path) = line.strip_prefix(prefix) {
                let trimmed = path.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
                break;
            }
        }
    }
    out
}

/// Content the patch adds: every `+`-prefixed line with the prefix stripped,
/// joined by `\n`. Returns `None` when there are no added lines.
pub(crate) fn added_content(command: &str) -> Option<String> {
    let added: Vec<&str> = command
        .lines()
        .filter_map(|line| line.strip_prefix('+'))
        .collect();
    if added.is_empty() {
        None
    } else {
        Some(added.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{extract, sensitive::SensitiveKind};
    use crate::hook_input::HookInput;
    use proptest::prelude::*;
    use std::collections::HashSet;

    #[test]
    fn paths_collects_add_update_delete_and_move() {
        let command = "\
*** Begin Patch
*** Add File: new.txt
*** Update File: old.txt
*** Move to: renamed.txt
*** Delete File: gone.txt
*** End Patch
";
        assert_eq!(
            paths(command),
            vec!["new.txt", "old.txt", "renamed.txt", "gone.txt"]
        );
    }

    #[test]
    fn paths_trims_indented_headers() {
        let command = "*** Begin Patch\n  *** Add File: a.txt\n*** End Patch\n";
        assert_eq!(paths(command), vec!["a.txt"]);
    }

    #[test]
    fn bash_bodies_reads_argument_and_heredoc_forms() {
        let arg = shell::parse("apply_patch '*** Begin Patch\n*** Add File: a\n*** End Patch'");
        assert_eq!(paths(&bash_bodies(&arg).concat()), vec!["a"]);
        let heredoc = shell::parse(
            "applypatch <<'EOF'\n*** Begin Patch\n*** Delete File: b\n*** End Patch\nEOF\n",
        );
        assert_eq!(paths(&bash_bodies(&heredoc).concat()), vec!["b"]);
        let wrapped = shell::parse("bash -c \"apply_patch '*** Add File: c'\"");
        assert_eq!(paths(&bash_bodies(&wrapped).concat()), vec!["c"]);
        let other = shell::parse("cat <<'EOF'\n*** Add File: d\nEOF\n");
        assert!(bash_bodies(&other).is_empty());
    }

    #[test]
    fn paths_ignores_malformed_lines() {
        let command = "*** Begin Patch\n*** Update File:\n*** Move to: \n*** End Patch\n";
        assert_eq!(paths(command).len(), 0);
    }

    #[test]
    fn added_content_extracts_add_file_body() {
        let command = "\
*** Begin Patch
*** Add File: src/notes.md
+line one
+line two
*** End Patch
";
        assert_eq!(added_content(command), Some("line one\nline two".into()));
    }

    #[test]
    fn added_content_skips_context_and_deletion_lines() {
        let command = "\
*** Begin Patch
*** Update File: src/notes.md
 context line
-deleted pem
+added line
*** End Patch
";
        assert_eq!(added_content(command), Some("added line".into()));
    }

    #[test]
    fn added_content_returns_none_without_plus_lines() {
        let command = "*** Begin Patch\n*** Delete File: gone.txt\n*** End Patch\n";
        assert_eq!(added_content(command), None);
    }

    #[test]
    fn added_content_handles_crlf() {
        let command = "*** Begin Patch\r\n*** Add File: x\r\n+hello\r\n*** End Patch\r\n";
        assert_eq!(added_content(command), Some("hello".into()));
    }

    #[test]
    fn added_content_treats_plus_only_line_as_empty_added_line() {
        let command = "*** Begin Patch\n*** Add File: x\n+\n*** End Patch\n";
        assert_eq!(added_content(command), Some(String::new()));
    }

    #[test]
    fn added_content_overapproximates_unified_diff_header() {
        let command = "\
*** Begin Patch
*** Update File: src/x
+++ b/file
+real added
*** End Patch
";
        assert_eq!(added_content(command), Some("++ b/file\nreal added".into()));
    }

    #[test]
    fn paths_and_added_content_do_not_interfere_on_directive_lines() {
        let command = "*** Begin Patch\n+*** Add File: .env\n+API_KEY=1\n*** End Patch\n";
        assert_eq!(paths(command).len(), 0);
        assert_eq!(
            added_content(command),
            Some("*** Add File: .env\nAPI_KEY=1".into())
        );
    }

    fn codex_add_file_patch(path: &str, body: &str) -> String {
        let mut out = format!("*** Begin Patch\n*** Add File: {path}\n");
        for line in body.split('\n') {
            out.push('+');
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("*** End Patch\n");
        out
    }

    fn sensitive_kinds(input: &HookInput) -> HashSet<SensitiveKind> {
        extract(input).sensitive.iter().map(|s| s.kind).collect()
    }

    proptest! {
        #[test]
        fn pbt_added_content_never_panics(command in ".*") {
            let _ = added_content(&command);
        }

        #[test]
        fn pbt_paths_never_panics(command in ".*") {
            let _ = paths(&command);
        }

        #[test]
        fn pbt_codex_add_file_roundtrip(body in "[ -~\\n]{0,120}") {
            let patch = codex_add_file_patch("src/notes.md", &body);
            let extracted = added_content(&patch).expect("add file patch has added lines");
            prop_assert_eq!(extracted, body);
        }

        #[test]
        fn pbt_add_file_sensitive_parity_with_write(body in "[ -~\\n]{0,120}") {
            let patch = codex_add_file_patch("src/notes.md", &body);
            let write = HookInput {
                tool_name: "Write".into(),
                tool_input: serde_json::json!({
                    "file_path": "src/notes.md",
                    "content": body,
                }),
            };
            let apply_patch = HookInput {
                tool_name: "apply_patch".into(),
                tool_input: serde_json::json!({ "command": patch }),
            };
            prop_assert_eq!(sensitive_kinds(&write), sensitive_kinds(&apply_patch));
        }
    }
}
