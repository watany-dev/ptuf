//! Codex `apply_patch` command parsing helpers.

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
    fn paths_ignores_malformed_lines() {
        let command = "*** Begin Patch\n*** Update File:\n*** Move to: \n*** End Patch\n";
        assert!(paths(command).is_empty());
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
        assert!(paths(command).is_empty());
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
