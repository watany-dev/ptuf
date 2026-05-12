//! `core.workspace` v1 — restrict tool I/O to a configured set of
//! workspace boundaries.
//!
//! `outside-access` denies any `Read` / `Edit` / `Write` / `apply_patch`
//! / MCP `path` / Bash redirect target whose canonical destination falls
//! outside the boundary set. The boundary set comes from the engine's
//! `repo_root` plus `packs.core.workspace.additionalWorkspaces` from the
//! merged config.
//!
//! Path resolution applies `canonicalize` to both candidate and
//! boundary so symlinks and `..` traversals are collapsed before the
//! prefix check; non-existent leaves fall back to climbing the ancestor
//! chain (see [`crate::facts::path::resolve_for_containment`]). Prefix
//! matching uses [`std::path::Path::starts_with`] (component-wise) so `/work-evil`
//! cannot impersonate `/work`.
//!
//! The pack ships disabled by default — Read inclusion would otherwise
//! block reads of external libraries (`~/.cargo/registry/...`,
//! `/usr/include`) for projects that have not opted in. Enable via
//! `packs.core.workspace.enabled: true` in `.ptuf.yaml`.

use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::facts::path::{self, PathFact};
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;

const RULE_ID: &str = "core.workspace.outside-access";

pub struct OutsideAccessRule;

pub static OUTSIDE_ACCESS_RULE: OutsideAccessRule = OutsideAccessRule;

impl ConfigRule for OutsideAccessRule {
    fn id(&self) -> &str {
        RULE_ID
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn default_decision(&self) -> DecisionKind {
        DecisionKind::Deny
    }

    fn evaluate(&self, facts: &Facts, _input: &HookInput) -> Option<Decision> {
        if facts.workspaces.is_empty() {
            return None;
        }
        for fact in facts.paths.iter().chain(facts.bash_redirects.iter()) {
            let resolved = path::resolve_for_containment(fact);
            if !path::is_within_workspace(&resolved, &facts.workspaces) {
                return Some(Decision::Deny {
                    rule_id: RULE_ID.into(),
                    reason: build_reason(fact, &resolved, &facts.workspaces),
                });
            }
        }
        None
    }
}

fn build_reason(
    fact: &PathFact,
    resolved: &std::path::Path,
    workspaces: &[std::path::PathBuf],
) -> String {
    let workspace_list = workspaces
        .iter()
        .map(|w| w.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let problem = format!(
        "Path {raw:?} (resolved {resolved}) falls outside the configured workspace \
         boundaries [{workspace_list}]. core.workspace.outside-access blocks reads \
         and writes that escape the project root.",
        raw = fact.raw,
        resolved = resolved.display(),
    );
    reason::build(
        RULE_ID,
        &problem,
        &[
            "Move the file under the project root or a directory listed in \
             packs.core.workspace.additionalWorkspaces.",
            "Add packs.core.workspace.additionalWorkspaces: [<path>] to .ptuf.yaml \
             if this destination is intentionally shared.",
            "Disable the rule for this repo with packs.core.workspace.enabled: false \
             when external access is the norm.",
        ],
    )
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::facts::path::{PathFact, PathOrigin, PathTool};
    use std::path::PathBuf;

    fn read_input(p: &str) -> HookInput {
        HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({ "file_path": p }),
        }
    }

    fn write_input(p: &str) -> HookInput {
        HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({ "file_path": p, "content": "x" }),
        }
    }

    fn facts_with_workspaces(input: &HookInput, workspaces: Vec<PathBuf>) -> Facts {
        // macOS `/var/folders/...` is a symlink to `/private/var/folders/...`.
        // `tempfile::TempDir::path()` returns the un-canonicalized form, but
        // the rule's `PathFact` canonicalizes its target — so the workspace
        // boundary check would compare `/private/var/folders/...` (resolved
        // input) against `/var/folders/...` (workspace) and report a false
        // Deny. Canonicalize each workspace path here so both sides share
        // the same resolved form. Falls back to the original path when the
        // directory does not exist (proptest passes synthetic paths).
        let mut f = crate::facts::extract(input);
        f.workspaces = workspaces
            .into_iter()
            .map(|w| w.canonicalize().unwrap_or(w))
            .collect();
        f
    }

    #[test]
    fn skips_when_no_workspaces_configured() {
        let f = facts_with_workspaces(&read_input("/etc/passwd"), Vec::new());
        let d = OUTSIDE_ACCESS_RULE.evaluate(&f, &read_input("/etc/passwd"));
        assert!(d.is_none(), "no workspace ⇒ skip; got {d:?}");
    }

    #[test]
    fn allows_write_inside_workspace() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let inside = dir.path().join("note.txt");
        let input = write_input(inside.to_str().expect("utf-8"));
        let f = facts_with_workspaces(&input, vec![dir.path().to_path_buf()]);
        let d = OUTSIDE_ACCESS_RULE.evaluate(&f, &input);
        assert!(d.is_none(), "inside ⇒ allow; got {d:?}");
    }

    #[test]
    fn denies_write_outside_workspace() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let input = write_input("/etc/ptuf-must-not-write");
        let f = facts_with_workspaces(&input, vec![dir.path().to_path_buf()]);
        match OUTSIDE_ACCESS_RULE.evaluate(&f, &input) {
            Some(Decision::Deny { rule_id, .. }) => assert_eq!(rule_id, RULE_ID),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn allows_read_inside_workspace() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let inside = dir.path().join("subdir/file.rs");
        let input = read_input(inside.to_str().expect("utf-8"));
        let f = facts_with_workspaces(&input, vec![dir.path().to_path_buf()]);
        assert!(OUTSIDE_ACCESS_RULE.evaluate(&f, &input).is_none());
    }

    #[test]
    fn denies_read_outside_workspace() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let input = read_input("/etc/passwd");
        let f = facts_with_workspaces(&input, vec![dir.path().to_path_buf()]);
        assert!(matches!(
            OUTSIDE_ACCESS_RULE.evaluate(&f, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn denies_bash_redirect_outside_workspace() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": "echo x > /etc/ptuf-redirect-x" }),
        };
        let f = facts_with_workspaces(&input, vec![dir.path().to_path_buf()]);
        assert!(matches!(
            OUTSIDE_ACCESS_RULE.evaluate(&f, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn lookalike_prefix_does_not_satisfy_boundary() {
        // workspace ≠ workspace-evil as a path component prefix, even
        // though `<ws>-evil/x` byte-prefix-matches `<ws>`. Both dirs
        // sit inside the same parent TempDir so RAII cleans them up
        // even on panic.
        let parent = tempfile::TempDir::new().expect("tempdir");
        let workspace = parent.path().join("work");
        let evil_root = parent.path().join("work-evil");
        std::fs::create_dir_all(&workspace).expect("mkdir workspace");
        std::fs::create_dir_all(&evil_root).expect("mkdir evil");
        let evil_target = evil_root.join("payload.txt");
        let input = write_input(evil_target.to_str().expect("utf-8"));
        let f = facts_with_workspaces(&input, vec![workspace]);
        assert!(matches!(
            OUTSIDE_ACCESS_RULE.evaluate(&f, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn dotdot_traversal_resolved_before_check() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let workspace = dir.path().canonicalize().expect("canonicalize");
        // /<ws>/foo/../../etc/passwd ⇒ /etc/passwd after normalization,
        // which lives outside the workspace.
        let traversal = workspace.join("foo/../../etc/passwd");
        let traversal_str = traversal.to_str().expect("utf-8");
        let input = read_input(traversal_str);
        let f = facts_with_workspaces(&input, vec![workspace]);
        assert!(matches!(
            OUTSIDE_ACCESS_RULE.evaluate(&f, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn symlink_inside_workspace_pointing_outside_is_denied() {
        // Use a self-contained outside tempdir as the symlink target rather
        // than an OS-specific path like /etc/hostname: macOS does not ship
        // /etc/hostname by default, which makes the symlink dangling and
        // lets climb-and-canonicalize re-resolve the path back inside the
        // workspace, producing a false Allow.
        let outside_dir = tempfile::TempDir::new().expect("outside tempdir");
        let outside_target = outside_dir.path().join("target");
        std::fs::write(&outside_target, b"x").expect("write outside target");
        let outside_canonical = outside_target
            .canonicalize()
            .expect("canonicalize outside target");

        let dir = tempfile::TempDir::new().expect("tempdir");
        let workspace = dir.path().canonicalize().expect("canonicalize");
        let link = workspace.join("escape");
        std::os::unix::fs::symlink(&outside_canonical, &link).expect("symlink");
        let input = read_input(link.to_str().expect("utf-8"));
        let f = facts_with_workspaces(&input, vec![workspace]);
        assert!(matches!(
            OUTSIDE_ACCESS_RULE.evaluate(&f, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn workspace_root_itself_being_a_symlink_is_followed_for_internal_writes() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let real = dir.path().join("real-root");
        std::fs::create_dir_all(&real).expect("mkdir");
        let alias = dir.path().join("alias-root");
        std::os::unix::fs::symlink(&real, &alias).expect("symlink");
        let canonical_workspace = alias.canonicalize().expect("canonicalize");
        let inside = real.join("note.txt");
        let input = write_input(inside.to_str().expect("utf-8"));
        let f = facts_with_workspaces(&input, vec![canonical_workspace]);
        assert!(OUTSIDE_ACCESS_RULE.evaluate(&f, &input).is_none());
    }

    #[test]
    fn nonexistent_descendant_is_classified_via_existing_ancestor() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let workspace = dir.path().canonicalize().expect("canonicalize");
        // /<ws>/new/nested/dir/x.txt does not exist; the climb-and-canon
        // helper should resolve it via the workspace ancestor and judge
        // it inside.
        let target = workspace.join("new/nested/dir/x.txt");
        let input = write_input(target.to_str().expect("utf-8"));
        let f = facts_with_workspaces(&input, vec![workspace]);
        assert!(OUTSIDE_ACCESS_RULE.evaluate(&f, &input).is_none());
    }

    #[test]
    fn matches_any_of_multiple_workspaces() {
        let a = tempfile::TempDir::new().expect("a");
        let b = tempfile::TempDir::new().expect("b");
        let inside_b = b.path().join("file.txt");
        let input = write_input(inside_b.to_str().expect("utf-8"));
        let f = facts_with_workspaces(&input, vec![a.path().to_path_buf(), b.path().to_path_buf()]);
        assert!(OUTSIDE_ACCESS_RULE.evaluate(&f, &input).is_none());
    }

    #[test]
    fn metadata_matches_design_baseline() {
        let r: &dyn ConfigRule = &OUTSIDE_ACCESS_RULE;
        assert_eq!(r.id(), RULE_ID);
        assert_eq!(r.severity(), Severity::Medium);
        assert_eq!(r.default_decision(), DecisionKind::Deny);
        assert!(r.overridable());
        assert!(!r.hard_deny());
    }

    #[test]
    fn deny_reason_carries_resolved_path_and_workspace_list() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let workspace = dir.path().canonicalize().expect("canonicalize");
        let input = write_input("/etc/ptuf-test-outside-write");
        let f = facts_with_workspaces(&input, vec![workspace.clone()]);
        let Some(Decision::Deny { reason, .. }) = OUTSIDE_ACCESS_RULE.evaluate(&f, &input) else {
            panic!("expected Deny");
        };
        assert!(reason.contains("/etc/ptuf-test-outside-write"));
        assert!(reason.contains(&workspace.display().to_string()));
        assert!(reason.contains(RULE_ID));
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pbt_no_panic_with_arbitrary_inputs(
            input in crate::testing::proptest::richer_hook_input(),
            ws_count in 0usize..=3usize,
        ) {
            let workspaces: Vec<PathBuf> = (0..ws_count)
                .map(|i| PathBuf::from(format!("/tmp/ptuf-pbt-ws-{i}")))
                .collect();
            let mut facts = crate::facts::extract(&input);
            facts.workspaces = workspaces;
            let _ = OUTSIDE_ACCESS_RULE.evaluate(&facts, &input);
        }

        #[test]
        fn pbt_empty_workspaces_always_skip(
            input in crate::testing::proptest::richer_hook_input(),
        ) {
            let facts = crate::facts::extract(&input);
            // facts.workspaces left empty — the engine never injected a boundary.
            prop_assert!(OUTSIDE_ACCESS_RULE.evaluate(&facts, &input).is_none());
        }

        #[test]
        fn pbt_outside_path_is_denied(
            // Pin to a known outside path; randomise the rest of the
            // payload so the rule's path-only check is still covered
            // for varied tool names.
            tool in prop::sample::select(vec!["Read", "Write", "Edit"]),
        ) {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let input = HookInput {
                tool_name: tool.into(),
                tool_input: serde_json::json!({
                    "file_path": "/etc/ptuf-pbt-outside-path",
                    "content": "x",
                }),
            };
            let mut facts = crate::facts::extract(&input);
            facts.workspaces = vec![dir.path().to_path_buf()];
            let d = OUTSIDE_ACCESS_RULE.evaluate(&facts, &input);
            let is_deny = matches!(d, Some(Decision::Deny { .. }));
            prop_assert!(is_deny);
        }

        #[test]
        fn pbt_inside_path_is_allowed(
            tool in prop::sample::select(vec!["Read", "Write", "Edit"]),
            tail in "[a-z][a-z0-9_]{0,16}",
        ) {
            let dir = tempfile::TempDir::new().expect("tempdir");
            // Canonicalize for macOS /var/folders → /private/var/folders
            // parity with the rule's PathFact resolution.
            let workspace = dir.path().canonicalize().expect("canonicalize");
            let inside = workspace.join(&tail);
            let input = HookInput {
                tool_name: tool.into(),
                tool_input: serde_json::json!({
                    "file_path": inside.to_str().expect("utf-8"),
                    "content": "x",
                }),
            };
            let mut facts = crate::facts::extract(&input);
            facts.workspaces = vec![workspace];
            let allowed = OUTSIDE_ACCESS_RULE.evaluate(&facts, &input).is_none();
            prop_assert!(allowed);
        }
    }

    // Re-export PathFact / PathOrigin / PathTool so the proptest module
    // can build hand-crafted facts when needed without touching other
    // crates' visibility.
    #[allow(dead_code)]
    type _Reexport = (PathFact, PathOrigin, PathTool);
}
