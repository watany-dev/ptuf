//! `Read` / `Edit` / `Write` `file_path` extraction with `~` expansion.
//!
//! Expansion uses the [`crate::config::scope::EnvLookup`] trait so tests
//! can inject a hermetic `HOME` (and the production path delegates to
//! [`crate::config::scope::SystemEnv`]).

use std::path::{Component, Path, PathBuf};

use crate::config::scope::{EnvLookup, SystemEnv};
use crate::facts::shell::{Bash, Redirect, RedirectOp};
use crate::hook_input::HookInput;

/// Tools whose payload exposes a `file_path` field that ptuf inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathTool {
    Read,
    Edit,
    Write,
    ApplyPatch,
    /// Any `mcp__<server>__<tool>` call that exposed a top-level
    /// `path` string. Treated like a write-capable tool by self-protection
    /// rules so MCP-driven edits cannot bypass the file allowlist.
    Mcp,
}

/// Source carrier that produced a [`PathFact`].
///
/// Distinguishes top-level tool inputs (`file_path`, MCP `path`) from
/// nested inputs (`files[].path`, `paths[]`, `items[].path`),
/// `apply_patch` patch lines, and Bash redirect targets. Rules and
/// self-protection use this to decide whether a path is a write
/// destination (and therefore eligible for guardrail checks) or merely
/// a read reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathOrigin {
    /// Top-level `file_path` (Read/Edit/Write) or top-level MCP `path`.
    ToolInputDirect,
    /// Nested MCP carriers: `files[].path`, `items[].path`, `paths[]`.
    ToolInputNested,
    /// `apply_patch` `*** Add/Update/Delete/Move` lines.
    ApplyPatch,
    /// Bash redirect operand (`>`, `>>`, `<`, `2>`, `&>`). Surfaced
    /// only by the engine — never emitted by [`extract_all_with_env`]
    /// because Bash inputs do not carry a tool-level `file_path`.
    BashRedirect,
}

/// File-path fact derived from a tool payload.
///
/// Preserves the source string (`raw`), the env-expanded form
/// (`expanded`), the absolutised form (`absolute`), and a best-effort
/// canonicalised form (`canonical_or_raw`) so self-protection,
/// file-tool, and Bash redirect classification all see the same view.
/// `canonical_or_raw` falls back to `absolute` for any I/O failure
/// (missing file, permission denied, symlink loop) so consumers never
/// have to handle `Option`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathFact {
    pub tool: PathTool,
    /// The string exactly as it appeared in the tool payload.
    pub raw: String,
    /// `~` / `$HOME` / `${HOME}` expanded against the supplied env.
    /// Falls back to `raw` when `HOME` is unset.
    pub expanded: PathBuf,
    /// `expanded` joined onto `base_dir` when relative; identical to
    /// `expanded` when already absolute or no `base_dir` is supplied.
    pub absolute: PathBuf,
    /// `absolute.canonicalize()` on success, otherwise a clone of
    /// `absolute`. Symlinks are collapsed when filesystem state allows.
    pub canonical_or_raw: PathBuf,
    /// Source carrier this fact was extracted from.
    pub origin: PathOrigin,
}

/// Backward-compatible alias kept so call sites that reference the
/// historical `FilePath` name continue to compile. New code should
/// prefer [`PathFact`].
pub type FilePath = PathFact;

/// Expand `~` / `$HOME` forms and, when requested, resolve a relative
/// path against `base_dir`.
pub(crate) fn resolve_with_env(raw: &str, base_dir: Option<&Path>, env: &dyn EnvLookup) -> PathBuf {
    let expanded = expand_home(raw, env);
    if expanded.is_relative()
        && let Some(base) = base_dir
    {
        return base.join(expanded);
    }
    expanded
}

/// Build all visible [`PathFact`]s using the supplied env lookup. The
/// `facts::extract` default path uses [`SystemEnv`]; tests inject a
/// `MapEnv` to verify `~` expansion deterministically.
///
/// MCP tool calls (`mcp__<server>__<tool>`) are normalised on generic
/// path carriers, including `path`, `paths[]`, `files[].path`, and
/// `items[].path`.
pub fn extract_all_with_env(input: &HookInput, env: &dyn EnvLookup) -> Vec<PathFact> {
    let (tool, tagged): (PathTool, Vec<(String, PathOrigin)>) = match input.tool_name.as_str() {
        "Read" | "Edit" | "Write" => {
            let tool = match input.tool_name.as_str() {
                "Read" => PathTool::Read,
                "Edit" => PathTool::Edit,
                _ => PathTool::Write,
            };
            let values = input
                .tool_input
                .get("file_path")
                .and_then(serde_json::Value::as_str)
                .map(|raw| (raw.to_owned(), PathOrigin::ToolInputDirect))
                .into_iter()
                .collect();
            (tool, values)
        },
        "apply_patch" => {
            let values = input
                .tool_input
                .get("command")
                .and_then(serde_json::Value::as_str)
                .map(collect_apply_patch_paths)
                .unwrap_or_default()
                .into_iter()
                .map(|raw| (raw, PathOrigin::ApplyPatch))
                .collect();
            (PathTool::ApplyPatch, values)
        },
        _ if input.is_mcp_tool() => (PathTool::Mcp, collect_mcp_paths(&input.tool_input)),
        _ => return Vec::new(),
    };
    tagged
        .into_iter()
        .map(|(raw, origin)| PathFact::from_raw(raw, tool, origin, None, env))
        .collect()
}

/// Compatibility helper: extract the first visible path with the supplied env.
pub fn extract_with_env(input: &HookInput, env: &dyn EnvLookup) -> Option<FilePath> {
    extract_all_with_env(input, env).into_iter().next()
}

/// Convenience: extract the first visible path using the production
/// environment.
pub fn extract(input: &HookInput) -> Option<FilePath> {
    extract_all_with_env(input, &SystemEnv).into_iter().next()
}

/// Convenience: extract every visible path using the production environment.
pub fn extract_all(input: &HookInput) -> Vec<FilePath> {
    extract_all_with_env(input, &SystemEnv)
}

fn collect_mcp_paths(value: &serde_json::Value) -> Vec<(String, PathOrigin)> {
    let mut out = Vec::new();
    push_tagged(value.get("path"), PathOrigin::ToolInputDirect, &mut out);
    for key in ["files", "items"] {
        if let Some(items) = value.get(key).and_then(serde_json::Value::as_array) {
            for item in items {
                push_tagged(item.get("path"), PathOrigin::ToolInputNested, &mut out);
            }
        }
    }
    if let Some(paths) = value.get("paths").and_then(serde_json::Value::as_array) {
        for item in paths {
            push_tagged(Some(item), PathOrigin::ToolInputNested, &mut out);
        }
    }
    out
}

fn push_tagged(
    value: Option<&serde_json::Value>,
    origin: PathOrigin,
    out: &mut Vec<(String, PathOrigin)>,
) {
    if let Some(s) = value.and_then(serde_json::Value::as_str) {
        out.push((s.to_owned(), origin));
    }
}

fn collect_apply_patch_paths(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in command.lines() {
        for prefix in [
            "*** Add File: ",
            "*** Update File: ",
            "*** Delete File: ",
            "*** Move to: ",
        ] {
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

/// Resolve a [`PathFact`] to the form used by workspace-containment
/// checks. When [`PathFact::canonical_or_raw`] differs from
/// [`PathFact::absolute`] we trust the canonicalisation (symlinks
/// already resolved); otherwise we climb the path until an existing
/// ancestor canonicalises, reattach the missing tail, and resolve any
/// remaining `..` components manually.
pub fn resolve_for_containment(fact: &PathFact) -> PathBuf {
    if fact.canonical_or_raw != fact.absolute {
        return fact.canonical_or_raw.clone();
    }
    climb_and_canonicalize(&fact.absolute)
}

/// True iff `target` is identical to or a descendant (component-wise)
/// of any path in `workspaces`. Both sides are expected to be canonical
/// or normalised to the same form.
pub fn is_within_workspace(target: &Path, workspaces: &[PathBuf]) -> bool {
    workspaces.iter().any(|w| target.starts_with(w))
}

/// Resolve `.` and `..` components without touching the filesystem.
/// Used as a final pass on paths whose tail does not exist on disk and
/// therefore cannot be canonicalised by the OS. `..` at the root or in
/// front of a `RootDir` component is a no-op (`PathBuf::pop` returns
/// false), matching POSIX semantics.
pub fn normalize_components(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {},
            Component::ParentDir => {
                let _ = out.pop();
            },
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn climb_and_canonicalize(abs: &Path) -> PathBuf {
    let mut current = abs.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(canon) = current.canonicalize() {
            let mut rebuilt = canon;
            for name in tail.iter().rev() {
                rebuilt.push(name);
            }
            return normalize_components(&rebuilt);
        }
        let Some(name) = current.file_name().map(std::ffi::OsStr::to_os_string) else {
            break;
        };
        tail.push(name);
        if !current.pop() {
            break;
        }
    }
    normalize_components(abs)
}

impl PathFact {
    /// Build a [`PathFact`] from a raw path string and its source
    /// metadata. Resolves expansion, absolutisation, and a best-effort
    /// canonicalisation in one pass. Public so the engine can produce
    /// [`PathOrigin::BashRedirect`] facts from parsed Bash pipelines.
    pub fn from_raw(
        raw: String,
        tool: PathTool,
        origin: PathOrigin,
        base_dir: Option<&Path>,
        env: &dyn EnvLookup,
    ) -> Self {
        let expanded = expand_home(&raw, env);
        let absolute = resolve_with_env(&raw, base_dir, env);
        let canonical_or_raw = absolute.canonicalize().unwrap_or_else(|_| absolute.clone());
        Self {
            tool,
            raw,
            expanded,
            absolute,
            canonical_or_raw,
            origin,
        }
    }
}

/// Build [`PathFact`]s for every Bash redirect target that points at a
/// file (`>`, `>>`, `<`, `2>`, `&>`). Heredoc bodies are skipped because
/// the target carries the body text rather than a path. The facts are
/// tagged with [`PathOrigin::BashRedirect`] so self-protection can treat
/// them as write destinations without polluting `Facts.paths`, which the
/// plugin DSL relies on to mean "tool-input-derived path".
///
/// Relative redirect targets are resolved against `repo_root` when one
/// is known; `~` and `$HOME` are expanded against the production
/// environment so `> ~/.claude/settings.json` hits the `ClaudeSettings`
/// guardrail.
pub fn from_bash_redirects(bash: Option<&Bash>, repo_root: Option<&Path>) -> Vec<PathFact> {
    let Some(bash) = bash else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_bash_redirects(bash, repo_root, &mut out);
    out
}

fn collect_bash_redirects(bash: &Bash, repo_root: Option<&Path>, out: &mut Vec<PathFact>) {
    for pipeline in &bash.segments {
        for redirect in &pipeline.redirects {
            push_redirect_fact(redirect, repo_root, out);
        }
        for command in &pipeline.commands {
            collect_command_redirects(command, repo_root, out);
        }
    }
}

fn collect_command_redirects(
    command: &crate::facts::shell::Argv,
    repo_root: Option<&Path>,
    out: &mut Vec<PathFact>,
) {
    for redirect in &command.inner_redirects {
        push_redirect_fact(redirect, repo_root, out);
    }
    for nested in &command.inner_argv {
        collect_command_redirects(nested, repo_root, out);
    }
}

fn push_redirect_fact(redirect: &Redirect, repo_root: Option<&Path>, out: &mut Vec<PathFact>) {
    if matches!(redirect.op, RedirectOp::Heredoc) {
        return;
    }
    if redirect.target.is_empty() {
        return;
    }
    out.push(PathFact::from_raw(
        redirect.target.clone(),
        PathTool::Write,
        PathOrigin::BashRedirect,
        repo_root,
        &SystemEnv,
    ));
}

/// Expand `~` / `$HOME` / `${HOME}` prefixes against the supplied env
/// lookup. Falls back to the raw string when `HOME` is unset. Made
/// `pub(crate)` so the engine can reuse it for additional-workspace
/// resolution.
pub(crate) fn expand_home(raw: &str, env: &dyn EnvLookup) -> PathBuf {
    let Some(home_os) = env.var_os("HOME") else {
        return PathBuf::from(raw);
    };
    let home = PathBuf::from(home_os);
    if let Some(rest) = raw.strip_prefix("~/") {
        return home.join(rest);
    }
    if raw == "~" {
        return home;
    }
    if let Some(rest) = raw.strip_prefix("$HOME/") {
        return home.join(rest);
    }
    if raw == "$HOME" {
        return home;
    }
    if let Some(rest) = raw.strip_prefix("${HOME}/") {
        return home.join(rest);
    }
    if raw == "${HOME}" {
        return home;
    }
    PathBuf::from(raw)
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;

    struct MapEnv(HashMap<String, OsString>);

    impl MapEnv {
        fn with_home(home: &str) -> Self {
            let mut m = HashMap::new();
            m.insert("HOME".to_string(), OsString::from(home));
            Self(m)
        }
        fn empty() -> Self {
            Self(HashMap::new())
        }
    }

    impl EnvLookup for MapEnv {
        fn var_os(&self, key: &str) -> Option<OsString> {
            self.0.get(key).cloned()
        }
    }

    fn input(tool: &str, file_path: serde_json::Value) -> HookInput {
        HookInput {
            tool_name: tool.into(),
            tool_input: serde_json::json!({ "file_path": file_path }),
        }
    }

    #[test]
    fn extracts_read_file_path() {
        let i = input("Read", serde_json::json!("/tmp/x.txt"));
        let fp = extract_with_env(&i, &MapEnv::with_home("/h")).unwrap();
        assert_eq!(fp.tool, PathTool::Read);
        assert_eq!(fp.raw, "/tmp/x.txt");
        assert_eq!(fp.absolute, PathBuf::from("/tmp/x.txt"));
    }

    #[test]
    fn extracts_edit_and_write() {
        let e = input("Edit", serde_json::json!("/etc/hosts"));
        let w = input("Write", serde_json::json!("/etc/hosts"));
        assert_eq!(
            extract_with_env(&e, &MapEnv::with_home("/h")).unwrap().tool,
            PathTool::Edit
        );
        assert_eq!(
            extract_with_env(&w, &MapEnv::with_home("/h")).unwrap().tool,
            PathTool::Write
        );
    }

    #[test]
    fn returns_none_for_unknown_tool() {
        let i = input("Bash", serde_json::json!("/x"));
        assert!(extract_with_env(&i, &MapEnv::with_home("/h")).is_none());
    }

    #[test]
    fn returns_none_when_field_missing_or_non_string() {
        let i = HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({}),
        };
        assert!(extract_with_env(&i, &MapEnv::with_home("/h")).is_none());
        let j = input("Read", serde_json::json!(123));
        assert!(extract_with_env(&j, &MapEnv::with_home("/h")).is_none());
    }

    #[test]
    fn expands_tilde_to_home() {
        let i = input("Read", serde_json::json!("~/.ssh/id_rsa"));
        let fp = extract_with_env(&i, &MapEnv::with_home("/home/me")).unwrap();
        assert_eq!(fp.absolute, PathBuf::from("/home/me/.ssh/id_rsa"));
    }

    #[test]
    fn expands_lone_tilde() {
        let i = input("Read", serde_json::json!("~"));
        let fp = extract_with_env(&i, &MapEnv::with_home("/home/me")).unwrap();
        assert_eq!(fp.absolute, PathBuf::from("/home/me"));
    }

    #[test]
    fn expands_home_envvar_forms() {
        for raw in ["$HOME/.ssh/id", "${HOME}/.ssh/id"] {
            let i = input("Read", serde_json::json!(raw));
            let fp = extract_with_env(&i, &MapEnv::with_home("/h")).unwrap();
            assert_eq!(fp.absolute, PathBuf::from("/h/.ssh/id"));
        }
    }

    #[test]
    fn lone_home_envvar_expands() {
        for raw in ["$HOME", "${HOME}"] {
            let i = input("Read", serde_json::json!(raw));
            let fp = extract_with_env(&i, &MapEnv::with_home("/h")).unwrap();
            assert_eq!(fp.absolute, PathBuf::from("/h"));
        }
    }

    #[test]
    fn falls_back_to_raw_when_home_unset() {
        let i = input("Read", serde_json::json!("~/.ssh/id"));
        let fp = extract_with_env(&i, &MapEnv::empty()).unwrap();
        assert_eq!(fp.absolute, PathBuf::from("~/.ssh/id"));
    }

    #[test]
    fn path_fact_canonical_falls_back_to_absolute_when_missing() {
        // `canonical_or_raw` is total: for any absolute path that does
        // not exist on disk it equals `absolute` rather than panicking
        // or yielding an empty `PathBuf`.
        let i = input(
            "Read",
            serde_json::json!("/ptuf-nonexistent-path/most-likely-missing"),
        );
        let fp = extract_with_env(&i, &MapEnv::with_home("/h")).expect("path");
        assert_eq!(fp.canonical_or_raw, fp.absolute);
        assert_eq!(
            fp.canonical_or_raw,
            PathBuf::from("/ptuf-nonexistent-path/most-likely-missing")
        );
    }

    #[test]
    fn path_fact_origin_distinguishes_apply_patch_from_direct() {
        let direct = input("Edit", serde_json::json!("/tmp/x"));
        let direct_fp = extract_with_env(&direct, &MapEnv::with_home("/h")).expect("path");
        assert_eq!(direct_fp.origin, PathOrigin::ToolInputDirect);

        let patched = HookInput {
            tool_name: "apply_patch".into(),
            tool_input: serde_json::json!({
                "command": "*** Begin Patch\n*** Add File: x\n*** End Patch\n"
            }),
        };
        let patch_fp = extract_with_env(&patched, &MapEnv::with_home("/h")).expect("path");
        assert_eq!(patch_fp.origin, PathOrigin::ApplyPatch);
    }

    #[test]
    fn path_fact_mcp_nested_origin_is_nested() {
        let i = HookInput {
            tool_name: "mcp__github__push_files".into(),
            tool_input: serde_json::json!({
                "files": [{"path": "/tmp/nested"}],
            }),
        };
        let paths = extract_all_with_env(&i, &MapEnv::with_home("/h"));
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].origin, PathOrigin::ToolInputNested);
    }

    #[test]
    fn extract_uses_system_env_lookup() {
        // Just exercise the production path: should not panic and
        // should treat an absolute path as identity.
        let i = input("Read", serde_json::json!("/tmp/sample"));
        let fp = extract(&i).unwrap();
        assert_eq!(fp.raw, "/tmp/sample");
    }

    #[test]
    fn extract_mcp_tool_uses_top_level_path_key() {
        let i = HookInput {
            tool_name: "mcp__github__create_or_update_file".into(),
            tool_input: serde_json::json!({"path": ".claude/settings.json"}),
        };
        let fp = extract_with_env(&i, &MapEnv::with_home("/h")).expect("path");
        assert_eq!(fp.tool, PathTool::Mcp);
        assert_eq!(fp.raw, ".claude/settings.json");
    }

    #[test]
    fn extract_all_collects_nested_mcp_paths() {
        let i = HookInput {
            tool_name: "mcp__github__push_files".into(),
            tool_input: serde_json::json!({
                "files": [{"path": "~/.claude/settings.json"}, {"path": "/tmp/a"}],
                "items": [{"path": "/tmp/b"}],
                "paths": ["/tmp/c"]
            }),
        };
        let paths = extract_all_with_env(&i, &MapEnv::with_home("/h"));
        let raws: Vec<_> = paths.iter().map(|p| p.raw.as_str()).collect();
        assert_eq!(
            raws,
            vec!["~/.claude/settings.json", "/tmp/a", "/tmp/b", "/tmp/c"]
        );
    }

    #[test]
    fn extract_mcp_tool_returns_none_when_path_missing() {
        let i = HookInput {
            tool_name: "mcp__filesystem__write_file".into(),
            tool_input: serde_json::json!({"content": "hi"}),
        };
        assert!(extract_with_env(&i, &MapEnv::with_home("/h")).is_none());
    }

    #[test]
    fn extract_mcp_tool_returns_none_when_path_is_not_string() {
        let i = HookInput {
            tool_name: "mcp__filesystem__write_file".into(),
            tool_input: serde_json::json!({"path": 7}),
        };
        assert!(extract_with_env(&i, &MapEnv::with_home("/h")).is_none());
    }

    #[test]
    fn extract_apply_patch_collects_add_update_delete_and_move_paths() {
        let i = HookInput {
            tool_name: "apply_patch".into(),
            tool_input: serde_json::json!({
                "command": "\
            *** Begin Patch\n\
            *** Add File: new.txt\n\
            *** Update File: old.txt\n\
            *** Move to: renamed.txt\n\
            *** Delete File: gone.txt\n\
            *** End Patch\n"
            }),
        };
        let paths = extract_all_with_env(&i, &MapEnv::with_home("/h"));
        let raws: Vec<_> = paths.iter().map(|p| p.raw.as_str()).collect();
        assert_eq!(raws, vec!["new.txt", "old.txt", "renamed.txt", "gone.txt"]);
        assert!(paths.iter().all(|p| p.tool == PathTool::ApplyPatch));
    }

    #[test]
    fn extract_apply_patch_ignores_malformed_lines() {
        let i = HookInput {
            tool_name: "apply_patch".into(),
            tool_input: serde_json::json!({
                "command": "*** Begin Patch\n*** Update File:\n*** Move to: \n*** End Patch\n"
            }),
        };
        assert!(extract_all_with_env(&i, &MapEnv::with_home("/h")).is_empty());
    }

    #[test]
    fn extract_mcp_tool_expands_home_in_raw_path() {
        let i = HookInput {
            tool_name: "mcp__filesystem__read_file".into(),
            tool_input: serde_json::json!({"path": "~/.aws/credentials"}),
        };
        let fp = extract_with_env(&i, &MapEnv::with_home("/home/me")).expect("path");
        assert_eq!(fp.absolute, PathBuf::from("/home/me/.aws/credentials"));
    }

    #[test]
    fn from_bash_redirects_returns_empty_for_none_bash() {
        assert!(from_bash_redirects(None, None).is_empty());
    }

    #[test]
    fn from_bash_redirects_returns_empty_when_no_redirects() {
        let bash = crate::facts::shell::parse("ls -la");
        assert!(from_bash_redirects(Some(&bash), None).is_empty());
    }

    #[test]
    fn from_bash_redirects_skips_heredoc_target() {
        // Heredoc bodies live in `Redirect.target` and must not be
        // misinterpreted as a path.
        let bash = crate::facts::shell::parse("cat <<EOF\nhello\nEOF\n");
        assert!(from_bash_redirects(Some(&bash), None).is_empty());
    }

    #[test]
    fn from_bash_redirects_emits_for_each_redirect_op() {
        // `>`, `>>`, `<`, `2>`, `&>` all surface as a `BashRedirect`
        // PathFact tagged as a `Write` destination.
        for cmd in [
            "echo hi > out.txt",
            "echo hi >> out.txt",
            "sh < script.sh",
            "cmd 2> err.log",
            "cmd &> all.log",
        ] {
            let bash = crate::facts::shell::parse(cmd);
            let facts = from_bash_redirects(Some(&bash), None);
            assert_eq!(facts.len(), 1, "expected one fact for {cmd:?}");
            assert_eq!(facts[0].tool, PathTool::Write);
            assert_eq!(facts[0].origin, PathOrigin::BashRedirect);
        }
    }

    #[test]
    fn from_bash_redirects_resolves_relative_against_repo_root() {
        let bash = crate::facts::shell::parse("echo y > .claude/settings.json");
        let facts = from_bash_redirects(Some(&bash), Some(Path::new("/repo")));
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0].absolute,
            PathBuf::from("/repo/.claude/settings.json")
        );
        assert_eq!(facts[0].raw, ".claude/settings.json");
    }

    #[test]
    fn normalize_components_resolves_dot_and_dotdot() {
        let p = PathBuf::from("/a/b/./c/../d");
        assert_eq!(normalize_components(&p), PathBuf::from("/a/b/d"));
    }

    #[test]
    fn normalize_components_dotdot_at_root_is_noop() {
        let p = PathBuf::from("/../etc/passwd");
        assert_eq!(normalize_components(&p), PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn normalize_components_preserves_relative() {
        let p = PathBuf::from("a/./b/../c");
        assert_eq!(normalize_components(&p), PathBuf::from("a/c"));
    }

    #[test]
    fn is_within_workspace_uses_component_prefix_not_byte_prefix() {
        let ws = vec![PathBuf::from("/work")];
        assert!(is_within_workspace(Path::new("/work/src/x.rs"), &ws));
        assert!(is_within_workspace(Path::new("/work"), &ws));
        // Lookalike prefix `/work-evil` must NOT match `/work`.
        assert!(!is_within_workspace(Path::new("/work-evil/secret"), &ws));
        assert!(!is_within_workspace(Path::new("/etc/passwd"), &ws));
    }

    #[test]
    fn is_within_workspace_empty_list_rejects_everything() {
        assert!(!is_within_workspace(Path::new("/work/x"), &[]));
    }

    #[test]
    fn resolve_for_containment_uses_canonical_when_available() {
        // When canonical_or_raw differs from absolute, that's the
        // symlink-resolved physical path and we trust it.
        let dir = std::env::temp_dir().join(format!(
            "ptuf-resolve-canon-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let real = dir.join("real.txt");
        std::fs::write(&real, "hi").expect("write");
        let fact = PathFact::from_raw(
            real.to_string_lossy().into_owned(),
            PathTool::Read,
            PathOrigin::ToolInputDirect,
            None,
            &MapEnv::with_home("/h"),
        );
        let resolved = resolve_for_containment(&fact);
        assert_eq!(resolved, real.canonicalize().expect("canon"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_for_containment_climbs_for_nonexistent_tail() {
        // For a path whose tail doesn't exist, climb until an ancestor
        // canonicalises, then reattach the tail.
        let dir = std::env::temp_dir().join(format!(
            "ptuf-resolve-climb-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let target = dir.join("does/not/exist.txt");
        let fact = PathFact::from_raw(
            target.to_string_lossy().into_owned(),
            PathTool::Write,
            PathOrigin::ToolInputDirect,
            None,
            &MapEnv::with_home("/h"),
        );
        let resolved = resolve_for_containment(&fact);
        let expected = dir
            .canonicalize()
            .expect("canon")
            .join("does/not/exist.txt");
        assert_eq!(resolved, expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_for_containment_resolves_dotdot_in_nonexistent_tail() {
        // A `..` in a non-existent path is resolved by normalize_components,
        // protecting us from `/work/../etc/passwd`-style traversal even
        // when nothing on disk lets canonicalize collapse it.
        let fact = PathFact {
            tool: PathTool::Read,
            raw: "/ptuf-nonexist/work/../etc/passwd".into(),
            expanded: PathBuf::from("/ptuf-nonexist/work/../etc/passwd"),
            absolute: PathBuf::from("/ptuf-nonexist/work/../etc/passwd"),
            canonical_or_raw: PathBuf::from("/ptuf-nonexist/work/../etc/passwd"),
            origin: PathOrigin::ToolInputDirect,
        };
        let resolved = resolve_for_containment(&fact);
        assert_eq!(resolved, PathBuf::from("/ptuf-nonexist/etc/passwd"));
    }

    use crate::testing::proptest::{file_path, richer_hook_input};
    use proptest::prelude::*;

    proptest! {
        // The extractor never panics for arbitrary HookInput shapes.
        #[test]
        fn pbt_extract_never_panics(i in richer_hook_input()) {
            let _ = extract_with_env(&i, &MapEnv::with_home("/h"));
            let _ = extract(&i);
        }

        // Tools other than Read/Edit/Write/MCP always yield None, even with
        // a file_path field present. The regex `[A-Z][A-Za-z]{0,8}` only
        // produces uppercase-leading names, so `mcp__*` is excluded by
        // construction and we don't need an extra prop_assume for it.
        #[test]
        fn pbt_non_path_tool_yields_none(
            tool in "[A-Z][A-Za-z]{0,8}",
            fp in file_path(),
        ) {
            prop_assume!(!matches!(tool.as_str(), "Read" | "Edit" | "Write"));
            let i = HookInput {
                tool_name: tool,
                tool_input: serde_json::json!({ "file_path": fp }),
            };
            prop_assert!(extract_with_env(&i, &MapEnv::with_home("/h")).is_none());
        }

        // Read/Edit/Write tools with a string file_path always extract,
        // and the .raw field round-trips the input verbatim.
        #[test]
        fn pbt_path_tool_round_trips_raw(
            tool in proptest::sample::select(&["Read", "Edit", "Write"][..]),
            fp in file_path(),
        ) {
            let i = HookInput {
                tool_name: tool.to_string(),
                tool_input: serde_json::json!({ "file_path": fp.clone() }),
            };
            let out = extract_with_env(&i, &MapEnv::with_home("/h")).expect("path");
            prop_assert_eq!(out.raw, fp);
        }

        // Absolute paths (starting with `/`) are returned identically as
        // the absolute form — `~`/`$HOME` expansion is a no-op for them.
        #[test]
        fn pbt_absolute_paths_are_identity(
            tool in proptest::sample::select(&["Read", "Edit", "Write"][..]),
            tail in "[a-zA-Z0-9_./-]{0,20}",
        ) {
            let raw = format!("/{tail}");
            let i = HookInput {
                tool_name: tool.to_string(),
                tool_input: serde_json::json!({ "file_path": raw.clone() }),
            };
            let out = extract_with_env(&i, &MapEnv::with_home("/h")).expect("path");
            prop_assert_eq!(out.absolute, PathBuf::from(raw));
        }

        // `~/` prefix always expands to `<home>/...` when HOME is set.
        #[test]
        fn pbt_tilde_prefix_expands_to_home(
            tail in "[a-zA-Z0-9_./-]{0,20}",
            home in "/(?:home|h)/[a-z0-9_]{1,8}",
        ) {
            let raw = format!("~/{tail}");
            let i = HookInput {
                tool_name: "Read".into(),
                tool_input: serde_json::json!({ "file_path": raw }),
            };
            let env = MapEnv::with_home(&home);
            let out = extract_with_env(&i, &env).expect("path");
            prop_assert_eq!(out.absolute, PathBuf::from(home).join(tail));
        }

        // When HOME is unset, ~ paths fall back to the raw form rather
        // than panicking or producing a partial expansion.
        #[test]
        fn pbt_no_home_falls_back_to_raw(tail in "[a-zA-Z0-9_./-]{0,20}") {
            let raw = format!("~/{tail}");
            let i = HookInput {
                tool_name: "Read".into(),
                tool_input: serde_json::json!({ "file_path": raw.clone() }),
            };
            let out = extract_with_env(&i, &MapEnv::empty()).expect("path");
            prop_assert_eq!(out.absolute, PathBuf::from(raw));
        }
    }
}
