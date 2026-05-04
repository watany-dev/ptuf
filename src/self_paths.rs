//! Self-protection target paths and labels.
//!
//! [`ProtectedPaths`] is built once per [`crate::engine::Engine`] from
//! the resolved config + repo root and consulted by the engine's
//! `decide` to populate [`crate::facts::Facts::protected`]. The actual
//! `core.self_protection.*` rules live in `crate::rules::self_protection`.

use std::path::{Path, PathBuf};

use crate::config::scope::{EnvLookup, SystemEnv, layout_for};
use crate::config::{Config, repo};
use crate::hook_input::HookInput;

/// Categories of protected target. Paired with a path on every
/// [`crate::facts::Facts::protected`] entry so rules can produce specific reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedKind {
    Binary,
    Config,
    Plugin,
    ClaudeSettings,
    HookScript,
}

impl ProtectedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Config => "config",
            Self::Plugin => "plugin",
            Self::ClaudeSettings => "claude_settings",
            Self::HookScript => "hook_script",
        }
    }
}

/// Resolved set of paths whose modification ptuf treats as a
/// guardrail-bypass attempt.
#[derive(Debug, Clone, Default)]
pub struct ProtectedPaths {
    pub binary: Option<PathBuf>,
    pub configs: Vec<PathBuf>,
    pub plugins: Vec<PathBuf>,
    pub claude_settings: Vec<PathBuf>,
    pub hook_scripts: Vec<PathBuf>,
}

impl ProtectedPaths {
    /// Build the protected set from the resolved engine state.
    pub fn collect(repo_root: Option<&Path>, config: &Config) -> Self {
        Self::collect_with_env(repo_root, config, &SystemEnv)
    }

    /// Hermetic variant used by tests; collapses to [`Self::collect`]
    /// in production via the [`SystemEnv`] lookup.
    pub fn collect_with_env(
        repo_root: Option<&Path>,
        config: &Config,
        env: &dyn EnvLookup,
    ) -> Self {
        let layout = layout_for(repo_root, env);
        let mut configs: Vec<PathBuf> = layout.ordered_paths();
        // Deduplicate while preserving order.
        configs.sort();
        configs.dedup();

        let mut claude_settings: Vec<PathBuf> = Vec::new();
        if let Some(root) = repo_root {
            claude_settings.push(root.join(".claude/settings.json"));
            claude_settings.push(root.join(".claude/settings.local.json"));
        }
        if let Some(home_os) = env.var_os("HOME") {
            let home = PathBuf::from(home_os);
            claude_settings.push(home.join(".claude/settings.json"));
        }
        claude_settings.sort();
        claude_settings.dedup();

        Self {
            binary: std::env::current_exe().ok(),
            configs,
            plugins: config.plugin_paths.clone(),
            claude_settings,
            hook_scripts: Vec::new(),
        }
    }

    /// Classify a `HookInput` against the protected set, returning the
    /// matched labels. Empty slice means "no self-protection match".
    pub fn classify_input(&self, input: &HookInput) -> Vec<ProtectedKind> {
        let mut out = Vec::new();
        let candidates = candidate_targets(input);
        for cand in &candidates {
            if let Some(kind) = self.match_path(cand)
                && !out.contains(&kind)
            {
                out.push(kind);
            }
        }
        out
    }

    fn match_path(&self, candidate: &Path) -> Option<ProtectedKind> {
        if let Some(b) = &self.binary
            && path_matches(candidate, b)
        {
            return Some(ProtectedKind::Binary);
        }
        if self.configs.iter().any(|p| path_matches(candidate, p)) {
            return Some(ProtectedKind::Config);
        }
        if self.plugins.iter().any(|p| path_matches(candidate, p)) {
            return Some(ProtectedKind::Plugin);
        }
        if self
            .claude_settings
            .iter()
            .any(|p| path_matches(candidate, p))
        {
            return Some(ProtectedKind::ClaudeSettings);
        }
        if self.hook_scripts.iter().any(|p| path_matches(candidate, p)) {
            return Some(ProtectedKind::HookScript);
        }
        None
    }
}

/// True when `candidate` refers to the same file as `target`. Tries
/// `canonicalize` first so symlinks collapse, then falls back to a
/// raw byte comparison so missing files still match.
fn path_matches(candidate: &Path, target: &Path) -> bool {
    if candidate == target {
        return true;
    }
    match (candidate.canonicalize(), target.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn candidate_targets(input: &HookInput) -> Vec<PathBuf> {
    let mut out = Vec::new();
    // Edit / Write / Read all expose `file_path`.
    if let Some(fp) = crate::facts::path::extract(input) {
        out.push(fp.absolute);
    }
    // Bash invocations carry destinations as positional args; collect
    // every positional that looks like a path. Don't try to interpret
    // the command itself — false positives are cheap (we reject), but
    // missing a target can let an unsafe write through.
    if let Some(cmd) = input.bash_command() {
        let bash = crate::facts::shell::parse(cmd);
        let writer_heads = ["rm", "mv", "cp", "chmod", "chown", "tee", "ln"];
        for argv in bash.segments.iter().flat_map(|p| p.commands.iter()) {
            let head = match argv.head.as_str() {
                "sudo" => argv.positional().next().unwrap_or(""),
                other => other,
            };
            let head_base = std::path::Path::new(head)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(head);
            if !writer_heads.contains(&head_base) {
                continue;
            }
            for a in argv.positional() {
                if a == head {
                    continue;
                }
                out.push(PathBuf::from(a));
            }
        }
    }
    out
}

/// Discover the repo root for the given start directory. Thin wrapper
/// over [`crate::config::repo::discover`] so callers don't need to
/// import the submodule directly.
pub fn discover_repo(start: &Path) -> Option<PathBuf> {
    repo::discover(start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;

    struct MapEnv(HashMap<String, OsString>);

    impl MapEnv {
        fn with(pairs: &[(&str, &str)]) -> Self {
            let mut m = HashMap::new();
            for (k, v) in pairs {
                m.insert((*k).to_string(), OsString::from(*v));
            }
            Self(m)
        }
    }

    impl EnvLookup for MapEnv {
        fn var_os(&self, key: &str) -> Option<OsString> {
            self.0.get(key).cloned()
        }
    }

    #[test]
    fn protected_kind_round_trip_strings() {
        for k in [
            ProtectedKind::Binary,
            ProtectedKind::Config,
            ProtectedKind::Plugin,
            ProtectedKind::ClaudeSettings,
            ProtectedKind::HookScript,
        ] {
            assert!(!k.as_str().is_empty());
        }
    }

    #[test]
    fn collect_includes_repo_local_claude_settings() {
        let env = MapEnv::with(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        assert!(
            p.claude_settings
                .iter()
                .any(|q| q == &PathBuf::from("/repo/.claude/settings.json"))
        );
        assert!(
            p.claude_settings
                .iter()
                .any(|q| q == &PathBuf::from("/h/.claude/settings.json"))
        );
    }

    #[test]
    fn classify_matches_edit_of_local_claude_settings() {
        let env = MapEnv::with(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({ "file_path": "/repo/.claude/settings.json" }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::ClaudeSettings));
    }

    #[test]
    fn classify_matches_rm_on_protected_path() {
        let env = MapEnv::with(&[("HOME", "/h")]);
        let mut cfg = Config::default();
        cfg.plugin_paths.push(PathBuf::from("/repo/plugin.yaml"));
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": "rm -f /repo/plugin.yaml" }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::Plugin));
    }

    #[test]
    fn classify_matches_sudo_writer_via_positional_unwrap() {
        let env = MapEnv::with(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({
                "command": "sudo rm -f /repo/.claude/settings.json"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::ClaudeSettings));
    }

    #[test]
    fn classify_returns_empty_for_unrelated_input() {
        let env = MapEnv::with(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": "ls -la" }),
        };
        assert!(p.classify_input(&input).is_empty());
    }

    #[test]
    fn discover_repo_returns_none_for_non_repo_path() {
        assert!(discover_repo(Path::new("/")).is_none());
    }

    #[test]
    fn collect_via_system_env_does_not_panic() {
        // Production smoke: walking SystemEnv over a fake repo path
        // must yield a valid (possibly empty) ProtectedPaths.
        let cfg = Config::default();
        let _ = ProtectedPaths::collect(Some(Path::new("/nonexistent-repo")), &cfg);
    }

    #[test]
    fn empty_when_no_repo_root_and_no_home() {
        let env = MapEnv::with(&[]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(None, &cfg, &env);
        assert!(p.claude_settings.is_empty());
    }

    use crate::testing::proptest::{protected_kind, richer_hook_input};
    use proptest::prelude::*;

    proptest! {
        // ProtectedKind::as_str is total and the labels are non-empty.
        #[test]
        fn pbt_kind_label_is_non_empty(k in protected_kind()) {
            prop_assert!(!k.as_str().is_empty());
        }

        // An empty ProtectedPaths classifies every input as
        // non-protected. This is the safe-baseline guarantee that
        // self-protection rules rely on when running outside a repo.
        #[test]
        fn pbt_empty_protected_classifies_to_empty(input in richer_hook_input()) {
            let p = ProtectedPaths::default();
            prop_assert!(p.classify_input(&input).is_empty());
        }

        // classify_input must not panic for any well-formed HookInput
        // shape, including arbitrary Bash strings, missing fields, and
        // non-string payload values.
        #[test]
        fn pbt_classify_never_panics(input in richer_hook_input()) {
            let env = MapEnv::with(&[("HOME", "/h")]);
            let cfg = Config::default();
            let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
            let _ = p.classify_input(&input);
        }

        // collect_with_env over an arbitrary HOME / repo path never
        // panics and always yields a `ProtectedPaths` whose lists are
        // sorted-deduplicated invariants.
        #[test]
        fn pbt_collect_yields_sorted_dedup_lists(
            home in "/(?:home|h)/[a-z0-9_]{1,8}",
            repo in "/(?:repo|src|home/[a-z]{1,5}/proj)",
        ) {
            let env = MapEnv::with(&[("HOME", home.as_str())]);
            let cfg = Config::default();
            let p = ProtectedPaths::collect_with_env(Some(Path::new(&repo)), &cfg, &env);
            // claude_settings is the only list whose ordering matters
            // for the dedup contract; verify it's sorted and unique.
            let mut sorted = p.claude_settings.clone();
            sorted.sort();
            sorted.dedup();
            prop_assert_eq!(p.claude_settings.clone(), sorted);
            // configs is also sort+dedup'd.
            let mut sorted_cfg = p.configs.clone();
            sorted_cfg.sort();
            sorted_cfg.dedup();
            prop_assert_eq!(p.configs.clone(), sorted_cfg);
        }
    }
}
