//! Self-protection target paths and labels.
//!
//! [`ProtectedPaths`] is built once per [`crate::engine::Engine`] from
//! the resolved config + repo root and consulted by the engine's
//! `decide` to populate [`crate::facts::Facts::protected`]. The actual
//! `core.self_protection.*` rules live in `crate::rules::self_protection`.

use std::path::{Path, PathBuf};
use std::{fs, io::ErrorKind};

use crate::config::scope::{EnvLookup, SystemEnv, layout_for};
use crate::config::{Config, repo};
use crate::hook_input::HookInput;
use serde_json::Value;

/// Categories of protected target. Paired with a path on every
/// [`crate::facts::Facts::protected`] entry so rules can produce specific reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedKind {
    Binary,
    Config,
    Plugin,
    ClaudeSettings,
    CodexSettings,
    HookScript,
    CopilotSettings,
    KiroSettings,
}

impl ProtectedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Config => "config",
            Self::Plugin => "plugin",
            Self::ClaudeSettings => "claude_settings",
            Self::CodexSettings => "codex_settings",
            Self::HookScript => "hook_script",
            Self::CopilotSettings => "copilot_settings",
            Self::KiroSettings => "kiro_settings",
        }
    }
}

/// Small, allocation-free set of protected target labels.
///
/// There are only eight [`ProtectedKind`] variants, so a fixed buffer is
/// simpler than pulling in a small-vector dependency for the hook hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedKinds {
    kinds: [ProtectedKind; Self::CAPACITY],
    len: usize,
}

impl ProtectedKinds {
    const CAPACITY: usize = 8;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_unique(&mut self, kind: ProtectedKind) {
        if self.contains(&kind) {
            return;
        }
        if self.len < Self::CAPACITY {
            self.kinds[self.len] = kind;
            self.len += 1;
        }
    }

    pub fn contains(&self, kind: &ProtectedKind) -> bool {
        self.as_slice().contains(kind)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProtectedKind> {
        self.as_slice().iter()
    }

    pub fn as_slice(&self) -> &[ProtectedKind] {
        &self.kinds[..self.len]
    }
}

impl Default for ProtectedKinds {
    fn default() -> Self {
        Self {
            kinds: [ProtectedKind::Binary; Self::CAPACITY],
            len: 0,
        }
    }
}

impl From<&[ProtectedKind]> for ProtectedKinds {
    fn from(kinds: &[ProtectedKind]) -> Self {
        let mut out = Self::new();
        for kind in kinds {
            out.push_unique(*kind);
        }
        out
    }
}

/// Resolved set of paths whose modification ptuf treats as a
/// guardrail-bypass attempt.
#[derive(Debug, Clone, Default)]
pub struct ProtectedPaths {
    pub repo_root: Option<PathBuf>,
    pub binary: Option<PathBuf>,
    pub configs: Vec<PathBuf>,
    pub plugins: Vec<PathBuf>,
    pub claude_settings: Vec<PathBuf>,
    pub codex_settings: Vec<PathBuf>,
    pub hook_scripts: Vec<PathBuf>,
    pub copilot_settings: Vec<PathBuf>,
    pub kiro_settings: Vec<PathBuf>,
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

        let mut codex_settings: Vec<PathBuf> = Vec::new();
        if let Some(root) = repo_root {
            codex_settings.push(root.join(".codex/config.toml"));
            codex_settings.push(root.join(".codex/hooks.json"));
        }
        if let Some(home_os) = env.var_os("HOME") {
            let home = PathBuf::from(home_os);
            codex_settings.push(home.join(".codex/config.toml"));
            codex_settings.push(home.join(".codex/hooks.json"));
        }
        codex_settings.sort();
        codex_settings.dedup();

        let mut hook_scripts = Vec::new();
        for settings_path in &claude_settings {
            let body = match fs::read_to_string(settings_path) {
                Ok(s) => s,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(_) => continue,
            };
            let parsed: Value = match serde_json::from_str(&body) {
                Ok(value) => value,
                Err(_) => continue,
            };
            for command in crate::init::claude_code::pre_tool_use_commands(&parsed) {
                let Some(executable) = crate::init::command_executable(&command) else {
                    continue;
                };
                let normalized = crate::facts::path::resolve_with_env(
                    executable,
                    repo_root.or_else(|| settings_path.parent()),
                    env,
                );
                if !hook_scripts.contains(&normalized) {
                    hook_scripts.push(normalized);
                }
            }
        }
        for hooks_path in codex_settings.iter().filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "hooks.json")
        }) {
            let body = match fs::read_to_string(hooks_path) {
                Ok(s) => s,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(_) => continue,
            };
            let parsed: Value = match serde_json::from_str(&body) {
                Ok(value) => value,
                Err(_) => continue,
            };
            for command in crate::init::codex::pre_tool_use_commands(&parsed) {
                let Some(executable) = crate::init::command_executable(&command) else {
                    continue;
                };
                let normalized = crate::facts::path::resolve_with_env(
                    executable,
                    repo_root.or_else(|| hooks_path.parent()),
                    env,
                );
                if !hook_scripts.contains(&normalized) {
                    hook_scripts.push(normalized);
                }
            }
        }

        let mut copilot_settings: Vec<PathBuf> = Vec::new();
        if let Some(root) = repo_root {
            copilot_settings.push(root.join(".github/hooks/ptuf.json"));
        }

        for hooks_path in &copilot_settings {
            let body = match fs::read_to_string(hooks_path) {
                Ok(s) => s,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(_) => continue,
            };
            let parsed: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for command in crate::init::copilot::pre_tool_use_commands(&parsed) {
                let Some(executable) = crate::init::command_executable(&command) else {
                    continue;
                };
                let normalized = crate::facts::path::resolve_with_env(
                    executable,
                    repo_root.or_else(|| hooks_path.parent()),
                    env,
                );
                if !hook_scripts.contains(&normalized) {
                    hook_scripts.push(normalized);
                }
            }
        }

        let mut kiro_settings: Vec<PathBuf> = Vec::new();
        if let Some(root) = repo_root {
            kiro_settings.push(root.join(".kiro/agents/ptuf-guarded.json"));
        }
        if let Some(home_os) = env.var_os("HOME") {
            let home = PathBuf::from(home_os);
            kiro_settings.push(home.join(".kiro/agents/ptuf-guarded.json"));
        }
        kiro_settings.sort();
        kiro_settings.dedup();

        for agent_path in &kiro_settings {
            let body = match fs::read_to_string(agent_path) {
                Ok(s) => s,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(_) => continue,
            };
            let parsed: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for command in crate::init::kiro::pre_tool_use_commands(&parsed) {
                let Some(executable) = crate::init::command_executable(&command) else {
                    continue;
                };
                let normalized = crate::facts::path::resolve_with_env(
                    executable,
                    repo_root.or_else(|| agent_path.parent()),
                    env,
                );
                if !hook_scripts.contains(&normalized) {
                    hook_scripts.push(normalized);
                }
            }
        }

        // Pre-cache `canonical_or_raw` on every target list so
        // `path_matches` only canonicalises the candidate. Symlinks
        // collapse for files that exist; non-existent targets keep
        // their raw form, which still matches a likewise non-existent
        // candidate via byte equality.
        let binary = std::env::current_exe()
            .ok()
            .map(|p| p.canonicalize().unwrap_or(p));
        let configs = canonicalize_each(configs);
        let plugins = canonicalize_each(config.plugin_paths.clone());
        let claude_settings = canonicalize_each(claude_settings);
        let codex_settings = canonicalize_each(codex_settings);
        let hook_scripts = canonicalize_each(hook_scripts);
        let copilot_settings = canonicalize_each(copilot_settings);
        let kiro_settings = canonicalize_each(kiro_settings);

        Self {
            repo_root: repo_root.map(Path::to_path_buf),
            binary,
            configs,
            plugins,
            claude_settings,
            codex_settings,
            hook_scripts,
            copilot_settings,
            kiro_settings,
        }
    }

    /// Classify a `HookInput` against the protected set, returning the
    /// matched labels. Empty set means "no self-protection match".
    pub fn classify_input(&self, input: &HookInput) -> ProtectedKinds {
        let paths = crate::facts::path::extract_all(input);
        self.classify_input_with_paths(input, &paths)
    }

    /// Variant used by the engine after it has already extracted path
    /// facts, avoiding a second scan of large `apply_patch` payloads.
    pub fn classify_input_with_paths(
        &self,
        input: &HookInput,
        paths: &[crate::facts::path::FilePath],
    ) -> ProtectedKinds {
        self.classify_input_with_paths_pair(input, paths, &[])
    }

    /// Variant that classifies the union of `paths` (tool-input
    /// derived) and `extra` (engine-supplied, e.g. Bash redirect
    /// targets) without forcing the caller to allocate a merged `Vec`.
    pub fn classify_input_with_paths_pair(
        &self,
        input: &HookInput,
        paths: &[crate::facts::path::FilePath],
        extra: &[crate::facts::path::FilePath],
    ) -> ProtectedKinds {
        let mut out = ProtectedKinds::new();
        let cwd = if self.repo_root.is_none() {
            std::env::current_dir().ok()
        } else {
            None
        };
        let base_dir = self.repo_root.as_deref().or(cwd.as_deref());
        let candidates = candidate_targets(input, paths.iter().chain(extra.iter()), base_dir);
        for cand in &candidates {
            if let Some(kind) = self.match_path(cand) {
                out.push_unique(kind);
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
        if self
            .codex_settings
            .iter()
            .any(|p| path_matches(candidate, p))
        {
            return Some(ProtectedKind::CodexSettings);
        }
        if self
            .copilot_settings
            .iter()
            .any(|p| path_matches(candidate, p))
        {
            return Some(ProtectedKind::CopilotSettings);
        }
        if self
            .kiro_settings
            .iter()
            .any(|p| path_matches(candidate, p))
        {
            return Some(ProtectedKind::KiroSettings);
        }
        if self.hook_scripts.iter().any(|p| path_matches(candidate, p)) {
            return Some(ProtectedKind::HookScript);
        }
        None
    }
}

/// Replace each entry with its `canonicalize().unwrap_or(self)` form
/// so the target side never re-canonicalises during match-time. The
/// helper is shared across every protected list; non-existent targets
/// keep their raw form, which still matches a likewise non-existent
/// candidate via byte equality.
fn canonicalize_each(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .map(|p| p.canonicalize().unwrap_or(p))
        .collect()
}

/// True when `candidate` refers to the same file as `target`. The
/// caller guarantees that `target` was already passed through
/// [`canonicalize_each`] at collect time, so we only canonicalise the
/// candidate here. Falls back to byte equality so missing files still
/// match when both sides spell the path identically.
fn path_matches(candidate: &Path, target: &Path) -> bool {
    if candidate == target {
        return true;
    }
    match candidate.canonicalize() {
        Ok(c) => c == target,
        Err(_) => false,
    }
}

fn candidate_targets<'a>(
    input: &HookInput,
    paths: impl IntoIterator<Item = &'a crate::facts::path::FilePath>,
    base_dir: Option<&Path>,
) -> Vec<PathBuf> {
    let event = input.event();
    let mut out = Vec::new();
    // Edit / Write / Read all expose `file_path`.
    for fp in paths {
        if fp.absolute.is_relative() {
            if let Some(base) = base_dir {
                out.push(base.join(&fp.absolute));
            } else {
                out.push(fp.absolute.clone());
            }
        } else {
            out.push(fp.absolute.clone());
        }
    }
    // Bash invocations carry destinations as positional args; collect
    // every positional that looks like a path. Don't try to interpret
    // the command itself — false positives are cheap (we reject), but
    // missing a target can let an unsafe write through.
    if let Some(cmd) = event.command {
        let bash = crate::facts::shell::parse(cmd);
        let writer_heads = ["rm", "mv", "cp", "chmod", "chown", "tee", "ln"];
        for argv in bash.commands() {
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
                out.push(crate::facts::path::resolve_with_env(
                    a,
                    base_dir,
                    &crate::config::scope::SystemEnv,
                ));
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
            ProtectedKind::CodexSettings,
            ProtectedKind::HookScript,
            ProtectedKind::CopilotSettings,
            ProtectedKind::KiroSettings,
        ] {
            assert!(!k.as_str().is_empty());
        }
    }

    #[test]
    fn protected_kinds_defaults_to_empty() {
        let kinds = ProtectedKinds::default();
        assert!(kinds.is_empty());
        assert_eq!(kinds.as_slice(), &[]);
        assert_eq!(kinds.iter().count(), 0);
    }

    #[test]
    fn protected_kinds_push_unique_preserves_order() {
        let mut kinds = ProtectedKinds::new();
        kinds.push_unique(ProtectedKind::Config);
        kinds.push_unique(ProtectedKind::Plugin);
        kinds.push_unique(ProtectedKind::Config);

        assert!(!kinds.is_empty());
        assert!(kinds.contains(&ProtectedKind::Config));
        assert!(kinds.contains(&ProtectedKind::Plugin));
        assert!(!kinds.contains(&ProtectedKind::Binary));
        assert_eq!(
            kinds.as_slice(),
            &[ProtectedKind::Config, ProtectedKind::Plugin]
        );
    }

    #[test]
    fn protected_kinds_from_slice_deduplicates() {
        let kinds = ProtectedKinds::from(
            [
                ProtectedKind::HookScript,
                ProtectedKind::HookScript,
                ProtectedKind::Binary,
            ]
            .as_slice(),
        );
        let collected: Vec<_> = kinds.iter().copied().collect();
        assert_eq!(
            collected,
            vec![ProtectedKind::HookScript, ProtectedKind::Binary]
        );
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
        assert!(
            p.codex_settings
                .iter()
                .any(|q| q == &PathBuf::from("/repo/.codex/config.toml"))
        );
        assert!(
            p.codex_settings
                .iter()
                .any(|q| q == &PathBuf::from("/h/.codex/hooks.json"))
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
    fn classify_matches_apply_patch_edit_of_repo_local_codex_settings() {
        let env = MapEnv::with(&[("HOME", "/h")]);
        let cfg = Config::default();
        let dir = std::env::temp_dir().join(format!(
            "ptuf-self-paths-codex-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".codex")).expect("mkdir");
        std::fs::write(dir.join(".codex/config.toml"), "").expect("touch");
        let p = ProtectedPaths::collect_with_env(Some(&dir), &cfg, &env);
        let input = HookInput {
            tool_name: "apply_patch".into(),
            tool_input: serde_json::json!({
                "command": "*** Begin Patch\n*** Update File: .codex/config.toml\n*** End Patch\n"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::CodexSettings));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classify_does_not_match_bare_relative_name_by_suffix() {
        let env = MapEnv::with(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "apply_patch".into(),
            tool_input: serde_json::json!({
                "command": "*** Begin Patch\n*** Update File: settings.json\n*** End Patch\n"
            }),
        };
        assert!(p.classify_input(&input).is_empty());
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
    fn collect_extracts_hook_scripts_from_claude_settings() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-self-paths-{}-{}",
            std::process::id(),
            line!()
        ));
        let home = dir.join("home");
        std::fs::create_dir_all(home.join(".claude")).expect("mkdir");
        std::fs::write(
            home.join(".claude/settings.json"),
            r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "./hooks/guard.sh hook claude-code" }
        ]
      }
    ]
  }
}"#,
        )
        .expect("write settings");
        let home_string = home.to_string_lossy().into_owned();
        let env = MapEnv::with(&[("HOME", home_string.as_str())]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        assert!(
            p.hook_scripts
                .iter()
                .any(|path| path == &PathBuf::from("/repo/./hooks/guard.sh"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_hook_command_canonicalizes_against_settings_dir() {
        // A relative hook command (`./hooks/guard.sh`) and a candidate
        // edit on the same physical file must converge on the same
        // `ProtectedKind` regardless of whether either side carries a
        // leading `./`.
        let dir = std::env::temp_dir().join(format!(
            "ptuf-self-paths-canonical-{}-{}",
            std::process::id(),
            line!()
        ));
        let home = dir.join("home");
        let hooks_dir = home.join(".claude/hooks");
        std::fs::create_dir_all(&hooks_dir).expect("mkdir hooks");
        std::fs::write(
            home.join(".claude/settings.json"),
            r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "./hooks/guard.sh hook claude-code" }
        ]
      }
    ]
  }
}"#,
        )
        .expect("write settings");
        let guard = hooks_dir.join("guard.sh");
        std::fs::write(&guard, "#!/bin/sh\n").expect("write guard");
        let home_string = home.to_string_lossy().into_owned();
        let env = MapEnv::with(&[("HOME", home_string.as_str())]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(None, &cfg, &env);
        let candidate = guard
            .canonicalize()
            .expect("guard.sh canonicalises to a real path");
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({
                "file_path": candidate.to_str().expect("utf-8"),
            }),
        };
        let labels = p.classify_input(&input);
        assert!(
            labels.contains(&ProtectedKind::HookScript),
            "expected HookScript classification, got {labels:?} (hook_scripts: {:?})",
            p.hook_scripts,
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_extracts_hook_scripts_from_codex_hooks_json() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-self-paths-codex-hooks-{}-{}",
            std::process::id(),
            line!()
        ));
        let home = dir.join("home");
        std::fs::create_dir_all(home.join(".codex")).expect("mkdir");
        std::fs::write(
            home.join(".codex/hooks.json"),
            r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|apply_patch|mcp__.*",
        "hooks": [
          { "type": "command", "command": "./hooks/guard.sh hook codex" }
        ]
      }
    ]
  }
}"#,
        )
        .expect("write settings");
        let home_string = home.to_string_lossy().into_owned();
        let env = MapEnv::with(&[("HOME", home_string.as_str())]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        assert!(
            p.hook_scripts
                .iter()
                .any(|path| path == &PathBuf::from("/repo/./hooks/guard.sh"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classify_matches_nested_mcp_path_on_hook_script() {
        let p = ProtectedPaths {
            hook_scripts: vec![PathBuf::from("/repo/hooks/guard.sh")],
            ..ProtectedPaths::default()
        };
        let input = HookInput {
            tool_name: "mcp__github__push_files".into(),
            tool_input: serde_json::json!({
                "files": [{"path": "/repo/hooks/guard.sh"}]
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::HookScript));
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
        assert!(p.codex_settings.is_empty());
    }

    #[test]
    fn classify_input_with_paths_pair_includes_extra_slice() {
        // The pair variant must classify the union of `paths` and
        // `extra` without forcing a merged Vec. A Bash redirect target
        // arrives via `extra` and should still hit the matching kind.
        let env = MapEnv::with(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": "ls" }),
        };
        let extra = vec![crate::facts::path::PathFact::from_raw(
            "/repo/.claude/settings.json".into(),
            crate::facts::path::PathTool::Write,
            crate::facts::path::PathOrigin::BashRedirect,
            Some(Path::new("/repo")),
            &env,
        )];
        let labels = p.classify_input_with_paths_pair(&input, &[], &extra);
        assert!(labels.contains(&ProtectedKind::ClaudeSettings));
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
