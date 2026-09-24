//! Self-protection target paths and labels.
//!
//! [`ProtectedPaths`] is built once per [`crate::engine::Engine`] from
//! the resolved config + repo root and consulted by the engine's
//! `decide` to populate [`crate::facts::Facts::protected`]. The actual
//! `core.self_protection.*` rules live in `crate::rules::self_protection`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::config::scope::{EnvLookup, SystemEnv, layout_for};
use crate::hook_input::HookInput;
use serde_json::Value;

/// Categories of protected target. Paired with a path on every
/// [`crate::facts::Facts::protected`] entry so rules can produce specific reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedKind {
    Binary,
    Config,
    Plugin,
    /// Hook registration, permission, and MCP config of every coding
    /// agent ptuf ships an adapter for (Claude Code, Codex, Copilot,
    /// Cursor, Kiro, Cline, Pi, OpenCode).
    AgentSettings,
    HookScript,
}

impl ProtectedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Config => "config",
            Self::Plugin => "plugin",
            Self::AgentSettings => "agent_settings",
            Self::HookScript => "hook_script",
        }
    }
}

/// Small, allocation-free set of protected target labels.
///
/// There are only five [`ProtectedKind`] variants, so a fixed buffer is
/// simpler than pulling in a small-vector dependency for the hook hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedKinds {
    kinds: [ProtectedKind; Self::CAPACITY],
    len: usize,
}

impl ProtectedKinds {
    const CAPACITY: usize = 5;

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
    /// Every agent config that can register / remove a hook or widen
    /// the agent's own permissions. Sorted and deduplicated.
    pub agent_settings: Vec<PathBuf>,
    pub hook_scripts: Vec<PathBuf>,
}

/// Extracts `PreToolUse`-equivalent hook commands from one agent's
/// parsed hook config.
type HookCommandParser = fn(&Value) -> Vec<String>;

impl ProtectedPaths {
    /// Build the protected set from the resolved engine state.
    pub fn collect(repo_root: Option<&Path>, config: &Config) -> Self {
        Self::collect_with_env(repo_root, config, &SystemEnv)
    }

    /// Hermetic variant used by tests; collapses to [`Self::collect`]
    /// in production via the [`SystemEnv`] lookup.
    pub(crate) fn collect_with_env(
        repo_root: Option<&Path>,
        config: &Config,
        env: &dyn EnvLookup,
    ) -> Self {
        let layout = layout_for(repo_root, env);
        let mut configs: Vec<PathBuf> = layout.ordered_paths();
        // Deduplicate while preserving order.
        configs.sort();
        configs.dedup();

        let home = env.var_os("HOME").map(PathBuf::from);
        let home = home.as_deref();

        let claude = collect_claude_paths(repo_root, home);
        let codex = collect_codex_paths(repo_root, home, env);
        let copilot = collect_copilot_paths(repo_root, home);
        let cursor = collect_cursor_paths(repo_root, home);
        let kiro_agents = collect_kiro_agent_jsons(repo_root, home);
        let kiro = collect_kiro_paths(repo_root, home, &kiro_agents);
        let cline = collect_cline_paths(repo_root, home);
        let pi = collect_pi_paths(repo_root, home);
        let opencode = collect_opencode_paths(repo_root, home, env);

        // Only the files that actually carry hook registrations are
        // parsed; permission / MCP config (e.g. `~/.claude.json`, which
        // can grow to megabytes) is path-protected without being read.
        let mut hook_scripts = Vec::new();
        let hook_sources: [(&[PathBuf], HookCommandParser); 5] = [
            (
                &claude.hook_sources,
                crate::init::claude_code::pre_tool_use_commands,
            ),
            (
                &codex.hook_sources,
                crate::init::codex::pre_tool_use_commands,
            ),
            (
                &copilot.hook_sources,
                crate::init::copilot::pre_tool_use_commands,
            ),
            (
                &cursor.hook_sources,
                crate::init::cursor::pre_tool_use_commands,
            ),
            (&kiro_agents, crate::init::kiro::pre_tool_use_commands),
        ];
        for (sources, parse) in hook_sources {
            extend_hook_scripts(&mut hook_scripts, sources, parse, repo_root, env);
        }

        let mut agent_settings: Vec<PathBuf> = [
            claude.paths,
            codex.paths,
            copilot.paths,
            cursor.paths,
            kiro,
            cline,
            pi,
            opencode,
        ]
        .concat();

        // Pre-cache `canonical_or_raw` on every target list so
        // `match_path` only canonicalises the candidate. Symlinks
        // collapse for files that exist; non-existent targets keep
        // their raw form, which still matches a likewise non-existent
        // candidate via byte equality.
        let binary = std::env::current_exe()
            .ok()
            .map(|p| p.canonicalize().unwrap_or(p));
        let configs = canonicalize_each(configs);
        let plugins = canonicalize_each(config.plugin_paths.clone());
        agent_settings = canonicalize_each(agent_settings);
        agent_settings.sort();
        agent_settings.dedup();
        let hook_scripts = canonicalize_each(hook_scripts);

        Self {
            repo_root: repo_root.map(Path::to_path_buf),
            binary,
            configs,
            plugins,
            agent_settings,
            hook_scripts,
        }
    }

    /// Classify a `HookInput` against the protected set, returning the
    /// matched labels. Empty set means "no self-protection match".
    ///
    /// This extracts path facts itself. The engine, which has already
    /// extracted them (and parsed the Bash command), calls
    /// [`Self::classify_input_prepared`] instead.
    pub fn classify_input(&self, input: &HookInput) -> ProtectedKinds {
        let paths = crate::facts::path::extract_all(input);
        self.classify_input_prepared(input, &paths, &[], None)
    }

    /// Classify the union of `paths` (tool-input derived) and `extra`
    /// (engine-supplied, e.g. Bash redirect targets) without forcing
    /// the caller to allocate a merged `Vec`, reusing an already-parsed
    /// Bash command (`facts.bash`) so the engine's hot path never
    /// parses the same command line twice. Pass `None` for `bash` to
    /// fall back to parsing the payload's `command` string internally.
    pub(crate) fn classify_input_prepared(
        &self,
        input: &HookInput,
        paths: &[crate::facts::path::FilePath],
        extra: &[crate::facts::path::FilePath],
        bash: Option<&crate::facts::shell::Bash>,
    ) -> ProtectedKinds {
        let mut out = ProtectedKinds::new();
        let cwd = if self.repo_root.is_none() {
            std::env::current_dir().ok()
        } else {
            None
        };
        let base_dir = self.repo_root.as_deref().or(cwd.as_deref());
        let candidates = candidate_targets(input, paths.iter().chain(extra.iter()), base_dir, bash);
        for cand in &candidates {
            if let Some(kind) = self.match_path(cand) {
                out.push_unique(kind);
            }
        }
        out
    }

    fn match_path(&self, candidate: &Path) -> Option<ProtectedKind> {
        // `candidate` is constant across every target list, so its
        // `canonicalize` (a syscall) is computed lazily at most once
        // per call instead of once per (candidate, target) pair.
        let mut canon: Option<Option<PathBuf>> = None;
        let mut matches = |target: &Path| {
            if candidate == target {
                return true;
            }
            canon
                .get_or_insert_with(|| candidate.canonicalize().ok())
                .as_deref()
                == Some(target)
        };
        if let Some(b) = &self.binary
            && matches(b)
        {
            return Some(ProtectedKind::Binary);
        }
        if self.configs.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::Config);
        }
        if self.plugins.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::Plugin);
        }
        if self.agent_settings.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::AgentSettings);
        }
        if self.hook_scripts.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::HookScript);
        }
        None
    }
}

/// Paths contributed by one agent: `paths` is everything to protect,
/// `hook_sources` the subset whose hook commands feed `hook_scripts`.
#[derive(Default)]
struct AgentPaths {
    paths: Vec<PathBuf>,
    hook_sources: Vec<PathBuf>,
}

/// Parse each existing `source` with `parse` and append the resolved
/// executable of every registered hook command to `hook_scripts`.
///
/// Missing, unreadable, and malformed files are skipped uniformly so a
/// TOCTOU race (file removed between enumeration and read) collapses
/// into the same control flow as malformed JSON.
fn extend_hook_scripts(
    hook_scripts: &mut Vec<PathBuf>,
    sources: &[PathBuf],
    parse: HookCommandParser,
    repo_root: Option<&Path>,
    env: &dyn EnvLookup,
) {
    for source in sources {
        let Ok(body) = fs::read_to_string(source) else {
            continue;
        };
        let Ok(parsed): Result<Value, _> = serde_json::from_str(&body) else {
            continue;
        };
        for command in parse(&parsed) {
            let Some(executable) = crate::init::command_executable(&command) else {
                continue;
            };
            let normalized = crate::facts::path::resolve_with_env(
                executable,
                repo_root.or_else(|| source.parent()),
                env,
            );
            if !hook_scripts.contains(&normalized) {
                hook_scripts.push(normalized);
            }
        }
    }
}

/// Claude Code: hook-bearing `settings*.json` plus the permission /
/// MCP surfaces (`.mcp.json`, `~/.claude.json`, managed settings) that
/// can pre-approve tools or bypass permission prompts.
fn collect_claude_paths(repo_root: Option<&Path>, home: Option<&Path>) -> AgentPaths {
    let mut out = AgentPaths::default();
    if let Some(root) = repo_root {
        out.hook_sources.push(root.join(".claude/settings.json"));
        out.hook_sources
            .push(root.join(".claude/settings.local.json"));
        out.paths.push(root.join(".mcp.json"));
    }
    if let Some(home) = home {
        out.hook_sources.push(home.join(".claude/settings.json"));
        out.hook_sources
            .push(home.join(".claude/settings.local.json"));
        out.paths.push(home.join(".claude.json"));
    }
    for managed in [
        "/etc/claude-code",
        "/Library/Application Support/ClaudeCode",
    ] {
        let managed = Path::new(managed);
        out.hook_sources.push(managed.join("managed-settings.json"));
        out.paths.push(managed.join("managed-mcp.json"));
    }
    out.paths.extend(out.hook_sources.iter().cloned());
    out
}

/// Codex: `config.toml` (sandbox / approval policy / MCP / feature
/// flags) and `hooks.json`, per repo, `$HOME`, and `$CODEX_HOME`.
fn collect_codex_paths(
    repo_root: Option<&Path>,
    home: Option<&Path>,
    env: &dyn EnvLookup,
) -> AgentPaths {
    let mut dirs = Vec::new();
    if let Some(root) = repo_root {
        dirs.push(root.join(".codex"));
    }
    if let Some(home) = home {
        dirs.push(home.join(".codex"));
    }
    if let Some(codex_home) = env.var_os("CODEX_HOME") {
        dirs.push(PathBuf::from(codex_home));
    }
    let mut out = AgentPaths::default();
    for dir in dirs {
        out.paths.push(dir.join("config.toml"));
        out.hook_sources.push(dir.join("hooks.json"));
    }
    out.paths.extend(out.hook_sources.iter().cloned());
    out
}

/// GitHub Copilot: the managed repo hook file plus the Copilot CLI
/// user config (trusted folders / allowed tools) and MCP config.
fn collect_copilot_paths(repo_root: Option<&Path>, home: Option<&Path>) -> AgentPaths {
    let mut out = AgentPaths::default();
    if let Some(root) = repo_root {
        out.hook_sources.push(root.join(".github/hooks/ptuf.json"));
    }
    if let Some(home) = home {
        out.paths.push(home.join(".copilot/config.json"));
        out.paths.push(home.join(".copilot/mcp-config.json"));
    }
    out.paths.extend(out.hook_sources.iter().cloned());
    out
}

/// Cursor: `hooks.json`, `mcp.json`, and the CLI permission config
/// (`<repo>/.cursor/cli.json`, `$HOME/.cursor/cli-config.json`).
fn collect_cursor_paths(repo_root: Option<&Path>, home: Option<&Path>) -> AgentPaths {
    let mut out = AgentPaths::default();
    if let Some(root) = repo_root {
        let dir = root.join(".cursor");
        out.hook_sources.push(dir.join("hooks.json"));
        out.paths.push(dir.join("mcp.json"));
        out.paths.push(dir.join("cli.json"));
    }
    if let Some(home) = home {
        let dir = home.join(".cursor");
        out.hook_sources.push(dir.join("hooks.json"));
        out.paths.push(dir.join("mcp.json"));
        out.paths.push(dir.join("cli-config.json"));
    }
    out.paths.extend(out.hook_sources.iter().cloned());
    out
}

/// Enumerate every `*.json` directly under `<repo>/.kiro/agents/` and
/// `$HOME/.kiro/agents/`. Missing directories are silently skipped so
/// the protected set degrades to empty when `ptuf init kiro` has not
/// yet been run, rather than locking unknown legacy paths.
fn collect_kiro_agent_jsons(repo_root: Option<&Path>, home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(root) = repo_root {
        dirs.push(root.join(".kiro/agents"));
    }

    if let Some(home) = home {
        dirs.push(home.join(".kiro/agents"));
    }

    let mut paths = Vec::new();

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) == Some("json") {
                paths.push(path);
            }
        }
    }

    paths.sort();
    paths.dedup();
    paths
}

/// Kiro: every agent JSON plus the workspace / user MCP config and
/// `settings/cli.json`, whose `chat.defaultAgent` could switch Kiro to
/// an agent without the ptuf hook.
fn collect_kiro_paths(
    repo_root: Option<&Path>,
    home: Option<&Path>,
    agents: &[PathBuf],
) -> Vec<PathBuf> {
    let mut paths = agents.to_vec();
    for base in [repo_root, home].into_iter().flatten() {
        paths.push(base.join(".kiro/settings/mcp.json"));
        paths.push(base.join(".kiro/settings/cli.json"));
    }
    paths
}

/// Cline: the `PreToolUse` wrapper `ptuf init cline` installs, in both
/// the repo-local and global hook directories, for both platforms.
fn collect_cline_paths(repo_root: Option<&Path>, home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(root) = repo_root {
        dirs.push(root.join(".clinerules/hooks"));
    }
    if let Some(home) = home {
        dirs.push(home.join("Documents/Cline/Hooks"));
    }
    let mut paths = Vec::new();
    for dir in dirs {
        paths.push(dir.join("PreToolUse"));
        paths.push(dir.join("PreToolUse.ps1"));
    }
    paths
}

fn collect_pi_paths(repo_root: Option<&Path>, home: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = home {
        let agent = home.join(".pi/agent");
        paths.push(agent.join("settings.json"));
        paths.push(agent.join("extensions/ptuf.ts"));
        paths.push(agent.join("extensions/ptuf/index.ts"));
    }
    if let Some(root) = repo_root {
        let pi = root.join(".pi");
        paths.push(pi.join("settings.json"));
        paths.push(pi.join("extensions/ptuf.ts"));
        paths.push(pi.join("extensions/ptuf/index.ts"));
    }
    paths
}

/// OpenCode: the managed ptuf plugin plus `opencode.json{,c}`, whose
/// `permission` block can turn every tool into `allow`.
fn collect_opencode_paths(
    repo_root: Option<&Path>,
    home: Option<&Path>,
    env: &dyn EnvLookup,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(xdg) = env.var_os("XDG_CONFIG_HOME") {
        dirs.push(PathBuf::from(xdg).join("opencode"));
    } else if let Some(home) = home {
        dirs.push(home.join(".config/opencode"));
    }
    let mut paths = Vec::new();
    if let Some(root) = repo_root {
        dirs.push(root.join(".opencode"));
        paths.push(root.join("opencode.json"));
        paths.push(root.join("opencode.jsonc"));
    }
    for dir in dirs {
        paths.push(dir.join("plugins/ptuf.ts"));
        paths.push(dir.join("plugin/ptuf.ts"));
        paths.push(dir.join("opencode.json"));
        paths.push(dir.join("opencode.jsonc"));
    }
    paths
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

fn candidate_targets<'a>(
    input: &HookInput,
    paths: impl IntoIterator<Item = &'a crate::facts::path::FilePath>,
    base_dir: Option<&Path>,
    bash: Option<&crate::facts::shell::Bash>,
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
        // Reuse the caller's parsed pipeline when available; parsing
        // here is the fallback for entry points that only hold the raw
        // payload.
        let parsed;
        let bash = if let Some(b) = bash {
            b
        } else {
            parsed = crate::facts::shell::parse(cmd);
            &parsed
        };
        let writer_heads = ["rm", "mv", "cp", "chmod", "chown", "tee", "ln", "sed"];
        for outer in bash.commands() {
            // Peel a privilege-escalation wrapper (`sudo rm ...`) so the
            // writer head and its destinations are the inner command's.
            let unwrapped = crate::facts::shell::unwrap_all_prefix_wrappers(outer);
            let argv = &unwrapped;
            let head = argv.head.as_str();
            if !writer_heads.contains(&argv.head_basename()) {
                continue;
            }
            for a in argv.positional() {
                if a == head {
                    continue;
                }
                let resolved = crate::facts::path::resolve_with_env(
                    a,
                    base_dir,
                    &crate::config::scope::SystemEnv,
                );
                out.push(resolved);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::config::scope::MapEnv;

    #[test]
    fn protected_kind_round_trip_strings() {
        for k in [
            ProtectedKind::Binary,
            ProtectedKind::Config,
            ProtectedKind::Plugin,
            ProtectedKind::AgentSettings,
            ProtectedKind::AgentSettings,
            ProtectedKind::HookScript,
            ProtectedKind::AgentSettings,
            ProtectedKind::AgentSettings,
            ProtectedKind::AgentSettings,
            ProtectedKind::AgentSettings,
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
    fn collect_includes_repo_local_and_home_agent_settings() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &PathBuf::from("/repo/.claude/settings.json"))
        );
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &PathBuf::from("/h/.claude/settings.json"))
        );
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &PathBuf::from("/repo/.codex/config.toml"))
        );
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &PathBuf::from("/h/.codex/hooks.json"))
        );
    }

    #[test]
    fn collect_includes_permission_and_mcp_surfaces_of_every_agent() {
        let env = MapEnv::new(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "/xdg")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        for expected in [
            // Claude Code
            "/repo/.claude/settings.local.json",
            "/repo/.mcp.json",
            "/h/.claude/settings.local.json",
            "/h/.claude.json",
            "/etc/claude-code/managed-settings.json",
            "/etc/claude-code/managed-mcp.json",
            // Copilot CLI
            "/h/.copilot/config.json",
            "/h/.copilot/mcp-config.json",
            // Cursor
            "/repo/.cursor/hooks.json",
            "/repo/.cursor/mcp.json",
            "/repo/.cursor/cli.json",
            "/h/.cursor/hooks.json",
            "/h/.cursor/mcp.json",
            "/h/.cursor/cli-config.json",
            // Kiro
            "/repo/.kiro/settings/mcp.json",
            "/h/.kiro/settings/mcp.json",
            "/repo/.kiro/settings/cli.json",
            // Cline
            "/repo/.clinerules/hooks/PreToolUse",
            "/h/Documents/Cline/Hooks/PreToolUse.ps1",
            // OpenCode
            "/repo/opencode.json",
            "/repo/opencode.jsonc",
            "/xdg/opencode/opencode.json",
        ] {
            assert!(
                p.agent_settings.iter().any(|q| q == Path::new(expected)),
                "{expected} missing from {:?}",
                p.agent_settings
            );
        }
    }

    #[test]
    fn collect_honours_codex_home() {
        let env = MapEnv::new(&[("HOME", "/h"), ("CODEX_HOME", "/codex-home")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(None, &cfg, &env);
        for expected in [
            "/codex-home/config.toml",
            "/codex-home/hooks.json",
            "/h/.codex/config.toml",
        ] {
            assert!(
                p.agent_settings.iter().any(|q| q == Path::new(expected)),
                "{expected} missing from {:?}",
                p.agent_settings
            );
        }
    }

    #[test]
    fn classify_matches_edit_of_permission_config() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        for path in [
            "/repo/.claude/settings.local.json",
            "/repo/.mcp.json",
            "/repo/.cursor/cli.json",
            "/repo/opencode.json",
        ] {
            let input = HookInput {
                tool_name: "Write".into(),
                tool_input: serde_json::json!({ "file_path": path }),
            };
            assert!(
                p.classify_input(&input)
                    .contains(&ProtectedKind::AgentSettings),
                "{path} should classify as agent settings"
            );
        }
    }

    #[test]
    fn collect_extracts_hook_scripts_from_cursor_hooks_json() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-self-paths-cursor-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".cursor")).expect("mkdir");
        std::fs::write(
            dir.join(".cursor/hooks.json"),
            r#"{
  "version": 1,
  "hooks": {
    "preToolUse": [
      { "command": "./hooks/guard.sh hook cursor" }
    ]
  }
}"#,
        )
        .expect("write hooks");
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(&dir), &cfg, &env);
        assert!(
            p.hook_scripts
                .iter()
                .any(|path| path == &dir.join("./hooks/guard.sh")),
            "expected hook script from cursor hooks.json, got {:?}",
            p.hook_scripts
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classify_matches_edit_of_local_claude_settings() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({ "file_path": "/repo/.claude/settings.json" }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::AgentSettings));
    }

    #[test]
    fn classify_matches_rm_on_protected_path() {
        let env = MapEnv::new(&[("HOME", "/h")]);
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
        let env = MapEnv::new(&[("HOME", "/h")]);
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
        assert!(labels.contains(&ProtectedKind::AgentSettings));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classify_does_not_match_bare_relative_name_by_suffix() {
        let env = MapEnv::new(&[("HOME", "/h")]);
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
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({
                "command": "sudo rm -f /repo/.claude/settings.json"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::AgentSettings));
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
        let env = MapEnv::new(&[("HOME", home_string.as_str())]);
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
        let env = MapEnv::new(&[("HOME", home_string.as_str())]);
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
        let env = MapEnv::new(&[("HOME", home_string.as_str())]);
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
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": "ls -la" }),
        };
        assert!(p.classify_input(&input).is_empty());
    }

    #[test]
    fn collect_via_system_env_does_not_panic() {
        // Production smoke: walking SystemEnv over a fake repo path
        // must yield a valid (possibly empty) ProtectedPaths.
        let cfg = Config::default();
        let _ = ProtectedPaths::collect(Some(Path::new("/nonexistent-repo")), &cfg);
    }

    #[test]
    fn only_managed_claude_settings_without_repo_root_and_home() {
        // System-wide managed settings do not depend on HOME / repo, so
        // they are the only agent settings left when both are absent.
        let env = MapEnv::new(&[]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(None, &cfg, &env);
        assert!(!p.agent_settings.is_empty());
        assert!(
            p.agent_settings
                .iter()
                .all(|q| q.to_string_lossy().contains("managed-")),
            "unexpected agent settings without HOME / repo: {:?}",
            p.agent_settings
        );
        assert!(p.hook_scripts.is_empty());
    }

    #[test]
    fn classify_input_prepared_includes_extra_slice() {
        // The pair variant must classify the union of `paths` and
        // `extra` without forcing a merged Vec. A Bash redirect target
        // arrives via `extra` and should still hit the matching kind.
        let env = MapEnv::new(&[("HOME", "/h")]);
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
        let labels = p.classify_input_prepared(&input, &[], &extra, None);
        assert!(labels.contains(&ProtectedKind::AgentSettings));
    }

    #[test]
    fn collect_includes_repo_local_copilot_settings() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &PathBuf::from("/repo/.github/hooks/ptuf.json"))
        );
    }

    #[test]
    fn collect_enumerates_every_kiro_agent_json_in_both_scopes() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-self-paths-kiro-enum-{}-{}",
            std::process::id(),
            line!()
        ));
        let repo = dir.join("repo");
        let home = dir.join("home");
        std::fs::create_dir_all(repo.join(".kiro/agents")).expect("mkdir repo agents");
        std::fs::create_dir_all(home.join(".kiro/agents")).expect("mkdir home agents");
        std::fs::write(repo.join(".kiro/agents/code-reviewer.json"), "{}").expect("write a");
        std::fs::write(repo.join(".kiro/agents/build.json"), "{}").expect("write b");
        std::fs::write(repo.join(".kiro/agents/notes.md"), "ignored").expect("write md");
        std::fs::write(home.join(".kiro/agents/default.json"), "{}").expect("write home");

        let home_string = home.to_string_lossy().into_owned();
        let env = MapEnv::new(&[("HOME", home_string.as_str())]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(&repo), &cfg, &env);

        let canon = |p: PathBuf| p.canonicalize().unwrap_or(p);
        let expected_a = canon(repo.join(".kiro/agents/code-reviewer.json"));
        let expected_b = canon(repo.join(".kiro/agents/build.json"));
        let expected_home = canon(home.join(".kiro/agents/default.json"));
        let ignored_md = canon(repo.join(".kiro/agents/notes.md"));

        assert!(p.agent_settings.iter().any(|q| q == &expected_a));
        assert!(p.agent_settings.iter().any(|q| q == &expected_b));
        assert!(p.agent_settings.iter().any(|q| q == &expected_home));
        assert!(
            !p.agent_settings.iter().any(|q| q == &ignored_md),
            "non-json agent should be excluded, got {:?}",
            p.agent_settings
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_has_no_kiro_agent_json_when_agents_dir_missing() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        assert!(
            !p.agent_settings
                .iter()
                .any(|q| q.to_string_lossy().contains(".kiro/agents/")),
            "no .kiro/agents/ dir should yield no kiro agent JSON, got {:?}",
            p.agent_settings
        );
    }

    #[test]
    fn collect_extracts_hook_scripts_from_copilot_hooks_json() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-self-paths-copilot-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(dir.join(".github/hooks")).expect("mkdir");
        std::fs::write(
            dir.join(".github/hooks/ptuf.json"),
            r#"{
  "hooks": {
    "preToolUse": [
      {
        "bash": "./hooks/guard.sh hook copilot",
        "powershell": "./hooks/guard.sh hook copilot"
      }
    ]
  }
}"#,
        )
        .expect("write hooks");
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(&dir), &cfg, &env);
        assert!(
            p.hook_scripts
                .iter()
                .any(|path| path == &dir.join("./hooks/guard.sh")),
            "expected hook script from copilot hooks.json, got {:?}",
            p.hook_scripts
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_extracts_hook_scripts_from_kiro_hooks_json() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-self-paths-kiro-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(dir.join(".kiro/agents")).expect("mkdir");
        std::fs::write(
            dir.join(".kiro/agents/ptuf-guarded.json"),
            r#"{
  "hooks": {
    "preToolUse": [
      {
        "command": "./hooks/guard.sh hook kiro"
      }
    ]
  }
}"#,
        )
        .expect("write agent");
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(&dir), &cfg, &env);
        assert!(
            p.hook_scripts
                .iter()
                .any(|path| path == &dir.join("./hooks/guard.sh")),
            "expected hook script from kiro ptuf-guarded.json, got {:?}",
            p.hook_scripts
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classify_matches_edit_of_copilot_settings() {
        let p = ProtectedPaths {
            agent_settings: vec![PathBuf::from("/repo/.github/hooks/ptuf.json")],
            ..ProtectedPaths::default()
        };
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/.github/hooks/ptuf.json"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::AgentSettings));
    }

    #[test]
    fn classify_matches_edit_of_kiro_settings() {
        let p = ProtectedPaths {
            agent_settings: vec![PathBuf::from("/repo/.kiro/agents/ptuf-guarded.json")],
            ..ProtectedPaths::default()
        };
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/.kiro/agents/ptuf-guarded.json"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::AgentSettings));
    }

    #[test]
    fn collect_includes_pi_settings_paths() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-self-pi-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".git")).expect("mkdir .git");
        std::fs::create_dir_all(dir.join(".pi/extensions")).expect("mkdir .pi");
        let home = dir.join("home");
        std::fs::create_dir_all(home.join(".pi/agent/extensions")).expect("mkdir agent");
        let home_string = home.to_string_lossy().into_owned();
        let env = MapEnv::new(&[("HOME", home_string.as_str())]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(&dir), &cfg, &env);
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &dir.join(".pi/extensions/ptuf.ts"))
        );
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &home.join(".pi/agent/extensions/ptuf.ts"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classify_matches_edit_of_pi_settings() {
        let p = ProtectedPaths {
            agent_settings: vec![PathBuf::from("/repo/.pi/extensions/ptuf.ts")],
            ..ProtectedPaths::default()
        };
        let input = HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/.pi/extensions/ptuf.ts"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::AgentSettings));
    }

    #[test]
    fn protected_kind_agent_settings_as_str() {
        assert_eq!(ProtectedKind::AgentSettings.as_str(), "agent_settings");
    }

    #[test]
    fn collect_includes_opencode_settings_paths() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-self-oc-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".git")).expect("mkdir .git");
        std::fs::create_dir_all(dir.join(".opencode/plugins")).expect("mkdir opencode");
        let home = dir.join("home");
        std::fs::create_dir_all(home.join(".config/opencode/plugins")).expect("mkdir config");
        let home_string = home.to_string_lossy().into_owned();
        let env = MapEnv::new(&[
            ("HOME", home_string.as_str()),
            ("XDG_CONFIG_HOME", "/xdg/opencode-config"),
        ]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(&dir), &cfg, &env);
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &PathBuf::from("/xdg/opencode-config/opencode/plugins/ptuf.ts"))
        );
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &PathBuf::from("/xdg/opencode-config/opencode/plugin/ptuf.ts"))
        );
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &dir.join(".opencode/plugins/ptuf.ts"))
        );
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &dir.join(".opencode/plugin/ptuf.ts"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_opencode_settings_falls_back_to_home_dot_config_without_xdg() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-self-oc-fallback-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let home = dir.join("home");
        std::fs::create_dir_all(home.join(".config/opencode/plugins")).expect("mkdir config");
        let home_string = home.to_string_lossy().into_owned();
        let env = MapEnv::new(&[("HOME", home_string.as_str())]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(None, &cfg, &env);
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &home.join(".config/opencode/plugins/ptuf.ts"))
        );
        assert!(
            p.agent_settings
                .iter()
                .any(|q| q == &home.join(".config/opencode/plugin/ptuf.ts"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classify_matches_edit_of_opencode_settings() {
        let p = ProtectedPaths {
            agent_settings: vec![PathBuf::from("/repo/.opencode/plugins/ptuf.ts")],
            ..ProtectedPaths::default()
        };
        let input = HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/.opencode/plugins/ptuf.ts"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::AgentSettings));
    }

    #[test]
    fn match_path_detects_pi_settings_targets() {
        let p = ProtectedPaths {
            agent_settings: vec![
                PathBuf::from("/repo/.pi/settings.json"),
                PathBuf::from("/home/user/.pi/agent/extensions/ptuf/index.ts"),
            ],
            ..ProtectedPaths::default()
        };
        assert_eq!(
            p.match_path(Path::new("/repo/.pi/settings.json")),
            Some(ProtectedKind::AgentSettings)
        );
        assert_eq!(
            p.match_path(Path::new("/home/user/.pi/agent/extensions/ptuf/index.ts")),
            Some(ProtectedKind::AgentSettings)
        );
    }

    #[test]
    fn match_path_detects_opencode_settings_targets() {
        let p = ProtectedPaths {
            agent_settings: vec![
                PathBuf::from("/xdg/opencode/plugins/ptuf.ts"),
                PathBuf::from("/xdg/opencode/plugin/ptuf.ts"),
                PathBuf::from("/repo/.opencode/plugins/ptuf.ts"),
                PathBuf::from("/repo/.opencode/plugin/ptuf.ts"),
            ],
            ..ProtectedPaths::default()
        };
        assert_eq!(
            p.match_path(Path::new("/xdg/opencode/plugins/ptuf.ts")),
            Some(ProtectedKind::AgentSettings)
        );
        assert_eq!(
            p.match_path(Path::new("/xdg/opencode/plugin/ptuf.ts")),
            Some(ProtectedKind::AgentSettings)
        );
        assert_eq!(
            p.match_path(Path::new("/repo/.opencode/plugins/ptuf.ts")),
            Some(ProtectedKind::AgentSettings)
        );
        assert_eq!(
            p.match_path(Path::new("/repo/.opencode/plugin/ptuf.ts")),
            Some(ProtectedKind::AgentSettings)
        );
    }

    #[test]
    fn classify_matches_edit_of_binary_path() {
        let p = ProtectedPaths {
            binary: Some(PathBuf::from("/usr/bin/ptuf")),
            ..ProtectedPaths::default()
        };
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({ "file_path": "/usr/bin/ptuf" }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::Binary));
    }

    #[test]
    fn classify_skips_non_writer_bash_head_with_positional_path() {
        // `echo` is not in the writer_heads allowlist, so its positional
        // arguments — even when they look like protected targets — must
        // not be added to the candidate set. This pins the
        // `!writer_heads.contains(&argv.head_basename())` skip branch.
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({
                "command": "echo /repo/.claude/settings.json"
            }),
        };
        assert!(
            p.classify_input(&input).is_empty(),
            "echo with a path positional must not match — head is not in writer_heads"
        );
    }

    #[test]
    fn classify_skips_self_positional_for_writer_head() {
        // `rm rm` has a positional that equals the head; the
        // `if a == head { continue; }` branch must skip it so the
        // writer-head literal does not get classified as a destination.
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": "rm rm" }),
        };
        // No protected path equals "rm", so the result is empty either
        // way — but the assertion records the intent and stops anyone
        // re-introducing the literal as a candidate.
        assert!(p.classify_input(&input).is_empty());
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
            let env = MapEnv::new(&[("HOME", "/h")]);
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
            let env = MapEnv::new(&[("HOME", home.as_str())]);
            let cfg = Config::default();
            let p = ProtectedPaths::collect_with_env(Some(Path::new(&repo)), &cfg, &env);
            // agent_settings merges every adapter's paths, so it must
            // come out sorted and unique.
            let mut sorted = p.agent_settings.clone();
            sorted.sort();
            sorted.dedup();
            prop_assert_eq!(p.agent_settings.clone(), sorted);
            // configs is also sort+dedup'd.
            let mut sorted_cfg = p.configs.clone();
            sorted_cfg.sort();
            sorted_cfg.dedup();
            prop_assert_eq!(p.configs.clone(), sorted_cfg);
        }
    }
}
