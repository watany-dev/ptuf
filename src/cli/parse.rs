//! Argument-parser submodule.
//!
//! Each `parse_*` helper consumes a peeked iterator and produces a
//! [`Command`] or a [`ParseError`]. The public entry point lives in
//! `cli/mod.rs::parse` so external callers (`src/main.rs`,
//! `tests/cli_smoke.rs`) keep the same path.

use std::path::PathBuf;

use crate::init::cursor::{CursorInitOptions, CursorScope};
use crate::init::kiro::{KiroInitOptions, KiroMode, ScopeFilter};
use crate::init::opencode::{OpencodeInitOptions, OpencodeScope};
use crate::init::pi::{PiInitOptions, PiScope};
use crate::update::UpdateOptions;

use super::{AuditOptions, Command, HookAgent, InitOptions, ParseError};

/// Versioned agent token for the Kiro CLI **v2** adapter — the
/// `.kiro/agents/*.json` + `hooks.preToolUse` contract.
///
/// Kiro CLI changed its hook contract in v3, so each adapter generation
/// gets its own explicit token. A versioned token always resolves to
/// that exact generation and never moves.
const KIRO_V2_AGENT: &str = "kiro-v2";

/// Versioned agent token for the Kiro CLI **v3** adapter — standalone
/// `.kiro/hooks/*.json` documents with the PascalCase `PreToolUse`
/// trigger. See [`KIRO_V2_AGENT`] for why the generation is pinned.
const KIRO_V3_AGENT: &str = "kiro-v3";

/// Unversioned Kiro token: a *floating* alias that resolves to whichever
/// Kiro adapter is newest in this build of ptuf (see
/// [`KIRO_LATEST_AGENT`]). Users who type `ptuf init kiro` are asking
/// for "the current Kiro", so the alias follows ptuf forward across
/// adapter generations.
const KIRO_LATEST_ALIAS: &str = "kiro";

/// The adapter [`KIRO_LATEST_ALIAS`] currently resolves to.
///
/// This is the single point of change when a newer Kiro adapter lands:
/// add its versioned token and repoint this const, and `ptuf init kiro`
/// follows automatically. The `command` written to disk is always pinned
/// to a *versioned* token (`ptuf hook kiro-v2` /
/// `ptuf hook kiro-v3`) so already-installed hook lines stay bound to the
/// adapter that wrote them instead of drifting with the alias.
const KIRO_LATEST_AGENT: HookAgent = HookAgent::KiroV3;

/// Versioned agent token for the OpenCode **v1** plugin API adapter
/// (`@opencode-ai/plugin` + `tool.execute.before`).
///
/// OpenCode's plugin API broke between v1 and v2: a v1 plugin does not
/// load under v2 and vice versa. A versioned token always resolves to
/// that exact generation and never moves.
const OPENCODE_V1_AGENT: &str = "opencode-v1";

/// Versioned agent token for the OpenCode **v2** plugin API adapter
/// (`@opencode/plugin` + `Plugin.define` + `ctx.tool.hook`). See
/// [`OPENCODE_V1_AGENT`] for why the generation is pinned.
const OPENCODE_V2_AGENT: &str = "opencode-v2";

/// Unversioned OpenCode token: a *floating* alias that resolves to
/// whichever OpenCode adapter is newest in this build of ptuf (see
/// [`OPENCODE_LATEST_AGENT`]).
const OPENCODE_LATEST_ALIAS: &str = "opencode";

/// The adapter [`OPENCODE_LATEST_ALIAS`] currently resolves to.
///
/// This is the single point of change when a newer OpenCode plugin API
/// lands: add its versioned token and repoint this const, and
/// `ptuf init opencode` follows automatically. Already-installed plugins
/// stay pinned because the generated plugin spawns a *versioned* token
/// (`ptuf hook opencode-v2`, see
/// [`crate::init::opencode::OpencodeGeneration::hook_token`]).
const OPENCODE_LATEST_AGENT: HookAgent = HookAgent::OpencodeV2;

pub(super) fn parse_init<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let mut agent: Option<HookAgent> = None;
    let mut dry_run = false;
    let mut no_verify = false;
    let mut new_agent = false;
    let mut workspace_only = false;
    let mut global = false;
    let mut shared_scope: Option<SharedScope> = None;
    let mut shared_root: Option<PathBuf> = None;
    let mut cursor_hooks: Option<PathBuf> = None;
    let mut pi_extension: Option<PathBuf> = None;
    while let Some(arg) = iter.next() {
        let arg = arg.as_str();
        if let Some(value) = value_flag(arg, "--scope", iter)? {
            shared_scope = Some(parse_shared_scope(&value)?);
        } else if let Some(value) = value_flag(arg, "--root", iter)? {
            shared_root = Some(PathBuf::from(value));
        } else if let Some(value) = value_flag(arg, "--hooks", iter)? {
            cursor_hooks = Some(PathBuf::from(value));
        } else if let Some(value) = value_flag(arg, "--extension", iter)? {
            pi_extension = Some(PathBuf::from(value));
        } else {
            match arg {
                "--dry-run" => dry_run = true,
                "--no-verify" => no_verify = true,
                "--new-agent" => new_agent = true,
                "--workspace-only" => workspace_only = true,
                "--global" => global = true,
                "claude-code"
                | "codex"
                | "copilot"
                | KIRO_LATEST_ALIAS
                | KIRO_V2_AGENT
                | KIRO_V3_AGENT
                | "cline"
                | "cursor"
                | "pi"
                | OPENCODE_LATEST_ALIAS
                | OPENCODE_V1_AGENT
                | OPENCODE_V2_AGENT => {
                    if agent.is_some() {
                        return Err(ParseError::UnexpectedArgument(arg.to_string()));
                    }
                    agent = Some(parse_agent(arg)?);
                },
                other => return Err(ParseError::UnexpectedArgument(other.to_string())),
            }
        }
    }
    if workspace_only && global {
        return Err(ParseError::ConflictingFlags("--workspace-only vs --global"));
    }
    if new_agent && workspace_only {
        return Err(ParseError::ConflictingFlags(
            "--new-agent vs --workspace-only",
        ));
    }
    if new_agent && agent != Some(HookAgent::KiroV2) {
        return Err(ParseError::ConflictingFlags(
            "--new-agent requires the `kiro-v2` agent",
        ));
    }
    if (workspace_only || global) && !is_kiro(agent) {
        return Err(ParseError::ConflictingFlags(
            "Kiro-only flag requires the `kiro` / `kiro-v2` / `kiro-v3` agent",
        ));
    }
    if agent == Some(HookAgent::KiroV2) && (shared_scope.is_some() || shared_root.is_some()) {
        return Err(ParseError::ConflictingFlags(
            "`--scope` / `--root` are not supported by `kiro-v2`; use --workspace-only / --global",
        ));
    }
    if agent == Some(HookAgent::KiroV3) && shared_scope.is_some() && (workspace_only || global) {
        return Err(ParseError::ConflictingFlags(
            "--scope vs --workspace-only / --global",
        ));
    }
    if cursor_hooks.is_some() && agent != Some(HookAgent::Cursor) {
        return Err(ParseError::ConflictingFlags(
            "Cursor-only flag requires `cursor` agent",
        ));
    }
    if (shared_scope.is_some() || shared_root.is_some())
        && agent != Some(HookAgent::Cursor)
        && agent != Some(HookAgent::Pi)
        && agent != Some(HookAgent::KiroV3)
        && !is_opencode(agent)
    {
        return Err(ParseError::ConflictingFlags(
            "`--scope` / `--root` require `cursor`, `pi`, `opencode`, or `kiro-v3` agent",
        ));
    }
    if pi_extension.is_some() && agent != Some(HookAgent::Pi) {
        return Err(ParseError::ConflictingFlags(
            "Pi-only flag requires `pi` agent",
        ));
    }
    // Dry-run never writes, so the synthetic-deny check would just
    // confirm whatever was already on disk; treat dry-run as "skip
    // verify" rather than as a parse error.
    let verify = !no_verify && !dry_run;
    // Kiro v3 also takes the shared `--scope` / `--root`; a Cursor / Pi /
    // OpenCode `--scope` must not leak into the Kiro options.
    let kiro_v3 = agent == Some(HookAgent::KiroV3);
    let kiro = KiroInitOptions {
        mode: if new_agent {
            KiroMode::NewAgent
        } else {
            KiroMode::PatchExisting
        },
        scope: if workspace_only || (kiro_v3 && shared_scope == Some(SharedScope::Local)) {
            ScopeFilter::WorkspaceOnly
        } else if global || (kiro_v3 && shared_scope == Some(SharedScope::Global)) {
            ScopeFilter::GlobalOnly
        } else {
            ScopeFilter::Both
        },
        root: shared_root.clone().filter(|_| kiro_v3),
    };
    let cursor = CursorInitOptions {
        scope: if agent == Some(HookAgent::Cursor) {
            shared_scope.map(Into::into).unwrap_or_default()
        } else {
            CursorScope::default()
        },
        root: if agent == Some(HookAgent::Cursor) {
            shared_root.clone()
        } else {
            None
        },
        hooks: cursor_hooks,
    };
    let pi = PiInitOptions {
        scope: if agent == Some(HookAgent::Pi) {
            shared_scope.map(Into::into).unwrap_or_default()
        } else {
            PiScope::default()
        },
        root: if agent == Some(HookAgent::Pi) {
            shared_root.clone()
        } else {
            None
        },
        extension: pi_extension,
    };
    let opencode = OpencodeInitOptions {
        scope: if is_opencode(agent) {
            shared_scope.map(Into::into).unwrap_or_default()
        } else {
            OpencodeScope::default()
        },
        root: if is_opencode(agent) {
            shared_root
        } else {
            None
        },
    };
    Ok(Command::Init(InitOptions {
        agent,
        verify,
        dry_run,
        kiro,
        cursor,
        pi,
        opencode,
    }))
}

/// Extract the value for a value-taking flag in either `--flag value` or
/// `--flag=value` form. Returns `Ok(None)` when `arg` is not this flag, so
/// callers can chain checks before falling through to the value-less flags.
fn value_flag<'a, I>(
    arg: &str,
    flag: &'static str,
    iter: &mut I,
) -> Result<Option<String>, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    if arg == flag {
        let value = iter.next().ok_or(ParseError::MissingValue(flag))?;
        Ok(Some(value.clone()))
    } else if let Some(value) = arg
        .strip_prefix(flag)
        .and_then(|rest| rest.strip_prefix('='))
    {
        Ok(Some(value.to_string()))
    } else {
        Ok(None)
    }
}

fn parse_shared_scope(value: &str) -> Result<SharedScope, ParseError> {
    match value {
        "local" => Ok(SharedScope::Local),
        "global" => Ok(SharedScope::Global),
        other => Err(ParseError::UnexpectedArgument(format!("--scope {other}"))),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SharedScope {
    Local,
    Global,
}

impl From<SharedScope> for CursorScope {
    fn from(scope: SharedScope) -> Self {
        match scope {
            SharedScope::Local => Self::Local,
            SharedScope::Global => Self::Global,
        }
    }
}

impl From<SharedScope> for PiScope {
    fn from(scope: SharedScope) -> Self {
        match scope {
            SharedScope::Local => Self::Local,
            SharedScope::Global => Self::Global,
        }
    }
}

impl From<SharedScope> for OpencodeScope {
    fn from(scope: SharedScope) -> Self {
        match scope {
            SharedScope::Local => Self::Local,
            SharedScope::Global => Self::Global,
        }
    }
}

fn parse_agent(value: &str) -> Result<HookAgent, ParseError> {
    match value {
        "claude-code" => Ok(HookAgent::ClaudeCode),
        "codex" => Ok(HookAgent::Codex),
        "copilot" => Ok(HookAgent::Copilot),
        KIRO_LATEST_ALIAS => Ok(KIRO_LATEST_AGENT),
        KIRO_V2_AGENT => Ok(HookAgent::KiroV2),
        KIRO_V3_AGENT => Ok(HookAgent::KiroV3),
        "cline" => Ok(HookAgent::Cline),
        "cursor" => Ok(HookAgent::Cursor),
        "pi" => Ok(HookAgent::Pi),
        OPENCODE_LATEST_ALIAS => Ok(OPENCODE_LATEST_AGENT),
        OPENCODE_V1_AGENT => Ok(HookAgent::OpencodeV1),
        OPENCODE_V2_AGENT => Ok(HookAgent::OpencodeV2),
        other => Err(ParseError::UnknownAgent(other.to_string())),
    }
}

/// True for either Kiro adapter generation. Both accept the
/// `--workspace-only` / `--global` scope filters.
fn is_kiro(agent: Option<HookAgent>) -> bool {
    matches!(agent, Some(HookAgent::KiroV2 | HookAgent::KiroV3))
}

/// True for either OpenCode adapter generation. Both share the same
/// `--scope` / `--root` handling and the same hook I/O contract; only the
/// generated plugin body and its pinned spawn token differ.
fn is_opencode(agent: Option<HookAgent>) -> bool {
    matches!(agent, Some(HookAgent::OpencodeV1 | HookAgent::OpencodeV2))
}

pub(super) fn parse_hook<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let agent = iter.next().ok_or(ParseError::MissingValue("agent"))?;
    let agent = parse_agent(agent)?;
    if let Some(extra) = iter.next() {
        return Err(ParseError::UnexpectedArgument(extra.clone()));
    }
    Ok(Command::HookPreToolUse { agent })
}

pub(super) fn parse_check<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let mut tool: Option<String> = None;
    let mut command: Option<String> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--tool" => {
                let value = iter.next().ok_or(ParseError::MissingValue("--tool"))?;
                tool = Some(value.clone());
            },
            other if other.starts_with("--tool=") => {
                tool = Some(other.trim_start_matches("--tool=").to_string());
            },
            other if command.is_none() => {
                command = Some(other.to_string());
            },
            other => {
                return Err(ParseError::UnexpectedArgument(other.to_string()));
            },
        }
    }
    let tool = tool.ok_or(ParseError::MissingValue("--tool"))?;
    let command = command.ok_or(ParseError::MissingValue("<command>"))?;
    Ok(Command::Check { tool, command })
}

pub(super) fn parse_update<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let mut check = false;
    let mut force = false;
    let mut skip_attestation = false;
    let mut version: Option<String> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--check" => check = true,
            "--force" => force = true,
            "--skip-attestation" => skip_attestation = true,
            "--version" => {
                let value = iter.next().ok_or(ParseError::MissingValue("--version"))?;
                version = Some(value.clone());
            },
            other if other.starts_with("--version=") => {
                version = Some(other.trim_start_matches("--version=").to_string());
            },
            other => return Err(ParseError::UnexpectedArgument(other.to_string())),
        }
    }
    if check && version.is_some() {
        return Err(ParseError::ConflictingFlags("--check vs --version"));
    }
    Ok(Command::Update(UpdateOptions {
        check,
        version,
        force,
        skip_attestation,
    }))
}

pub(super) fn parse_audit<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let mut path = None;
    let mut decision = None;
    let mut rule_id = None;
    let mut tool = None;
    let mut since_secs = None;
    let mut limit = None;
    let mut stats = false;
    while let Some(arg) = iter.next() {
        let arg = arg.as_str();
        if let Some(value) = value_flag(arg, "--path", iter)? {
            path = Some(PathBuf::from(value));
        } else if let Some(value) = value_flag(arg, "--decision", iter)? {
            decision = Some(parse_audit_decision(&value)?);
        } else if let Some(value) = value_flag(arg, "--rule", iter)? {
            rule_id = Some(value);
        } else if let Some(value) = value_flag(arg, "--tool", iter)? {
            tool = Some(value);
        } else if let Some(value) = value_flag(arg, "--since", iter)? {
            since_secs = Some(parse_audit_since(&value)?);
        } else if let Some(value) = value_flag(arg, "--limit", iter)? {
            limit = Some(parse_audit_limit(&value)?);
        } else if arg == "--stats" {
            stats = true;
        } else {
            return Err(ParseError::UnexpectedArgument(arg.to_string()));
        }
    }
    if stats && limit.is_some() {
        return Err(ParseError::ConflictingFlags("--stats vs --limit"));
    }
    Ok(Command::Audit(AuditOptions {
        path,
        decision,
        rule_id,
        tool,
        since_secs,
        limit,
        stats,
    }))
}

fn parse_audit_decision(value: &str) -> Result<String, ParseError> {
    match value {
        "allow" | "monitor" | "ask" | "deny" => Ok(value.to_string()),
        other => Err(ParseError::UnexpectedArgument(format!(
            "--decision {other}"
        ))),
    }
}

fn parse_audit_since(value: &str) -> Result<u64, ParseError> {
    crate::audit::read::parse_since(value, std::time::SystemTime::now())
        .map_err(|_| ParseError::UnexpectedArgument(format!("--since {value}")))
}

fn parse_audit_limit(value: &str) -> Result<usize, ParseError> {
    value
        .parse::<usize>()
        .map_err(|_| ParseError::UnexpectedArgument(format!("--limit {value}")))
}

pub(super) fn parse_plugin<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let sub = iter.next().ok_or(ParseError::MissingValue("subcommand"))?;
    if sub != "check" {
        return Err(ParseError::UnknownCommand(format!("plugin {sub}")));
    }
    let path = iter.next().ok_or(ParseError::MissingValue("<path>"))?;
    if let Some(extra) = iter.next() {
        return Err(ParseError::UnexpectedArgument(extra.clone()));
    }
    Ok(Command::PluginCheck {
        path: PathBuf::from(path),
    })
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::init::cursor::{CursorInitOptions, CursorScope};
    use crate::init::kiro::{KiroInitOptions, KiroMode, ScopeFilter};
    use crate::init::opencode::OpencodeInitOptions;
    use crate::init::pi::{PiInitOptions, PiScope};
    use crate::update::UpdateOptions;

    use super::super::test_support::s;
    use super::super::{
        AuditOptions, Command, GlobalFlags, HookAgent, InitOptions, ParseError, parse,
    };
    use super::{
        KIRO_LATEST_AGENT, KIRO_LATEST_ALIAS, KIRO_V2_AGENT, KIRO_V3_AGENT, OPENCODE_LATEST_AGENT,
        OPENCODE_LATEST_ALIAS, OPENCODE_V1_AGENT, OPENCODE_V2_AGENT, parse_agent,
    };

    fn ok(args: &[&str]) -> (GlobalFlags, Command) {
        parse(&s(args)).unwrap()
    }

    fn cmd(args: &[&str]) -> Command {
        ok(args).1
    }

    #[test]
    fn rejects_no_args_with_missing_subcommand_error() {
        assert!(matches!(
            parse(&[]),
            Err(ParseError::MissingValue("subcommand"))
        ));
    }

    #[test]
    fn parses_help_and_version() {
        assert_eq!(cmd(&["--help"]), Command::Help);
        assert_eq!(cmd(&["-h"]), Command::Help);
        assert_eq!(cmd(&["--version"]), Command::Version);
        assert_eq!(cmd(&["-V"]), Command::Version);
    }

    #[test]
    fn parses_hook_subcommand() {
        assert_eq!(
            cmd(&["hook", "claude-code"]),
            Command::HookPreToolUse {
                agent: HookAgent::ClaudeCode
            }
        );
        assert_eq!(
            cmd(&["hook", "codex"]),
            Command::HookPreToolUse {
                agent: HookAgent::Codex
            }
        );
        assert_eq!(
            cmd(&["hook", "copilot"]),
            Command::HookPreToolUse {
                agent: HookAgent::Copilot
            }
        );
        assert_eq!(
            cmd(&["hook", "kiro"]),
            Command::HookPreToolUse {
                agent: HookAgent::KiroV3
            }
        );
        assert_eq!(
            cmd(&["hook", "kiro-v2"]),
            Command::HookPreToolUse {
                agent: HookAgent::KiroV2
            }
        );
        assert_eq!(
            cmd(&["hook", "kiro-v3"]),
            Command::HookPreToolUse {
                agent: HookAgent::KiroV3
            }
        );
        assert_eq!(
            cmd(&["hook", "cline"]),
            Command::HookPreToolUse {
                agent: HookAgent::Cline
            }
        );
        assert_eq!(
            cmd(&["hook", "cursor"]),
            Command::HookPreToolUse {
                agent: HookAgent::Cursor
            }
        );
        assert_eq!(
            cmd(&["hook", "pi"]),
            Command::HookPreToolUse {
                agent: HookAgent::Pi
            }
        );
        assert_eq!(
            cmd(&["hook", "opencode"]),
            Command::HookPreToolUse {
                agent: HookAgent::OpencodeV2
            }
        );
        assert_eq!(
            cmd(&["hook", "opencode-v1"]),
            Command::HookPreToolUse {
                agent: HookAgent::OpencodeV1
            }
        );
        assert_eq!(
            cmd(&["hook", "opencode-v2"]),
            Command::HookPreToolUse {
                agent: HookAgent::OpencodeV2
            }
        );
    }

    #[test]
    fn rejects_unknown_hook_agent() {
        assert!(matches!(
            parse(&s(&["hook", "other"])),
            Err(ParseError::UnknownAgent(_))
        ));
    }

    /// `kiro-v4` does not exist; it must not silently resolve to the
    /// newest adapter.
    #[test]
    fn rejects_unknown_kiro_generation_token() {
        assert!(matches!(
            parse(&s(&["hook", "kiro-v4"])),
            Err(ParseError::UnknownAgent(_))
        ));
        assert!(matches!(
            parse(&s(&["init", "kiro-v4"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn rejects_extra_args_after_hook() {
        assert!(matches!(
            parse(&s(&["hook", "claude-code", "pre-tool-use"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn hook_requires_agent() {
        assert!(matches!(
            parse(&s(&["hook"])),
            Err(ParseError::MissingValue("agent"))
        ));
    }

    #[test]
    fn hook_rejects_global_json() {
        assert!(matches!(
            parse(&s(&["--json", "hook", "claude-code"])),
            Err(ParseError::ConflictingFlags(_))
        ));
    }

    #[test]
    fn parses_check_with_separate_value() {
        assert_eq!(
            cmd(&["check", "--tool", "Bash", "ls -la"]),
            Command::Check {
                tool: "Bash".into(),
                command: "ls -la".into(),
            }
        );
    }

    #[test]
    fn parses_check_with_equals_form() {
        assert_eq!(
            cmd(&["check", "--tool=Bash", "ls"]),
            Command::Check {
                tool: "Bash".into(),
                command: "ls".into(),
            }
        );
    }

    #[test]
    fn check_requires_tool_and_command() {
        assert!(matches!(
            parse(&s(&["check", "--tool", "Bash"])),
            Err(ParseError::MissingValue("<command>"))
        ));
        assert!(matches!(
            parse(&s(&["check", "ls"])),
            Err(ParseError::MissingValue("--tool"))
        ));
    }

    #[test]
    fn check_extra_positional_argument_is_rejected() {
        assert!(matches!(
            parse(&s(&["check", "--tool", "Bash", "ls", "extra"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn parses_plugin_check_subcommand() {
        assert_eq!(
            cmd(&["plugin", "check", "demo.yaml"]),
            Command::PluginCheck {
                path: PathBuf::from("demo.yaml"),
            }
        );
    }

    #[test]
    fn rejects_unknown_plugin_subcommand() {
        assert!(matches!(
            parse(&s(&["plugin", "test", "demo.yaml"])),
            Err(ParseError::UnknownCommand(_))
        ));
    }

    #[test]
    fn plugin_check_requires_path() {
        assert!(matches!(
            parse(&s(&["plugin", "check"])),
            Err(ParseError::MissingValue("<path>"))
        ));
    }

    #[test]
    fn plugin_check_rejects_extra_argument() {
        assert!(matches!(
            parse(&s(&["plugin", "check", "p.yaml", "extra"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn plugin_requires_a_subcommand() {
        assert!(matches!(
            parse(&s(&["plugin"])),
            Err(ParseError::MissingValue("subcommand"))
        ));
    }

    #[test]
    fn rejects_unknown_top_level_command() {
        assert!(matches!(
            parse(&s(&["unknown-cmd"])),
            Err(ParseError::UnknownCommand(_))
        ));
    }

    #[test]
    fn parses_init_no_agent_returns_init_with_none() {
        let (g, c) = ok(&["init"]);
        assert!(!g.json);
        assert_eq!(
            c,
            Command::Init(InitOptions {
                agent: None,
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions::default(),
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parses_init_with_each_agent_token() {
        for (token, expected) in [
            ("claude-code", HookAgent::ClaudeCode),
            ("codex", HookAgent::Codex),
            ("copilot", HookAgent::Copilot),
            ("kiro", HookAgent::KiroV3),
            ("kiro-v2", HookAgent::KiroV2),
            ("kiro-v3", HookAgent::KiroV3),
            ("cline", HookAgent::Cline),
            ("cursor", HookAgent::Cursor),
            ("pi", HookAgent::Pi),
            ("opencode", HookAgent::OpencodeV2),
            ("opencode-v1", HookAgent::OpencodeV1),
            ("opencode-v2", HookAgent::OpencodeV2),
        ] {
            let c = cmd(&["init", token]);
            assert_eq!(
                c,
                Command::Init(InitOptions {
                    agent: Some(expected),
                    verify: true,
                    dry_run: false,
                    kiro: KiroInitOptions::default(),
                    cursor: CursorInitOptions::default(),
                    pi: PiInitOptions::default(),
                    opencode: OpencodeInitOptions::default(),
                }),
                "agent token {token}",
            );
        }
    }

    #[test]
    fn parses_init_no_verify_flag() {
        assert_eq!(
            cmd(&["init", "--no-verify"]),
            Command::Init(InitOptions {
                agent: None,
                verify: false,
                dry_run: false,
                kiro: KiroInitOptions::default(),
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parses_init_dry_run_implies_verify_off() {
        assert_eq!(
            cmd(&["init", "--dry-run"]),
            Command::Init(InitOptions {
                agent: None,
                verify: false,
                dry_run: true,
                kiro: KiroInitOptions::default(),
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parses_init_with_agent_and_dry_run() {
        assert_eq!(
            cmd(&["init", "claude-code", "--dry-run"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::ClaudeCode),
                verify: false,
                dry_run: true,
                kiro: KiroInitOptions::default(),
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_accepts_new_agent_with_kiro() {
        assert_eq!(
            cmd(&["init", "kiro-v2", "--new-agent"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::KiroV2),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions {
                    mode: KiroMode::NewAgent,
                    scope: ScopeFilter::Both,
                    root: None,
                },
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_accepts_workspace_only_with_kiro() {
        assert_eq!(
            cmd(&["init", "kiro-v2", "--workspace-only"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::KiroV2),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions {
                    mode: KiroMode::PatchExisting,
                    scope: ScopeFilter::WorkspaceOnly,
                    root: None,
                },
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_accepts_global_with_kiro() {
        assert_eq!(
            cmd(&["init", "kiro-v2", "--global"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::KiroV2),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions {
                    mode: KiroMode::PatchExisting,
                    scope: ScopeFilter::GlobalOnly,
                    root: None,
                },
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    /// `--workspace-only` / `--global` keep working on the `kiro` alias
    /// after it moved to v3, and mean the same as `--scope local|global`
    /// there. `--new-agent` is a v2-only agent-profile mode.
    #[test]
    fn parse_init_maps_kiro_scope_flags_onto_v3() {
        let v3 = |scope, root: Option<&str>| {
            Command::Init(InitOptions {
                agent: Some(HookAgent::KiroV3),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions {
                    mode: KiroMode::PatchExisting,
                    scope,
                    root: root.map(PathBuf::from),
                },
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
            })
        };
        for token in [KIRO_LATEST_ALIAS, KIRO_V3_AGENT] {
            assert_eq!(cmd(&["init", token]), v3(ScopeFilter::Both, None));
            for (args, scope) in [
                (&["--workspace-only"][..], ScopeFilter::WorkspaceOnly),
                (&["--scope", "local"][..], ScopeFilter::WorkspaceOnly),
                (&["--global"][..], ScopeFilter::GlobalOnly),
                (&["--scope", "global"][..], ScopeFilter::GlobalOnly),
            ] {
                let mut argv = vec!["init", token];
                argv.extend_from_slice(args);
                assert_eq!(cmd(&argv), v3(scope, None), "{argv:?}");
            }
            assert_eq!(
                cmd(&["init", token, "--scope", "local", "--root", "/repo"]),
                v3(ScopeFilter::WorkspaceOnly, Some("/repo"))
            );
        }
    }

    #[test]
    fn parse_init_rejects_kiro_flag_combinations_per_generation() {
        for combo in [
            vec!["init", "kiro", "--new-agent"],
            vec!["init", "kiro-v3", "--new-agent"],
            vec!["init", "kiro-v3", "--scope", "local", "--global"],
            vec!["init", "kiro-v3", "--scope", "global", "--workspace-only"],
            vec!["init", "kiro-v2", "--scope", "local"],
            vec!["init", "kiro-v2", "--root", "/x"],
            vec!["init", "kiro", "--workspace-only", "--global"],
            vec!["init", "--global"],
            vec!["init", "cursor", "--workspace-only"],
        ] {
            assert!(
                matches!(parse(&s(&combo)), Err(ParseError::ConflictingFlags(_))),
                "expected ConflictingFlags for {combo:?}",
            );
        }
    }

    /// The unversioned `kiro` token is a *floating* alias: it resolves
    /// to whichever Kiro adapter is newest in this build, not to a fixed
    /// generation. Pinning the assertion to `KIRO_LATEST_AGENT` (rather
    /// than to a concrete variant) is what makes this test keep guarding
    /// the intent whenever a newer adapter lands — repointing the const
    /// must carry the alias with it.
    #[test]
    fn bare_kiro_token_resolves_to_the_latest_kiro_adapter() {
        assert_eq!(parse_agent(KIRO_LATEST_ALIAS), Ok(KIRO_LATEST_AGENT));
        assert_eq!(
            cmd(&["hook", KIRO_LATEST_ALIAS]),
            Command::HookPreToolUse {
                agent: KIRO_LATEST_AGENT
            }
        );
    }

    /// Versioned tokens are the opposite: each one is frozen to its own
    /// adapter generation and must never follow the alias forward.
    #[test]
    fn kiro_versioned_tokens_are_pinned_to_their_adapter() {
        assert_eq!(parse_agent(KIRO_V2_AGENT), Ok(HookAgent::KiroV2));
        assert_eq!(parse_agent(KIRO_V3_AGENT), Ok(HookAgent::KiroV3));
        assert_eq!(parse_agent(KIRO_LATEST_ALIAS), Ok(HookAgent::KiroV3));
    }

    /// The bare `opencode` token floats to the newest OpenCode adapter,
    /// while `opencode-v1` / `opencode-v2` stay pinned to their own plugin
    /// API generation. A v1 plugin does not load under v2 (and vice
    /// versa), so the generation must never drift with the alias.
    #[test]
    fn opencode_tokens_split_floating_alias_from_pinned_generations() {
        assert_eq!(
            parse_agent(OPENCODE_LATEST_ALIAS),
            Ok(OPENCODE_LATEST_AGENT)
        );
        assert_eq!(
            parse_agent(OPENCODE_LATEST_ALIAS),
            Ok(HookAgent::OpencodeV2)
        );
        assert_eq!(parse_agent(OPENCODE_V1_AGENT), Ok(HookAgent::OpencodeV1));
        assert_eq!(parse_agent(OPENCODE_V2_AGENT), Ok(HookAgent::OpencodeV2));
        assert_eq!(
            cmd(&["hook", OPENCODE_LATEST_ALIAS]),
            Command::HookPreToolUse {
                agent: OPENCODE_LATEST_AGENT
            }
        );
    }

    /// `opencode-v3` is a future adapter with a different plugin API; it
    /// must not silently resolve to the v2 adapter.
    #[test]
    fn rejects_opencode_v3_agent_token() {
        assert!(matches!(
            parse(&s(&["hook", "opencode-v3"])),
            Err(ParseError::UnknownAgent(_))
        ));
        assert!(matches!(
            parse(&s(&["init", "opencode-v3"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    /// `--scope` / `--root` are shared by both OpenCode generations, so
    /// either versioned token must thread them into `OpencodeInitOptions`.
    #[test]
    fn parse_init_accepts_scope_and_root_with_either_opencode_generation() {
        for token in [OPENCODE_V1_AGENT, OPENCODE_V2_AGENT] {
            let agent = parse_agent(token).unwrap();
            assert_eq!(
                cmd(&["init", token, "--scope", "local", "--root", "/repo"]),
                Command::Init(InitOptions {
                    agent: Some(agent),
                    verify: true,
                    dry_run: false,
                    kiro: KiroInitOptions::default(),
                    cursor: CursorInitOptions::default(),
                    pi: PiInitOptions::default(),
                    opencode: OpencodeInitOptions {
                        scope: crate::init::opencode::OpencodeScope::Local,
                        root: Some(PathBuf::from("/repo")),
                    },
                }),
                "token {token}",
            );
        }
    }

    /// The implicit `opencode` alias must also accept `--scope` /
    /// `--root`; it resolves to the v2 adapter today.
    #[test]
    fn parse_init_accepts_scope_with_bare_opencode_alias() {
        assert_eq!(
            cmd(&["init", OPENCODE_LATEST_ALIAS, "--scope", "local"]),
            Command::Init(InitOptions {
                agent: Some(OPENCODE_LATEST_AGENT),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions::default(),
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions {
                    scope: crate::init::opencode::OpencodeScope::Local,
                    root: None,
                },
            }),
        );
    }

    #[test]
    fn parse_init_accepts_new_agent_with_global() {
        assert_eq!(
            cmd(&["init", "kiro-v2", "--new-agent", "--global"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::KiroV2),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions {
                    mode: KiroMode::NewAgent,
                    scope: ScopeFilter::GlobalOnly,
                    root: None,
                },
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_rejects_workspace_only_with_global() {
        assert!(matches!(
            parse(&s(&["init", "kiro", "--workspace-only", "--global"])),
            Err(ParseError::ConflictingFlags(_))
        ));
    }

    #[test]
    fn parse_init_rejects_new_agent_with_workspace_only() {
        assert!(matches!(
            parse(&s(&["init", "kiro", "--new-agent", "--workspace-only"])),
            Err(ParseError::ConflictingFlags(_))
        ));
    }

    #[test]
    fn parse_init_rejects_kiro_flag_without_kiro_agent() {
        for combo in [
            vec!["init", "--new-agent"],
            vec!["init", "--workspace-only"],
            vec!["init", "--global"],
            vec!["init", "claude-code", "--new-agent"],
            vec!["init", "codex", "--workspace-only"],
            vec!["init", "copilot", "--global"],
        ] {
            assert!(
                matches!(parse(&s(&combo)), Err(ParseError::ConflictingFlags(_))),
                "expected ConflictingFlags for {combo:?}",
            );
        }
    }

    #[test]
    fn parse_init_accepts_scope_global_with_pi() {
        assert_eq!(
            cmd(&["init", "pi", "--scope", "global"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::Pi),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions::default(),
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions {
                    scope: PiScope::Global,
                    root: None,
                    extension: None,
                },
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_accepts_scope_local_with_pi_and_root() {
        assert_eq!(
            cmd(&["init", "pi", "--scope", "local", "--root", "/repo"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::Pi),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions::default(),
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions {
                    scope: PiScope::Local,
                    root: Some(PathBuf::from("/repo")),
                    extension: None,
                },
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_rejects_scope_without_cursor_or_pi_agent() {
        assert!(matches!(
            parse(&s(&["init", "--scope", "global"])),
            Err(ParseError::ConflictingFlags(_))
        ));
    }

    #[test]
    fn parse_init_accepts_extension_with_pi() {
        assert_eq!(
            cmd(&["init", "pi", "--extension", "/tmp/ptuf.ts"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::Pi),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions::default(),
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions {
                    scope: PiScope::default(),
                    root: None,
                    extension: Some(PathBuf::from("/tmp/ptuf.ts")),
                },
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_rejects_pi_extension_without_pi_agent() {
        assert!(matches!(
            parse(&s(&["init", "--extension", "/tmp/ptuf.ts"])),
            Err(ParseError::ConflictingFlags(_))
        ));
    }

    #[test]
    fn parse_init_accepts_scope_global_with_cursor() {
        assert_eq!(
            cmd(&["init", "cursor", "--scope", "global"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::Cursor),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
                cursor: CursorInitOptions {
                    scope: CursorScope::Global,
                    root: None,
                    hooks: None,
                },
                pi: PiInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_accepts_scope_local_equals_form_with_cursor() {
        assert_eq!(
            cmd(&["init", "cursor", "--scope=local"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::Cursor),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
                cursor: CursorInitOptions {
                    scope: CursorScope::Local,
                    root: None,
                    hooks: None,
                },
                pi: PiInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_accepts_root_and_hooks_with_cursor() {
        assert_eq!(
            cmd(&[
                "init",
                "cursor",
                "--root",
                "/repo",
                "--hooks",
                "/tmp/h.json"
            ]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::Cursor),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
                cursor: CursorInitOptions {
                    scope: CursorScope::Local,
                    root: Some(PathBuf::from("/repo")),
                    hooks: Some(PathBuf::from("/tmp/h.json")),
                },
                pi: PiInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_rejects_cursor_flag_without_cursor_agent() {
        for combo in [
            vec!["init", "--scope", "global"],
            vec!["init", "--root", "/x"],
            vec!["init", "--hooks", "/x.json"],
            vec!["init", "claude-code", "--scope", "local"],
            vec!["init", "kiro-v2", "--root", "/x"],
        ] {
            assert!(
                matches!(parse(&s(&combo)), Err(ParseError::ConflictingFlags(_))),
                "expected ConflictingFlags for {combo:?}",
            );
        }
    }

    #[test]
    fn parse_init_rejects_invalid_scope_value() {
        assert!(matches!(
            parse(&s(&["init", "cursor", "--scope", "workspace"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn parse_init_requires_value_for_cursor_flags() {
        assert!(matches!(
            parse(&s(&["init", "cursor", "--scope"])),
            Err(ParseError::MissingValue("--scope"))
        ));
        assert!(matches!(
            parse(&s(&["init", "cursor", "--root"])),
            Err(ParseError::MissingValue("--root"))
        ));
        assert!(matches!(
            parse(&s(&["init", "cursor", "--hooks"])),
            Err(ParseError::MissingValue("--hooks"))
        ));
    }

    #[test]
    fn init_rejects_two_agent_tokens() {
        assert!(matches!(
            parse(&s(&["init", "claude-code", "codex"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn init_rejects_unknown_flags() {
        assert!(matches!(
            parse(&s(&["init", "--bogus"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
        assert!(matches!(
            parse(&s(&["init", "claude-code", "--settings=/tmp/x.json"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn parse_global_json_before_subcommand() {
        let (g, c) = ok(&["--json", "init"]);
        assert!(g.json);
        assert!(matches!(c, Command::Init(_)));
    }

    #[test]
    fn parse_global_json_then_check() {
        let (g, c) = ok(&["--json", "check", "--tool", "Bash", "ls"]);
        assert!(g.json);
        assert!(matches!(c, Command::Check { .. }));
    }

    #[test]
    fn parse_global_json_after_subcommand_is_unknown_arg() {
        assert!(matches!(
            parse(&s(&["init", "--json"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
        assert!(matches!(
            parse(&s(&["check", "--tool", "Bash", "ls", "--json"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn parses_update_no_flags() {
        assert_eq!(
            cmd(&["update"]),
            Command::Update(UpdateOptions {
                check: false,
                version: None,
                force: false,
                skip_attestation: false,
            })
        );
    }

    #[test]
    fn parses_update_check_flag() {
        assert_eq!(
            cmd(&["update", "--check"]),
            Command::Update(UpdateOptions {
                check: true,
                version: None,
                force: false,
                skip_attestation: false,
            })
        );
    }

    #[test]
    fn parses_update_version_pin_separate_value() {
        assert_eq!(
            cmd(&["update", "--version", "v0.2.0"]),
            Command::Update(UpdateOptions {
                check: false,
                version: Some("v0.2.0".to_string()),
                force: false,
                skip_attestation: false,
            })
        );
    }

    #[test]
    fn parses_update_version_pin_equals_form() {
        assert_eq!(
            cmd(&["update", "--version=v0.2.0"]),
            Command::Update(UpdateOptions {
                check: false,
                version: Some("v0.2.0".to_string()),
                force: false,
                skip_attestation: false,
            })
        );
    }

    #[test]
    fn parses_update_force_flag() {
        assert_eq!(
            cmd(&["update", "--force"]),
            Command::Update(UpdateOptions {
                check: false,
                version: None,
                force: true,
                skip_attestation: false,
            })
        );
    }

    #[test]
    fn parses_update_combines_force_and_version() {
        assert_eq!(
            cmd(&["update", "--version", "v0.2.0", "--force"]),
            Command::Update(UpdateOptions {
                check: false,
                version: Some("v0.2.0".to_string()),
                force: true,
                skip_attestation: false,
            })
        );
    }

    #[test]
    fn parses_update_skip_attestation_flag() {
        assert_eq!(
            cmd(&["update", "--skip-attestation"]),
            Command::Update(UpdateOptions {
                check: false,
                version: None,
                force: false,
                skip_attestation: true,
            })
        );
    }

    #[test]
    fn update_rejects_check_with_version() {
        assert!(matches!(
            parse(&s(&["update", "--check", "--version", "v0.2.0"])),
            Err(ParseError::ConflictingFlags(_))
        ));
        assert!(matches!(
            parse(&s(&["update", "--version=v0.2.0", "--check"])),
            Err(ParseError::ConflictingFlags(_))
        ));
    }

    #[test]
    fn update_rejects_unknown_flag() {
        assert!(matches!(
            parse(&s(&["update", "--bogus"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn update_rejects_positional_argument() {
        assert!(matches!(
            parse(&s(&["update", "extra"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn update_requires_value_for_version_flag() {
        assert!(matches!(
            parse(&s(&["update", "--version"])),
            Err(ParseError::MissingValue("--version"))
        ));
    }

    #[test]
    fn update_rejects_global_json() {
        assert!(matches!(
            parse(&s(&["--json", "update"])),
            Err(ParseError::ConflictingFlags(_))
        ));
    }

    #[test]
    fn parses_audit_defaults() {
        assert_eq!(cmd(&["audit"]), Command::Audit(AuditOptions::default()));
    }

    #[test]
    fn parses_audit_flags_and_equals_form() {
        assert_eq!(
            cmd(&[
                "audit",
                "--path",
                "/tmp/a.jsonl",
                "--decision=deny",
                "--rule",
                "core.x",
                "--tool=Bash",
                "--since=2024-01-01T00:00:00Z",
                "--limit",
                "5",
            ]),
            Command::Audit(AuditOptions {
                path: Some(PathBuf::from("/tmp/a.jsonl")),
                decision: Some("deny".into()),
                rule_id: Some("core.x".into()),
                tool: Some("Bash".into()),
                since_secs: Some(1_704_067_200),
                limit: Some(5),
                stats: false,
            })
        );
    }

    #[test]
    fn parses_audit_stats_without_limit() {
        assert_eq!(
            cmd(&["audit", "--stats"]),
            Command::Audit(AuditOptions {
                stats: true,
                ..AuditOptions::default()
            })
        );
    }

    #[test]
    fn parses_audit_limit_zero() {
        assert_eq!(
            cmd(&["audit", "--limit", "0"]),
            Command::Audit(AuditOptions {
                limit: Some(0),
                ..AuditOptions::default()
            })
        );
    }

    #[test]
    fn parses_audit_accepts_global_json() {
        let (g, c) = ok(&["--json", "audit"]);
        assert!(g.json);
        assert!(matches!(c, Command::Audit(_)));
    }

    #[test]
    fn audit_rejects_invalid_decision() {
        assert!(matches!(
            parse(&s(&["audit", "--decision", "block"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn audit_rejects_non_numeric_limit() {
        assert!(matches!(
            parse(&s(&["audit", "--limit", "all"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn audit_rejects_stats_with_limit() {
        assert!(matches!(
            parse(&s(&["audit", "--stats", "--limit", "1"])),
            Err(ParseError::ConflictingFlags(_))
        ));
        assert!(matches!(
            parse(&s(&["audit", "--limit=0", "--stats"])),
            Err(ParseError::ConflictingFlags(_))
        ));
    }

    #[test]
    fn audit_rejects_bad_since() {
        assert!(matches!(
            parse(&s(&["audit", "--since", "yesterday"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn audit_rejects_unknown_flag() {
        assert!(matches!(
            parse(&s(&["audit", "--bogus"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn audit_requires_values_and_accepts_remaining_decisions() {
        for flag in [
            "--path",
            "--decision",
            "--rule",
            "--tool",
            "--since",
            "--limit",
        ] {
            assert!(
                matches!(
                    parse(&s(&["audit", flag])),
                    Err(ParseError::MissingValue(_))
                ),
                "{flag}"
            );
        }
        for decision in ["allow", "monitor", "ask"] {
            assert_eq!(
                cmd(&["audit", "--decision", decision]),
                Command::Audit(AuditOptions {
                    decision: Some(decision.into()),
                    ..AuditOptions::default()
                })
            );
        }
        assert!(matches!(
            parse(&s(&["audit", "--since", "18446744073709551615m"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
        match cmd(&["audit", "--since", "1h"]) {
            Command::Audit(opts) => assert!(opts.since_secs.is_some()),
            other => panic!("expected audit, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_display() {
        assert!(format!("{}", ParseError::UnknownCommand("x".into())).contains("unknown command"));
        assert!(format!("{}", ParseError::UnknownAgent("x".into())).contains("unknown agent"));
        assert!(format!("{}", ParseError::MissingValue("x")).contains("missing value"));
        assert!(format!("{}", ParseError::UnexpectedArgument("x".into())).contains("unexpected"));
        assert!(
            format!("{}", ParseError::ConflictingFlags("a vs b")).contains("conflicting flags")
        );
    }
}
