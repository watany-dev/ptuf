//! CLI surface — public types, top-level dispatch, and the engine
//! fail-closed bootstrap.
//!
//! Argument parsing lives in `parse`, subcommand execution lives in
//! `run`, and decision/exit-code rendering lives in `output`. The
//! `parse` and `run` symbols are re-exported here so external callers
//! (`src/main.rs`, `tests/cli_smoke.rs`) keep their existing import
//! paths.

use std::io::{Read, Write};
use std::path::PathBuf;

use crate::Decision;
use crate::engine::Engine;
use crate::reason;

mod copilot_input;
mod kiro_input;
mod output;
mod parse;
mod run;

#[cfg(test)]
mod test_support;

/// Reserved rule id used when the engine itself failed to load policy
/// and the CLI must fail-closed
/// (`docs/design/cli-and-hooks.md:104-114`).
pub(crate) const POLICY_LOAD_FAILED_RULE: &str = "core.engine.policy-load-failed";
/// Reserved rule id used when the hook stdin payload is unreadable,
/// oversized, or not valid JSON. Claude Code treats `exit 1` as a
/// non-blocking warning, so these initialisation failures must surface
/// as a `Decision::Deny` (exit 2) to preserve the fail-closed contract.
pub(crate) const INVALID_PAYLOAD_RULE: &str = "core.engine.invalid-payload";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAgent {
    ClaudeCode,
    Codex,
    Copilot,
    Kiro,
}

impl HookAgent {
    pub(super) fn audit_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Copilot => "copilot",
            Self::Kiro => "kiro",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClaudeInitOptions {
    pub settings_path: Option<PathBuf>,
    pub verify: bool,
    pub json: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodexInitOptions {
    pub root: Option<PathBuf>,
    pub hooks_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub verify: bool,
    pub json: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CopilotProfile {
    #[default]
    Local,
    Cloud,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopilotInitOptions {
    pub root: Option<PathBuf>,
    pub hooks_path: Option<PathBuf>,
    pub profile: CopilotProfile,
    pub verify: bool,
    pub json: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InitOptions {
    ClaudeCode(ClaudeInitOptions),
    Codex(CodexInitOptions),
    Copilot(CopilotInitOptions),
}

/// Build the engine for the CWD-derived project scope, or surface a
/// reserved deny so the CLI can render a fail-closed response.
///
/// Production CLI entry points (`hook ...` / `eval`) all go through
/// this helper. The `crate::decide` shim is intentionally lenient
/// (`Engine::default` fallback) for embedded library use.
///
/// `agent` is the adapter name surfaced in audit records — `"claude-code"`
/// for hook entry, `"cli"` for eval.
pub(crate) fn build_engine_or_fail_closed<W: Write>(
    stderr: &mut W,
    agent: &'static str,
) -> Result<Engine, Decision> {
    match Engine::for_cwd() {
        Ok(engine) => Ok(engine.with_agent(agent)),
        Err(err) => {
            let _ = writeln!(stderr, "ptuf: could not load policy: {err}");
            Err(policy_load_failed_deny())
        },
    }
}

fn policy_load_failed_deny() -> Decision {
    Decision::Deny {
        rule_id: POLICY_LOAD_FAILED_RULE.into(),
        reason: reason::build(
            POLICY_LOAD_FAILED_RULE,
            "ptuf could not load policy and is failing closed",
            &["fix the configuration error reported on stderr and re-run"],
        ),
    }
}

/// Parsed CLI invocation. The bare invocation (no arguments) is
/// rejected as a usage error so callers must always pick a subcommand.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// `ptuf hook <agent>` — read JSON payload from stdin and emit an
    /// agent-specific `hookSpecificOutput` response on stdout.
    HookPreToolUse { agent: HookAgent },
    /// `ptuf eval --tool <name> <command>` — manual evaluation.
    Eval { tool: String, command: String },
    /// `ptuf plugin test <path>` — run plugin assertions.
    PluginTest { path: PathBuf },
    /// `ptuf init <agent> [--dry-run] [--settings <PATH>]` — install the
    /// PreToolUse hook entry.
    Init { dry_run: bool, options: InitOptions },
    /// `ptuf doctor [--json]` — print a diagnostic report.
    Doctor { json: bool },
    /// `--help` / `-h`.
    Help,
    /// `--version` / `-V`.
    Version,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    UnknownCommand(String),
    UnknownAgent(String),
    MissingValue(&'static str),
    UnexpectedArgument(String),
    ConflictingFlags(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCommand(c) => write!(f, "unknown command: {c}"),
            Self::UnknownAgent(a) => write!(f, "unknown agent: {a}"),
            Self::MissingValue(name) => write!(f, "missing value for {name}"),
            Self::UnexpectedArgument(a) => write!(f, "unexpected argument: {a}"),
            Self::ConflictingFlags(detail) => write!(f, "conflicting flags: {detail}"),
        }
    }
}

/// Parse argv (excluding the program name) into a [`Command`].
pub fn parse(args: &[String]) -> Result<Command, ParseError> {
    let mut iter = args.iter();
    let first = iter.next().ok_or(ParseError::MissingValue("subcommand"))?;

    match first.as_str() {
        "-h" | "--help" => Ok(Command::Help),
        "-V" | "--version" => Ok(Command::Version),
        "hook" => parse::parse_hook(&mut iter),
        "eval" => parse::parse_eval(&mut iter),
        "plugin" => parse::parse_plugin(&mut iter),
        "init" => parse::parse_init(&mut iter),
        "doctor" => parse::parse_doctor(&mut iter),
        other => Err(ParseError::UnknownCommand(other.to_string())),
    }
}

const HELP: &str = "ptuf — PreToolUseFilter, a guardrail for coding agents

USAGE:
    ptuf hook <AGENT>                            (run as the agent's PreToolUse hook;
                                                  AGENT = claude-code | codex | copilot | kiro)
    ptuf eval --tool <NAME> <COMMAND>            (evaluate a single tool call)
    ptuf plugin test <PATH>                      (run a plugin's deny/allow tests)
    ptuf init claude-code [--dry-run]            (register hook in
                          [--settings <PATH>]    ~/.claude/settings.json;
                          [--verify [--json]]    --verify runs synthetic deny +
                                                  fail-closed checks after install)
    ptuf init codex [--dry-run]                  (register repo-local Codex hook in
                    [--root <PATH>]              <repo>/.codex/{hooks.json,config.toml})
                    [--hooks <PATH>]
                    [--config <PATH>]
                    [--verify [--json]]
    ptuf init copilot [--dry-run]                (register repo-local Copilot hook in
                      [--root <PATH>]            <repo>/.github/hooks/ptuf.json)
                      [--hooks <PATH>]
                      [--profile local|cloud]
                      [--verify [--json]]
    ptuf doctor [--json]                         (print a diagnostic report)
    ptuf --help | --version

EXIT CODES:
    0   allow / monitor / ask / plugin tests pass
    1   non-hook internal error (eval / plugin / init / doctor / bad arguments)
        or plugin tests fail
    2   deny — including hook initialisation failures (invalid stdin payload,
        policy load error)
";

/// Run a parsed [`Command`] against the given I/O streams. Returns the u8
/// exit code so [`crate::io_runner::run`] can wrap it in [`std::process::ExitCode`].
pub fn run<R: Read, W1: Write, W2: Write>(
    command: Command,
    stdin: R,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    match command {
        Command::HookPreToolUse { agent } => run::run_hook(agent, stdin, stdout, stderr),
        Command::Eval { tool, command } => run::run_eval(&tool, &command, stdout, stderr),
        Command::PluginTest { path } => run::run_plugin_test(&path, stdout, stderr),
        Command::Init { dry_run, options } => run::run_init(options, dry_run, stdout, stderr),
        Command::Doctor { json } => run::run_doctor(json, stdout, stderr),
        Command::Help => {
            let _ = writeln!(stdout, "{HELP}");
            0
        },
        Command::Version => {
            let _ = writeln!(stdout, "ptuf {}", env!("CARGO_PKG_VERSION"));
            0
        },
    }
}

#[cfg(test)]
mod tests {

    use super::HookAgent;

    #[test]
    fn hook_agent_audit_name_distinguishes_variants() {
        assert_eq!(HookAgent::ClaudeCode.audit_name(), "claude-code");
        assert_eq!(HookAgent::Codex.audit_name(), "codex");
        assert_eq!(HookAgent::Copilot.audit_name(), "copilot");
        assert_eq!(HookAgent::Kiro.audit_name(), "kiro");
    }
}
