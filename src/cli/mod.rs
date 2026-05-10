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
mod input_helpers;
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

/// Parsed `ptuf init [<agent>] [--no-verify] [--dry-run]`.
///
/// `agent = None` means "auto-detect every agent reachable from
/// `cwd` / `$HOME`". `verify` defaults to `true`; `--no-verify`
/// flips it off, and `--dry-run` implicitly disables verify (a
/// dry run never writes, so the synthetic-deny check would just
/// confirm the unmodified disk state).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InitOptions {
    pub agent: Option<HookAgent>,
    pub verify: bool,
    pub dry_run: bool,
}

/// Top-level flags that apply uniformly across subcommands.
///
/// Currently only `--json`, accepted exclusively before the
/// subcommand token (`ptuf --json init`). Per-subcommand
/// `--json` was removed in the v0 simplification; `hook` rejects
/// `--json` at parse time because the hook protocol output shape
/// is fixed by Claude Code / Codex / Copilot / Kiro.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GlobalFlags {
    pub json: bool,
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
    /// `ptuf check --tool <name> <command>` — manual evaluation.
    Check { tool: String, command: String },
    /// `ptuf plugin check <path>` — run plugin assertions.
    PluginCheck { path: PathBuf },
    /// `ptuf init [<agent>] [--no-verify] [--dry-run]` — install the
    /// PreToolUse hook entry. `agent = None` auto-detects every
    /// agent reachable from cwd / `$HOME`.
    Init(InitOptions),
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

/// Parse argv (excluding the program name) into a [`GlobalFlags`] +
/// [`Command`]. `--json` is accepted only as a leading global flag —
/// any later occurrence is rejected by the subcommand parser as an
/// unexpected argument.
pub fn parse(args: &[String]) -> Result<(GlobalFlags, Command), ParseError> {
    let mut iter = args.iter().peekable();
    let mut globals = GlobalFlags::default();
    while let Some(a) = iter.peek() {
        if a.as_str() == "--json" {
            globals.json = true;
            iter.next();
        } else {
            break;
        }
    }
    let first = iter.next().ok_or(ParseError::MissingValue("subcommand"))?;

    let cmd = match first.as_str() {
        "-h" | "--help" => Command::Help,
        "-V" | "--version" => Command::Version,
        "hook" => parse::parse_hook(&mut iter)?,
        "check" => parse::parse_check(&mut iter)?,
        "plugin" => parse::parse_plugin(&mut iter)?,
        "init" => parse::parse_init(&mut iter)?,
        other => return Err(ParseError::UnknownCommand(other.to_string())),
    };

    if globals.json && matches!(cmd, Command::HookPreToolUse { .. }) {
        return Err(ParseError::ConflictingFlags(
            "--json is meaningless for `hook`",
        ));
    }
    Ok((globals, cmd))
}

const HELP: &str = "ptuf — PreToolUseFilter, a guardrail for coding agents

USAGE:
    ptuf [--json] init [<AGENT>] [--no-verify] [--dry-run]
        (auto-detect every agent under cwd / $HOME and install the
         PreToolUse hook with verify enabled by default. AGENT pins
         to a single adapter: claude-code | codex | copilot | kiro)
    ptuf hook <AGENT>
        (run as the agent's PreToolUse hook over stdin/stdout)
    ptuf [--json] check --tool <NAME> <COMMAND>
        (evaluate a single tool call against the active policy)
    ptuf [--json] plugin check <PATH>
        (run a plugin's deny/allow tests)
    ptuf --help | --version

EXIT CODES:
    0   allow / monitor / ask / plugin tests pass / init succeeds
    1   non-hook internal error (check / plugin / init / bad arguments)
        or plugin tests fail or verify fails
    2   deny — including hook initialisation failures (invalid stdin
        payload, policy load error)
";

/// Run a parsed [`Command`] against the given I/O streams. Returns the u8
/// exit code so [`crate::io_runner::run`] can wrap it in [`std::process::ExitCode`].
pub fn run<R: Read, W1: Write, W2: Write>(
    globals: GlobalFlags,
    command: Command,
    stdin: R,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    match command {
        Command::HookPreToolUse { agent } => run::run_hook(agent, stdin, stdout, stderr),
        Command::Check { tool, command } => run::run_check(&tool, &command, stdout, stderr),
        Command::PluginCheck { path } => run::run_plugin_check(&path, stdout, stderr),
        Command::Init(options) => run::run_init(globals, options, stdout, stderr),
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
