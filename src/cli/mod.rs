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
use crate::init::cursor::CursorInitOptions;
use crate::init::kiro::KiroInitOptions;
use crate::init::opencode::OpencodeInitOptions;
use crate::init::pi::PiInitOptions;
use crate::reason;

pub use crate::update::UpdateOptions;

mod cline_input;
mod copilot_input;
mod cursor_input;
mod input_helpers;
mod kiro_input;
mod opencode_input;
mod output;
mod parse;
mod pi_input;
mod run;

#[cfg(test)]
mod test_support;

/// Lossy Copilot stdin normaliser for coverage-guided fuzzing.
#[doc(hidden)]
pub fn fuzz_copilot_parse(body: &str) {
    let _ = copilot_input::parse(body);
}

/// Lossy OpenCode stdin normaliser for coverage-guided fuzzing.
#[doc(hidden)]
pub fn fuzz_opencode_parse(body: &str) {
    let _ = opencode_input::parse(body);
}

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
    Cline,
    Cursor,
    Pi,
    Opencode,
}

impl HookAgent {
    pub(super) fn audit_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Copilot => "copilot",
            Self::Kiro => "kiro",
            Self::Cline => "cline",
            Self::Cursor => "cursor",
            Self::Pi => "pi",
            Self::Opencode => "opencode",
        }
    }
}

/// Parsed `ptuf init [<agent>] [--no-verify] [--dry-run]
/// [--new-agent] [--workspace-only] [--global]`.
///
/// `agent = None` means "auto-detect every agent reachable from
/// `cwd` / `$HOME`". `verify` defaults to `true`; `--no-verify`
/// flips it off, and `--dry-run` implicitly disables verify (a
/// dry run never writes, so the synthetic-deny check would just
/// confirm the unmodified disk state).
///
/// `kiro` carries the Kiro-specific flags. These are accepted only
/// when `agent == Some(HookAgent::Kiro)`; the parser rejects them
/// against other agents (or against auto-detect) with
/// `ParseError::ConflictingFlags`.
///
/// `cursor` carries the Cursor-specific flags (`--scope` / `--root` /
/// `--hooks`), accepted only when `agent == Some(HookAgent::Cursor)`
/// with the same `ParseError::ConflictingFlags` guard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InitOptions {
    pub agent: Option<HookAgent>,
    pub verify: bool,
    pub dry_run: bool,
    pub kiro: KiroInitOptions,
    pub cursor: CursorInitOptions,
    pub pi: PiInitOptions,
    pub opencode: OpencodeInitOptions,
}

/// Top-level flags that apply uniformly across subcommands.
///
/// Currently only `--json`, accepted exclusively before the
/// subcommand token (`ptuf --json init`). Per-subcommand
/// `--json` was removed in the v0 simplification; `hook` rejects
/// `--json` at parse time because the hook protocol output shape
/// is fixed by Claude Code / Codex / Copilot / Kiro / Cline / Cursor / Pi / OpenCode.
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
    /// `ptuf update [--check] [--version <TAG>] [--force]` — upgrade
    /// the ptuf binary in place via either `cargo install` or the
    /// prebuilt installer, auto-detected from the running binary's
    /// location.
    Update(UpdateOptions),
    /// `ptuf readonly on|off|status [--global]` — toggle forced
    /// readonly mode in `.ptuf.local.yaml` (or the user config).
    Readonly {
        action: ReadonlyAction,
        global: bool,
    },
    /// `--help` / `-h`.
    Help,
    /// `--version` / `-V`.
    Version,
}

/// Subcommand of `ptuf readonly`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadonlyAction {
    On,
    Off,
    Status,
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
        "update" => parse::parse_update(&mut iter)?,
        "readonly" => parse::parse_readonly(&mut iter)?,
        other => return Err(ParseError::UnknownCommand(other.to_string())),
    };

    if globals.json && matches!(cmd, Command::HookPreToolUse { .. }) {
        return Err(ParseError::ConflictingFlags(
            "--json is meaningless for `hook`",
        ));
    }
    if globals.json && matches!(cmd, Command::Update(_)) {
        return Err(ParseError::ConflictingFlags(
            "--json is meaningless for `update`",
        ));
    }
    Ok((globals, cmd))
}

const HELP: &str = "ptuf — PreToolUseFilter, a guardrail for coding agents

USAGE:
    ptuf [--json] init [<AGENT>] [--no-verify] [--dry-run]
                       [--new-agent] [--workspace-only] [--global]
                       [--scope <local|global>] [--root <PATH>]
                       [--hooks <PATH>]
        (auto-detect every agent under cwd / $HOME and install the
         PreToolUse hook with verify enabled by default. AGENT pins
         to a single adapter: claude-code | codex | copilot | kiro
         | cline | cursor | pi | opencode)
        Kiro-only flags:
          --new-agent       Create a dedicated ptuf-guarded.json agent
                            (legacy single-file behavior) instead of
                            patching every existing agent JSON.
          --workspace-only  Patch only <repo>/.kiro/agents/*.json.
          --global          Patch only $HOME/.kiro/agents/*.json.
        Cursor-only flags:
          --scope <local|global>
                            local (default) patches <repo>/.cursor/hooks.json;
                            global patches $HOME/.cursor/hooks.json.
          --root <PATH>     Override the repo-discovery start directory.
          --hooks <PATH>    Patch this exact hooks.json file instead.
        Pi-only flags:
          --scope <local|global>
                            global (default) writes $HOME/.pi/agent/extensions/ptuf.ts;
                            local writes <repo>/.pi/extensions/ptuf.ts.
          --root <PATH>     Override the repo-discovery start directory.
          --extension <PATH>
                            Write this exact extension file instead.
        OpenCode-only flags:
          --scope <local|global>
                            global (default) writes $XDG_CONFIG_HOME/opencode/plugins/ptuf.ts;
                            local writes <repo>/.opencode/plugins/ptuf.ts.
          --root <PATH>     Override the repo-discovery start directory.
    ptuf hook <AGENT>
        (run as the agent's PreToolUse hook over stdin/stdout)
    ptuf [--json] check --tool <NAME> <COMMAND>
        (evaluate a single tool call against the active policy)
    ptuf [--json] plugin check <PATH>
        (run a plugin's deny/allow tests)
    ptuf update [--check] [--version <TAG>] [--force]
        (update the ptuf binary in-place from the latest GitHub
         release; auto-detects cargo install vs. prebuilt installer)
    ptuf readonly on|off|status [--global]
        (toggle forced readonly mode; writes <repo>/.ptuf.local.yaml
         by default, or the user config with --global)
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
        Command::Update(options) => run::run_update(options, stdout, stderr),
        Command::Readonly { action, global } => run::run_readonly(action, global, stdout, stderr),
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
        assert_eq!(HookAgent::Cline.audit_name(), "cline");
        assert_eq!(HookAgent::Cursor.audit_name(), "cursor");
        assert_eq!(HookAgent::Pi.audit_name(), "pi");
        assert_eq!(HookAgent::Opencode.audit_name(), "opencode");
    }
}
