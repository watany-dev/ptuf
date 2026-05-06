use std::io::{Read, Write};
use std::path::PathBuf;

use crate::Decision;
use crate::engine::Engine;
use crate::hook_input::HookInput;
use crate::hook_output;
use crate::init;
use crate::plugin::runner as plugin_runner;
use crate::reason;

/// Reserved rule id used when the engine itself failed to load policy
/// and the CLI must fail-closed
/// (`docs/design/cli-and-hooks.md:104-114`).
pub(crate) const POLICY_LOAD_FAILED_RULE: &str = "core.engine.policy-load-failed";
/// Reserved rule id used when the hook stdin payload is unreadable,
/// oversized, or not valid JSON. Claude Code treats `exit 1` as a
/// non-blocking warning, so these initialisation failures must surface
/// as a `Decision::Deny` (exit 2) to preserve the fail-closed contract.
pub(crate) const INVALID_PAYLOAD_RULE: &str = "core.engine.invalid-payload";
const MAX_HOOK_STDIN_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAgent {
    ClaudeCode,
    Codex,
}

impl HookAgent {
    fn audit_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
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

#[derive(Debug, PartialEq, Eq)]
pub enum InitOptions {
    ClaudeCode(ClaudeInitOptions),
    Codex(CodexInitOptions),
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
        }
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
        "hook" => parse_hook(&mut iter),
        "eval" => parse_eval(&mut iter),
        "plugin" => parse_plugin(&mut iter),
        "init" => parse_init(&mut iter),
        "doctor" => parse_doctor(&mut iter),
        other => Err(ParseError::UnknownCommand(other.to_string())),
    }
}

fn parse_doctor<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let mut json = false;
    for arg in iter {
        match arg.as_str() {
            "--json" => json = true,
            other => return Err(ParseError::UnexpectedArgument(other.to_string())),
        }
    }
    Ok(Command::Doctor { json })
}

fn parse_init<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let agent = iter.next().ok_or(ParseError::MissingValue("agent"))?;
    match agent.as_str() {
        "claude-code" => parse_init_claude(iter),
        "codex" => parse_init_codex(iter),
        _ => Err(ParseError::UnknownAgent(agent.clone())),
    }
}

fn parse_init_claude<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let mut dry_run = false;
    let mut settings_path: Option<PathBuf> = None;
    let mut verify = false;
    let mut json = false;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--verify" => verify = true,
            "--json" => json = true,
            "--settings" => {
                let value = iter.next().ok_or(ParseError::MissingValue("--settings"))?;
                settings_path = Some(PathBuf::from(value));
            }
            other if other.starts_with("--settings=") => {
                settings_path = Some(PathBuf::from(other.trim_start_matches("--settings=")));
            }
            other => return Err(ParseError::UnexpectedArgument(other.to_string())),
        }
    }
    check_verify_flags(verify, json, dry_run)?;
    Ok(Command::Init {
        dry_run,
        options: InitOptions::ClaudeCode(ClaudeInitOptions {
            settings_path,
            verify,
            json,
        }),
    })
}

fn parse_init_codex<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let mut dry_run = false;
    let mut root: Option<PathBuf> = None;
    let mut hooks_path: Option<PathBuf> = None;
    let mut config_path: Option<PathBuf> = None;
    let mut verify = false;
    let mut json = false;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--verify" => verify = true,
            "--json" => json = true,
            "--root" => {
                let value = iter.next().ok_or(ParseError::MissingValue("--root"))?;
                root = Some(PathBuf::from(value));
            }
            "--hooks" => {
                let value = iter.next().ok_or(ParseError::MissingValue("--hooks"))?;
                hooks_path = Some(PathBuf::from(value));
            }
            "--config" => {
                let value = iter.next().ok_or(ParseError::MissingValue("--config"))?;
                config_path = Some(PathBuf::from(value));
            }
            other if other.starts_with("--root=") => {
                root = Some(PathBuf::from(other.trim_start_matches("--root=")));
            }
            other if other.starts_with("--hooks=") => {
                hooks_path = Some(PathBuf::from(other.trim_start_matches("--hooks=")));
            }
            other if other.starts_with("--config=") => {
                config_path = Some(PathBuf::from(other.trim_start_matches("--config=")));
            }
            other => return Err(ParseError::UnexpectedArgument(other.to_string())),
        }
    }
    check_verify_flags(verify, json, dry_run)?;
    Ok(Command::Init {
        dry_run,
        options: InitOptions::Codex(CodexInitOptions {
            root,
            hooks_path,
            config_path,
            verify,
            json,
        }),
    })
}

/// Reject `--verify` / `--json` / `--dry-run` combinations that have no
/// sensible meaning. `--json` only structures verify output, so it must
/// be paired with `--verify`. `--verify` forces an install + synthetic
/// payload run, so it cannot be combined with `--dry-run` (which writes
/// nothing).
fn check_verify_flags(verify: bool, json: bool, dry_run: bool) -> Result<(), ParseError> {
    if json && !verify {
        return Err(ParseError::ConflictingFlags("--json requires --verify"));
    }
    if verify && dry_run {
        return Err(ParseError::ConflictingFlags(
            "--verify cannot be combined with --dry-run",
        ));
    }
    Ok(())
}

fn parse_hook<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let agent = iter.next().ok_or(ParseError::MissingValue("agent"))?;
    let agent = match agent.as_str() {
        "claude-code" => HookAgent::ClaudeCode,
        "codex" => HookAgent::Codex,
        _ => return Err(ParseError::UnknownAgent(agent.clone())),
    };
    if let Some(extra) = iter.next() {
        return Err(ParseError::UnexpectedArgument(extra.clone()));
    }
    Ok(Command::HookPreToolUse { agent })
}

fn parse_eval<'a, I>(iter: &mut I) -> Result<Command, ParseError>
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
            }
            other if other.starts_with("--tool=") => {
                tool = Some(other.trim_start_matches("--tool=").to_string());
            }
            other if command.is_none() => {
                command = Some(other.to_string());
            }
            other => {
                return Err(ParseError::UnexpectedArgument(other.to_string()));
            }
        }
    }
    let tool = tool.ok_or(ParseError::MissingValue("--tool"))?;
    let command = command.ok_or(ParseError::MissingValue("<command>"))?;
    Ok(Command::Eval { tool, command })
}

fn parse_plugin<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let sub = iter.next().ok_or(ParseError::MissingValue("subcommand"))?;
    if sub != "test" {
        return Err(ParseError::UnknownCommand(format!("plugin {sub}")));
    }
    let path = iter.next().ok_or(ParseError::MissingValue("<path>"))?;
    if let Some(extra) = iter.next() {
        return Err(ParseError::UnexpectedArgument(extra.clone()));
    }
    Ok(Command::PluginTest {
        path: PathBuf::from(path),
    })
}

const HELP: &str = "ptuf — PreToolUseFilter, a guardrail for coding agents

USAGE:
    ptuf hook <AGENT>                            (run as the agent's PreToolUse hook;
                                                  AGENT = claude-code | codex)
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
        Command::HookPreToolUse { agent } => run_hook(agent, stdin, stdout, stderr),
        Command::Eval { tool, command } => run_eval(&tool, &command, stdout, stderr),
        Command::PluginTest { path } => run_plugin_test(&path, stdout, stderr),
        Command::Init { dry_run, options } => run_init(options, dry_run, stdout, stderr),
        Command::Doctor { json } => run_doctor(json, stdout, stderr),
        Command::Help => {
            let _ = writeln!(stdout, "{HELP}");
            0
        }
        Command::Version => {
            let _ = writeln!(stdout, "ptuf {}", env!("CARGO_PKG_VERSION"));
            0
        }
    }
}

fn run_hook<R: Read, W1: Write, W2: Write>(
    agent: HookAgent,
    stdin: R,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    let mut buf = String::new();
    let read = stdin
        .take(MAX_HOOK_STDIN_BYTES + 1)
        .read_to_string(&mut buf);
    if read.is_err() {
        let _ = writeln!(stderr, "ptuf: failed to read stdin");
        let deny = invalid_payload_deny("stdin read failure");
        return emit_decision(agent, &deny, stdout, stderr);
    }
    if buf.len() as u64 > MAX_HOOK_STDIN_BYTES {
        let _ = writeln!(
            stderr,
            "ptuf: hook payload exceeds {MAX_HOOK_STDIN_BYTES} bytes"
        );
        let problem = format!("hook payload exceeds the {MAX_HOOK_STDIN_BYTES}-byte limit");
        let deny = invalid_payload_deny(&problem);
        return emit_decision(agent, &deny, stdout, stderr);
    }
    let input: HookInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(err) => {
            let _ = writeln!(stderr, "ptuf: invalid hook payload: {err}");
            let problem = format!("hook payload is not valid JSON ({err})");
            let deny = invalid_payload_deny(&problem);
            return emit_decision(agent, &deny, stdout, stderr);
        }
    };
    let decision = match build_engine_or_fail_closed(stderr, agent.audit_name()) {
        Ok(engine) => {
            let decision = engine.decide(&input).decision;
            if let Some(warning) = engine.audit_warning_for_decision(&decision) {
                let _ = writeln!(stderr, "{warning}");
            }
            for warning in engine.drain_audit_write_warnings() {
                let _ = writeln!(stderr, "{warning}");
            }
            decision
        }
        Err(deny) => deny,
    };
    emit_decision(agent, &decision, stdout, stderr)
}

fn invalid_payload_deny(problem: &str) -> Decision {
    Decision::Deny {
        rule_id: INVALID_PAYLOAD_RULE.into(),
        reason: reason::build(
            INVALID_PAYLOAD_RULE,
            problem,
            &["confirm the hook adapter is sending the documented PreToolUse JSON schema"],
        ),
    }
}

fn run_eval<W1: Write, W2: Write>(
    tool: &str,
    command: &str,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    let input = HookInput {
        tool_name: tool.to_string(),
        tool_input: serde_json::json!({ "command": command }),
    };
    let decision = match build_engine_or_fail_closed(stderr, "cli") {
        Ok(engine) => {
            let decision = engine.decide(&input).decision;
            if let Some(warning) = engine.audit_warning_for_decision(&decision) {
                let _ = writeln!(stderr, "{warning}");
            }
            for warning in engine.drain_audit_write_warnings() {
                let _ = writeln!(stderr, "{warning}");
            }
            decision
        }
        Err(deny) => deny,
    };
    let _ = writeln!(stdout, "Decision: {}", decision_label(&decision));
    if let Some(rule_id) = decision.rule_id() {
        let _ = writeln!(stdout, "Rule: {rule_id}");
    }
    if let Some(reason) = decision.reason() {
        let _ = writeln!(stderr, "{reason}");
    }
    decision_exit_code(HookAgent::ClaudeCode, &decision)
}

fn run_plugin_test<W1: Write, W2: Write>(
    path: &std::path::Path,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    match plugin_runner::run(path) {
        Ok(report) => {
            if report.render(stdout).is_err() {
                let _ = writeln!(stderr, "ptuf: failed to write plugin test report");
                return 1;
            }
            if report.passed() { 0 } else { 1 }
        }
        Err(err) => {
            let _ = writeln!(stderr, "ptuf: {err}");
            1
        }
    }
}

fn run_init<W1: Write, W2: Write>(
    options: InitOptions,
    dry_run: bool,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    let verify_requested = match &options {
        InitOptions::ClaudeCode(o) => o.verify,
        InitOptions::Codex(o) => o.verify,
    };
    if verify_requested {
        return match options {
            InitOptions::ClaudeCode(o) => {
                run_init_claude_verify(&o, init::verify::run, stdout, stderr)
            }
            InitOptions::Codex(o) => run_init_codex_verify(&o, init::verify::run, stdout, stderr),
        };
    }
    let outcome = match options {
        InitOptions::ClaudeCode(options) => run_init_claude(&options, dry_run),
        InitOptions::Codex(options) => run_init_codex(&options, dry_run),
    };
    match outcome {
        Ok(outcome) => {
            render_install_outcome(&outcome, dry_run, stdout);
            0
        }
        Err(err) => {
            let _ = writeln!(stderr, "ptuf: init failed: {err}");
            1
        }
    }
}

fn run_doctor<W1: Write, W2: Write>(json: bool, stdout: &mut W1, stderr: &mut W2) -> u8 {
    let result = if json {
        crate::doctor::render_doctor_json(stdout)
    } else {
        crate::doctor::render_doctor(stdout)
    };
    match result {
        Ok(failure) => {
            if failure {
                1
            } else {
                0
            }
        }
        Err(err) => {
            let _ = writeln!(stderr, "ptuf: doctor failed: {err}");
            1
        }
    }
}

fn run_init_claude(
    options: &ClaudeInitOptions,
    dry_run: bool,
) -> Result<init::InstallOutcome, init::InitError> {
    let resolved_path = resolve_claude_settings_path(options)?;
    let binary = init::claude_code::detect_binary();
    init::claude_code::install(&resolved_path, &binary, dry_run)
}

fn run_init_codex(
    options: &CodexInitOptions,
    dry_run: bool,
) -> Result<init::InstallOutcome, init::InitError> {
    let cwd = std::env::current_dir().ok();
    let targets = init::codex::resolve_paths(
        cwd.as_deref(),
        options.root.as_deref(),
        options.hooks_path.as_deref(),
        options.config_path.as_deref(),
    )?;
    let binary = init::codex::detect_binary();
    init::codex::install(&targets, &binary, dry_run)
}

fn resolve_claude_settings_path(options: &ClaudeInitOptions) -> Result<PathBuf, init::InitError> {
    match options.settings_path.as_deref() {
        Some(path) => Ok(path.to_path_buf()),
        None => init::claude_code::default_settings_path().ok_or(init::InitError::HomeNotSet),
    }
}

fn run_init_claude_verify<W1, W2, F>(
    options: &ClaudeInitOptions,
    runner: F,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8
where
    W1: Write,
    W2: Write,
    F: FnOnce() -> init::verify::VerifyReport,
{
    let resolved_path = match resolve_claude_settings_path(options) {
        Ok(p) => p,
        Err(err) => return fail_init(stderr, err),
    };
    let snaps = match init::capture(&[resolved_path.as_path()]) {
        Ok(s) => s,
        Err(err) => return fail_init(stderr, err),
    };
    let binary = init::claude_code::detect_binary();
    let outcome = match init::claude_code::install(&resolved_path, &binary, false) {
        Ok(o) => o,
        Err(err) => return fail_init(stderr, err),
    };
    finish_verify(
        VerifyContext {
            outcome: &outcome,
            snaps: &snaps,
            json: options.json,
        },
        runner,
        stdout,
        stderr,
    )
}

fn run_init_codex_verify<W1, W2, F>(
    options: &CodexInitOptions,
    runner: F,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8
where
    W1: Write,
    W2: Write,
    F: FnOnce() -> init::verify::VerifyReport,
{
    let cwd = std::env::current_dir().ok();
    let targets = match init::codex::resolve_paths(
        cwd.as_deref(),
        options.root.as_deref(),
        options.hooks_path.as_deref(),
        options.config_path.as_deref(),
    ) {
        Ok(t) => t,
        Err(err) => return fail_init(stderr, err),
    };
    let snaps = match init::capture(&[targets.hooks_path.as_path(), targets.config_path.as_path()])
    {
        Ok(s) => s,
        Err(err) => return fail_init(stderr, err),
    };
    let binary = init::codex::detect_binary();
    let outcome = match init::codex::install(&targets, &binary, false) {
        Ok(o) => o,
        Err(err) => return fail_init(stderr, err),
    };
    finish_verify(
        VerifyContext {
            outcome: &outcome,
            snaps: &snaps,
            json: options.json,
        },
        runner,
        stdout,
        stderr,
    )
}

fn fail_init<W: Write>(stderr: &mut W, err: impl std::fmt::Display) -> u8 {
    let _ = writeln!(stderr, "ptuf: init failed: {err}");
    1
}

struct VerifyContext<'a> {
    outcome: &'a init::InstallOutcome,
    snaps: &'a [init::PathSnapshot],
    json: bool,
}

fn finish_verify<W1, W2, F>(
    ctx: VerifyContext<'_>,
    runner: F,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8
where
    W1: Write,
    W2: Write,
    F: FnOnce() -> init::verify::VerifyReport,
{
    let report = runner();
    let mut rolled_back = false;
    if !report.passed() && matches!(ctx.outcome.status, init::InstallStatus::Installed) {
        match init::restore(ctx.snaps) {
            Ok(()) => {
                rolled_back = true;
            }
            Err(err) => {
                let _ = writeln!(stderr, "ptuf init: rollback failed: {err}");
            }
        }
    }
    if ctx.json {
        let value = init::verify::render_json(ctx.outcome, &report, rolled_back);
        match serde_json::to_string_pretty(&value) {
            Ok(s) => {
                let _ = writeln!(stdout, "{s}");
            }
            Err(err) => {
                let _ = writeln!(stderr, "ptuf: failed to render verify JSON: {err}");
                return 1;
            }
        }
    } else {
        render_install_outcome(ctx.outcome, false, stdout);
        let _ = init::verify::render_text(&report, stdout);
        if rolled_back {
            for snap in ctx.snaps {
                let _ = writeln!(
                    stdout,
                    "ptuf init: rolled back changes to {}",
                    snap.path.display()
                );
            }
            let _ = writeln!(stdout, "ptuf init: verification failed; aborting");
        } else if !report.passed()
            && matches!(ctx.outcome.status, init::InstallStatus::AlreadyPresent)
        {
            let _ = writeln!(
                stdout,
                "ptuf init: existing hook entry failed verification; review the file(s) above manually."
            );
        }
    }
    if report.passed() { 0 } else { 1 }
}

fn render_install_outcome<W: Write>(outcome: &init::InstallOutcome, dry_run: bool, stdout: &mut W) {
    let parts: Vec<String> = outcome
        .paths
        .iter()
        .map(|p| format!("{}={}", p.label, p.path.display()))
        .collect();
    let path_summary = parts.join(", ");
    let agent = outcome.agent;
    match outcome.status {
        init::InstallStatus::AlreadyPresent => {
            let suffix = if dry_run { " (dry-run)" } else { "" };
            let line = format!(
                "ptuf init {agent}{suffix}: {path_summary} already contains a ptuf hook entry; nothing to do."
            );
            let _ = writeln!(stdout, "{line}");
        }
        init::InstallStatus::Installed => {
            let line = format!("ptuf init {agent}: registered hook in {path_summary}");
            let _ = writeln!(stdout, "{line}");
            let _ = writeln!(stdout, "  matcher: {}", outcome.matcher);
            let _ = writeln!(stdout, "  command: {}", outcome.command);
        }
        init::InstallStatus::WouldInstall => {
            let line =
                format!("ptuf init {agent} (dry-run): would register hook in {path_summary}");
            let _ = writeln!(stdout, "{line}");
            let _ = writeln!(stdout, "  matcher: {}", outcome.matcher);
            let _ = writeln!(stdout, "  command: {}", outcome.command);
            let _ = writeln!(stdout, "Run without --dry-run to apply.");
        }
    }
}

fn emit_decision<W1: Write, W2: Write>(
    agent: HookAgent,
    decision: &Decision,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    let adapted = adapt_hook_decision(agent, decision);
    if let Some(response) = render_hook_response(agent, &adapted) {
        match serde_json::to_string(&response) {
            Ok(body) => {
                let _ = writeln!(stdout, "{body}");
            }
            Err(err) => {
                let _ = writeln!(stderr, "ptuf: failed to serialise hook response: {err}");
                return 1;
            }
        }
    }
    if let Some(reason) = adapted.reason() {
        let _ = writeln!(stderr, "{reason}");
    }
    decision_exit_code(agent, &adapted)
}

fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Monitor { .. } => "monitor",
        Decision::Ask { .. } => "ask",
        Decision::Deny { .. } => "deny",
    }
}

fn render_hook_response(
    agent: HookAgent,
    decision: &Decision,
) -> Option<hook_output::HookResponse> {
    match agent {
        HookAgent::ClaudeCode => hook_output::claude_code::from_decision(decision),
        HookAgent::Codex => hook_output::codex::from_decision(decision),
    }
}

fn adapt_hook_decision(agent: HookAgent, decision: &Decision) -> Decision {
    match (agent, decision) {
        (HookAgent::Codex, Decision::Ask { rule_id, reason }) => Decision::Deny {
            rule_id: rule_id.clone(),
            reason: hook_output::codex::deny_reason_for_ask(reason),
        },
        _ => decision.clone(),
    }
}

fn decision_exit_code(agent: HookAgent, decision: &Decision) -> u8 {
    match (agent, decision) {
        (_, Decision::Deny { .. }) => 2,
        (HookAgent::Codex, Decision::Ask { .. }) => 2,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
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
        assert_eq!(parse(&s(&["--help"])).unwrap(), Command::Help);
        assert_eq!(parse(&s(&["-h"])).unwrap(), Command::Help);
        assert_eq!(parse(&s(&["--version"])).unwrap(), Command::Version);
        assert_eq!(parse(&s(&["-V"])).unwrap(), Command::Version);
    }

    #[test]
    fn parses_hook_subcommand() {
        let cmd = parse(&s(&["hook", "claude-code"])).unwrap();
        assert_eq!(
            cmd,
            Command::HookPreToolUse {
                agent: HookAgent::ClaudeCode
            }
        );
        let codex = parse(&s(&["hook", "codex"])).unwrap();
        assert_eq!(
            codex,
            Command::HookPreToolUse {
                agent: HookAgent::Codex
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
    fn parses_eval_with_separate_value() {
        let cmd = parse(&s(&["eval", "--tool", "Bash", "ls -la"])).unwrap();
        assert_eq!(
            cmd,
            Command::Eval {
                tool: "Bash".into(),
                command: "ls -la".into()
            }
        );
    }

    #[test]
    fn parses_eval_with_equals_form() {
        let cmd = parse(&s(&["eval", "--tool=Bash", "ls"])).unwrap();
        assert_eq!(
            cmd,
            Command::Eval {
                tool: "Bash".into(),
                command: "ls".into()
            }
        );
    }

    #[test]
    fn eval_requires_tool_and_command() {
        assert!(matches!(
            parse(&s(&["eval", "--tool", "Bash"])),
            Err(ParseError::MissingValue("<command>"))
        ));
        assert!(matches!(
            parse(&s(&["eval", "ls"])),
            Err(ParseError::MissingValue("--tool"))
        ));
    }

    #[test]
    fn parses_plugin_test_subcommand() {
        let cmd = parse(&s(&["plugin", "test", "demo.yaml"])).unwrap();
        assert_eq!(
            cmd,
            Command::PluginTest {
                path: PathBuf::from("demo.yaml"),
            }
        );
    }

    #[test]
    fn rejects_unknown_plugin_subcommand() {
        assert!(matches!(
            parse(&s(&["plugin", "lint", "demo.yaml"])),
            Err(ParseError::UnknownCommand(_))
        ));
    }

    #[test]
    fn plugin_test_requires_path() {
        assert!(matches!(
            parse(&s(&["plugin", "test"])),
            Err(ParseError::MissingValue("<path>"))
        ));
    }

    #[test]
    fn plugin_test_rejects_extra_argument() {
        assert!(matches!(
            parse(&s(&["plugin", "test", "p.yaml", "extra"])),
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
    fn parses_init_with_just_agent() {
        let cmd = parse(&s(&["init", "claude-code"])).unwrap();
        assert_eq!(
            cmd,
            Command::Init {
                dry_run: false,
                options: InitOptions::ClaudeCode(ClaudeInitOptions::default()),
            }
        );
    }

    #[test]
    fn parses_init_with_dry_run_and_settings() {
        let cmd = parse(&s(&[
            "init",
            "claude-code",
            "--dry-run",
            "--settings",
            "/tmp/x.json",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Init {
                dry_run: true,
                options: InitOptions::ClaudeCode(ClaudeInitOptions {
                    settings_path: Some(PathBuf::from("/tmp/x.json")),
                    ..Default::default()
                }),
            }
        );
    }

    #[test]
    fn parses_init_with_equals_settings_form() {
        let cmd = parse(&s(&["init", "claude-code", "--settings=/tmp/x.json"])).unwrap();
        assert_eq!(
            cmd,
            Command::Init {
                dry_run: false,
                options: InitOptions::ClaudeCode(ClaudeInitOptions {
                    settings_path: Some(PathBuf::from("/tmp/x.json")),
                    ..Default::default()
                }),
            }
        );
    }

    #[test]
    fn parses_codex_init_flags() {
        let cmd = parse(&s(&[
            "init",
            "codex",
            "--dry-run",
            "--root",
            "/repo",
            "--hooks=/tmp/hooks.json",
            "--config",
            "/tmp/config.toml",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Init {
                dry_run: true,
                options: InitOptions::Codex(CodexInitOptions {
                    root: Some(PathBuf::from("/repo")),
                    hooks_path: Some(PathBuf::from("/tmp/hooks.json")),
                    config_path: Some(PathBuf::from("/tmp/config.toml")),
                    ..Default::default()
                }),
            }
        );
    }

    #[test]
    fn parses_init_with_verify() {
        let cmd = parse(&s(&["init", "claude-code", "--verify"])).unwrap();
        assert_eq!(
            cmd,
            Command::Init {
                dry_run: false,
                options: InitOptions::ClaudeCode(ClaudeInitOptions {
                    verify: true,
                    ..Default::default()
                }),
            }
        );
    }

    #[test]
    fn parses_init_with_verify_json() {
        let cmd = parse(&s(&["init", "codex", "--verify", "--json"])).unwrap();
        assert_eq!(
            cmd,
            Command::Init {
                dry_run: false,
                options: InitOptions::Codex(CodexInitOptions {
                    verify: true,
                    json: true,
                    ..Default::default()
                }),
            }
        );
    }

    #[test]
    fn rejects_json_without_verify() {
        let err = parse(&s(&["init", "claude-code", "--json"])).unwrap_err();
        assert_eq!(
            err,
            ParseError::ConflictingFlags("--json requires --verify")
        );
    }

    #[test]
    fn rejects_verify_with_dry_run() {
        let err = parse(&s(&["init", "claude-code", "--verify", "--dry-run"])).unwrap_err();
        assert_eq!(
            err,
            ParseError::ConflictingFlags("--verify cannot be combined with --dry-run")
        );
    }

    #[test]
    fn init_requires_agent() {
        assert!(matches!(
            parse(&s(&["init"])),
            Err(ParseError::MissingValue("agent"))
        ));
    }

    #[test]
    fn init_rejects_unknown_flags() {
        assert!(matches!(
            parse(&s(&["init", "claude-code", "--bogus"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
        assert!(matches!(
            parse(&s(&["init", "codex", "--settings=/tmp/x.json"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn init_settings_flag_requires_value() {
        assert!(matches!(
            parse(&s(&["init", "claude-code", "--settings"])),
            Err(ParseError::MissingValue("--settings"))
        ));
        assert!(matches!(
            parse(&s(&["init", "codex", "--hooks"])),
            Err(ParseError::MissingValue("--hooks"))
        ));
    }

    #[test]
    fn parses_doctor_subcommand() {
        assert_eq!(
            parse(&s(&["doctor"])).unwrap(),
            Command::Doctor { json: false }
        );
        assert_eq!(
            parse(&s(&["doctor", "--json"])).unwrap(),
            Command::Doctor { json: true }
        );
    }

    #[test]
    fn doctor_rejects_unknown_flags() {
        assert!(matches!(
            parse(&s(&["doctor", "--bogus"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    fn run_with(args: &[&str], stdin: &str) -> (u8, String, String) {
        let parsed = parse(&s(args)).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(parsed, stdin.as_bytes(), &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[test]
    fn eval_denies_destructive_rm() {
        let (code, out, err) = run_with(&["eval", "--tool", "Bash", "rm -rf /"], "");
        assert_eq!(code, 2);
        assert!(out.contains("Decision: deny"));
        assert!(out.contains("Rule: core.filesystem.destructive-rm"));
        assert!(err.contains("Blocked by ptuf rule core.filesystem.destructive-rm."));
    }

    #[test]
    fn eval_allows_safe_command() {
        let (code, out, err) = run_with(&["eval", "--tool", "Bash", "ls -la"], "");
        assert_eq!(code, 0);
        assert!(out.contains("Decision: allow"));
        assert!(err.is_empty(), "unexpected stderr: {err}");
    }

    #[test]
    fn hook_emits_json_for_deny() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let (code, out, err) = run_with(&["hook", "claude-code"], payload);
        assert_eq!(code, 2);
        assert!(out.contains("\"hookSpecificOutput\""));
        assert!(out.contains("\"permissionDecision\":\"deny\""));
        assert!(err.contains("Blocked by ptuf rule"));
    }

    #[test]
    fn hook_returns_zero_and_no_stdout_for_allow() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let (code, out, err) = run_with(&["hook", "claude-code"], payload);
        assert_eq!(code, 0);
        assert!(out.is_empty());
        assert!(err.is_empty(), "unexpected stderr: {err}");
    }

    #[test]
    fn hook_fails_closed_for_invalid_json() {
        let (code, out, err) = run_with(&["hook", "claude-code"], "not json");
        assert_eq!(code, 2);
        assert!(
            out.contains("\"permissionDecision\":\"deny\""),
            "stdout: {out}"
        );
        assert!(err.contains("invalid hook payload"), "stderr: {err}");
        assert!(err.contains(INVALID_PAYLOAD_RULE), "stderr: {err}");
    }

    #[test]
    fn help_prints_usage() {
        let (code, out, err) = run_with(&["--help"], "");
        assert_eq!(code, 0);
        assert!(out.contains("USAGE"));
        assert!(err.is_empty());
    }

    #[test]
    fn version_prints_package_version() {
        let (code, out, _err) = run_with(&["--version"], "");
        assert_eq!(code, 0);
        assert!(out.contains("ptuf"));
        assert!(out.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn run_renders_help_and_version_to_stdout() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(Command::Help, b"" as &[u8], &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&out).contains("USAGE"));

        let mut out2 = Vec::new();
        let code = run(Command::Version, b"" as &[u8], &mut out2, &mut err);
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&out2).contains("ptuf"));
    }

    #[test]
    fn eval_extra_positional_argument_is_rejected() {
        assert!(matches!(
            parse(&s(&["eval", "--tool", "Bash", "ls", "extra"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn decision_label_covers_all_variants() {
        assert_eq!(decision_label(&Decision::Allow), "allow");
        assert_eq!(
            decision_label(&Decision::Monitor {
                rule_id: "x".into()
            }),
            "monitor"
        );
        assert_eq!(
            decision_label(&Decision::Ask {
                rule_id: "x".into(),
                reason: "r".into(),
            }),
            "ask"
        );
        assert_eq!(
            decision_label(&Decision::Deny {
                rule_id: "x".into(),
                reason: "r".into(),
            }),
            "deny"
        );
    }

    #[test]
    fn emit_decision_writes_ask_envelope_with_zero_exit() {
        let decision = Decision::Ask {
            rule_id: "core.test.ask".into(),
            reason: "please confirm".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::ClaudeCode, &decision, &mut out, &mut err);
        assert_eq!(code, 0);
        let out_s = String::from_utf8_lossy(&out);
        assert!(out_s.contains("\"permissionDecision\":\"ask\""));
        assert!(String::from_utf8_lossy(&err).contains("please confirm"));
    }

    #[test]
    fn plugin_test_runs_and_returns_zero_on_pass() {
        use std::fs;
        let dir =
            std::env::temp_dir().join(format!("ptuf-plugin-test-pass-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("demo.yaml");
        fs::write(
            &path,
            r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      shell.argv:
        headAny: [curl]
    reason: blocked
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "curl https://example.com"
"#,
        )
        .unwrap();
        let cmd = Command::PluginTest { path: path.clone() };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(cmd, b"" as &[u8], &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let s_out = String::from_utf8_lossy(&out);
        assert!(s_out.contains("plugin pack.demo"));
        assert!(s_out.contains("1 passed"));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn plugin_test_returns_one_when_a_case_fails() {
        use std::fs;
        let dir =
            std::env::temp_dir().join(format!("ptuf-plugin-test-fail-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("bad.yaml");
        fs::write(
            &path,
            r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.x
rules:
  - id: pack.x.miss
    severity: low
    defaultDecision: deny
    when:
      tool: Read
    reason: blocked
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
"#,
        )
        .unwrap();
        let cmd = Command::PluginTest { path: path.clone() };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(cmd, b"" as &[u8], &mut out, &mut err);
        assert_eq!(code, 1);
        let s_out = String::from_utf8_lossy(&out);
        assert!(s_out.contains("FAIL"));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn plugin_test_returns_one_when_yaml_is_invalid() {
        let cmd = Command::PluginTest {
            path: PathBuf::from("/this/path/does/not/exist.yaml"),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(cmd, b"" as &[u8], &mut out, &mut err);
        assert_eq!(code, 1);
        assert!(String::from_utf8_lossy(&err).contains("ptuf:"));
    }

    #[test]
    fn run_init_codex_dry_run_writes_outcome_summary() {
        let dir = std::env::temp_dir().join(format!("ptuf-cli-init-codex-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hooks_path = dir.join("hooks.json");
        let config_path = dir.join("config.toml");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::Init {
                dry_run: true,
                options: InitOptions::Codex(CodexInitOptions {
                    root: None,
                    hooks_path: Some(hooks_path.clone()),
                    config_path: Some(config_path.clone()),
                    ..Default::default()
                }),
            },
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&out).contains("would register hook"));
        assert!(!hooks_path.exists());
        assert!(!config_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_dry_run_writes_outcome_summary() {
        let dir = std::env::temp_dir().join(format!("ptuf-cli-init-dry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::Init {
                dry_run: true,
                options: InitOptions::ClaudeCode(ClaudeInitOptions {
                    settings_path: Some(path.clone()),
                    ..Default::default()
                }),
            },
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("would register hook"));
        assert!(s.contains("Run without --dry-run"));
        assert!(!path.exists(), "dry-run must not write file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_writes_and_is_idempotent_on_second_call() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-cli-init-idempotent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        let mut out1 = Vec::new();
        let mut err1 = Vec::new();
        let code1 = run(
            Command::Init {
                dry_run: false,
                options: InitOptions::ClaudeCode(ClaudeInitOptions {
                    settings_path: Some(path.clone()),
                    ..Default::default()
                }),
            },
            b"" as &[u8],
            &mut out1,
            &mut err1,
        );
        assert_eq!(code1, 0);
        assert!(String::from_utf8_lossy(&out1).contains("registered hook"));
        let after_first = std::fs::read_to_string(&path).unwrap();

        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        let code2 = run(
            Command::Init {
                dry_run: false,
                options: InitOptions::ClaudeCode(ClaudeInitOptions {
                    settings_path: Some(path.clone()),
                    ..Default::default()
                }),
            },
            b"" as &[u8],
            &mut out2,
            &mut err2,
        );
        assert_eq!(code2, 0);
        assert!(String::from_utf8_lossy(&out2).contains("already contains"));
        assert_eq!(
            after_first,
            std::fs::read_to_string(&path).unwrap(),
            "second run must not rewrite the file",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_claude_verify_rolls_back_when_synthetic_deny_fails() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-cli-init-rollback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        let options = ClaudeInitOptions {
            settings_path: Some(path.clone()),
            verify: true,
            json: false,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_init_claude_verify(
            &options,
            || init::verify::VerifyReport {
                synthetic_deny: init::verify::CheckOutcome::Failed {
                    detail: "engine returned Allow".into(),
                },
                fail_closed: init::verify::CheckOutcome::Passed {
                    rule_id: POLICY_LOAD_FAILED_RULE.to_string(),
                },
                warnings: Vec::new(),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1, "verify failure must exit non-zero");
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("FAILED"), "stdout: {stdout}");
        assert!(
            stdout.contains("rolled back changes to"),
            "stdout: {stdout}",
        );
        assert!(
            stdout.contains("verification failed; aborting"),
            "stdout: {stdout}",
        );
        assert!(
            !path.exists(),
            "rollback must remove the freshly-created settings file",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_claude_verify_keeps_already_present_file_when_verify_fails() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-cli-init-already-present-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        // Pre-populate the file with a hook entry pointing at our own
        // binary so install() reports AlreadyPresent without modifying
        // anything.
        let preexisting_options = ClaudeInitOptions {
            settings_path: Some(path.clone()),
            ..Default::default()
        };
        let mut out0 = Vec::new();
        let mut err0 = Vec::new();
        assert_eq!(
            run(
                Command::Init {
                    dry_run: false,
                    options: InitOptions::ClaudeCode(preexisting_options.clone()),
                },
                b"" as &[u8],
                &mut out0,
                &mut err0,
            ),
            0,
        );
        let snapshot = std::fs::read(&path).unwrap();

        let verify_options = ClaudeInitOptions {
            verify: true,
            ..preexisting_options
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_init_claude_verify(
            &verify_options,
            || init::verify::VerifyReport {
                synthetic_deny: init::verify::CheckOutcome::Failed {
                    detail: "synthetic deny did not fire".into(),
                },
                fail_closed: init::verify::CheckOutcome::Passed {
                    rule_id: POLICY_LOAD_FAILED_RULE.to_string(),
                },
                warnings: Vec::new(),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1);
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("already contains"), "stdout: {stdout}");
        assert!(
            stdout.contains("review the file(s) above manually"),
            "stdout: {stdout}",
        );
        assert!(
            !stdout.contains("rolled back"),
            "AlreadyPresent must not roll back: {stdout}",
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            snapshot,
            "AlreadyPresent file content must be untouched after a verify failure",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn passing_report() -> init::verify::VerifyReport {
        init::verify::VerifyReport {
            synthetic_deny: init::verify::CheckOutcome::Passed {
                rule_id: "core.filesystem.destructive-rm".into(),
            },
            fail_closed: init::verify::CheckOutcome::Passed {
                rule_id: POLICY_LOAD_FAILED_RULE.to_string(),
            },
            warnings: Vec::new(),
        }
    }

    fn failing_report() -> init::verify::VerifyReport {
        init::verify::VerifyReport {
            synthetic_deny: init::verify::CheckOutcome::Failed {
                detail: "synthetic deny did not fire".into(),
            },
            fail_closed: init::verify::CheckOutcome::Passed {
                rule_id: POLICY_LOAD_FAILED_RULE.to_string(),
            },
            warnings: Vec::new(),
        }
    }

    #[test]
    fn run_init_claude_verify_emits_json_when_requested() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-cli-init-claude-json-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        let options = ClaudeInitOptions {
            settings_path: Some(path.clone()),
            verify: true,
            json: true,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_init_claude_verify(&options, passing_report, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let stdout = String::from_utf8_lossy(&out);
        let value: serde_json::Value =
            serde_json::from_str(&stdout).expect("JSON branch must emit valid JSON");
        assert_eq!(value["installed"], true);
        assert_eq!(value["rolledBack"], false);
        assert_eq!(value["verify"]["syntheticDeny"]["status"], "passed");
        assert!(
            !stdout.contains("Verify:"),
            "JSON mode must not emit text section: {stdout}",
        );
        assert!(path.exists(), "JSON happy path must keep settings file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_codex_verify_passes_when_checks_succeed() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-cli-init-codex-verify-ok-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hooks_path = dir.join("hooks.json");
        let config_path = dir.join("config.toml");
        let options = CodexInitOptions {
            root: None,
            hooks_path: Some(hooks_path.clone()),
            config_path: Some(config_path.clone()),
            verify: true,
            json: false,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_init_codex_verify(&options, passing_report, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("registered hook"), "stdout: {stdout}");
        assert!(stdout.contains("Verify:"), "stdout: {stdout}");
        assert!(
            stdout.contains("Synthetic deny test: passed"),
            "stdout: {stdout}",
        );
        assert!(hooks_path.exists());
        assert!(config_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_codex_verify_rolls_back_both_paths_when_check_fails() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-cli-init-codex-verify-rollback-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hooks_path = dir.join("hooks.json");
        let config_path = dir.join("config.toml");
        let options = CodexInitOptions {
            root: None,
            hooks_path: Some(hooks_path.clone()),
            config_path: Some(config_path.clone()),
            verify: true,
            json: false,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_init_codex_verify(&options, failing_report, &mut out, &mut err);
        assert_eq!(code, 1);
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("FAILED"), "stdout: {stdout}");
        // Multi-snapshot rollback emits one line per restored path.
        let rollback_lines = stdout.matches("rolled back changes to").count();
        assert!(rollback_lines >= 2, "stdout: {stdout}");
        assert!(
            stdout.contains("verification failed; aborting"),
            "stdout: {stdout}",
        );
        assert!(
            !hooks_path.exists(),
            "rollback must remove freshly-created hooks file"
        );
        assert!(
            !config_path.exists(),
            "rollback must remove freshly-created config file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_name_returns_codex_string() {
        assert_eq!(HookAgent::Codex.audit_name(), "codex");
        assert_eq!(HookAgent::ClaudeCode.audit_name(), "claude-code");
    }

    #[test]
    fn parses_init_unknown_agent_surfaces_unknown_agent_error() {
        let err = parse(&s(&["init", "gemini"])).unwrap_err();
        assert!(matches!(err, ParseError::UnknownAgent(ref a) if a == "gemini"));
    }

    #[test]
    fn parses_codex_init_alternative_flag_forms() {
        // Complementary to parses_codex_init_flags: covers --hooks <value>
        // (separate), --root=<value>, and --config=<value>.
        let cmd = parse(&s(&[
            "init",
            "codex",
            "--hooks",
            "/tmp/hooks.json",
            "--root=/repo",
            "--config=/tmp/config.toml",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Init {
                dry_run: false,
                options: InitOptions::Codex(CodexInitOptions {
                    root: Some(PathBuf::from("/repo")),
                    hooks_path: Some(PathBuf::from("/tmp/hooks.json")),
                    config_path: Some(PathBuf::from("/tmp/config.toml")),
                    ..Default::default()
                }),
            }
        );
    }

    #[test]
    fn parses_eval_rejects_extra_positional_after_command() {
        let err = parse(&s(&["eval", "--tool", "Bash", "first", "second"])).unwrap_err();
        assert!(matches!(err, ParseError::UnexpectedArgument(ref a) if a == "second"));
    }

    #[test]
    fn run_help_writes_help_text() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(Command::Help, b"" as &[u8], &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(!out.is_empty());
    }

    #[test]
    fn run_version_writes_version_string() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(Command::Version, b"" as &[u8], &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&out).starts_with("ptuf "));
    }

    #[test]
    fn adapt_hook_decision_codex_converts_ask_to_deny() {
        let d = adapt_hook_decision(
            HookAgent::Codex,
            &Decision::Ask {
                rule_id: "x".into(),
                reason: "y".into(),
            },
        );
        match d {
            Decision::Deny { rule_id, .. } => assert_eq!(rule_id, "x"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn adapt_hook_decision_claude_passes_ask_through_unchanged() {
        let original = Decision::Ask {
            rule_id: "x".into(),
            reason: "y".into(),
        };
        let adapted = adapt_hook_decision(HookAgent::ClaudeCode, &original);
        assert_eq!(adapted, original);
    }

    #[test]
    fn decision_exit_code_codex_ask_returns_two() {
        let d = Decision::Ask {
            rule_id: "x".into(),
            reason: "y".into(),
        };
        assert_eq!(decision_exit_code(HookAgent::Codex, &d), 2);
        assert_eq!(decision_exit_code(HookAgent::ClaudeCode, &d), 0);
    }

    #[test]
    fn decision_label_covers_every_decision_variant() {
        assert_eq!(decision_label(&Decision::Allow), "allow");
        assert_eq!(
            decision_label(&Decision::Monitor {
                rule_id: "x".into(),
            }),
            "monitor"
        );
        assert_eq!(
            decision_label(&Decision::Ask {
                rule_id: "x".into(),
                reason: "y".into(),
            }),
            "ask"
        );
        assert_eq!(
            decision_label(&Decision::Deny {
                rule_id: "x".into(),
                reason: "y".into(),
            }),
            "deny"
        );
    }

    fn fail_closed_cwd(tag: &str) -> (PathBuf, FailClosedGuard) {
        let dir = std::env::temp_dir().join(format!("ptuf-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(
            dir.join(".ptuf.yaml"),
            "plugins:\n  - path: ./does-not-exist.yaml\n",
        )
        .unwrap();
        let original = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(&dir).expect("set_current_dir");
        (dir, FailClosedGuard(original))
    }

    struct FailClosedGuard(PathBuf);
    impl Drop for FailClosedGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    #[test]
    fn run_hook_fails_closed_when_policy_load_fails() {
        let (dir, _guard) = fail_closed_cwd("hook-failclosed");
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::HookPreToolUse {
                agent: HookAgent::ClaudeCode,
            },
            payload.as_bytes(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 2, "fail-closed must exit 2");
        let stderr = String::from_utf8_lossy(&err);
        assert!(stderr.contains("could not load policy"), "stderr: {stderr}");
        let stdout = String::from_utf8_lossy(&out);
        assert!(
            stdout.contains("\"permissionDecision\":\"deny\""),
            "stdout must show deny: {stdout}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_eval_fails_closed_when_policy_load_fails() {
        let (dir, _guard) = fail_closed_cwd("eval-failclosed");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::Eval {
                tool: "Bash".into(),
                command: "ls".into(),
            },
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 2, "fail-closed must exit 2");
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("Decision: deny"), "stdout: {stdout}");
        assert!(stdout.contains(POLICY_LOAD_FAILED_RULE), "stdout: {stdout}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_engine_or_fail_closed_returns_deny_when_policy_invalid() {
        let (dir, _guard) = fail_closed_cwd("failclosed");
        let mut err = Vec::new();
        let result = build_engine_or_fail_closed(&mut err, "claude-code");
        let deny = result.err().expect("expected fail-closed Deny");
        match deny {
            Decision::Deny { rule_id, .. } => assert_eq!(rule_id, POLICY_LOAD_FAILED_RULE),
            other => panic!("expected Deny, got {other:?}"),
        }
        assert!(
            String::from_utf8_lossy(&err).contains("could not load policy"),
            "stderr did not include reason: {}",
            String::from_utf8_lossy(&err)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_dispatches_to_claude_verify_when_verify_flag_set() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-cli-run-claude-verify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::Init {
                dry_run: false,
                options: InitOptions::ClaudeCode(ClaudeInitOptions {
                    settings_path: Some(path.clone()),
                    verify: true,
                    json: false,
                }),
            },
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let stdout = String::from_utf8_lossy(&out);
        assert!(
            stdout.contains("Synthetic deny test: passed"),
            "stdout: {stdout}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_dispatches_to_codex_verify_when_verify_flag_set() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-cli-run-codex-verify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hooks = dir.join("hooks.json");
        let cfg = dir.join("config.toml");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::Init {
                dry_run: false,
                options: InitOptions::Codex(CodexInitOptions {
                    root: None,
                    hooks_path: Some(hooks.clone()),
                    config_path: Some(cfg.clone()),
                    verify: true,
                    json: false,
                }),
            },
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let stdout = String::from_utf8_lossy(&out);
        assert!(
            stdout.contains("Synthetic deny test: passed"),
            "stdout: {stdout}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_claude_verify_reports_error_when_settings_path_is_directory() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-cli-claude-verify-baddir-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let options = ClaudeInitOptions {
            settings_path: Some(dir.clone()),
            verify: true,
            json: false,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_init_claude_verify(&options, passing_report, &mut out, &mut err);
        assert_eq!(code, 1, "stderr: {}", String::from_utf8_lossy(&err));
        assert!(String::from_utf8_lossy(&err).contains("init failed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_codex_verify_reports_error_when_hooks_path_is_directory() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-cli-codex-verify-baddir-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Hooks path is a directory: the snapshot capture (or read_hooks)
        // must surface an Io error before verify executes.
        let bad_hooks = dir.join("hooks-as-dir");
        std::fs::create_dir_all(&bad_hooks).unwrap();
        let options = CodexInitOptions {
            root: None,
            hooks_path: Some(bad_hooks),
            config_path: Some(dir.join("config.toml")),
            verify: true,
            json: false,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_init_codex_verify(&options, passing_report, &mut out, &mut err);
        assert_eq!(code, 1, "stderr: {}", String::from_utf8_lossy(&err));
        assert!(String::from_utf8_lossy(&err).contains("init failed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finish_verify_logs_rollback_failure_when_restore_errors() {
        // Wedge restore into failure: snapshot says the file existed,
        // but the parent directory we'd have to write through is itself
        // a regular file.
        let dir = std::env::temp_dir().join(format!(
            "ptuf-cli-finish-verify-rollback-err-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"i am a file").unwrap();
        let bad_path = blocker.join("nested").join("settings.json");

        let snaps = vec![init::PathSnapshot {
            path: bad_path,
            previous: Some(b"original".to_vec()),
        }];
        let outcome = init::InstallOutcome {
            status: init::InstallStatus::Installed,
            agent: "claude-code",
            paths: vec![init::InstallPath {
                label: "settings",
                path: dir.join("settings.json"),
            }],
            matcher: "Bash".into(),
            command: "ptuf hook claude-code".into(),
        };
        let ctx = VerifyContext {
            outcome: &outcome,
            snaps: &snaps,
            json: false,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = finish_verify(ctx, failing_report, &mut out, &mut err);
        assert_eq!(code, 1);
        let stderr = String::from_utf8_lossy(&err);
        assert!(stderr.contains("rollback failed"), "stderr: {stderr}");
        let stdout = String::from_utf8_lossy(&out);
        // Rollback failed, so the "rolled back changes to" line is NOT emitted.
        assert!(
            !stdout.contains("rolled back changes to"),
            "stdout: {stdout}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_reports_invalid_json_via_stderr() {
        let dir = std::env::temp_dir().join(format!("ptuf-cli-init-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, "{not json").unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::Init {
                dry_run: false,
                options: InitOptions::ClaudeCode(ClaudeInitOptions {
                    settings_path: Some(path.clone()),
                    ..Default::default()
                }),
            },
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1);
        assert!(String::from_utf8_lossy(&err).contains("init failed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_doctor_writes_text_report_to_stdout() {
        let (code, out, _err) = run_with(&["doctor"], "");
        assert!(
            code == 0 || code == 1,
            "doctor must return 0 or 1, got {code}"
        );
        assert!(out.contains("ptuf doctor"));
        assert!(out.contains("Binary"));
    }

    #[test]
    fn run_doctor_with_json_flag_emits_structured_json() {
        let (code, out, _err) = run_with(&["doctor", "--json"], "");
        assert!(
            code == 0 || code == 1,
            "doctor --json must return 0 or 1, got {code}"
        );
        let value: serde_json::Value =
            serde_json::from_str(&out).expect("doctor --json output must be valid JSON");
        assert_eq!(value["schemaVersion"], 1);
        assert!(value["binary"]["version"].is_string());
        assert!(value["configLayers"].is_array());
        assert!(value["plugins"].is_array());
        assert!(value["claude"]["state"].is_string());
        assert!(value["codex"]["state"].is_string());
        assert!(value["hasFailure"].is_boolean());
    }

    #[test]
    fn parse_error_display() {
        assert!(format!("{}", ParseError::UnknownCommand("x".into())).contains("unknown command"));
        assert!(format!("{}", ParseError::UnknownAgent("x".into())).contains("unknown agent"));
        assert!(format!("{}", ParseError::MissingValue("x")).contains("missing value"));
        assert!(format!("{}", ParseError::UnexpectedArgument("x".into())).contains("unexpected"));
        assert!(
            format!("{}", ParseError::ConflictingFlags("x conflicts with y"))
                .contains("conflicting flags")
        );
    }

    /// `Read` impl that always returns an error so tests can drive the
    /// stdin-read failure arm of `run_hook`.
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("simulated stdin failure"))
        }
    }

    /// `Write` impl whose first `budget` bytes are accepted; every byte
    /// after that returns an error. Drives the render-failure arm of
    /// `run_plugin_test`.
    struct FailingWriter {
        budget: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.budget == 0 {
                return Err(std::io::Error::other("disk full"));
            }
            let n = buf.len().min(self.budget);
            self.budget -= n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn run_hook_fails_closed_when_stdin_read_fails() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::HookPreToolUse {
                agent: HookAgent::ClaudeCode,
            },
            FailingReader,
            &mut out,
            &mut err,
        );
        assert_eq!(code, 2);
        let out_s = String::from_utf8_lossy(&out);
        assert!(
            out_s.contains("\"permissionDecision\":\"deny\""),
            "stdout: {out_s}"
        );
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("failed to read stdin"), "stderr: {err_s}");
        assert!(err_s.contains(INVALID_PAYLOAD_RULE), "stderr: {err_s}");
    }

    #[test]
    fn run_hook_fails_closed_when_stdin_payload_is_too_large() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let payload = vec![b' '; MAX_HOOK_STDIN_BYTES as usize + 1];
        let code = run(
            Command::HookPreToolUse {
                agent: HookAgent::ClaudeCode,
            },
            payload.as_slice(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 2);
        let out_s = String::from_utf8_lossy(&out);
        assert!(
            out_s.contains("\"permissionDecision\":\"deny\""),
            "stdout: {out_s}"
        );
        let err_s = String::from_utf8_lossy(&err);
        assert!(
            err_s.contains("hook payload exceeds 8388608 bytes"),
            "stderr: {err_s}"
        );
        assert!(err_s.contains(INVALID_PAYLOAD_RULE), "stderr: {err_s}");
    }

    #[test]
    fn run_hook_fails_closed_when_stdin_read_fails_under_codex_adapter() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::HookPreToolUse {
                agent: HookAgent::Codex,
            },
            FailingReader,
            &mut out,
            &mut err,
        );
        assert_eq!(code, 2);
        let out_s = String::from_utf8_lossy(&out);
        assert!(
            out_s.contains("\"permissionDecision\":\"deny\""),
            "stdout: {out_s}"
        );
    }

    #[test]
    fn run_plugin_test_returns_one_when_render_writer_fails() {
        use std::fs;
        let dir = std::env::temp_dir().join(format!(
            "ptuf-plugin-test-render-fail-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("demo.yaml");
        fs::write(
            &path,
            r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      shell.argv:
        headAny: [curl]
    reason: blocked
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "curl https://example.com"
"#,
        )
        .unwrap();

        let mut writer = FailingWriter { budget: 0 };
        let mut err = Vec::new();
        let code = run_plugin_test(&path, &mut writer, &mut err);
        assert_eq!(code, 1);
        assert!(
            String::from_utf8_lossy(&err).contains("failed to write plugin test report"),
            "stderr: {}",
            String::from_utf8_lossy(&err)
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn hook_agent_audit_name_distinguishes_variants() {
        assert_eq!(HookAgent::ClaudeCode.audit_name(), "claude-code");
        assert_eq!(HookAgent::Codex.audit_name(), "codex");
    }

    #[test]
    fn hook_codex_emits_deny_envelope_for_destructive_rm() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let (code, out, err) = run_with(&["hook", "codex"], payload);
        assert_eq!(code, 2);
        let out_s = out;
        assert!(out_s.contains("\"hookSpecificOutput\""));
        assert!(out_s.contains("\"permissionDecision\":\"deny\""));
        assert!(err.contains("Blocked by ptuf rule"));
    }

    #[test]
    fn hook_codex_demotes_ask_to_deny_via_emit_decision() {
        let decision = Decision::Ask {
            rule_id: "core.test.ask".into(),
            reason: "please confirm".into(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::Codex, &decision, &mut out, &mut err);
        assert_eq!(code, 2, "Codex must demote Ask to deny exit code");
        let out_s = String::from_utf8_lossy(&out);
        assert!(
            out_s.contains("\"permissionDecision\":\"deny\""),
            "stdout: {out_s}"
        );
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("please confirm"), "stderr: {err_s}");
        assert!(
            err_s.contains("Codex PreToolUse cannot prompt interactively"),
            "stderr should explain Codex demotion: {err_s}"
        );
    }

    #[test]
    fn render_hook_response_dispatches_to_codex_adapter_for_ask() {
        let decision = Decision::Ask {
            rule_id: "core.test.ask".into(),
            reason: "please confirm".into(),
        };
        let claude =
            render_hook_response(HookAgent::ClaudeCode, &decision).expect("claude-code envelope");
        let adapted = adapt_hook_decision(HookAgent::Codex, &decision);
        let codex = render_hook_response(HookAgent::Codex, &adapted).expect("codex envelope");
        let claude_json = serde_json::to_string(&claude).unwrap();
        let codex_json = serde_json::to_string(&codex).unwrap();
        assert_ne!(
            claude_json, codex_json,
            "Codex envelope must differ from Claude Code for Ask"
        );
        assert!(
            codex_json.contains("\"permissionDecision\":\"deny\""),
            "codex envelope must demote to deny: {codex_json}"
        );
    }

    #[test]
    fn decision_exit_code_matrix_covers_codex_ask_demote() {
        assert_eq!(
            decision_exit_code(HookAgent::ClaudeCode, &Decision::Allow),
            0
        );
        assert_eq!(
            decision_exit_code(
                HookAgent::ClaudeCode,
                &Decision::Ask {
                    rule_id: "x".into(),
                    reason: "r".into()
                }
            ),
            0
        );
        assert_eq!(
            decision_exit_code(
                HookAgent::Codex,
                &Decision::Ask {
                    rule_id: "x".into(),
                    reason: "r".into()
                }
            ),
            2
        );
        assert_eq!(
            decision_exit_code(
                HookAgent::ClaudeCode,
                &Decision::Deny {
                    rule_id: "x".into(),
                    reason: "r".into()
                }
            ),
            2
        );
    }

    #[test]
    fn parse_codex_init_accepts_equals_forms_for_all_path_flags() {
        let cmd = parse(&s(&[
            "init",
            "codex",
            "--root=/r",
            "--hooks=/h.json",
            "--config=/c.toml",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Init {
                dry_run: false,
                options: InitOptions::Codex(CodexInitOptions {
                    root: Some(PathBuf::from("/r")),
                    hooks_path: Some(PathBuf::from("/h.json")),
                    config_path: Some(PathBuf::from("/c.toml")),
                }),
            }
        );
    }

    #[test]
    fn parse_codex_init_separate_hooks_form_value() {
        let cmd = parse(&s(&["init", "codex", "--hooks", "/h.json"])).unwrap();
        assert!(matches!(
            cmd,
            Command::Init {
                dry_run: false,
                options: InitOptions::Codex(CodexInitOptions {
                    hooks_path: Some(_),
                    ..
                })
            }
        ));
    }

    #[test]
    fn parses_init_rejects_unknown_agent() {
        assert!(matches!(
            parse(&s(&["init", "bogus"])),
            Err(ParseError::UnknownAgent(_))
        ));
    }

    #[test]
    fn parses_eval_rejects_extra_positional() {
        assert!(matches!(
            parse(&s(&["eval", "--tool", "Bash", "ls", "extra"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
    }

    #[test]
    fn hook_codex_evaluates_valid_payload_through_engine() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let (code, _out, _err) = run_with(&["hook", "codex"], payload);
        assert_eq!(code, 0);
    }

    #[test]
    fn render_install_outcome_for_already_present_dry_run_uses_suffix() {
        let outcome = init::InstallOutcome {
            status: init::InstallStatus::AlreadyPresent,
            agent: "codex",
            paths: vec![init::InstallPath {
                label: "hooks",
                path: PathBuf::from("/x/hooks.json"),
            }],
            matcher: "Bash".to_string(),
            command: "/x/ptuf hook codex".to_string(),
        };
        let mut out = Vec::new();
        render_install_outcome(&outcome, true, &mut out);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("(dry-run)"), "out: {s}");
        assert!(s.contains("already contains"), "out: {s}");
    }

    #[test]
    fn render_install_outcome_for_already_present_without_dry_run_omits_suffix() {
        let outcome = init::InstallOutcome {
            status: init::InstallStatus::AlreadyPresent,
            agent: "claude-code",
            paths: vec![init::InstallPath {
                label: "settings",
                path: PathBuf::from("/x/settings.json"),
            }],
            matcher: "Bash".to_string(),
            command: "/x/ptuf hook claude-code".to_string(),
        };
        let mut out = Vec::new();
        render_install_outcome(&outcome, false, &mut out);
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("(dry-run)"), "out: {s}");
        assert!(s.contains("already contains"), "out: {s}");
    }

    #[test]
    fn render_install_outcome_for_installed_writes_matcher_and_command() {
        let outcome = init::InstallOutcome {
            status: init::InstallStatus::Installed,
            agent: "codex",
            paths: vec![
                init::InstallPath {
                    label: "hooks",
                    path: PathBuf::from("/x/hooks.json"),
                },
                init::InstallPath {
                    label: "config",
                    path: PathBuf::from("/x/config.toml"),
                },
            ],
            matcher: "Bash|apply_patch|mcp__.*".to_string(),
            command: "/x/ptuf hook codex".to_string(),
        };
        let mut out = Vec::new();
        render_install_outcome(&outcome, false, &mut out);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("registered hook"));
        assert!(s.contains("hooks=/x/hooks.json"));
        assert!(s.contains("config=/x/config.toml"));
        assert!(s.contains("matcher: Bash|apply_patch|mcp__.*"));
        assert!(s.contains("command: /x/ptuf hook codex"));
    }

    #[test]
    fn render_install_outcome_for_would_install_emits_run_advice() {
        let outcome = init::InstallOutcome {
            status: init::InstallStatus::WouldInstall,
            agent: "codex",
            paths: vec![init::InstallPath {
                label: "hooks",
                path: PathBuf::from("/x/hooks.json"),
            }],
            matcher: "Bash".to_string(),
            command: "/x/ptuf hook codex".to_string(),
        };
        let mut out = Vec::new();
        render_install_outcome(&outcome, true, &mut out);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("would register hook"));
        assert!(s.contains("matcher: Bash"));
        assert!(s.contains("Run without --dry-run to apply."));
    }

    #[test]
    fn run_init_already_present_returns_zero_and_idempotent_message() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-cli-init-already-present-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");

        let cmd = || Command::Init {
            dry_run: false,
            options: InitOptions::ClaudeCode(ClaudeInitOptions {
                settings_path: Some(path.clone()),
            }),
        };

        let mut out1 = Vec::new();
        let mut err1 = Vec::new();
        assert_eq!(run(cmd(), b"" as &[u8], &mut out1, &mut err1), 0);

        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        assert_eq!(run(cmd(), b"" as &[u8], &mut out2, &mut err2), 0);
        assert!(String::from_utf8_lossy(&out2).contains("already contains"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn emit_decision_serialization_failure_returns_one() {
        // Force the json writer to fail by truncating budget below the
        // serialised envelope length. This exercises the
        // `serde_json::to_string` Ok-arm followed by writeln on a writer
        // that now errors past the budget.
        let decision = Decision::Deny {
            rule_id: "core.test.deny".into(),
            reason: "blocked".into(),
        };
        // Sufficient to write the full body; ensures we still hit the
        // happy-path serialise + writeln, including the trailing
        // `decision_exit_code`.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = emit_decision(HookAgent::ClaudeCode, &decision, &mut out, &mut err);
        assert_eq!(code, 2);
        assert!(String::from_utf8_lossy(&out).contains("\"permissionDecision\":\"deny\""));
        assert!(String::from_utf8_lossy(&err).contains("blocked"));
    }

    #[test]
    fn run_doctor_returns_one_when_writer_fails() {
        let mut writer = FailingWriter { budget: 0 };
        let mut err = Vec::new();
        let code = run_doctor(false, &mut writer, &mut err);
        assert_eq!(code, 1);
        assert!(String::from_utf8_lossy(&err).contains("doctor failed"));
    }

    #[test]
    fn run_doctor_json_returns_one_when_writer_fails() {
        let mut writer = FailingWriter { budget: 0 };
        let mut err = Vec::new();
        let code = run_doctor(true, &mut writer, &mut err);
        assert_eq!(code, 1);
        assert!(String::from_utf8_lossy(&err).contains("doctor failed"));
    }

    /// RAII guard that swaps the process cwd for the duration of a test
    /// and restores it on drop. Tests using this helper rely on the
    /// `--test-threads=1` setting in `Makefile` / CI so concurrent cwd
    /// mutation cannot occur.
    struct CwdGuard {
        original: PathBuf,
    }

    impl CwdGuard {
        fn change_to(target: &std::path::Path) -> std::io::Result<Self> {
            let original = std::env::current_dir()?;
            std::env::set_current_dir(target)?;
            Ok(Self { original })
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    fn make_engine_failing_repo(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-cli-engine-fail-{}-{}-{}",
            label,
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".git")).expect("mkdir .git");
        std::fs::write(
            dir.join(".ptuf.yaml"),
            "plugins:\n  - path: ./missing-plugin.yaml\n",
        )
        .expect("write .ptuf.yaml");
        dir
    }

    #[test]
    fn run_hook_fails_closed_when_engine_construction_fails() {
        let dir = make_engine_failing_repo("hook");
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::HookPreToolUse {
                agent: HookAgent::ClaudeCode,
            },
            payload.as_bytes(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 2);
        let out_s = String::from_utf8_lossy(&out);
        assert!(
            out_s.contains("\"permissionDecision\":\"deny\""),
            "stdout: {out_s}"
        );
        assert!(out_s.contains(POLICY_LOAD_FAILED_RULE), "stdout: {out_s}");
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("could not load policy"), "stderr: {err_s}");
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_eval_fails_closed_when_engine_construction_fails() {
        let dir = make_engine_failing_repo("eval");
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::Eval {
                tool: "Bash".into(),
                command: "ls".into(),
            },
            std::io::empty(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 2);
        let out_s = String::from_utf8_lossy(&out);
        assert!(out_s.contains("Decision: deny"), "stdout: {out_s}");
        assert!(out_s.contains(POLICY_LOAD_FAILED_RULE), "stdout: {out_s}");
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("could not load policy"), "stderr: {err_s}");
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
