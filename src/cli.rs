use std::io::{Read, Write};
use std::path::PathBuf;

use crate::Decision;
use crate::engine::Engine;
use crate::hook_input::HookInput;
use crate::hook_output;
use crate::init;
use crate::plugin::runner as plugin_runner;

/// Reserved rule id used when the engine itself failed to load policy
/// and the CLI must fail-closed
/// (`docs/design/cli-and-hooks.md:104-114`).
pub(crate) const POLICY_LOAD_FAILED_RULE: &str = "core.engine.policy-load-failed";

/// Build the engine for the CWD-derived project scope, or surface a
/// reserved deny so the CLI can render a fail-closed response.
///
/// Production CLI entry points (compat / `hook ...` / `eval`) all go
/// through this helper. The `crate::decide` shim is intentionally
/// lenient (`Engine::default` fallback) for embedded library use.
pub(crate) fn build_engine_or_fail_closed<W: Write>(stderr: &mut W) -> Result<Engine, Decision> {
    Engine::for_cwd().map_err(|err| {
        let _ = writeln!(stderr, "ptuf: could not load policy: {err}");
        Decision::Deny {
            rule_id: POLICY_LOAD_FAILED_RULE.into(),
            reason: "ptuf could not load policy; failing closed.".into(),
        }
    })
}

/// Parsed CLI invocation. The bare-arguments form is preserved for hook
/// compatibility with the bootstrap (`echo ... | ptuf`) usage.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// No arguments — read JSON payload from stdin (bootstrap behaviour).
    Compat,
    /// `ptuf hook claude-code pre-tool-use` — read JSON payload from stdin
    /// and emit a `hookSpecificOutput` response on stdout.
    HookClaudeCodePreToolUse,
    /// `ptuf eval --tool <name> <command>` — manual evaluation.
    Eval { tool: String, command: String },
    /// `ptuf plugin test <path>` — run plugin assertions.
    PluginTest { path: PathBuf },
    /// `ptuf init <agent> [--dry-run] [--settings <PATH>]` — install the
    /// PreToolUse hook entry.
    Init {
        agent: String,
        dry_run: bool,
        settings_path: Option<PathBuf>,
    },
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
    UnknownEvent(String),
    MissingValue(&'static str),
    UnexpectedArgument(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCommand(c) => write!(f, "unknown command: {c}"),
            Self::UnknownAgent(a) => write!(f, "unknown agent: {a}"),
            Self::UnknownEvent(e) => write!(f, "unknown event: {e}"),
            Self::MissingValue(name) => write!(f, "missing value for {name}"),
            Self::UnexpectedArgument(a) => write!(f, "unexpected argument: {a}"),
        }
    }
}

/// Parse argv (excluding the program name) into a [`Command`].
pub fn parse(args: &[String]) -> Result<Command, ParseError> {
    let mut iter = args.iter();
    let Some(first) = iter.next() else {
        return Ok(Command::Compat);
    };

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
    let mut dry_run = false;
    let mut settings_path: Option<PathBuf> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
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
    Ok(Command::Init {
        agent: agent.clone(),
        dry_run,
        settings_path,
    })
}

fn parse_hook<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let agent = iter.next().ok_or(ParseError::MissingValue("agent"))?;
    if agent != "claude-code" {
        return Err(ParseError::UnknownAgent(agent.clone()));
    }
    let event = iter.next().ok_or(ParseError::MissingValue("event"))?;
    if event != "pre-tool-use" {
        return Err(ParseError::UnknownEvent(event.clone()));
    }
    if let Some(extra) = iter.next() {
        return Err(ParseError::UnexpectedArgument(extra.clone()));
    }
    Ok(Command::HookClaudeCodePreToolUse)
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
    ptuf                                         (compat: read JSON from stdin)
    ptuf hook claude-code pre-tool-use           (Claude Code PreToolUse hook)
    ptuf eval --tool <NAME> <COMMAND>            (evaluate a single tool call)
    ptuf plugin test <PATH>                      (run a plugin's deny/allow tests)
    ptuf init claude-code [--dry-run]            (register PreToolUse hook in
                          [--settings <PATH>]    ~/.claude/settings.json)
    ptuf doctor [--json]                         (print a diagnostic report)
    ptuf --help | --version

EXIT CODES:
    0   allow / monitor / ask / plugin tests pass
    1   internal error (bad JSON, bad arguments) or plugin tests fail
    2   deny
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
        Command::Compat => crate::io_runner::run_compat_code(stdin, stderr),
        Command::HookClaudeCodePreToolUse => run_hook(stdin, stdout, stderr),
        Command::Eval { tool, command } => run_eval(&tool, &command, stdout, stderr),
        Command::PluginTest { path } => run_plugin_test(&path, stdout, stderr),
        Command::Init {
            agent,
            dry_run,
            settings_path,
        } => run_init(&agent, dry_run, settings_path.as_deref(), stdout, stderr),
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

fn run_hook<R: Read, W1: Write, W2: Write>(mut stdin: R, stdout: &mut W1, stderr: &mut W2) -> u8 {
    let mut buf = String::new();
    if stdin.read_to_string(&mut buf).is_err() {
        let _ = writeln!(stderr, "ptuf: failed to read stdin");
        return 1;
    }
    let input: HookInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(err) => {
            let _ = writeln!(stderr, "ptuf: invalid hook payload: {err}");
            return 1;
        }
    };
    let decision = match build_engine_or_fail_closed(stderr) {
        Ok(engine) => engine.decide(&input).decision,
        Err(deny) => deny,
    };
    emit_decision(&decision, stdout, stderr)
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
    let decision = match build_engine_or_fail_closed(stderr) {
        Ok(engine) => engine.decide(&input).decision,
        Err(deny) => deny,
    };
    let _ = writeln!(stdout, "Decision: {}", decision_label(&decision));
    if let Some(rule_id) = decision.rule_id() {
        let _ = writeln!(stdout, "Rule: {rule_id}");
    }
    if let Some(reason) = decision.reason() {
        let _ = writeln!(stderr, "{reason}");
    }
    decision_exit_code(&decision)
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
    agent: &str,
    dry_run: bool,
    settings_path: Option<&std::path::Path>,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    if agent != "claude-code" {
        let _ = writeln!(stderr, "ptuf: unknown agent: {agent}");
        return 1;
    }

    let resolved_path = match settings_path {
        Some(p) => p.to_path_buf(),
        None => match init::claude_code::default_settings_path() {
            Some(p) => p,
            None => {
                let _ = writeln!(
                    stderr,
                    "ptuf: $HOME is not set; pass --settings <PATH> explicitly"
                );
                return 1;
            }
        },
    };
    let binary = init::claude_code::detect_binary();

    match init::claude_code::install(&resolved_path, &binary, dry_run) {
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
    if json {
        let _ = writeln!(
            stderr,
            "ptuf: --json output is not yet implemented (planned for v0.4); falling back to text"
        );
    }
    match crate::doctor::render_doctor(stdout) {
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

fn render_install_outcome<W: Write>(outcome: &init::InstallOutcome, dry_run: bool, stdout: &mut W) {
    let path = outcome.settings_path.display();
    match outcome.status {
        init::InstallStatus::AlreadyPresent => {
            let suffix = if dry_run { " (dry-run)" } else { "" };
            let _ = writeln!(
                stdout,
                "ptuf init claude-code{suffix}: {path} already contains a ptuf hook entry; nothing to do."
            );
        }
        init::InstallStatus::Installed => {
            let _ = writeln!(stdout, "ptuf init claude-code: registered hook in {path}");
            let _ = writeln!(stdout, "  matcher: {}", outcome.matcher);
            let _ = writeln!(stdout, "  command: {}", outcome.command);
        }
        init::InstallStatus::WouldInstall => {
            let _ = writeln!(
                stdout,
                "ptuf init claude-code (dry-run): would register hook in {path}"
            );
            let _ = writeln!(stdout, "  matcher: {}", outcome.matcher);
            let _ = writeln!(stdout, "  command: {}", outcome.command);
            let _ = writeln!(stdout, "Run without --dry-run to apply.");
        }
    }
}

fn emit_decision<W1: Write, W2: Write>(
    decision: &Decision,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    if let Some(response) = hook_output::from_decision(decision) {
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
    if let Some(reason) = decision.reason() {
        let _ = writeln!(stderr, "{reason}");
    }
    decision_exit_code(decision)
}

fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Monitor { .. } => "monitor",
        Decision::Ask { .. } => "ask",
        Decision::Deny { .. } => "deny",
    }
}

fn decision_exit_code(decision: &Decision) -> u8 {
    match decision {
        Decision::Deny { .. } => 2,
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
    fn parses_compat_when_no_args() {
        assert_eq!(parse(&[]).unwrap(), Command::Compat);
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
        let cmd = parse(&s(&["hook", "claude-code", "pre-tool-use"])).unwrap();
        assert_eq!(cmd, Command::HookClaudeCodePreToolUse);
    }

    #[test]
    fn rejects_unknown_agent_or_event() {
        assert!(matches!(
            parse(&s(&["hook", "codex", "pre-tool-use"])),
            Err(ParseError::UnknownAgent(_))
        ));
        assert!(matches!(
            parse(&s(&["hook", "claude-code", "post-tool-use"])),
            Err(ParseError::UnknownEvent(_))
        ));
    }

    #[test]
    fn rejects_extra_args_after_hook() {
        assert!(matches!(
            parse(&s(&["hook", "claude-code", "pre-tool-use", "extra"])),
            Err(ParseError::UnexpectedArgument(_))
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
                agent: "claude-code".into(),
                dry_run: false,
                settings_path: None,
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
                agent: "claude-code".into(),
                dry_run: true,
                settings_path: Some(PathBuf::from("/tmp/x.json")),
            }
        );
    }

    #[test]
    fn parses_init_with_equals_settings_form() {
        let cmd = parse(&s(&["init", "claude-code", "--settings=/tmp/x.json"])).unwrap();
        assert_eq!(
            cmd,
            Command::Init {
                agent: "claude-code".into(),
                dry_run: false,
                settings_path: Some(PathBuf::from("/tmp/x.json")),
            }
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
    }

    #[test]
    fn init_settings_flag_requires_value() {
        assert!(matches!(
            parse(&s(&["init", "claude-code", "--settings"])),
            Err(ParseError::MissingValue("--settings"))
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
        assert!(err.is_empty());
    }

    #[test]
    fn hook_emits_json_for_deny() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let (code, out, err) = run_with(&["hook", "claude-code", "pre-tool-use"], payload);
        assert_eq!(code, 2);
        assert!(out.contains("\"hookSpecificOutput\""));
        assert!(out.contains("\"permissionDecision\":\"deny\""));
        assert!(err.contains("Blocked by ptuf rule"));
    }

    #[test]
    fn hook_returns_zero_and_no_stdout_for_allow() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let (code, out, err) = run_with(&["hook", "claude-code", "pre-tool-use"], payload);
        assert_eq!(code, 0);
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[test]
    fn hook_returns_one_for_invalid_json() {
        let (code, out, err) = run_with(&["hook", "claude-code", "pre-tool-use"], "not json");
        assert_eq!(code, 1);
        assert!(out.is_empty());
        assert!(err.contains("invalid hook payload"));
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
    fn run_dispatches_compat_branch() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let (code, out, err) = run_with(&[], payload);
        assert_eq!(code, 2);
        assert!(out.is_empty());
        assert!(err.contains("Blocked by ptuf rule"));
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
        let code = emit_decision(&decision, &mut out, &mut err);
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
    fn run_init_unknown_agent_returns_one() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::Init {
                agent: "codex".into(),
                dry_run: true,
                settings_path: Some(PathBuf::from("/tmp/should-not-be-touched.json")),
            },
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1);
        assert!(String::from_utf8_lossy(&err).contains("unknown agent"));
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
                agent: "claude-code".into(),
                dry_run: true,
                settings_path: Some(path.clone()),
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
                agent: "claude-code".into(),
                dry_run: false,
                settings_path: Some(path.clone()),
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
                agent: "claude-code".into(),
                dry_run: false,
                settings_path: Some(path.clone()),
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
                agent: "claude-code".into(),
                dry_run: false,
                settings_path: Some(path.clone()),
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
    fn run_doctor_with_json_flag_warns_and_falls_back_to_text() {
        let (_code, out, err) = run_with(&["doctor", "--json"], "");
        assert!(out.contains("ptuf doctor"));
        assert!(err.contains("--json output is not yet implemented"));
    }

    #[test]
    fn parse_error_display() {
        assert!(format!("{}", ParseError::UnknownCommand("x".into())).contains("unknown command"));
        assert!(format!("{}", ParseError::UnknownAgent("x".into())).contains("unknown agent"));
        assert!(format!("{}", ParseError::UnknownEvent("x".into())).contains("unknown event"));
        assert!(format!("{}", ParseError::MissingValue("x")).contains("missing value"));
        assert!(format!("{}", ParseError::UnexpectedArgument("x".into())).contains("unexpected"));
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
    fn run_hook_returns_one_when_stdin_read_fails() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            Command::HookClaudeCodePreToolUse,
            FailingReader,
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1);
        assert!(out.is_empty());
        assert!(String::from_utf8_lossy(&err).contains("failed to read stdin"));
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
}
