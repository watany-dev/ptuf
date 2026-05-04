use std::io::{Read, Write};
use std::path::PathBuf;

use crate::hook_input::HookInput;
use crate::hook_output;
use crate::plugin::runner as plugin_runner;
use crate::{Decision, decide};

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
        other => Err(ParseError::UnknownCommand(other.to_string())),
    }
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
    emit_decision(&decide(&input), stdout, stderr)
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
    let decision = decide(&input);
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
            parse(&s(&["doctor"])),
            Err(ParseError::UnknownCommand(_))
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
    fn parse_error_display() {
        assert!(format!("{}", ParseError::UnknownCommand("x".into())).contains("unknown command"));
        assert!(format!("{}", ParseError::UnknownAgent("x".into())).contains("unknown agent"));
        assert!(format!("{}", ParseError::UnknownEvent("x".into())).contains("unknown event"));
        assert!(format!("{}", ParseError::MissingValue("x")).contains("missing value"));
        assert!(format!("{}", ParseError::UnexpectedArgument("x".into())).contains("unexpected"));
    }
}
