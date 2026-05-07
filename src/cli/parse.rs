//! Argument-parser submodule.
//!
//! Each `parse_*` helper consumes a peeked iterator and produces a
//! [`Command`] or a [`ParseError`]. The public entry point lives in
//! `cli/mod.rs::parse` so external callers (`src/main.rs`,
//! `tests/cli_smoke.rs`) keep the same path.

use std::path::PathBuf;

use super::{ClaudeInitOptions, CodexInitOptions, Command, HookAgent, InitOptions, ParseError};

pub(super) fn parse_doctor<'a, I>(iter: &mut I) -> Result<Command, ParseError>
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

pub(super) fn parse_init<'a, I>(iter: &mut I) -> Result<Command, ParseError>
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

pub(super) fn parse_init_claude<'a, I>(iter: &mut I) -> Result<Command, ParseError>
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

pub(super) fn parse_init_codex<'a, I>(iter: &mut I) -> Result<Command, ParseError>
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

pub(super) fn parse_hook<'a, I>(iter: &mut I) -> Result<Command, ParseError>
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

pub(super) fn parse_eval<'a, I>(iter: &mut I) -> Result<Command, ParseError>
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

pub(super) fn parse_plugin<'a, I>(iter: &mut I) -> Result<Command, ParseError>
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

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use super::super::test_support::s;
    use super::super::{
        ClaudeInitOptions, CodexInitOptions, Command, HookAgent, InitOptions, ParseError, parse,
    };

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
        assert!(matches!(
            parse(&s(&["init", "claude-code", "--json"])),
            Err(ParseError::ConflictingFlags(_))
        ));
    }

    #[test]
    fn rejects_verify_with_dry_run() {
        assert!(matches!(
            parse(&s(&["init", "claude-code", "--verify", "--dry-run"])),
            Err(ParseError::ConflictingFlags(_))
        ));
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

    #[test]
    fn eval_extra_positional_argument_is_rejected() {
        assert!(matches!(
            parse(&s(&["eval", "--tool", "Bash", "ls", "extra"])),
            Err(ParseError::UnexpectedArgument(_))
        ));
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
                    ..Default::default()
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
