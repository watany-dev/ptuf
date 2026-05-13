//! Argument-parser submodule.
//!
//! Each `parse_*` helper consumes a peeked iterator and produces a
//! [`Command`] or a [`ParseError`]. The public entry point lives in
//! `cli/mod.rs::parse` so external callers (`src/main.rs`,
//! `tests/cli_smoke.rs`) keep the same path.

use std::path::PathBuf;

use crate::update::UpdateOptions;

use super::{Command, HookAgent, InitOptions, ParseError};

pub(super) fn parse_init<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let mut agent: Option<HookAgent> = None;
    let mut dry_run = false;
    let mut no_verify = false;
    for arg in iter {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--no-verify" => no_verify = true,
            "claude-code" | "codex" | "copilot" | "kiro" => {
                if agent.is_some() {
                    return Err(ParseError::UnexpectedArgument(arg.clone()));
                }
                agent = Some(parse_agent(arg)?);
            },
            other => return Err(ParseError::UnexpectedArgument(other.to_string())),
        }
    }
    // Dry-run never writes, so the synthetic-deny check would just
    // confirm whatever was already on disk; treat dry-run as "skip
    // verify" rather than as a parse error.
    let verify = !no_verify && !dry_run;
    Ok(Command::Init(InitOptions {
        agent,
        verify,
        dry_run,
    }))
}

fn parse_agent(value: &str) -> Result<HookAgent, ParseError> {
    match value {
        "claude-code" => Ok(HookAgent::ClaudeCode),
        "codex" => Ok(HookAgent::Codex),
        "copilot" => Ok(HookAgent::Copilot),
        "kiro" => Ok(HookAgent::Kiro),
        other => Err(ParseError::UnknownAgent(other.to_string())),
    }
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

    use crate::update::UpdateOptions;

    use super::super::test_support::s;
    use super::super::{Command, GlobalFlags, HookAgent, InitOptions, ParseError, parse};

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
                agent: HookAgent::Kiro
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
            })
        );
    }

    #[test]
    fn parses_init_with_each_agent_token() {
        for (token, expected) in [
            ("claude-code", HookAgent::ClaudeCode),
            ("codex", HookAgent::Codex),
            ("copilot", HookAgent::Copilot),
            ("kiro", HookAgent::Kiro),
        ] {
            let c = cmd(&["init", token]);
            assert_eq!(
                c,
                Command::Init(InitOptions {
                    agent: Some(expected),
                    verify: true,
                    dry_run: false,
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
            })
        );
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
