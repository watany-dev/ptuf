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

use super::{Command, HookAgent, InitOptions, ParseError, ReadonlyAction};

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
                "claude-code" | "codex" | "copilot" | "kiro" | "cline" | "cursor" | "pi"
                | "opencode" => {
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
    let kiro_only_flag_set = new_agent || workspace_only || global;
    if kiro_only_flag_set && agent != Some(HookAgent::Kiro) {
        return Err(ParseError::ConflictingFlags(
            "Kiro-only flag requires `kiro` agent",
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
        && agent != Some(HookAgent::Opencode)
    {
        return Err(ParseError::ConflictingFlags(
            "`--scope` / `--root` require `cursor`, `pi`, or `opencode` agent",
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
    let kiro = KiroInitOptions {
        mode: if new_agent {
            KiroMode::NewAgent
        } else {
            KiroMode::PatchExisting
        },
        scope: if workspace_only {
            ScopeFilter::WorkspaceOnly
        } else if global {
            ScopeFilter::GlobalOnly
        } else {
            ScopeFilter::Both
        },
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
        scope: if agent == Some(HookAgent::Opencode) {
            shared_scope.map(Into::into).unwrap_or_default()
        } else {
            OpencodeScope::default()
        },
        root: if agent == Some(HookAgent::Opencode) {
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

#[derive(Clone, Copy)]
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
        "kiro" => Ok(HookAgent::Kiro),
        "cline" => Ok(HookAgent::Cline),
        "cursor" => Ok(HookAgent::Cursor),
        "pi" => Ok(HookAgent::Pi),
        "opencode" => Ok(HookAgent::Opencode),
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

pub(super) fn parse_readonly<'a, I>(iter: &mut I) -> Result<Command, ParseError>
where
    I: Iterator<Item = &'a String>,
{
    let action_tok = iter
        .next()
        .ok_or(ParseError::MissingValue("on|off|status"))?;
    let action = match action_tok.as_str() {
        "on" => ReadonlyAction::On,
        "off" => ReadonlyAction::Off,
        "status" => ReadonlyAction::Status,
        other => {
            return Err(ParseError::UnexpectedArgument(other.to_string()));
        },
    };
    let mut global = false;
    for arg in iter {
        match arg.as_str() {
            "--global" => global = true,
            other => return Err(ParseError::UnexpectedArgument(other.to_string())),
        }
    }
    Ok(Command::Readonly { action, global })
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
                agent: HookAgent::Opencode
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
            ("kiro", HookAgent::Kiro),
            ("cline", HookAgent::Cline),
            ("cursor", HookAgent::Cursor),
            ("pi", HookAgent::Pi),
            ("opencode", HookAgent::Opencode),
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
            cmd(&["init", "kiro", "--new-agent"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::Kiro),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions {
                    mode: KiroMode::NewAgent,
                    scope: ScopeFilter::Both,
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
            cmd(&["init", "kiro", "--workspace-only"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::Kiro),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions {
                    mode: KiroMode::PatchExisting,
                    scope: ScopeFilter::WorkspaceOnly,
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
            cmd(&["init", "kiro", "--global"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::Kiro),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions {
                    mode: KiroMode::PatchExisting,
                    scope: ScopeFilter::GlobalOnly,
                },
                cursor: CursorInitOptions::default(),
                pi: PiInitOptions::default(),
                opencode: OpencodeInitOptions::default(),
            })
        );
    }

    #[test]
    fn parse_init_accepts_new_agent_with_global() {
        assert_eq!(
            cmd(&["init", "kiro", "--new-agent", "--global"]),
            Command::Init(InitOptions {
                agent: Some(HookAgent::Kiro),
                verify: true,
                dry_run: false,
                kiro: KiroInitOptions {
                    mode: KiroMode::NewAgent,
                    scope: ScopeFilter::GlobalOnly,
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
            vec!["init", "kiro", "--root", "/x"],
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
    fn parse_readonly_on_off_status_and_global() {
        use crate::cli::{Command, ReadonlyAction, parse};
        let args = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        let (_, cmd) = parse(&args(&["readonly", "on"])).expect("on");
        assert_eq!(
            cmd,
            Command::Readonly {
                action: ReadonlyAction::On,
                global: false
            }
        );
        let (_, cmd) = parse(&args(&["readonly", "off", "--global"])).expect("off");
        assert_eq!(
            cmd,
            Command::Readonly {
                action: ReadonlyAction::Off,
                global: true
            }
        );
        let (_, cmd) = parse(&args(&["readonly", "status"])).expect("status");
        assert_eq!(
            cmd,
            Command::Readonly {
                action: ReadonlyAction::Status,
                global: false
            }
        );
        let _ = parse(&args(&["readonly"])).unwrap_err();
        let _ = parse(&args(&["readonly", "maybe"])).unwrap_err();
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
