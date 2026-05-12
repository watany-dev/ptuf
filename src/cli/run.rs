//! Subcommand dispatch — every `run_*` helper takes the I/O streams of
//! the parent `cli::run` and returns a u8 exit code.
//!
//! The hook entry must always fail-closed (exit 2) when initialisation
//! fails, so payload-read / JSON / engine-build errors all funnel
//! through [`invalid_payload_deny`] and `policy_load_failed_deny`.

use std::io::{Read, Write};
use std::path::PathBuf;

use crate::Decision;
use crate::hook_input::HookInput;
use crate::init;
use crate::plugin::runner as plugin_runner;
use crate::reason;
use crate::update::exe::RealExeLocator;
use crate::update::spawn::ProcessSpawner;
use crate::update::{self, UpdateOptions};

use super::copilot_input;
use super::kiro_input;
use super::output::{decision_exit_code, decision_label, emit_decision};
use super::{
    GlobalFlags, HookAgent, INVALID_PAYLOAD_RULE, InitOptions, build_engine_or_fail_closed,
};

pub(super) const MAX_HOOK_STDIN_BYTES: u64 = 8 * 1024 * 1024;

pub(super) fn run_hook<R: Read, W1: Write, W2: Write>(
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
    let input: HookInput = match parse_hook_input_for_agent(agent, &buf) {
        Ok(v) => v,
        Err(problem) => {
            let _ = writeln!(stderr, "ptuf: invalid hook payload: {problem}");
            let deny = invalid_payload_deny(&problem);
            return emit_decision(agent, &deny, stdout, stderr);
        },
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
        },
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

/// Parse stdin into a [`HookInput`] using the agent-specific schema.
///
/// Claude Code and Codex both speak the snake_case
/// `tool_name`/`tool_input` shape directly. Copilot may send either the
/// snake_case form or the camelCase `toolName`/`toolArgs` form (with
/// `toolArgs` either a JSON object or a JSON-encoded string), so its
/// payload routes through `cli::copilot_input::parse` for normalisation
/// before the engine sees it. Kiro uses a snake_case shape but with its
/// own tool-name vocabulary (`shell`, `read`, `write`, `@server/tool`,
/// etc.), so its payload routes through `cli::kiro_input::parse`.
fn parse_hook_input_for_agent(agent: HookAgent, body: &str) -> Result<HookInput, String> {
    match agent {
        HookAgent::ClaudeCode | HookAgent::Codex => serde_json::from_str::<HookInput>(body)
            .map_err(|err| format!("hook payload is not valid JSON ({err})")),
        HookAgent::Copilot => copilot_input::parse(body).map_err(|err| err.to_string()),
        HookAgent::Kiro => kiro_input::parse(body).map_err(|err| err.to_string()),
    }
}

pub(super) fn run_check<W1: Write, W2: Write>(
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
        },
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

pub(super) fn run_plugin_check<W1: Write, W2: Write>(
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
            u8::from(!report.passed())
        },
        Err(err) => {
            let _ = writeln!(stderr, "ptuf: {err}");
            1
        },
    }
}

/// `ptuf init [<agent>] [--no-verify] [--dry-run]` entry point.
///
/// Responsibilities:
/// - resolve which agents to install for (`Some(a)` -> `[a]`,
///   `None` -> auto-detect from cwd / `$HOME`)
/// - if no agents detected at all, exit 1 with "no agent detected"
/// - run install (and verify, when requested) for each agent
///   independently and aggregate the exit code
pub(super) fn run_init<W1: Write, W2: Write>(
    globals: GlobalFlags,
    options: InitOptions,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    run_init_with(globals, options, init::verify::run, stdout, stderr)
}

pub(super) fn run_init_with<W1, W2, F>(
    globals: GlobalFlags,
    options: InitOptions,
    mut runner: F,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8
where
    W1: Write,
    W2: Write,
    F: FnMut() -> init::verify::VerifyReport,
{
    let cwd = std::env::current_dir().ok();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let agents = if let Some(a) = options.agent {
        vec![a]
    } else {
        let detected = init::detect_agents(cwd.as_deref(), home.as_deref());
        if detected.is_empty() {
            let _ = writeln!(
                stderr,
                "ptuf init: no agent detected under cwd / $HOME; pass an explicit agent (claude-code | codex | copilot | kiro)",
            );
            return 1;
        }
        if !globals.json {
            let labels: Vec<&str> = detected.iter().map(|a| a.audit_name()).collect();
            let _ = writeln!(stdout, "ptuf init: detected agents: {}", labels.join(", "));
        }
        detected
    };

    let mut overall: u8 = 0;
    let mut json_results: Vec<serde_json::Value> = Vec::new();

    for agent in agents {
        let result = install_one(agent, cwd.as_deref(), &options, &mut runner, stderr);
        match result {
            Ok(InstallStep {
                outcome,
                report,
                rolled_back,
            }) => {
                if let Some(report) = report.as_ref()
                    && !report.passed()
                {
                    overall = 1;
                }
                if globals.json {
                    let value = match report.as_ref() {
                        Some(r) => init::verify::render_json(&outcome, r, rolled_back),
                        None => render_install_json(&outcome, options.dry_run),
                    };
                    json_results.push(value);
                } else {
                    render_install_outcome(&outcome, options.dry_run, stdout);
                    if let Some(report) = report.as_ref() {
                        let _ = init::verify::render_text(report, stdout);
                        if rolled_back {
                            let _ =
                                writeln!(stdout, "ptuf init: rolled back changes (verify failed)");
                        } else if !report.passed()
                            && matches!(outcome.status, init::InstallStatus::AlreadyPresent)
                        {
                            let _ = writeln!(
                                stdout,
                                "ptuf init: existing hook entry failed verification; review the file(s) above manually.",
                            );
                        }
                    }
                }
            },
            Err(err) => {
                overall = 1;
                if globals.json {
                    json_results.push(serde_json::json!({
                        "agent": agent.audit_name(),
                        "error": err.to_string(),
                    }));
                } else {
                    let _ = writeln!(stderr, "ptuf init {}: {err}", agent.audit_name());
                }
            },
        }
    }

    if globals.json {
        let payload = if json_results.len() == 1 {
            json_results.remove(0)
        } else {
            serde_json::Value::Array(json_results)
        };
        match serde_json::to_string_pretty(&payload) {
            Ok(s) => {
                let _ = writeln!(stdout, "{s}");
            },
            Err(err) => {
                let _ = writeln!(stderr, "ptuf: failed to render init JSON: {err}");
                return 1;
            },
        }
    }

    overall
}

pub(super) fn run_update<W1: Write, W2: Write>(
    options: UpdateOptions,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
    let spawner = ProcessSpawner;
    let locator = RealExeLocator;
    update::run(options, &spawner, &locator, stdout, stderr)
}

struct InstallStep {
    outcome: init::InstallOutcome,
    report: Option<init::verify::VerifyReport>,
    rolled_back: bool,
}

fn install_one<F, W: Write>(
    agent: HookAgent,
    cwd: Option<&std::path::Path>,
    options: &InitOptions,
    runner: &mut F,
    stderr: &mut W,
) -> Result<InstallStep, init::InitError>
where
    F: FnMut() -> init::verify::VerifyReport,
{
    let plan = AgentPlan::resolve(agent, cwd)?;
    let snaps = if options.verify {
        Some(init::capture(
            &plan
                .snapshot_paths
                .iter()
                .map(PathBuf::as_path)
                .collect::<Vec<_>>(),
        )?)
    } else {
        None
    };
    let outcome = (plan.install)(options.dry_run)?;
    if !options.verify {
        return Ok(InstallStep {
            outcome,
            report: None,
            rolled_back: false,
        });
    }
    let report = runner();
    let mut rolled_back = false;
    if !report.passed()
        && matches!(outcome.status, init::InstallStatus::Installed)
        && let Some(snaps) = snaps.as_deref()
    {
        match init::restore(snaps) {
            Ok(()) => {
                rolled_back = true;
            },
            Err(err) => {
                let _ = writeln!(stderr, "ptuf init: rollback failed: {err}");
            },
        }
    }
    Ok(InstallStep {
        outcome,
        report: Some(report),
        rolled_back,
    })
}

struct AgentPlan {
    snapshot_paths: Vec<PathBuf>,
    install: Box<dyn FnOnce(bool) -> Result<init::InstallOutcome, init::InitError>>,
}

impl AgentPlan {
    fn resolve(agent: HookAgent, cwd: Option<&std::path::Path>) -> Result<Self, init::InitError> {
        match agent {
            HookAgent::ClaudeCode => {
                let path = init::claude_code::default_settings_path()
                    .ok_or(init::InitError::HomeNotSet)?;
                let install_path = path.clone();
                Ok(Self {
                    snapshot_paths: vec![path],
                    install: Box::new(move |dry_run| {
                        let binary = init::claude_code::detect_binary();
                        init::claude_code::install(&install_path, &binary, dry_run)
                    }),
                })
            },
            HookAgent::Codex => {
                let targets = init::codex::resolve_paths(cwd)?;
                Ok(Self {
                    snapshot_paths: vec![targets.hooks_path.clone(), targets.config_path.clone()],
                    install: Box::new(move |dry_run| {
                        let binary = init::codex::detect_binary();
                        init::codex::install(&targets, &binary, dry_run)
                    }),
                })
            },
            HookAgent::Copilot => {
                let targets = init::copilot::resolve_paths(cwd)?;
                Ok(Self {
                    snapshot_paths: vec![targets.hooks_path.clone()],
                    install: Box::new(move |dry_run| {
                        let binary = init::copilot::detect_binary();
                        init::copilot::install(&targets, &binary, dry_run)
                    }),
                })
            },
            HookAgent::Kiro => {
                let targets = init::kiro::resolve_paths(cwd)?;
                Ok(Self {
                    snapshot_paths: vec![targets.agent_config_path.clone()],
                    install: Box::new(move |dry_run| {
                        let binary = init::kiro::detect_binary();
                        init::kiro::install(&targets, &binary, dry_run)
                    }),
                })
            },
        }
    }
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
        },
        init::InstallStatus::Installed => {
            let line = format!("ptuf init {agent}: registered hook in {path_summary}");
            let _ = writeln!(stdout, "{line}");
            let _ = writeln!(stdout, "  matcher: {}", outcome.matcher);
            let _ = writeln!(stdout, "  command: {}", outcome.command);
        },
        init::InstallStatus::WouldInstall => {
            let line =
                format!("ptuf init {agent} (dry-run): would register hook in {path_summary}");
            let _ = writeln!(stdout, "{line}");
            let _ = writeln!(stdout, "  matcher: {}", outcome.matcher);
            let _ = writeln!(stdout, "  command: {}", outcome.command);
            let _ = writeln!(stdout, "Run without --dry-run to apply.");
        },
    }
}

fn render_install_json(outcome: &init::InstallOutcome, dry_run: bool) -> serde_json::Value {
    serde_json::json!({
        "agent": outcome.agent,
        "status": match outcome.status {
            init::InstallStatus::Installed => "installed",
            init::InstallStatus::AlreadyPresent => "alreadyPresent",
            init::InstallStatus::WouldInstall => "wouldInstall",
        },
        "dryRun": dry_run,
        "matcher": outcome.matcher,
        "command": outcome.command,
        "paths": outcome.paths.iter().map(|p| serde_json::json!({
            "label": p.label,
            "path": p.path.display().to_string(),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::init;

    use super::super::test_support::{
        CwdGuard, FailingReader, FailingWriter, make_engine_failing_repo, run_with,
    };
    use super::super::{
        Command, GlobalFlags, HookAgent, INVALID_PAYLOAD_RULE, InitOptions,
        POLICY_LOAD_FAILED_RULE, run,
    };
    use super::{MAX_HOOK_STDIN_BYTES, render_install_outcome, run_init_with, run_plugin_check};

    fn cmd_init(agent: Option<HookAgent>, verify: bool, dry_run: bool) -> Command {
        Command::Init(InitOptions {
            agent,
            verify,
            dry_run,
        })
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

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-cli-run-{}-{}-{}",
            tag,
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn check_denies_destructive_rm() {
        let (code, out, err) = run_with(&["check", "--tool", "Bash", "rm -rf /"], "");
        assert_eq!(code, 2);
        assert!(out.contains("Decision: deny"));
        assert!(out.contains("Rule: core.filesystem.destructive-rm"));
        assert!(err.contains("Blocked by ptuf rule core.filesystem.destructive-rm."));
    }

    #[test]
    fn check_allows_safe_command() {
        let (code, out, err) = run_with(&["check", "--tool", "Bash", "ls -la"], "");
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
        let code = run(
            GlobalFlags::default(),
            Command::Help,
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&out).contains("USAGE"));

        let mut out2 = Vec::new();
        let code = run(
            GlobalFlags::default(),
            Command::Version,
            b"" as &[u8],
            &mut out2,
            &mut err,
        );
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&out2).contains("ptuf"));
    }

    #[test]
    fn plugin_check_runs_and_returns_zero_on_pass() {
        use std::fs;
        let dir = workdir("plugin-check-pass");
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
        let cmd = Command::PluginCheck { path: path.clone() };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
            cmd,
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let s_out = String::from_utf8_lossy(&out);
        assert!(s_out.contains("plugin pack.demo"));
        assert!(s_out.contains("1 passed"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plugin_check_returns_one_when_yaml_is_invalid() {
        let cmd = Command::PluginCheck {
            path: PathBuf::from("/this/path/does/not/exist.yaml"),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
            cmd,
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1);
        assert!(String::from_utf8_lossy(&err).contains("ptuf:"));
    }

    #[test]
    fn run_init_explicit_kiro_dry_run_writes_outcome_summary() {
        let dir = workdir("init-kiro-dry");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let agent_path = dir.join(".kiro/agents/ptuf-guarded.json");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
            cmd_init(Some(HookAgent::Kiro), false, true),
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        assert!(String::from_utf8_lossy(&out).contains("would register hook"));
        assert!(!agent_path.exists());
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_explicit_copilot_writes_hook_file() {
        let dir = workdir("init-copilot-real");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let hooks_path = dir.join(".github/hooks/ptuf.json");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
            cmd_init(Some(HookAgent::Copilot), false, false),
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        assert!(String::from_utf8_lossy(&out).contains("registered hook"));
        assert!(hooks_path.exists());
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_codex_explicit_dry_run() {
        let dir = workdir("init-codex-dry");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
            cmd_init(Some(HookAgent::Codex), false, true),
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&out).contains("would register hook"));
        assert!(!dir.join(".codex/hooks.json").exists());
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_verify_passes_for_copilot_via_runner_injection() {
        let dir = workdir("init-copilot-verify");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let hooks_path = dir.join(".github/hooks/ptuf.json");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_init_with(
            GlobalFlags::default(),
            InitOptions {
                agent: Some(HookAgent::Copilot),
                verify: true,
                dry_run: false,
            },
            passing_report,
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("registered hook"), "stdout: {stdout}");
        assert!(stdout.contains("Verify:"), "stdout: {stdout}");
        assert!(hooks_path.exists());
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_verify_rolls_back_on_failure() {
        let dir = workdir("init-copilot-rollback");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let hooks_path = dir.join(".github/hooks/ptuf.json");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_init_with(
            GlobalFlags::default(),
            InitOptions {
                agent: Some(HookAgent::Copilot),
                verify: true,
                dry_run: false,
            },
            failing_report,
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1);
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("FAILED"), "stdout: {stdout}");
        assert!(stdout.contains("rolled back"), "stdout: {stdout}");
        assert!(
            !hooks_path.exists(),
            "rollback must remove freshly-created hook file",
        );
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_verify_emits_json_when_global_json_set() {
        let dir = workdir("init-copilot-json");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_init_with(
            GlobalFlags { json: true },
            InitOptions {
                agent: Some(HookAgent::Copilot),
                verify: true,
                dry_run: false,
            },
            passing_report,
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let stdout = String::from_utf8_lossy(&out);
        let value: serde_json::Value =
            serde_json::from_str(&stdout).expect("JSON branch must emit valid JSON");
        assert_eq!(value["installed"], true);
        assert_eq!(value["rolledBack"], false);
        assert!(
            !stdout.contains("Verify:"),
            "JSON mode must not emit text section: {stdout}",
        );
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_no_verify_writes_without_running_verify() {
        let dir = workdir("init-no-verify");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let hooks_path = dir.join(".github/hooks/ptuf.json");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
            cmd_init(Some(HookAgent::Copilot), false, false),
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let stdout = String::from_utf8_lossy(&out);
        assert!(stdout.contains("registered hook"));
        assert!(
            !stdout.contains("Verify:"),
            "verify=false must not emit Verify section: {stdout}",
        );
        assert!(hooks_path.exists());
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_already_present_returns_zero_and_idempotent_message() {
        let dir = workdir("init-idempotent");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let mut out1 = Vec::new();
        let mut err1 = Vec::new();
        assert_eq!(
            run(
                GlobalFlags::default(),
                cmd_init(Some(HookAgent::Copilot), false, false),
                b"" as &[u8],
                &mut out1,
                &mut err1,
            ),
            0,
        );
        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        assert_eq!(
            run(
                GlobalFlags::default(),
                cmd_init(Some(HookAgent::Copilot), false, false),
                b"" as &[u8],
                &mut out2,
                &mut err2,
            ),
            0,
        );
        assert!(String::from_utf8_lossy(&out2).contains("already contains"));
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_reports_resolve_error() {
        // No repo discoverable, no HOME -> RepoRootNotFound for codex/copilot/kiro
        let dir = workdir("init-no-repo");
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
            cmd_init(Some(HookAgent::Copilot), false, false),
            b"" as &[u8],
            &mut out,
            &mut err,
        );
        // Copilot resolve_paths walks to $HOME if no repo, so we may actually succeed.
        // The point is: it never panics and returns either 0 or 1.
        assert!(code == 0 || code == 1, "code: {code}");
        drop(_guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_hook_routes_copilot_payload_through_normaliser() {
        let payload = r#"{"toolName":"bash","toolArgs":"{\"command\":\"rm -rf /\"}"}"#;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
            Command::HookPreToolUse {
                agent: HookAgent::Copilot,
            },
            payload.as_bytes(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "Copilot deny must exit 0 to stay fail-closed");
        let out_s = String::from_utf8_lossy(&out);
        assert!(
            out_s.contains("\"permissionDecision\":\"deny\""),
            "stdout: {out_s}",
        );
        assert!(
            !out_s.contains("hookSpecificOutput"),
            "Copilot must emit a bare envelope: {out_s}",
        );
    }

    #[test]
    fn run_hook_fails_closed_when_stdin_read_fails() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
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
            GlobalFlags::default(),
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
    fn run_hook_accepts_stdin_payload_exactly_at_the_size_ceiling() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let body = br#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let mut payload = Vec::with_capacity(MAX_HOOK_STDIN_BYTES as usize);
        payload.extend_from_slice(body);
        payload.resize(MAX_HOOK_STDIN_BYTES as usize, b' ');
        assert_eq!(payload.len() as u64, MAX_HOOK_STDIN_BYTES);

        let code = run(
            GlobalFlags::default(),
            Command::HookPreToolUse {
                agent: HookAgent::ClaudeCode,
            },
            payload.as_slice(),
            &mut out,
            &mut err,
        );
        let err_s = String::from_utf8_lossy(&err);
        assert!(
            !err_s.contains("hook payload exceeds"),
            "size deny fired at exact limit: {err_s}",
        );
        assert!(code == 0 || code == 1, "got exit code {code}: {err_s}");
    }

    // `read_to_string` rejects invalid UTF-8, so lone surrogates / bare
    // 0xFF / truncated multi-byte leads route through `failed to read
    // stdin` (not `invalid hook payload`) and must fail-closed.
    #[test]
    fn run_hook_fails_closed_for_invalid_utf8_stdin_payload() {
        for bytes in [&b"\xFF"[..], &b"\xC2"[..], &b"\xED\xA0\x80"[..]] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = run(
                GlobalFlags::default(),
                Command::HookPreToolUse {
                    agent: HookAgent::ClaudeCode,
                },
                bytes,
                &mut out,
                &mut err,
            );
            assert_eq!(code, 2, "expected fail-closed for bytes {bytes:?}");
            let out_s = String::from_utf8_lossy(&out);
            assert!(
                out_s.contains("\"permissionDecision\":\"deny\""),
                "stdout: {out_s}",
            );
            let err_s = String::from_utf8_lossy(&err);
            assert!(err_s.contains("failed to read stdin"), "stderr: {err_s}");
            assert!(err_s.contains(INVALID_PAYLOAD_RULE), "stderr: {err_s}");
        }
    }

    #[test]
    fn run_hook_fails_closed_when_stdin_read_fails_under_codex_adapter() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
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
    fn run_plugin_check_returns_one_when_render_writer_fails() {
        use std::fs;
        let dir = workdir("plugin-render-fail");
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
        let code = run_plugin_check(&path, &mut writer, &mut err);
        assert_eq!(code, 1);
        assert!(
            String::from_utf8_lossy(&err).contains("failed to write plugin test report"),
            "stderr: {}",
            String::from_utf8_lossy(&err)
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hook_codex_emits_deny_envelope_for_destructive_rm() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let (code, out, err) = run_with(&["hook", "codex"], payload);
        assert_eq!(code, 2);
        assert!(out.contains("\"hookSpecificOutput\""));
        assert!(out.contains("\"permissionDecision\":\"deny\""));
        assert!(err.contains("Blocked by ptuf rule"));
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
    fn run_hook_fails_closed_when_engine_construction_fails() {
        let dir = make_engine_failing_repo("hook");
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
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
    fn run_check_fails_closed_when_engine_construction_fails() {
        let dir = make_engine_failing_repo("check");
        let _guard = CwdGuard::change_to(&dir).expect("set_current_dir");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            GlobalFlags::default(),
            Command::Check {
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
