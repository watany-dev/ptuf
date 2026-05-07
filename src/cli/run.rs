//! Subcommand dispatch — every `run_*` helper takes the I/O streams of
//! the parent `cli::run` and returns a u8 exit code.
//!
//! The hook entry must always fail-closed (exit 2) when initialisation
//! fails, so payload-read / JSON / engine-build errors all funnel
//! through [`invalid_payload_deny`] and `policy_load_failed_deny`.

use std::io::{Read, Write};

use crate::Decision;
use crate::hook_input::HookInput;
use crate::init;
use crate::plugin::runner as plugin_runner;
use crate::reason;

use super::output::{decision_exit_code, decision_label, emit_decision};
use super::{
    ClaudeInitOptions, CodexInitOptions, HookAgent, INVALID_PAYLOAD_RULE, InitOptions,
    build_engine_or_fail_closed,
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

pub(super) fn run_eval<W1: Write, W2: Write>(
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

pub(super) fn run_plugin_test<W1: Write, W2: Write>(
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

pub(super) fn run_init<W1: Write, W2: Write>(
    options: InitOptions,
    dry_run: bool,
    stdout: &mut W1,
    stderr: &mut W2,
) -> u8 {
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

pub(super) fn run_doctor<W1: Write, W2: Write>(json: bool, stdout: &mut W1, stderr: &mut W2) -> u8 {
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
    let resolved_path = match options.settings_path.as_deref() {
        Some(path) => path.to_path_buf(),
        None => init::claude_code::default_settings_path().ok_or(init::InitError::HomeNotSet)?,
    };
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::path::PathBuf;

    use crate::init;

    use super::super::test_support::{
        CwdGuard, FailingReader, FailingWriter, make_engine_failing_repo, run_with,
    };
    use super::super::{
        ClaudeInitOptions, CodexInitOptions, Command, HookAgent, INVALID_PAYLOAD_RULE, InitOptions,
        POLICY_LOAD_FAILED_RULE, run,
    };
    use super::{MAX_HOOK_STDIN_BYTES, render_install_outcome, run_doctor, run_plugin_test};

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
