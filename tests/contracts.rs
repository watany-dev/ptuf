// `clippy.toml`'s `allow-*-in-tests` only matches `#[test]` bodies and
// `#[cfg(test)]` modules — free helpers at integration-test file scope
// fall outside both, so relax `unwrap`/`expect` explicitly here.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ptuf"))
}

fn run(args: &[&str], stdin: &str) -> (i32, String, String) {
    run_in(Path::new("."), args, stdin)
}

fn run_in(cwd: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut child = binary()
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ptuf");
    {
        let mut sin = child.stdin.take().expect("stdin");
        sin.write_all(stdin.as_bytes()).expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait");
    (
        output.status.code().expect("exit code"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn repo() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir .git");
    dir
}

#[test]
fn hook_deny_json_contract_is_stable() {
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let (code, stdout, stderr) = run(&["hook", "claude-code"], payload);
    assert_eq!(code, 2);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        value["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|s| s.contains("core.filesystem.destructive-rm"))
    );
    assert!(stderr.contains("core.filesystem.destructive-rm"));
}

#[test]
fn audit_contract_includes_allowlist_id_for_suppressed_rule() {
    let dir = repo();
    let audit_path = dir.path().join("audit.jsonl");
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        format!(
            "audit:\n  path: {}\n  includeAllowed: true\nallowlists:\n  - id: approved-reset\n    appliesTo:\n      rules: [core.git.reset-hard]\n    when:\n      shell.argv:\n        headAny: [git]\n",
            audit_path.display()
        ),
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(
        dir.path(),
        &["check", "--tool", "Bash", "git reset --hard HEAD~3"],
        "",
    );
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(stdout.contains("Decision: allow"), "stdout: {stdout}");

    let body = std::fs::read_to_string(&audit_path).expect("read audit");
    let line = body.lines().next().expect("audit line");
    let value: serde_json::Value = serde_json::from_str(line).expect("audit json");
    let expected: BTreeSet<String> =
        serde_json::from_str(include_str!("contracts/audit-schema-keys.json"))
            .expect("audit key fixture");
    let actual: BTreeSet<String> = value
        .as_object()
        .expect("audit object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(value["decision"], "allow");
    assert_eq!(value["allowlistId"], "approved-reset");
    assert_eq!(value["agent"], "cli");
    assert_eq!(value["schemaVersion"], 1);
}

#[test]
fn hook_invalid_stdin_payload_fails_closed() {
    let dir = repo();
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "claude-code"], "not json");
    assert_eq!(code, 2, "stdout: {stdout} stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        value["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason string")
            .contains("core.engine.invalid-payload"),
        "stdout: {stdout}"
    );
    assert!(stderr.contains("invalid hook payload"), "stderr: {stderr}");
}

#[test]
fn hook_oversized_stdin_payload_fails_closed() {
    let dir = repo();
    let payload = "A".repeat(8 * 1024 * 1024 + 1);
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "claude-code"], &payload);
    assert_eq!(code, 2, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        value["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason string")
            .contains("core.engine.invalid-payload"),
        "stdout: {stdout}"
    );
    assert!(stderr.contains("hook payload exceeds"), "stderr: {stderr}");
}

#[test]
fn hook_invalid_stdin_payload_fails_closed_under_codex_adapter() {
    let dir = repo();
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "codex"], "{not valid");
    assert_eq!(code, 2, "stdout: {stdout} stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        value["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason string")
            .contains("core.engine.invalid-payload"),
        "stdout: {stdout}"
    );
}

#[test]
fn plugin_loader_error_contract_fails_closed() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "plugins:\n  - path: ./missing-plugin.yaml\n",
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(dir.path(), &["check", "--tool", "Bash", "ls"], "");
    assert_eq!(code, 2, "stdout: {stdout} stderr: {stderr}");
    assert!(stdout.contains("Decision: deny"), "stdout: {stdout}");
    assert!(stdout.contains("core.engine.policy-load-failed"));
    assert!(stderr.contains("could not load policy"), "stderr: {stderr}");
}

#[test]
fn nested_mcp_paths_contract_hits_self_protection() {
    let dir = repo();
    let payload = r#"{"tool_name":"mcp__github__push_files","tool_input":{"files":[{"path":".claude/settings.json","content":"{}"}]}}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "claude-code"], payload);
    assert_eq!(code, 2, "stdout: {stdout} stderr: {stderr}");
    assert!(stderr.contains("core.self_protection.claude-settings"));
}

#[test]
fn hook_script_contract_blocks_repo_local_hook_edits() {
    let dir = repo();
    std::fs::create_dir_all(dir.path().join(".claude")).expect("mkdir .claude");
    std::fs::create_dir_all(dir.path().join("hooks")).expect("mkdir hooks");
    std::fs::write(
        dir.path().join(".claude/settings.json"),
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "./hooks/guard.sh hook claude-code" }
        ]
      }
    ]
  }
}"#,
    )
    .expect("write settings");
    std::fs::write(dir.path().join("hooks/guard.sh"), "#!/bin/sh\n").expect("write hook");

    let payload = r#"{"tool_name":"Write","tool_input":{"file_path":"./hooks/guard.sh","content":"echo changed"}}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "claude-code"], payload);
    assert_eq!(code, 2, "stdout: {stdout} stderr: {stderr}");
    assert!(stderr.contains("core.self_protection.hook-script"));
}

// ---------------------------------------------------------------
// GitHub Copilot adapter contracts.
//
// Copilot's `preToolUse` hook treats a non-zero exit as a hook
// failure and may skip the response entirely, which would make a
// deny fail open. The CLI therefore expresses fail-closed via the
// stdout JSON (`permissionDecision: "deny"`) and keeps the exit
// code at 0 for *every* Decision under the Copilot adapter —
// initialisation failures (invalid payload / policy load failure)
// included.
// ---------------------------------------------------------------

#[test]
fn copilot_camel_bash_command_denies_rm_rf_root() {
    let payload = r#"{"toolName":"bash","toolArgs":"{\"command\":\"rm -rf /\"}"}"#;
    let (code, stdout, stderr) = run(&["hook", "copilot"], payload);
    assert_eq!(code, 0, "Copilot must return exit 0 even for deny");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert!(
        value.get("hookSpecificOutput").is_none(),
        "Copilot must emit a bare envelope: {stdout}"
    );
    assert_eq!(value["permissionDecision"], "deny");
    assert!(
        value["permissionDecisionReason"]
            .as_str()
            .is_some_and(|s| s.contains("core.filesystem.destructive-rm")),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("core.filesystem.destructive-rm"));
}

#[test]
fn copilot_invalid_payload_outputs_deny_and_exit_zero() {
    let dir = repo();
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "copilot"], "not json");
    assert_eq!(code, 0, "Copilot fail-closed must keep exit 0");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert!(value.get("hookSpecificOutput").is_none());
    assert_eq!(value["permissionDecision"], "deny");
    assert!(
        value["permissionDecisionReason"]
            .as_str()
            .expect("reason string")
            .contains("core.engine.invalid-payload"),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("invalid hook payload"), "stderr: {stderr}");
}

#[test]
fn copilot_policy_load_failure_outputs_deny_and_exit_zero() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "plugins:\n  - path: ./missing-plugin.yaml\n",
    )
    .expect("write yaml");
    let payload = r#"{"toolName":"bash","toolArgs":{"command":"ls"}}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "copilot"], payload);
    assert_eq!(code, 0, "Copilot policy-load failure must keep exit 0");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert!(value.get("hookSpecificOutput").is_none());
    assert_eq!(value["permissionDecision"], "deny");
    assert!(
        value["permissionDecisionReason"]
            .as_str()
            .expect("reason string")
            .contains("core.engine.policy-load-failed"),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("could not load policy"), "stderr: {stderr}");
}

#[test]
fn copilot_ask_demotes_to_deny() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "plugins:\n  - path: ./ask-plugin.yaml\n",
    )
    .expect("write yaml");
    std::fs::write(
        dir.path().join("ask-plugin.yaml"),
        "apiVersion: ptuf.dev/v1\nkind: Plugin\nmetadata:\n  name: pack.ask\nrules:\n  - id: pack.ask.confirm-curl\n    severity: medium\n    defaultDecision: ask\n    when:\n      shell.argv:\n        headAny: [curl]\n    reason: please confirm\n",
    )
    .expect("write plugin");

    let payload = r#"{"toolName":"bash","toolArgs":{"command":"curl https://example.com"}}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "copilot"], payload);
    assert_eq!(code, 0, "Copilot Ask demote must keep exit 0");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert!(value.get("hookSpecificOutput").is_none());
    assert_eq!(
        value["permissionDecision"], "deny",
        "Ask must demote to deny under Copilot"
    );
    let reason = value["permissionDecisionReason"]
        .as_str()
        .expect("reason string");
    assert!(reason.contains("please confirm"), "stdout: {stdout}");
    assert!(
        reason.contains("GitHub Copilot hooks do not reliably process interactive ask"),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("please confirm"), "stderr: {stderr}");
}

#[test]
fn copilot_allow_outputs_empty_stdout_and_exit_zero() {
    let dir = repo();
    let payload = r#"{"toolName":"bash","toolArgs":{"command":"ls"}}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "copilot"], payload);
    assert_eq!(code, 0);
    assert!(
        stdout.is_empty(),
        "Allow must produce no Copilot envelope: {stdout}",
    );
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn copilot_snake_case_payload_is_accepted() {
    let dir = repo();
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let (code, stdout, _stderr) = run_in(dir.path(), &["hook", "copilot"], payload);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["permissionDecision"], "deny");
}

#[test]
fn copilot_view_maps_to_read_path() {
    let dir = repo();
    let payload = r#"{"toolName":"view","toolArgs":{"filePath":"~/.ssh/id_rsa"}}"#;
    let (code, stdout, _stderr) = run_in(dir.path(), &["hook", "copilot"], payload);
    assert_eq!(code, 0, "Copilot deny still exits 0");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["permissionDecision"], "deny");
    assert!(
        value["permissionDecisionReason"]
            .as_str()
            .is_some_and(|s| s.contains("core.secrets.sensitive-read")),
        "stdout: {stdout}",
    );
}

#[test]
fn copilot_create_maps_to_write_content() {
    let dir = repo();
    let payload =
        r#"{"toolName":"create","toolArgs":{"path":"./.claude/settings.json","content":"{}"}}"#;
    let (code, stdout, _stderr) = run_in(dir.path(), &["hook", "copilot"], payload);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["permissionDecision"], "deny");
    // create→Write must reach self_protection — confirms the file_path
    // shape was preserved through the camel→snake reshape.
    assert!(
        value["permissionDecisionReason"]
            .as_str()
            .is_some_and(|s| s.contains("core.self_protection.")),
        "stdout: {stdout}",
    );
}

#[test]
fn copilot_unknown_tool_never_panics() {
    let dir = repo();
    let payload = r#"{"toolName":"some-future-tool","toolArgs":{"goal":"x"}}"#;
    let (code, _stdout, _stderr) = run_in(dir.path(), &["hook", "copilot"], payload);
    // Unknown tools should pass through to engine (likely Allow,
    // exit 0, empty stdout). The contract here is only that the CLI
    // does not crash and stays at exit 0 under Copilot.
    assert_eq!(code, 0);
}

// ---------------------------------------------------------------
// Cline adapter contracts.
//
// Cline's `PreToolUse` file hook is fail-open on process failures in
// some paths, so the CLI expresses every Decision via stdout JSON and
// fixes the exit code at 0. A block is `{"cancel":true,...}`; Allow /
// Monitor is the bare `{}` object. The renderer never emits
// `shouldContinue` (which would let the call proceed).
// ---------------------------------------------------------------

#[test]
fn cline_deny_outputs_cancel_json_and_exit_zero() {
    let payload = r#"{"hookName":"tool_call","tool_call":{"id":"c1","name":"run_commands","input":{"command":"rm -rf /"}}}"#;
    let (code, stdout, stderr) = run(&["hook", "cline"], payload);
    assert_eq!(code, 0, "Cline must return exit 0 even for deny");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["cancel"], true);
    assert!(value.get("shouldContinue").is_none(), "stdout: {stdout}");
    assert!(
        value.get("hookSpecificOutput").is_none(),
        "stdout: {stdout}"
    );
    assert!(
        value["errorMessage"]
            .as_str()
            .is_some_and(|s| s.contains("core.filesystem.destructive-rm")),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("core.filesystem.destructive-rm"));
}

#[test]
fn cline_allow_outputs_empty_object_and_exit_zero() {
    let payload = r#"{"hookName":"tool_call","tool_call":{"id":"c1","name":"run_commands","input":{"command":"ls"}}}"#;
    let (code, stdout, stderr) = run(&["hook", "cline"], payload);
    assert_eq!(code, 0);
    assert_eq!(stdout, "{}\n", "Allow must produce the bare {{}} object");
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn cline_invalid_payload_outputs_cancel_json_and_exit_zero() {
    let dir = repo();
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "cline"], "not json");
    assert_eq!(code, 0, "Cline fail-closed must keep exit 0");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["cancel"], true);
    assert!(value.get("shouldContinue").is_none());
    assert!(
        value["errorMessage"]
            .as_str()
            .expect("reason string")
            .contains("core.engine.invalid-payload"),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("invalid hook payload"), "stderr: {stderr}");
}

#[test]
fn cline_ask_demotes_to_cancel_with_note() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "plugins:\n  - path: ./ask-plugin.yaml\n",
    )
    .expect("write yaml");
    std::fs::write(
        dir.path().join("ask-plugin.yaml"),
        "apiVersion: ptuf.dev/v1\nkind: Plugin\nmetadata:\n  name: pack.ask\nrules:\n  - id: pack.ask.confirm-curl\n    severity: medium\n    defaultDecision: ask\n    when:\n      shell.argv:\n        headAny: [curl]\n    reason: please confirm\n",
    )
    .expect("write plugin");

    let payload = r#"{"hookName":"tool_call","tool_call":{"id":"c1","name":"run_commands","input":{"command":"curl https://example.com"}}}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "cline"], payload);
    assert_eq!(code, 0, "Cline Ask demote must keep exit 0");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(
        value["cancel"], true,
        "Ask must demote to cancel under Cline"
    );
    let reason = value["errorMessage"].as_str().expect("reason string");
    assert!(reason.contains("please confirm"), "stdout: {stdout}");
    assert!(
        reason.contains("Cline PreToolUse file hooks"),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("please confirm"), "stderr: {stderr}");
}

#[test]
fn cursor_deny_outputs_bare_permission_envelope_and_exit_two() {
    let payload = r#"{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"rm -rf /"},"cwd":"/tmp"}"#;
    let (code, stdout, stderr) = run(&["hook", "cursor"], payload);
    assert_eq!(code, 2, "Cursor deny must exit 2");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["permission"], "deny");
    assert!(
        value.get("hookSpecificOutput").is_none(),
        "Cursor uses a bare envelope: {stdout}",
    );
    assert!(
        value["agent_message"]
            .as_str()
            .is_some_and(|s| s.contains("core.filesystem.destructive-rm")),
        "stdout: {stdout}",
    );
    assert!(
        value["user_message"]
            .as_str()
            .is_some_and(|s| s.contains("core.filesystem.destructive-rm")),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("core.filesystem.destructive-rm"));
}

#[test]
fn cursor_ask_is_preserved_not_demoted_and_exit_zero() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "plugins:\n  - path: ./ask-plugin.yaml\n",
    )
    .expect("write yaml");
    std::fs::write(
        dir.path().join("ask-plugin.yaml"),
        "apiVersion: ptuf.dev/v1\nkind: Plugin\nmetadata:\n  name: pack.ask\nrules:\n  - id: pack.ask.confirm-curl\n    severity: medium\n    defaultDecision: ask\n    when:\n      shell.argv:\n        headAny: [curl]\n    reason: please confirm\n",
    )
    .expect("write plugin");

    let payload = r#"{"hook_event_name":"beforeShellExecution","command":"curl https://example.com","cwd":"/tmp"}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "cursor"], payload);
    assert_eq!(code, 0, "Cursor keeps Ask at exit 0");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(
        value["permission"], "ask",
        "Cursor must preserve Ask, never demote to deny: {stdout}",
    );
    let reason = value["agent_message"].as_str().expect("reason string");
    assert!(reason.contains("please confirm"), "stdout: {stdout}");
    assert!(
        !reason.contains("demote") && !reason.contains("Cline"),
        "Cursor reason must be verbatim, no demotion note: {stdout}",
    );
    assert!(stderr.contains("please confirm"), "stderr: {stderr}");
}

#[test]
fn cursor_allow_outputs_explicit_allow_and_exit_zero() {
    let payload = r#"{"hook_event_name":"beforeShellExecution","command":"ls","cwd":"/tmp"}"#;
    let (code, stdout, stderr) = run(&["hook", "cursor"], payload);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(
        value["permission"], "allow",
        "Cursor failClosed hooks require an explicit allow response: {stdout}"
    );
    assert!(value.get("user_message").is_none(), "stdout: {stdout}");
    assert!(value.get("agent_message").is_none(), "stdout: {stdout}");
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn cursor_invalid_payload_fails_closed_with_permission_deny_exit_two() {
    let dir = repo();
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "cursor"], "not json");
    assert_eq!(code, 2, "Cursor fail-closed exits 2");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["permission"], "deny");
    assert!(
        value["agent_message"]
            .as_str()
            .is_some_and(|s| s.contains("core.engine.invalid-payload")),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("invalid hook payload"), "stderr: {stderr}");
}

#[test]
fn cursor_unsupported_event_fails_closed() {
    // postToolUse is observe-only territory in the spec; MVP rejects it as a
    // fail-closed deny rather than silently allowing it through.
    let payload =
        r#"{"hook_event_name":"postToolUse","tool_name":"Shell","tool_input":{"command":"ls"}}"#;
    let (code, stdout, stderr) = run(&["hook", "cursor"], payload);
    assert_eq!(code, 2, "unsupported event fails closed: {stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["permission"], "deny");
    assert!(
        value["agent_message"]
            .as_str()
            .is_some_and(|s| s.contains("core.engine.invalid-payload")),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("invalid hook payload"), "stderr: {stderr}");
}

#[test]
fn cursor_mcp_execution_normalises_to_mcp_tool() {
    // beforeMCPExecution must reach the engine as mcp__<server>__<tool>. We
    // assert it does not crash and produces a well-formed envelope; a safe
    // tool yields explicit Allow (exit 0).
    let payload = r#"{"hook_event_name":"beforeMCPExecution","metadata":{"server":"github","tool_name":"get_me"}}"#;
    let (code, stdout, stderr) = run(&["hook", "cursor"], payload);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["permission"], "allow", "stdout: {stdout}");
}

#[test]
fn workspace_outside_access_denies_read_outside_repo_when_pack_enabled() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "packs:\n  core.workspace:\n    enabled: true\n",
    )
    .expect("write yaml");
    let payload = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/hostname"}}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "claude-code"], payload);
    assert_eq!(code, 2, "stdout: {stdout} stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        value["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|s| s.contains("core.workspace.outside-access"))
    );
}

#[test]
fn workspace_outside_access_skips_when_pack_disabled() {
    let dir = repo();
    // Default config has core.workspace disabled; reading outside the
    // repo must surface as Allow (no other rule fires for /etc/hostname).
    let payload = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/hostname"}}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "claude-code"], payload);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
}

#[test]
fn workspace_outside_access_allows_inside_repo_when_pack_enabled() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "packs:\n  core.workspace:\n    enabled: true\n",
    )
    .expect("write yaml");
    let inside = dir.path().join("src/main.rs");
    let payload = format!(
        r#"{{"tool_name":"Read","tool_input":{{"file_path":"{}"}}}}"#,
        inside.display(),
    );
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "claude-code"], &payload);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
}

#[test]
fn workspace_outside_access_honours_additional_workspaces() {
    let dir = repo();
    let extra = tempfile::TempDir::new().expect("extra tempdir");
    let extra_path = extra.path().to_str().expect("utf-8");
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        format!(
            "packs:\n  core.workspace:\n    enabled: true\n    additionalWorkspaces:\n      - {extra_path}\n",
        ),
    )
    .expect("write yaml");
    let inside_extra = extra.path().join("notes.md");
    let payload = format!(
        r#"{{"tool_name":"Write","tool_input":{{"file_path":"{}","content":"x"}}}}"#,
        inside_extra.display(),
    );
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "claude-code"], &payload);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
}

#[test]
fn init_verify_json_schema_contract_is_stable() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let home = dir.path();
    std::fs::create_dir_all(home.join(".claude")).expect("mkdir .claude");
    let mut child = binary()
        .args(["--json", "init", "claude-code"])
        .current_dir(home)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ptuf");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait");
    let code = output.status.code().expect("exit");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");

    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid init verify json");
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["agent"], "claude-code");
    assert_eq!(value["installed"], true);
    assert_eq!(value["alreadyPresent"], false);
    assert_eq!(value["rolledBack"], false);
    assert_eq!(value["verify"]["syntheticDeny"]["status"], "passed");
    assert_eq!(
        value["verify"]["syntheticDeny"]["ruleId"],
        "core.filesystem.destructive-rm"
    );
    assert_eq!(value["verify"]["failClosed"]["status"], "passed");
    assert_eq!(
        value["verify"]["failClosed"]["ruleId"],
        "core.engine.policy-load-failed"
    );

    let expected: BTreeSet<String> =
        serde_json::from_str(include_str!("contracts/init-verify-schema-keys.json"))
            .expect("init verify key fixture");
    let actual: BTreeSet<String> = value
        .as_object()
        .expect("init verify json object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(actual, expected);
}

// ---------------------------------------------------------------
// OpenAI Codex adapter contracts (mirror Copilot / Cursor density).
// ---------------------------------------------------------------

#[test]
fn codex_deny_outputs_permission_deny_exit_two() {
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let (code, stdout, stderr) = run(&["hook", "codex"], payload);
    assert_eq!(code, 2, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        value["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|s| s.contains("core.filesystem.destructive-rm")),
        "stdout: {stdout}",
    );
}

#[test]
fn codex_allow_outputs_empty_stdout_exit_zero() {
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let (code, stdout, stderr) = run(&["hook", "codex"], payload);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.is_empty(), "allow must emit no stdout: {stdout}");
}

#[test]
fn codex_ask_demotes_to_deny() {
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~3"}}"#;
    let (code, stdout, stderr) = run(&["hook", "codex"], payload);
    assert_eq!(code, 2, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        stdout.contains("Codex PreToolUse cannot prompt interactively"),
        "stdout: {stdout}",
    );
}

#[test]
fn codex_policy_load_failure_fails_closed() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "plugins:\n  - path: ./missing-plugin.yaml\n",
    )
    .expect("write yaml");
    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "codex"], payload);
    assert_eq!(code, 2, "stdout: {stdout} stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        value["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|s| s.contains("core.engine.policy-load-failed")),
        "stdout: {stdout}",
    );
    assert!(stderr.contains("could not load policy"), "stderr: {stderr}");
}

#[test]
fn codex_oversized_stdin_fails_closed() {
    let dir = repo();
    let payload = "A".repeat(8 * 1024 * 1024 + 1);
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "codex"], &payload);
    assert_eq!(code, 2, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid hook json");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        value["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|s| s.contains("core.engine.invalid-payload")),
        "stdout: {stdout}",
    );
}

#[test]
fn allowlist_when_git_head_mismatch_not_suppressed() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "allowlists:\n  - id: wrong-head\n    appliesTo:\n      rules: [core.git.reset-hard]\n    when:\n      shell.argv:\n        headAny: [wget]\n",
    )
    .expect("write yaml");
    let (code, stdout, stderr) = run_in(
        dir.path(),
        &["check", "--tool", "Bash", "git reset --hard HEAD~3"],
        "",
    );
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("Decision: ask"),
        "wget-only when must not suppress git reset: {stdout}",
    );
}
