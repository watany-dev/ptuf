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
fn doctor_json_schema_contract_exposes_expected_top_level_keys() {
    let dir = repo();
    let (code, stdout, stderr) = run_in(dir.path(), &["doctor", "--json"], "");
    assert!(code == 0 || code == 1, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid doctor json");
    assert_eq!(value["schemaVersion"], 1);

    let expected: BTreeSet<String> =
        serde_json::from_str(include_str!("contracts/doctor-schema-keys.json"))
            .expect("doctor key fixture");
    let actual: BTreeSet<String> = value
        .as_object()
        .expect("doctor json object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(actual, expected);
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
        &["eval", "--tool", "Bash", "git reset --hard HEAD~3"],
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

    let (code, stdout, stderr) = run_in(dir.path(), &["eval", "--tool", "Bash", "ls"], "");
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

#[test]
fn init_verify_json_schema_contract_is_stable() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let settings = dir.path().join("settings.json");
    let settings_str = settings.to_string_lossy().into_owned();
    let (code, stdout, stderr) = run(
        &[
            "init",
            "claude-code",
            "--verify",
            "--json",
            "--settings",
            &settings_str,
        ],
        "",
    );
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
