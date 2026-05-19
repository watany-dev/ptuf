//! End-to-end integration coverage for *config-driven* behaviour.
//!
//! `cli_smoke.rs` and `contracts.rs` drive the binary and pin its
//! decision / JSON output; `filter_proptest.rs` proves the layered-
//! config composition laws at the library level. What was missing is a
//! layer that runs the **real `ptuf` binary** against a `.ptuf.yaml`
//! on disk and checks that each documented config knob actually
//! changes the observable decision or audit output:
//!
//! * `rules:` per-rule overrides (`enabled` / `decision` / `severity`)
//!   — including the rule that a `hardDeny` rule ignores a disable
//! * `packs:` toggles dropping a whole pack's rules
//! * allowlist `expiresAt` lifecycle (past / future / malformed)
//! * audit `redaction` (`strict` default vs `off`)
//! * audit `includeDenied` gating
//! * `mode: monitor` demotion surfacing in the audit record
//!
//! Each knob was previously exercised only by unit / property tests
//! that never crossed the CLI / config-file boundary.

// `clippy.toml`'s `allow-*-in-tests` only matches `#[test]` bodies and
// `#[cfg(test)]` modules — free helpers at integration-test file scope
// fall outside both, so relax `unwrap`/`expect` explicitly here.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use tempfile::TempDir;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ptuf"))
}

/// A throwaway repo root. The `.git` directory makes config-scope
/// discovery treat the tempdir as the project root so the `.ptuf.yaml`
/// written into it is picked up as the project layer.
fn repo() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir .git");
    dir
}

/// Run `ptuf` inside `cwd` with the system / user config layers pinned
/// to absent directories so only the project `.ptuf.yaml` under `cwd`
/// contributes. Keeps every case hermetic regardless of the developer's
/// real `/etc/ptuf` or `~/.config/ptuf`.
fn run_in(cwd: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let absent_etc = cwd.join(".absent-etc");
    let absent_cfg = cwd.join(".absent-config");
    let mut child = binary()
        .args(args)
        .current_dir(cwd)
        .env("PTUF_ETC_DIR", absent_etc.as_os_str())
        .env("PTUF_CONFIG_DIR", absent_cfg.as_os_str())
        .env("HOME", cwd.as_os_str())
        .env_remove("XDG_CONFIG_HOME")
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

/// Parse the first JSONL record written to `audit_path`.
fn read_one_audit_line(audit_path: &Path) -> serde_json::Value {
    let body = std::fs::read_to_string(audit_path).expect("read audit jsonl");
    let line = body.lines().next().expect("at least one audit line");
    serde_json::from_str(line).expect("audit line is valid json")
}

// ---------------------------------------------------------------
// `rules:` per-rule overrides through the binary.
// ---------------------------------------------------------------

#[test]
fn rule_override_enabled_false_disables_overridable_rule() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "rules:\n  core.git.reset-hard:\n    enabled: false\n",
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(
        dir.path(),
        &["check", "--tool", "Bash", "git reset --hard HEAD~3"],
        "",
    );
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("Decision: allow"),
        "disabling core.git.reset-hard must drop it to allow; stdout: {stdout}",
    );
}

#[test]
fn rule_override_decision_field_promotes_ask_to_deny() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "rules:\n  core.git.reset-hard:\n    decision: deny\n",
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(
        dir.path(),
        &["check", "--tool", "Bash", "git reset --hard HEAD~3"],
        "",
    );
    assert_eq!(
        code, 2,
        "a `decision: deny` override must block; stdout: {stdout} stderr: {stderr}",
    );
    assert!(stdout.contains("Decision: deny"), "stdout: {stdout}");
    assert!(
        stdout.contains("core.git.reset-hard"),
        "the deny must still be attributed to the overridden rule; stdout: {stdout}",
    );
}

#[test]
fn rule_override_cannot_disable_hard_deny_rule() {
    let dir = repo();
    // core.filesystem.destructive-rm is hardDeny: a config `enabled:
    // false` must be ignored so the rule still fires.
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "rules:\n  core.filesystem.destructive-rm:\n    enabled: false\n",
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(dir.path(), &["check", "--tool", "Bash", "rm -rf /"], "");
    assert_eq!(
        code, 2,
        "a hardDeny rule must survive a disable override; stdout: {stdout} stderr: {stderr}",
    );
    assert!(stdout.contains("Decision: deny"), "stdout: {stdout}");
    assert!(
        stdout.contains("core.filesystem.destructive-rm"),
        "stdout: {stdout}",
    );
}

#[test]
fn rule_override_severity_is_reflected_in_audit() {
    let dir = repo();
    let audit_path = dir.path().join("audit.jsonl");
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        format!(
            "audit:\n  path: {}\nrules:\n  core.git.reset-hard:\n    severity: low\n",
            audit_path.display(),
        ),
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(
        dir.path(),
        &["check", "--tool", "Bash", "git reset --hard HEAD~3"],
        "",
    );
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(stdout.contains("Decision: ask"), "stdout: {stdout}");

    let record = read_one_audit_line(&audit_path);
    assert_eq!(record["decision"], "ask");
    assert_eq!(record["ruleId"], "core.git.reset-hard");
    assert_eq!(
        record["severity"], "low",
        "the severity override must reach the audit record: {record}",
    );
}

// ---------------------------------------------------------------
// `packs:` toggles through the binary.
// ---------------------------------------------------------------

#[test]
fn disabling_a_pack_drops_its_rules() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        "packs:\n  core.git:\n    enabled: false\n",
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(
        dir.path(),
        &["check", "--tool", "Bash", "git reset --hard HEAD~3"],
        "",
    );
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("Decision: allow"),
        "disabling core.git must drop core.git.reset-hard; stdout: {stdout}",
    );
}

// ---------------------------------------------------------------
// Allowlist `expiresAt` lifecycle through the binary.
//
// `core.git.reset-hard` is an Ask rule; a covering allowlist entry
// suppresses it to Allow only while the entry is still live.
// ---------------------------------------------------------------

/// Project YAML with one allowlist entry covering `core.git.reset-hard`
/// for any `git` invocation, expiring at `expires_at`. The timestamp is
/// quoted so YAML keeps it a string (an unquoted RFC3339 value would
/// deserialize as a YAML timestamp type).
fn allowlist_yaml(expires_at: &str) -> String {
    format!(
        "allowlists:\n  - id: approved-reset\n    appliesTo:\n      rules: [core.git.reset-hard]\n    \
         when:\n      shell.argv:\n        headAny: [git]\n    expiresAt: \"{expires_at}\"\n",
    )
}

#[test]
fn expired_allowlist_no_longer_suppresses() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        allowlist_yaml("2000-01-01T00:00:00Z"),
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
        "an expired allowlist must not suppress the rule; stdout: {stdout}",
    );
}

#[test]
fn future_dated_allowlist_still_suppresses() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        allowlist_yaml("2099-01-01T00:00:00Z"),
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(
        dir.path(),
        &["check", "--tool", "Bash", "git reset --hard HEAD~3"],
        "",
    );
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    assert!(
        stdout.contains("Decision: allow"),
        "a future-dated allowlist must still suppress the rule; stdout: {stdout}",
    );
}

#[test]
fn malformed_expiry_is_treated_as_expired() {
    let dir = repo();
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        allowlist_yaml("not-a-timestamp"),
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
        "a malformed expiresAt must fail closed (treated as expired); stdout: {stdout}",
    );
}

// ---------------------------------------------------------------
// Audit `redaction` modes through the binary.
// ---------------------------------------------------------------

/// A denied command whose argument string also carries a secret-shaped
/// token, so the audit `commandRedacted` field is observable.
const COMMAND_WITH_SECRET: &str = "rm -rf / ; echo ghp_ABCDEFGHIJ0123456789";

#[test]
fn audit_redacts_secret_in_command_by_default() {
    let dir = repo();
    let audit_path = dir.path().join("audit.jsonl");
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        format!("audit:\n  path: {}\n", audit_path.display()),
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(
        dir.path(),
        &["check", "--tool", "Bash", COMMAND_WITH_SECRET],
        "",
    );
    assert_eq!(code, 2, "stdout: {stdout} stderr: {stderr}");

    let record = read_one_audit_line(&audit_path);
    let redacted = record["commandRedacted"]
        .as_str()
        .expect("commandRedacted string");
    assert!(
        !redacted.contains("ghp_ABCDEFGHIJ0123456789"),
        "strict redaction (the default) must scrub the token: {redacted}",
    );
    assert!(
        redacted.contains("***"),
        "the redacted command must carry the placeholder: {redacted}",
    );
    assert!(
        redacted.contains("rm -rf"),
        "redaction must be targeted, not a blanket replacement: {redacted}",
    );
}

#[test]
fn audit_redaction_off_preserves_raw_secret() {
    let dir = repo();
    let audit_path = dir.path().join("audit.jsonl");
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        format!(
            "audit:\n  path: {}\n  redaction: \"off\"\n",
            audit_path.display(),
        ),
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(
        dir.path(),
        &["check", "--tool", "Bash", COMMAND_WITH_SECRET],
        "",
    );
    assert_eq!(code, 2, "stdout: {stdout} stderr: {stderr}");

    let record = read_one_audit_line(&audit_path);
    let recorded = record["commandRedacted"]
        .as_str()
        .expect("commandRedacted string");
    assert!(
        recorded.contains("ghp_ABCDEFGHIJ0123456789"),
        "redaction: off must keep the raw command verbatim: {recorded}",
    );
}

// ---------------------------------------------------------------
// Audit `includeDenied` gating through the binary.
// ---------------------------------------------------------------

#[test]
fn audit_include_denied_false_suppresses_deny_record() {
    let dir = repo();
    let audit_path = dir.path().join("audit.jsonl");
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        format!(
            "audit:\n  path: {}\n  includeDenied: false\n",
            audit_path.display(),
        ),
    )
    .expect("write yaml");

    let (code, stdout, stderr) = run_in(dir.path(), &["check", "--tool", "Bash", "rm -rf /"], "");
    assert_eq!(
        code, 2,
        "the decision itself is unchanged by audit gating; stdout: {stdout} stderr: {stderr}",
    );

    // The sink drops the record before any file is created, so the
    // path may simply not exist — treat that as an empty log.
    let recorded = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(
        !recorded.contains("\"decision\":\"deny\""),
        "includeDenied: false must keep deny records out of the audit log: {recorded}",
    );
}

// ---------------------------------------------------------------
// `mode: monitor` demotion surfacing in the audit record.
// ---------------------------------------------------------------

#[test]
fn monitor_mode_demotes_deny_and_audit_records_mode_demoted() {
    let dir = repo();
    let audit_path = dir.path().join("audit.jsonl");
    std::fs::write(
        dir.path().join(".ptuf.yaml"),
        format!("mode: monitor\naudit:\n  path: {}\n", audit_path.display()),
    )
    .expect("write yaml");

    let payload = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let (code, stdout, stderr) = run_in(dir.path(), &["hook", "claude-code"], payload);
    assert_eq!(
        code, 0,
        "monitor mode must demote the hard deny to exit 0; stderr: {stderr}",
    );
    assert!(
        stdout.is_empty(),
        "a demoted Monitor decision produces no claude-code hook envelope: {stdout}",
    );

    let record = read_one_audit_line(&audit_path);
    assert_eq!(record["decision"], "monitor");
    assert_eq!(record["mode"], "monitor");
    assert_eq!(record["agent"], "claude-code");
    assert_eq!(record["ruleId"], "core.filesystem.destructive-rm");
    assert_eq!(
        record["modeDemoted"], true,
        "the audit record must flag the deny->monitor demotion: {record}",
    );
}
