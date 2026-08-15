//! Binary smoke tests for `ptuf audit`.
//!
//! Lives in a dedicated target (not `cli_smoke.rs`) so credential-path
//! fixtures in that file do not trip `core.secrets.sensitive-read`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ptuf"))
}

fn run_in(args: &[&str], cwd: &Path, home: Option<&Path>, stdin: &str) -> (i32, String, String) {
    let mut cmd = binary();
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(h) = home {
        cmd.env("HOME", h);
    }
    let mut child = cmd.spawn().expect("spawn ptuf");
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

fn audit_line(decision: &str, rule: &str) -> String {
    serde_json::json!({
        "schemaVersion": 1,
        "timestamp": "2026-08-15T09:12:03Z",
        "event": "PreToolUse",
        "tool": "Bash",
        "decision": decision,
        "ruleId": rule,
        "severity": "high",
        "commandRedacted": "ls",
        "mode": "enforce",
        "agent": "cli",
    })
    .to_string()
}

#[test]
fn audit_path_json_filters_decision() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let body = format!(
        "{}\n{}\n",
        audit_line("deny", "core.a"),
        audit_line("allow", "core.b")
    );
    std::fs::write(&path, body).expect("write jsonl");
    let path_s = path.to_string_lossy().into_owned();
    let (code, stdout, stderr) = run_in(
        &["--json", "audit", "--path", &path_s, "--decision", "deny"],
        dir.path(),
        Some(dir.path()),
        "",
    );
    assert_eq!(code, 0, "stderr={stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["matched"], 1);
    assert_eq!(value["returned"], 1);
    assert_eq!(value["records"][0]["decision"], "deny");
    assert!(!stderr.contains("scanned"));
}

#[test]
fn audit_missing_file_is_empty_success() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let missing = dir.path().join("no-such-audit.jsonl");
    let path_s = missing.to_string_lossy().into_owned();
    let (code, stdout, stderr) = run_in(
        &["audit", "--path", &path_s],
        dir.path(),
        Some(dir.path()),
        "",
    );
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.is_empty(), "stdout={stdout}");
    assert!(stderr.contains("0 matched, 0 returned"), "stderr={stderr}");
}

#[test]
fn audit_skips_broken_line() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let body = format!(
        "{}\nthis is not json\n{}\n",
        audit_line("deny", "core.a"),
        audit_line("ask", "core.b")
    );
    std::fs::write(&path, body).expect("write jsonl");
    let path_s = path.to_string_lossy().into_owned();
    let (code, stdout, stderr) = run_in(
        &["audit", "--path", &path_s, "--limit", "0"],
        dir.path(),
        Some(dir.path()),
        "",
    );
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.contains("core.a"), "stdout={stdout}");
    assert!(stdout.contains("core.b"), "stdout={stdout}");
    assert!(
        stderr.contains("2 valid") && stderr.contains("1 invalid"),
        "stderr={stderr}"
    );
}

#[test]
fn audit_default_path_under_home() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let home = dir.path().join("home");
    let cwd = dir.path().join("cwd");
    std::fs::create_dir_all(&home).expect("mkdir home");
    std::fs::create_dir_all(&cwd).expect("mkdir cwd");
    let audit_dir = home.join(".local/share/ptuf");
    std::fs::create_dir_all(&audit_dir).expect("mkdir audit dir");
    std::fs::write(
        audit_dir.join("audit.jsonl"),
        format!("{}\n", audit_line("deny", "core.home")),
    )
    .expect("write default audit");
    let (code, stdout, stderr) = run_in(&["audit"], &cwd, Some(&home), "");
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.contains("core.home"), "stdout={stdout}");
}

#[test]
fn audit_project_config_custom_path() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let repo = dir.path();
    std::fs::create_dir_all(repo.join(".git")).expect("mkdir .git");
    let custom = repo.join("custom-audit.jsonl");
    std::fs::write(
        &custom,
        format!("{}\n", audit_line("monitor", "core.custom")),
    )
    .expect("write custom audit");
    std::fs::write(
        repo.join(".ptuf.yaml"),
        format!("audit:\n  path: {}\n", custom.display()),
    )
    .expect("write yaml");
    let (code, stdout, stderr) = run_in(&["audit"], repo, Some(repo), "");
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.contains("core.custom"), "stdout={stdout}");
}

fn object_keys(value: &serde_json::Value) -> BTreeSet<String> {
    value.as_object().expect("object").keys().cloned().collect()
}

#[test]
fn audit_list_json_top_level_keys() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    std::fs::write(&path, format!("{}\n", audit_line("deny", "core.a"))).expect("write jsonl");
    let path_s = path.to_string_lossy().into_owned();
    let (code, stdout, stderr) = run_in(
        &["--json", "audit", "--path", &path_s],
        dir.path(),
        Some(dir.path()),
        "",
    );
    assert_eq!(code, 0, "stderr={stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("list json");
    let expected: BTreeSet<String> =
        serde_json::from_str(include_str!("contracts/audit-list-json-keys.json"))
            .expect("list key fixture");
    assert_eq!(object_keys(&value), expected);
}

#[test]
fn audit_stats_json_top_level_keys() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    std::fs::write(&path, format!("{}\n", audit_line("deny", "core.a"))).expect("write jsonl");
    let path_s = path.to_string_lossy().into_owned();
    let (code, stdout, stderr) = run_in(
        &["--json", "audit", "--path", &path_s, "--stats"],
        dir.path(),
        Some(dir.path()),
        "",
    );
    assert_eq!(code, 0, "stderr={stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("stats json");
    let expected: BTreeSet<String> =
        serde_json::from_str(include_str!("contracts/audit-stats-json-keys.json"))
            .expect("stats key fixture");
    assert_eq!(object_keys(&value), expected);
    assert!(value["byDecision"].is_array());
    assert!(value["byRule"].is_array());
}
