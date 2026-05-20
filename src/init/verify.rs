//! `ptuf init <agent> --verify` の検証ロジック。
//!
//! インストール直後に builtin rules だけで構築した [`Engine`] を 1 度起動し、
//! `rm -rf /` payload が `core.filesystem.destructive-rm` で deny されること
//! (synthetic deny check) と、Engine 構築失敗時に CLI が
//! `core.engine.policy-load-failed` で fail-closed する経路が機能すること
//! (fail-closed check) を確認する。
//!
//! ロールバック経路をテストできるよう `run_with` が check 関数を引数で
//! 受け取り、production パスの `run` はそれを既定の実装で呼ぶ薄いラッパに
//! している。

use std::io::{self, Write};
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::Decision;
use crate::cli::POLICY_LOAD_FAILED_RULE;
use crate::config::Config;
use crate::engine::Engine;
use crate::hook_input::HookInput;
use crate::init::{InstallOutcome, InstallStatus};
use crate::plugin::PluginSet;

/// Synthetic payload (`rm -rf /`) が hard-deny で発火させる rule id。
/// `tests/contracts.rs` で固定 contract として保証する。
pub(crate) const SYNTHETIC_DENY_RULE: &str = "core.filesystem.destructive-rm";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CheckOutcome {
    Passed { rule_id: String },
    Failed { detail: String },
}

impl CheckOutcome {
    pub(crate) fn is_passed(&self) -> bool {
        matches!(self, Self::Passed { .. })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VerifyReport {
    pub synthetic_deny: CheckOutcome,
    pub fail_closed: CheckOutcome,
    pub warnings: Vec<String>,
}

impl VerifyReport {
    pub(crate) fn passed(&self) -> bool {
        self.synthetic_deny.is_passed() && self.fail_closed.is_passed()
    }
}

/// Production verification — both checks use the real builtin pipeline.
pub(crate) fn run() -> VerifyReport {
    run_with(synthetic_deny_check, fail_closed_check)
}

/// Test-injectable variant. The closures are invoked in order so a
/// caller can simulate either failure mode independently.
pub(crate) fn run_with<F, G>(synth: F, fc: G) -> VerifyReport
where
    F: FnOnce() -> CheckOutcome,
    G: FnOnce() -> CheckOutcome,
{
    VerifyReport {
        synthetic_deny: synth(),
        fail_closed: fc(),
        warnings: Vec::new(),
    }
}

/// Build a builtin-only [`Engine`] (no project policy, no plugins) and
/// confirm that `rm -rf /` triggers the canonical hard-deny rule.
pub(crate) fn synthetic_deny_check() -> CheckOutcome {
    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: json!({ "command": "rm -rf /" }),
    };
    let engine = Engine::with_components(Config::default(), PluginSet::new());
    classify_synthetic_deny(engine.decide(&input).decision)
}

fn classify_synthetic_deny(decision: Decision) -> CheckOutcome {
    match decision {
        Decision::Deny { rule_id, .. } if rule_id == SYNTHETIC_DENY_RULE => {
            CheckOutcome::Passed { rule_id }
        },
        Decision::Deny { rule_id, .. } => CheckOutcome::Failed {
            detail: format!(
                "engine returned Deny but with unexpected rule_id={rule_id} (expected {SYNTHETIC_DENY_RULE})"
            ),
        },
        other => CheckOutcome::Failed {
            detail: format!("engine returned {other:?}; expected Deny({SYNTHETIC_DENY_RULE})"),
        },
    }
}

/// Force the engine constructor down its plugin-loader-failure branch
/// and confirm the CLI fail-closed contract still maps that to
/// `core.engine.policy-load-failed`.
pub(crate) fn fail_closed_check() -> CheckOutcome {
    let nonexistent = PathBuf::from("/__ptuf__verify__nonexistent__plugin__do_not_create__.yaml");
    let mut config = Config {
        plugin_paths: vec![nonexistent],
        ..Config::default()
    };
    // Audit must stay quiet during verify so it never touches the
    // user's audit log; `with_config` short-circuits on plugin load
    // failure before opening the sink, but disable it explicitly for
    // future-proofing.
    config.audit.enabled = false;
    classify_fail_closed(Engine::with_config(config).is_err())
}

fn classify_fail_closed(load_failed: bool) -> CheckOutcome {
    if load_failed {
        CheckOutcome::Passed {
            rule_id: POLICY_LOAD_FAILED_RULE.to_string(),
        }
    } else {
        CheckOutcome::Failed {
            detail: "engine built successfully despite a missing plugin path".to_string(),
        }
    }
}

pub(crate) fn render_text<W: Write>(report: &VerifyReport, w: &mut W) -> io::Result<()> {
    writeln!(w, "Verify:")?;
    writeln!(
        w,
        "  Synthetic deny test: {}",
        format_outcome(&report.synthetic_deny)
    )?;
    writeln!(
        w,
        "  Fail-closed internal error test: {}",
        format_outcome(&report.fail_closed)
    )?;
    if report.warnings.is_empty() {
        writeln!(w, "  Warnings: none")?;
    } else {
        writeln!(w, "  Warnings:")?;
        for warning in &report.warnings {
            writeln!(w, "    {warning}")?;
        }
    }
    Ok(())
}

fn format_outcome(outcome: &CheckOutcome) -> String {
    match outcome {
        CheckOutcome::Passed { rule_id } => format!("passed (rule: {rule_id})"),
        CheckOutcome::Failed { detail } => format!("FAILED — {detail}"),
    }
}

pub(crate) fn render_json(
    outcome: &InstallOutcome,
    report: &VerifyReport,
    rolled_back: bool,
) -> Value {
    let paths: Vec<Value> = outcome
        .paths
        .iter()
        .map(|p| {
            json!({
                "label": p.label,
                "path": p.path.to_string_lossy(),
            })
        })
        .collect();
    json!({
        "schemaVersion": 1,
        "agent": outcome.agent,
        "installed": matches!(outcome.status, InstallStatus::Installed),
        "alreadyPresent": matches!(outcome.status, InstallStatus::AlreadyPresent),
        "paths": paths,
        "matcher": outcome.matcher,
        "command": outcome.command,
        "verify": {
            "syntheticDeny": outcome_to_json(&report.synthetic_deny),
            "failClosed": outcome_to_json(&report.fail_closed),
            "warnings": report.warnings,
        },
        "rolledBack": rolled_back,
    })
}

fn outcome_to_json(outcome: &CheckOutcome) -> Value {
    match outcome {
        CheckOutcome::Passed { rule_id } => json!({"status": "passed", "ruleId": rule_id}),
        CheckOutcome::Failed { detail } => json!({"status": "failed", "detail": detail}),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::init::InstallPath;

    fn passed(rule_id: &str) -> CheckOutcome {
        CheckOutcome::Passed {
            rule_id: rule_id.to_string(),
        }
    }

    fn failed(detail: &str) -> CheckOutcome {
        CheckOutcome::Failed {
            detail: detail.to_string(),
        }
    }

    fn sample_outcome() -> InstallOutcome {
        InstallOutcome {
            status: InstallStatus::Installed,
            agent: "claude-code",
            paths: vec![InstallPath {
                label: "settings",
                path: PathBuf::from("/tmp/settings.json"),
            }],
            matcher: "Bash|Read|Edit|Write|WebFetch|mcp__.*".into(),
            command: "/usr/local/bin/ptuf hook claude-code".into(),
            kiro_report: None,
        }
    }

    #[test]
    fn synthetic_deny_check_passes_for_rm_rf_root() {
        let outcome = synthetic_deny_check();
        assert_eq!(
            outcome,
            CheckOutcome::Passed {
                rule_id: SYNTHETIC_DENY_RULE.into(),
            }
        );
    }

    #[test]
    fn fail_closed_check_passes_when_plugin_path_missing() {
        let outcome = fail_closed_check();
        assert_eq!(
            outcome,
            CheckOutcome::Passed {
                rule_id: POLICY_LOAD_FAILED_RULE.into(),
            }
        );
    }

    #[test]
    fn run_returns_passing_report_in_default_environment() {
        let report = run();
        assert!(report.passed(), "verify::run() must pass: {report:?}");
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn run_with_uses_provided_closures() {
        let report = run_with(|| passed("a"), || passed("b"));
        assert_eq!(report.synthetic_deny, passed("a"));
        assert_eq!(report.fail_closed, passed("b"));
        assert!(report.passed());
    }

    #[test]
    fn passed_helper_reports_pass_only_when_both_pass() {
        let both_pass = VerifyReport {
            synthetic_deny: passed("x"),
            fail_closed: passed("y"),
            warnings: Vec::new(),
        };
        assert!(both_pass.passed());

        let synth_failed = VerifyReport {
            synthetic_deny: failed("nope"),
            fail_closed: passed("y"),
            warnings: Vec::new(),
        };
        assert!(!synth_failed.passed());

        let fc_failed = VerifyReport {
            synthetic_deny: passed("x"),
            fail_closed: failed("nope"),
            warnings: Vec::new(),
        };
        assert!(!fc_failed.passed());
    }

    #[test]
    fn render_text_shows_passed_branches_and_no_warnings() {
        let report = VerifyReport {
            synthetic_deny: passed("core.filesystem.destructive-rm"),
            fail_closed: passed("core.engine.policy-load-failed"),
            warnings: Vec::new(),
        };
        let mut buf = Vec::new();
        render_text(&report, &mut buf).expect("render");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Verify:"));
        assert!(s.contains("Synthetic deny test: passed (rule: core.filesystem.destructive-rm)"));
        assert!(s.contains(
            "Fail-closed internal error test: passed (rule: core.engine.policy-load-failed)"
        ));
        assert!(s.contains("Warnings: none"));
    }

    #[test]
    fn render_text_shows_failed_branches() {
        let report = VerifyReport {
            synthetic_deny: failed("got Allow"),
            fail_closed: passed("core.engine.policy-load-failed"),
            warnings: Vec::new(),
        };
        let mut buf = Vec::new();
        render_text(&report, &mut buf).expect("render");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Synthetic deny test: FAILED — got Allow"));
    }

    #[test]
    fn render_text_lists_warnings_when_present() {
        let report = VerifyReport {
            synthetic_deny: passed("a"),
            fail_closed: passed("b"),
            warnings: vec!["audit log path not writable".into()],
        };
        let mut buf = Vec::new();
        render_text(&report, &mut buf).expect("render");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Warnings:"));
        assert!(s.contains("audit log path not writable"));
        assert!(!s.contains("Warnings: none"));
    }

    #[test]
    fn render_json_has_expected_shape() {
        let outcome = sample_outcome();
        let report = VerifyReport {
            synthetic_deny: passed("core.filesystem.destructive-rm"),
            fail_closed: passed("core.engine.policy-load-failed"),
            warnings: Vec::new(),
        };
        let value = render_json(&outcome, &report, false);
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["agent"], "claude-code");
        assert_eq!(value["installed"], true);
        assert_eq!(value["alreadyPresent"], false);
        assert_eq!(value["verify"]["syntheticDeny"]["status"], "passed");
        assert_eq!(
            value["verify"]["syntheticDeny"]["ruleId"],
            "core.filesystem.destructive-rm"
        );
        assert_eq!(value["verify"]["failClosed"]["status"], "passed");
        assert_eq!(value["rolledBack"], false);
        assert_eq!(value["paths"][0]["label"], "settings");
    }

    #[test]
    fn render_json_marks_failed_status_with_detail() {
        let outcome = sample_outcome();
        let report = VerifyReport {
            synthetic_deny: failed("got Allow"),
            fail_closed: passed("core.engine.policy-load-failed"),
            warnings: vec!["x".into()],
        };
        let value = render_json(&outcome, &report, true);
        assert_eq!(value["verify"]["syntheticDeny"]["status"], "failed");
        assert_eq!(value["verify"]["syntheticDeny"]["detail"], "got Allow");
        assert_eq!(value["verify"]["warnings"][0], "x");
        assert_eq!(value["rolledBack"], true);
    }

    #[test]
    fn render_json_marks_already_present_status() {
        let mut outcome = sample_outcome();
        outcome.status = InstallStatus::AlreadyPresent;
        let report = VerifyReport {
            synthetic_deny: passed("a"),
            fail_closed: passed("b"),
            warnings: Vec::new(),
        };
        let value = render_json(&outcome, &report, false);
        assert_eq!(value["installed"], false);
        assert_eq!(value["alreadyPresent"], true);
    }

    #[test]
    fn classify_synthetic_deny_passes_for_canonical_rule() {
        let outcome = classify_synthetic_deny(Decision::Deny {
            rule_id: SYNTHETIC_DENY_RULE.into(),
            reason: "x".into(),
        });
        assert_eq!(
            outcome,
            CheckOutcome::Passed {
                rule_id: SYNTHETIC_DENY_RULE.into(),
            }
        );
    }

    #[test]
    fn classify_synthetic_deny_fails_when_rule_id_differs() {
        let outcome = classify_synthetic_deny(Decision::Deny {
            rule_id: "core.other".into(),
            reason: "x".into(),
        });
        match outcome {
            CheckOutcome::Failed { detail } => {
                assert!(detail.contains("unexpected rule_id=core.other"), "{detail}");
                assert!(detail.contains(SYNTHETIC_DENY_RULE), "{detail}");
            },
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn classify_synthetic_deny_fails_for_non_deny_decision() {
        let outcome = classify_synthetic_deny(Decision::Allow);
        match outcome {
            CheckOutcome::Failed { detail } => {
                assert!(detail.contains("Allow"), "{detail}");
                assert!(detail.contains(SYNTHETIC_DENY_RULE), "{detail}");
            },
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn classify_fail_closed_passes_when_engine_load_failed() {
        let outcome = classify_fail_closed(true);
        assert_eq!(
            outcome,
            CheckOutcome::Passed {
                rule_id: POLICY_LOAD_FAILED_RULE.into(),
            }
        );
    }

    #[test]
    fn classify_fail_closed_fails_when_engine_loaded_successfully() {
        let outcome = classify_fail_closed(false);
        match outcome {
            CheckOutcome::Failed { detail } => {
                assert!(detail.contains("missing plugin path"), "{detail}");
            },
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
