//! `ptuf plugin test <path>` runner.
//!
//! For each rule defined in the plugin file, evaluates every entry
//! under `tests.deny:` and `tests.allow:` against the rule alone and
//! reports pass/fail counts. The runner does **not** evaluate built-in
//! rules — a plugin author should only assert their own rule's
//! behaviour without binding to the engine's whole pipeline.
//!
//! Exit semantics for callers (`cli::run_plugin_test`):
//! * 0 — every case passed,
//! * 1 — at least one case failed or the plugin file failed to load.
//!
//! See `docs/design/cli-and-hooks.md:17,28` for the user-facing
//! contract.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::Decision;
use crate::HookInput;
use crate::facts;
use crate::rules::ConfigRule;

use super::PluginError;
use super::dsl::{WhenNode, compile};
use super::loader::load_path;
use super::rule::PluginRule;
use super::schema::{RawPlugin, RawRule, RawTestCase};

/// Result of executing one `tests.deny` or `tests.allow` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseOutcome {
    pub rule_id: String,
    pub expectation: Expectation,
    pub passed: bool,
    pub command: String,
    pub got: Option<Decision>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// The rule should fire (return `Some(_)`).
    ShouldTrigger,
    /// The rule should not fire (return `None`).
    ShouldSkip,
}

/// Aggregated result of running every test case in a plugin file.
#[derive(Debug)]
pub struct RunReport {
    pub source: PathBuf,
    pub plugin_name: String,
    pub cases: Vec<CaseOutcome>,
}

impl RunReport {
    /// `true` iff every case passed.
    pub fn passed(&self) -> bool {
        self.cases.iter().all(|c| c.passed)
    }

    pub fn passed_count(&self) -> usize {
        self.cases.iter().filter(|c| c.passed).count()
    }

    pub fn failed_count(&self) -> usize {
        self.cases.iter().filter(|c| !c.passed).count()
    }

    /// Render a human-readable summary. Returns the underlying I/O
    /// error if one of the writes fails.
    pub fn render<W: Write>(&self, out: &mut W) -> io::Result<()> {
        writeln!(
            out,
            "plugin {} ({}): {} passed, {} failed",
            self.plugin_name,
            self.source.display(),
            self.passed_count(),
            self.failed_count()
        )?;
        for case in &self.cases {
            let mark = if case.passed { "ok " } else { "FAIL" };
            let label = match case.expectation {
                Expectation::ShouldTrigger => "deny",
                Expectation::ShouldSkip => "allow",
            };
            writeln!(out, "  {mark} {} [{label}] {}", case.rule_id, case.command)?;
            if !case.passed {
                match &case.got {
                    Some(d) => writeln!(out, "       got {}", decision_label(d))?,
                    None => writeln!(out, "       got <no decision>")?,
                }
            }
        }
        Ok(())
    }
}

/// Run every plugin test case from `path`.
pub fn run(path: &Path) -> Result<RunReport, PluginError> {
    let loaded = load_path(path)?;
    let cases = build_cases(path, &loaded.raw_rules)?;
    let outcomes = cases.into_iter().map(execute_case).collect();
    Ok(RunReport {
        source: path.to_path_buf(),
        plugin_name: loaded.name,
        cases: outcomes,
    })
}

/// Run from an in-memory YAML string. Mostly handy for tests of the
/// runner itself; the public CLI path always reads from disk.
pub fn run_str(path: &Path, source: &str) -> Result<RunReport, PluginError> {
    let raw: RawPlugin = serde_yaml_ng::from_str(source).map_err(|e| PluginError::Yaml {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let cases = build_cases(path, &raw.rules)?;
    let outcomes = cases.into_iter().map(execute_case).collect();
    Ok(RunReport {
        source: path.to_path_buf(),
        plugin_name: raw.metadata.name,
        cases: outcomes,
    })
}

struct PreparedCase {
    rule: PluginRule,
    raw_case: RawTestCase,
    expectation: Expectation,
    rule_id: String,
}

fn build_cases(path: &Path, raw_rules: &[RawRule]) -> Result<Vec<PreparedCase>, PluginError> {
    let mut out = Vec::new();
    for raw_rule in raw_rules {
        for case in &raw_rule.tests.deny {
            out.push(prepare_case(
                path,
                raw_rule,
                case.clone(),
                Expectation::ShouldTrigger,
            )?);
        }
        for case in &raw_rule.tests.allow {
            out.push(prepare_case(
                path,
                raw_rule,
                case.clone(),
                Expectation::ShouldSkip,
            )?);
        }
    }
    Ok(out)
}

fn prepare_case(
    path: &Path,
    raw_rule: &RawRule,
    raw_case: RawTestCase,
    expectation: Expectation,
) -> Result<PreparedCase, PluginError> {
    let when: WhenNode = compile(&raw_rule.when).map_err(|e| PluginError::Compile {
        path: path.to_path_buf(),
        rule_id: raw_rule.id.clone(),
        message: e.to_string(),
    })?;
    let rule = PluginRule::from_raw(clone_raw_rule(raw_rule), when);
    Ok(PreparedCase {
        rule_id: raw_rule.id.clone(),
        rule,
        raw_case,
        expectation,
    })
}

fn execute_case(prepared: PreparedCase) -> CaseOutcome {
    let input = HookInput {
        tool_name: prepared.raw_case.input.tool_name,
        tool_input: prepared.raw_case.input.tool_input,
    };
    let command = input
        .bash_command()
        .map_or_else(|| format!("(tool={})", input.tool_name), str::to_owned);
    let facts = facts::extract(&input);
    let got = prepared.rule.evaluate(&facts, &input);
    let passed = match prepared.expectation {
        Expectation::ShouldTrigger => got.is_some(),
        Expectation::ShouldSkip => got.is_none(),
    };
    CaseOutcome {
        rule_id: prepared.rule_id,
        expectation: prepared.expectation,
        passed,
        command,
        got,
    }
}

fn clone_raw_rule(raw: &RawRule) -> RawRule {
    RawRule {
        id: raw.id.clone(),
        title: raw.title.clone(),
        severity: raw.severity,
        default_decision: raw.default_decision,
        overridable: raw.overridable,
        hard_deny: raw.hard_deny,
        when: raw.when.clone(),
        reason: raw.reason.clone(),
        remediation: raw.remediation.clone(),
        tests: super::schema::RawTests {
            deny: raw.tests.deny.clone(),
            allow: raw.tests.allow.clone(),
        },
    }
}

fn decision_label(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Monitor { .. } => "monitor",
        Decision::Ask { .. } => "ask",
        Decision::Deny { .. } => "deny",
    }
}

impl Clone for RawTestCase {
    fn clone(&self) -> Self {
        Self {
            input: super::schema::RawTestInput {
                tool_name: self.input.tool_name.clone(),
                tool_input: self.input.tool_input.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn p() -> PathBuf {
        PathBuf::from("test.yaml")
    }

    #[test]
    fn passes_when_all_cases_meet_expectations() {
        let yaml = r#"
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
      allow:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
"#;
        let report = run_str(&p(), yaml).expect("run");
        assert_eq!(report.cases.len(), 2);
        assert!(report.passed());
        assert_eq!(report.passed_count(), 2);
        assert_eq!(report.failed_count(), 0);
    }

    #[test]
    fn fails_when_deny_case_does_not_trigger() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: x
rules:
  - id: x.bad
    severity: low
    defaultDecision: deny
    when:
      tool: Read
    reason: r
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
"#;
        let report = run_str(&p(), yaml).expect("run");
        assert!(!report.passed());
        assert_eq!(report.failed_count(), 1);
    }

    #[test]
    fn fails_when_allow_case_triggers() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: x
rules:
  - id: x.bad
    severity: low
    defaultDecision: deny
    when:
      tool: Bash
    reason: r
    tests:
      allow:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
"#;
        let report = run_str(&p(), yaml).expect("run");
        assert!(!report.passed());
        assert_eq!(report.failed_count(), 1);
    }

    #[test]
    fn invalid_yaml_propagates_as_plugin_error() {
        let err = run_str(&p(), "::nope::").expect_err("should fail");
        assert!(matches!(err, PluginError::Yaml { .. }));
    }

    #[test]
    fn no_test_section_yields_zero_cases_and_passes() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: empty
rules:
  - id: empty.x
    severity: low
    defaultDecision: deny
    when:
      tool: Bash
    reason: r
"#;
        let report = run_str(&p(), yaml).expect("run");
        assert!(report.passed());
        assert!(report.cases.is_empty());
    }

    #[test]
    fn render_includes_pass_and_fail_summary() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: r
rules:
  - id: r.x
    severity: low
    defaultDecision: deny
    when:
      tool: Bash
    reason: r
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
      allow:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
"#;
        let report = run_str(&p(), yaml).expect("run");
        let mut buf = Vec::new();
        report.render(&mut buf).expect("render");
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("plugin r"));
        assert!(s.contains("FAIL"));
        assert!(s.contains("ok"));
    }

    /// `Write` impl that succeeds for the first `fail_after` bytes and
    /// then returns `Err` on every subsequent call. Used to exercise the
    /// `?`-propagation paths inside [`RunReport::render`] without
    /// touching the filesystem.
    struct FailingWriter {
        budget: usize,
    }

    impl FailingWriter {
        fn new(budget: usize) -> Self {
            Self { budget }
        }
    }

    impl Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.budget == 0 {
                return Err(io::Error::other("disk full"));
            }
            let n = buf.len().min(self.budget);
            self.budget -= n;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn render_propagates_io_error_when_header_write_fails() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: r
rules:
  - id: r.x
    severity: low
    defaultDecision: deny
    when:
      tool: Bash
    reason: r
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
"#;
        let report = run_str(&p(), yaml).expect("run");
        let mut writer = FailingWriter::new(0);
        let err = report.render(&mut writer).expect_err("header must fail");
        assert!(format!("{err}").contains("disk full"));
    }

    #[test]
    fn render_propagates_io_error_when_per_case_write_fails() {
        // Configure a deny case whose rule does NOT fire: that forces
        // render down the `case.passed == false` branch with `got: None`,
        // which adds a third writeln per case. With a budget that just
        // covers the header, the per-case line triggers the second `?`.
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: r
rules:
  - id: r.x
    severity: low
    defaultDecision: deny
    when:
      tool: Read
    reason: r
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
"#;
        let report = run_str(&p(), yaml).expect("run");
        // Header "plugin r (test.yaml): 0 passed, 1 failed\n" is 41 bytes.
        let mut writer = FailingWriter::new(41);
        let err = report
            .render(&mut writer)
            .expect_err("per-case write must fail");
        assert!(format!("{err}").contains("disk full"));
    }

    #[test]
    fn prepare_case_propagates_compile_error_for_unknown_when_key() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: bad
rules:
  - id: bad.r
    severity: low
    defaultDecision: deny
    when:
      noSuchFact: yes
    reason: r
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
"#;
        let err = run_str(&p(), yaml).expect_err("compile must fail");
        match err {
            PluginError::Compile {
                path,
                rule_id,
                message,
            } => {
                assert_eq!(path, p());
                assert_eq!(rule_id, "bad.r");
                assert!(
                    message.contains("noSuchFact") || message.contains("unknown"),
                    "unexpected message: {message}"
                );
            },
            other => panic!("expected Compile, got {other:?}"),
        }
    }

    #[test]
    fn decision_label_returns_each_label_directly() {
        // The render path only ever calls `decision_label` for failing
        // cases whose `got` is `Some(_)`, which in practice is always
        // `Decision::Deny`. Hit Allow / Monitor / Ask directly so the
        // remaining match arms are covered.
        assert_eq!(decision_label(&Decision::Allow), "allow");
        assert_eq!(
            decision_label(&Decision::Monitor {
                rule_id: "x".into()
            }),
            "monitor"
        );
        assert_eq!(
            decision_label(&Decision::Ask {
                rule_id: "x".into(),
                reason: "r".into(),
            }),
            "ask"
        );
        assert_eq!(
            decision_label(&Decision::Deny {
                rule_id: "x".into(),
                reason: "r".into(),
            }),
            "deny"
        );
    }

    use proptest::prelude::*;

    /// One `CaseOutcome` with an arbitrary `passed` flag; the remaining
    /// fields are fixed dummies since the count invariants only read
    /// `passed`.
    fn case_outcome() -> impl Strategy<Value = CaseOutcome> {
        any::<bool>().prop_map(|passed| CaseOutcome {
            rule_id: String::new(),
            expectation: Expectation::ShouldTrigger,
            passed,
            command: String::new(),
            got: None,
        })
    }

    fn run_report() -> impl Strategy<Value = RunReport> {
        proptest::collection::vec(case_outcome(), 0..8).prop_map(|cases| RunReport {
            source: PathBuf::from("test.yaml"),
            plugin_name: "p".to_string(),
            cases,
        })
    }

    proptest! {
        // `passed_count` and `failed_count` partition the case list:
        // together they always sum to the total number of cases.
        #[test]
        fn pbt_run_report_counts_partition_cases(report in run_report()) {
            prop_assert_eq!(
                report.passed_count() + report.failed_count(),
                report.cases.len(),
            );
        }

        // `passed()` is exactly "no failures": it holds iff
        // `failed_count()` is zero (the empty-case report included).
        #[test]
        fn pbt_run_report_passed_iff_no_failures(report in run_report()) {
            prop_assert_eq!(report.passed(), report.failed_count() == 0);
        }
    }
}
