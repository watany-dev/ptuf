//! Serde schema for `apiVersion: ptuf.dev/v1, kind: Plugin` YAML files.
//!
//! Mirrors the layout described in
//! `docs/design/config-and-plugins.md:91-166`. The structs are
//! deliberately permissive on their `Default` form so a partially
//! filled YAML still round-trips without bespoke `Option` wrappers.
//! Field validation (apiVersion / kind / supported facts / `when`
//! compile) lives in [`super::loader`] so this module stays a pure
//! data shape.

use serde::Deserialize;
use serde_yaml_ng::Value;

use crate::decision::{DecisionKind, Severity};

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawPlugin {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: RawMetadata,
    #[serde(default)]
    pub capabilities: RawCapabilities,
    #[serde(default)]
    pub rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RawMetadata {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RawCapabilities {
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    pub id: String,
    #[serde(default)]
    pub title: String,
    pub severity: Severity,
    #[serde(rename = "defaultDecision")]
    pub default_decision: DecisionKind,
    #[serde(default)]
    pub overridable: Option<bool>,
    #[serde(rename = "hardDeny", default)]
    pub hard_deny: Option<bool>,
    pub when: Value,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub remediation: Vec<String>,
    #[serde(default)]
    pub tests: RawTests,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RawTests {
    #[serde(default)]
    pub deny: Vec<RawTestCase>,
    #[serde(default)]
    pub allow: Vec<RawTestCase>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawTestCase {
    pub input: RawTestInput,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawTestInput {
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_minimal_plugin() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: example
"#;
        let plugin: RawPlugin = serde_yaml_ng::from_str(yaml).expect("parse");
        assert_eq!(plugin.api_version, "ptuf.dev/v1");
        assert_eq!(plugin.kind, "Plugin");
        assert_eq!(plugin.metadata.name, "example");
        assert!(plugin.rules.is_empty());
    }

    #[test]
    fn parses_capabilities_block() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: x
capabilities:
  events: [PreToolUse]
  tools: [Bash]
  requires: [shell.ast, shell.pipeline]
"#;
        let plugin: RawPlugin = serde_yaml_ng::from_str(yaml).expect("parse");
        assert_eq!(plugin.capabilities.events, vec!["PreToolUse"]);
        assert_eq!(plugin.capabilities.tools, vec!["Bash"]);
        assert_eq!(
            plugin.capabilities.requires,
            vec!["shell.ast", "shell.pipeline"]
        );
    }

    #[test]
    fn parses_rule_with_when_and_tests() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: x
rules:
  - id: x.demo
    title: Demo
    severity: high
    defaultDecision: deny
    when:
      all:
        - tool: Bash
    reason: nope
    remediation:
      - try something else
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: rm -rf /
      allow:
        - input:
            tool_name: Bash
            tool_input:
              command: ls
"#;
        let plugin: RawPlugin = serde_yaml_ng::from_str(yaml).expect("parse");
        assert_eq!(plugin.rules.len(), 1);
        let rule = &plugin.rules[0];
        assert_eq!(rule.id, "x.demo");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.default_decision, DecisionKind::Deny);
        assert_eq!(rule.remediation, vec!["try something else"]);
        assert_eq!(rule.tests.deny.len(), 1);
        assert_eq!(rule.tests.allow.len(), 1);
        assert_eq!(rule.tests.deny[0].input.tool_name, "Bash");
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: x
weird: 1
"#;
        let err = serde_yaml_ng::from_str::<RawPlugin>(yaml).expect_err("should reject");
        assert!(
            err.to_string().contains("weird") || err.to_string().contains("unknown"),
            "unexpected: {err}"
        );
    }
}
