//! Read a plugin YAML file from disk and turn it into a usable
//! [`LoadedPlugin`] (plugin metadata + a list of [`PluginRule`]s ready
//! to evaluate).
//!
//! Validation order, returning the first failure:
//! 1. file I/O,
//! 2. YAML parse,
//! 3. `apiVersion: ptuf.dev/v1`,
//! 4. `kind: Plugin`,
//! 5. every entry under `capabilities.requires` is a fact ptuf
//!    actually exposes,
//! 6. each rule's `when:` compiles into the AST.

use std::fs;
use std::path::{Path, PathBuf};

use super::PluginError;
use super::dsl::compile;
use super::rule::PluginRule;
use super::schema::{RawPlugin, RawRule};

/// Facts that can be referenced from a plugin's
/// `capabilities.requires`. Must stay in sync with the supported
/// `when:` leaves in [`super::dsl`].
pub const SUPPORTED_FACTS: &[&str] = &[
    "shell.ast",
    "shell.argv",
    "shell.pipeline",
    "tool",
    "event",
    "path",
    "url",
    "sensitive_path",
];

/// A successfully loaded and validated plugin.
#[derive(Debug)]
pub struct LoadedPlugin {
    pub name: String,
    pub version: String,
    pub rules: Vec<PluginRule>,
    pub raw_rules: Vec<RawRule>,
    pub source: PathBuf,
}

impl LoadedPlugin {
    /// Number of rules the plugin contributed.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Load a single plugin file from disk.
pub fn load_path(path: &Path) -> Result<LoadedPlugin, PluginError> {
    let source = fs::read_to_string(path).map_err(|e| PluginError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    load_str(path, &source)
}

/// Load a plugin from an in-memory string. Used by tests and by the
/// `ptuf plugin test` runner once it has read the file itself.
pub fn load_str(path: &Path, source: &str) -> Result<LoadedPlugin, PluginError> {
    let raw: RawPlugin = serde_yaml_ng::from_str(source).map_err(|e| PluginError::Yaml {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    if raw.api_version != "ptuf.dev/v1" {
        return Err(PluginError::ApiVersion {
            path: path.to_path_buf(),
            found: raw.api_version,
        });
    }
    if raw.kind != "Plugin" {
        return Err(PluginError::Kind {
            path: path.to_path_buf(),
            found: raw.kind,
        });
    }

    for fact in &raw.capabilities.requires {
        if !SUPPORTED_FACTS.contains(&fact.as_str()) {
            return Err(PluginError::UnsupportedFact {
                path: path.to_path_buf(),
                name: fact.clone(),
            });
        }
    }

    let mut compiled = Vec::with_capacity(raw.rules.len());
    let mut originals = Vec::with_capacity(raw.rules.len());
    for raw_rule in raw.rules {
        let when = compile(&raw_rule.when).map_err(|e| PluginError::Compile {
            path: path.to_path_buf(),
            rule_id: raw_rule.id.clone(),
            message: e.to_string(),
        })?;
        let raw_clone = clone_raw_rule(&raw_rule);
        compiled.push(PluginRule::from_raw(raw_rule, when));
        originals.push(raw_clone);
    }

    Ok(LoadedPlugin {
        name: raw.metadata.name,
        version: raw.metadata.version,
        rules: compiled,
        raw_rules: originals,
        source: path.to_path_buf(),
    })
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
            deny: raw.tests.deny.iter().map(clone_raw_case).collect(),
            allow: raw.tests.allow.iter().map(clone_raw_case).collect(),
        },
    }
}

fn clone_raw_case(c: &super::schema::RawTestCase) -> super::schema::RawTestCase {
    super::schema::RawTestCase {
        input: super::schema::RawTestInput {
            tool_name: c.input.tool_name.clone(),
            tool_input: c.input.tool_input.clone(),
        },
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::rules::ConfigRule;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("test.yaml")
    }

    #[test]
    fn loads_minimal_plugin() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: example
  version: 0.1.0
"#;
        let loaded = load_str(&p(), yaml).expect("load");
        assert_eq!(loaded.name, "example");
        assert_eq!(loaded.version, "0.1.0");
        assert_eq!(loaded.rule_count(), 0);
    }

    #[test]
    fn rejects_wrong_api_version() {
        let yaml = r#"
apiVersion: ptuf.dev/v999
kind: Plugin
metadata:
  name: x
"#;
        let err = load_str(&p(), yaml).expect_err("should reject");
        assert!(matches!(err, PluginError::ApiVersion { .. }));
    }

    #[test]
    fn rejects_wrong_kind() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: ConfigMap
metadata:
  name: x
"#;
        let err = load_str(&p(), yaml).expect_err("should reject");
        assert!(matches!(err, PluginError::Kind { .. }));
    }

    #[test]
    fn rejects_unsupported_required_fact() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: x
capabilities:
  requires: [shell.ast, url.parse]
"#;
        let err = load_str(&p(), yaml).expect_err("should reject");
        match err {
            PluginError::UnsupportedFact { name, .. } => assert_eq!(name, "url.parse"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn loads_rule_and_compiles_when() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
capabilities:
  requires: [shell.argv, tool, event]
rules:
  - id: pack.demo.block-rm
    severity: high
    defaultDecision: deny
    when:
      all:
        - tool: Bash
        - shell.argv:
            headAny: [rm]
    reason: rm denied
    remediation:
      - try delete-only-this-dir
"#;
        let loaded = load_str(&p(), yaml).expect("load");
        assert_eq!(loaded.rule_count(), 1);
        assert_eq!(loaded.rules[0].id(), "pack.demo.block-rm");
    }

    #[test]
    fn rejects_when_with_unknown_key() {
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
      huh: yes
    reason: r
"#;
        let err = load_str(&p(), yaml).expect_err("should reject");
        match err {
            PluginError::Compile { rule_id, .. } => assert_eq!(rule_id, "x.bad"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn malformed_yaml_yields_yaml_error() {
        let err = load_str(&p(), "::not yaml::").expect_err("should reject");
        assert!(matches!(err, PluginError::Yaml { .. }));
    }

    #[test]
    fn loader_accepts_shell_ast_but_dsl_has_no_when_node() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.ast
capabilities:
  requires: [shell.ast]
rules:
  - id: pack.ast.placeholder
    severity: low
    defaultDecision: allow
    when:
      tool: Bash
    reason: capability placeholder
"#;
        let loaded = load_str(&p(), yaml).expect("shell.ast is a supported capability");
        assert_eq!(loaded.name, "pack.ast");
    }

    #[test]
    fn supported_facts_includes_expected_v0_3_set() {
        for f in [
            "shell.ast",
            "shell.argv",
            "shell.pipeline",
            "tool",
            "event",
            "path",
            "url",
            "sensitive_path",
        ] {
            assert!(SUPPORTED_FACTS.contains(&f), "missing: {f}");
        }
    }

    // load_path on a non-existent file surfaces as `PluginError::Io`
    // with the original path preserved, so audit consumers can attribute
    // the failure to a specific plugin file.
    #[test]
    fn load_path_returns_io_error_for_missing_file() {
        let path = PathBuf::from("/nonexistent/ptuf-plugin-does-not-exist.yaml");
        let err = load_path(&path).expect_err("should fail");
        match err {
            PluginError::Io { path: returned, .. } => assert_eq!(returned, path),
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    // Each error variant must carry the original `path`. This is the
    // cross-variant invariant relied on by the fail-closed audit
    // record.
    #[test]
    fn plugin_load_errors_carry_path_and_observed_fields() {
        let yaml_path = PathBuf::from("/abs/plugin.yaml");
        match load_str(&yaml_path, "::not yaml::").expect_err("yaml") {
            PluginError::Yaml { path, .. } => assert_eq!(path, yaml_path),
            other => panic!("expected Yaml, got {other:?}"),
        }

        let api_path = PathBuf::from("/abs/api.yaml");
        let bad_api = "apiVersion: foo/v0\nkind: Plugin\nmetadata:\n  name: x\n";
        match load_str(&api_path, bad_api).expect_err("api version") {
            PluginError::ApiVersion { path, found } => {
                assert_eq!(path, api_path);
                assert_eq!(found, "foo/v0");
            },
            other => panic!("expected ApiVersion, got {other:?}"),
        }

        let kind_yaml = "apiVersion: ptuf.dev/v1\nkind: Bogus\nmetadata:\n  name: x\n";
        match load_str(&p(), kind_yaml).expect_err("kind") {
            PluginError::Kind { found, .. } => assert_eq!(found, "Bogus"),
            other => panic!("expected Kind, got {other:?}"),
        }
    }

    // The `Compile` failure path carries the rule id and the original
    // file path, so a failing plugin can be located even when nested
    // deep under `all:` / `any:`.
    #[test]
    fn compile_error_carries_rule_id_and_path_for_nested_invalid_when() {
        let path = PathBuf::from("/abs/p.yaml");
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: x
rules:
  - id: pack.x.nested-bad
    severity: low
    defaultDecision: deny
    when:
      all:
        - any:
            - shell.argv: 42
    reason: r
"#;
        let err = load_str(&path, yaml).expect_err("nested compile err");
        match err {
            PluginError::Compile {
                path: returned,
                rule_id,
                ..
            } => {
                assert_eq!(returned, path);
                assert_eq!(rule_id, "pack.x.nested-bad");
            },
            other => panic!("expected Compile error, got {other:?}"),
        }
    }

    use proptest::prelude::*;

    // Plugin YAML inputs: mostly arbitrary noise, plus partially-valid
    // documents that drive each validation branch (apiVersion / kind,
    // capability facts, rule `when:` compilation).
    fn plugin_source() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => crate::testing::proptest::arbitrary_command(),
            1 => ("[A-Za-z0-9./]{1,16}", "[A-Za-z]{1,12}", "[a-z.]{1,16}").prop_map(
                |(api, kind, name)| format!(
                    "apiVersion: {api}\nkind: {kind}\nmetadata:\n  name: {name}\n",
                ),
            ),
            1 => "[a-z.]{1,16}".prop_map(|fact| format!(
                "apiVersion: ptuf.dev/v1\nkind: Plugin\nmetadata:\n  name: x\n\
                 capabilities:\n  requires: [{fact}]\n",
            )),
            1 => "[a-z.]{1,16}".prop_map(|rule_id| format!(
                "apiVersion: ptuf.dev/v1\nkind: Plugin\nmetadata:\n  name: pack.demo\n\
                 rules:\n  - id: {rule_id}\n    severity: high\n    \
                 defaultDecision: deny\n    when:\n      all:\n        - tool: Bash\n    \
                 reason: r\n",
            )),
        ]
    }

    proptest! {
        // `load_str` is total: any input — binary noise or
        // partially-valid plugin YAML — yields `Ok` or `Err`, never a
        // panic. This is the plugin trust boundary; a panic here would
        // crash the hook instead of failing closed.
        #[test]
        fn pbt_load_str_is_total_on_arbitrary_input(source in plugin_source()) {
            let _ = load_str(&p(), &source);
        }
    }
}
