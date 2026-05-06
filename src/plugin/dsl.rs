//! `when:` DSL: AST and evaluator.
//!
//! Compiles a `serde_yaml_ng::Value` into a strongly-typed [`WhenNode`]
//! tree at plugin load time, then evaluates the tree against [`Facts`]
//! and the original [`HookInput`] at hook time. Supported leaves are
//! intentionally narrow for v0.2 — see
//! `docs/design/config-and-plugins.md:121-141` and
//! `docs/design/architecture.md:57-77`.

use serde_yaml_ng::Value;

use crate::HookInput;
use crate::facts::Facts;

/// Compiled boolean expression. The combinators (`All`, `Any`, `Not`)
/// match the YAML keys; the leaves match the supported facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhenNode {
    All(Vec<WhenNode>),
    Any(Vec<WhenNode>),
    Not(Box<WhenNode>),
    Event(String),
    Tool(String),
    ToolAny(Vec<String>),
    ShellArgvHeadAny(Vec<String>),
    ShellPipelineFromTo { from: Vec<String>, to: Vec<String> },
    PathFilePathPrefixAny(Vec<String>),
    UrlSchemeAny(Vec<String>),
    UrlHostAny(Vec<String>),
    SensitivePathAny(Vec<String>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CompileError {
    /// The mapping had a key the loader does not recognise.
    UnknownKey(String),
    /// A leaf had the wrong YAML shape (e.g. expected a string list).
    InvalidShape { key: String, message: String },
    /// `all` / `any` was given an empty list.
    EmptyMapping,
    /// `when:` was something other than a mapping.
    NotAMapping,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::UnknownKey(k) => write!(f, "unknown key in when expression: {k}"),
            CompileError::InvalidShape { key, message } => {
                write!(f, "invalid shape for `{key}`: {message}")
            }
            CompileError::EmptyMapping => write!(f, "when expression was empty"),
            CompileError::NotAMapping => write!(f, "when expression must be a mapping"),
        }
    }
}

impl std::error::Error for CompileError {}

/// Compile a YAML `when:` value into an executable AST.
pub fn compile(value: &Value) -> Result<WhenNode, CompileError> {
    let mapping = value.as_mapping().ok_or(CompileError::NotAMapping)?;
    if mapping.is_empty() {
        return Err(CompileError::EmptyMapping);
    }
    if mapping.len() > 1 {
        // Multiple top-level keys at the same level are interpreted as
        // an implicit `all:` so that the human-friendly form
        // `tool: Bash` + `event: PreToolUse` works without nesting.
        let mut nodes = Vec::with_capacity(mapping.len());
        for (k, v) in mapping {
            let key = k.as_str().ok_or_else(|| CompileError::InvalidShape {
                key: format!("{k:?}"),
                message: "expected a string key".into(),
            })?;
            nodes.push(compile_pair(key, v)?);
        }
        return Ok(WhenNode::All(nodes));
    }
    let (k, v) = mapping.iter().next().ok_or(CompileError::EmptyMapping)?;
    let key = k.as_str().ok_or_else(|| CompileError::InvalidShape {
        key: format!("{k:?}"),
        message: "expected a string key".into(),
    })?;
    compile_pair(key, v)
}

fn compile_pair(key: &str, value: &Value) -> Result<WhenNode, CompileError> {
    match key {
        "all" => Ok(WhenNode::All(compile_list(key, value)?)),
        "any" => Ok(WhenNode::Any(compile_list(key, value)?)),
        "not" => Ok(WhenNode::Not(Box::new(compile(value)?))),
        "event" => Ok(WhenNode::Event(expect_string(key, value)?)),
        "tool" => Ok(WhenNode::Tool(expect_string(key, value)?)),
        "toolAny" => Ok(WhenNode::ToolAny(expect_string_list(key, value)?)),
        "shell.argv" => compile_shell_argv(value),
        "shell.pipeline" => compile_shell_pipeline(value),
        "path.filePathPrefixAny" => Ok(WhenNode::PathFilePathPrefixAny(expect_string_list(
            key, value,
        )?)),
        "url.schemeAny" => Ok(WhenNode::UrlSchemeAny(expect_string_list(key, value)?)),
        "url.hostAny" => Ok(WhenNode::UrlHostAny(expect_string_list(key, value)?)),
        "sensitive.pathKindAny" => Ok(WhenNode::SensitivePathAny(expect_string_list(key, value)?)),
        other => Err(CompileError::UnknownKey(other.to_string())),
    }
}

fn compile_list(key: &str, value: &Value) -> Result<Vec<WhenNode>, CompileError> {
    let seq = value
        .as_sequence()
        .ok_or_else(|| CompileError::InvalidShape {
            key: key.to_string(),
            message: "expected a list of mappings".into(),
        })?;
    if seq.is_empty() {
        return Err(CompileError::InvalidShape {
            key: key.to_string(),
            message: "list must not be empty".into(),
        });
    }
    seq.iter().map(compile).collect()
}

fn compile_shell_argv(value: &Value) -> Result<WhenNode, CompileError> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| CompileError::InvalidShape {
            key: "shell.argv".into(),
            message: "expected a mapping".into(),
        })?;
    let mut head_any: Option<Vec<String>> = None;
    for (k, v) in mapping {
        let key = k.as_str().ok_or_else(|| CompileError::InvalidShape {
            key: "shell.argv".into(),
            message: format!("non-string key {k:?}"),
        })?;
        match key {
            "headAny" => head_any = Some(expect_string_list(key, v)?),
            other => {
                return Err(CompileError::UnknownKey(format!("shell.argv.{other}")));
            }
        }
    }
    let head_any = head_any.ok_or_else(|| CompileError::InvalidShape {
        key: "shell.argv".into(),
        message: "must contain `headAny`".into(),
    })?;
    Ok(WhenNode::ShellArgvHeadAny(head_any))
}

fn compile_shell_pipeline(value: &Value) -> Result<WhenNode, CompileError> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| CompileError::InvalidShape {
            key: "shell.pipeline".into(),
            message: "expected a mapping".into(),
        })?;
    let mut from: Option<Vec<String>> = None;
    let mut to: Option<Vec<String>> = None;
    for (k, v) in mapping {
        let key = k.as_str().ok_or_else(|| CompileError::InvalidShape {
            key: "shell.pipeline".into(),
            message: format!("non-string key {k:?}"),
        })?;
        match key {
            "from" => from = Some(parse_endpoint("from", v)?),
            "to" => to = Some(parse_endpoint("to", v)?),
            other => {
                return Err(CompileError::UnknownKey(format!("shell.pipeline.{other}")));
            }
        }
    }
    let from = from.ok_or_else(|| CompileError::InvalidShape {
        key: "shell.pipeline".into(),
        message: "missing `from`".into(),
    })?;
    let to = to.ok_or_else(|| CompileError::InvalidShape {
        key: "shell.pipeline".into(),
        message: "missing `to`".into(),
    })?;
    Ok(WhenNode::ShellPipelineFromTo { from, to })
}

fn parse_endpoint(label: &str, value: &Value) -> Result<Vec<String>, CompileError> {
    let mapping = value
        .as_mapping()
        .ok_or_else(|| CompileError::InvalidShape {
            key: format!("shell.pipeline.{label}"),
            message: "expected a mapping with `commandAny`".into(),
        })?;
    for (k, v) in mapping {
        let key = k.as_str().ok_or_else(|| CompileError::InvalidShape {
            key: format!("shell.pipeline.{label}"),
            message: format!("non-string key {k:?}"),
        })?;
        if key == "commandAny" {
            return expect_string_list(&format!("shell.pipeline.{label}.commandAny"), v);
        }
    }
    Err(CompileError::InvalidShape {
        key: format!("shell.pipeline.{label}"),
        message: "missing `commandAny`".into(),
    })
}

fn expect_string(key: &str, value: &Value) -> Result<String, CompileError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| CompileError::InvalidShape {
            key: key.to_string(),
            message: "expected a string".into(),
        })
}

fn expect_string_list(key: &str, value: &Value) -> Result<Vec<String>, CompileError> {
    let seq = value
        .as_sequence()
        .ok_or_else(|| CompileError::InvalidShape {
            key: key.to_string(),
            message: "expected a sequence of strings".into(),
        })?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let s = item.as_str().ok_or_else(|| CompileError::InvalidShape {
            key: key.to_string(),
            message: "items must be strings".into(),
        })?;
        out.push(s.to_owned());
    }
    Ok(out)
}

/// Currently the only event v0.2 supports.
const PRE_TOOL_USE: &str = "PreToolUse";

/// Evaluate a compiled AST against the hook context.
pub fn evaluate(node: &WhenNode, facts: &Facts, input: &HookInput) -> bool {
    match node {
        WhenNode::All(children) => children.iter().all(|c| evaluate(c, facts, input)),
        WhenNode::Any(children) => children.iter().any(|c| evaluate(c, facts, input)),
        WhenNode::Not(inner) => !evaluate(inner, facts, input),
        WhenNode::Event(name) => name == PRE_TOOL_USE,
        WhenNode::Tool(name) => input.tool_name == *name,
        WhenNode::ToolAny(names) => names.contains(&input.tool_name),
        WhenNode::ShellArgvHeadAny(heads) => match facts.bash.as_ref() {
            None => false,
            Some(bash) => bash
                .commands()
                .into_iter()
                .any(|argv| heads.contains(&argv.head)),
        },
        WhenNode::ShellPipelineFromTo { from, to } => match facts.bash.as_ref() {
            None => false,
            Some(bash) => bash.segments.iter().any(|pipe| {
                let mut seen_from = false;
                for cmd in &pipe.commands {
                    if !seen_from {
                        if from.contains(&cmd.head) {
                            seen_from = true;
                        }
                        continue;
                    }
                    if to.contains(&cmd.head) {
                        return true;
                    }
                    // sudo <interpreter> ...
                    if cmd.head == "sudo"
                        && let Some(first) = cmd.positional().next()
                        && to.iter().any(|t| first == *t)
                    {
                        return true;
                    }
                }
                false
            }),
        },
        WhenNode::PathFilePathPrefixAny(prefixes) => match facts.path.as_ref() {
            None => facts.paths.iter().any(|path| {
                let abs = path.absolute.to_string_lossy();
                prefixes
                    .iter()
                    .any(|p| path.raw.starts_with(p) || abs.starts_with(p))
            }),
            Some(path) => {
                let abs = path.absolute.to_string_lossy();
                prefixes
                    .iter()
                    .any(|p| path.raw.starts_with(p) || abs.starts_with(p))
                    || facts.paths.iter().any(|path| {
                        let abs = path.absolute.to_string_lossy();
                        prefixes
                            .iter()
                            .any(|p| path.raw.starts_with(p) || abs.starts_with(p))
                    })
            }
        },
        WhenNode::UrlSchemeAny(schemes) => facts
            .url
            .as_ref()
            .is_some_and(|u| schemes.iter().any(|s| s.eq_ignore_ascii_case(&u.scheme))),
        WhenNode::UrlHostAny(hosts) => facts
            .url
            .as_ref()
            .is_some_and(|u| hosts.iter().any(|h| h.eq_ignore_ascii_case(&u.host))),
        WhenNode::SensitivePathAny(kinds) => facts.sensitive.iter().any(|s| {
            let tag = s.kind.as_str();
            kinds.iter().any(|k| k == tag)
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::facts;
    use serde_json::json;

    fn yaml(value: &str) -> Value {
        serde_yaml_ng::from_str::<Value>(value).expect("parse yaml")
    }

    fn bash_input(cmd: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: json!({ "command": cmd }),
        }
    }

    #[test]
    fn compiles_single_tool_leaf() {
        let v = yaml("tool: Bash\n");
        let node = compile(&v).expect("compile");
        assert_eq!(node, WhenNode::Tool("Bash".into()));
    }

    #[test]
    fn implicit_all_for_two_top_level_keys() {
        let v = yaml("tool: Bash\nevent: PreToolUse\n");
        let node = compile(&v).expect("compile");
        match node {
            WhenNode::All(children) => assert_eq!(children.len(), 2),
            other => panic!("expected All, got {other:?}"),
        }
    }

    #[test]
    fn compiles_all_with_nested_leaves() {
        let v = yaml(
            r#"
all:
  - tool: Bash
  - event: PreToolUse
"#,
        );
        let node = compile(&v).expect("compile");
        match node {
            WhenNode::All(children) => {
                assert_eq!(children[0], WhenNode::Tool("Bash".into()));
                assert_eq!(children[1], WhenNode::Event("PreToolUse".into()));
            }
            other => panic!("expected All, got {other:?}"),
        }
    }

    #[test]
    fn compiles_not_negation() {
        let v = yaml("not:\n  tool: Bash\n");
        let node = compile(&v).expect("compile");
        match node {
            WhenNode::Not(inner) => assert_eq!(*inner, WhenNode::Tool("Bash".into())),
            other => panic!("expected Not, got {other:?}"),
        }
    }

    #[test]
    fn unknown_key_is_rejected() {
        let v = yaml("frobnicate: yes\n");
        let err = compile(&v).expect_err("should fail");
        assert_eq!(err, CompileError::UnknownKey("frobnicate".into()));
    }

    #[test]
    fn shell_argv_requires_head_any() {
        let v = yaml("shell.argv: {}\n");
        let err = compile(&v).expect_err("should fail");
        assert!(matches!(err, CompileError::InvalidShape { .. }));
    }

    #[test]
    fn shell_pipeline_compiles_from_to() {
        let v = yaml(
            r#"
shell.pipeline:
  from:
    commandAny: [curl, wget]
  to:
    commandAny: [bash, sh]
"#,
        );
        let node = compile(&v).expect("compile");
        assert_eq!(
            node,
            WhenNode::ShellPipelineFromTo {
                from: vec!["curl".into(), "wget".into()],
                to: vec!["bash".into(), "sh".into()],
            }
        );
    }

    #[test]
    fn shell_pipeline_missing_to_is_rejected() {
        let v = yaml(
            r#"
shell.pipeline:
  from:
    commandAny: [curl]
"#,
        );
        let err = compile(&v).expect_err("should fail");
        assert!(matches!(err, CompileError::InvalidShape { .. }));
    }

    #[test]
    fn evaluate_tool_match() {
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        assert!(evaluate(&WhenNode::Tool("Bash".into()), &facts, &input));
        assert!(!evaluate(&WhenNode::Tool("Read".into()), &facts, &input));
    }

    #[test]
    fn evaluate_tool_any_match() {
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        let node = WhenNode::ToolAny(vec!["Bash".into(), "Read".into()]);
        assert!(evaluate(&node, &facts, &input));
    }

    #[test]
    fn evaluate_event_only_pre_tool_use() {
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        assert!(evaluate(
            &WhenNode::Event("PreToolUse".into()),
            &facts,
            &input
        ));
        assert!(!evaluate(
            &WhenNode::Event("PostToolUse".into()),
            &facts,
            &input
        ));
    }

    #[test]
    fn evaluate_shell_argv_head_any() {
        let input = bash_input("rm -rf /");
        let facts = facts::extract(&input);
        let node = WhenNode::ShellArgvHeadAny(vec!["rm".into(), "/bin/rm".into()]);
        assert!(evaluate(&node, &facts, &input));
        let node2 = WhenNode::ShellArgvHeadAny(vec!["mv".into()]);
        assert!(!evaluate(&node2, &facts, &input));
    }

    #[test]
    fn evaluate_shell_pipeline_from_to() {
        let input = bash_input("curl -fsSL https://x | bash");
        let facts = facts::extract(&input);
        let node = WhenNode::ShellPipelineFromTo {
            from: vec!["curl".into(), "wget".into()],
            to: vec!["bash".into(), "sh".into()],
        };
        assert!(evaluate(&node, &facts, &input));
    }

    #[test]
    fn evaluate_shell_pipeline_through_sudo() {
        let input = bash_input("curl -fsSL https://x | sudo bash");
        let facts = facts::extract(&input);
        let node = WhenNode::ShellPipelineFromTo {
            from: vec!["curl".into()],
            to: vec!["bash".into()],
        };
        assert!(evaluate(&node, &facts, &input));
    }

    #[test]
    fn evaluate_shell_pipeline_misses_when_order_inverted() {
        let input = bash_input("bash | curl https://x");
        let facts = facts::extract(&input);
        let node = WhenNode::ShellPipelineFromTo {
            from: vec!["curl".into()],
            to: vec!["bash".into()],
        };
        assert!(!evaluate(&node, &facts, &input));
    }

    #[test]
    fn evaluate_all_combinator() {
        let input = bash_input("rm -rf /");
        let facts = facts::extract(&input);
        let node = WhenNode::All(vec![
            WhenNode::Tool("Bash".into()),
            WhenNode::ShellArgvHeadAny(vec!["rm".into()]),
        ]);
        assert!(evaluate(&node, &facts, &input));
    }

    #[test]
    fn evaluate_any_short_circuits() {
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        let node = WhenNode::Any(vec![
            WhenNode::Tool("Read".into()),
            WhenNode::Tool("Bash".into()),
        ]);
        assert!(evaluate(&node, &facts, &input));
    }

    #[test]
    fn evaluate_not_inverts() {
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        let node = WhenNode::Not(Box::new(WhenNode::Tool("Read".into())));
        assert!(evaluate(&node, &facts, &input));
    }

    #[test]
    fn evaluate_shell_argv_returns_false_for_non_bash_input() {
        let input = HookInput {
            tool_name: "Read".into(),
            tool_input: json!({ "file_path": "/tmp/x" }),
        };
        let facts = facts::extract(&input);
        let node = WhenNode::ShellArgvHeadAny(vec!["rm".into()]);
        assert!(!evaluate(&node, &facts, &input));
    }

    #[test]
    fn evaluate_shell_pipeline_returns_false_for_non_bash_input() {
        let input = HookInput {
            tool_name: "Read".into(),
            tool_input: json!({ "file_path": "/tmp/x" }),
        };
        let facts = facts::extract(&input);
        let node = WhenNode::ShellPipelineFromTo {
            from: vec!["curl".into()],
            to: vec!["bash".into()],
        };
        assert!(!evaluate(&node, &facts, &input));
    }

    #[test]
    fn compile_error_display_covers_every_variant() {
        let unknown = CompileError::UnknownKey("foo".into());
        assert!(format!("{unknown}").contains("foo"));

        let invalid = CompileError::InvalidShape {
            key: "tool".into(),
            message: "expected string".into(),
        };
        let s = format!("{invalid}");
        assert!(s.contains("tool"));
        assert!(s.contains("expected string"));

        let empty = CompileError::EmptyMapping;
        assert!(format!("{empty}").contains("empty"));

        let not_map = CompileError::NotAMapping;
        assert!(format!("{not_map}").contains("mapping"));
    }

    #[test]
    fn compile_error_is_a_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(CompileError::EmptyMapping);
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn compile_rejects_non_mapping_top_level() {
        let v = yaml("- a\n- b\n");
        let err = compile(&v).expect_err("should fail");
        assert_eq!(err, CompileError::NotAMapping);
    }

    #[test]
    fn compile_rejects_empty_mapping() {
        let v = yaml("{}\n");
        let err = compile(&v).expect_err("should fail");
        assert_eq!(err, CompileError::EmptyMapping);
    }

    #[test]
    fn compile_rejects_non_string_key_in_single_mapping() {
        let v = yaml("1: foo\n");
        let err = compile(&v).expect_err("should fail");
        assert!(matches!(err, CompileError::InvalidShape { .. }));
    }

    #[test]
    fn compile_rejects_non_string_key_in_multi_mapping() {
        let v = yaml("tool: Bash\n1: bar\n");
        let err = compile(&v).expect_err("should fail");
        assert!(matches!(err, CompileError::InvalidShape { .. }));
    }

    #[test]
    fn compile_list_rejects_non_sequence() {
        let v = yaml("all: 42\n");
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::InvalidShape { key, message } => {
                assert_eq!(key, "all");
                assert!(message.contains("list"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn compile_list_rejects_empty_sequence() {
        let v = yaml("all: []\n");
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::InvalidShape { key, message } => {
                assert_eq!(key, "all");
                assert!(message.contains("empty"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn shell_argv_rejects_non_mapping() {
        let v = yaml("shell.argv: 42\n");
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::InvalidShape { key, .. } => assert_eq!(key, "shell.argv"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn shell_argv_rejects_non_string_key() {
        let v = yaml("shell.argv:\n  1: foo\n");
        let err = compile(&v).expect_err("should fail");
        assert!(matches!(err, CompileError::InvalidShape { .. }));
    }

    #[test]
    fn shell_argv_rejects_unknown_subkey() {
        let v = yaml("shell.argv:\n  pathAny: [/bin/rm]\n");
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::UnknownKey(k) => assert_eq!(k, "shell.argv.pathAny"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn shell_pipeline_rejects_non_mapping() {
        let v = yaml("shell.pipeline: 42\n");
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::InvalidShape { key, .. } => assert_eq!(key, "shell.pipeline"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn shell_pipeline_rejects_non_string_key() {
        let v = yaml("shell.pipeline:\n  1: bar\n");
        let err = compile(&v).expect_err("should fail");
        assert!(matches!(err, CompileError::InvalidShape { .. }));
    }

    #[test]
    fn shell_pipeline_rejects_unknown_subkey() {
        let v = yaml("shell.pipeline:\n  via:\n    commandAny: [sudo]\n");
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::UnknownKey(k) => assert_eq!(k, "shell.pipeline.via"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn shell_pipeline_rejects_missing_from() {
        let v = yaml(
            r#"
shell.pipeline:
  to:
    commandAny: [bash]
"#,
        );
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::InvalidShape { key, message } => {
                assert_eq!(key, "shell.pipeline");
                assert!(message.contains("from"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn parse_endpoint_rejects_non_mapping() {
        let v = yaml(
            r#"
shell.pipeline:
  from: 42
  to:
    commandAny: [bash]
"#,
        );
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::InvalidShape { key, .. } => assert_eq!(key, "shell.pipeline.from"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn parse_endpoint_rejects_non_string_key() {
        let v = yaml(
            r#"
shell.pipeline:
  from:
    1: foo
  to:
    commandAny: [bash]
"#,
        );
        let err = compile(&v).expect_err("should fail");
        assert!(matches!(err, CompileError::InvalidShape { .. }));
    }

    #[test]
    fn parse_endpoint_rejects_missing_command_any() {
        let v = yaml(
            r#"
shell.pipeline:
  from:
    other: value
  to:
    commandAny: [bash]
"#,
        );
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::InvalidShape { key, message } => {
                assert_eq!(key, "shell.pipeline.from");
                assert!(message.contains("commandAny"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn expect_string_rejects_non_string() {
        let v = yaml("tool: 42\n");
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::InvalidShape { key, message } => {
                assert_eq!(key, "tool");
                assert!(message.contains("string"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn expect_string_list_rejects_non_sequence() {
        let v = yaml("toolAny: 42\n");
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::InvalidShape { key, message } => {
                assert_eq!(key, "toolAny");
                assert!(message.contains("sequence"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn expect_string_list_rejects_non_string_item() {
        let v = yaml("toolAny: [Bash, 42]\n");
        let err = compile(&v).expect_err("should fail");
        match err {
            CompileError::InvalidShape { key, message } => {
                assert_eq!(key, "toolAny");
                assert!(message.contains("string"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    // --- v0.3 leaves ---------------------------------------------------

    #[test]
    fn compiles_path_file_path_prefix_any() {
        let v = yaml("path.filePathPrefixAny: [/etc/, /var/]\n");
        let node = compile(&v).expect("compile");
        assert_eq!(
            node,
            WhenNode::PathFilePathPrefixAny(vec!["/etc/".into(), "/var/".into()]),
        );
    }

    #[test]
    fn evaluate_path_prefix_against_read_input() {
        let input = HookInput {
            tool_name: "Read".into(),
            tool_input: json!({ "file_path": "/etc/shadow" }),
        };
        let facts = facts::extract(&input);
        let node = WhenNode::PathFilePathPrefixAny(vec!["/etc/".into()]);
        assert!(evaluate(&node, &facts, &input));
        let other = WhenNode::PathFilePathPrefixAny(vec!["/var/".into()]);
        assert!(!evaluate(&other, &facts, &input));
    }

    #[test]
    fn evaluate_path_prefix_returns_false_for_non_path_tool() {
        let input = bash_input("ls /etc");
        let facts = facts::extract(&input);
        let node = WhenNode::PathFilePathPrefixAny(vec!["/etc".into()]);
        assert!(!evaluate(&node, &facts, &input));
    }

    #[test]
    fn compiles_url_scheme_any_and_host_any() {
        let v = yaml(
            r#"
all:
  - url.schemeAny: [http, https]
  - url.hostAny: ["169.254.169.254"]
"#,
        );
        let node = compile(&v).expect("compile");
        match node {
            WhenNode::All(children) => {
                assert_eq!(
                    children[0],
                    WhenNode::UrlSchemeAny(vec!["http".into(), "https".into()]),
                );
                assert_eq!(
                    children[1],
                    WhenNode::UrlHostAny(vec!["169.254.169.254".into()]),
                );
            }
            other => panic!("expected All, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_url_scheme_and_host_against_webfetch() {
        let input = HookInput {
            tool_name: "WebFetch".into(),
            tool_input: json!({ "url": "http://169.254.169.254/latest/meta-data" }),
        };
        let facts = facts::extract(&input);
        let scheme = WhenNode::UrlSchemeAny(vec!["HTTP".into()]);
        assert!(evaluate(&scheme, &facts, &input));
        let host = WhenNode::UrlHostAny(vec!["169.254.169.254".into()]);
        assert!(evaluate(&host, &facts, &input));
        let other = WhenNode::UrlHostAny(vec!["example.com".into()]);
        assert!(!evaluate(&other, &facts, &input));
    }

    #[test]
    fn evaluate_url_leaves_return_false_when_no_url() {
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        assert!(!evaluate(
            &WhenNode::UrlSchemeAny(vec!["http".into()]),
            &facts,
            &input,
        ));
        assert!(!evaluate(
            &WhenNode::UrlHostAny(vec!["x".into()]),
            &facts,
            &input,
        ));
    }

    #[test]
    fn compiles_sensitive_path_kind_any() {
        let v = yaml("sensitive.pathKindAny: [ssh_dir, dotenv]\n");
        let node = compile(&v).expect("compile");
        assert_eq!(
            node,
            WhenNode::SensitivePathAny(vec!["ssh_dir".into(), "dotenv".into()]),
        );
    }

    #[test]
    fn evaluate_sensitive_kind_against_read_of_ssh() {
        let input = HookInput {
            tool_name: "Read".into(),
            tool_input: json!({ "file_path": "~/.ssh/id_ed25519" }),
        };
        let facts = facts::extract(&input);
        let node = WhenNode::SensitivePathAny(vec!["ssh_dir".into()]);
        assert!(evaluate(&node, &facts, &input));
        let other = WhenNode::SensitivePathAny(vec!["dotenv".into()]);
        assert!(!evaluate(&other, &facts, &input));
    }

    #[test]
    fn evaluate_sensitive_kind_returns_false_when_no_match() {
        let input = bash_input("ls");
        let facts = facts::extract(&input);
        let node = WhenNode::SensitivePathAny(vec!["ssh_dir".into()]);
        assert!(!evaluate(&node, &facts, &input));
    }

    #[test]
    fn new_leaf_keys_reject_non_sequence() {
        for key in [
            "path.filePathPrefixAny",
            "url.schemeAny",
            "url.hostAny",
            "sensitive.pathKindAny",
        ] {
            let v = yaml(&format!("{key}: 42\n"));
            let err = compile(&v).expect_err("should fail");
            match err {
                CompileError::InvalidShape { key: got, .. } => assert_eq!(got, key),
                other => panic!("unexpected: {other:?}"),
            }
        }
    }

    use crate::testing::proptest::richer_hook_input;
    use proptest::prelude::*;

    /// Strategy: arbitrary YAML strings drawn from a printable ASCII
    /// soup. Most will fail to parse; the ones that do parse must not
    /// cause `compile` or `evaluate` to panic.
    fn arbitrary_yaml() -> impl Strategy<Value = String> {
        "[ -~\n]{0,80}".prop_map(|s| s.to_string())
    }

    fn yaml_or_default(s: &str) -> Value {
        serde_yaml_ng::from_str::<Value>(s).unwrap_or(Value::Null)
    }

    proptest! {
        // compile never panics on arbitrary YAML strings — failures
        // come back as Err, never as a panic.
        #[test]
        fn pbt_compile_never_panics(s in arbitrary_yaml()) {
            let v = yaml_or_default(&s);
            let _ = compile(&v);
        }

        // For any compiled WhenNode, evaluate never panics on arbitrary
        // hook inputs.
        #[test]
        fn pbt_evaluate_simple_leaves_never_panic(input in richer_hook_input()) {
            let facts = crate::facts::extract(&input);
            let nodes = [
                WhenNode::Tool("Bash".into()),
                WhenNode::ToolAny(vec!["Bash".into(), "Read".into()]),
                WhenNode::Event("PreToolUse".into()),
                WhenNode::ShellArgvHeadAny(vec!["rm".into()]),
                WhenNode::ShellPipelineFromTo {
                    from: vec!["curl".into()],
                    to: vec!["bash".into()],
                },
                WhenNode::PathFilePathPrefixAny(vec!["/etc".into()]),
                WhenNode::UrlSchemeAny(vec!["http".into()]),
                WhenNode::UrlHostAny(vec!["example.com".into()]),
                WhenNode::SensitivePathAny(vec!["ssh_dir".into()]),
                WhenNode::Not(Box::new(WhenNode::Tool("Bash".into()))),
                WhenNode::All(vec![WhenNode::Tool("Bash".into())]),
                WhenNode::Any(vec![WhenNode::Tool("Bash".into())]),
            ];
            for node in &nodes {
                let _ = evaluate(node, &facts, &input);
            }
        }

        // `Tool(t)` evaluates true iff input.tool_name == t.
        #[test]
        fn pbt_tool_leaf_correct(
            input in richer_hook_input(),
            target in "[A-Z][A-Za-z]{0,8}",
        ) {
            let facts = crate::facts::extract(&input);
            let result = evaluate(&WhenNode::Tool(target.clone()), &facts, &input);
            prop_assert_eq!(result, input.tool_name == target);
        }

        // `ToolAny(list)` evaluates true iff input.tool_name is in list.
        #[test]
        fn pbt_tool_any_membership(
            input in richer_hook_input(),
            extras in proptest::collection::vec("[A-Z][A-Za-z]{0,6}", 0..3),
        ) {
            let facts = crate::facts::extract(&input);
            let result = evaluate(&WhenNode::ToolAny(extras.clone()), &facts, &input);
            prop_assert_eq!(result, extras.contains(&input.tool_name));
        }

        // `Not(child)` always inverts `child`.
        #[test]
        fn pbt_not_inverts(input in richer_hook_input(), tool in "[A-Z][A-Za-z]{0,6}") {
            let facts = crate::facts::extract(&input);
            let inner = WhenNode::Tool(tool);
            let direct = evaluate(&inner, &facts, &input);
            let negated = evaluate(&WhenNode::Not(Box::new(inner)), &facts, &input);
            prop_assert_eq!(direct, !negated);
        }

        // `All([])` is vacuously true; `Any([])` is vacuously false.
        // (compile() rejects empty mappings, but the AST itself permits
        // these and evaluate() must respect their algebraic identities.)
        #[test]
        fn pbt_all_any_vacuous(input in richer_hook_input()) {
            let facts = crate::facts::extract(&input);
            prop_assert!(evaluate(&WhenNode::All(vec![]), &facts, &input));
            prop_assert!(!evaluate(&WhenNode::Any(vec![]), &facts, &input));
        }

        // `Event(s)` only ever matches the literal "PreToolUse".
        #[test]
        fn pbt_event_only_pre_tool_use(
            input in richer_hook_input(),
            event in "[A-Za-z]{1,16}",
        ) {
            let facts = crate::facts::extract(&input);
            let result = evaluate(&WhenNode::Event(event.clone()), &facts, &input);
            prop_assert_eq!(result, event == "PreToolUse");
        }

        // shell.argv head matching is gated on facts.bash being Some,
        // which in turn requires tool_name == "Bash".
        #[test]
        fn pbt_shell_argv_requires_bash(input in richer_hook_input()) {
            let facts = crate::facts::extract(&input);
            let node = WhenNode::ShellArgvHeadAny(vec!["whatever".into()]);
            let result = evaluate(&node, &facts, &input);
            if input.tool_name != "Bash" {
                prop_assert!(!result);
            }
        }

        // url.* leaves can only match when facts.url is populated, which
        // requires tool_name == "WebFetch" with a parseable URL.
        #[test]
        fn pbt_url_leaves_require_webfetch(input in richer_hook_input()) {
            let facts = crate::facts::extract(&input);
            let scheme = WhenNode::UrlSchemeAny(vec!["http".into(), "https".into(), "ftp".into()]);
            let host = WhenNode::UrlHostAny(vec!["example.com".into(), "169.254.169.254".into()]);
            if input.tool_name != "WebFetch" {
                prop_assert!(!evaluate(&scheme, &facts, &input));
                prop_assert!(!evaluate(&host, &facts, &input));
            }
        }
    }
}
