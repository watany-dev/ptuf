//! `core.engine.dynamic-eval` — Ask before running interpreters whose
//! `-c` / `-e` / first-positional argument hides code from the parser
//! (so other built-in rules cannot inspect what will actually run).

use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::facts::shell::{Argv, unwrap_prefix_wrapper};
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;

pub struct DynamicEval;

const RULE_ID: &str = "core.engine.dynamic-eval";

#[derive(Debug, Clone, Copy)]
enum EvalShape {
    FlagDashC,
    FlagDashE,
    FlagDashCorE,
    FirstPositional,
}

const DYNAMIC_EVAL_HEADS: &[(&str, EvalShape)] = &[
    ("bash", EvalShape::FlagDashC),
    ("sh", EvalShape::FlagDashC),
    ("zsh", EvalShape::FlagDashC),
    ("ksh", EvalShape::FlagDashC),
    ("dash", EvalShape::FlagDashC),
    ("fish", EvalShape::FlagDashC),
    ("python", EvalShape::FlagDashC),
    ("python3", EvalShape::FlagDashC),
    ("ruby", EvalShape::FlagDashCorE),
    ("perl", EvalShape::FlagDashE),
    ("node", EvalShape::FlagDashE),
    ("eval", EvalShape::FirstPositional),
];

impl ConfigRule for DynamicEval {
    fn id(&self) -> &str {
        RULE_ID
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn default_decision(&self) -> DecisionKind {
        DecisionKind::Ask
    }

    fn overridable(&self) -> bool {
        true
    }

    fn hard_deny(&self) -> bool {
        false
    }

    fn evaluate(&self, facts: &Facts, _input: &HookInput) -> Option<Decision> {
        let bash = facts.bash.as_ref()?;
        let triggered = bash.commands().into_iter().any(invokes_dynamic_eval);
        if !triggered {
            return None;
        }

        let reason = reason::build(
            RULE_ID,
            "The command loads code at runtime through an interpreter flag \
             (`bash -c`, `python -c`, `node -e`, `eval`, …). The inner code is \
             opaque to ptuf, so other rules cannot inspect what will actually run.",
            &[
                "Save the inner code to a script file and run that file directly.",
                "Show the inner code to the user before approving.",
                "Suppress this rule via an allowlist when the inner code is trusted.",
            ],
        );

        Some(Decision::Ask {
            rule_id: RULE_ID.into(),
            reason,
        })
    }
}

fn invokes_dynamic_eval(argv: &Argv) -> bool {
    if matches_dynamic_eval(argv) {
        return true;
    }
    if let Some(unwrapped) = unwrap_prefix_wrapper(argv) {
        return matches_dynamic_eval(&unwrapped);
    }
    false
}

fn matches_dynamic_eval(argv: &Argv) -> bool {
    let head = head_basename(&argv.head);
    let Some(shape) = DYNAMIC_EVAL_HEADS
        .iter()
        .find(|(name, _)| *name == head)
        .map(|(_, shape)| *shape)
    else {
        return false;
    };
    shape_triggers(shape, &argv.args)
}

fn head_basename(head: &str) -> &str {
    head.rsplit('/').next().unwrap_or(head)
}

fn shape_triggers(shape: EvalShape, args: &[String]) -> bool {
    match shape {
        EvalShape::FlagDashC => has_flag_with_value(args, "-c"),
        EvalShape::FlagDashE => has_flag_with_value(args, "-e"),
        EvalShape::FlagDashCorE => {
            has_flag_with_value(args, "-c") || has_flag_with_value(args, "-e")
        },
        EvalShape::FirstPositional => args.iter().any(|a| !a.starts_with('-')),
    }
}

/// Return `true` when `args` contains `flag` followed by another arg, i.e.
/// the interpreter is actually being asked to evaluate code.
fn has_flag_with_value(args: &[String], flag: &str) -> bool {
    let Some(short_flag) = flag
        .strip_prefix('-')
        .filter(|rest| rest.len() == 1)
        .and_then(|rest| rest.chars().next())
    else {
        return false;
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag || short_flag_cluster_contains(arg, short_flag) {
            return iter.next().is_some();
        }
    }
    false
}

fn short_flag_cluster_contains(arg: &str, flag: char) -> bool {
    let Some(rest) = arg.strip_prefix('-') else {
        return false;
    };
    if rest.starts_with('-') || rest.is_empty() {
        return false;
    }
    rest.chars().any(|c| c == flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": cmd }),
        }
    }

    fn evaluate_for(input: &HookInput) -> Option<Decision> {
        let facts = crate::facts::extract(input);
        DynamicEval.evaluate(&facts, input)
    }

    fn assert_ask(cmd: &str) {
        let input = bash(cmd);
        let result = evaluate_for(&input);
        assert!(
            matches!(&result, Some(Decision::Ask { rule_id, .. }) if rule_id == RULE_ID),
            "expected ask for {cmd:?}, got {result:?}",
        );
    }

    fn assert_allow(cmd: &str) {
        let input = bash(cmd);
        let result = evaluate_for(&input);
        assert!(
            result.is_none(),
            "expected allow for {cmd:?}, got {result:?}"
        );
    }

    #[test]
    fn asks_on_bash_dash_c() {
        assert_ask("bash -c 'echo hi'");
    }

    #[test]
    fn asks_on_interpreter_dash_eval_flags() {
        for cmd in [
            "sh -c 'rm -rf /'",
            "python -c 'import os; os.system(\"id\")'",
            "python3 -c 'print(1)'",
            "node -e 'console.log(1)'",
            "perl -e 'print 1'",
            "ruby -e 'puts 1'",
            "ruby -c file.rb",
        ] {
            assert_ask(cmd);
        }
    }

    #[test]
    fn asks_on_combined_shell_short_options() {
        assert_ask("bash -lc 'echo hi'");
        assert_ask("sh -ec 'echo hi'");
    }

    #[test]
    fn asks_on_eval_first_positional() {
        assert_ask("eval 'echo hi'");
    }

    #[test]
    fn asks_on_sudo_bash_dash_c() {
        assert_ask("sudo bash -c 'echo hi'");
        assert_ask("sudo -u root python -c 'pass'");
    }

    #[test]
    fn asks_on_absolute_path_head() {
        assert_ask("/usr/bin/bash -c 'echo hi'");
    }

    #[test]
    fn asks_on_find_exec_eval_wrapper_itself() {
        assert_ask(r"find . -exec bash -c 'echo hi' \;");
    }

    #[test]
    fn allows_bash_login_shell() {
        assert_allow("bash --login");
        assert_allow("bash");
    }

    #[test]
    fn allows_python_repl_or_script() {
        assert_allow("python file.py");
        assert_allow("python3");
    }

    #[test]
    fn allows_eval_without_argument() {
        assert_allow("eval");
        // `eval -x` has no positional args, so we do not fire.
        assert_allow("eval -x");
    }

    #[test]
    fn allows_dash_c_without_value() {
        assert_allow("bash -c");
    }

    #[test]
    fn allows_unrelated_command() {
        assert_allow("echo hello");
        assert_allow("ls -la");
    }

    #[test]
    fn ignores_non_bash_tools() {
        let input = HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({ "command": "bash -c 'rm -rf /'" }),
        };
        let facts = crate::facts::extract(&input);
        assert!(DynamicEval.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn fires_inside_pipeline() {
        assert_ask("ls | bash -c 'cat'");
    }

    #[test]
    fn fires_after_separator() {
        assert_ask("echo hi; bash -c 'rm tmp'");
    }

    use crate::testing::proptest::{arbitrary_command, bash_command, non_bash_hook_input};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pbt_non_bash_yields_none(input in non_bash_hook_input()) {
            prop_assert!(evaluate_for(&input).is_none());
        }

        #[test]
        fn pbt_evaluate_never_panics(cmd in arbitrary_command()) {
            let input = bash(&cmd);
            let _ = evaluate_for(&input);
        }

        #[test]
        fn pbt_only_emits_ask_with_correct_id(cmd in bash_command()) {
            let input = bash(&cmd);
            if let Some(d) = evaluate_for(&input) {
                match d {
                    Decision::Ask { rule_id, .. } => prop_assert_eq!(rule_id, RULE_ID),
                    other => prop_assert!(
                        false,
                        "expected Ask, got {other:?}",
                    ),
                }
            }
        }

        // Negative space: heads outside the dynamic-eval table never fire.
        #[test]
        fn pbt_no_dynamic_head_means_no_fire(
            head in "[a-z][a-z0-9]{0,5}",
            args in proptest::collection::vec("[a-zA-Z0-9_./-]{1,8}", 0..3),
        ) {
            let known: Vec<&str> = DYNAMIC_EVAL_HEADS.iter().map(|(n, _)| *n).collect();
            prop_assume!(!known.contains(&head.as_str()));
            let cmd = if args.is_empty() {
                head
            } else {
                format!("{} {}", head, args.join(" "))
            };
            let input = bash(&cmd);
            prop_assert!(evaluate_for(&input).is_none());
        }
    }
}
