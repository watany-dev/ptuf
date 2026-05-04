//! Reusable [`proptest`] strategies for ptuf data types.
//!
//! Strategies live in one place so per-module property tests stay
//! short and focused on the invariant under test rather than on
//! generator plumbing. The bash-command generators deliberately
//! sample three regions of the input space:
//!
//! 1. **Benign**: short alphanumeric tokens with safe heads
//!    (`ls`, `echo`, `cat`).
//! 2. **Suspicious**: heads and arguments drawn from the same
//!    vocabulary the built-in rules look for (`rm`, `curl`, `sudo`,
//!    `~/.ssh/id_rsa`, …) so rules actually fire often enough to
//!    cover their `Some(Deny)` arms.
//! 3. **Adversarial**: arbitrary printable ASCII soup that includes
//!    shell metacharacters, used to drive panic-safety properties.
//!
//! All strategies are `pub(crate)` so they are reachable from each
//! module's `#[cfg(test)] mod tests` block via
//! `crate::testing::proptest::*`, and from `tests/engine_proptest.rs`
//! through the integration-test crate that re-imports the lib.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::collection::vec;
use proptest::prelude::*;
use serde_json::json;

use crate::decision::{Decision, DecisionKind, Severity};
use crate::hook_input::HookInput;

/// Short, dotted rule identifiers similar to `core.network.foo`.
pub fn rule_id() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,5}(\\.[a-z][a-z0-9]{0,5}){1,3}".prop_map(|s| s.to_string())
}

/// Short reason strings without control characters; long enough to
/// exercise allocation but short enough to keep failure messages
/// readable.
pub fn reason_text() -> impl Strategy<Value = String> {
    "[ -~]{0,40}".prop_map(|s| s.to_string())
}

/// `Severity` variants drawn uniformly.
pub fn severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

/// `DecisionKind` variants drawn uniformly.
pub fn decision_kind() -> impl Strategy<Value = DecisionKind> {
    prop_oneof![
        Just(DecisionKind::Allow),
        Just(DecisionKind::Monitor),
        Just(DecisionKind::Ask),
        Just(DecisionKind::Deny),
    ]
}

/// Full `Decision` values across all four variants.
pub fn decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        rule_id().prop_map(|rule_id| Decision::Monitor { rule_id }),
        (rule_id(), reason_text()).prop_map(|(rule_id, reason)| Decision::Ask { rule_id, reason }),
        (rule_id(), reason_text()).prop_map(|(rule_id, reason)| Decision::Deny { rule_id, reason }),
    ]
}

/// Bounded list of decisions for `aggregate` properties.
pub fn decision_list() -> impl Strategy<Value = Vec<Decision>> {
    vec(decision(), 0..8)
}

/// Heads that the built-in rules treat as dangerous primitives.
const DANGEROUS_HEADS: &[&str] = &[
    "rm",
    "/bin/rm",
    "/usr/bin/rm",
    "curl",
    "wget",
    "fetch",
    "scp",
    "rsync",
    "nc",
    "ncat",
    "sudo",
    "bash",
    "sh",
    "zsh",
    "python",
    "python3",
    "ruby",
    "node",
];

/// Heads that no built-in rule should fire on.
const SAFE_HEADS: &[&str] = &[
    "ls", "echo", "cat", "grep", "head", "tail", "wc", "true", "false", "pwd", "date",
];

/// Arguments commonly seen alongside dangerous heads, including
/// destructive flag combinations and credential paths.
const SUSPICIOUS_ARGS: &[&str] = &[
    "-rf",
    "-fr",
    "-rfv",
    "--recursive",
    "--force",
    "/",
    "/*",
    "/etc",
    "/usr",
    "/var",
    "~",
    "~/",
    "$HOME",
    "${HOME}",
    "~/.ssh/id_rsa",
    "~/.aws/credentials",
    "~/.kube/config",
    ".env",
    ".env.production",
    "https://example.com/install.sh",
    "https://example.com/i.py",
    "id_rsa",
    "id_ed25519",
];

/// Single bash word: either a safe identifier or a sample drawn from
/// the suspicious-args list. Kept whitespace-free so the resulting
/// command parses as a single argv entry.
fn bash_word() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => "[a-zA-Z0-9_./-]{1,12}".prop_map(|s| s.to_string()),
        1 => proptest::sample::select(SUSPICIOUS_ARGS).prop_map(|s| s.to_string()),
    ]
}

fn bash_head() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => proptest::sample::select(SAFE_HEADS).prop_map(|s| s.to_string()),
        2 => proptest::sample::select(DANGEROUS_HEADS).prop_map(|s| s.to_string()),
        1 => "[a-z][a-z0-9]{0,8}".prop_map(|s| s.to_string()),
    ]
}

fn bash_argv() -> impl Strategy<Value = String> {
    (bash_head(), vec(bash_word(), 0..4)).prop_map(|(head, args)| {
        if args.is_empty() {
            head
        } else {
            format!("{} {}", head, args.join(" "))
        }
    })
}

/// One-pipeline command: zero or more `|`-joined argvs.
fn bash_pipeline() -> impl Strategy<Value = String> {
    vec(bash_argv(), 1..3).prop_map(|cmds| cmds.join(" | "))
}

/// Compound command: pipelines joined by `;`, `&&`, or `||`.
pub fn bash_command() -> impl Strategy<Value = String> {
    let sep = prop_oneof![Just("; "), Just(" && "), Just(" || ")];
    (vec(bash_pipeline(), 1..3), vec(sep, 0..3)).prop_map(|(parts, seps)| {
        let mut out = String::new();
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                let s = seps.get(i - 1).copied().unwrap_or("; ");
                out.push_str(s);
            }
            out.push_str(part);
        }
        out
    })
}

/// Adversarial bash-string generator: any printable ASCII plus the
/// metacharacters the lexer cares about. Used for panic-safety
/// properties where structure of the output is not asserted.
pub fn arbitrary_command() -> impl Strategy<Value = String> {
    "[ -~]{0,40}".prop_map(|s| s.to_string())
}

/// Hook tool names. Bash is over-represented because that is the
/// surface every built-in rule cares about.
fn tool_name() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => Just("Bash".to_string()),
        1 => proptest::sample::select(&["Read", "Write", "Edit", "Glob", "Grep"][..])
            .prop_map(|s| s.to_string()),
        1 => "[A-Z][A-Za-z]{0,8}".prop_map(|s| s.to_string()),
    ]
}

/// `HookInput` covering Bash payloads with a `command` string and
/// non-Bash payloads with miscellaneous JSON shapes.
pub fn hook_input() -> impl Strategy<Value = HookInput> {
    prop_oneof![
        4 => bash_command().prop_map(|command| HookInput {
            tool_name: "Bash".to_string(),
            tool_input: json!({ "command": command }),
        }),
        1 => (tool_name(), bash_command()).prop_map(|(tool_name, command)| HookInput {
            tool_name,
            tool_input: json!({ "command": command }),
        }),
        1 => tool_name().prop_map(|tool_name| HookInput {
            tool_name,
            tool_input: json!({}),
        }),
    ]
}

/// `HookInput` whose `tool_name` is guaranteed to be different from
/// `"Bash"`. Used by rule-level PBT to verify that no built-in rule
/// fires on non-Bash tools.
pub fn non_bash_hook_input() -> impl Strategy<Value = HookInput> {
    let names = prop_oneof![
        proptest::sample::select(&["Read", "Write", "Edit", "Glob", "Grep"][..])
            .prop_map(|s| s.to_string()),
        "[A-Z][A-Za-z]{0,8}".prop_map(|s| s.to_string()),
    ]
    .prop_filter("must not be Bash", |s| s != "Bash");
    prop_oneof![
        2 => (names.clone(), bash_command()).prop_map(|(tool_name, command)| HookInput {
            tool_name,
            tool_input: json!({ "command": command }),
        }),
        1 => names.prop_map(|tool_name| HookInput {
            tool_name,
            tool_input: json!({}),
        }),
    ]
}
