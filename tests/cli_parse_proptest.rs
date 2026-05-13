//! Property tests for [`ptuf::cli::parse`].
//!
//! `cli::parse` sits at the external argv boundary, so its key
//! invariants are *panic safety* and *totality*: every printable
//! argument list must produce either a [`Command`] or a
//! [`ParseError`], never a panic. The properties below cover the
//! happy paths for the subcommands the CLI documents, plus the
//! "unknown subcommand → error" closure.
//!
//! Strategies live in [`ptuf::testing::proptest::argv_tokens`].

#![allow(clippy::expect_used)]

use proptest::prelude::*;

use ptuf::cli::{Command, ParseError, parse};
use ptuf::testing::proptest::{arbitrary_command, argv_tokens};

/// Subcommand tokens that `parse` accepts at position 0 (in addition
/// to `--help` / `-h` / `--version` / `-V`). Held here only as
/// documentation; `unknown_head()` generates strings outside this
/// set directly to avoid global rejects under high `PROPTEST_CASES`.
const KNOWN_HEADS: &[&str] = &[
    "hook",
    "check",
    "plugin",
    "init",
    "-h",
    "--help",
    "-V",
    "--version",
    "--json",
];

/// Strategy producing a non-empty argv whose first token is **not**
/// in [`KNOWN_HEADS`]. Built by transforming arbitrary printable ASCII
/// into a guaranteed-unknown string (prefixing with `x_` if the raw
/// draw collides with a known head). Avoids `prop_assume!` so the
/// 10000-case PBT run does not hit `Too many global rejects`.
fn unknown_head() -> impl Strategy<Value = String> {
    "[!-~]{1,16}".prop_map(|s| {
        if KNOWN_HEADS.contains(&s.as_str()) {
            format!("x_{s}")
        } else {
            s
        }
    })
}

proptest! {
    // `parse` is total over arbitrary argv: it returns Result and
    // never panics, regardless of token count or content.
    #[test]
    fn pbt_parse_is_total(args in argv_tokens()) {
        let _ = parse(&args);
    }

    // `check --tool <NAME> <COMMAND>` succeeds for arbitrary command
    // strings and surfaces the original tool / command verbatim. We
    // pre-shape the command so it can never be flag-looking, avoiding
    // the historical `prop_assume!` discard. The `--` → `x--` rewrite
    // preserves the invariant under test (verbatim round-trip) because
    // the rewritten string is itself an arbitrary command argument.
    #[test]
    fn pbt_parse_check_total(
        tool in proptest::sample::select(&["Bash", "Read", "Write", "Edit"][..])
            .prop_map(std::string::ToString::to_string),
        cmd in arbitrary_command().prop_map(|c| {
            if c.starts_with("--") { format!("x{c}") } else { c }
        }),
    ) {
        let args = vec![
            "check".into(),
            "--tool".into(),
            tool.clone(),
            cmd.clone(),
        ];
        match parse(&args) {
            Ok((_, Command::Check { tool: got_tool, command: got_cmd })) => {
                prop_assert_eq!(got_tool, tool);
                prop_assert_eq!(got_cmd, cmd);
            }
            other => prop_assert!(false, "expected Check, got {other:?}"),
        }
    }

    // `init [<agent>] [...flags]` with random argv tails never panics.
    // Outcome is either Ok((_, Init(_))) or a ParseError.
    #[test]
    fn pbt_parse_init_total(
        agent in proptest::option::of(
            proptest::sample::select(&["claude-code", "codex", "copilot", "kiro"][..])
                .prop_map(std::string::ToString::to_string)
        ),
        tail in argv_tokens(),
    ) {
        let mut args = vec!["init".to_string()];
        if let Some(a) = agent {
            args.push(a);
        }
        args.extend(tail);
        match parse(&args) {
            Ok((_, Command::Init(_))) | Err(_) => {}
            other => prop_assert!(
                false,
                "init returned unexpected variant {other:?}",
            ),
        }
    }

    // `--json` may appear before any subcommand and should never panic.
    #[test]
    fn pbt_parse_global_json_total(tail in argv_tokens()) {
        let mut args = vec!["--json".to_string()];
        args.extend(tail);
        let _ = parse(&args);
    }

    // Any first token that is not in the known-head set must surface
    // as ParseError::UnknownCommand. Exhaustively encodes "fail closed
    // on unknown subcommand" at the parser layer.
    #[test]
    fn pbt_parse_unknown_subcommand_yields_err(
        head in unknown_head(),
        tail in argv_tokens(),
    ) {
        let mut args = vec![head.clone()];
        args.extend(tail);
        match parse(&args) {
            Err(ParseError::UnknownCommand(c)) => prop_assert_eq!(c, head),
            other => prop_assert!(
                false,
                "unknown head {head:?} should produce UnknownCommand, got {other:?}",
            ),
        }
    }
}
