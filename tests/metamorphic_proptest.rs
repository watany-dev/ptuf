//! Metamorphic / monotonicity property tests for the decision pipeline.
//!
//! The rest of the PBT suite checks *intrinsic* properties of a single
//! evaluation (panic-safety, totality, the `aggregate` algebra). This file
//! owns the *relational* property that most directly defends ptuf's
//! bypass-resistance claim: rewriting a command in a way that does not
//! change its meaning must never weaken the engine's decision.
//!
//! Two layers cooperate:
//!
//! - The **H** group ("soundness") re-parses each rewritten command and
//!   checks the decision-relevant tokens round-trip as intended. If a
//!   transform in `ptuf::testing::proptest` is buggy, an H property fails
//!   first, so a red P property always points at the engine, not the
//!   generator.
//! - The **P** group asserts the monotonicity itself. Transforms that fully
//!   preserve meaning (alternate `rm` spellings, quoting) assert decision
//!   *equality* (`==`); transforms that can only add risk (privilege
//!   wrappers, `bash -c` nesting, compounding with a benign segment) assert
//!   the decision is *at least as strict* (`>=`), compared via the public
//!   `DecisionKind` ordering (`Allow < Monitor < Ask < Deny`).
//!
//! Mode demotion monotonicity already lives in `tests/filter_proptest.rs`
//! and is intentionally not duplicated here.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;
use std::sync::OnceLock;

use proptest::prelude::*;

use ptuf::decision::DecisionKind;
use ptuf::facts::sensitive::{self, SensitiveKind};
use ptuf::facts::shell;
use ptuf::testing::proptest::{
    conjoin_safe, dangerous_rm_tokens, insert_harmless_flag, normalize_sensitive_path,
    privilege_wrap, quote_token, render_tokens, rewrite_rm_head, sensitive_base_path, shellc_wrap,
    split_bundled_flag, whitespace_join,
};
use ptuf::{Engine, HookInput};

/// Default engine via the public builder, shared across all properties:
/// `Engine::with_config` collects project facts and opens the audit
/// sink, which is wasted work when rebuilt for every proptest case.
/// Cannot fail for the default config because it lists no plugin paths.
fn default_engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        Engine::builder()
            .build()
            .expect("Engine::builder with default config cannot fail")
    })
}

fn bash(cmd: &str) -> HookInput {
    HookInput {
        tool_name: "Bash".into(),
        tool_input: serde_json::json!({ "command": cmd }),
    }
}

fn kind_of(engine: &Engine, cmd: &str) -> DecisionKind {
    engine.decide(&bash(cmd)).decision.kind()
}

/// Head + args of the first surfaced command, flattened back into a token
/// vector for round-trip comparison.
fn first_command_tokens(cmd: &str) -> Vec<String> {
    let parsed = shell::parse(cmd);
    let commands = parsed.commands();
    let first = commands.first().expect("at least one command");
    let mut tokens = vec![first.head.clone()];
    tokens.extend(first.args.clone());
    tokens
}

/// `true` if some surfaced command flattens to exactly `tokens` (used to
/// confirm a wrapper still exposes its inner command to the rules).
fn surfaces_command(cmd: &str, tokens: &[String]) -> bool {
    let parsed = shell::parse(cmd);
    parsed.commands().iter().any(|c| {
        let mut flat = vec![c.head.clone()];
        flat.extend(c.args.clone());
        flat == tokens
    })
}

fn sensitive_kinds(path: &str) -> HashSet<SensitiveKind> {
    sensitive::classify(path)
        .into_iter()
        .map(|s| s.kind)
        .collect()
}

proptest! {
    // --- H group: transform soundness ------------------------------------

    // Inserting a harmless flag adds exactly that token and nothing else.
    #[test]
    fn pbt_harmless_flag_preserves_argv_shape(base in dangerous_rm_tokens()) {
        let mutated = insert_harmless_flag(&base);
        prop_assert_eq!(first_command_tokens(&render_tokens(&mutated)), mutated);
    }

    // Splitting a bundled short flag round-trips to the split token vector.
    #[test]
    fn pbt_split_bundled_flags_preserves_argv_shape(base in dangerous_rm_tokens()) {
        let mutated = split_bundled_flag(&base);
        prop_assert_eq!(first_command_tokens(&render_tokens(&mutated)), mutated);
    }

    // Rewriting the rm head round-trips to the rewritten token vector.
    #[test]
    fn pbt_rm_head_form_preserves_argv_shape(
        base in dangerous_rm_tokens(),
        form in any::<usize>(),
    ) {
        let mutated = rewrite_rm_head(&base, form);
        prop_assert_eq!(first_command_tokens(&render_tokens(&mutated)), mutated);
    }

    // A privilege wrapper round-trips to the wrapper-prefixed token vector
    // (the rule, not the parser, unwraps it — so the outer argv stays whole).
    #[test]
    fn pbt_privilege_wrap_preserves_argv_shape(
        base in dangerous_rm_tokens(),
        form in any::<usize>(),
    ) {
        let mutated = privilege_wrap(&base, form);
        prop_assert_eq!(first_command_tokens(&render_tokens(&mutated)), mutated);
    }

    // Quoting strips back to the original tokens.
    #[test]
    fn pbt_quote_insertion_preserves_argv_shape(
        base in dangerous_rm_tokens(),
        idx in any::<usize>(),
        form in any::<usize>(),
    ) {
        let mutated = quote_token(&base, idx, form);
        prop_assert_eq!(first_command_tokens(&render_tokens(&mutated)), base);
    }

    // Extra inter-token whitespace is insignificant.
    #[test]
    fn pbt_whitespace_pad_preserves_argv_shape(
        base in dangerous_rm_tokens(),
        widths in proptest::collection::vec(any::<usize>(), 0..6),
    ) {
        prop_assert_eq!(first_command_tokens(&whitespace_join(&base, &widths)), base);
    }

    // `bash -c '…'` still surfaces the inner command to the rules.
    #[test]
    fn pbt_shellc_wrap_surfaces_inner_command(base in dangerous_rm_tokens()) {
        let cmd = shellc_wrap(&render_tokens(&base));
        prop_assert!(surfaces_command(&cmd, &base), "inner not surfaced: {}", cmd);
    }

    // Compounding with a benign segment leaves the dangerous segment intact.
    #[test]
    fn pbt_conjunction_surfaces_dangerous_segment(
        base in dangerous_rm_tokens(),
        form in any::<usize>(),
    ) {
        let cmd = conjoin_safe(&render_tokens(&base), form);
        prop_assert!(surfaces_command(&cmd, &base), "segment dropped: {}", cmd);
    }

    // --- P group: decision monotonicity ----------------------------------

    // P1: any sequence of token-level transforms plus an optional string
    // wrap never weakens the decision.
    #[test]
    fn pbt_spt_preserves_or_strengthens_decision(
        base in dangerous_rm_tokens(),
        ops in proptest::collection::vec(0usize..5, 1..4),
        idx in any::<usize>(),
        form in any::<usize>(),
        widths in proptest::collection::vec(any::<usize>(), 0..6),
        wrap in 0usize..4,
    ) {
        let engine = default_engine();
        let base_kind = kind_of(engine, &render_tokens(&base));
        prop_assume!(base_kind == DecisionKind::Deny);

        let mut tokens = base;
        for op in &ops {
            tokens = match op % 5 {
                0 => split_bundled_flag(&tokens),
                1 => rewrite_rm_head(&tokens, *op),
                2 => insert_harmless_flag(&tokens),
                3 => privilege_wrap(&tokens, *op),
                _ => quote_token(&tokens, idx, form),
            };
        }
        let mut cmd = whitespace_join(&tokens, &widths);
        cmd = match wrap {
            1 => shellc_wrap(&cmd),
            2 => conjoin_safe(&cmd, form),
            3 => shellc_wrap(&conjoin_safe(&cmd, form)),
            _ => cmd,
        };

        prop_assert!(
            kind_of(engine, &cmd) >= base_kind,
            "decision weakened by transform: {}",
            cmd
        );
    }

    // P2: splitting a bundled flag (`-rf` -> `-r -f`) keeps the deny.
    #[test]
    fn pbt_split_bundled_flags_keeps_deny(base in dangerous_rm_tokens()) {
        let engine = default_engine();
        let base_kind = kind_of(engine, &render_tokens(&base));
        let mutated = render_tokens(&split_bundled_flag(&base));
        prop_assert!(kind_of(engine, &mutated) >= base_kind);
    }

    // P3: a recognised privilege wrapper keeps the deny.
    #[test]
    fn pbt_privilege_wrap_keeps_deny(
        base in dangerous_rm_tokens(),
        form in any::<usize>(),
    ) {
        let engine = default_engine();
        let base_kind = kind_of(engine, &render_tokens(&base));
        let mutated = render_tokens(&privilege_wrap(&base, form));
        prop_assert!(kind_of(engine, &mutated) >= base_kind);
    }

    // P4: `bash -c '…'` nesting keeps the deny.
    #[test]
    fn pbt_shellc_wrap_keeps_deny(base in dangerous_rm_tokens()) {
        let engine = default_engine();
        let base_kind = kind_of(engine, &render_tokens(&base));
        let mutated = shellc_wrap(&render_tokens(&base));
        prop_assert!(kind_of(engine, &mutated) >= base_kind);
    }

    // P5: alternate rm head spellings leave the decision unchanged.
    #[test]
    fn pbt_rm_head_path_form_invariant(
        base in dangerous_rm_tokens(),
        form in any::<usize>(),
    ) {
        let engine = default_engine();
        let base_kind = kind_of(engine, &render_tokens(&base));
        let mutated = render_tokens(&rewrite_rm_head(&base, form));
        prop_assert_eq!(kind_of(engine, &mutated), base_kind);
    }

    // P6: semantics-preserving quoting leaves the decision unchanged.
    #[test]
    fn pbt_quote_insertion_invariant(
        base in dangerous_rm_tokens(),
        idx in any::<usize>(),
        form in any::<usize>(),
    ) {
        let engine = default_engine();
        let base_kind = kind_of(engine, &render_tokens(&base));
        let mutated = render_tokens(&quote_token(&base, idx, form));
        prop_assert_eq!(kind_of(engine, &mutated), base_kind);
    }

    // P7: compounding a deny with a benign segment preserves the danger.
    #[test]
    fn pbt_conjunction_preserves_danger(
        base in dangerous_rm_tokens(),
        form in any::<usize>(),
    ) {
        let engine = default_engine();
        let base_kind = kind_of(engine, &render_tokens(&base));
        let mutated = conjoin_safe(&render_tokens(&base), form);
        prop_assert!(kind_of(engine, &mutated) >= base_kind);
    }

    // P8: normalising a sensitive path keeps every recognised kind.
    #[test]
    fn pbt_sensitive_path_norm_keeps_classification(
        base in sensitive_base_path(),
        form in any::<usize>(),
    ) {
        let base_kinds = sensitive_kinds(&base);
        prop_assume!(!base_kinds.is_empty());
        let mutated = normalize_sensitive_path(&base, form);
        let mutated_kinds = sensitive_kinds(&mutated);
        prop_assert!(
            base_kinds.is_subset(&mutated_kinds),
            "classification lost: base={} mutated={}",
            base,
            mutated
        );
    }
}
