//! Adversarial bypass regression corpus.
//!
//! `tests/bypass/corpus.jsonl` is a version-controlled negative-security
//! suite — each line is one evasion attempt against the guardrail. It is
//! differential from the proptest layer: PBT explores random structured
//! inputs, this corpus pins *named, curated* adversarial cases so a fix
//! never silently regresses.
//!
//! Two expectation kinds:
//!
//! - `must_catch` — the engine must still block. The decision rank must be
//!   at least the recorded `decision` (`deny >= ask >= monitor >= allow`).
//! - `known_gap` — a documented limitation (see `docs/adr/0001-env-protection-gaps.md`).
//!   The decision must equal the recorded value exactly, so both a
//!   regression *and* an unannounced improvement surface as a failure and
//!   force the corpus to be updated.
//!
//! New bypasses found by fuzzing (`fuzz/`) or by audit are appended to
//! `corpus.jsonl`.

use ptuf::decision::DecisionKind;
use ptuf::{Engine, HookInput};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    hook_input: HookInput,
    expect: Expect,
    /// When true, decide under `Config.readonly = true`.
    #[serde(default)]
    readonly: bool,
}

#[derive(Debug, Deserialize)]
struct Expect {
    kind: ExpectKind,
    decision: DecisionKind,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ExpectKind {
    MustCatch,
    KnownGap,
}

#[test]
fn bypass_corpus_holds() {
    let raw = include_str!("bypass/corpus.jsonl");
    let engine = Engine::builder()
        .agent("bypass-corpus")
        .build()
        .expect("default-config engine builds");
    let readonly_engine = Engine::builder()
        .config(ptuf::config::Config {
            readonly: true,
            ..ptuf::config::Config::default()
        })
        .agent("bypass-corpus-readonly")
        .build()
        .expect("readonly-config engine builds");

    let mut cases = 0_usize;
    let mut failures: Vec<String> = Vec::new();

    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let case: Case = serde_json::from_str(trimmed)
            .unwrap_or_else(|e| panic!("corpus.jsonl:{}: invalid JSON: {e}", idx + 1));
        cases += 1;

        let engine = if case.readonly {
            &readonly_engine
        } else {
            &engine
        };
        let got = engine.decide(&case.hook_input).decision.kind();
        let ok = match case.expect.kind {
            ExpectKind::MustCatch => got >= case.expect.decision,
            ExpectKind::KnownGap => got == case.expect.decision,
        };
        if !ok {
            failures.push(format!(
                "[{}] ({:?}): expected {:?}, got {:?}",
                case.id, case.expect.kind, case.expect.decision, got,
            ));
        }
    }

    assert!(cases > 0, "corpus.jsonl yielded no cases");
    assert!(
        failures.is_empty(),
        "{} of {cases} bypass corpus case(s) failed:\n{}",
        failures.len(),
        failures.join("\n"),
    );
}
