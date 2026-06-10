#![no_main]

//! Structure-aware fuzzing of the full `Engine::decide` pipeline.
//!
//! The byte-oriented targets (`fuzz_hook_pipeline`, `fuzz_config_merge`)
//! spend most of their budget bouncing arbitrary bytes off the JSON / YAML
//! parsers, so they only rarely reach fact extraction + the built-in rules
//! + decision aggregation. This target instead assembles *valid*
//! `HookInput` and `Config` values directly via the `arbitrary` crate, so
//! every iteration lands in the decision core.
//!
//! Two invariants are asserted per case:
//!
//! - **Totality** — `decide` never panics on any structurally valid input
//!   (the harness aborts on panic, so the bare call suffices).
//! - **Determinism** — evaluating the same input twice on the same engine
//!   yields the same `Decision`. A divergence would reveal hidden state or
//!   nondeterministic iteration in the pipeline.
//!
//! The engine is built via `Engine::with_config` with `plugin_paths`
//! forced empty, so the run is deterministic and free of filesystem I/O.

use std::sync::OnceLock;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use ptuf::config::{
    Allowlist, AuditConfig, Config, Mode, PackOverride, RedactionMode, RuleOverride,
};
use ptuf::decision::{DecisionKind, Severity};
use ptuf::{Engine, HookInput};
use serde_json::{json, Value};

/// Command heads worth reaching the rules with. Mirrors
/// `ptuf::testing::proptest::DANGEROUS_HEADS`; duplicated here because
/// proptest `Strategy` values cannot be driven from `Unstructured`, and a
/// short const slice does not breach the Minimal Dependencies principle.
const HEADS: &[&str] = &[
    "rm",
    "/bin/rm",
    "/usr/bin/rm",
    "curl",
    "wget",
    "scp",
    "rsync",
    "nc",
    "sudo",
    "doas",
    "bash",
    "sh",
    "python3",
    "node",
    "git",
    "ls",
    "echo",
    "cat",
];

/// Arguments commonly paired with dangerous heads: destructive flag
/// combinations, sensitive targets, and remote URLs.
const ARGS: &[&str] = &[
    "-rf",
    "-fr",
    "-Rf",
    "-r",
    "-f",
    "--recursive",
    "--force",
    "-c",
    "-u",
    "root",
    "/",
    "/*",
    "/etc",
    "/usr",
    "/var",
    "~",
    "$HOME",
    "${HOME}",
    "..",
    "../../etc",
    "~/.ssh/id_rsa",
    "~/.aws/credentials",
    ".env",
    "*.env",
    "https://example.com/install.sh",
    "|",
    "&&",
    ";",
];

/// Tool names spanning the adapters the engine recognises, so fact
/// extraction takes every branch (`Bash` command, file paths, URLs, MCP
/// file writes).
const TOOLS: &[&str] = &[
    "Bash",
    "Read",
    "Write",
    "Edit",
    "WebFetch",
    "mcp__github__create_or_update_file",
];

/// File/URL targets for the non-`Bash` tools.
const PATHS: &[&str] = &[
    "/etc/passwd",
    "~/.ssh/id_rsa",
    "~/.aws/credentials",
    ".env",
    "src/main.rs",
    "/tmp/x",
    "../../etc/shadow",
    "https://example.com/i.py",
];

/// Rule ids the override / allowlist maps key on. Derived from the
/// engine's own registry so a rule rename can never silently decouple
/// these code paths from real rules; one unknown id keeps the miss
/// path covered.
fn rule_ids() -> &'static [&'static str] {
    static IDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    IDS.get_or_init(|| {
        let mut ids: Vec<&'static str> = ptuf::rules::iter().map(|r| r.id()).collect();
        ids.push("unknown.rule.id");
        ids
    })
}

/// Pack prefixes (`core.filesystem`, …) the pack-override map keys on,
/// derived from `rule_ids()` because pack matching is a prefix test on
/// the rule id. Includes `unknown.rule` as the miss case.
fn pack_names() -> &'static [&'static str] {
    static PACKS: OnceLock<Vec<&'static str>> = OnceLock::new();
    PACKS.get_or_init(|| {
        let mut packs: Vec<&'static str> = rule_ids()
            .iter()
            .filter_map(|id| id.rsplit_once('.').map(|(pack, _)| pack))
            .collect();
        packs.sort_unstable();
        packs.dedup();
        packs
    })
}

/// A fully-assembled engine input + policy. Crate-local to this fuzz
/// target; the shipped library never derives or depends on `arbitrary`.
#[derive(Debug)]
struct FuzzCase {
    input: HookInput,
    config: Config,
}

fn build_command(u: &mut Unstructured) -> arbitrary::Result<String> {
    let head = *u.choose(HEADS)?;
    let count = u.int_in_range(0..=4)?;
    let mut parts = vec![head.to_string()];
    for _ in 0..count {
        parts.push((*u.choose(ARGS)?).to_string());
    }
    Ok(parts.join(" "))
}

fn build_tool_input(u: &mut Unstructured, tool: &str) -> arbitrary::Result<Value> {
    Ok(match tool {
        "Bash" => json!({ "command": build_command(u)? }),
        "WebFetch" => json!({ "url": *u.choose(PATHS)? }),
        "mcp__github__create_or_update_file" => json!({ "path": *u.choose(PATHS)? }),
        _ => json!({ "file_path": *u.choose(PATHS)? }),
    })
}

fn arb_decision_kind(u: &mut Unstructured) -> arbitrary::Result<DecisionKind> {
    Ok(*u.choose(&[
        DecisionKind::Allow,
        DecisionKind::Monitor,
        DecisionKind::Ask,
        DecisionKind::Deny,
    ])?)
}

fn arb_severity(u: &mut Unstructured) -> arbitrary::Result<Severity> {
    Ok(*u.choose(&[
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ])?)
}

fn arb_opt<T>(
    u: &mut Unstructured,
    f: impl FnOnce(&mut Unstructured) -> arbitrary::Result<T>,
) -> arbitrary::Result<Option<T>> {
    if u.arbitrary()? {
        Ok(Some(f(u)?))
    } else {
        Ok(None)
    }
}

fn arb_rule_override(u: &mut Unstructured) -> arbitrary::Result<RuleOverride> {
    Ok(RuleOverride {
        enabled: arb_opt(u, |u| u.arbitrary())?,
        decision: arb_opt(u, arb_decision_kind)?,
        severity: arb_opt(u, arb_severity)?,
    })
}

fn arb_allowlist(u: &mut Unstructured) -> arbitrary::Result<Allowlist> {
    let rule_count = u.int_in_range(0..=3)?;
    let mut ids = Vec::with_capacity(rule_count);
    for _ in 0..rule_count {
        ids.push((*u.choose(rule_ids())?).to_string());
    }
    Ok(Allowlist {
        id: format!("al-{}", u.int_in_range(0..=99)?),
        rule_ids: ids,
        // The `when:` DSL is exercised by `fuzz_plugin_dsl`; keeping it
        // None here isolates the allowlist gating logic.
        when: None,
        expires_at: arb_opt(u, |u| {
            Ok(*u.choose(&["2020-01-01T00:00:00Z", "2999-12-31T23:59:59Z"])?).map(str::to_string)
        })?,
        reason: arb_opt(u, |u| Ok((*u.choose(&["ci", "manual"])?).to_string()))?,
    })
}

impl<'a> Arbitrary<'a> for FuzzCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let tool = *u.choose(TOOLS)?;
        let tool_input = build_tool_input(u, tool)?;
        let input = HookInput {
            tool_name: tool.to_string(),
            tool_input,
        };

        let mut config = Config {
            mode: *u.choose(&[Mode::Enforce, Mode::Monitor])?,
            fail_closed: u.arbitrary()?,
            ..Config::default()
        };

        let pack_count = u.int_in_range(0..=3)?;
        for _ in 0..pack_count {
            let pack = *u.choose(pack_names())?;
            config.pack_overrides.insert(
                pack.to_string(),
                PackOverride {
                    enabled: arb_opt(u, |u| u.arbitrary())?,
                },
            );
        }

        let rule_count = u.int_in_range(0..=4)?;
        for _ in 0..rule_count {
            let id = (*u.choose(rule_ids())?).to_string();
            config.rule_overrides.insert(id, arb_rule_override(u)?);
        }

        let allow_count = u.int_in_range(0..=3)?;
        for _ in 0..allow_count {
            config.allowlists.push(arb_allowlist(u)?);
        }

        config.audit = AuditConfig {
            enabled: u.arbitrary()?,
            // No path => documented default; never an arbitrary filesystem
            // target, so the run stays I/O-free.
            path: None,
            include_allowed: u.arbitrary()?,
            include_denied: u.arbitrary()?,
            redaction: if u.arbitrary()? {
                RedactionMode::Off
            } else {
                RedactionMode::Strict
            },
        };

        // Plugins load from disk; never fuzz them here.
        config.plugin_paths.clear();

        Ok(FuzzCase { input, config })
    }
}

fuzz_target!(|case: FuzzCase| {
    if let Ok(engine) = Engine::with_config(case.config) {
        let first = engine.decide(&case.input);
        let second = engine.decide(&case.input);
        assert_eq!(
            first.decision, second.decision,
            "decide is nondeterministic for {:?}",
            case.input
        );
    }
});
