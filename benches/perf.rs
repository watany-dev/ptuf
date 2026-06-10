//! Micro-benchmarks for the hot paths flagged in the performance review.
//!
//! All fixtures are built through ptuf's public API (`Engine::with_config`,
//! `Engine::decide`, `config::yaml` / `config::merge`, `plugin::loader`) so
//! the benches stay at the same boundary a hook invocation hits, without
//! exposing internal helpers. Each bench scales the dimension that the
//! flagged code is `O(.)` in so the growth curve is visible:
//!
//! - H2 `decide_allowlist_scan`  — allowlist entry count (linear scan + RFC3339 parse per entry)
//! - H3 `decide_pack_disabled`   — pack-override count (per-rule `format!` allocation)
//! - H4 `decide_sensitive_class` — bash token count (11 regexes per token)
//! - H1 `plugin_load`            — rule count (per-rule `clone_raw_rule` of test metadata)
//! - M1 `config_load`            — fixed 4-layer parse + merge baseline
//! - M2 `decide_shell_parse`     — command byte length (single tokenize pass)
//!
//! Run with `cargo bench --bench perf`.

use divan::{Bencher, black_box};
use ptuf::config::{Allowlist, AuditConfig, Config, PackOverride};
use ptuf::{Engine, HookInput};

fn main() {
    divan::main();
}

// --- shared fixture helpers -------------------------------------------------

/// Audit disabled so `decide` benches measure rule logic, not sink I/O.
fn quiet_audit() -> AuditConfig {
    AuditConfig {
        include_allowed: false,
        include_denied: false,
        ..AuditConfig::default()
    }
}

/// A Bash payload. `bash_command` only fires for `tool_name == "Bash"`.
fn bash_input(command: String) -> HookInput {
    HookInput {
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({ "command": command }),
    }
}

/// `rm -rf /` trips the builtin `core.filesystem.destructive-rm` deny, so
/// the allowlist / pack machinery downstream of a fired rule runs.
fn destructive_input() -> HookInput {
    bash_input("rm -rf /".to_string())
}

// --- H2: allowlist linear scan + per-entry RFC3339 parse --------------------

// NOTE: the builtin `core.filesystem.destructive-rm` is `hard_deny`, and
// `allowlist_hit_for` returns immediately for hard-deny rules without
// scanning. So H2 only bites on *soft* deny rules. We inject a soft-deny
// plugin rule keyed on a unique head token, fire it, and point every
// allowlist entry at it (expired, so the scan traverses all `n` entries,
// paying one RFC3339 parse each).

const ALLOWLIST_RULE_ID: &str = "pack.bench.al-deny";
const ALLOWLIST_HEAD: &str = "zzbenchcmd";

fn soft_deny_plugin_yaml() -> String {
    format!(
        r#"apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.bench
rules:
  - id: {ALLOWLIST_RULE_ID}
    severity: medium
    defaultDecision: deny
    when:
      shell.argv:
        headAny: [{ALLOWLIST_HEAD}]
    reason: blocked
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "{ALLOWLIST_HEAD} x"
"#
    )
}

/// Build a config whose plugin set contains the soft-deny rule and `n`
/// expired allowlist entries that all name it. Returns the temp plugin
/// file too so the caller keeps it alive for the engine's lifetime.
fn config_with_allowlists(n: usize) -> Option<(Config, tempfile::NamedTempFile)> {
    use std::io::Write as _;
    let mut file = tempfile::Builder::new().suffix(".yaml").tempfile().ok()?;
    file.write_all(soft_deny_plugin_yaml().as_bytes()).ok()?;
    file.flush().ok()?;
    let allowlists = (0..n)
        .map(|i| Allowlist {
            id: format!("al-{i}"),
            rule_ids: vec![ALLOWLIST_RULE_ID.to_string()],
            when: None,
            expires_at: Some("2000-01-01T00:00:00Z".to_string()),
            reason: None,
        })
        .collect();
    let config = Config {
        allowlists,
        plugin_paths: vec![file.path().to_path_buf()],
        audit: quiet_audit(),
        ..Config::default()
    };
    Some((config, file))
}

#[divan::bench(args = [10, 100, 1000])]
fn decide_allowlist_scan(bencher: Bencher, n: usize) {
    let Some((config, _keepalive)) = config_with_allowlists(n) else {
        return;
    };
    let Ok(engine) = Engine::with_config(config) else {
        return;
    };
    let input = bash_input(format!("{ALLOWLIST_HEAD} x"));
    bencher.bench_local(|| engine.decide(black_box(&input)));
}

// --- H3: pack-disable scan + per-comparison `format!` allocation ------------

/// `m` extra disabled packs whose names match no real rule, so
/// `is_pack_disabled`'s `.any()` scans them all (one `format!("{pack}.")`
/// per comparison) for every builtin + plugin rule.
fn config_with_packs(m: usize) -> Config {
    let mut pack_overrides = Config::default().pack_overrides;
    for i in 0..m {
        pack_overrides.insert(
            format!("benchpack-{i}"),
            PackOverride {
                enabled: Some(false),
            },
        );
    }
    Config {
        pack_overrides,
        audit: quiet_audit(),
        ..Config::default()
    }
}

#[divan::bench(args = [10, 100, 1000])]
fn decide_pack_disabled(bencher: Bencher, m: usize) {
    let Ok(engine) = Engine::with_config(config_with_packs(m)) else {
        return;
    };
    let input = destructive_input();
    bencher.bench_local(|| engine.decide(black_box(&input)));
}

// --- H4: sensitive classification (11 regexes per token) --------------------

/// A command with `tokens` path-like arguments; `collect_sensitive` runs
/// `classify` (11 regexes) over each one.
fn sensitive_command(tokens: usize) -> String {
    let mut cmd = String::from("echo");
    for i in 0..tokens {
        cmd.push_str(&format!(" /home/u{i}/.ssh/id_rsa_{i}"));
    }
    cmd
}

#[divan::bench(args = [16, 256, 4096])]
fn decide_sensitive_class(bencher: Bencher, tokens: usize) {
    let Ok(engine) = Engine::with_config(Config {
        audit: quiet_audit(),
        ..Config::default()
    }) else {
        return;
    };
    let input = bash_input(sensitive_command(tokens));
    bencher.bench_local(|| engine.decide(black_box(&input)));
}

// --- M2: shell tokenize single pass over a long command ---------------------

/// One oversized argument so the byte state machine dominates and
/// `classify` stays cheap (a single token).
fn long_command(bytes: usize) -> String {
    let mut cmd = String::from("echo ");
    cmd.push_str(&"a".repeat(bytes));
    cmd
}

#[divan::bench(args = [1024, 65536, 1_048_576])]
fn decide_shell_parse(bencher: Bencher, bytes: usize) {
    let Ok(engine) = Engine::with_config(Config {
        audit: quiet_audit(),
        ..Config::default()
    }) else {
        return;
    };
    let input = bash_input(long_command(bytes));
    bencher.bench_local(|| engine.decide(black_box(&input)));
}

// --- H1: plugin load (per-rule clone of test metadata) ----------------------

/// `rules` rules, each carrying deny + allow test cases, so `load_str`
/// pays the `clone_raw_rule` cost (test metadata only used by `plugin-check`).
fn plugin_yaml_with_rules(rules: usize) -> String {
    let mut src = String::from(
        "apiVersion: ptuf.dev/v1\nkind: Plugin\nmetadata:\n  name: pack.bench\nrules:\n",
    );
    for i in 0..rules {
        src.push_str(&format!(
            r#"  - id: pack.bench.rule-{i}
    severity: medium
    defaultDecision: deny
    when:
      shell.argv:
        headAny: [curl]
    reason: blocked-{i}
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "curl https://example.com/{i}"
      allow:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls {i}"
"#
        ));
    }
    src
}

#[divan::bench(args = [10, 100, 500])]
fn plugin_load(bencher: Bencher, rules: usize) {
    let src = plugin_yaml_with_rules(rules);
    let path = std::path::Path::new("bench.yaml");
    bencher
        .bench_local(|| ptuf::plugin::loader::load_str(black_box(path), black_box(&src)).is_ok());
}

// --- M1: config 4-layer parse + merge baseline ------------------------------

fn config_layer(idx: usize) -> String {
    format!(
        "version: 1\nfailClosed: true\npacks:\n  core.network:\n    enabled: false\n\
         allowlists:\n  - id: al-{idx}\n    appliesTo:\n      rules: \
         [core.filesystem.destructive-rm]\n    expiresAt: \"2030-01-01T00:00:00Z\"\n\
         audit:\n  enabled: true\n  includeDenied: true\n"
    )
}

#[divan::bench]
fn config_load(bencher: Bencher) {
    let sources: Vec<String> = (0..4).map(config_layer).collect();
    let path = std::path::Path::new("bench.yaml");
    bencher.bench_local(|| {
        let mut layers = Vec::with_capacity(sources.len());
        for src in &sources {
            if let Ok(raw) = ptuf::config::yaml::parse_str(path, black_box(src)) {
                layers.push(raw);
            }
        }
        ptuf::config::merge::merge(layers)
    });
}
