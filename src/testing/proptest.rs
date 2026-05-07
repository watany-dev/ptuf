//! Reusable proptest strategies for ptuf data types.
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

use crate::config::Mode;
use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::sensitive::SensitiveKind;
use crate::hook_input::HookInput;
use crate::self_paths::ProtectedKind;

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

/// All engine [`Mode`] variants drawn uniformly.
pub fn mode() -> impl Strategy<Value = Mode> {
    prop_oneof![Just(Mode::Enforce), Just(Mode::Monitor)]
}

/// All six [`ProtectedKind`] variants drawn uniformly.
pub fn protected_kind() -> impl Strategy<Value = ProtectedKind> {
    prop_oneof![
        Just(ProtectedKind::Binary),
        Just(ProtectedKind::Config),
        Just(ProtectedKind::Plugin),
        Just(ProtectedKind::ClaudeSettings),
        Just(ProtectedKind::CodexSettings),
        Just(ProtectedKind::HookScript),
    ]
}

/// All eleven [`SensitiveKind`] variants drawn uniformly.
pub fn sensitive_kind() -> impl Strategy<Value = SensitiveKind> {
    prop_oneof![
        Just(SensitiveKind::SshDir),
        Just(SensitiveKind::AwsDir),
        Just(SensitiveKind::GcloudDir),
        Just(SensitiveKind::KubeConfig),
        Just(SensitiveKind::DockerConfig),
        Just(SensitiveKind::PrivateKeyFile),
        Just(SensitiveKind::Dotenv),
        Just(SensitiveKind::Npmrc),
        Just(SensitiveKind::Pypirc),
        Just(SensitiveKind::Tfstate),
        Just(SensitiveKind::PemBlob),
    ]
}

/// File-path strings: a mix of project-relative paths, absolute paths
/// under common system roots, `~`/`$HOME` forms, and well-known
/// sensitive paths. The mix is heavily biased so that `path` /
/// `sensitive` extractors actually exercise their non-empty arms.
pub fn file_path() -> impl Strategy<Value = String> {
    let safe_abs =
        "/(?:tmp|repo|home/me|var/log|opt/app)/[a-zA-Z0-9_./-]{0,16}".prop_map(|s| s.to_string());
    let project_rel = "[a-zA-Z0-9_./-]{1,20}".prop_map(|s| s.to_string());
    let home_form = prop_oneof![
        Just("~".to_string()),
        Just("$HOME".to_string()),
        Just("${HOME}".to_string()),
    ];
    let home_with_suffix =
        (home_form.clone(), "[a-zA-Z0-9_./-]{0,16}").prop_map(|(prefix, rest)| {
            if rest.is_empty() {
                prefix
            } else {
                format!("{prefix}/{rest}")
            }
        });
    let sensitive_paths = proptest::sample::select(
        &[
            "~/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "~/.ssh/config",
            "~/.aws/credentials",
            "~/.aws/config",
            "~/.config/gcloud/application_default_credentials.json",
            "~/.kube/config",
            "~/.docker/config.json",
            ".env",
            ".env.production",
            "/srv/app/.env",
            "infra/main.tfstate",
            ".npmrc",
            ".pypirc",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ptuf/policy.yaml",
            "/repo/.ptuf.yaml",
            "/repo/.claude/settings.json",
        ][..],
    )
    .prop_map(|s| s.to_string());
    prop_oneof![
        2 => safe_abs,
        2 => project_rel,
        1 => home_form,
        2 => home_with_suffix,
        2 => sensitive_paths,
    ]
}

/// URL-shaped strings spanning safe HTTPs, SSRF-style cloud-metadata
/// endpoints, alternative schemes, malformed strings, and arbitrary
/// printable ASCII. Used by URL-fact and rule PBT to exercise both
/// happy and adversarial paths through `url::parse`.
pub fn web_url() -> impl Strategy<Value = String> {
    let safe = proptest::sample::select(
        &[
            "https://example.com/",
            "https://api.github.com/repos/x/y",
            "http://example.com:8080/admin",
            "https://example.com:443",
            "https://user:pass@example.com/x",
        ][..],
    )
    .prop_map(|s| s.to_string());
    let cloud = proptest::sample::select(
        &[
            "http://169.254.169.254/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ][..],
    )
    .prop_map(|s| s.to_string());
    let weird_scheme = proptest::sample::select(
        &[
            "file:///etc/shadow",
            "ftp://example.com/",
            "data:,abc",
            "javascript:alert(1)",
        ][..],
    )
    .prop_map(|s| s.to_string());
    let malformed = proptest::sample::select(
        &[
            "example.com/foo",
            "http:///foo",
            "://x",
            "http://example.com:notaport/",
            "http://[::1]:abc/",
            "",
        ][..],
    )
    .prop_map(|s| s.to_string());
    let arbitrary = "[ -~]{0,40}".prop_map(|s| s.to_string());
    prop_oneof![
        4 => safe,
        2 => cloud,
        1 => weird_scheme,
        2 => malformed,
        1 => arbitrary,
    ]
}

/// `HookInput` for `Read` / `Edit` / `Write` covering the three tool
/// names with realistic `file_path` distributions.
pub fn read_edit_write_input() -> impl Strategy<Value = HookInput> {
    let tool = proptest::sample::select(&["Read", "Edit", "Write"][..]).prop_map(|s| s.to_string());
    prop_oneof![
        4 => (tool.clone(), file_path()).prop_map(|(tool_name, fp)| HookInput {
            tool_name,
            tool_input: json!({ "file_path": fp }),
        }),
        // Edit has new_string, Write has content.
        1 => (file_path(), "[ -~]{0,40}").prop_map(|(fp, body)| HookInput {
            tool_name: "Write".into(),
            tool_input: json!({ "file_path": fp, "content": body }),
        }),
        1 => (file_path(), "[ -~]{0,40}").prop_map(|(fp, body)| HookInput {
            tool_name: "Edit".into(),
            tool_input: json!({ "file_path": fp, "new_string": body }),
        }),
        // Missing or non-string field — exercises None branches.
        1 => Just(HookInput {
            tool_name: "Read".into(),
            tool_input: json!({}),
        }),
    ]
}

/// `HookInput` for the `WebFetch` tool, biased toward URL shapes that
/// the URL fact extractor and the cloud-metadata rule actually care
/// about.
pub fn web_fetch_input() -> impl Strategy<Value = HookInput> {
    prop_oneof![
        4 => web_url().prop_map(|u| HookInput {
            tool_name: "WebFetch".into(),
            tool_input: json!({ "url": u }),
        }),
        1 => Just(HookInput {
            tool_name: "WebFetch".into(),
            tool_input: json!({}),
        }),
    ]
}

/// Superset hook-input strategy spanning every tool surface the engine
/// is exercised against (Bash, Read/Edit/Write, WebFetch, plus
/// arbitrary unknown tools).
pub fn richer_hook_input() -> impl Strategy<Value = HookInput> {
    prop_oneof![
        4 => hook_input(),
        2 => read_edit_write_input(),
        2 => web_fetch_input(),
        1 => "[A-Z][A-Za-z]{0,8}".prop_map(|s| HookInput {
            tool_name: s.to_string(),
            tool_input: json!({}),
        }),
    ]
}

/// Single argv token biased toward tokens that the CLI parser
/// (`crate::cli::parse`) actually distinguishes: subcommand names,
/// agent names, flag names with and without `=value` form, tool
/// names, plus a sliver of arbitrary printable ASCII so adversarial
/// shapes get probed too. Returned tokens never contain whitespace
/// so they line up one-to-one with `argv` slots.
fn argv_token() -> impl Strategy<Value = String> {
    let subcmd = proptest::sample::select(
        &[
            "doctor",
            "init",
            "hook",
            "eval",
            "plugin",
            "test",
            "--help",
            "-h",
            "--version",
            "-V",
        ][..],
    )
    .prop_map(|s| s.to_string());
    let agent = proptest::sample::select(&["claude-code", "codex"][..]).prop_map(|s| s.to_string());
    let flag = proptest::sample::select(
        &[
            "--json",
            "--dry-run",
            "--tool",
            "--settings",
            "--root",
            "--hooks",
            "--config",
            "--tool=Bash",
            "--settings=foo",
            "--root=/tmp",
            "--hooks=foo.json",
            "--config=foo.toml",
        ][..],
    )
    .prop_map(|s| s.to_string());
    let tool = proptest::sample::select(&["Bash", "Read", "Write", "Edit"][..])
        .prop_map(|s| s.to_string());
    let arbitrary = "[!-~]{0,16}".prop_map(|s| s.to_string());
    prop_oneof![
        4 => subcmd,
        2 => agent,
        3 => flag,
        2 => tool,
        2 => arbitrary,
    ]
}

/// Argv vector for `crate::cli::parse` PBT: 0 to 6 tokens drawn from
/// [`argv_token`]. The empty vector exercises the "missing subcommand"
/// error branch; longer vectors stress the per-subcommand parsers.
pub fn argv_tokens() -> impl Strategy<Value = Vec<String>> {
    vec(argv_token(), 0..=6)
}

/// Bash command words mixing single-quoted, double-quoted, and
/// backslash-escaped tokens. Used by `facts::shell::parse` PBT to
/// stress quote handling and to keep flags/positional invariants
/// intact across quoting forms.
pub fn bash_with_quoting() -> impl Strategy<Value = String> {
    let head = bash_head();
    let single = "[ a-zA-Z0-9_./-]{0,8}".prop_map(|s| format!("'{s}'"));
    let double = "[ a-zA-Z0-9_./-]{0,8}".prop_map(|s| format!("\"{s}\""));
    let escaped = "[a-zA-Z0-9_./-]{1,4}".prop_map(|s| format!("\\ {s}"));
    let plain = "[a-zA-Z0-9_./-]{1,8}".prop_map(|s| s.to_string());
    let word = prop_oneof![
        2 => plain,
        2 => single,
        2 => double,
        1 => escaped,
    ];
    (head, vec(word, 0..4)).prop_map(|(h, args)| {
        if args.is_empty() {
            h
        } else {
            format!("{h} {}", args.join(" "))
        }
    })
}

/// One-pipeline command containing at least one redirect operator
/// drawn from `>`, `>>`, `<`, `2>`, `&>`. The redirect target is a
/// short safe filename. Used to verify that every emitted operator
/// shows up in `Pipeline.redirects` with the same kind.
pub fn bash_redirects() -> impl Strategy<Value = (String, Vec<&'static str>)> {
    let op = prop_oneof![Just(">"), Just(">>"), Just("<"), Just("2>"), Just("&>"),];
    (
        bash_head(),
        vec(
            (op, "[a-z][a-z0-9_]{0,6}").prop_map(|(o, t)| (o, format!("{o} {t}"))),
            1..3,
        ),
    )
        .prop_map(|(head, redirs)| {
            let ops: Vec<&'static str> = redirs.iter().map(|(o, _)| *o).collect();
            let cmd = format!(
                "{head} {}",
                redirs
                    .iter()
                    .map(|(_, fragment)| fragment.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            (cmd, ops)
        })
}

/// Bash heredoc command (`cat <<TAG\nbody\nTAG\n` form). The
/// terminator is one of a fixed allow-list and the body avoids the
/// terminator literal so the heredoc closes cleanly. Used to check
/// `Bash::has_heredoc` and that the body stays inside one
/// `Redirect.target`.
pub fn bash_heredoc() -> impl Strategy<Value = (String, &'static str)> {
    let terminator = prop_oneof![Just("EOF"), Just("END"), Just("DONE")];
    let dash = prop_oneof![Just(""), Just("-")];
    (terminator, dash, "[a-zA-Z0-9 _./-]{0,30}").prop_map(|(tag, dash, body_seed)| {
        let body: String = body_seed
            .split_whitespace()
            .filter(|w| *w != tag)
            .collect::<Vec<_>>()
            .join(" ");
        let cmd = format!("cat <<{dash}{tag}\n{body}\n{tag}\n");
        (cmd, tag)
    })
}

/// Bash command containing at least one process substitution
/// (`<(cmd)` or `>(cmd)`) with balanced parens around a safe inner
/// argv. Used to check `Bash::has_process_substitution`.
pub fn bash_process_subst() -> impl Strategy<Value = String> {
    let direction = prop_oneof![Just("<"), Just(">")];
    (bash_head(), direction, "[a-z][a-z0-9_]{0,6}")
        .prop_map(|(head, dir, inner)| format!("{head} {dir}({inner} arg)"))
}

/// Combined short-option wrapper (`bash -lc 'X'`, `sh -ec 'X'`,
/// `dash -ic 'X'`). Used to verify that the wrapper inspector still
/// pulls `inner_argv` out of grouped short flags.
pub fn combined_short_opts() -> impl Strategy<Value = String> {
    let interp = prop_oneof![Just("bash"), Just("sh"), Just("dash")];
    let opts = prop_oneof![Just("lc"), Just("ec"), Just("ic"), Just("uc"),];
    (interp, opts, "[a-z][a-z0-9 _-]{0,12}").prop_map(|(i, o, body)| format!("{i} -{o} '{body}'"))
}

/// Wrapper command nested up to `depth` levels deep using `bash -c`,
/// `sh -c`, `eval`, or `xargs sh -c`. The innermost layer is a single
/// safe head. Used to verify the bounded-depth `inner_argv` chain
/// (the parser uses `nesting_budget = 2` from `parse_with_depth`,
/// so chains never grow beyond two).
pub fn bash_wrapper_nested(depth: usize) -> impl Strategy<Value = String> {
    let depth = depth.min(4);
    let inner = "[a-z][a-z0-9]{0,4}".prop_map(|s| s.to_string());
    inner.prop_map(move |leaf| {
        let mut cmd = leaf;
        for _ in 0..depth {
            cmd = format!("bash -c '{}'", cmd.replace('\'', "'\\''"));
        }
        cmd
    })
}

/// Adversarial byte vector that contains valid printable ASCII most
/// of the time but mixes in invalid UTF-8 sequences (lone surrogate
/// markers, naked 0xFF, an incomplete continuation byte) about 30%
/// of the time. Used to drive fail-closed PBT for the hook stdin
/// reader, which must surface an error rather than panic.
pub fn arbitrary_utf8_bytes() -> impl Strategy<Value = Vec<u8>> {
    let printable = "[ -~]{0,40}".prop_map(|s| s.into_bytes());
    let bad = prop_oneof![
        Just(vec![0xFFu8]),
        Just(vec![0xC2u8]),           // dangling 2-byte lead.
        Just(vec![0xED, 0xA0, 0x80]), // UTF-8-encoded surrogate U+D800.
        Just(vec![0xE0, 0x80]),       // truncated 3-byte sequence.
    ];
    prop_oneof![
        7 => printable,
        3 => (bad, "[ -~]{0,8}").prop_map(|(mut b, tail)| {
            b.extend_from_slice(tail.as_bytes());
            b
        }),
    ]
}

/// MCP-shaped `tool_input` JSON for `mcp__<server>__<tool>` payloads.
/// Covers top-level `path`, `files[].path`, `items[].path`, and
/// `paths[]` shapes that `collect_event_paths` extracts. The depth
/// argument selects which shape:
/// - `0`: top-level `{ "path": "..." }`
/// - `1`: `{ "files": [ { "path": "..." } ] }` /
///   `{ "items": [ { "path": "..." } ] }`
/// - `2`: `{ "paths": ["..."] }`
pub fn mcp_nested_input(depth: u8) -> impl Strategy<Value = serde_json::Value> {
    let path_str = file_path();
    let depth = depth.min(2);
    match depth {
        0 => path_str.prop_map(|p| json!({ "path": p })).boxed(),
        1 => (path_str, prop_oneof![Just("files"), Just("items")])
            .prop_map(|(p, key)| json!({ key: [{ "path": p }] }))
            .boxed(),
        _ => vec(file_path(), 1..3)
            .prop_map(|ps| json!({ "paths": ps }))
            .boxed(),
    }
}

/// `Bash` commands assembled from heads that no built-in rule fires
/// on, with at most one safe argument. Used by RULES negative-space
/// PBT to verify that benign inputs reach `evaluate() == None` for
/// every rule.
pub fn safe_command_string() -> impl Strategy<Value = String> {
    let head = proptest::sample::select(SAFE_HEADS).prop_map(|s| s.to_string());
    let arg = prop_oneof![
        Just(String::new()),
        "[a-zA-Z0-9_./-]{1,8}".prop_map(|s| s.to_string()),
    ];
    (head, arg).prop_map(|(h, a)| if a.is_empty() { h } else { format!("{h} {a}") })
}
