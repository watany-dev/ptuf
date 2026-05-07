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
    "[a-z][a-z0-9]{0,5}(\\.[a-z][a-z0-9]{0,5}){1,3}".prop_map(|s| s)
}

/// Short reason strings without control characters; long enough to
/// exercise allocation but short enough to keep failure messages
/// readable.
pub fn reason_text() -> impl Strategy<Value = String> {
    "[ -~]{0,40}".prop_map(|s| s)
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
        4 => "[a-zA-Z0-9_./-]{1,12}".prop_map(|s| s),
        1 => proptest::sample::select(SUSPICIOUS_ARGS).prop_map(std::string::ToString::to_string),
    ]
}

fn bash_head() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => proptest::sample::select(SAFE_HEADS).prop_map(std::string::ToString::to_string),
        2 => proptest::sample::select(DANGEROUS_HEADS).prop_map(std::string::ToString::to_string),
        1 => "[a-z][a-z0-9]{0,8}".prop_map(|s| s),
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
    "[ -~]{0,40}".prop_map(|s| s)
}

/// Hook tool names. Bash is over-represented because that is the
/// surface every built-in rule cares about.
fn tool_name() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => Just("Bash".to_string()),
        1 => proptest::sample::select(&["Read", "Write", "Edit", "Glob", "Grep"][..])
            .prop_map(std::string::ToString::to_string),
        1 => "[A-Z][A-Za-z]{0,8}".prop_map(|s| s),
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
    let safe_abs = "/(?:tmp|repo|home/me|var/log|opt/app)/[a-zA-Z0-9_./-]{0,16}".prop_map(|s| s);
    let project_rel = "[a-zA-Z0-9_./-]{1,20}".prop_map(|s| s);
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
    .prop_map(std::string::ToString::to_string);
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
    let arbitrary = "[ -~]{0,40}".prop_map(|s| s);
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
    let arbitrary = "[!-~]{0,16}".prop_map(|s| s);
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
