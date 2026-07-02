//! Classify a string against the protected-credentials shapes defined in
//! `docs/design/policy-packs.md` §`core.secrets`.
//!
//! The legacy [`crate::rules::patterns::SENSITIVE_PATH`] regex remains
//! the source of truth for the existing `core.secrets.sensitive-path-to-network`
//! rule. This module adds an *additive* per-variant view so other tools
//! (`Read`, `Edit`, `Write`, plugin DSL) can match a typed
//! [`SensitiveKind`] without disturbing the existing rule's tests.

use regex::Regex;
use std::sync::OnceLock;

/// Distinct kinds of sensitive token that `classify` recognises.
///
/// String tags (`as_str`) are stable and double as the value space for
/// the future `sensitive.pathKindAny:` plugin DSL leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitiveKind {
    SshDir,
    AwsDir,
    GcloudDir,
    KubeConfig,
    DockerConfig,
    PrivateKeyFile,
    Dotenv,
    Npmrc,
    Pypirc,
    Tfstate,
    PemBlob,
}

impl SensitiveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SshDir => "ssh_dir",
            Self::AwsDir => "aws_dir",
            Self::GcloudDir => "gcloud_dir",
            Self::KubeConfig => "kube_config",
            Self::DockerConfig => "docker_config",
            Self::PrivateKeyFile => "private_key_file",
            Self::Dotenv => "dotenv",
            Self::Npmrc => "npmrc",
            Self::Pypirc => "pypirc",
            Self::Tfstate => "tfstate",
            Self::PemBlob => "pem_blob",
        }
    }

    /// Parse a tag back into a [`SensitiveKind`]. Used by the plugin
    /// DSL when matching `sensitive.pathKindAny:`.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ssh_dir" => Self::SshDir,
            "aws_dir" => Self::AwsDir,
            "gcloud_dir" => Self::GcloudDir,
            "kube_config" => Self::KubeConfig,
            "docker_config" => Self::DockerConfig,
            "private_key_file" => Self::PrivateKeyFile,
            "dotenv" => Self::Dotenv,
            "npmrc" => Self::Npmrc,
            "pypirc" => Self::Pypirc,
            "tfstate" => Self::Tfstate,
            "pem_blob" => Self::PemBlob,
            _ => return None,
        })
    }
}

/// A single match against a sensitive shape. `raw` is the substring as
/// it appeared in the input token; `kind` identifies the category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitivePath {
    pub kind: SensitiveKind,
    pub raw: String,
}

#[expect(
    clippy::expect_used,
    reason = "static pattern literal validated by tests"
)]
fn build(pat: &str) -> Regex {
    Regex::new(pat).expect("sensitive variant regex")
}

// `(?i-u:…)` scopes ASCII case-insensitive matching to literal path
// fragments so `.ENV`/`.Ssh` on case-insensitive filesystems (macOS APFS,
// Windows NTFS) still classify. The `-u` selects ASCII case folding so
// the regex compiles without the optional `unicode-case` feature (kept
// disabled per `Cargo.toml [dependencies] regex` to keep the binary
// minimal). Surrounding `\s`/`\b`/`\S` stay Unicode-aware. The PEM blob
// pattern stays case-sensitive because RFC 7468 mandates uppercase header
// labels.
//
// Anchors on the `.env` pattern include glob metacharacters,
// brace-expansion punctuation, and `=` so `cat *.env`, `cat {a,b}.env`,
// `cp ?.env`, `rm [abc].env`, and `dd if=.env` / `--env-file=.env` style
// flag values are caught at the token boundary.
//
// `PROBES` is the single source of truth: declaration order is the order
// `classify` reports matches in. Each entry pairs the variant's pattern
// with the lowercase literal fragment every one of its matches must
// contain. The needle gates the regex behind a cheap substring scan —
// ptuf runs as one short-lived process per hook call, so an ungated
// probe would pay regex *compilation* on every invocation even for
// `ls`-grade input. Keep each needle in sync with its pattern literal;
// the `pbt_classify_matches_ungated_probes` property test pins the
// equivalence.
const PROBES: &[(SensitiveKind, &str, &str)] = &[
    (
        SensitiveKind::SshDir,
        ".ssh",
        r"(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.ssh)(?:/|$|\b)",
    ),
    (
        SensitiveKind::AwsDir,
        ".aws",
        r"(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.aws)(?:/|$|\b)",
    ),
    (
        SensitiveKind::GcloudDir,
        "gcloud",
        r"(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.config/gcloud)(?:/|$|\b)",
    ),
    (
        SensitiveKind::KubeConfig,
        ".kube",
        r"(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.kube/config)\b",
    ),
    (
        SensitiveKind::DockerConfig,
        ".docker",
        r"(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.docker/config\.json)\b",
    ),
    (
        SensitiveKind::PrivateKeyFile,
        "id_",
        r"\b(?i-u:id_(?:rsa|dsa|ecdsa|ed25519))\b",
    ),
    (
        SensitiveKind::Dotenv,
        ".env",
        r"(?:^|/|\s|[*?\[\]={},])(?i-u:\.env)(?:\.[A-Za-z0-9_-]+)?\b",
    ),
    (
        SensitiveKind::Npmrc,
        ".npmrc",
        r"(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.npmrc)\b",
    ),
    (
        SensitiveKind::Pypirc,
        ".pypirc",
        r"(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.pypirc)\b",
    ),
    (SensitiveKind::Tfstate, ".tfstate", r"\S+(?i-u:\.tfstate)\b"),
    (
        SensitiveKind::PemBlob,
        "-----begin",
        r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----",
    ),
];

/// Per-variant regexes, indexed parallel to [`PROBES`]. Each slot
/// compiles on first use and only for variants whose needle actually
/// appeared in a token, so no-secret invocations never build any of
/// them.
static SENSITIVE_REGEXES: [OnceLock<Regex>; PROBES.len()] =
    [const { OnceLock::new() }; PROBES.len()];

/// Inspect a single string token and return every sensitive shape it
/// matches. The slice preserves variant declaration order for
/// determinism.
pub fn classify(token: &str) -> Vec<SensitivePath> {
    let mut out = Vec::new();
    // The probe regexes only fold ASCII case (`(?i-u:…)`), so an ASCII
    // lowercase of the token is enough for the needle gate.
    let lower = token.to_ascii_lowercase();
    for (idx, (kind, needle, pat)) in PROBES.iter().enumerate() {
        if !lower.contains(needle) {
            continue;
        }
        let re = SENSITIVE_REGEXES[idx].get_or_init(|| build(pat));
        for m in re.find_iter(token) {
            out.push(SensitivePath {
                kind: *kind,
                raw: m.as_str().to_string(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {

    use super::*;

    fn kinds(s: &str) -> Vec<SensitiveKind> {
        classify(s).into_iter().map(|m| m.kind).collect()
    }

    #[test]
    fn classifies_ssh_dir() {
        assert!(kinds("~/.ssh/id_rsa").contains(&SensitiveKind::SshDir));
        assert!(kinds("$HOME/.ssh/").contains(&SensitiveKind::SshDir));
        assert!(kinds("/home/user/.ssh/config").contains(&SensitiveKind::SshDir));
        assert!(kinds("/root/.ssh/id_rsa").contains(&SensitiveKind::SshDir));
    }

    #[test]
    fn classifies_aws_dir() {
        assert!(kinds("~/.aws/credentials").contains(&SensitiveKind::AwsDir));
        assert!(kinds("/home/user/.aws/credentials").contains(&SensitiveKind::AwsDir));
    }

    #[test]
    fn classifies_gcloud_dir() {
        assert!(
            kinds("~/.config/gcloud/application_default_credentials.json")
                .contains(&SensitiveKind::GcloudDir)
        );
    }

    #[test]
    fn classifies_kube_and_docker_config() {
        assert!(kinds("~/.kube/config").contains(&SensitiveKind::KubeConfig));
        assert!(kinds("~/.docker/config.json").contains(&SensitiveKind::DockerConfig));
        assert!(kinds("/home/alice/.kube/config").contains(&SensitiveKind::KubeConfig));
        assert!(kinds("/var/root/.docker/config.json").contains(&SensitiveKind::DockerConfig));
    }

    #[test]
    fn classifies_private_key_file() {
        // All four standard OpenSSH private-key filenames, including the
        // DSA form (`id_dsa`) that the alternation originally omitted.
        assert!(kinds("id_rsa").contains(&SensitiveKind::PrivateKeyFile));
        assert!(kinds("id_dsa").contains(&SensitiveKind::PrivateKeyFile));
        assert!(kinds("id_ecdsa").contains(&SensitiveKind::PrivateKeyFile));
        assert!(kinds("id_ed25519").contains(&SensitiveKind::PrivateKeyFile));
        assert!(kinds("~/.ssh/id_dsa").contains(&SensitiveKind::PrivateKeyFile));
        // Lookalikes that are not real key names must not classify.
        assert!(!kinds("id_dss").contains(&SensitiveKind::PrivateKeyFile));
        assert!(!kinds("id_rsational").contains(&SensitiveKind::PrivateKeyFile));
    }

    #[test]
    fn classifies_dotenv_variants() {
        assert!(kinds(".env").contains(&SensitiveKind::Dotenv));
        assert!(kinds(".env.production").contains(&SensitiveKind::Dotenv));
        assert!(kinds("/srv/app/.env").contains(&SensitiveKind::Dotenv));
    }

    #[test]
    fn classifies_case_variant_paths() {
        assert!(kinds(".ENV").contains(&SensitiveKind::Dotenv));
        assert!(kinds(".Env.PRODUCTION").contains(&SensitiveKind::Dotenv));
        assert!(kinds("~/.SSH/id_rsa").contains(&SensitiveKind::SshDir));
        assert!(kinds("~/.AWS/credentials").contains(&SensitiveKind::AwsDir));
        assert!(kinds("~/.Kube/config").contains(&SensitiveKind::KubeConfig));
        assert!(kinds(".NPMRC").contains(&SensitiveKind::Npmrc));
        assert!(kinds("ID_RSA").contains(&SensitiveKind::PrivateKeyFile));
    }

    #[test]
    fn classifies_dotenv_through_glob_anchor() {
        assert!(kinds("*.env").contains(&SensitiveKind::Dotenv));
        assert!(kinds("?.env").contains(&SensitiveKind::Dotenv));
        assert!(kinds("[abc].env").contains(&SensitiveKind::Dotenv));
        assert!(kinds("a*.env").contains(&SensitiveKind::Dotenv));
        assert!(kinds("dir/*.env.local").contains(&SensitiveKind::Dotenv));
    }

    #[test]
    fn classifies_dotenv_through_brace_expansion_anchor() {
        assert!(kinds("{a,b}.env").contains(&SensitiveKind::Dotenv));
        assert!(kinds("{x,y,z}.env").contains(&SensitiveKind::Dotenv));
        assert!(kinds("{.env,.env.local}").contains(&SensitiveKind::Dotenv));
        assert!(kinds("prefix{a,b}.env").contains(&SensitiveKind::Dotenv));
        assert!(kinds("{app,web}.env.production").contains(&SensitiveKind::Dotenv));
    }

    #[test]
    fn does_not_misclassify_dotenv_lookalikes() {
        // No leading anchor character: not a path token.
        assert!(!kinds("envfile").contains(&SensitiveKind::Dotenv));
        assert!(!kinds("data.env").contains(&SensitiveKind::Dotenv));
        assert!(!kinds("benvironment").contains(&SensitiveKind::Dotenv));
    }

    #[test]
    fn pem_blob_remains_case_sensitive() {
        // RFC 7468 requires uppercase headers; lowercase must not match.
        assert!(!kinds("-----begin rsa private key-----").contains(&SensitiveKind::PemBlob));
    }

    #[test]
    fn classifies_npmrc_pypirc_tfstate() {
        // Real credential files live at a path boundary; each of these
        // must classify.
        for token in [".npmrc", "~/.npmrc", "/home/user/.npmrc", "$HOME/.npmrc"] {
            assert!(
                kinds(token).contains(&SensitiveKind::Npmrc),
                "missed {token:?}"
            );
        }
        for token in [".pypirc", "~/.pypirc", "/root/.pypirc", "${HOME}/.pypirc"] {
            assert!(
                kinds(token).contains(&SensitiveKind::Pypirc),
                "missed {token:?}"
            );
        }
        assert!(kinds("infra/main.tfstate").contains(&SensitiveKind::Tfstate));
    }

    #[test]
    fn does_not_misclassify_npmrc_pypirc_lookalikes() {
        // `.` preceded by a word char is not a path boundary, so these
        // lookalikes must not classify (the previous unanchored probe
        // wrongly matched `data.npmrc`).
        assert!(!kinds("data.npmrc").contains(&SensitiveKind::Npmrc));
        assert!(!kinds("xpypirc").contains(&SensitiveKind::Pypirc));
        assert!(!kinds("npmrc").contains(&SensitiveKind::Npmrc));
    }

    #[test]
    fn classifies_pem_blob() {
        assert!(
            kinds("-----BEGIN RSA PRIVATE KEY-----").contains(&SensitiveKind::PemBlob),
            "PEM header should classify"
        );
    }

    #[test]
    fn classify_returns_empty_for_safe_input() {
        assert!(classify("ls -la").is_empty());
        assert!(classify("https://example.com/data.json").is_empty());
    }

    #[test]
    fn match_records_raw_substring() {
        let m = classify("/tmp/.env.production").into_iter().next().unwrap();
        assert_eq!(m.kind, SensitiveKind::Dotenv);
        assert!(m.raw.contains(".env"));
    }

    #[test]
    fn multiple_kinds_can_match_one_token() {
        let ms = classify("~/.ssh/id_rsa");
        assert!(ms.iter().any(|m| m.kind == SensitiveKind::SshDir));
        assert!(ms.iter().any(|m| m.kind == SensitiveKind::PrivateKeyFile));
    }

    use crate::testing::proptest::sensitive_kind;
    use proptest::prelude::*;

    proptest! {
        // classify never panics on arbitrary printable ASCII.
        #[test]
        fn pbt_classify_never_panics(s in "[ -~]{0,80}") {
            let _ = classify(&s);
        }

        // The needle prefilter must never change behaviour: running the
        // probe regexes without any gating yields exactly the same
        // matches as `classify`. Guards the per-probe needles against
        // drifting out of sync with their regex literals.
        #[test]
        fn pbt_classify_matches_ungated_probes(s in "[ -~]{0,80}") {
            static UNGATED: std::sync::LazyLock<Vec<Regex>> = std::sync::LazyLock::new(|| {
                PROBES.iter().map(|(_, _, pat)| build(pat)).collect()
            });
            let mut reference = Vec::new();
            for ((kind, _, _), re) in PROBES.iter().zip(UNGATED.iter()) {
                for m in re.find_iter(&s) {
                    reference.push(SensitivePath {
                        kind: *kind,
                        raw: m.as_str().to_string(),
                    });
                }
            }
            prop_assert_eq!(classify(&s), reference);
        }

        // SensitiveKind::as_str is total and parse round-trips for every
        // variant.
        #[test]
        fn pbt_kind_round_trips(k in sensitive_kind()) {
            prop_assert_eq!(SensitiveKind::parse(k.as_str()), Some(k));
        }

        // For every match the parser produces, the recorded `raw`
        // substring really does appear inside the input string.
        #[test]
        fn pbt_match_raw_is_substring(s in "[ -~]{0,80}") {
            for m in classify(&s) {
                prop_assert!(s.contains(&m.raw), "raw {:?} not substring of {:?}", m.raw, s);
            }
        }

        // Plain alphanumeric tokens (no slashes/dots/tilde) cannot match
        // any sensitive shape.
        #[test]
        fn pbt_plain_alphanumeric_never_classifies(s in "[A-Za-z0-9]{0,40}") {
            prop_assert!(classify(&s).is_empty());
        }

        // Brace-expansion argv tokens must always classify as Dotenv.
        #[test]
        fn pbt_brace_dotenv_tokens_always_classify(token in crate::testing::proptest::dotenv_brace_token()) {
            let kinds: Vec<_> = classify(&token).into_iter().map(|m| m.kind).collect();
            prop_assert!(
                kinds.contains(&SensitiveKind::Dotenv),
                "expected Dotenv for {token:?}, got {kinds:?}",
            );
        }

        // Every B2-anchored dotenv literal must match the legacy SENSITIVE_PATH regex.
        #[test]
        fn pbt_anchored_dotenv_literals_match_sensitive_path(
            token in crate::testing::proptest::dotenv_anchored_literal_token(),
        ) {
            prop_assert!(
                crate::rules::patterns::SENSITIVE_PATH.is_match(&token),
                "SENSITIVE_PATH missed {token:?}",
            );
        }

        // Negative space: lookalikes without anchors must stay clean.
        #[test]
        fn pbt_dotenv_false_positives_never_classify(
            token in crate::testing::proptest::dotenv_false_positive_token(),
        ) {
            prop_assert!(
                classify(&token).iter().all(|m| m.kind != SensitiveKind::Dotenv),
                "false positive Dotenv for {token:?}: {:?}",
                classify(&token),
            );
        }

        // Every standard OpenSSH private-key filename classifies as
        // PrivateKeyFile under any representative path prefix. Pins the
        // `id_dsa` hole shut across the full key family.
        #[test]
        fn pbt_ssh_key_family_always_classifies(
            key in "id_(rsa|dsa|ecdsa|ed25519)",
            prefix in "(|~/\\.ssh/|\\$HOME/\\.ssh/|/home/user/\\.ssh/|/root/\\.ssh/)",
        ) {
            let s = format!("{prefix}{key}");
            let kinds: Vec<_> = classify(&s).into_iter().map(|m| m.kind).collect();
            prop_assert!(
                kinds.contains(&SensitiveKind::PrivateKeyFile),
                "expected PrivateKeyFile from {s:?}, got {kinds:?}",
            );
        }

                // SSH-dir samples always classify as SshDir.
        #[test]
        fn pbt_ssh_dir_always_classifies(tail in "[a-zA-Z0-9_./-]{0,16}") {
            for prefix in ["~", "$HOME", "${HOME}"] {
                let s = format!("{prefix}/.ssh/{tail}");
                let kinds: Vec<_> = classify(&s).into_iter().map(|m| m.kind).collect();
                prop_assert!(
                    kinds.contains(&SensitiveKind::SshDir),
                    "expected SshDir from {s:?}, got {kinds:?}",
                );
            }
        }
    }
}
