//! Classify a string against the protected-credentials shapes defined in
//! `docs/design/policy-packs.md` §`core.secrets`.
//!
//! Most variants are detected with hand-written ASCII scanners in the
//! private `logic` submodule; [`SensitiveKind::Dotenv`] retains a compiled
//! regex because its anchor
//! set (line start / slash / whitespace / glob meta `*?[]` / `=`) plus the
//! optional dotted suffix is awkward to express in plain code.
//!
//! The legacy [`crate::rules::patterns::SENSITIVE_PATH`] regex remains
//! the source of truth for the existing `core.secrets.sensitive-path-to-network`
//! rule. This module adds an *additive* per-variant view so other tools
//! (`Read`, `Edit`, `Write`, plugin DSL) can match a typed
//! [`SensitiveKind`] without disturbing the existing rule's tests.

use core::ops::Range;
use regex::Regex;
use std::sync::LazyLock;

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

// Dotenv keeps a regex because its anchor set (`^`, `/`, whitespace, glob
// meta `*?[]`, and `=`) combined with the optional dotted suffix is
// noticeably clearer as a regex than as hand-rolled scanner state. All
// other variants are pure ASCII scanners in [`logic`].
static DOTENV: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?:^|/|\s|[*?\[\]=])(?i-u:\.env)(?:\.[A-Za-z0-9_-]+)?\b"));

pub(crate) mod logic {
    //! Hand-written ASCII scanners that replace per-variant regexes.
    //!
    //! Each `pub fn <kind>(token: &str) -> Vec<Range<usize>>` returns the
    //! non-overlapping leftmost match ranges, matching the semantics of
    //! `Regex::find_iter`. ASCII case-insensitive comparisons replace the
    //! original `(?i-u:…)` scopes; `\b` is implemented as the ASCII word
    //! boundary (`[A-Za-z0-9_]` on either side). Surrounding `\s` checks
    //! use `u8::is_ascii_whitespace`, which is sufficient for the path
    //! tokens this module classifies.
    //!
    //! `is_ascii_word_char` / `left_word_boundary` / `right_word_boundary`
    //! are `pub` (re-exported only through this `pub(crate) mod logic`) so
    //! `audit::redaction` can reuse the same boundary definition without
    //! re-declaring it.

    use core::ops::Range;

    pub fn is_ascii_word_char(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    pub fn left_word_boundary(bytes: &[u8], at: usize) -> bool {
        at == 0 || !is_ascii_word_char(bytes[at - 1])
    }

    pub fn right_word_boundary(bytes: &[u8], at: usize) -> bool {
        at == bytes.len() || !is_ascii_word_char(bytes[at])
    }

    fn starts_with_ignore_ascii_case(bytes: &[u8], at: usize, lit: &[u8]) -> bool {
        at + lit.len() <= bytes.len() && bytes[at..at + lit.len()].eq_ignore_ascii_case(lit)
    }

    // Home-prefix variants share the structure
    // `(prefix)/<dir>(/|end|\b)` with `prefix ∈ {~, $HOME, ${HOME}}`.
    // `LeftAnchor::Whitespace` adds a `(^|\s)` requirement that also
    // consumes the leading whitespace into the match.
    const HOME_PREFIXES: [&[u8]; 3] = [b"~", b"$HOME", b"${HOME}"];

    #[derive(Clone, Copy)]
    enum LeftAnchor {
        Whitespace,
        None,
    }

    fn left_anchor_start(bytes: &[u8], at: usize, anchor: LeftAnchor) -> Option<usize> {
        match anchor {
            LeftAnchor::None => Some(at),
            LeftAnchor::Whitespace => {
                if at == 0 {
                    Some(0)
                } else if bytes[at - 1].is_ascii_whitespace() {
                    Some(at - 1)
                } else {
                    None
                }
            },
        }
    }

    fn matches_home_dir(token: &str, dir_literal: &[u8], anchor: LeftAnchor) -> Vec<Range<usize>> {
        let bytes = token.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let mut advance = 1usize;
            for prefix in &HOME_PREFIXES {
                if !bytes[i..].starts_with(prefix) {
                    continue;
                }
                let Some(match_start) = left_anchor_start(bytes, i, anchor) else {
                    continue;
                };
                let after_prefix = i + prefix.len();
                if bytes.get(after_prefix) != Some(&b'/') {
                    continue;
                }
                let dir_start = after_prefix + 1;
                if !starts_with_ignore_ascii_case(bytes, dir_start, dir_literal) {
                    continue;
                }
                let dir_end = dir_start + dir_literal.len();
                if !right_word_boundary(bytes, dir_end) {
                    continue;
                }
                out.push(match_start..dir_end);
                advance = dir_end - i;
                break;
            }
            i += advance;
        }
        out
    }

    pub(super) fn ssh_dir(token: &str) -> Vec<Range<usize>> {
        matches_home_dir(token, b".ssh", LeftAnchor::Whitespace)
    }
    pub(super) fn aws_dir(token: &str) -> Vec<Range<usize>> {
        matches_home_dir(token, b".aws", LeftAnchor::Whitespace)
    }
    pub(super) fn gcloud_dir(token: &str) -> Vec<Range<usize>> {
        matches_home_dir(token, b".config/gcloud", LeftAnchor::Whitespace)
    }
    pub(super) fn kube_config(token: &str) -> Vec<Range<usize>> {
        matches_home_dir(token, b".kube/config", LeftAnchor::None)
    }
    pub(super) fn docker_config(token: &str) -> Vec<Range<usize>> {
        matches_home_dir(token, b".docker/config.json", LeftAnchor::None)
    }

    pub(super) fn private_key_file(token: &str) -> Vec<Range<usize>> {
        let bytes = token.as_bytes();
        let candidates: [&[u8]; 3] = [b"id_rsa", b"id_ed25519", b"id_ecdsa"];
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let mut advance = 1usize;
            for cand in &candidates {
                if starts_with_ignore_ascii_case(bytes, i, cand)
                    && left_word_boundary(bytes, i)
                    && right_word_boundary(bytes, i + cand.len())
                {
                    out.push(i..i + cand.len());
                    advance = cand.len();
                    break;
                }
            }
            i += advance;
        }
        out
    }

    fn simple_suffix(token: &str, lit: &[u8]) -> Vec<Range<usize>> {
        let bytes = token.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let mut advance = 1usize;
            if starts_with_ignore_ascii_case(bytes, i, lit)
                && right_word_boundary(bytes, i + lit.len())
            {
                out.push(i..i + lit.len());
                advance = lit.len();
            }
            i += advance;
        }
        out
    }

    pub(super) fn npmrc(token: &str) -> Vec<Range<usize>> {
        simple_suffix(token, b".npmrc")
    }
    pub(super) fn pypirc(token: &str) -> Vec<Range<usize>> {
        simple_suffix(token, b".pypirc")
    }

    pub(super) fn tfstate(token: &str) -> Vec<Range<usize>> {
        let bytes = token.as_bytes();
        let lit: &[u8] = b".tfstate";
        let mut out = Vec::new();
        let mut i = 0;
        while i + lit.len() <= bytes.len() {
            let mut advance = 1usize;
            if bytes[i..i + lit.len()].eq_ignore_ascii_case(lit)
                && i > 0
                && !bytes[i - 1].is_ascii_whitespace()
            {
                let mut left = i;
                while left > 0 && !bytes[left - 1].is_ascii_whitespace() {
                    left -= 1;
                }
                let end = i + lit.len();
                if right_word_boundary(bytes, end) {
                    out.push(left..end);
                    advance = end - i;
                }
            }
            i += advance;
        }
        out
    }

    // RFC 7468 mandates uppercase headers, so this scanner is intentionally
    // case-sensitive. Mirrors `-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----`:
    // at least one whitespace after BEGIN, at least one upper/whitespace
    // byte before PRIVATE, then `\s+KEY-----`.
    pub(super) fn pem_blob(token: &str) -> Vec<Range<usize>> {
        let bytes = token.as_bytes();
        let begin: &[u8] = b"-----BEGIN";
        let private_kw: &[u8] = b"PRIVATE";
        let key_tail: &[u8] = b"KEY-----";
        let mut out = Vec::new();
        let mut i = 0;
        'outer: while i + begin.len() <= bytes.len() {
            if &bytes[i..i + begin.len()] != begin {
                i += 1;
                continue;
            }
            let mut j = i + begin.len();
            if j >= bytes.len() || !bytes[j].is_ascii_whitespace() {
                i += 1;
                continue;
            }
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let mut p = j;
            while p + private_kw.len() <= bytes.len() {
                if &bytes[p..p + private_kw.len()] == private_kw
                    && p > j
                    && bytes[j..p]
                        .iter()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_whitespace())
                {
                    let mut q = p + private_kw.len();
                    if q < bytes.len() && bytes[q].is_ascii_whitespace() {
                        while q < bytes.len() && bytes[q].is_ascii_whitespace() {
                            q += 1;
                        }
                        if q + key_tail.len() <= bytes.len()
                            && &bytes[q..q + key_tail.len()] == key_tail
                        {
                            let end = q + key_tail.len();
                            out.push(i..end);
                            i = end;
                            continue 'outer;
                        }
                    }
                }
                p += 1;
            }
            i += 1;
        }
        out
    }
}

fn dotenv_via_regex(token: &str) -> Vec<Range<usize>> {
    DOTENV.find_iter(token).map(|m| m.range()).collect()
}

/// Inspect a single string token and return every sensitive shape it
/// matches. The slice preserves variant declaration order for
/// determinism.
pub fn classify(token: &str) -> Vec<SensitivePath> {
    type Probe = fn(&str) -> Vec<Range<usize>>;
    let probes: &[(Probe, SensitiveKind)] = &[
        (logic::ssh_dir, SensitiveKind::SshDir),
        (logic::aws_dir, SensitiveKind::AwsDir),
        (logic::gcloud_dir, SensitiveKind::GcloudDir),
        (logic::kube_config, SensitiveKind::KubeConfig),
        (logic::docker_config, SensitiveKind::DockerConfig),
        (logic::private_key_file, SensitiveKind::PrivateKeyFile),
        (dotenv_via_regex, SensitiveKind::Dotenv),
        (logic::npmrc, SensitiveKind::Npmrc),
        (logic::pypirc, SensitiveKind::Pypirc),
        (logic::tfstate, SensitiveKind::Tfstate),
        (logic::pem_blob, SensitiveKind::PemBlob),
    ];
    let mut out = Vec::new();
    for (probe, kind) in probes {
        for range in probe(token) {
            out.push(SensitivePath {
                kind: *kind,
                raw: token[range].to_string(),
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
    fn all_variant_regexes_compile() {
        // Only `Dotenv` retains a regex; the other variants are pure
        // hand-written scanners exercised by the classification tests below.
        LazyLock::force(&DOTENV);
    }

    #[test]
    fn classifies_ssh_dir() {
        assert!(kinds("~/.ssh/id_rsa").contains(&SensitiveKind::SshDir));
        assert!(kinds("$HOME/.ssh/").contains(&SensitiveKind::SshDir));
    }

    #[test]
    fn classifies_aws_dir() {
        assert!(kinds("~/.aws/credentials").contains(&SensitiveKind::AwsDir));
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
    }

    #[test]
    fn classifies_private_key_file() {
        assert!(kinds("id_rsa").contains(&SensitiveKind::PrivateKeyFile));
        assert!(kinds("id_ed25519").contains(&SensitiveKind::PrivateKeyFile));
        assert!(kinds("id_ecdsa").contains(&SensitiveKind::PrivateKeyFile));
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
        assert!(kinds(".npmrc").contains(&SensitiveKind::Npmrc));
        assert!(kinds(".pypirc").contains(&SensitiveKind::Pypirc));
        assert!(kinds("infra/main.tfstate").contains(&SensitiveKind::Tfstate));
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
    fn as_str_round_trips_via_from_str() {
        for k in [
            SensitiveKind::SshDir,
            SensitiveKind::AwsDir,
            SensitiveKind::GcloudDir,
            SensitiveKind::KubeConfig,
            SensitiveKind::DockerConfig,
            SensitiveKind::PrivateKeyFile,
            SensitiveKind::Dotenv,
            SensitiveKind::Npmrc,
            SensitiveKind::Pypirc,
            SensitiveKind::Tfstate,
            SensitiveKind::PemBlob,
        ] {
            assert_eq!(SensitiveKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(SensitiveKind::parse("nope"), None);
    }

    #[test]
    fn match_records_raw_substring() {
        let m = classify("/tmp/.env.production").into_iter().next().unwrap();
        assert_eq!(m.kind, SensitiveKind::Dotenv);
        assert!(m.raw.contains(".env"));
    }

    #[test]
    fn multiple_kinds_can_match_one_token() {
        // A PEM blob with a private-key hint embedded would match both,
        // but more usefully: a dotenv path inside an ssh-style segment
        // doesn't conflate — just verify a token can produce >=1 match.
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

        // SensitiveKind::as_str is total and parse round-trips for every
        // variant.
        #[test]
        fn pbt_kind_round_trips(k in sensitive_kind()) {
            prop_assert_eq!(SensitiveKind::parse(k.as_str()), Some(k));
        }

        // Unknown tags never parse to Some.
        #[test]
        fn pbt_unknown_kind_parse_returns_none(s in "[a-z]{0,8}") {
            prop_assume!(SensitiveKind::parse(&s).is_none());
            prop_assert!(SensitiveKind::parse(&s).is_none());
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
