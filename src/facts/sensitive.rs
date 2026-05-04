//! Classify a string against the protected-credentials shapes defined in
//! [`docs/design/policy-packs.md`] §`core.secrets`.
//!
//! The legacy [`crate::rules::patterns::SENSITIVE_PATH`] regex remains
//! the source of truth for the existing `core.secrets.sensitive-path-to-network`
//! rule. This module adds an *additive* per-variant view so other tools
//! (`Read`, `Edit`, `Write`, plugin DSL) can match a typed
//! [`SensitiveKind`] without disturbing the existing rule's tests.

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

#[allow(clippy::expect_used)]
fn build(pat: &str) -> Regex {
    Regex::new(pat).expect("sensitive variant regex")
}

static SSH_DIR: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?:^|[\s])(?:~|\$HOME|\$\{HOME\})/\.ssh(?:/|$|\b)"));
static AWS_DIR: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?:^|[\s])(?:~|\$HOME|\$\{HOME\})/\.aws(?:/|$|\b)"));
static GCLOUD_DIR: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?:^|[\s])(?:~|\$HOME|\$\{HOME\})/\.config/gcloud(?:/|$|\b)"));
static KUBE_CONFIG: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?:~|\$HOME|\$\{HOME\})/\.kube/config\b"));
static DOCKER_CONFIG: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?:~|\$HOME|\$\{HOME\})/\.docker/config\.json\b"));
static PRIVATE_KEY_FILE: LazyLock<Regex> = LazyLock::new(|| build(r"\bid_(?:rsa|ed25519|ecdsa)\b"));
static DOTENV: LazyLock<Regex> =
    LazyLock::new(|| build(r"(?:^|/|\s)\.env(?:\.[A-Za-z0-9_-]+)?\b"));
static NPMRC: LazyLock<Regex> = LazyLock::new(|| build(r"\.npmrc\b"));
static PYPIRC: LazyLock<Regex> = LazyLock::new(|| build(r"\.pypirc\b"));
static TFSTATE: LazyLock<Regex> = LazyLock::new(|| build(r"\S+\.tfstate\b"));
static PEM_BLOB: LazyLock<Regex> =
    LazyLock::new(|| build(r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----"));

/// Inspect a single string token and return every sensitive shape it
/// matches. The slice preserves variant declaration order for
/// determinism.
pub fn classify(token: &str) -> Vec<SensitivePath> {
    let probes: &[(&LazyLock<Regex>, SensitiveKind)] = &[
        (&SSH_DIR, SensitiveKind::SshDir),
        (&AWS_DIR, SensitiveKind::AwsDir),
        (&GCLOUD_DIR, SensitiveKind::GcloudDir),
        (&KUBE_CONFIG, SensitiveKind::KubeConfig),
        (&DOCKER_CONFIG, SensitiveKind::DockerConfig),
        (&PRIVATE_KEY_FILE, SensitiveKind::PrivateKeyFile),
        (&DOTENV, SensitiveKind::Dotenv),
        (&NPMRC, SensitiveKind::Npmrc),
        (&PYPIRC, SensitiveKind::Pypirc),
        (&TFSTATE, SensitiveKind::Tfstate),
        (&PEM_BLOB, SensitiveKind::PemBlob),
    ];
    let mut out = Vec::new();
    for (re, kind) in probes {
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
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn kinds(s: &str) -> Vec<SensitiveKind> {
        classify(s).into_iter().map(|m| m.kind).collect()
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
        assert!(kinds("~/.config/gcloud/application_default_credentials.json")
            .contains(&SensitiveKind::GcloudDir));
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
}
