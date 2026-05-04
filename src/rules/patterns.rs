use regex::Regex;
use std::sync::LazyLock;

/// Network sink commands that can exfiltrate data when given sensitive paths.
/// Used by `core.secrets.sensitive-path-to-network`.
#[allow(clippy::expect_used)]
pub static NETWORK_SINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:curl|wget|nc|ncat|scp|rsync|ftp|sftp)\b").expect("NETWORK_SINK regex")
});

/// Sensitive filesystem paths whose contents must not flow into network sinks.
/// See `docs/design/policy-packs.md` `core.secrets`.
#[allow(clippy::expect_used)]
pub static SENSITIVE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?x)",
        r"(?:",
        r"(?:~|\$HOME|\$\{HOME\})/\.ssh(?:/|\b)",
        r"|(?:~|\$HOME|\$\{HOME\})/\.aws(?:/|\b)",
        r"|(?:~|\$HOME|\$\{HOME\})/\.config/gcloud(?:/|\b)",
        r"|(?:~|\$HOME|\$\{HOME\})/\.kube/config\b",
        r"|(?:~|\$HOME|\$\{HOME\})/\.docker/config\.json\b",
        r"|\bid_(?:rsa|ed25519|ecdsa)\b",
        r"|(?:^|/|\s)\.env(?:\.[A-Za-z0-9_-]+)?\b",
        r"|\b\.npmrc\b",
        r"|\b\.pypirc\b",
        r"|\S+\.tfstate\b",
        r"|-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----",
        r")",
    ))
    .expect("SENSITIVE_PATH regex")
});

/// Pipeline pattern for `<fetcher> ... | <interpreter>`.
/// Used by `core.network.remote-script-pipe`.
#[allow(clippy::expect_used)]
pub static REMOTE_PIPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?x)",
        r"\b(?:curl|wget|fetch)\b",
        r"[^|]*",
        r"\|\s*",
        r"(?:sudo\s+)?",
        r"(?:bash|sh|zsh|fish|ksh|dash|python3?|ruby|node|perl)\b",
    ))
    .expect("REMOTE_PIPE regex")
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    /// Eagerly compile every shared regex so a malformed pattern fails loudly
    /// in tests instead of panicking at first use in production.
    #[test]
    fn all_regexes_compile() {
        LazyLock::force(&NETWORK_SINK);
        LazyLock::force(&SENSITIVE_PATH);
        LazyLock::force(&REMOTE_PIPE);
    }
}
