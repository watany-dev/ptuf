use regex::Regex;
use std::sync::LazyLock;

/// Sensitive filesystem paths whose contents must not flow into network sinks.
/// See `docs/design/policy-packs.md` `core.secrets`.
///
/// Applied to individual shell tokens (heads, args, env values) via
/// [`facts::shell`](crate::facts::shell), so anchors like `^` align with
/// token boundaries rather than command-string positions.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    /// Eagerly compile the shared regex so a malformed pattern fails loudly
    /// in tests instead of panicking at first use in production.
    #[test]
    fn all_regexes_compile() {
        LazyLock::force(&SENSITIVE_PATH);
    }
}
