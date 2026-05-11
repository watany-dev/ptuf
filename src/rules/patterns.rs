use regex::Regex;
use std::sync::LazyLock;

use crate::facts::shell::Argv;

/// Sensitive filesystem paths whose contents must not flow into network sinks.
/// See `docs/design/policy-packs.md` `core.secrets`.
///
/// Applied to individual shell tokens (heads, args, env values) via
/// [`facts::shell`](crate::facts::shell), so anchors like `^` align with
/// token boundaries rather than command-string positions.
#[expect(
    clippy::expect_used,
    reason = "static pattern literal validated by tests"
)]
pub static SENSITIVE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    // `(?i)` defends case-insensitive filesystems and `.ENV`/`.SSH` variants.
    // The PEM header sub-pattern is wrapped in `(?-i)` to honour RFC 7468's
    // uppercase requirement. The dotenv anchor includes glob metacharacters
    // (`*`, `?`, `[`, `]`) so literal-glob argv tokens are caught.
    Regex::new(concat!(
        r"(?ix)",
        r"(?:",
        r"(?:~|\$HOME|\$\{HOME\})/\.ssh(?:/|\b)",
        r"|(?:~|\$HOME|\$\{HOME\})/\.aws(?:/|\b)",
        r"|(?:~|\$HOME|\$\{HOME\})/\.config/gcloud(?:/|\b)",
        r"|(?:~|\$HOME|\$\{HOME\})/\.kube/config\b",
        r"|(?:~|\$HOME|\$\{HOME\})/\.docker/config\.json\b",
        r"|\bid_(?:rsa|ed25519|ecdsa)\b",
        r"|(?:^|/|\s|[*?\[\]=])\.env(?:\.[A-Za-z0-9_-]+)?\b",
        r"|\b\.npmrc\b",
        r"|\b\.pypirc\b",
        r"|\S+\.tfstate\b",
        r"|(?-i:-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----)",
        r")",
    ))
    .expect("SENSITIVE_PATH regex")
});

/// True when this argv has a token (head, positional/flag arg, or env
/// assignment value) that matches [`SENSITIVE_PATH`]. Shared by every
/// rule that needs "does this argv mention a credentials path?".
pub(super) fn argv_references_sensitive(argv: &Argv) -> bool {
    if SENSITIVE_PATH.is_match(&argv.head) {
        return true;
    }
    if argv.args.iter().any(|a| SENSITIVE_PATH.is_match(a)) {
        return true;
    }
    argv.env_assignments
        .iter()
        .any(|e| SENSITIVE_PATH.is_match(&e.value))
}

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
