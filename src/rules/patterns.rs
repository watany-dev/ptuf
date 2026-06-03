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
    // ASCII case-insensitive matching is scoped to each literal path
    // fragment via `(?i-u:…)` so case-variant filesystems still classify.
    // The `-u` selects ASCII case folding so the regex compiles without
    // the optional `unicode-case` feature (kept disabled per `Cargo.toml`).
    // Surrounding `\s`/`\b`/`\S` stay Unicode-aware so the regex matches
    // only valid UTF-8 and Unicode whitespace still anchors token
    // boundaries. The PEM header branch is naturally case-sensitive,
    // honouring RFC 7468's uppercase requirement. The dotenv anchor
    // includes glob metacharacters (`*`, `?`, `[`, `]`) and brace-expansion
    // punctuation (`{`, `}`, `,`) so literal-glob / `{a,b}.env` argv tokens
    // are caught.
    Regex::new(concat!(
        r"(?x)",
        r"(?:",
        r"(?:~|\$HOME|\$\{HOME\})/(?i-u:\.ssh)(?:/|\b)",
        r"|(?:~|\$HOME|\$\{HOME\})/(?i-u:\.aws)(?:/|\b)",
        r"|(?:~|\$HOME|\$\{HOME\})/(?i-u:\.config/gcloud)(?:/|\b)",
        r"|(?:~|\$HOME|\$\{HOME\})/(?i-u:\.kube/config)\b",
        r"|(?:~|\$HOME|\$\{HOME\})/(?i-u:\.docker/config\.json)\b",
        r"|\b(?i-u:id_(?:rsa|ed25519|ecdsa))\b",
        r"|(?:^|/|\s|[*?\[\]={},])(?i-u:\.env)(?:\.[A-Za-z0-9_-]+)?\b",
        r"|\b(?i-u:\.npmrc)\b",
        r"|\b(?i-u:\.pypirc)\b",
        r"|\S+(?i-u:\.tfstate)\b",
        r"|-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----",
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

    #[test]
    fn sensitive_path_matches_dotenv_case_insensitive() {
        let cases = [
            (".env", true),
            (".ENV", true),
            ("foo/.env.bar", true),
            ("/repo/.env", true),
        ];
        for (token, expect) in cases {
            assert_eq!(SENSITIVE_PATH.is_match(token), expect, "token {token:?}");
        }
    }

    #[test]
    fn sensitive_path_rejects_non_secret_paths() {
        assert!(!SENSITIVE_PATH.is_match("README"));
        assert!(!SENSITIVE_PATH.is_match("/tmp/foo"));
    }

    #[test]
    fn sensitive_path_dd_if_form() {
        assert!(SENSITIVE_PATH.is_match("if=.env"));
    }

    #[test]
    fn sensitive_path_brace_expansion_form() {
        for token in [
            "{a,b}.env",
            "{x,y,z}.env",
            "{.env,.env.local}",
            "prefix{a,b}.env",
            "{app,web}.env.production",
        ] {
            assert!(SENSITIVE_PATH.is_match(token), "token {token:?}");
        }
    }

    use crate::testing::proptest::{
        dotenv_anchored_literal_token, dotenv_brace_token, dotenv_false_positive_token,
    };
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pbt_brace_dotenv_matches_sensitive_path(token in dotenv_brace_token()) {
            prop_assert!(
                SENSITIVE_PATH.is_match(&token),
                "SENSITIVE_PATH missed brace token {token:?}",
            );
        }

        #[test]
        fn pbt_anchored_dotenv_literals_match_sensitive_path(token in dotenv_anchored_literal_token()) {
            prop_assert!(
                SENSITIVE_PATH.is_match(&token),
                "SENSITIVE_PATH missed {token:?}",
            );
        }

        #[test]
        fn pbt_dotenv_false_positives_rejected(token in dotenv_false_positive_token()) {
            prop_assert!(
                !SENSITIVE_PATH.is_match(&token),
                "SENSITIVE_PATH false positive on {token:?}",
            );
        }

        #[test]
        fn pbt_sensitive_path_is_match_never_panics(s in "[ -~]{0,80}") {
            let _ = SENSITIVE_PATH.is_match(&s);
        }
    }
}
