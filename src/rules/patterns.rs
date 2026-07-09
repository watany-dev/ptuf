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
        r"(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.ssh)(?:/|\b)",
        r"|(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.aws)(?:/|\b)",
        r"|(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.config/gcloud)(?:/|\b)",
        r"|(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.kube/config)\b",
        r"|(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.docker/config\.json)\b",
        r"|\b(?i-u:id_(?:rsa|dsa|ecdsa|ed25519))\b",
        r"|(?:^|/|\s|[*?\[\]={},])(?i-u:\.env)(?:\.[A-Za-z0-9_-]+)?\b",
        r"|(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.npmrc)\b",
        r"|(?:^|/|\s|(?:~|\$HOME|\$\{HOME\})/)(?i-u:\.pypirc)\b",
        r"|\S+(?i-u:\.tfstate)\b",
        r"|-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----",
        r")",
    ))
    .expect("SENSITIVE_PATH regex")
});

/// Lowercase literal fragments — one per [`SENSITIVE_PATH`] alternation
/// branch. A token that contains none of them cannot match the regex,
/// so callers can skip both the `LazyLock` compilation (paid once per
/// short-lived hook process) and the scan on the common safe-token
/// path. Keep in sync with the pattern above; the
/// `pbt_prefilter_matches_regex` property test pins the equivalence.
const SENSITIVE_NEEDLES: &[&str] = &[
    ".ssh",
    ".aws",
    "gcloud",
    ".kube/config",
    ".docker/config",
    "id_",
    ".env",
    ".npmrc",
    ".pypirc",
    ".tfstate",
    "-----begin",
];

/// Prefiltered equivalent of `SENSITIVE_PATH.is_match`. All rule-side
/// callers go through this so the big alternation regex is only
/// compiled when a token actually carries a credential-shaped
/// fragment.
pub(super) fn matches_sensitive_path(token: &str) -> bool {
    let normalized = crate::facts::sensitive::normalize_for_sensitive_match(token);
    // The regex only folds ASCII case (`(?i-u:…)`), so an ASCII
    // lowercase of the normalized token is enough for the needle gate.
    let lower = normalized.to_ascii_lowercase();
    if !SENSITIVE_NEEDLES.iter().any(|n| lower.contains(n)) {
        return false;
    }
    SENSITIVE_PATH.is_match(normalized.as_ref())
}

/// True when this argv has a token (head, positional/flag arg, or env
/// assignment value) that matches [`SENSITIVE_PATH`]. Shared by every
/// rule that needs "does this argv mention a credentials path?".
pub(super) fn argv_references_sensitive(argv: &Argv) -> bool {
    if matches_sensitive_path(&argv.head) {
        return true;
    }
    if argv.args.iter().any(|a| matches_sensitive_path(a)) {
        return true;
    }
    argv.env_assignments
        .iter()
        .any(|e| matches_sensitive_path(&e.value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_path_matches_cyrillic_dotenv() {
        assert!(matches_sensitive_path(".\u{0435}nv"));
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
        assert!(SENSITIVE_PATH.is_match("if=.env"));
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

    #[test]
    fn sensitive_path_rejects_non_secret_paths() {
        assert!(!SENSITIVE_PATH.is_match("README"));
        assert!(!SENSITIVE_PATH.is_match("/tmp/foo"));
    }

    #[test]
    fn sensitive_path_matches_npmrc_pypirc_at_path_boundaries() {
        // Real credential files live at a path boundary (`~/.npmrc`,
        // `/home/u/.pypirc`, or a bare leading `.npmrc`). A leading `\b`
        // anchor would miss all of these because `.` is a non-word char,
        // yet it would wrongly match the `data.npmrc` lookalike.
        for token in [
            ".npmrc",
            "~/.npmrc",
            "/home/user/.npmrc",
            "$HOME/.npmrc",
            ".pypirc",
            "~/.pypirc",
            "/root/.pypirc",
        ] {
            assert!(SENSITIVE_PATH.is_match(token), "missed {token:?}");
        }
        for token in ["data.npmrc", "xpypirc", "npmrc"] {
            assert!(!SENSITIVE_PATH.is_match(token), "false positive {token:?}");
        }
    }

    #[test]
    fn sensitive_path_matches_all_ssh_key_families() {
        for token in [
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "~/.ssh/id_dsa",
        ] {
            assert!(SENSITIVE_PATH.is_match(token), "missed {token:?}");
        }
    }

    #[test]
    fn sensitive_path_matches_absolute_secret_directories() {
        let cases = [
            ("/home/user/.ssh/config", true),
            ("/root/.ssh/id_rsa", true),
            ("/home/user/.aws/credentials", true),
            ("/root/.aws/credentials", true),
            (
                "/home/user/.config/gcloud/application_default_credentials.json",
                true,
            ),
            ("/home/alice/.kube/config", true),
            ("/var/root/.docker/config.json", true),
            ("~/.ssh/id_rsa", true),
            ("$HOME/.aws/credentials", true),
        ];
        for (token, expect) in cases {
            assert_eq!(SENSITIVE_PATH.is_match(token), expect, "token {token:?}");
        }
    }

    #[test]
    fn argv_references_sensitive_checks_head_and_args() {
        let bash = crate::facts::shell::parse("id_rsa");
        let argv = bash.commands().into_iter().next().expect("argv");
        assert!(argv_references_sensitive(argv));
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

        // The needle prefilter must be behaviour-preserving: for any
        // printable-ASCII token the gated helper and the raw regex
        // agree. Guards SENSITIVE_NEEDLES against drifting out of sync
        // with the alternation branches.
        #[test]
        fn pbt_prefilter_matches_regex(s in "[ -~]{0,80}") {
            prop_assert_eq!(
                matches_sensitive_path(&s),
                SENSITIVE_PATH.is_match(&s),
                "prefilter diverged on {:?}",
                s,
            );
        }

        // Classifier parity: the Bash-side `SENSITIVE_PATH` (source of
        // truth for `sensitive-path-to-network` / `sensitive-bash-read`)
        // and the file-tool-side `classify` (which feeds `facts.sensitive`
        // and `sensitive-read`) must agree on whether a token is a
        // credentials path. A divergence means one surface catches a
        // secret shape the other lets through — exactly the npmrc/pypirc
        // anchor bug this property was added to pin. Exercised over both
        // arbitrary printable ASCII and credential-shaped tokens.
        #[test]
        fn pbt_sensitive_path_matches_classify(s in "[ -~]{0,80}") {
            prop_assert_eq!(
                SENSITIVE_PATH.is_match(&s),
                !crate::facts::sensitive::classify(&s).is_empty(),
                "SENSITIVE_PATH and classify diverged on {:?}",
                s,
            );
        }

        #[test]

        #[test]
        fn pbt_sensitive_path_matches_classify_on_homoglyphs(
            (token, _needle) in crate::testing::proptest::homoglyph_substituted_needle(),
        ) {
            prop_assert_eq!(
                crate::rules::patterns::matches_sensitive_path(&token),
                !crate::facts::sensitive::classify(&token).is_empty(),
            );
        }

        fn pbt_sensitive_path_matches_classify_on_secret_shapes(
            s in crate::testing::proptest::sensitive_shaped_token(),
        ) {
            prop_assert_eq!(
                SENSITIVE_PATH.is_match(&s),
                !crate::facts::sensitive::classify(&s).is_empty(),
                "SENSITIVE_PATH and classify diverged on {:?}",
                s,
            );
        }
    }
}
