//! Strict redaction for audit log entries.
//!
//! The redactor masks the categories documented in
//! `docs/design/audit.md:64-75`:
//!   1. Sensitive `KEY=VALUE` env assignments and `"key": "value"` JSON
//!      pairs whose key contains `TOKEN`, `KEY`, `SECRET`, `PASSWORD`,
//!      `CREDENTIAL`, or `PRIVATE`.
//!   2. Common token shapes — GitHub classic (`ghp_…`) and fine-grained
//!      PAT (`github_pat_…`), Slack (`xox[abprs]-…`), Stripe
//!      (`sk_live_…` / `pk_live_…` / `rk_live_…` / `whsec_…`),
//!      OpenAI-style (`sk-…`), AWS Access Key ID (`AKIA…`), and JWT.
//!   3. HTTP basic auth (`https://user:pass@host/…`) — masks the
//!      password component.
//!   4. PEM-encoded blobs (`-----BEGIN … PRIVATE KEY-----`).
//!
//! All replacements emit the literal `***`. The redactor is intentionally
//! conservative: false positives are preferable to leaking a credential
//! into an audit file. It runs on already-extracted command strings,
//! never on raw structured input.

#![expect(
    clippy::expect_used,
    reason = "static regex literals validated by tests"
)]

use std::sync::LazyLock;

use regex::Regex;

const PLACEHOLDER: &str = "***";

static SENSITIVE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    // Match `KEY=value` style env assignments where the key contains
    // any of the sensitive substrings. Keys are matched case-insensitively
    // through explicit character classes so the regex compiles without
    // the optional `unicode-case` feature. Values stop at whitespace or
    // shell separators so multi-token redaction stays bounded.
    Regex::new(
        r"\b([A-Za-z0-9_]*(?:[Tt][Oo][Kk][Ee][Nn]|[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee])[A-Za-z0-9_]*)\s*=\s*('[^']*'|\x22[^\x22]*\x22|[^\s;|&]+)",
    )
    .expect("static sensitive-key regex compiles")
});

static GH_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{10,}\b").expect("gh token")
});

// GitHub fine-grained PAT — `github_pat_<22 alnum>_<59 alnum>`.
// Keep the format strict (matches AWS_AKID's fixed-length style) so the
// regex engine cannot wander into long alphanumeric strings; future GitHub
// formats falling outside this shape are caught by the SENSITIVE_KEY net
// when surfaced through env assignments.
static GH_FINE_GRAINED_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b").expect("gh fine-grained pat")
});

// Slack — `xoxa-` / `xoxb-` / `xoxp-` / `xoxr-` / `xoxs-` followed by a
// dash-and-alnum payload. The trailing `\b` anchors on a word boundary,
// so a tail ending in `-` is intentionally left untouched (mirrors the
// existing OPENAI_KEY caveat).
static SLACK_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b").expect("slack token"));

// Stripe — `(sk|pk|rk)_(live|test)_…` API keys plus webhook signing
// secret `whsec_…`. Underscore-separated, so the prefix never collides
// with the dash-style OPENAI_KEY (`sk-…`).
static STRIPE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:sk|pk|rk)_(?:live|test)|whsec)_[A-Za-z0-9]{16,}\b").expect("stripe key")
});

static OPENAI_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsk-[A-Za-z0-9_-]{16,}\b").expect("openai key"));

static AWS_AKID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("aws akid"));

static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").expect("jwt")
});

// JSON-style sensitive `"key": "value"` pairs — same keyword set as
// SENSITIVE_KEY (case-insensitive via explicit char classes). Catches
// GCP service account JSON (`"private_key"`), OAuth (`"client_secret"`,
// `"refresh_token"`), and Firebase admin keys without needing one regex
// per provider.
static JSON_SENSITIVE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#""([A-Za-z0-9_]*(?:[Tt][Oo][Kk][Ee][Nn]|[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee])[A-Za-z0-9_]*)"\s*:\s*"((?:\\.|[^"\\])*)""#,
    )
    .expect("json sensitive key regex compiles")
});

static BASIC_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^:/@\s]+):(?P<pass>[^@\s]+)@")
        .expect("basic auth")
});

static PEM_BLOB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
        .expect("pem blob")
});

/// Keyword fragments shared by [`SENSITIVE_KEY`] and
/// [`JSON_SENSITIVE_KEY`] — both regexes require one of these in the
/// key, case-insensitively.
const KEYWORD_NEEDLES: &[&str] = &[
    "token",
    "key",
    "secret",
    "password",
    "credential",
    "private",
];

/// Strict redactor used by the JSONL audit sink. The algorithm runs
/// each pattern in turn — the order is from most specific (PEM blob,
/// env assignments) to most generic (free-floating tokens).
///
/// Every pattern is gated behind a literal-needle scan of the original
/// input so its `LazyLock` regex is only compiled when the input can
/// actually contain that token shape (ptuf is one process per hook
/// call, so an ungated chain would recompile all ten regexes on every
/// audited decision). Gating on the *original* input is sound: each
/// replacement only deletes matched text or splices in `***` /
/// captured substrings, so no pass can introduce a needle that the
/// original input did not already contain.
pub fn redact_strict(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let has_keyword = KEYWORD_NEEDLES.iter().any(|n| lower.contains(n));

    let mut out = if input.contains("-----BEGIN") {
        PEM_BLOB.replace_all(input, PLACEHOLDER).into_owned()
    } else {
        input.to_owned()
    };

    if has_keyword {
        out = JSON_SENSITIVE_KEY
            .replace_all(&out, |caps: &regex::Captures| {
                format!(r#""{}":"{}""#, &caps[1], PLACEHOLDER)
            })
            .into_owned();

        out = SENSITIVE_KEY
            .replace_all(&out, |caps: &regex::Captures| {
                format!("{}={}", &caps[1], PLACEHOLDER)
            })
            .into_owned();
    }

    if input.contains("://") {
        out = BASIC_AUTH
            .replace_all(&out, |caps: &regex::Captures| {
                format!("{}{}:{}@", &caps["scheme"], &caps["user"], PLACEHOLDER)
            })
            .into_owned();
    }

    if ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .any(|p| input.contains(p))
    {
        out = GH_TOKEN.replace_all(&out, PLACEHOLDER).into_owned();
    }
    if input.contains("github_pat_") {
        out = GH_FINE_GRAINED_TOKEN
            .replace_all(&out, PLACEHOLDER)
            .into_owned();
    }
    if input.contains("xox") {
        out = SLACK_TOKEN.replace_all(&out, PLACEHOLDER).into_owned();
    }
    if ["sk_", "pk_", "rk_", "whsec_"]
        .iter()
        .any(|p| input.contains(p))
    {
        out = STRIPE_KEY.replace_all(&out, PLACEHOLDER).into_owned();
    }
    if input.contains("sk-") {
        out = OPENAI_KEY.replace_all(&out, PLACEHOLDER).into_owned();
    }
    if input.contains("AKIA") {
        out = AWS_AKID.replace_all(&out, PLACEHOLDER).into_owned();
    }
    if input.contains("eyJ") {
        out = JWT.replace_all(&out, PLACEHOLDER).into_owned();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLACK_PREFIXES: &[&str] = &["xoxa", "xoxb", "xoxp", "xoxr", "xoxs"];
    const STRIPE_PREFIXES: &[&str] = &[
        "sk_live", "sk_test", "pk_live", "pk_test", "rk_live", "rk_test", "whsec",
    ];

    #[test]
    fn passes_through_benign_command() {
        let s = "ls -la /tmp";
        assert_eq!(redact_strict(s), s);
    }

    #[test]
    fn redacts_token_env_assignment() {
        let s = "GITHUB_TOKEN=abcdef1234 cargo run";
        let out = redact_strict(s);
        assert_eq!(out, "GITHUB_TOKEN=*** cargo run");
    }

    #[test]
    fn redacts_password_in_quoted_value() {
        let s = "MY_PASSWORD='hunter2 with spaces' env";
        let out = redact_strict(s);
        assert!(out.contains("MY_PASSWORD=***"));
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn redacts_secret_with_double_quotes() {
        let s = "AWS_SECRET=\"abc def\" cmd";
        let out = redact_strict(s);
        assert!(out.contains("AWS_SECRET=***"));
        assert!(!out.contains("abc def"));
    }

    #[test]
    fn redacts_private_key_assignment() {
        let s = "MY_PRIVATE=foo cmd";
        let out = redact_strict(s);
        assert!(out.contains("MY_PRIVATE=***"));
    }

    #[test]
    fn does_not_touch_non_sensitive_assignment() {
        let s = "PATH=/usr/bin cmd";
        assert_eq!(redact_strict(s), s);
    }

    #[test]
    fn redacts_github_token() {
        let s = "curl -H 'Authorization: token ghp_ABCDEFGHIJ1234567890' https://api.github.com";
        let out = redact_strict(s);
        assert!(out.contains("***"));
        assert!(!out.contains("ghp_ABCDEFGHIJ"));
    }

    #[test]
    fn redacts_openai_key() {
        let s = "OPENAI=sk-AbCdEf0123456789xyz curl";
        let out = redact_strict(s);
        assert!(!out.contains("sk-AbCdEf0123456789xyz"));
    }

    #[test]
    fn redacts_aws_access_key_id() {
        let s = "echo AKIAIOSFODNN7EXAMPLE";
        let out = redact_strict(s);
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn redacts_jwt_blob() {
        let s = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwR";
        let out = redact_strict(s);
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwR"));
        assert!(out.contains("***"));
    }

    #[test]
    fn redacts_basic_auth_password_only() {
        let s = "git clone https://alice:hunter2@example.com/repo.git";
        let out = redact_strict(s);
        assert!(out.contains("alice:***@"));
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn redacts_pem_block() {
        let s = "echo -----BEGIN RSA PRIVATE KEY-----\\nMIIEow...\\n-----END RSA PRIVATE KEY-----";
        let out = redact_strict(s);
        assert!(out.contains("***"));
        assert!(!out.contains("MIIEow"));
    }

    #[test]
    fn redacts_github_fine_grained_pat() {
        let pat = format!("github_pat_{}_{}", "A".repeat(22), "B".repeat(59));
        let s = format!("curl -H 'Authorization: token {pat}' https://api.github.com");
        let out = redact_strict(&s);
        assert!(!out.contains(&pat), "kept {pat:?} in {out:?}");
        assert!(out.contains("***"));
    }

    #[test]
    fn does_not_touch_short_github_pat_lookalike() {
        let s = "github_pat_short value";
        assert_eq!(redact_strict(s), s);
    }

    #[test]
    fn redacts_slack_bot_token() {
        for prefix in SLACK_PREFIXES {
            let token = format!("{prefix}-1234567890-ABCDEFGHIJ");
            let s = format!("curl -H 'X-Slack-Token: {token}' https://slack.com/api");
            let out = redact_strict(&s);
            assert!(!out.contains(&token), "kept {token} in {out}");
            assert!(out.contains("***"));
        }
    }

    #[test]
    fn redacts_stripe_live_secret() {
        let key = "sk_live_AbCdEf0123456789xyzABCD";
        let s = format!("stripe charges create --api-key {key}");
        let out = redact_strict(&s);
        assert!(!out.contains(key), "kept {key} in {out}");
        assert!(out.contains("***"));
    }

    #[test]
    fn redacts_stripe_webhook_signing_secret() {
        let key = "whsec_AbCdEf0123456789xyzABCD";
        let s = format!("export WEBHOOK={key} && cmd");
        let out = redact_strict(&s);
        assert!(!out.contains(key), "kept {key} in {out}");
        assert!(out.contains("***"));
    }

    #[test]
    fn redacts_json_private_key_block() {
        let s = r#"echo '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEow...\n-----END PRIVATE KEY-----","client_email":"x@y"}'"#;
        let out = redact_strict(s);
        assert!(!out.contains("MIIEow"));
        assert!(out.contains(r#""private_key":"***""#));
    }

    #[test]
    fn redacts_json_client_secret_without_pem() {
        let s = r#"curl -d '{"client_secret":"abcdef0123456789"}'"#;
        let out = redact_strict(s);
        assert!(!out.contains("abcdef0123456789"));
        assert!(out.contains(r#""client_secret":"***""#));
    }

    #[test]
    fn redacts_json_refresh_token_with_spaces() {
        let s = r#"{"refresh_token" : "1//abcDEF_xyz-123"}"#;
        let out = redact_strict(s);
        assert!(!out.contains("1//abcDEF_xyz-123"));
    }

    #[test]
    fn does_not_touch_benign_json_field() {
        let s = r#"{"name":"alice","age":30}"#;
        assert_eq!(redact_strict(s), s);
    }

    #[test]
    fn handles_multiple_categories_in_one_string() {
        let s = "TOKEN=abc curl -u u:p@host ghp_ABCDEFGHIJ12345";
        let out = redact_strict(s);
        assert!(out.contains("TOKEN=***"));
        assert!(!out.contains("ghp_"));
    }

    #[test]
    fn long_input_does_not_break_replacement() {
        let mut s = String::new();
        for _ in 0..200 {
            s.push_str("ls -la; ");
        }
        s.push_str("TOKEN=abc");
        let out = redact_strict(&s);
        assert!(out.ends_with("TOKEN=***"));
    }

    #[test]
    fn placeholder_constant_is_stable() {
        assert_eq!(PLACEHOLDER, "***");
    }

    use proptest::prelude::*;

    proptest! {
        // Idempotence: redacting twice yields the same result as once.
        #[test]
        fn pbt_redact_is_idempotent(s in "[ -~]{0,80}") {
            let once = redact_strict(&s);
            let twice = redact_strict(&once);
            prop_assert_eq!(once, twice);
        }

        // Never panics on adversarial input.
        #[test]
        fn pbt_redact_never_panics(s in ".{0,80}") {
            let _ = redact_strict(&s);
        }

        // GitHub token shape is always replaced.
        #[test]
        fn pbt_redacts_github_tokens(suffix in "[A-Za-z0-9]{10,30}") {
            for prefix in ["ghp", "gho", "ghu", "ghs", "ghr"] {
                let needle = format!("{prefix}_{suffix}");
                let s = format!("echo {needle} done");
                let out = redact_strict(&s);
                prop_assert!(!out.contains(&needle), "kept {needle:?} in {out:?}");
                prop_assert!(out.contains("***"));
            }
        }

        // OpenAI-style key shape is replaced when the trailing token is
        // word-boundary-terminated. The detector regex anchors with `\b`
        // on both sides, so a suffix ending in `-` (a non-word char) is
        // intentionally not detected — guard the suffix accordingly.
        #[test]
        fn pbt_redacts_openai_keys(suffix in "[A-Za-z0-9_-]{15,39}[A-Za-z0-9_]") {
            let needle = format!("sk-{suffix}");
            let s = format!("ENV={needle} cmd");
            let out = redact_strict(&s);
            prop_assert!(!out.contains(&needle));
        }

        // AWS access key id shape is always replaced.
        #[test]
        fn pbt_redacts_aws_akid(suffix in "[A-Z0-9]{16}") {
            let needle = format!("AKIA{suffix}");
            let s = format!("echo {needle}");
            let out = redact_strict(&s);
            prop_assert!(!out.contains(&needle));
        }

        // Sensitive `KEY=VALUE` shape (with sensitive substring in key)
        // strips the value.
        #[test]
        fn pbt_redacts_sensitive_env_assignments(value in "[A-Za-z0-9_]{1,30}") {
            for k in ["GITHUB_TOKEN", "MY_SECRET", "DB_PASSWORD", "API_KEY"] {
                let s = format!("{k}={value} cmd");
                let out = redact_strict(&s);
                let placeholder_form = format!("{k}=***");
                let raw_form = format!("{k}={value}");
                prop_assert!(out.contains(&placeholder_form));
                prop_assert!(!out.contains(&raw_form));
            }
        }

        // Plain ascii without any sensitive tokens passes through unchanged.
        #[test]
        fn pbt_benign_passes_through(s in "[a-zA-Z0-9 /._-]{0,60}") {
            // Avoid accidental key-shaped substrings.
            prop_assume!(!s.contains("AKIA"));
            prop_assume!(!s.contains("ghp_"));
            prop_assume!(!s.contains("gho_"));
            prop_assume!(!s.contains("ghu_"));
            prop_assume!(!s.contains("ghs_"));
            prop_assume!(!s.contains("ghr_"));
            prop_assume!(!s.contains("github_pat_"));
            prop_assume!(!s.contains("sk-"));
            for prefix in STRIPE_PREFIXES {
                let needle = format!("{prefix}_");
                prop_assume!(!s.contains(&needle));
            }
            for prefix in SLACK_PREFIXES {
                let needle = format!("{prefix}-");
                prop_assume!(!s.contains(&needle));
            }
            prop_assume!(!s.contains("eyJ"));
            // No `KEY=VALUE` shape with sensitive substrings:
            let lower = s.to_lowercase();
            for needle in ["token", "key", "secret", "password", "credential", "private"] {
                prop_assume!(!lower.contains(needle));
            }
            prop_assert_eq!(redact_strict(&s), s);
        }

        // Basic-auth password is replaced with `***`; the username is
        // preserved unchanged. Schemes and hosts are kept intact too.
        #[test]
        fn pbt_basic_auth_redaction_keeps_user(
            scheme in "(https?|ssh|ftp)",
            user in "[a-zA-Z][a-zA-Z0-9._-]{0,12}",
            pass in "[A-Za-z0-9!#$%^*]{1,20}",
            host in "[a-z][a-z0-9.-]{0,12}\\.com",
        ) {
            let s = format!("{scheme}://{user}:{pass}@{host}/path");
            let out = redact_strict(&s);
            let user_mask = format!("{user}:***@");
            let scheme_prefix = format!("{scheme}://");
            prop_assert!(out.contains(&user_mask));
            prop_assert!(out.contains(&scheme_prefix));
            prop_assert!(out.contains(host.as_str()));
            // Password leakage: ensure the literal pass token is gone.
            // We can't simply check absence (pass might be a substring of
            // user/host), but we can require the new form contains the
            // mask between user/host.
            prop_assert!(out.contains(":***@"));
        }

        // PEM blob redaction always drops the body between BEGIN / END
        // markers when both are present.
        #[test]
        fn pbt_pem_blob_redaction_replaces_block(
            label in "(?:RSA |EC |DSA |OPENSSH |)",
            body in "[A-Za-z0-9/+= \\n]{16,80}",
        ) {
            let blob = format!(
                "-----BEGIN {label}PRIVATE KEY-----\n{body}\n-----END {label}PRIVATE KEY-----"
            );
            let s = format!("echo '{blob}' && true");
            let out = redact_strict(&s);
            prop_assert!(out.contains("***"));
            // The embedded body must be gone. body is at least 16 chars
            // and made of base64-friendly classes, so substring presence
            // means it leaked.
            prop_assert!(!out.contains(&body), "leaked body in {out:?}");
        }

        // GitHub fine-grained PAT shape `github_pat_<22>_<59>` is always
        // replaced.
        #[test]
        fn pbt_redacts_github_fine_grained_pat(
            head in "[A-Za-z0-9]{22}",
            tail in "[A-Za-z0-9]{59}",
        ) {
            let token = format!("github_pat_{head}_{tail}");
            let s = format!("curl -H 'Authorization: token {token}' api");
            let out = redact_strict(&s);
            prop_assert!(!out.contains(&token), "kept {token:?} in {out:?}");
            prop_assert!(out.contains("***"));
        }

        // Slack token shapes are always replaced. The trailing token must
        // end on a word character so that `\b` matches; the suffix
        // generator anchors with `[A-Za-z0-9]` accordingly. Sampling the
        // prefix as a proptest arg keeps total cases at the default 256
        // instead of 5×.
        #[test]
        fn pbt_redacts_slack_tokens(
            prefix in proptest::sample::select(SLACK_PREFIXES),
            suffix in "[A-Za-z0-9-]{9,29}[A-Za-z0-9]",
        ) {
            let needle = format!("{prefix}-{suffix}");
            let s = format!("ENV={needle} cmd");
            let out = redact_strict(&s);
            prop_assert!(!out.contains(&needle), "kept {needle:?} in {out:?}");
        }

        // Stripe API keys (`sk|pk|rk_live|test_…`) and webhook secret
        // (`whsec_…`) are always replaced.
        #[test]
        fn pbt_redacts_stripe_keys(
            prefix in proptest::sample::select(STRIPE_PREFIXES),
            suffix in "[A-Za-z0-9]{16,40}",
        ) {
            let needle = format!("{prefix}_{suffix}");
            let s = format!("echo {needle}");
            let out = redact_strict(&s);
            prop_assert!(!out.contains(&needle), "kept {needle:?} in {out:?}");
        }

        // JSON-style `"<sensitive-key>": "<value>"` strips the value
        // regardless of value content (modulo embedded `"` / `\` which the
        // generator avoids to keep the JSON well-formed). Presence of the
        // masked form `"k":"***"` is the canonical witness — checking for
        // value absence directly is unreliable because short values may
        // coincide with characters in the key (e.g. `_` appearing in
        // `client_credential`).
        #[test]
        fn pbt_redacts_json_sensitive_values(value in "[A-Za-z0-9/+=.-]{1,40}") {
            for k in [
                "token",
                "secret",
                "password",
                "private_key",
                "api_key",
                "client_credential",
            ] {
                let s = format!(r#"{{"{k}":"{value}"}}"#);
                let out = redact_strict(&s);
                let masked = format!(r#""{k}":"***""#);
                prop_assert!(out.contains(&masked), "missing mask for {k} in {out:?}");
            }
        }

        // Output never contains the literal `***` placeholder more than
        // once per redacted token (idempotence corollary). We check that
        // running redact_strict on a redacted output does not introduce
        // additional placeholders.
        #[test]
        fn pbt_idempotent_does_not_grow_placeholders(s in "[ -~]{0,80}") {
            let once = redact_strict(&s);
            let twice = redact_strict(&once);
            let count_once = once.matches(PLACEHOLDER).count();
            let count_twice = twice.matches(PLACEHOLDER).count();
            prop_assert_eq!(count_once, count_twice);
        }

        // Redaction never expands the input by more than a bounded
        // factor: each match shrinks to "***", so length must stay
        // ≤ original length + (matches × len("***"))-ish. We assert a
        // simpler upper bound: the output is no longer than the input
        // plus the longest expansion we can think of (3× input).
        #[test]
        fn pbt_redaction_does_not_explode_length(s in "[ -~]{0,200}") {
            let out = redact_strict(&s);
            prop_assert!(out.len() <= s.len() * 3 + 16);
        }

        // Multi-token stuffing: combining several detectable patterns in
        // one string redacts every one of them.
        // The JWT detector anchors on `\b`, so the last segment must end
        // in a word character (not `-`); we constrain the suffix
        // accordingly.
        #[test]
        fn pbt_multi_token_stuffing(
            ghp in "ghp_[A-Za-z0-9]{12,20}",
            akia in "AKIA[A-Z0-9]{16}",
            jwt_a in "[A-Za-z0-9_-]{4,8}",
            jwt_b in "[A-Za-z0-9_-]{4,8}",
            jwt_c in "[A-Za-z0-9_-]{3,7}[A-Za-z0-9_]",
        ) {
            let jwt = format!("eyJ{jwt_a}.{jwt_b}.{jwt_c}");
            let s = format!("X={ghp} Y={akia} Z={jwt}");
            let out = redact_strict(&s);
            prop_assert!(!out.contains(&ghp));
            prop_assert!(!out.contains(&akia));
            prop_assert!(!out.contains(&jwt));
        }

        // Length is preserved or reduced: the placeholder is shorter
        // than each minimum-length token detector, so redaction either
        // shrinks the string or leaves it unchanged.
        #[test]
        fn pbt_redaction_of_known_tokens_shrinks_or_equals(
            ghp in "ghp_[A-Za-z0-9]{12,30}",
        ) {
            let s = format!("echo {ghp}");
            let out = redact_strict(&s);
            prop_assert!(out.len() <= s.len());
        }
    }
}
