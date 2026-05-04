//! Strict redaction for audit log entries.
//!
//! The redactor masks five categories of value documented in
//! `docs/design/audit.md:64-75`:
//!   1. Environment-variable assignments whose key includes `TOKEN`,
//!      `KEY`, `SECRET`, `PASSWORD`, `CREDENTIAL`, or `PRIVATE`.
//!   2. Common token shapes (`ghp_…`, `sk-…`, `AKIA…`, JWT 3-segment).
//!   3. HTTP basic auth (`https://user:pass@host/…`) — masks the
//!      password component.
//!   4. PEM-encoded blobs (`-----BEGIN … PRIVATE KEY-----`).
//!   5. (Future) project-root substitution — out of scope for v0.2.
//!
//! All replacements emit the literal `***`. The redactor is intentionally
//! conservative: false positives are preferable to leaking a credential
//! into an audit file. It runs on already-extracted command strings,
//! never on raw structured input.

#![allow(clippy::expect_used)]

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

static OPENAI_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsk-[A-Za-z0-9_-]{16,}\b").expect("openai key"));

static AWS_AKID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("aws akid"));

static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").expect("jwt")
});

static BASIC_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^:/@\s]+):(?P<pass>[^@\s]+)@")
        .expect("basic auth")
});

static PEM_BLOB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
        .expect("pem blob")
});

/// Strict redactor used by the JSONL audit sink. The algorithm runs
/// each pattern in turn — the order is from most specific (PEM blob,
/// env assignments) to most generic (free-floating tokens).
pub fn redact_strict(input: &str) -> String {
    let mut out = PEM_BLOB.replace_all(input, PLACEHOLDER).into_owned();

    out = SENSITIVE_KEY
        .replace_all(&out, |caps: &regex::Captures| {
            format!("{}={}", &caps[1], PLACEHOLDER)
        })
        .into_owned();

    out = BASIC_AUTH
        .replace_all(&out, |caps: &regex::Captures| {
            format!("{}{}:{}@", &caps["scheme"], &caps["user"], PLACEHOLDER)
        })
        .into_owned();

    out = GH_TOKEN.replace_all(&out, PLACEHOLDER).into_owned();
    out = OPENAI_KEY.replace_all(&out, PLACEHOLDER).into_owned();
    out = AWS_AKID.replace_all(&out, PLACEHOLDER).into_owned();
    out = JWT.replace_all(&out, PLACEHOLDER).into_owned();

    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
