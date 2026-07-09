//! Classify a string against the protected-credentials shapes defined in
//! `docs/design/policy-packs.md` §`core.secrets`.
//!
//! The legacy [`crate::rules::patterns::SENSITIVE_PATH`] regex remains
//! the source of truth for the existing `core.secrets.sensitive-path-to-network`
//! rule. This module adds an *additive* per-variant view so other tools
//! (`Read`, `Edit`, `Write`, plugin DSL) can match a typed
//! [`SensitiveKind`] without disturbing the existing rule's tests.

use regex::Regex;
use std::borrow::Cow;
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

/// Fold needle lookalikes (Cyrillic / Greek) to ASCII, after optional
/// Latin-1→UTF-8 recovery for Bash `push_latin1` mojibake.
///
/// ASCII-only tokens return [`Cow::Borrowed`] (zero cost). Non-ASCII
/// outside the fold table is left unchanged (fail-closed; no FP on
/// legitimate non-ASCII filenames). See ADR 0007 / issue #163.
pub(crate) fn fold_sensitive_homoglyphs(token: &str) -> Cow<'_, str> {
    if token.is_ascii() {
        return Cow::Borrowed(token);
    }
    // Bash path: Latin-1 mojibake of UTF-8 → recover when every char ≤ U+00FF.
    let recovered: Cow<'_, str> = if token.chars().all(|c| c <= '\u{00FF}') {
        let bytes: Vec<u8> = token.chars().map(|c| c as u8).collect();
        match std::str::from_utf8(&bytes) {
            Ok(s) => Cow::Owned(s.to_owned()),
            Err(_) => Cow::Borrowed(token),
        }
    } else {
        Cow::Borrowed(token)
    };
    let folded = fold_lookalike_chars(recovered.as_ref());
    if folded.as_str() == token {
        Cow::Borrowed(token)
    } else {
        Cow::Owned(folded)
    }
}

fn fold_lookalike_chars(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    for c in token.chars() {
        out.push(fold_char(c));
    }
    out
}

fn fold_char(c: char) -> char {
    // Needle alphabet lookalikes only (Cyrillic + Greek). Caps included;
    // downstream ASCII case-fold handles case. ponytail: bounded table,
    // full confusables if a new needle letter needs coverage.
    match c {
        '\u{0430}' | '\u{0410}' | '\u{03B1}' | '\u{0391}' => 'a',
        '\u{0441}' | '\u{0421}' => 'c',
        '\u{0435}' | '\u{0415}' | '\u{03B5}' | '\u{0395}' => 'e',
        '\u{0456}' | '\u{0406}' | '\u{03B9}' | '\u{0399}' => 'i',
        '\u{043A}' | '\u{041A}' | '\u{03BA}' | '\u{039A}' => 'k',
        '\u{043E}' | '\u{041E}' | '\u{03BF}' | '\u{039F}' => 'o',
        '\u{0440}' | '\u{0420}' | '\u{03C1}' | '\u{03A1}' => 'p',
        '\u{0455}' | '\u{0405}' => 's',
        '\u{03C4}' | '\u{03A4}' => 't',
        '\u{03C5}' | '\u{03A5}' => 'u',
        '\u{03BD}' | '\u{039D}' => 'v',
        '\u{0445}' | '\u{0425}' => 'x',
        '\u{0443}' | '\u{0423}' => 'y',
        '\u{03B7}' | '\u{0397}' => 'h',
        _ => c,
    }
}

/// Inspect a single string token and return every sensitive shape it
/// matches. The slice preserves variant declaration order for
/// determinism.
pub fn classify(token: &str) -> Vec<SensitivePath> {
    let mut out = Vec::new();
    classify_into(token, &mut out);
    out
}

/// [`classify`] variant that appends into a caller-owned buffer, so
/// per-token sweeps over large payloads skip the intermediate `Vec`.
pub fn classify_into(token: &str, out: &mut Vec<SensitivePath>) {
    let folded = fold_sensitive_homoglyphs(token);
    let token = folded.as_ref();
    let mask = needle_mask(token.as_bytes());
    if mask == 0 {
        return;
    }
    for (idx, (kind, _, pat)) in PROBES.iter().enumerate() {
        if mask & (1_u16 << idx) == 0 {
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
}

/// Byte values that can open a probe needle, in either ASCII case.
/// The `memchr` path splits them across two `memchr3` scans (its arity
/// limit is three). Every `PROBES` needle must start with one of these
/// bytes — pinned by the
/// `needle_first_bytes_are_covered_by_mask_triggers` test.
const MASK_TRIGGERS_A: (u8, u8, u8) = (b'.', b'-', b'g');
const MASK_TRIGGERS_B: (u8, u8, u8) = (b'G', b'i', b'I');

const fn is_mask_trigger(b: u8) -> bool {
    matches!(b, b'.' | b'-' | b'g' | b'G' | b'i' | b'I')
}

/// Single-pass, allocation-free replacement for the former
/// `token.to_ascii_lowercase()` + per-needle `contains` gate: bit `i`
/// is set iff `PROBES[i]`'s needle occurs in `bytes` under ASCII case
/// folding. Short tokens — the common case — take one bytewise pass;
/// long payloads use `memchr` SIMD scans to jump between candidate
/// start bytes, so a megabyte with no needle-opening byte costs two
/// vector sweeps and nothing else.
fn needle_mask(bytes: &[u8]) -> u16 {
    const ALL: u16 = (1_u16 << PROBES.len()) - 1;
    let mut mask = 0_u16;
    if bytes.len() <= 64 {
        for pos in 0..bytes.len() {
            if is_mask_trigger(bytes[pos]) {
                check_needles_at(bytes, pos, &mut mask);
                if mask == ALL {
                    break;
                }
            }
        }
        return mask;
    }
    let (a0, a1, a2) = MASK_TRIGGERS_A;
    for pos in memchr::memchr3_iter(a0, a1, a2, bytes) {
        check_needles_at(bytes, pos, &mut mask);
        if mask == ALL {
            return mask;
        }
    }
    let (b0, b1, b2) = MASK_TRIGGERS_B;
    for pos in memchr::memchr3_iter(b0, b1, b2, bytes) {
        check_needles_at(bytes, pos, &mut mask);
        if mask == ALL {
            return mask;
        }
    }
    mask
}

/// Test whether any needle starts at `bytes[pos]` and record it in
/// `mask`. Dispatches on the first byte — and, for the eight
/// dot-needles, the second byte, which is unique per needle — so each
/// candidate position costs at most one slice comparison. The
/// hard-coded `PROBES` indices are pinned by the
/// `check_needles_at_detects_each_needle_at_its_index` test.
fn check_needles_at(bytes: &[u8], pos: usize, mask: &mut u16) {
    let idx = match bytes[pos].to_ascii_lowercase() {
        b'.' => {
            let Some(&second) = bytes.get(pos + 1) else {
                return;
            };
            match second.to_ascii_lowercase() {
                b's' => 0, // .ssh
                b'a' => 1, // .aws
                b'k' => 3, // .kube
                b'd' => 4, // .docker
                b'e' => 6, // .env
                b'n' => 7, // .npmrc
                b'p' => 8, // .pypirc
                b't' => 9, // .tfstate
                _ => return,
            }
        },
        b'g' => 2,  // gcloud
        b'i' => 5,  // id_
        b'-' => 10, // -----begin
        _ => return,
    };
    let bit = 1_u16 << idx;
    if *mask & bit != 0 {
        return;
    }
    let n = PROBES[idx].1.as_bytes();
    if bytes.len() - pos >= n.len() && bytes[pos..pos + n.len()].eq_ignore_ascii_case(n) {
        *mask |= bit;
    }
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
    fn classifies_cyrillic_homoglyph_dotenv() {
        // U+0435 CYRILLIC SMALL LETTER IE — ADR 0007 / issue #163.
        assert!(kinds(".\u{0435}nv").contains(&SensitiveKind::Dotenv));
    }

    #[test]
    fn classifies_latin1_mojibake_dotenv() {
        // Bash `push_latin1` turns UTF-8 Cyrillic-e dotenv into Latin-1 mojibake.
        let real = ".\u{0435}nv";
        let mojibake: String = real.as_bytes().iter().map(|&b| b as char).collect();
        assert_eq!(mojibake, ".\u{00d0}\u{00b5}nv");
        assert!(kinds(&mojibake).contains(&SensitiveKind::Dotenv));
    }

    #[test]
    fn does_not_classify_non_ascii_non_needle() {
        // Fail-closed: table-outside non-ASCII must not become a hit.
        assert!(classify("\u{8cc7}\u{6599}.txt").is_empty());
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
    fn needle_first_bytes_are_covered_by_mask_triggers() {
        // `needle_mask` only inspects positions found by the two
        // `memchr3` trigger scans. A needle whose first byte (in either
        // ASCII case) is missing from the trigger set would silently
        // never gate its probe on.
        let (a0, a1, a2) = MASK_TRIGGERS_A;
        let (b0, b1, b2) = MASK_TRIGGERS_B;
        let triggers = [a0, a1, a2, b0, b1, b2];
        for (kind, needle, _) in PROBES {
            let first = needle.as_bytes()[0];
            for b in [first.to_ascii_lowercase(), first.to_ascii_uppercase()] {
                assert!(
                    triggers.contains(&b),
                    "trigger set misses {b:?} for {kind:?} needle {needle:?}"
                );
            }
        }
    }

    #[test]
    fn check_needles_at_detects_each_needle_at_its_index() {
        // `check_needles_at` dispatches to hard-coded `PROBES` indices;
        // reordering `PROBES` without updating the dispatch table would
        // silently drop needles. Feed each needle (both ASCII cases) at
        // position 0 and require its own bit to light up.
        for (idx, (kind, needle, _)) in PROBES.iter().enumerate() {
            for cased in [needle.to_ascii_lowercase(), needle.to_ascii_uppercase()] {
                let mut mask = 0_u16;
                check_needles_at(cased.as_bytes(), 0, &mut mask);
                assert_eq!(
                    mask,
                    1_u16 << idx,
                    "dispatch missed {kind:?} needle {cased:?} (idx {idx})"
                );
            }
        }
    }

    #[test]
    fn classify_into_appends_without_clearing() {
        let mut out = classify("~/.ssh/id_rsa");
        let before = out.len();
        assert!(before >= 2);
        classify_into(".env", &mut out);
        assert_eq!(out.len(), before + 1);
        assert_eq!(out[before].kind, SensitiveKind::Dotenv);
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

    #[test]
    fn homoglyph_single_letter_fold_matches_ascii() {
        // Replacing one ASCII needle letter with a table lookalike must
        // classify the same as the plain ASCII token (ADR 0007).
        let pairs = [
            (".env", ".\u{0435}nv"),     // Cyrillic e
            (".env", ".\u{03B5}nv"),     // Greek epsilon
            (".ssh", ".\u{0455}sh"),     // Cyrillic dze → s
            (".aws", ".\u{0430}ws"),     // Cyrillic a
            ("id_rsa", "id_r\u{0455}a"), // Cyrillic s
            (".npmrc", ".n\u{0440}mrc"), // Cyrillic p
            (".pypirc", ".\u{0440}ypirc"),
        ];
        for (ascii, glyph) in pairs {
            let a = classify(ascii);
            let g = classify(glyph);
            assert_eq!(
                a.iter().map(|m| m.kind).collect::<Vec<_>>(),
                g.iter().map(|m| m.kind).collect::<Vec<_>>(),
                "ascii={ascii:?} glyph={glyph:?}"
            );
            assert!(!a.is_empty(), "sanity: {ascii:?} must classify");
        }
    }

    #[test]
    fn fold_table_miss_does_not_invent_hit() {
        // Hiragana / CJK outside the fold table must not become a needle.
        assert!(classify(".\u{3042}nv").is_empty());
        assert!(classify("\u{8cc7}\u{6599}.txt").is_empty());
    }

    proptest! {
        // classify never panics on arbitrary printable ASCII.
        #[test]
        #[test]
        fn pbt_fold_is_idempotent(s in "\\PC{0,40}") {
            let once = fold_sensitive_homoglyphs(&s);
            let twice = fold_sensitive_homoglyphs(once.as_ref());
            prop_assert_eq!(once.as_ref(), twice.as_ref());
        }

        #[test]
        fn pbt_fold_outside_table_preserves_classify(s in "[ -~]{0,20}\\PC{0,5}[ -~]{0,20}") {
            // If fold changes nothing, classify is unchanged (tautology on
            // the folded path). Pin: tokens whose fold equals themselves
            // classify identically before/after an explicit fold call.
            let folded = fold_sensitive_homoglyphs(&s);
            if folded.as_ref() == s.as_str() {
                prop_assert_eq!(classify(&s), classify(folded.as_ref()));
            }
        }

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
