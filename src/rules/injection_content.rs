//! `core.injection.invisible-chars` — asks the user before the agent
//! ingests a file whose bytes carry characters that are invisible or
//! misleading to a human reviewer.
//!
//! Every other rule judges the *tool input* (a path string, a command
//! string). This is the first rule that opens the target file and
//! inspects its **contents**. The threat it covers: a file that looks
//! benign in a normal editor or code review can hide instructions from
//! the reviewer while still feeding them into the agent's context —
//! zero-width spaces, bidirectional (BiDi) overrides (the "Trojan
//! Source" attack), Unicode Tag characters (ASCII smuggling),
//! variation selectors (data smuggling), or raw C0/C1 control bytes.
//! When the agent reads such a file the hidden payload becomes an
//! indirect prompt injection.
//!
//! Scope: `Read` / `Edit`, path-bearing MCP tool calls, and Bash
//! "reader" heads (`cat`, `head`, …) — i.e. the surfaces that pull file
//! contents into the transcript. `Write` / `apply_patch` are out of
//! scope because that content originates from the agent itself.
//!
//! Default is `Ask`, not `Deny`: legitimate files occasionally contain
//! a soft hyphen or a stray control byte. `hard_deny` is `false` so a
//! project can suppress the rule for an audited file via
//! `overrides.allow` in `.ptuf.yaml`.
//!
//! I/O is best-effort and fails open: a missing file, a permission
//! error, a non-regular file (directory / FIFO / device), a binary
//! payload, or a non-UTF-8 blob all yield `None` rather than blocking
//! the call.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::config::scope::SystemEnv;
use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::facts::shell::{Argv, Bash};
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;
use super::sensitive_bash_read::READER_HEADS;

/// `core.injection.invisible-chars` rule — see module docs.
pub struct InvisibleChars;

const RULE_ID: &str = "core.injection.invisible-chars";

/// Hard cap on how many bytes of any single file are read before
/// scanning. A 1 MiB head keeps the PreToolUse hook fast even for
/// multi-gigabyte files; an injection payload that needs to influence
/// the model lives near the content a reviewer reads.
const MAX_SCAN_BYTES: u64 = 1024 * 1024;

/// File extensions whose contents are binary by nature. Scanning them
/// only wastes I/O — the C0/C1 detector would fire on almost every
/// byte — so they are skipped before the file is opened.
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tiff", "pdf", "zip", "gz", "tgz", "bz2",
    "xz", "zst", "7z", "rar", "tar", "mp3", "mp4", "mov", "avi", "mkv", "webm", "wav", "flac",
    "ogg", "woff", "woff2", "ttf", "otf", "eot", "class", "jar", "wasm", "o", "a", "so", "dylib",
    "dll", "exe", "bin", "pyc", "pyo", "node", "obj", "lib",
];

/// Which family of suspicious character was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    ZeroWidth,
    BidiControl,
    UnicodeTag,
    VariationSelector,
    ControlChar,
}

impl Category {
    fn label(self) -> &'static str {
        match self {
            Self::ZeroWidth => "zero-width / invisible Unicode character",
            Self::BidiControl => "bidirectional (BiDi) control character",
            Self::UnicodeTag => "Unicode Tag character (ASCII smuggling)",
            Self::VariationSelector => "Unicode variation selector (used to smuggle hidden data)",
            Self::ControlChar => "C0/C1 control character",
        }
    }
}

/// First suspicious character located in a scanned file.
#[derive(Debug, Clone, Copy)]
struct Finding {
    category: Category,
    codepoint: u32,
    line: usize,
}

impl ConfigRule for InvisibleChars {
    fn id(&self) -> &str {
        RULE_ID
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn default_decision(&self) -> DecisionKind {
        DecisionKind::Ask
    }

    fn evaluate(&self, facts: &Facts, input: &HookInput) -> Option<Decision> {
        let finding = scan_candidates(facts, input)
            .iter()
            .find_map(|path| scan_file(path))?;
        Some(Decision::Ask {
            rule_id: RULE_ID.into(),
            reason: build_reason(&finding),
        })
    }
}

/// Files this hook call is about to pull into the agent's context.
fn scan_candidates(facts: &Facts, input: &HookInput) -> Vec<PathBuf> {
    if input.tool_name == "Bash" {
        return bash_reader_targets(facts.bash.as_ref());
    }
    if matches!(input.tool_name.as_str(), "Read" | "Edit") || input.is_mcp_tool() {
        return facts
            .paths
            .iter()
            .map(|p| p.canonical_or_raw.clone())
            .collect();
    }
    Vec::new()
}

/// Positional file arguments of every reader-head command in a parsed
/// Bash line. `Bash::commands()` already flattens wrapper payloads
/// (`bash -c`, `xargs`, `find -exec`), so no extra recursion is needed.
fn bash_reader_targets(bash: Option<&Bash>) -> Vec<PathBuf> {
    let Some(bash) = bash else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for argv in bash.commands() {
        collect_reader_args(argv, &mut out);
    }
    out
}

/// Reader heads from `READER_HEADS` that this rule must *not* treat as
/// content readers. `xxd` / `od` / `hexdump` render bytes as a hex
/// dump, so a hidden character shows up plainly in their output instead
/// of slipping into the agent's context unseen — the threat model does
/// not apply. `xxd` is also exactly what `build_reason` recommends as
/// the remediation, so flagging it would be self-defeating.
const HEX_DUMP_HEADS: &[&str] = &["xxd", "od", "hexdump"];

/// True when a Bash command head pulls file *contents* into the
/// transcript verbatim. Reuses the `sensitive-bash-read` allowlist but
/// drops the hex-dump heads (see `HEX_DUMP_HEADS`).
fn is_content_reader(head: &str) -> bool {
    READER_HEADS.contains(&head) && !HEX_DUMP_HEADS.contains(&head)
}

fn collect_reader_args(argv: &Argv, out: &mut Vec<PathBuf>) {
    if is_content_reader(&argv.head) {
        out.extend(argv.positional().map(resolve_candidate));
        return;
    }
    if let Some(inner) = crate::facts::shell::unwrap_privilege_wrapper(argv)
        && is_content_reader(&inner.head)
    {
        out.extend(inner.positional().map(resolve_candidate));
    }
}

/// Expand `~` / `$HOME` in a raw Bash token to a filesystem path. ptuf
/// runs in the agent's cwd, so a relative result resolves correctly.
fn resolve_candidate(raw: &str) -> PathBuf {
    crate::facts::path::resolve_with_env(raw, None, &SystemEnv)
}

/// Open a file and return the first suspicious character, or `None`
/// when the file is absent / binary / non-regular / unreadable.
fn scan_file(path: &Path) -> Option<Finding> {
    if has_binary_extension(path) {
        return None;
    }
    // `is_file()` rejects directories, FIFOs, and devices: opening a
    // FIFO and calling `read_to_end` would otherwise block forever.
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_SCAN_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    scan_bytes(&buf)
}

fn has_binary_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|ext| BINARY_EXTENSIONS.contains(&ext.as_str()))
}

/// Scan a byte buffer. A NUL byte marks the payload as binary; an
/// invalid-UTF-8 tail (e.g. a multibyte char split by the 1 MiB cap)
/// is dropped so only the valid prefix is inspected.
fn scan_bytes(buf: &[u8]) -> Option<Finding> {
    if buf.contains(&0) {
        return None;
    }
    let text = match std::str::from_utf8(buf) {
        Ok(text) => text,
        Err(err) => std::str::from_utf8(&buf[..err.valid_up_to()]).ok()?,
    };
    let mut line = 1usize;
    for (idx, ch) in text.char_indices() {
        if ch == '\n' {
            line += 1;
            continue;
        }
        if let Some(category) = classify(ch, idx == 0) {
            return Some(Finding {
                category,
                codepoint: u32::from(ch),
                line,
            });
        }
    }
    None
}

/// Classify a single character. `is_first_char` exempts a leading
/// U+FEFF, which is a legitimate byte-order mark at file start.
fn classify(ch: char, is_first_char: bool) -> Option<Category> {
    if ch == '\u{FEFF}' && is_first_char {
        return None;
    }
    match ch {
        // Zero-width / invisible format characters, including the
        // invisible math operators U+2061-2064 (U+2060 is WORD JOINER)
        // and U+034F COMBINING GRAPHEME JOINER.
        '\u{200B}'
        | '\u{200C}'
        | '\u{200D}'
        | '\u{2060}'..='\u{2064}'
        | '\u{FEFF}'
        | '\u{00AD}'
        | '\u{034F}'
        | '\u{180E}'
        | '\u{115F}'
        | '\u{1160}'
        | '\u{3164}'
        | '\u{FFA0}' => Some(Category::ZeroWidth),
        // Strong BiDi overrides and isolates plus the directional marks
        // LRM / RLM / ALM (Trojan Source).
        '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        | '\u{200E}'
        | '\u{200F}'
        | '\u{061C}' => Some(Category::BidiControl),
        // Unicode Tag block.
        '\u{E0000}'..='\u{E007F}' => Some(Category::UnicodeTag),
        // Variation Selectors Supplement — a data-smuggling vector. The
        // standard selectors U+FE00-FE0F are deliberately not flagged:
        // they are ubiquitous in legitimate emoji variation sequences.
        '\u{E0100}'..='\u{E01EF}' => Some(Category::VariationSelector),
        // C0 controls (TAB / LF / CR allowed; NUL handled as binary) and C1 controls.
        '\u{0001}'..='\u{0008}'
        | '\u{000B}'
        | '\u{000C}'
        | '\u{000E}'..='\u{001F}'
        | '\u{007F}'..='\u{009F}' => Some(Category::ControlChar),
        _ => None,
    }
}

fn build_reason(finding: &Finding) -> String {
    let problem = format!(
        "The file ptuf is about to read contains a {} (U+{:04X}) on line {}. A character \
         like this is invisible or misleading to a human reviewer but still enters the \
         agent's context, so a file that looks benign in review can carry hidden \
         instructions (an indirect prompt-injection / Trojan Source attack).",
        finding.category.label(),
        finding.codepoint,
        finding.line,
    );
    reason::build(
        RULE_ID,
        &problem,
        &[
            "Ask the user to inspect the file with a hex viewer (e.g. `xxd`) before proceeding.",
            "Operate on a cleaned copy with the hidden characters stripped.",
            "If the characters are legitimate for this file, suppress this rule for it via \
             `overrides.allow` in `.ptuf.yaml`.",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn evaluate_for(input: &HookInput) -> Option<Decision> {
        let facts = crate::facts::extract(input);
        InvisibleChars.evaluate(&facts, input)
    }

    fn read_input(path: &Path) -> HookInput {
        HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({ "file_path": path.to_string_lossy() }),
        }
    }

    fn write_file(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).expect("write temp file");
        path
    }

    fn assert_ask(input: &HookInput) {
        let result = evaluate_for(input);
        assert!(
            matches!(&result, Some(Decision::Ask { rule_id, .. }) if rule_id == RULE_ID),
            "expected Ask, got {result:?}",
        );
    }

    fn assert_silent(input: &HookInput) {
        let result = evaluate_for(input);
        assert!(result.is_none(), "expected None, got {result:?}");
    }

    #[test]
    fn asks_for_unicode_category_representatives() {
        let dir = TempDir::new().expect("tempdir");
        let cases: &[(&str, &[u8])] = &[
            ("zwsp.txt", "hello\u{200B}world\n".as_bytes()),
            ("bidi.txt", "let admin = \u{202E}true;\n".as_bytes()),
            ("tag.txt", "ok\u{E0041}\n".as_bytes()),
            ("c0.txt", b"alpha\x07beta\n"),
            ("lrm.txt", "head\u{200E}tail\n".as_bytes()),
            ("rlm.txt", "head\u{200F}tail\n".as_bytes()),
            ("alm.txt", "head\u{061C}tail\n".as_bytes()),
            ("func.txt", "a\u{2061}b\n".as_bytes()),
            ("times.txt", "a\u{2062}b\n".as_bytes()),
            ("plus.txt", "a\u{2064}b\n".as_bytes()),
            ("cgj.txt", "a\u{034F}b\n".as_bytes()),
            ("vs-lo.txt", "x\u{E0100}y\n".as_bytes()),
            ("vs-hi.txt", "x\u{E01EF}y\n".as_bytes()),
        ];
        for (name, bytes) in cases {
            let path = write_file(&dir, name, bytes);
            assert_ask(&read_input(&path));
        }
    }

    #[test]
    fn allows_clean_file() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "clean.txt", b"plain text\twith tab\nand newline\n");
        assert_silent(&read_input(&path));
    }

    #[test]
    fn allows_leading_bom() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "bom.txt", "\u{FEFF}clean content\n".as_bytes());
        assert_silent(&read_input(&path));
    }

    #[test]
    fn asks_for_bom_not_at_start() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "mid.txt", "head\u{FEFF}tail\n".as_bytes());
        assert_ask(&read_input(&path));
    }

    #[test]
    fn silent_for_missing_file() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("does-not-exist.txt");
        assert_silent(&read_input(&path));
    }

    #[test]
    fn silent_for_directory() {
        let dir = TempDir::new().expect("tempdir");
        assert_silent(&read_input(dir.path()));
    }

    #[test]
    fn silent_for_binary_with_nul() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "blob.dat", b"head\x00\xe2\x80\x8btail");
        assert_silent(&read_input(&path));
    }

    #[test]
    fn silent_for_invalid_utf8() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "raw.dat", &[0xFF, 0xFE, 0xFD]);
        assert_silent(&read_input(&path));
    }

    #[test]
    fn asks_for_invisible_before_invalid_utf8() {
        // Valid-UTF-8 prefix carries a ZWSP; the trailing invalid byte
        // is dropped but the finding in the prefix still surfaces.
        let dir = TempDir::new().expect("tempdir");
        let mut bytes = "x\u{200B}y".as_bytes().to_vec();
        bytes.push(0xFF);
        let path = write_file(&dir, "mixed.dat", &bytes);
        assert_ask(&read_input(&path));
    }

    #[test]
    fn silent_for_binary_extension() {
        let dir = TempDir::new().expect("tempdir");
        // ZWSP inside, but a `.png` is skipped before opening.
        let path = write_file(&dir, "image.png", "x\u{200B}y".as_bytes());
        assert_silent(&read_input(&path));
    }

    #[test]
    fn asks_for_edit_tool() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "edit.txt", "data\u{200D}more\n".as_bytes());
        let input = HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({ "file_path": path.to_string_lossy() }),
        };
        assert_ask(&input);
    }

    #[test]
    fn asks_for_mcp_tool() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "mcp.txt", "value\u{2066}end\n".as_bytes());
        let input = HookInput {
            tool_name: "mcp__filesystem__read_file".into(),
            tool_input: serde_json::json!({ "path": path.to_string_lossy() }),
        };
        assert_ask(&input);
    }

    #[test]
    fn silent_for_write_tool() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "out.txt", "hidden\u{200B}payload\n".as_bytes());
        let input = HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({ "file_path": path.to_string_lossy() }),
        };
        assert_silent(&input);
    }

    #[test]
    fn silent_for_non_path_tool() {
        let input = HookInput {
            tool_name: "Glob".into(),
            tool_input: serde_json::json!({ "pattern": "**/*.rs" }),
        };
        assert_silent(&input);
    }

    fn bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": cmd }),
        }
    }

    #[test]
    fn asks_for_bash_cat() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "feed.txt", "before\u{200B}after\n".as_bytes());
        assert_ask(&bash(&format!("cat {}", path.display())));
    }

    #[test]
    fn silent_for_bash_clean_cat() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "ok.txt", b"nothing hidden here\n");
        assert_silent(&bash(&format!("cat {}", path.display())));
    }

    #[test]
    fn silent_for_bash_non_reader_head() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "rm.txt", "hidden\u{200B}\n".as_bytes());
        assert_silent(&bash(&format!("rm {}", path.display())));
    }

    #[test]
    fn asks_for_bash_wrapper() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "wrap.txt", "wrapped\u{202E}payload\n".as_bytes());
        assert_ask(&bash(&format!("bash -c 'cat {}'", path.display())));
    }

    #[test]
    fn asks_for_bash_sudo_cat() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "sudo.txt", "x\u{2060}y\n".as_bytes());
        assert_ask(&bash(&format!("sudo cat {}", path.display())));
    }

    #[test]
    fn silent_for_bash_without_command() {
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({}),
        };
        assert_silent(&input);
    }

    #[test]
    fn scans_only_head_of_huge_file() {
        let dir = TempDir::new().expect("tempdir");
        // 1.5 MiB of clean ASCII, then a ZWSP past the 1 MiB cap.
        let mut bytes = vec![b'a'; 1024 * 1024 + 512 * 1024];
        bytes.extend_from_slice("\u{200B}".as_bytes());
        let path = write_file(&dir, "huge.txt", &bytes);
        assert_silent(&read_input(&path));
    }

    #[test]
    fn asks_for_invisible_within_scan_cap() {
        let dir = TempDir::new().expect("tempdir");
        let mut bytes = "\u{200B}".as_bytes().to_vec();
        bytes.extend(std::iter::repeat_n(b'a', 2 * 1024 * 1024));
        let path = write_file(&dir, "huge2.txt", &bytes);
        assert_ask(&read_input(&path));
    }

    #[test]
    fn reason_names_category_and_line() {
        let rule: &dyn ConfigRule = &InvisibleChars;
        assert_eq!(rule.severity(), Severity::High);
        assert_eq!(rule.default_decision(), DecisionKind::Ask);
        let finding = Finding {
            category: Category::BidiControl,
            codepoint: 0x202E,
            line: 7,
        };
        let text = build_reason(&finding);
        assert!(text.contains("core.injection.invisible-chars"));
        assert!(text.contains("U+202E"));
        assert!(text.contains("line 7"));
        assert!(text.contains("BiDi"));
    }

    #[test]
    fn is_content_reader_excludes_hex_dumps() {
        assert!(is_content_reader("cat"));
        assert!(is_content_reader("grep"));
        assert!(!is_content_reader("xxd"));
        assert!(!is_content_reader("od"));
        assert!(!is_content_reader("hexdump"));
        // A head that is not a reader at all stays false.
        assert!(!is_content_reader("rm"));
    }

    #[test]
    fn silent_for_bash_hex_dump_heads() {
        let dir = TempDir::new().expect("tempdir");
        for head in ["xxd", "od", "hexdump"] {
            let path = write_file(&dir, &format!("{head}.txt"), "x\u{200B}y\n".as_bytes());
            assert_silent(&bash(&format!("{head} {}", path.display())));
        }
    }

    #[test]
    fn silent_for_bash_sudo_xxd() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "sudo-xxd.txt", "a\u{200B}b\n".as_bytes());
        assert_silent(&bash(&format!("sudo xxd {}", path.display())));
    }

    #[test]
    fn asks_for_bash_head_still_fires() {
        // `head` is a reader head but not a hex dumper, so the exclusion
        // must not over-reach.
        let dir = TempDir::new().expect("tempdir");
        let path = write_file(&dir, "head.txt", "x\u{200B}y\n".as_bytes());
        assert_ask(&bash(&format!("head {}", path.display())));
    }

    #[test]
    fn asks_for_directional_marks() {
        let dir = TempDir::new().expect("tempdir");
        for (name, ch) in [
            ("lrm.txt", '\u{200E}'),
            ("rlm.txt", '\u{200F}'),
            ("alm.txt", '\u{061C}'),
        ] {
            let path = write_file(&dir, name, format!("head{ch}tail\n").as_bytes());
            assert_ask(&read_input(&path));
        }
    }

    #[test]
    fn asks_for_invisible_math_operators() {
        let dir = TempDir::new().expect("tempdir");
        for (name, ch) in [
            ("func.txt", '\u{2061}'),
            ("times.txt", '\u{2062}'),
            ("plus.txt", '\u{2064}'),
        ] {
            let path = write_file(&dir, name, format!("a{ch}b\n").as_bytes());
            assert_ask(&read_input(&path));
        }
    }

    #[test]
    fn asks_for_variation_selector_supplement() {
        let dir = TempDir::new().expect("tempdir");
        for (name, ch) in [("vs-lo.txt", '\u{E0100}'), ("vs-hi.txt", '\u{E01EF}')] {
            let path = write_file(&dir, name, format!("x{ch}y\n").as_bytes());
            assert_ask(&read_input(&path));
        }
    }

    #[test]
    fn asks_for_new_categories_via_bash_and_mcp() {
        // A new category must fire on every ingestion surface, not just
        // the `Read` path.
        let dir = TempDir::new().expect("tempdir");
        let bash_path = write_file(&dir, "bash-new.txt", "x\u{200E}y\n".as_bytes());
        assert_ask(&bash(&format!("cat {}", bash_path.display())));

        let mcp_path = write_file(&dir, "mcp-new.txt", "x\u{E0100}y\n".as_bytes());
        assert_ask(&HookInput {
            tool_name: "mcp__filesystem__read_file".into(),
            tool_input: serde_json::json!({ "path": mcp_path.to_string_lossy() }),
        });
    }

    #[test]
    fn allows_standard_variation_selectors() {
        // U+FE00-FE0F are ubiquitous in emoji variation sequences and
        // are deliberately left undetected.
        let dir = TempDir::new().expect("tempdir");
        for (name, ch) in [("vs00.txt", '\u{FE00}'), ("vs0f.txt", '\u{FE0F}')] {
            let path = write_file(&dir, name, format!("emoji\u{2764}{ch}\n").as_bytes());
            assert_silent(&read_input(&path));
        }
    }

    #[test]
    fn allows_codepoints_adjacent_to_new_ranges() {
        // U+2065 is right after the invisible math operators; U+E0090
        // sits in the gap between the Tag block and the VS Supplement;
        // U+E01F0 is right after the VS Supplement. None must fire.
        let dir = TempDir::new().expect("tempdir");
        for (name, ch) in [
            ("past-math.txt", '\u{2065}'),
            ("tag-gap.txt", '\u{E0090}'),
            ("past-vs.txt", '\u{E01F0}'),
        ] {
            let path = write_file(&dir, name, format!("x{ch}y\n").as_bytes());
            assert_silent(&read_input(&path));
        }
    }

    #[test]
    fn reason_names_variation_selector_category() {
        let finding = Finding {
            category: Category::VariationSelector,
            codepoint: 0xE0100,
            line: 3,
        };
        let text = build_reason(&finding);
        assert!(text.contains("core.injection.invisible-chars"));
        assert!(text.contains("U+E0100"));
        assert!(text.contains("line 3"));
        assert!(text.contains("variation selector"));
    }

    use crate::testing::proptest::richer_hook_input;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pbt_evaluate_never_panics(input in richer_hook_input()) {
            let facts = crate::facts::extract(&input);
            let _ = InvisibleChars.evaluate(&facts, &input);
        }

        #[test]
        fn pbt_only_emits_ask_with_correct_id(input in richer_hook_input()) {
            let facts = crate::facts::extract(&input);
            if let Some(decision) = InvisibleChars.evaluate(&facts, &input) {
                match decision {
                    Decision::Ask { rule_id, .. } => prop_assert_eq!(rule_id, RULE_ID),
                    other => prop_assert!(false, "expected Ask, got {other:?}"),
                }
            }
        }

        // Printable ASCII plus TAB / LF / CR never trips the scanner.
        #[test]
        fn pbt_clean_ascii_never_flagged(text in "[ -~\n\t\r]{0,256}") {
            prop_assert!(scan_bytes(text.as_bytes()).is_none());
        }

        // The scanner never panics for arbitrary byte buffers.
        #[test]
        fn pbt_scan_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = scan_bytes(&bytes);
        }

        // A hex-dump head yields no scan candidates regardless of its
        // arguments, so the rule can never fire on `xxd` / `od` /
        // `hexdump`.
        #[test]
        fn pbt_hex_dump_heads_yield_no_candidates(
            idx in 0usize..HEX_DUMP_HEADS.len(),
            args in proptest::collection::vec("[a-zA-Z0-9_./-]{1,12}", 0..4),
        ) {
            let cmd = format!("{} {}", HEX_DUMP_HEADS[idx], args.join(" "));
            let input = bash(&cmd);
            let facts = crate::facts::extract(&input);
            prop_assert!(scan_candidates(&facts, &input).is_empty());
        }

        // Printable ASCII plus the standard variation selectors
        // U+FE00-FE0F never trips the scanner — emoji variation
        // sequences must not be flagged.
        #[test]
        fn pbt_standard_variation_selectors_never_flagged(
            text in "[ -~\u{FE00}-\u{FE0F}]{0,256}",
        ) {
            prop_assert!(scan_bytes(text.as_bytes()).is_none());
        }
    }
}
