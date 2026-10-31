//! Metamorphic bounded-exhaustive check: bash quote removal.
//!
//! In bash, quoting a word that contains no expansion characters does not
//! change the word the command sees (`rm`, `'rm'`, `r''m`, `r\m`, `$'rm'`
//! all run `rm`). So for every `must_catch` Bash case in the bypass corpus,
//! every single quote-removal-equivalent rewrite of one of its plain words
//! must be caught at least as strictly as the original.
//!
//! "Plain" words are made only of `[A-Za-z0-9_./,:@%+-]` and are not
//! reserved words, so quoting cannot change tilde/glob/brace expansion,
//! assignment or keyword recognition. For each such word every rewrite
//! below is tried at every position (the bound): whole-word `'..'`,
//! `".."`, `$'..'`; an empty `''` / `""` inserted at each inner position;
//! a backslash before each character; a split into `'a'"b"` at each inner
//! position.

use ptuf::decision::DecisionKind;
use ptuf::{Engine, HookInput};

const RESERVED: &[&str] = &[
    "if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do",
    "done", "in", "function", "time", "{", "}", "!", "[[", "]]", "coproc",
];

fn is_plain(word: &str) -> bool {
    !word.is_empty()
        && !RESERVED.contains(&word)
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./,:@%+-".contains(&b))
}

/// True when byte offset `at` of `cmd` is outside any quoting, i.e. a word
/// starting there is a top-level shell word. Rewriting a word that sits
/// inside quotes (an `su -c '...'` payload) would change its meaning.
fn at_top_level(cmd: &str, at: usize) -> bool {
    let (mut single, mut double, mut escaped) = (false, false, false);
    for b in cmd[..at].bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if !single => escaped = true,
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            _ => {},
        }
    }
    !single && !double && !escaped
}

fn rewrites(word: &str) -> Vec<String> {
    let mut out = vec![
        format!("'{word}'"),
        format!("\"{word}\""),
        format!("$'{word}'"),
    ];
    for i in 1..word.len() {
        let (a, b) = word.split_at(i);
        out.push(format!("{a}''{b}"));
        out.push(format!("{a}\"\"{b}"));
        out.push(format!("'{a}'\"{b}\""));
    }
    for i in 0..word.len() {
        let (a, b) = word.split_at(i);
        out.push(format!("{a}\\{b}"));
    }
    out
}

fn rank(kind: DecisionKind) -> u8 {
    match kind {
        DecisionKind::Allow => 0,
        DecisionKind::Monitor => 1,
        DecisionKind::Ask => 2,
        DecisionKind::Deny => 3,
    }
}

fn bash(cmd: &str) -> HookInput {
    serde_json::from_value(serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": cmd },
    }))
    .expect("hook input")
}

#[test]
fn quote_removal_equivalent_rewrites_stay_caught() {
    let engine = Engine::builder()
        .agent("quote-equivalence")
        .build()
        .expect("default-config engine builds");
    let mut checked = 0_usize;
    let mut misses: Vec<String> = Vec::new();
    for line in include_str!("bypass/corpus.jsonl").lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let case: serde_json::Value = serde_json::from_str(line).expect("corpus json");
        if case["expect"]["kind"] != "must_catch" || case["hook_input"]["tool_name"] != "Bash" {
            continue;
        }
        let Some(cmd) = case["hook_input"]["tool_input"]["command"].as_str() else {
            continue;
        };
        let base = rank(engine.decide(&bash(cmd)).decision.kind());
        // Heredoc bodies and multi-line scripts are not word lists.
        if cmd.contains('\n') || cmd.contains("<<") {
            continue;
        }
        // Words separated by single spaces can be swapped out without
        // re-tokenising; only top-level ones are rewritten.
        let words: Vec<&str> = cmd.split(' ').collect();
        let mut offset = 0;
        for (idx, word) in words.iter().enumerate() {
            let start = offset;
            offset += word.len() + 1;
            if !is_plain(word) || !at_top_level(cmd, start) {
                continue;
            }
            for rewrite in rewrites(word) {
                let mut variant = words.clone();
                variant[idx] = &rewrite;
                let variant = variant.join(" ");
                checked += 1;
                let got = engine.decide(&bash(&variant)).decision.kind();
                if rank(got) < base {
                    misses.push(format!(
                        "{id}: {variant:?} -> {got:?} (original {cmd:?})",
                        id = case["id"].as_str().unwrap_or("?"),
                    ));
                }
            }
        }
        // Blank separators bash treats like a single space: a tab, a run of
        // spaces, a backslash-newline continuation, and `${IFS}` (unquoted,
        // default IFS) — each swapped in for every top-level space.
        let mut at = 0;
        while let Some(rel) = cmd[at..].find(' ') {
            let pos = at + rel;
            at = pos + 1;
            if !at_top_level(cmd, pos) {
                continue;
            }
            // `${IFS}~` would suppress tilde expansion; not equivalent.
            let tilde_next = cmd[pos + 1..].starts_with('~');
            for sep in ["\t", "   ", " \\\n ", "${IFS}"] {
                if sep == "${IFS}" && tilde_next {
                    continue;
                }
                let variant = format!("{}{sep}{}", &cmd[..pos], &cmd[pos + 1..]);
                checked += 1;
                let got = engine.decide(&bash(&variant)).decision.kind();
                if rank(got) < base {
                    misses.push(format!(
                        "{id}: {variant:?} -> {got:?} (original {cmd:?})",
                        id = case["id"].as_str().unwrap_or("?"),
                    ));
                }
            }
        }
    }
    eprintln!("checked {checked} variants");
    assert!(checked > 1000, "only {checked} variants generated");
    assert!(
        misses.is_empty(),
        "{} of {checked} quote-equivalent variants weakened the decision:\n{}",
        misses.len(),
        misses.join("\n"),
    );
}
