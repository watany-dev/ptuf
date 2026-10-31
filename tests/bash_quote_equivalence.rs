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

/// Builtins with no external counterpart: an exec wrapper (`sudo`,
/// `nohup`) cannot run them.
const SHELL_ONLY_BUILTINS: &[&str] = &[
    "cd",
    "source",
    ".",
    "eval",
    "exec",
    "builtin",
    "export",
    "alias",
    "unset",
    "set",
    "trap",
    "declare",
    "typeset",
    "local",
    "readonly",
    "enable",
    "hash",
    "pushd",
    "popd",
    "ulimit",
    "umask",
    "shopt",
    "mapfile",
    "readarray",
    "let",
    "return",
    "exit",
    "shift",
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
    HookInput {
        tool_name: "Bash".into(),
        tool_input: serde_json::json!({ "command": cmd }),
    }
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
        // Whole-command contexts that run the command unchanged: a
        // subshell, a brace group, a preceding no-op, and transparent
        // exec wrappers in front of the first simple command.
        let mut contexts = vec![
            format!("({cmd})"),
            format!("{{ {cmd}; }}"),
            format!("true; {cmd}"),
            format!(": && {cmd}"),
            format!("false || {cmd}"),
        ];
        // Re-parsed payload carriers. Only one level is added and only
        // around commands without single quotes, so the original's own
        // nesting stays within `NESTING_BUDGET`.
        if !cmd.contains('\'') {
            for carrier in [
                "bash -c",
                "sh -c",
                "eval",
                "su -c",
                "bash -lc",
                "sudo sh -c",
            ] {
                contexts.push(format!("{carrier} '{cmd}'"));
            }
        }
        let first = cmd.split([' ', '\t']).next().unwrap_or_default();
        // A wrapper only applies to a simple command: not to a reserved
        // word (`sudo coproc` runs a program named `coproc`), a group or an
        // assignment. Shell-only builtins (`cd`, `source`, `eval`) cannot
        // be exec'd, so only the shell's own `command` / `builtin` forms
        // reach them.
        if !cmd.starts_with(['(', '{']) && !first.contains('=') && !RESERVED.contains(&first) {
            let shell_only = SHELL_ONLY_BUILTINS.contains(&first);
            for wrapper in [
                "command",
                "builtin command",
                "command -p",
                "\\command",
                "exec",
                "nohup",
                "nice",
                "nice -n 5",
                "env",
                "env -i",
                "time",
                "timeout 9",
                "timeout -s KILL 9",
                "stdbuf -o0",
                "setsid",
                "ionice -c3",
                "sudo",
                "sudo -E",
                "doas",
                "chrt -o 0",
                "taskset 1",
                "flock /tmp/l",
                "chroot /",
                "busybox",
                "X=1",
                "LC_ALL=C X=1",
                "/usr/bin/time -o /dev/null",
            ] {
                if shell_only && !wrapper.contains("command") && !wrapper.contains('=') {
                    continue;
                }
                contexts.push(format!("{wrapper} {cmd}"));
            }
        }
        for variant in contexts {
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
    eprintln!("checked {checked} variants");
    assert!(checked > 1000, "only {checked} variants generated");
    assert!(
        misses.is_empty(),
        "{} of {checked} quote-equivalent variants weakened the decision:\n{}",
        misses.len(),
        misses.join("\n"),
    );
}

/// A top-level word that names a filesystem path the kernel resolves
/// (absolute, `~/`, `./` or `../`), with nothing bash would expand or
/// treat specially. `/dev/tcp/…` and friends are matched by bash as
/// literal strings in redirects, so their spelling matters and they are
/// left alone.
fn is_path_word(word: &str) -> bool {
    (word.starts_with('/')
        || word.starts_with("~/")
        || word.starts_with("./")
        || word.starts_with("../"))
        && !word.starts_with("/dev/")
        && !word.contains("://")
        && word
            .bytes()
            .skip(usize::from(word.starts_with('~')))
            .all(|b| b.is_ascii_alphanumeric() || b"_./,:@%+-".contains(&b))
}

/// Path spellings the kernel resolves to the same file: a doubled `/`
/// and an inserted `/./` at each separator, and for a bare dotfile
/// argument of a file-taking command the `./` prefix.
fn path_rewrites(word: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in word.match_indices('/') {
        let (a, b) = word.split_at(i);
        out.push(format!("{a}/{b}"));
        out.push(format!("{a}/.{b}"));
    }
    out
}

/// Commands whose operands are all file paths, so `.env` and `./.env`
/// name the same file.
const FILE_OPERAND_HEADS: &[&str] = &[
    "cat", "less", "more", "head", "tail", "rm", "cp", "mv", "chmod", "tee", "source", ".",
    "truncate", "shred", "nl", "tac", "base64", "xxd", "od", "strings",
];

#[test]
fn path_spelling_equivalent_rewrites_stay_caught() {
    let engine = Engine::builder()
        .agent("path-equivalence")
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
        if cmd.contains('\n') || cmd.contains("<<") {
            continue;
        }
        let base = rank(engine.decide(&bash(cmd)).decision.kind());
        let words: Vec<&str> = cmd.split(' ').collect();
        let file_operands = words
            .first()
            .is_some_and(|h| FILE_OPERAND_HEADS.contains(h));
        let mut offset = 0;
        for (idx, word) in words.iter().enumerate() {
            let start = offset;
            offset += word.len() + 1;
            if idx == 0 || !at_top_level(cmd, start) {
                continue;
            }
            let mut variants = if is_path_word(word) {
                path_rewrites(word)
            } else {
                Vec::new()
            };
            if file_operands && word.starts_with('.') && !word.starts_with("./") && is_plain(word) {
                variants.push(format!("./{word}"));
                variants.extend(path_rewrites(&format!("./{word}")));
            }
            for rewrite in variants {
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
    }
    eprintln!("checked {checked} path variants");
    assert!(checked > 100, "only {checked} path variants generated");
    assert!(
        misses.is_empty(),
        "{} of {checked} path-equivalent variants weakened the decision:\n{}",
        misses.len(),
        misses.join("\n")
    );
}

/// git global options that change neither the repository nor the
/// subcommand, inserted between `git` and its subcommand.
const GIT_NEUTRAL_GLOBALS: &[&str] = &[
    "-C .",
    "-C.",
    "--no-pager",
    "-P",
    "--paginate",
    "-p",
    "-c color.ui=never",
    "-ccolor.ui=never",
    "--config-env=color.ui=HOME",
    "--literal-pathspecs",
    "--no-replace-objects",
    "--no-optional-locks",
    "--no-advice",
    "--git-dir=.git",
    "--git-dir .git",
    "--work-tree=.",
    "--work-tree .",
    "--namespace=x",
    "--exec-path=/usr/lib/git-core",
];

#[test]
fn git_global_option_insertions_stay_caught() {
    let engine = Engine::builder()
        .agent("git-equivalence")
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
        if cmd.contains('\n') || cmd.contains("<<") {
            continue;
        }
        let base = rank(engine.decide(&bash(cmd)).decision.kind());
        let mut offset = 0;
        for word in cmd.split(' ') {
            let start = offset;
            offset += word.len() + 1;
            if word != "git" || !at_top_level(cmd, start) {
                continue;
            }
            // Only a command-position `git` (start, or after an operator).
            let before = cmd[..start].trim_end();
            if !(before.is_empty() || before.ends_with(['&', '|', ';', '('])) {
                continue;
            }
            let after = start + word.len();
            for opt in GIT_NEUTRAL_GLOBALS {
                let variant = format!("{} {opt}{}", &cmd[..after], &cmd[after..]);
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
    eprintln!("checked {checked} git variants");
    assert!(checked > 100, "only {checked} git variants generated");
    assert!(
        misses.is_empty(),
        "{} of {checked} git-option variants weakened the decision:\n{}",
        misses.len(),
        misses.join("\n")
    );
}

/// Equivalent spellings of a redirect operator: the explicit default fd,
/// and `>|` for `>` (identical unless `noclobber` is set).
fn redirect_op_spellings(op: &str) -> &'static [&'static str] {
    match op {
        ">" => &["1>", ">|", "1>|"],
        ">>" => &["1>>"],
        "<" => &["0<"],
        "2>" => &["2>|"],
        "&>" => &[">&"],
        _ => &[],
    }
}

/// Redirects may appear anywhere in a simple command (`>f cmd a`,
/// `cmd >f a`, `cmd a >f` are the same), the target may be attached to
/// the operator, and the operator has equivalent spellings.
#[test]
fn redirect_placement_and_spelling_rewrites_stay_caught() {
    let engine = Engine::builder()
        .agent("redirect-equivalence")
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
        if cmd.contains('\n') || cmd.contains("<<") {
            continue;
        }
        let base = rank(engine.decide(&bash(cmd)).decision.kind());
        let words: Vec<&str> = cmd.split(' ').collect();
        let mut starts = Vec::with_capacity(words.len());
        let mut offset = 0;
        for w in &words {
            starts.push(offset);
            offset += w.len() + 1;
        }
        let mut variants = Vec::new();
        for idx in 0..words.len().saturating_sub(1) {
            let op = words[idx];
            let target = words[idx + 1];
            if redirect_op_spellings(op).is_empty()
                || !at_top_level(cmd, starts[idx])
                || target.is_empty()
                || target.starts_with(['&', '(', '<', '>'])
            {
                continue;
            }
            let rebuild = |replacement: &[String], at: usize, drop: usize| {
                let mut out: Vec<String> = words.iter().map(|w| (*w).to_string()).collect();
                out.splice(idx..idx + drop, std::iter::empty());
                for (k, r) in replacement.iter().enumerate() {
                    out.insert(at + k, r.clone());
                }
                out.join(" ")
            };
            // Attached target and alternative operator spellings, in place.
            variants.push(rebuild(&[format!("{op}{target}")], idx, 2));
            for alt in redirect_op_spellings(op) {
                variants.push(rebuild(&[(*alt).to_string(), target.to_string()], idx, 2));
                variants.push(rebuild(&[format!("{alt}{target}")], idx, 2));
            }
            // Move `op target` to the start of its simple command and to
            // right after its head.
            let start = (0..idx)
                .rev()
                .find(|&k| matches!(words[k], "&&" | "||" | ";" | "|"))
                .map_or(0, |k| k + 1);
            let head = words.get(start).copied().unwrap_or_default();
            if start < idx
                && !head.contains('=')
                && !RESERVED.contains(&head)
                && !head.starts_with(['(', '{'])
            {
                let pair = [op.to_string(), target.to_string()];
                variants.push(rebuild(&pair, start, 2));
                if start + 1 < idx {
                    variants.push(rebuild(&pair, start + 1, 2));
                }
            }
        }
        for variant in variants {
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
    eprintln!("checked {checked} redirect variants");
    assert!(checked > 50, "only {checked} redirect variants generated");
    assert!(
        misses.is_empty(),
        "{} of {checked} redirect variants weakened the decision:\n{}",
        misses.len(),
        misses.join("\n")
    );
}

/// GNU coreutils whose short options are all boolean (for the options the
/// corpus uses), so a cluster may be split or reordered and options may
/// follow operands (GNU `getopt` permutes argv).
const BOOLEAN_FLAG_HEADS: &[&str] = &["rm", "cp", "mv", "ln", "cat", "mkdir", "touch", "shred"];

/// Head and option spellings that run the same program: the head by
/// absolute path (`/usr/bin/rm`), a short-option cluster split or
/// reversed (`-rf` → `-r -f`, `-fr`), and options moved after the
/// operands (`rm / -rf`).
#[test]
fn head_path_and_option_order_rewrites_stay_caught() {
    let engine = Engine::builder()
        .agent("argv-equivalence")
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
        if cmd.contains('\n') || cmd.contains("<<") {
            continue;
        }
        let base = rank(engine.decide(&bash(cmd)).decision.kind());
        let words: Vec<&str> = cmd.split(' ').collect();
        let mut starts = Vec::with_capacity(words.len());
        let mut offset = 0;
        for w in &words {
            starts.push(offset);
            offset += w.len() + 1;
        }
        let mut variants = Vec::new();
        for (idx, head) in words.iter().enumerate() {
            let command_position = idx == 0 || matches!(words[idx - 1], "&&" | "||" | ";" | "|");
            if !command_position
                || !at_top_level(cmd, starts[idx])
                || !is_plain(head)
                || head.contains(['/', '='])
            {
                continue;
            }
            // The simple command's words: up to the next operator.
            let end = (idx + 1..words.len())
                .find(|&k| {
                    matches!(words[k], "&&" | "||" | ";" | "|")
                        || words[k].starts_with(['>', '<', '2'])
                })
                .unwrap_or(words.len());
            let replace = |new: Vec<String>| {
                let mut out: Vec<String> = words[..idx].iter().map(|w| (*w).to_string()).collect();
                out.extend(new);
                out.extend(words[end..].iter().map(|w| (*w).to_string()));
                out.join(" ")
            };
            let simple: Vec<String> = words[idx..end].iter().map(|w| (*w).to_string()).collect();
            if !SHELL_ONLY_BUILTINS.contains(head) {
                let mut new = simple.clone();
                new[0] = format!("/usr/bin/{head}");
                variants.push(replace(new));
            }
            if !BOOLEAN_FLAG_HEADS.contains(head)
                || simple[1..].iter().any(|a| a == "--" || !is_plain(a))
            {
                continue;
            }
            let (flags, operands): (Vec<&String>, Vec<&String>) = simple[1..]
                .iter()
                .partition(|a| a.starts_with('-') && a.len() > 1 && !a.starts_with("--"));
            if flags.is_empty() || operands.is_empty() {
                continue;
            }
            let split: Vec<String> = flags
                .iter()
                .flat_map(|f| f[1..].chars().map(|c| format!("-{c}")).collect::<Vec<_>>())
                .collect();
            let reversed: Vec<String> = flags
                .iter()
                .map(|f| format!("-{}", f[1..].chars().rev().collect::<String>()))
                .collect();
            let ops: Vec<String> = operands.iter().map(|s| (*s).clone()).collect();
            for flag_form in [split, reversed] {
                let mut before = vec![(*head).to_string()];
                before.extend(flag_form.iter().cloned());
                before.extend(ops.iter().cloned());
                variants.push(replace(before));
                let mut after = vec![(*head).to_string()];
                after.extend(ops.iter().cloned());
                after.extend(flag_form.iter().cloned());
                variants.push(replace(after));
            }
        }
        for variant in variants {
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
    eprintln!("checked {checked} argv variants");
    assert!(checked > 100, "only {checked} argv variants generated");
    assert!(
        misses.is_empty(),
        "{} of {checked} argv variants weakened the decision:\n{}",
        misses.len(),
        misses.join("\n")
    );
}
