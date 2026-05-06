//! Minimal shell fact extraction.
//!
//! Splits a Bash command string into segments (`;`, `&&`, `||`),
//! pipelines (`|`), and per-command [`Argv`] (env assignments + head +
//! args). Quoting (`'`, `"`, `` ` ``) is honoured so that a separator
//! inside quotes does not split the command.
//!
//! Scope intentionally excludes redirects, heredocs, and process
//! substitution; rules that need them must grow the lexer first.
//! Command substitution (`` `…` `` / `$(…)`) is *detected* but the
//! body is treated as opaque text inside the surrounding word — the
//! parser does not re-enter to extract facts from substitution bodies.
//! Rules that need accurate argv (e.g. sensitive-net) can opt in to
//! pessimistic handling by reading [`Bash::has_command_substitution`].
//! See `docs/design/architecture.md` §fact extraction.

/// A parsed Bash command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bash {
    pub segments: Vec<Pipeline>,
    /// `true` if the source contained a `` ` … ` `` or `$(…)` command
    /// substitution. The substitution body is folded into the
    /// surrounding word as opaque text, so callers that depend on
    /// accurate argv should treat such commands pessimistically.
    pub has_command_substitution: bool,
}

/// One `;` / `&&` / `||`-bounded pipeline. Multiple commands inside are
/// joined by `|`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub commands: Vec<Argv>,
}

/// A single command invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argv {
    /// Leading `KEY=VALUE` env assignments (e.g. `FOO=1 cmd ...`).
    pub env_assignments: Vec<EnvAssignment>,
    /// The command head (`rm`, `/bin/rm`, `sudo`, `curl`, ...).
    pub head: String,
    /// Remaining arguments (flags + positional).
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvAssignment {
    pub key: String,
    pub value: String,
}

impl Argv {
    /// Iterate over arguments that look like flags (`-r`, `--recursive`).
    pub fn flags(&self) -> impl Iterator<Item = &str> {
        self.args.iter().filter(|a| is_flag(a)).map(String::as_str)
    }

    /// Iterate over positional (non-flag) arguments.
    pub fn positional(&self) -> impl Iterator<Item = &str> {
        self.args.iter().filter(|a| !is_flag(a)).map(String::as_str)
    }
}

const SUDO_VALUE_SHORT_FLAGS: &[char] = &['C', 'g', 'h', 'p', 'T', 't', 'U', 'u'];
const SUDO_VALUE_LONG_FLAGS: &[&str] = &[
    "close-from",
    "chdir",
    "group",
    "host",
    "login-class",
    "prompt",
    "role",
    "type",
    "user",
];

/// Return the command that `sudo` would execute.
///
/// This intentionally understands common value-taking sudo options so
/// `sudo -u root git ...` unwraps to `git ...`, not to `root ...`.
pub(crate) fn unwrap_sudo(argv: &Argv) -> Option<Argv> {
    if argv.head != "sudo" {
        return None;
    }

    let mut i = 0;
    while i < argv.args.len() {
        let arg = argv.args[i].as_str();
        if arg == "--" {
            i += 1;
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        if let Some(flag) = arg.strip_prefix("--") {
            if let Some(name) = flag.split('=').next()
                && SUDO_VALUE_LONG_FLAGS.contains(&name)
                && !flag.contains('=')
            {
                i += 1;
            }
            i += 1;
            continue;
        }
        if let Some(value_flag) = short_sudo_value_flag(arg)
            && arg.len() == 2
            && arg.ends_with(value_flag)
        {
            i += 1;
        }
        i += 1;
    }

    let head = argv.args.get(i)?.to_string();
    let rest = argv.args.iter().skip(i + 1).cloned().collect();
    Some(Argv {
        env_assignments: Vec::new(),
        head,
        args: rest,
    })
}

fn short_sudo_value_flag(arg: &str) -> Option<char> {
    let mut chars = arg.strip_prefix('-')?.chars();
    let flag = chars.next()?;
    if SUDO_VALUE_SHORT_FLAGS.contains(&flag) {
        Some(flag)
    } else {
        None
    }
}

fn is_flag(a: &str) -> bool {
    a.starts_with('-') && a != "-" && a != "--"
}

/// Parse a raw Bash command string into a [`Bash`] structure.
///
/// Returns an empty `Bash` (no segments) for an entirely blank command.
pub fn parse(command: &str) -> Bash {
    let (tokens, has_command_substitution) = tokenize(command);
    let segments = split_segments(tokens);
    let pipelines: Vec<Pipeline> = segments.into_iter().map(parse_pipeline).collect();
    Bash {
        segments: pipelines
            .into_iter()
            .filter(|p| !p.commands.is_empty())
            .collect(),
        has_command_substitution,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Pipe,
    And,
    Or,
    Semi,
}

fn tokenize(s: &str) -> (Vec<Token>, bool) {
    let mut out = Vec::new();
    let mut saw_command_substitution = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'|' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                out.push(Token::Or);
                i += 2;
            } else {
                out.push(Token::Pipe);
                i += 1;
            }
            continue;
        }
        if c == b'&' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                out.push(Token::And);
                i += 2;
            } else {
                // Lone `&` (background operator). ptuf does not model
                // background semantics; skip it so the lexer always makes
                // forward progress. Without this, `read_word` would return
                // (empty, 0 bytes) and `tokenize` would infinite-loop.
                i += 1;
            }
            continue;
        }
        if c == b';' {
            out.push(Token::Semi);
            i += 1;
            continue;
        }
        // Otherwise: read a word, honouring quotes.
        let (word, advanced, word_subst) = read_word(&bytes[i..]);
        // Forward-progress invariant: every separator and whitespace
        // byte is consumed above, so `read_word` is always called on a
        // non-trivial first byte and must advance by at least 1. The
        // assertion documents this; if a future change adds a code path
        // that returns 0, debug builds fail fast instead of looping.
        debug_assert!(advanced > 0, "read_word must consume at least one byte");
        if word_subst {
            saw_command_substitution = true;
        }
        out.push(Token::Word(word));
        i += advanced;
    }
    (out, saw_command_substitution)
}

/// Read a single shell "word" starting at `bytes[0]`. Quoted spans
/// (`'`, `"`, `` ` ``) are absorbed into the word with their delimiters
/// stripped. Returns the decoded word, the number of bytes consumed,
/// and a flag set when the word contained a `` ` `` or `$(` command
/// substitution opening.
///
/// The caller is expected to skip whitespace and the separator bytes
/// (`|`, `&`, `;`) before calling — under that contract this function
/// always consumes at least one byte.
fn read_word(bytes: &[u8]) -> (String, usize, bool) {
    let mut buf = String::new();
    let mut i = 0;
    let mut saw_subst = false;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            break;
        }
        if matches!(c, b'|' | b'&' | b';') {
            break;
        }
        if c == b'\\' && i + 1 < bytes.len() {
            buf.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        // Unquoted `$(`: command substitution. Body bytes fall through
        // and are folded into the word as opaque text.
        if c == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            saw_subst = true;
        }
        if c == b'\'' || c == b'"' || c == b'`' {
            if c == b'`' {
                saw_subst = true;
            }
            let quote = c;
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if quote == b'"' && bytes[i] == b'\\' && i + 1 < bytes.len() {
                    buf.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                // `$(` inside a double-quoted span is still a command
                // substitution. Single-quoted spans are literal so the
                // sequence does not count there.
                if quote == b'"' && bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'('
                {
                    saw_subst = true;
                }
                buf.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // closing quote
            }
            continue;
        }
        buf.push(c as char);
        i += 1;
    }
    (buf, i, saw_subst)
}

fn split_segments(tokens: Vec<Token>) -> Vec<Vec<Token>> {
    let mut segments = Vec::new();
    let mut current = Vec::new();
    for tok in tokens {
        match tok {
            Token::And | Token::Or | Token::Semi => {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

fn parse_pipeline(tokens: Vec<Token>) -> Pipeline {
    let mut commands = Vec::new();
    let mut current_words: Vec<String> = Vec::new();
    for tok in tokens {
        match tok {
            Token::Word(w) => current_words.push(w),
            Token::Pipe => {
                if !current_words.is_empty() {
                    commands.push(parse_argv(std::mem::take(&mut current_words)));
                }
            }
            // Segment splitters never reach here; ignore defensively.
            Token::And | Token::Or | Token::Semi => {}
        }
    }
    if !current_words.is_empty() {
        commands.push(parse_argv(current_words));
    }
    Pipeline { commands }
}

fn parse_argv(words: Vec<String>) -> Argv {
    // VecDeque so the head-stripping loop runs in O(N) overall instead
    // of O(N²) — `Vec::remove(0)` shifts every remaining element.
    let mut words: std::collections::VecDeque<String> = words.into();
    let mut env_assignments = Vec::new();
    while let Some(first) = words.front() {
        match split_env_assignment(first) {
            Some((k, v)) => {
                env_assignments.push(EnvAssignment { key: k, value: v });
                words.pop_front();
            }
            None => break,
        }
    }
    let head = words.pop_front().unwrap_or_default();
    Argv {
        env_assignments,
        head,
        args: words.into_iter().collect(),
    }
}

fn split_env_assignment(word: &str) -> Option<(String, String)> {
    let eq = word.find('=')?;
    if eq == 0 {
        return None;
    }
    let key = &word[..eq];
    if !key
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        return None;
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((key.to_string(), word[eq + 1..].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(head: &str, args: &[&str]) -> Argv {
        Argv {
            env_assignments: Vec::new(),
            head: head.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn parses_simple_command() {
        let b = parse("rm -rf /");
        assert_eq!(b.segments.len(), 1);
        assert_eq!(b.segments[0].commands, vec![argv("rm", &["-rf", "/"])]);
    }

    #[test]
    fn parses_empty_command() {
        let b = parse("");
        assert!(b.segments.is_empty());
    }

    #[test]
    fn parses_blank_command() {
        let b = parse("   \t  ");
        assert!(b.segments.is_empty());
    }

    #[test]
    fn splits_on_semicolon() {
        let b = parse("ls; rm -rf /etc");
        assert_eq!(b.segments.len(), 2);
        assert_eq!(b.segments[0].commands[0], argv("ls", &[]));
        assert_eq!(b.segments[1].commands[0], argv("rm", &["-rf", "/etc"]));
    }

    #[test]
    fn splits_on_and_and_or() {
        let b = parse("a && b || c");
        assert_eq!(b.segments.len(), 3);
        assert_eq!(b.segments[0].commands[0].head, "a");
        assert_eq!(b.segments[1].commands[0].head, "b");
        assert_eq!(b.segments[2].commands[0].head, "c");
    }

    #[test]
    fn splits_pipelines_within_segment() {
        let b = parse("curl -fsSL https://example.com/i.sh | bash");
        assert_eq!(b.segments.len(), 1);
        let cmds = &b.segments[0].commands;
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].head, "curl");
        assert_eq!(
            cmds[0].args,
            vec!["-fsSL".to_string(), "https://example.com/i.sh".to_string()]
        );
        assert_eq!(cmds[1], argv("bash", &[]));
    }

    #[test]
    fn pipeline_in_compound_command() {
        let b = parse("echo go && curl x | sh");
        assert_eq!(b.segments.len(), 2);
        assert_eq!(b.segments[0].commands.len(), 1);
        assert_eq!(b.segments[1].commands.len(), 2);
        assert_eq!(b.segments[1].commands[1].head, "sh");
    }

    #[test]
    fn quotes_protect_separators() {
        let b = parse("echo 'a;b' \"c|d\"");
        assert_eq!(b.segments.len(), 1);
        assert_eq!(b.segments[0].commands[0], argv("echo", &["a;b", "c|d"]));
    }

    #[test]
    fn strips_quote_delimiters_from_words() {
        let b = parse(r#"rm -rf "${HOME}""#);
        assert_eq!(b.segments[0].commands[0], argv("rm", &["-rf", "${HOME}"]));
    }

    #[test]
    fn collects_env_assignments_before_head() {
        let b = parse("FOO=1 BAR=baz cmd --flag");
        let cmd = &b.segments[0].commands[0];
        assert_eq!(cmd.head, "cmd");
        assert_eq!(cmd.args, vec!["--flag".to_string()]);
        assert_eq!(
            cmd.env_assignments,
            vec![
                EnvAssignment {
                    key: "FOO".into(),
                    value: "1".into(),
                },
                EnvAssignment {
                    key: "BAR".into(),
                    value: "baz".into(),
                },
            ]
        );
    }

    #[test]
    fn does_not_treat_url_as_env_assignment() {
        // `https://...` has `://` not `=`, but verify that a URL with a
        // query string is still treated as a single arg, not as an env.
        let b = parse("curl https://example.com/?key=value");
        let cmd = &b.segments[0].commands[0];
        assert_eq!(cmd.head, "curl");
        assert!(cmd.env_assignments.is_empty());
    }

    #[test]
    fn rejects_env_with_non_identifier_key() {
        // `1FOO=bar` is not a valid env key (starts with digit).
        let b = parse("1FOO=bar cmd");
        let first = &b.segments[0].commands[0];
        assert_eq!(first.head, "1FOO=bar");
        assert!(first.env_assignments.is_empty());
    }

    #[test]
    fn flags_iterator_filters_dash_args() {
        let cmd = argv("rm", &["-rf", "--force", "/etc", "build"]);
        let flags: Vec<_> = cmd.flags().collect();
        assert_eq!(flags, vec!["-rf", "--force"]);
        let pos: Vec<_> = cmd.positional().collect();
        assert_eq!(pos, vec!["/etc", "build"]);
    }

    #[test]
    fn lone_dash_is_not_a_flag() {
        let cmd = argv("tar", &["-czf", "-", "."]);
        let flags: Vec<_> = cmd.flags().collect();
        assert_eq!(flags, vec!["-czf"]);
        let pos: Vec<_> = cmd.positional().collect();
        assert_eq!(pos, vec!["-", "."]);
    }

    #[test]
    fn double_dash_separator_is_not_a_flag() {
        let cmd = argv("rm", &["--", "--weird-file"]);
        let flags: Vec<_> = cmd.flags().collect();
        assert_eq!(flags, vec!["--weird-file"]);
        let pos: Vec<_> = cmd.positional().collect();
        assert_eq!(pos, vec!["--"]);
    }

    #[test]
    fn full_path_command_keeps_head_intact() {
        let b = parse("/usr/bin/rm -rf /etc");
        assert_eq!(b.segments[0].commands[0].head, "/usr/bin/rm");
    }

    #[test]
    fn double_pipe_is_or_not_pipeline() {
        let b = parse("a || b");
        assert_eq!(b.segments.len(), 2);
        assert_eq!(b.segments[0].commands[0].head, "a");
        assert_eq!(b.segments[1].commands[0].head, "b");
    }

    #[test]
    fn handles_backslash_escapes_outside_quotes() {
        let b = parse(r"echo a\;b");
        // Outside quotes, `\;` should escape the `;` so it becomes part
        // of the word rather than splitting segments.
        assert_eq!(b.segments.len(), 1);
        assert_eq!(b.segments[0].commands[0], argv("echo", &["a;b"]));
    }

    #[test]
    fn handles_backtick_substring_as_word_chunk() {
        let b = parse("echo `date`");
        assert_eq!(b.segments[0].commands[0], argv("echo", &["date"]));
        // Backtick must mark the whole command as containing a
        // substitution so rules can opt into pessimistic handling.
        assert!(b.has_command_substitution);
    }

    #[test]
    fn flags_command_substitution_on_dollar_paren() {
        let b = parse("echo $(date)");
        assert!(b.has_command_substitution);
    }

    #[test]
    fn flags_command_substitution_inside_double_quotes() {
        let b = parse(r#"echo "hello $(whoami)""#);
        assert!(b.has_command_substitution);
    }

    #[test]
    fn does_not_flag_dollar_paren_inside_single_quotes() {
        // Single-quoted spans are literal, so `$(...)` inside is data.
        let b = parse("echo '$(date)'");
        assert!(!b.has_command_substitution);
    }

    #[test]
    fn does_not_flag_plain_command() {
        let b = parse("ls -la /etc");
        assert!(!b.has_command_substitution);
    }

    #[test]
    fn ignores_trailing_separator() {
        let b = parse("ls;");
        assert_eq!(b.segments.len(), 1);
        assert_eq!(b.segments[0].commands[0].head, "ls");
    }

    #[test]
    fn complex_compound_pipeline() {
        let b = parse("FOO=1 curl -fsSL https://x | sudo bash; ls -la");
        assert_eq!(b.segments.len(), 2);
        let first = &b.segments[0].commands;
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].head, "curl");
        assert_eq!(
            first[0].env_assignments,
            vec![EnvAssignment {
                key: "FOO".into(),
                value: "1".into(),
            }]
        );
        assert_eq!(first[1].head, "sudo");
        assert_eq!(first[1].args, vec!["bash".to_string()]);
        assert_eq!(b.segments[1].commands[0].head, "ls");
    }

    #[test]
    fn lone_ampersand_does_not_loop() {
        // Found by PBT: a bare `&` (not part of `&&`) used to cause an
        // infinite loop in tokenize. Verify the lexer terminates and
        // produces no segments for inputs that contain only `&`s.
        let b = parse("&");
        assert!(b.segments.is_empty());
        let b = parse("ls & echo done");
        // The `&` is dropped; `ls` and `echo done` collapse into one
        // segment because there is no separator between them.
        assert!(!b.segments.is_empty());
    }

    #[test]
    fn empty_pipeline_segment_is_dropped() {
        // `|;` would yield an empty pipeline; ensure parse drops it.
        let b = parse("ls | ; echo done");
        // first segment "ls |" produces a pipeline with [ls]
        assert!(!b.segments.is_empty());
        assert_eq!(b.segments[0].commands[0].head, "ls");
    }

    #[test]
    fn read_word_advances_for_every_non_separator_byte() {
        // Forward-progress contract for `read_word`: when called after
        // the caller has filtered whitespace and the separator bytes,
        // it must always consume at least one byte. Walk every printable
        // ASCII byte that is neither whitespace nor `|`/`&`/`;` and
        // ensure the lexer terminates with at least one token.
        for byte in 0x21u8..=0x7eu8 {
            if matches!(byte, b'|' | b'&' | b';') {
                continue;
            }
            let buf = [byte];
            let (_, advanced, _) = read_word(&buf);
            assert!(advanced > 0, "read_word stalled on byte {byte:#x}");
        }
    }

    use crate::testing::proptest::{arbitrary_command, bash_command};
    use proptest::collection::vec as pvec;
    use proptest::prelude::*;

    proptest! {
        // Adversarial: the parser must not panic, hang, or blow up memory
        // for any printable ASCII. (PBT discovered a real infinite-loop
        // bug here when fed a lone `&` — see `lone_ampersand_does_not_loop`.)
        #[test]
        fn pbt_parse_never_panics(s in arbitrary_command()) {
            let _ = parse(&s);
        }

        // Structured generator: the parser still succeeds and produces
        // at least one segment whenever the source has non-whitespace
        // content.
        #[test]
        fn pbt_structured_command_yields_segments(s in bash_command()) {
            let b = parse(&s);
            if s.chars().any(|c| !c.is_whitespace()) {
                prop_assert!(!b.segments.is_empty());
            }
        }

        // Whitespace-only input parses to an empty segment list.
        #[test]
        fn pbt_blank_input_has_no_segments(spaces in "[ \\t]{0,20}") {
            let b = parse(&spaces);
            prop_assert!(b.segments.is_empty());
        }

        // Single-quoted text protects shell separators: any printable
        // ASCII (without single quotes) wrapped in `'…'` becomes one
        // segment with one command.
        #[test]
        fn pbt_single_quotes_protect_separators(inner in "[ -&(-~]{0,30}") {
            // Exclude ' (0x27) from the inner so we don't terminate the quote.
            let cmd = format!("echo '{inner}'");
            let b = parse(&cmd);
            prop_assert_eq!(b.segments.len(), 1);
            prop_assert_eq!(b.segments[0].commands.len(), 1);
            prop_assert_eq!(&b.segments[0].commands[0].head, "echo");
        }

        // is_flag invariant lifted to user-facing semantics.
        #[test]
        fn pbt_flags_partition_args(args in pvec("[A-Za-z0-9_./-]{1,8}", 0..6)) {
            let cmd = format!("ls {}", args.join(" "));
            let b = parse(&cmd);
            if let Some(first) = b.segments.first().and_then(|p| p.commands.first()) {
                let flags: Vec<&str> = first.flags().collect();
                let positional: Vec<&str> = first.positional().collect();
                // Disjoint:
                for f in &flags {
                    prop_assert!(!positional.contains(f));
                }
                // Union spans every recorded arg:
                prop_assert_eq!(flags.len() + positional.len(), first.args.len());
            }
        }

        // Joining N safe heads with `|` produces one segment with N commands.
        #[test]
        fn pbt_pipe_produces_n_commands(heads in pvec("[a-z][a-z0-9]{0,5}", 1..4)) {
            let cmd = heads.join(" | ");
            let b = parse(&cmd);
            prop_assert_eq!(b.segments.len(), 1);
            prop_assert_eq!(b.segments[0].commands.len(), heads.len());
            for (i, h) in heads.iter().enumerate() {
                prop_assert_eq!(&b.segments[0].commands[i].head, h);
            }
        }

        // Joining N safe heads with `;` produces N segments.
        #[test]
        fn pbt_semicolon_produces_n_segments(heads in pvec("[a-z][a-z0-9]{0,5}", 1..4)) {
            let cmd = heads.join("; ");
            let b = parse(&cmd);
            prop_assert_eq!(b.segments.len(), heads.len());
            for (i, h) in heads.iter().enumerate() {
                prop_assert_eq!(&b.segments[i].commands[0].head, h);
            }
        }

        // Env assignments come before the head and are stripped from args.
        #[test]
        fn pbt_env_assignments_precede_head(
            keys in pvec("[A-Z_][A-Z0-9_]{0,6}", 0..3),
            vals in pvec("[a-zA-Z0-9]{1,6}", 0..3),
        ) {
            // Build matching K=V pairs, then a head + flag.
            let n = keys.len().min(vals.len());
            let mut prefix = String::new();
            for i in 0..n {
                prefix.push_str(&format!("{}={} ", keys[i], vals[i]));
            }
            let cmd = format!("{prefix}cmd --flag");
            let b = parse(&cmd);
            prop_assert_eq!(b.segments.len(), 1);
            let argv = &b.segments[0].commands[0];
            prop_assert_eq!(&argv.head, "cmd");
            prop_assert_eq!(argv.env_assignments.len(), n);
            for i in 0..n {
                prop_assert_eq!(&argv.env_assignments[i].key, &keys[i]);
                prop_assert_eq!(&argv.env_assignments[i].value, &vals[i]);
            }
        }
    }
}
