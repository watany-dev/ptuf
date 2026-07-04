//! `core.secrets.sensitive-bash-read` — asks the user before a Bash
//! command reads a credentials file out to its stdout / stdin.
//!
//! The sibling `core.secrets.sensitive-path-to-network` rule only fires
//! when a *network* sink is co-located with a sensitive token; plain
//! `cat ~/.ssh/id_rsa` or `source .env` slip past it because there is no
//! pipe to curl/scp/etc. But emitting secret contents to the agent's
//! transcript is itself an exposure: the AUT now knows the secret, and
//! any later step (prompt injection, debug logging, copy-paste into a
//! comment) can leak it.
//!
//! This rule covers that gap. It targets a curated allowlist of
//! "reader" command heads plus the Bash stdin redirect (`< .env`).
//! Write-style redirects (`>`, `>>`, `2>`, `&>`) are *not* in scope —
//! those are handled by the file-tool rule `core.secrets.sensitive-read`
//! once Write/apply_patch joined its matcher.
//!
//! Default is `Ask`, not `Deny`, because false positives are expected
//! (`cat .env.example`, `source ./hack/setup-env.sh`). `hard_deny` is
//! `false` so projects can suppress the rule via `overrides.allow` in
//! `.ptuf.yaml` once they have audited a specific shape.

use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::facts::shell::{Argv, Bash, Pipeline, Redirect, RedirectOp};
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;
use super::patterns::{argv_references_sensitive, matches_sensitive_path};

pub struct SensitiveBashRead;

const RULE_ID: &str = "core.secrets.sensitive-bash-read";

/// Command heads that emit file contents to stdout, stdin, or another
/// downstream consumer. Keep this list *narrow*: every entry produces
/// `Ask` prompts on its sensitive-path uses, so a head whose typical
/// invocation rarely touches credentials does not belong here.
///
/// Explicitly excluded:
/// - `tee` — writes stdin to a file. The reader is whatever upstream
///   command feeds tee; tee itself is a sink, not a source.
/// - `>`, `>>`, `2>`, `&>` redirect targets — write destinations,
///   covered by `core.secrets.sensitive-read` (via Write payloads).
pub(crate) const READER_HEADS: &[&str] = &[
    "cat", "head", "tail", "less", "more", "view", "bat", "xxd", "od", "hexdump", "strings",
    "base64", "base32", "grep", "egrep", "fgrep", "awk", "gawk", "mawk", "sed", "cut", "tr",
    "sort", "uniq", "wc", "nl", "tac", "rev", "column", "file", "dd", "source", ".",
];

impl ConfigRule for SensitiveBashRead {
    fn id(&self) -> &str {
        RULE_ID
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn default_decision(&self) -> DecisionKind {
        DecisionKind::Ask
    }

    fn evaluate(&self, facts: &Facts, _input: &HookInput) -> Option<Decision> {
        let bash = facts.bash.as_ref()?;
        if !bash_reads_sensitive_path(bash) {
            return None;
        }
        let reason = reason::build(
            RULE_ID,
            "The command would feed a credentials file (SSH key, AWS / gcloud / kube config, \
             dotenv, npmrc, pypirc, tfstate, or PEM blob) into its stdout or stdin. The agent \
             would then see the secret in its transcript even though no network sink is \
             involved.",
            &[
                "Ask the user to inspect or transform the file themselves.",
                "Operate on a redacted copy with the secret values stripped.",
                "If `.env.example` (or another non-secret sample) is intended, suppress this \
                 rule for that file via `overrides.allow` in `.ptuf.yaml`.",
            ],
        );
        Some(Decision::Ask {
            rule_id: RULE_ID.into(),
            reason,
        })
    }
}

/// `$(...)` collapses substitution bodies into the surrounding word, so
/// pipeline scope can no longer see what executes inside. Widen to
/// command-wide co-occurrence in that case: false positives are
/// preferable to letting a substitution hide a sensitive read shape.
fn bash_reads_sensitive_path(bash: &Bash) -> bool {
    if bash.has_command_substitution {
        let commands = bash.commands();
        let has_reader = commands.iter().any(|a| invokes_reader(a));
        let has_sensitive = commands.iter().any(|a| argv_references_sensitive(a));
        return has_reader && has_sensitive;
    }
    bash.segments.iter().any(pipeline_reads_sensitive)
}

fn pipeline_reads_sensitive(pipe: &Pipeline) -> bool {
    let argv_match = pipe.commands.iter().any(argv_reads_sensitive);
    let stdin_match = pipe.redirects.iter().any(stdin_target_is_sensitive);
    argv_match || stdin_match
}

/// True when this argv (or any wrapped inner argv) is a reader head
/// invoked on a sensitive token. The wrapper recursion covers
/// `bash -c '...'`, `xargs`, `find -exec`, and `eval`.
fn argv_reads_sensitive(argv: &Argv) -> bool {
    if invokes_reader(argv) && argv_has_sensitive_positional(argv) {
        return true;
    }
    if let Some(inner) = crate::facts::shell::unwrap_privilege_wrapper(argv)
        && invokes_reader(&inner)
        && argv_has_sensitive_positional(&inner)
    {
        return true;
    }
    // Heredoc/inner_redirects on this argv: a `< .env` inside a wrapped
    // bash -c shows up there.
    if argv.inner_redirects.iter().any(stdin_target_is_sensitive) {
        return true;
    }
    argv.inner_argv.iter().any(argv_reads_sensitive)
}

fn argv_has_sensitive_positional(argv: &Argv) -> bool {
    if matches_sensitive_path(&argv.head) {
        return true;
    }
    argv.args.iter().any(|a| matches_sensitive_path(a))
}

fn invokes_reader(argv: &Argv) -> bool {
    READER_HEADS.contains(&argv.head_basename())
}

fn stdin_target_is_sensitive(r: &Redirect) -> bool {
    matches!(r.op, RedirectOp::Stdin) && matches_sensitive_path(&r.target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook_input::HookInput;

    fn bash(cmd: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": cmd }),
        }
    }

    fn evaluate_for(input: &HookInput) -> Option<Decision> {
        let facts = crate::facts::extract(input);
        SensitiveBashRead.evaluate(&facts, input)
    }

    fn assert_ask(cmd: &str) {
        let result = evaluate_for(&bash(cmd));
        assert!(
            matches!(&result, Some(Decision::Ask { rule_id, .. }) if rule_id == RULE_ID),
            "expected Ask for {cmd:?}, got {result:?}",
        );
    }

    fn assert_silent(cmd: &str) {
        let result = evaluate_for(&bash(cmd));
        assert!(
            result.is_none(),
            "expected None for {cmd:?}, got {result:?}",
        );
    }

    #[test]
    fn asks_for_reader_heads_on_sensitive_paths() {
        for cmd in [
            "cat .env",
            "cat /repo/.env.production",
            "source .env",
            "source ./.env.production",
            ". .env.production",
            "cat ~/.ssh/id_rsa",
            "head ~/.aws/credentials",
            "tail -n 1 ~/.kube/config",
        ] {
            assert_ask(cmd);
        }
    }

    #[test]
    fn asks_for_absolute_and_relative_path_reader_heads() {
        // Reader heads must match on basename: /bin/cat is still cat.
        assert_ask("/bin/cat ~/.ssh/id_rsa");
        assert_ask("/usr/bin/head -n 5 ~/.aws/credentials");
        assert_ask("./cat .env");
    }

    #[test]
    fn asks_for_redirected_stdin() {
        assert_ask("read -r LINE < .env");
        assert_ask("awk '{print}' < .env");
    }

    #[test]
    fn asks_for_sudo_cat() {
        assert_ask("sudo cat .env");
        assert_ask("sudo head -n 5 ~/.ssh/id_rsa");
    }

    #[test]
    fn asks_for_inner_bash_c() {
        assert_ask("bash -c 'cat .env'");
        assert_ask("bash -c 'cat < .env'");
    }

    #[test]
    fn asks_for_command_substitution_pessimistic() {
        // The substitution body is folded into the surrounding token,
        // so the outer reader head + the leaked sensitive substring
        // still satisfy the pessimistic-mode coexistence check.
        assert_ask("cat $(echo .env)");
        assert_ask("source $(printf %s .env.production)");
    }

    #[test]
    fn gap_cmdsubst_outer_nonreader_surfaces_sensitive_token() {
        // ADR 0001 known_gap: outer head `echo` is not a reader, so the
        // rule stays silent even though the substitution body mentions
        // `.env`. Pin both the surfaced token and the Allow-equivalent
        // outcome so a fix must update corpus + this test together.
        let cmd = "echo $(cat .env)";
        let input = bash(cmd);
        let facts = crate::facts::extract(&input);
        let bash_facts = facts.bash.as_ref().expect("bash facts");
        let surfaces_sensitive = bash_facts
            .commands()
            .iter()
            .any(|argv| crate::rules::patterns::argv_references_sensitive(argv));
        assert!(
            surfaces_sensitive,
            "parser should still surface the .env token in argv"
        );
        assert_silent(cmd);
    }

    #[test]
    fn asks_for_brace_expansion_dotenv() {
        assert_ask("cat {a,b}.env");
        assert_ask("head {x,y,z}.env");
        assert_ask("cat {.env,.env.local}");
        assert_ask("cat prefix{a,b}.env");
        assert_ask("tail -n 1 {app,web}.env.production");
    }

    #[test]
    fn gap_unicode_homoglyph_normalizes_or_flags() {
        // ADR 0001 known_gap: Cyrillic homoglyph `.еnv` evades the ASCII
        // `(?i-u:.env)` anchor until normalization is implemented.
        assert_silent("cat .еnv"); // U+0435 CYRILLIC SMALL LETTER IE
    }

    #[test]
    fn asks_for_dd_in_either_direction() {
        // `dd if=.env of=/tmp/x` is a read; `dd if=/tmp/x of=.env` is a
        // write. Both surface a sensitive path on the argv so both Ask.
        // The Ask resolution is left to the user.
        assert_ask("dd if=.env of=/tmp/out");
        assert_ask("dd if=/tmp/in of=.env");
    }

    #[test]
    fn asks_for_absolute_path_ssh_config() {
        assert_ask("cat /home/user/.ssh/config");
        assert_ask("cat /root/.aws/credentials");
    }

    #[test]
    fn allows_non_reader_with_dotenv_arg() {
        assert_silent("rm .env");
        assert_silent("chmod 600 .env");
        assert_silent("mv .env .env.bak");
        assert_silent("ls -la .env");
    }

    #[test]
    fn allows_reader_without_sensitive_arg() {
        assert_silent("cat /repo/README.md");
        assert_silent("grep -r foo /repo/src");
        assert_silent("head -n 5 Cargo.toml");
    }

    #[test]
    fn allows_redirect_write_to_sensitive_path() {
        // Write-side redirects belong to sensitive-read (Write tool) —
        // this rule only fires on Stdin (`<`).
        assert_silent("echo X=1 > .env");
        assert_silent("echo X=1 >> .env");
    }

    #[test]
    fn allows_tee_into_sensitive_path() {
        // tee is a writer, not a reader. The shape `cat foo | tee .env`
        // is a write to `.env`; the reader judgement belongs to the
        // upstream `cat foo` (non-sensitive in this example).
        assert_silent("echo hi | tee .env");
    }

    #[test]
    fn allows_unrelated_segments_separated_by_semicolon() {
        // Each `;`-separated segment is judged independently; only
        // segments that themselves combine reader + sensitive fire.
        assert_silent("cat /repo/README.md; ls .env");
        assert_silent("ls -la; echo done");
    }

    #[test]
    fn asks_when_sensitive_segment_present_among_others() {
        // Even if other segments are unrelated, a single sensitive read
        // segment must fire.
        assert_ask("ls -la; cat .env; echo done");
    }

    #[test]
    fn ignores_non_bash_tools() {
        let input = HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({"command": "cat .env"}),
        };
        let facts = crate::facts::extract(&input);
        assert!(SensitiveBashRead.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn metadata_matches_design() {
        assert!(!SensitiveBashRead.hard_deny());
        assert!(SensitiveBashRead.overridable());
        assert_eq!(SensitiveBashRead.severity(), Severity::High);
        assert_eq!(SensitiveBashRead.default_decision(), DecisionKind::Ask);
        assert_eq!(SensitiveBashRead.id(), RULE_ID);
    }

    use crate::testing::proptest::{
        arbitrary_command, bash_command, bash_reader_brace_dotenv_command, dotenv_brace_token,
        non_bash_hook_input,
    };
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pbt_non_bash_yields_none(input in non_bash_hook_input()) {
            prop_assert!(evaluate_for(&input).is_none());
        }

        #[test]
        fn pbt_evaluate_never_panics(cmd in arbitrary_command()) {
            let _ = evaluate_for(&bash(&cmd));
        }

        #[test]
        fn pbt_only_emits_ask_with_correct_id(cmd in bash_command()) {
            let input = bash(&cmd);
            if let Some(d) = evaluate_for(&input) {
                match d {
                    Decision::Ask { rule_id, .. } => prop_assert_eq!(rule_id, RULE_ID),
                    other => prop_assert!(false, "expected Ask, got {other:?}"),
                }
            }
        }

        // Reader + brace dotenv argv token must always Ask.
        #[test]
        fn pbt_reader_brace_dotenv_always_asks(cmd in bash_reader_brace_dotenv_command()) {
            let input = bash(&cmd);
            let d = evaluate_for(&input);
            prop_assert!(
                matches!(d, Some(Decision::Ask { ref rule_id, .. }) if rule_id == RULE_ID),
                "expected Ask for {cmd:?}, got {d:?}",
            );
        }

        // Parsed argv must surface the brace token for regex matching.
        #[test]
        fn pbt_brace_dotenv_surfaces_on_argv(token in dotenv_brace_token()) {
            let cmd = format!("cat {token}");
            let facts = crate::facts::extract(&bash(&cmd));
            let bash_facts = facts.bash.as_ref().expect("bash facts");
            let surfaces = bash_facts.commands().iter().any(|argv| {
                crate::rules::patterns::argv_references_sensitive(argv)
            });
            prop_assert!(surfaces, "argv did not reference sensitive for {cmd:?}");
        }

                // Without any reader head, the rule cannot fire — even with
        // sensitive-looking arguments.
        #[test]
        fn pbt_no_reader_head_means_no_fire(
            head in "[a-z][a-z0-9]{0,5}",
            args in proptest::collection::vec("[a-zA-Z0-9_./-]{1,8}", 0..3),
        ) {
            prop_assume!(!READER_HEADS.contains(&head.as_str()));
            prop_assume!(head != "sudo");
            let cmd = if args.is_empty() {
                head
            } else {
                format!("{} {}", head, args.join(" "))
            };
            let input = bash(&cmd);
            prop_assert!(evaluate_for(&input).is_none());
        }
    }
}
