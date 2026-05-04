use std::io::{Read, Write};
use std::process::ExitCode;

use crate::cli;
use crate::{Decision, HookInput};

/// Top-level CLI entry. Parses argv, dispatches to a [`crate::cli::Command`],
/// and returns an [`ExitCode`].
pub fn run<R, W1, W2, S>(args: &[S], stdin: R, stdout: &mut W1, stderr: &mut W2) -> ExitCode
where
    R: Read,
    W1: Write,
    W2: Write,
    S: AsRef<str>,
{
    let owned: Vec<String> = args.iter().map(|s| s.as_ref().to_string()).collect();
    let command = match cli::parse(&owned) {
        Ok(c) => c,
        Err(err) => {
            let _ = writeln!(stderr, "ptuf: {err}");
            return ExitCode::from(1);
        }
    };
    ExitCode::from(cli::run(command, stdin, stdout, stderr))
}

/// Bootstrap-compatible runner: stdin (JSON) -> decide -> exit code + stderr.
///
/// Returns:
/// - `0` on Allow / Monitor / Ask
/// - `2` on Deny (with reason on stderr)
/// - `1` on internal error (read failure or invalid JSON)
pub fn run_compat<R: Read, W: Write>(stdin: R, stderr: &mut W) -> ExitCode {
    ExitCode::from(run_compat_code(stdin, stderr))
}

pub(crate) fn run_compat_code<R: Read, W: Write>(mut stdin: R, stderr: &mut W) -> u8 {
    let mut buf = String::new();
    if stdin.read_to_string(&mut buf).is_err() {
        let _ = writeln!(stderr, "ptuf: failed to read stdin");
        return 1;
    }

    let input: HookInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(err) => {
            let _ = writeln!(stderr, "ptuf: invalid hook payload: {err}");
            return 1;
        }
    };

    let decision = match cli::build_engine_or_fail_closed(stderr) {
        Ok(engine) => engine.decide(&input).decision,
        Err(deny) => deny,
    };
    emit_compat_decision(&decision, stderr)
}

/// Emit a compat-mode decision: allow/monitor are silent, ask writes the
/// reason to stderr (exit 0), deny writes the reason to stderr (exit 2).
pub(crate) fn emit_compat_decision<W: Write>(decision: &Decision, stderr: &mut W) -> u8 {
    match decision {
        Decision::Allow | Decision::Monitor { .. } => 0,
        Decision::Ask { reason, .. } => {
            let _ = writeln!(stderr, "{reason}");
            0
        }
        Decision::Deny { reason, .. } => {
            let _ = writeln!(stderr, "{reason}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_compat_test(input: &str) -> (u8, String) {
        let mut stderr = Vec::new();
        let code = run_compat_code(input.as_bytes(), &mut stderr);
        (code, String::from_utf8_lossy(&stderr).into_owned())
    }

    #[test]
    fn allow_payload_returns_zero_and_no_stderr() {
        let (code, stderr) =
            run_compat_test(r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
    }

    #[test]
    fn deny_payload_returns_two_with_reason() {
        let (code, stderr) =
            run_compat_test(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#);
        assert_eq!(code, 2);
        assert!(stderr.contains("Blocked by ptuf rule core.filesystem.destructive-rm."));
    }

    #[test]
    fn invalid_json_returns_one_with_stderr() {
        let (code, stderr) = run_compat_test("not json");
        assert_eq!(code, 1);
        assert!(stderr.contains("invalid hook payload"));
    }

    #[test]
    fn empty_payload_returns_one() {
        let (code, stderr) = run_compat_test("");
        assert_eq!(code, 1);
        assert!(stderr.contains("invalid hook payload"));
    }

    #[test]
    fn run_dispatches_eval_with_args() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let args: Vec<&str> = vec!["eval", "--tool", "Bash", "ls"];
        let _exit = run(&args, b"" as &[u8], &mut out, &mut err);
        let out_s = String::from_utf8_lossy(&out);
        assert!(out_s.contains("Decision: allow"));
    }

    #[test]
    fn run_reports_unknown_command_to_stderr_with_exit_one() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let args: Vec<&str> = vec!["unknown-cmd"];
        let _exit = run(&args, b"" as &[u8], &mut out, &mut err);
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("unknown command"));
    }

    #[test]
    fn emit_compat_ask_writes_reason_with_zero_exit() {
        let decision = Decision::Ask {
            rule_id: "core.test.ask".into(),
            reason: "please confirm".into(),
        };
        let mut stderr = Vec::new();
        let code = emit_compat_decision(&decision, &mut stderr);
        assert_eq!(code, 0);
        assert!(String::from_utf8_lossy(&stderr).contains("please confirm"));
    }

    #[test]
    fn emit_compat_monitor_is_silent_with_zero_exit() {
        let decision = Decision::Monitor {
            rule_id: "core.test.monitor".into(),
        };
        let mut stderr = Vec::new();
        let code = emit_compat_decision(&decision, &mut stderr);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
    }

    #[test]
    fn run_compat_wraps_into_exit_code() {
        let mut err = Vec::new();
        // ExitCode does not expose its byte; we just exercise the code path.
        let _ = run_compat(b"" as &[u8], &mut err);
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("invalid hook payload"));
    }

    /// `Read` impl that always returns `ErrorKind::Other`. Used to drive
    /// the stdin-read failure arm without spawning a real process or
    /// touching the filesystem.
    struct FailingReader;

    impl std::io::Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("simulated stdin failure"))
        }
    }

    #[test]
    fn run_compat_returns_one_when_stdin_read_fails() {
        let mut stderr = Vec::new();
        let code = run_compat_code(FailingReader, &mut stderr);
        assert_eq!(code, 1);
        assert!(String::from_utf8_lossy(&stderr).contains("failed to read stdin"));
    }
}
