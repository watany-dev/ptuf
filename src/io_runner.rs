use std::io::{Read, Write};
use std::process::ExitCode;

use crate::cli;

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn run_with_no_args_reports_missing_subcommand() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let args: Vec<&str> = vec![];
        let _exit = run(&args, b"" as &[u8], &mut out, &mut err);
        let err_s = String::from_utf8_lossy(&err);
        assert!(err_s.contains("missing value for subcommand"), "{err_s}");
    }
}
