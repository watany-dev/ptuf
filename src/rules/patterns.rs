use crate::facts::shell::Argv;

/// Prefiltered "does this token name a credentials path?" predicate.
///
/// The classifier itself lives in [`crate::facts::sensitive`] — one
/// implementation, one `PROBES` table, shared by the Bash-side rules
/// here and by the file-tool / MCP surfaces. This wrapper exists only
/// so the rule modules read naturally; it adds no matching logic of its
/// own.
pub(super) fn matches_sensitive_path(token: &str) -> bool {
    crate::facts::sensitive::matches(token)
}

/// True when this argv has a token (head, positional/flag arg, or env
/// assignment value) naming a credentials path. Shared by every
/// rule that needs "does this argv mention a credentials path?".
pub(super) fn argv_references_sensitive(argv: &Argv) -> bool {
    if matches_sensitive_path(&argv.head) {
        return true;
    }
    if argv.args.iter().any(|a| matches_sensitive_path(a)) {
        return true;
    }
    argv.env_assignments
        .iter()
        .any(|e| matches_sensitive_path(&e.value))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Token-level classification is `facts::sensitive`'s contract and is
    // covered there. What is this module's own is the argv walk: head,
    // positional args, and env-assignment values all count.
    fn argv_of(cmd: &str) -> Argv {
        crate::facts::shell::parse(cmd)
            .commands()
            .into_iter()
            .next()
            .expect("argv")
            .clone()
    }

    #[test]
    fn argv_references_sensitive_covers_head_args_and_env() {
        for cmd in [
            "id_rsa",
            "cat ~/.aws/credentials",
            "AWS_SHARED_CREDENTIALS_FILE=$HOME/.aws/credentials aws s3 ls",
        ] {
            assert!(argv_references_sensitive(&argv_of(cmd)), "missed {cmd:?}");
        }
    }

    #[test]
    fn argv_references_sensitive_is_quiet_on_safe_commands() {
        for cmd in ["ls -la", "cat README.md", "LANG=C grep foo /tmp/bar"] {
            assert!(
                !argv_references_sensitive(&argv_of(cmd)),
                "false positive on {cmd:?}",
            );
        }
    }
}
