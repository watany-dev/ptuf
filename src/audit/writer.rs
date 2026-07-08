//! JSONL writer used by [`super::JsonlSink`].
//!
//! Serialises one [`AuditRecord`] to a single line and appends it to
//! a file opened with `O_APPEND`. Cross-process atomicity is
//! guaranteed by the caller: `JsonlSink::record` takes an OS-level
//! advisory lock (`flock(2)` on Unix, `LockFileEx` on Windows) around
//! the write so concurrent ptuf processes cannot interleave records
//! even when a record exceeds a page or `write_all` has to loop on
//! partial writes.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use super::record::AuditRecord;

/// Errors raised while opening or writing the JSONL file. Both
/// variants surface the offending path so the caller can decide
/// whether to fail the request or only emit a stderr warning.
#[derive(Debug)]
pub enum WriteError {
    Io(io::Error),
    Serialize(String),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "audit io error: {e}"),
            Self::Serialize(m) => write!(f, "audit serialize error: {m}"),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Serialize(_) => None,
        }
    }
}

/// Open `path` for append, creating it (and any missing parent
/// directories) if needed.
pub fn open_append(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new().create(true).append(true).open(path)
}

/// Encode one record as a JSON line and append it to `dst`. The
/// newline is appended to the JSON before the single `write_all` call
/// so the line and its terminator hit the underlying file together.
pub fn append_record<W: Write>(dst: &mut W, record: &AuditRecord) -> Result<(), WriteError> {
    let mut line =
        serde_json::to_string(record).map_err(|e| WriteError::Serialize(e.to_string()))?;
    line.push('\n');
    dst.write_all(line.as_bytes()).map_err(WriteError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::time::UNIX_EPOCH;

    fn rec() -> AuditRecord {
        crate::audit::record::test_deny_record("rm -rf /")
    }

    #[test]
    fn append_record_writes_one_line_terminated_with_newline() {
        let mut buf = Vec::new();
        append_record(&mut buf, &rec()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.ends_with('\n'));
        assert_eq!(s.matches('\n').count(), 1);
        assert!(s.contains("\"decision\":\"deny\""));
    }

    #[test]
    fn open_append_creates_missing_parent_dirs() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let nested = dir.path().join("nested/deep/audit.jsonl");
        let mut f = open_append(&nested).expect("open");
        append_record(&mut f, &rec()).expect("write");
        let body = std::fs::read_to_string(&nested).expect("read");
        assert!(body.contains("\"decision\":\"deny\""));
    }

    #[test]
    fn open_append_works_when_parent_already_exists() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let mut f = open_append(&path).expect("open");
        append_record(&mut f, &rec()).expect("write");
    }

    #[test]
    fn write_error_display_covers_both_variants() {
        let io_err = WriteError::Io(io::Error::other("nope"));
        let ser_err = WriteError::Serialize("bad".into());
        assert!(format!("{io_err}").contains("audit io error"));
        assert!(format!("{ser_err}").contains("audit serialize error"));
    }

    #[test]
    fn write_error_source_matches_variant() {
        let io_err = WriteError::Io(io::Error::other("nope"));
        let ser_err = WriteError::Serialize("bad".into());
        let dyn_err: &dyn std::error::Error = &io_err;
        assert!(dyn_err.source().is_some());
        let dyn_err: &dyn std::error::Error = &ser_err;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn open_append_returns_io_error_when_parent_is_a_regular_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let blocker = dir.path().join("audit-not-a-dir");
        std::fs::write(&blocker, b"x").expect("write blocker");
        let path = blocker.join("audit.jsonl");
        open_append(&path).expect_err("expected io error");
    }

    #[test]
    fn open_append_returns_io_error_for_empty_path() {
        open_append(Path::new("")).expect_err("expected io error");
    }

    // Skipped under root because root bypasses the POSIX permission
    // check, which would yield a false negative.
    #[cfg(unix)]
    #[test]
    fn open_append_returns_permission_denied_for_unwritable_parent() {
        use std::os::unix::fs::PermissionsExt;

        if euid_is_root() {
            return;
        }

        let dir = tempfile::TempDir::new().expect("tempdir");
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).expect("mkdir");
        let mut perms = std::fs::metadata(&locked).expect("meta").permissions();
        perms.set_mode(0o444); // r--r--r--, no write/exec.
        std::fs::set_permissions(&locked, perms.clone()).expect("chmod 0444");

        let path = locked.join("audit.jsonl");
        let result = open_append(&path);

        // Restore permissions so TempDir can clean up.
        let mut restore = perms;
        restore.set_mode(0o755);
        let _ = std::fs::set_permissions(&locked, restore);

        let err = result.expect_err("expected permission denied");
        assert_eq!(
            err.kind(),
            io::ErrorKind::PermissionDenied,
            "unexpected error: {err:?}",
        );
    }

    // `id -u` avoids touching `unsafe` (the crate forbids it); on
    // systems without `id` we conservatively return false.
    #[cfg(unix)]
    fn euid_is_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u32>().ok())
            == Some(0)
    }

    use proptest::prelude::*;

    fn command_redacted() -> impl Strategy<Value = String> {
        prop_oneof![
            crate::testing::proptest::arbitrary_command(),
            "[ -~\n\t\r]{0,48}",
        ]
    }

    // Arbitrary audit records, including ones whose redacted command
    // carries raw newlines / control bytes.
    fn audit_record() -> impl Strategy<Value = AuditRecord> {
        use crate::testing::proptest::{decision, mode, richer_hook_input, severity};
        (
            0u64..4_000_000_000,
            decision(),
            mode(),
            any::<bool>(),
            richer_hook_input(),
            proptest::option::of(severity()),
            command_redacted(),
            proptest::option::of("[A-Za-z0-9-]{0,16}"),
            proptest::collection::vec("[a-z0-9.@/-]{0,20}", 0..4),
        )
            .prop_map(
                |(secs, decision, mode, demoted, input, severity, cmd, allow, plugins)| {
                    AuditRecord::builder(&decision, &input, cmd)
                        .timestamp(UNIX_EPOCH + std::time::Duration::from_secs(secs))
                        .mode(mode)
                        .mode_demoted(demoted)
                        .severity(severity)
                        .allowlist_id(allow)
                        .agent("claude-code")
                        .plugin_versions(plugins)
                        .build()
                },
            )
    }

    proptest! {
        // `append_record` emits exactly one line: the output ends with a
        // single `\n`, and the JSON body before it holds no raw newline
        // even when the record carries newline-laden fields (serde
        // escapes them into `\n` escape sequences).
        #[test]
        fn pbt_append_record_emits_one_terminated_line(record in audit_record()) {
            let mut buf = Vec::new();
            append_record(&mut buf, &record).expect("append");
            let text = String::from_utf8(buf).expect("utf8");
            prop_assert!(text.ends_with('\n'));
            prop_assert_eq!(text.matches('\n').count(), 1);
            let body = &text[..text.len() - 1];
            prop_assert!(!body.contains('\n'));
        }

        // The line body always parses back as a JSON object.
        #[test]
        fn pbt_append_record_body_is_valid_json(record in audit_record()) {
            let mut buf = Vec::new();
            append_record(&mut buf, &record).expect("append");
            let text = String::from_utf8(buf).expect("utf8");
            let body = text.strip_suffix('\n').expect("newline-terminated");
            let value = serde_json::from_str::<serde_json::Value>(body)
                .expect("valid JSON");
            prop_assert!(value.is_object());
        }
    }
}
