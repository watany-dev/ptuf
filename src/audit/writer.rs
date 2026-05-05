//! JSONL writer used by [`super::JsonlSink`].
//!
//! Serialises one [`AuditRecord`] to a single line, then writes the
//! line in **one** `write_all` call against a file opened with
//! `O_APPEND`. POSIX guarantees a single `write` shorter than
//! `PIPE_BUF` is atomic, so concurrent ptuf processes appending to the
//! same audit file cannot interleave records. Windows lacks the same
//! guarantee — see `docs/design/audit.md` and the README caveat.

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
            WriteError::Io(e) => write!(f, "audit io error: {e}"),
            WriteError::Serialize(m) => write!(f, "audit serialize error: {m}"),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WriteError::Io(e) => Some(e),
            WriteError::Serialize(_) => None,
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
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::Decision;
    use crate::config::Mode;
    use crate::decision::Severity;
    use crate::hook_input::HookInput;
    use serde_json::json;
    use std::time::UNIX_EPOCH;

    fn rec() -> AuditRecord {
        AuditRecord::build(
            UNIX_EPOCH,
            &Decision::Deny {
                rule_id: "r".into(),
                reason: "x".into(),
            },
            Mode::Enforce,
            false,
            &HookInput {
                tool_name: "Bash".into(),
                tool_input: json!({"command": "rm -rf /"}),
            },
            None,
            Some(Severity::Critical),
            "rm -rf /".into(),
            None,
            "claude-code",
            Vec::new(),
        )
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
        let dir = std::env::temp_dir().join(format!(
            "ptuf-audit-writer-{}-{}",
            std::process::id(),
            line!()
        ));
        let nested = dir.join("nested/deep/audit.jsonl");
        let _ = std::fs::remove_dir_all(&dir);
        let mut f = open_append(&nested).expect("open");
        append_record(&mut f, &rec()).expect("write");
        let body = std::fs::read_to_string(&nested).expect("read");
        assert!(body.contains("\"decision\":\"deny\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_append_with_no_parent_works_for_bare_filename() {
        // PathBuf::parent() of a single-component path returns Some("")
        // — exercise the early-return branch in open_append.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ptuf-audit-bare-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut f = open_append(&path).expect("open");
        append_record(&mut f, &rec()).expect("write");
        let _ = std::fs::remove_file(&path);
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
}
