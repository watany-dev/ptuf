//! Audit subsystem.
//!
//! Records every decision the engine emits (subject to the user's
//! `audit.includeAllowed` / `audit.includeDenied` filters) into a
//! JSONL file documented in `docs/design/audit.md`. Sinks are pluggable
//! via the [`AuditSink`] trait so tests can capture records in memory
//! and the production engine can append to disk.

pub mod record;
pub mod redaction;
pub mod time;
pub mod writer;

use std::fs::File;
use std::path::PathBuf;
use std::sync::Mutex;

pub use record::AuditRecord;
pub use redaction::redact_strict;

use writer::WriteError;

/// Sink errors. Both variants reach the engine, which decides whether
/// to demote them to a stderr warning or short-circuit the request
/// (currently the engine always treats them as best-effort warnings —
/// audit failures must not block tool execution).
#[derive(Debug)]
pub enum AuditError {
    /// The sink rejected a record. Wraps the underlying writer error.
    Write(WriteError),
    /// The sink could not be initialised (e.g. opening the JSONL file
    /// failed). The engine surfaces this through stderr and continues
    /// with a [`NoopSink`].
    Open { path: PathBuf, message: String },
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Write(e) => write!(f, "{e}"),
            AuditError::Open { path, message } => {
                write!(f, "audit: open {}: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AuditError::Write(e) => Some(e),
            AuditError::Open { .. } => None,
        }
    }
}

/// Pluggable backend for audit records. Implementors must be cheap to
/// clone-share via `Arc` because the engine holds them behind a
/// trait object for the lifetime of the process.
pub trait AuditSink: Send + Sync {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

/// No-op sink used when audit is disabled.
#[derive(Debug, Default)]
pub struct NoopSink;

impl AuditSink for NoopSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Ok(())
    }
}

/// In-memory sink used by tests. The captured records can be inspected
/// via [`MemorySink::records`].
#[derive(Debug, Default)]
pub struct MemorySink {
    inner: Mutex<Vec<AuditRecord>>,
}

impl MemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the captured records. Returns an empty vec if the
    /// internal mutex was poisoned, to keep callers out of `Result`
    /// boilerplate.
    pub fn records(&self) -> Vec<AuditRecord> {
        match self.inner.lock() {
            Ok(guard) => guard.clone(),
            Err(poison) => poison.into_inner().clone(),
        }
    }
}

impl AuditSink for MemorySink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        if let Ok(mut guard) = self.inner.lock() {
            guard.push(record.clone());
        }
        Ok(())
    }
}

/// JSONL file sink. The file is opened once and reused; concurrent
/// writes from one process serialise behind the [`Mutex`].
pub struct JsonlSink {
    file: Mutex<File>,
}

impl JsonlSink {
    pub fn open(path: &std::path::Path) -> Result<Self, AuditError> {
        let f = writer::open_append(path).map_err(|e| AuditError::Open {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        Ok(Self {
            file: Mutex::new(f),
        })
    }
}

impl AuditSink for JsonlSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        match self.file.lock() {
            Ok(mut guard) => writer::append_record(&mut *guard, record).map_err(AuditError::Write),
            Err(_) => Ok(()),
        }
    }
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
    fn noop_sink_accepts_any_record() {
        let s = NoopSink;
        assert!(s.record(&rec()).is_ok());
    }

    #[test]
    fn memory_sink_captures_records_in_order() {
        let s = MemorySink::new();
        s.record(&rec()).unwrap();
        s.record(&rec()).unwrap();
        let captured = s.records();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].decision, "deny");
    }

    #[test]
    fn jsonl_sink_appends_to_a_real_file() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-audit-mod-{}-{}", std::process::id(), line!()));
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_dir_all(&dir);

        let sink = JsonlSink::open(&path).expect("open");
        sink.record(&rec()).expect("first");
        sink.record(&rec()).expect("second");

        let body = std::fs::read_to_string(&path).expect("read");
        assert_eq!(body.lines().count(), 2);
        assert!(body.contains("\"ruleId\":\"r\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jsonl_sink_open_reports_path_on_failure() {
        // /proc on Linux is read-only; opening for append there fails
        // synchronously and exercises the `AuditError::Open` arm.
        let bad = std::path::PathBuf::from("/proc/this-cannot-be-created/audit.jsonl");
        match JsonlSink::open(&bad) {
            Ok(_) => {} // Some sandboxes happily create paths under /proc.
            Err(AuditError::Open { path, message }) => {
                assert_eq!(path, bad);
                assert!(!message.is_empty());
            }
            Err(other) => panic!("unexpected variant: {other}"),
        }
    }

    #[test]
    fn audit_error_display_covers_both_variants() {
        let open = AuditError::Open {
            path: PathBuf::from("/x"),
            message: "nope".into(),
        };
        assert!(format!("{open}").contains("audit: open /x"));
        let write = AuditError::Write(WriteError::Serialize("bad".into()));
        assert!(format!("{write}").contains("audit serialize error"));
    }

    #[test]
    fn memory_sink_records_handles_poisoned_mutex() {
        use std::sync::Arc;
        let sink = Arc::new(MemorySink::new());
        sink.record(&rec()).unwrap();

        // Poison the mutex by panicking inside a held guard.
        let inner_arc = sink.clone();
        let _ = std::thread::spawn(move || {
            let _guard = inner_arc.inner.lock().unwrap();
            panic!("intentional poison");
        })
        .join();

        // records() must surface the captured row even though the
        // mutex is now poisoned.
        let recs = sink.records();
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn jsonl_sink_record_is_ok_when_mutex_is_poisoned() {
        use std::sync::Arc;
        let dir = std::env::temp_dir().join(format!(
            "ptuf-audit-poison-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("audit.jsonl");

        let sink = Arc::new(JsonlSink::open(&path).expect("open"));

        // Poison the file mutex by panicking inside a held guard.
        let inner = sink.clone();
        let _ = std::thread::spawn(move || {
            let _guard = inner.file.lock().unwrap();
            panic!("intentional poison");
        })
        .join();

        // record() must swallow the poison and return Ok so the engine
        // does not surface audit errors to the agent.
        assert!(sink.record(&rec()).is_ok());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn audit_error_source_visible_via_dyn_error() {
        let write = AuditError::Write(WriteError::Io(std::io::Error::other("boom")));
        let dyn_err: &dyn std::error::Error = &write;
        assert!(dyn_err.source().is_some());
        let open = AuditError::Open {
            path: PathBuf::from("/x"),
            message: "nope".into(),
        };
        let dyn_err: &dyn std::error::Error = &open;
        assert!(dyn_err.source().is_none());
    }
}
