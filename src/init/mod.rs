//! `ptuf init <agent>` — install ptuf as a `PreToolUse` hook in the
//! target agent's settings file(s).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

pub mod claude_code;
pub mod codex;
pub mod verify;

/// Errors surfaced by every `init` adapter.
#[derive(Debug)]
pub enum InitError {
    /// Agent name not recognised.
    UnknownAgent(String),
    /// Settings file or its parent directory could not be read / written.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Existing settings file is not valid JSON; refuse to overwrite.
    Json { path: PathBuf, message: String },
    /// Existing config file is not valid TOML; refuse to overwrite.
    Toml { path: PathBuf, message: String },
    /// Settings file is JSON but the path we expected to navigate
    /// (`hooks.PreToolUse[]`) is occupied by a value of the wrong type.
    Schema { path: PathBuf, message: String },
    /// `$HOME` is unset and no explicit `--settings` path was given.
    HomeNotSet,
    /// No repository root could be discovered and the caller did not
    /// provide enough explicit Codex target paths to proceed.
    RepoRootNotFound,
}

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAgent(a) => write!(f, "unknown agent: {a}"),
            Self::Io { path, source } => {
                write!(f, "io error at {}: {source}", path.display())
            }
            Self::Json { path, message } => {
                write!(f, "invalid JSON in {}: {message}", path.display())
            }
            Self::Toml { path, message } => {
                write!(f, "invalid TOML in {}: {message}", path.display())
            }
            Self::Schema { path, message } => {
                write!(
                    f,
                    "unexpected settings shape in {}: {message}",
                    path.display()
                )
            }
            Self::HomeNotSet => write!(f, "$HOME is not set; pass --settings <PATH> explicitly"),
            Self::RepoRootNotFound => write!(
                f,
                "could not discover a repository root; pass --root <PATH> or explicit --hooks/--config paths"
            ),
        }
    }
}

impl std::error::Error for InitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Outcome of an install attempt. Identical for dry-run and live runs;
/// the `dry_run` flag passed in determines whether [`InstallStatus`]
/// uses the `Would*` variants.
#[derive(Debug, PartialEq, Eq)]
pub struct InstallOutcome {
    pub status: InstallStatus,
    pub agent: &'static str,
    pub paths: Vec<InstallPath>,
    pub matcher: String,
    pub command: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct InstallPath {
    pub label: &'static str,
    pub path: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InstallStatus {
    /// File already contains a hook entry pointing at our binary; no
    /// change required.
    AlreadyPresent,
    /// Wrote a new entry to disk.
    Installed,
    /// `--dry-run`: an entry would have been written.
    WouldInstall,
}

/// Pre-install snapshot of a single target file. `previous = None`
/// means the file did not exist when the snapshot was captured, so a
/// rollback should remove the file rather than overwrite it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PathSnapshot {
    pub path: PathBuf,
    pub previous: Option<Vec<u8>>,
}

/// Read every `path` into memory so that a later [`restore`] can put
/// the target tree back exactly as it was. Permission errors (or any
/// other [`std::io::Error`] aside from `NotFound`) propagate as
/// [`InitError::Io`].
pub(crate) fn capture(paths: &[&Path]) -> Result<Vec<PathSnapshot>, InitError> {
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let previous = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => {
                return Err(InitError::Io {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        };
        out.push(PathSnapshot {
            path: path.to_path_buf(),
            previous,
        });
    }
    Ok(out)
}

/// Best-effort rollback. Each path is restored independently so a
/// single failure does not leave later snapshots un-restored; the
/// first error encountered is returned at the end while the remaining
/// snapshots are still attempted. Writes go through a temp + rename
/// so a crash mid-restore cannot leave a half-written file.
pub(crate) fn restore(snapshots: &[PathSnapshot]) -> Result<(), InitError> {
    let mut first_err: Option<InitError> = None;
    for snap in snapshots {
        if let Err(e) = restore_one(snap)
            && first_err.is_none()
        {
            first_err = Some(e);
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn restore_one(snap: &PathSnapshot) -> Result<(), InitError> {
    match &snap.previous {
        None => match fs::remove_file(&snap.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(InitError::Io {
                path: snap.path.clone(),
                source: e,
            }),
        },
        Some(bytes) => write_atomically(&snap.path, bytes),
    }
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), InitError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| InitError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let tmp = sibling_temp_path(path);
    fs::write(&tmp, bytes).map_err(|e| InitError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| InitError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

fn sibling_temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("snapshot.tmp"));
    name.push(format!(".ptuf-snap.{}.tmp", std::process::id()));
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn init_error_display_covers_all_variants() {
        assert!(format!("{}", InitError::UnknownAgent("x".into())).contains("unknown agent"));
        assert!(
            format!(
                "{}",
                InitError::Io {
                    path: PathBuf::from("/p"),
                    source: std::io::Error::other("boom")
                }
            )
            .contains("io error")
        );
        assert!(
            format!(
                "{}",
                InitError::Json {
                    path: PathBuf::from("/p"),
                    message: "bad".into()
                }
            )
            .contains("invalid JSON")
        );
        assert!(
            format!(
                "{}",
                InitError::Toml {
                    path: PathBuf::from("/p"),
                    message: "bad".into()
                }
            )
            .contains("invalid TOML")
        );
        assert!(
            format!(
                "{}",
                InitError::Schema {
                    path: PathBuf::from("/p"),
                    message: "wrong type".into()
                }
            )
            .contains("unexpected settings shape")
        );
        assert!(format!("{}", InitError::HomeNotSet).contains("HOME"));
        assert!(format!("{}", InitError::RepoRootNotFound).contains("repository root"));
    }

    #[test]
    fn init_error_source_exposes_io_only() {
        let err = InitError::Io {
            path: PathBuf::from("/p"),
            source: std::io::Error::other("x"),
        };
        assert!(std::error::Error::source(&err).is_some());
        assert!(std::error::Error::source(&InitError::HomeNotSet).is_none());
    }

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-init-snap-{}-{}-{}",
            tag,
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn capture_records_existing_and_missing_files() {
        let dir = workdir("capture");
        let exists = dir.join("a.json");
        let missing = dir.join("b.json");
        fs::write(&exists, b"hello").expect("write a");

        let snaps = capture(&[exists.as_path(), missing.as_path()]).expect("capture");
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].path, exists);
        assert_eq!(snaps[0].previous.as_deref(), Some(b"hello".as_slice()));
        assert_eq!(snaps[1].path, missing);
        assert!(snaps[1].previous.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_recreates_original_contents() {
        let dir = workdir("restore-existing");
        let path = dir.join("a.json");
        fs::write(&path, b"original").expect("write");
        let snaps = capture(&[path.as_path()]).expect("capture");

        fs::write(&path, b"polluted").expect("overwrite");
        restore(&snaps).expect("restore");
        assert_eq!(fs::read(&path).unwrap(), b"original");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_removes_files_that_did_not_exist_before() {
        let dir = workdir("restore-missing");
        let path = dir.join("a.json");
        let snaps = capture(&[path.as_path()]).expect("capture");
        assert!(snaps[0].previous.is_none());

        fs::write(&path, b"new content").expect("write new");
        restore(&snaps).expect("restore");
        assert!(!path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_is_idempotent_when_target_already_absent() {
        let dir = workdir("restore-noop");
        let path = dir.join("never-existed.json");
        let snaps = capture(&[path.as_path()]).expect("capture");
        // File never created; restore should be a successful no-op.
        restore(&snaps).expect("restore noop");
        assert!(!path.exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
