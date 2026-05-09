//! `ptuf init <agent>` — install ptuf as a `PreToolUse` hook in the
//! target agent's settings file(s).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::cli::HookAgent;

pub mod claude_code;
pub mod codex;
pub mod copilot;
pub mod kiro;
pub mod verify;

/// Auto-detect every agent reachable from the given `cwd` and `$HOME`.
///
/// - `ClaudeCode`: requires `$HOME/.claude/` to exist.
/// - `Codex`: `<repo>/.codex/` or `$HOME/.codex/`.
/// - `Copilot`: `<repo>/.github/`.
/// - `Kiro`: `<repo>/.kiro/` or `$HOME/.kiro/`.
///
/// Returns agents in a stable order so callers can install / report
/// deterministically.
pub fn detect_agents(cwd: Option<&Path>) -> Vec<HookAgent> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let repo = cwd.and_then(crate::config::repo::discover);
    let mut found = Vec::new();
    if home.as_ref().is_some_and(|h| h.join(".claude").is_dir()) {
        found.push(HookAgent::ClaudeCode);
    }
    if repo.as_ref().is_some_and(|r| r.join(".codex").is_dir())
        || home.as_ref().is_some_and(|h| h.join(".codex").is_dir())
    {
        found.push(HookAgent::Codex);
    }
    if repo.as_ref().is_some_and(|r| r.join(".github").is_dir()) {
        found.push(HookAgent::Copilot);
    }
    if repo.as_ref().is_some_and(|r| r.join(".kiro").is_dir())
        || home.as_ref().is_some_and(|h| h.join(".kiro").is_dir())
    {
        found.push(HookAgent::Kiro);
    }
    found
}

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
            },
            Self::Json { path, message } => {
                write!(f, "invalid JSON in {}: {message}", path.display())
            },
            Self::Toml { path, message } => {
                write!(f, "invalid TOML in {}: {message}", path.display())
            },
            Self::Schema { path, message } => {
                write!(
                    f,
                    "unexpected settings shape in {}: {message}",
                    path.display()
                )
            },
            Self::HomeNotSet => write!(
                f,
                "$HOME is not set; ptuf init needs HOME to locate the agent's settings file"
            ),
            Self::RepoRootNotFound => write!(
                f,
                "could not discover a repository root; run ptuf init from inside a git working tree"
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
            },
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
    let mut name = path.file_name().map_or_else(
        || std::ffi::OsString::from("snapshot.tmp"),
        std::ffi::OsStr::to_os_string,
    );
    name.push(format!(".ptuf-snap.{}.tmp", std::process::id()));
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {

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

    #[test]
    fn write_atomically_returns_io_error_when_parent_is_a_regular_file() {
        // Wedge `create_dir_all` into failure by giving the target a
        // parent that is itself a regular file.
        let dir = workdir("atomic-parent-is-file");
        let blocker = dir.join("blocker");
        fs::write(&blocker, b"i am a file").expect("write blocker");
        let target = blocker.join("nested").join("file.json");

        let err = write_atomically(&target, b"hello").expect_err("must fail");
        match err {
            InitError::Io { source, .. } => {
                // Some platforms surface NotADirectory, others NotFound; both are fine.
                let kind = source.kind();
                assert!(
                    kind == ErrorKind::NotADirectory
                        || kind == ErrorKind::AlreadyExists
                        || kind == ErrorKind::NotFound
                        || kind == ErrorKind::Other,
                    "unexpected error kind: {kind:?}",
                );
            },
            other => panic!("expected Io error, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_propagates_first_error_when_atomic_write_fails() {
        // Snapshot says the file existed (Some(...)), but the real
        // filesystem now has a regular file where the parent directory
        // should be — the restore can't write through it.
        let dir = workdir("restore-error");
        let blocker = dir.join("blocker");
        fs::write(&blocker, b"blocker").expect("write blocker");
        let bad_path = blocker.join("nested").join("settings.json");
        let good_path = dir.join("good.json");
        fs::write(&good_path, b"polluted").expect("write good");

        let snaps = vec![
            PathSnapshot {
                path: bad_path.clone(),
                previous: Some(b"original".to_vec()),
            },
            PathSnapshot {
                path: good_path.clone(),
                previous: Some(b"good-original".to_vec()),
            },
        ];
        let err = restore(&snaps).expect_err("must surface error");
        assert!(matches!(err, InitError::Io { .. }));
        // Second snapshot is restored even though the first failed.
        assert_eq!(fs::read(&good_path).unwrap(), b"good-original");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_one_propagates_remove_file_error_when_path_is_a_directory() {
        let dir = workdir("restore-remove-dir");
        let blocker = dir.join("not-a-file");
        fs::create_dir_all(&blocker).expect("mkdir blocker");

        let snaps = vec![PathSnapshot {
            path: blocker.clone(),
            previous: None,
        }];
        let err = restore(&snaps).expect_err("remove_file on a dir must fail");
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomically_propagates_rename_error_when_target_is_a_directory() {
        let dir = workdir("atomic-rename-dir");
        let target = dir.join("target");
        fs::create_dir_all(&target).expect("mkdir target");

        let err = write_atomically(&target, b"hello").expect_err("rename onto dir must fail");
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomically_propagates_write_error_when_temp_path_is_a_directory() {
        let dir = workdir("atomic-write-collision");
        let target = dir.join("target.json");
        let collision = dir.join(format!("target.json.ptuf-snap.{}.tmp", std::process::id()));
        fs::create_dir_all(&collision).expect("mkdir collision");

        let err = write_atomically(&target, b"hello").expect_err("write onto dir must fail");
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sibling_temp_path_falls_back_when_path_has_no_parent() {
        // Bare filename: no parent and a usable file_name; we must get
        // a path back (in the cwd) with the snapshot suffix appended.
        let p = Path::new("just-a-name.json");
        let tmp = sibling_temp_path(p);
        let s = tmp.to_string_lossy();
        assert!(s.starts_with("just-a-name.json"), "got {s}");
        assert!(s.contains(".ptuf-snap."), "got {s}");
        assert!(
            tmp.parent()
                .map(|p| p.as_os_str().is_empty())
                .unwrap_or(true)
        );
    }
}
