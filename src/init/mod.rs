//! `ptuf init <agent>` — install ptuf as a `PreToolUse` hook in the
//! target agent's settings file(s).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::cli::HookAgent;

pub mod claude_code;
pub mod cline;
pub mod codex;
pub mod copilot;
pub mod cursor;
pub mod kiro;
pub mod pi;
pub mod verify;

/// Return the first whitespace-delimited token of `cmd`, which is the
/// executable path/name. Used by path-collection callers to extract the
/// binary from a full hook command string.
pub(crate) fn command_executable(cmd: &str) -> Option<&str> {
    cmd.split_whitespace().next()
}

/// Auto-detect every agent reachable from the given `cwd` and `home`.
///
/// - `ClaudeCode`: requires `<home>/.claude/` to exist.
/// - `Codex`: `<repo>/.codex/` or `<home>/.codex/`.
/// - `Copilot`: `<repo>/.github/`.
/// - `Kiro`: `<repo>/.kiro/` or `<home>/.kiro/`.
/// - `Cline`: `<repo>/.clinerules/` or `<repo>/.cline/`, or
///   `<home>/Documents/Cline/` or `<home>/.cline/`.
/// - `Cursor`: `<repo>/.cursor/` or `<home>/.cursor/`.
///
/// Returns agents in a stable order so callers can install / report
/// deterministically. Production callers pass `std::env::var_os("HOME")`
/// for `home`; tests inject deterministic paths.
pub fn detect_agents(cwd: Option<&Path>, home: Option<&Path>) -> Vec<HookAgent> {
    let repo = cwd.and_then(crate::config::repo::discover);
    let mut found = Vec::new();
    if home.is_some_and(|h| h.join(".claude").is_dir()) {
        found.push(HookAgent::ClaudeCode);
    }
    if repo.as_deref().is_some_and(|r| r.join(".codex").is_dir())
        || home.is_some_and(|h| h.join(".codex").is_dir())
    {
        found.push(HookAgent::Codex);
    }
    if repo.as_deref().is_some_and(|r| r.join(".github").is_dir()) {
        found.push(HookAgent::Copilot);
    }
    if repo.as_deref().is_some_and(|r| r.join(".kiro").is_dir())
        || home.is_some_and(|h| h.join(".kiro").is_dir())
    {
        found.push(HookAgent::Kiro);
    }
    if repo
        .as_deref()
        .is_some_and(|r| r.join(".clinerules").is_dir() || r.join(".cline").is_dir())
        || home.is_some_and(|h| h.join("Documents/Cline").is_dir() || h.join(".cline").is_dir())
    {
        found.push(HookAgent::Cline);
    }
    if repo.as_deref().is_some_and(|r| r.join(".cursor").is_dir())
        || home.is_some_and(|h| h.join(".cursor").is_dir())
    {
        found.push(HookAgent::Cursor);
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
    /// A host hook file already exists at `path` but ptuf did not write
    /// it, so overwriting it would clobber the user's own hook.
    HookFileConflict { path: PathBuf },
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
            Self::HookFileConflict { path } => write!(
                f,
                "existing Cline PreToolUse hook is not managed by ptuf: {}; move or remove it, then re-run ptuf init cline",
                path.display()
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

/// Adapter-specific install reporting carried back to the CLI
/// dispatcher and renderer. `kiro` is populated only by the Kiro
/// adapter, whose default mode patches an unbounded set of agent JSON
/// files. Other adapters install into a single fixed file and have no
/// per-file breakdown to surface. Kept `pub(crate)` so it does not
/// inflate the lib crate's public surface — embedded `kiro::install`
/// callers receive only the bare [`InstallOutcome`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AdapterRunReport {
    pub outcome: InstallOutcome,
    pub kiro: Option<kiro::KiroInstallExtras>,
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
    write_secure(&tmp, bytes).map_err(|e| InitError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| InitError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Create `tmp` with mode 0600 on Unix and write `bytes` to it. Used by
/// every host adapter so freshly installed `settings.json` / `hooks.json`
/// / `config.toml` files are not world-readable on shared hosts.
///
/// Falls back to `fs::write` on non-Unix where mode bits don't apply
/// (NTFS ACLs are inherited from the parent directory).
///
/// `create_new` is used so a stale tmp from a previous run can't smuggle
/// in a looser mode; if one is present we drop it once and retry — same-
/// pid collisions are possible in tests that re-enter `install` rapidly.
#[cfg(unix)]
pub(crate) fn write_secure(tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let open = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp)
    };
    let mut file = match open() {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(tmp)?;
            open()?
        },
        Err(e) => return Err(e),
    };
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn write_secure(tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(tmp, bytes)
}

/// Like [`write_secure`], but creates `tmp` with mode 0700 so the file
/// is owner-only *executable* — used by the Cline adapter, whose hook is
/// a wrapper script the host runs directly rather than a config entry.
///
/// On non-Unix the mode bits don't apply; NTFS ACLs are inherited from
/// the parent directory just as with [`write_secure`].
#[cfg(unix)]
pub(crate) fn write_executable(tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let open = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(tmp)
    };
    let mut file = match open() {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(tmp)?;
            open()?
        },
        Err(e) => return Err(e),
    };
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn write_executable(tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(tmp, bytes)
}

/// True iff the trailing whitespace-delimited tokens of `cmd` equal
/// `tail`. Each adapter wraps this with its own `COMMAND_TAIL`
/// (e.g. `&["hook", "claude-code"]`) to recognise hook entries that
/// already invoke `ptuf hook <adapter>`.
pub(crate) fn command_invokes_ptuf_hook(cmd: &str, tail: &[&str]) -> bool {
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let n = tokens.len();
    if n < tail.len() {
        return false;
    }
    tokens[n - tail.len()..] == *tail
}

/// Shared backing for every adapter's `detect_binary`: prefer
/// `std::env::current_exe()` so the rendered hook command points at
/// the same binary that ran `ptuf init`, falling back to the literal
/// `"ptuf"` so the entry remains useful when `current_exe` is
/// unavailable (e.g. a CI container without a stable absolute path).
pub(crate) fn detect_binary_impl() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| "ptuf".to_string())
}

/// Sibling temp path for adapter install writes:
/// `<dir>/<file_name>.ptuf.{pid}.tmp`, or
/// `<dir>/<default_name>.ptuf.{pid}.tmp` when `path` has no file name.
///
/// Distinct from [`sibling_temp_path`] (snapshot variant, `.ptuf-snap.`)
/// so an install write and a snapshot write on the same destination
/// cannot collide on temp file names.
pub(crate) fn sibling_install_tmp_path(path: &Path, default_name: &str) -> PathBuf {
    let mut name = path.file_name().map_or_else(
        || std::ffi::OsString::from(default_name),
        std::ffi::OsStr::to_os_string,
    );
    name.push(format!(".ptuf.{}.tmp", std::process::id()));
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
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
        assert!(
            format!(
                "{}",
                InitError::HookFileConflict {
                    path: PathBuf::from("/p/PreToolUse")
                }
            )
            .contains("not managed by ptuf")
        );
        let io_err = InitError::Io {
            path: PathBuf::from("/p"),
            source: std::io::Error::other("x"),
        };
        assert!(std::error::Error::source(&io_err).is_some());
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
    fn command_invokes_ptuf_hook_matches_trailing_tokens_against_arbitrary_tail() {
        let tail: &[&str] = &["hook", "demo"];
        assert!(command_invokes_ptuf_hook("ptuf hook demo", tail));
        assert!(command_invokes_ptuf_hook("/usr/bin/ptuf hook demo", tail));
        assert!(!command_invokes_ptuf_hook("ptuf hook other", tail));
        assert!(!command_invokes_ptuf_hook("hook", tail));
        assert!(!command_invokes_ptuf_hook("", tail));
    }

    #[test]
    fn command_executable_returns_first_token_or_none() {
        assert_eq!(command_executable("/x/ptuf hook"), Some("/x/ptuf"));
        assert_eq!(command_executable("/x/ptuf hook codex"), Some("/x/ptuf"));
        assert_eq!(command_executable(""), None);
    }

    #[test]
    fn detect_binary_impl_returns_a_non_empty_string() {
        // Every adapter's `detect_binary` delegates here; a non-empty
        // string is the contract the host config writers depend on.
        assert!(!detect_binary_impl().is_empty());
    }

    #[test]
    fn sibling_install_tmp_path_falls_back_to_bare_filename_when_no_parent() {
        // Bare input filename: helper must keep the file_name and emit a
        // sibling tmp with the install `.ptuf.` infix (NOT `.ptuf-snap.`),
        // and the result must have no parent directory.
        let tmp = sibling_install_tmp_path(Path::new("hooks.json"), "fallback");
        assert!(
            tmp.parent()
                .map(Path::as_os_str)
                .unwrap_or_default()
                .is_empty(),
            "no-parent input must yield no-parent temp path: {tmp:?}",
        );
        let s = tmp.to_string_lossy();
        assert!(s.starts_with("hooks.json.ptuf."), "got {s}");
        assert!(
            !s.contains(".ptuf-snap."),
            "must not collide with snap suffix: {s}"
        );
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

    #[test]
    fn sibling_temp_path_uses_snapshot_tmp_when_path_has_no_file_name() {
        // Paths like ".." have no file_name(); the fallback must produce
        // a path containing "snapshot.tmp" so the caller still gets a
        // usable temp file name.
        let p = Path::new("..");
        let tmp = sibling_temp_path(p);
        let s = tmp.to_string_lossy();
        assert!(s.contains("snapshot.tmp"), "got {s}");
    }

    #[cfg(unix)]
    #[test]
    fn write_secure_surfaces_non_already_exists_open_errors() {
        use std::io::ErrorKind;
        let dir = workdir("write-secure-open-fail");
        let blocker = dir.join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let tmp = blocker.join("child.tmp");
        let err = write_secure(&tmp, b"x").expect_err("open on file parent must fail");
        assert_ne!(err.kind(), ErrorKind::AlreadyExists);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_executable_surfaces_non_already_exists_open_errors() {
        use std::io::ErrorKind;
        let dir = workdir("write-exec-open-fail");
        let blocker = dir.join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let tmp = blocker.join("child.tmp");
        let err = write_executable(&tmp, b"x").expect_err("open on file parent must fail");
        assert_ne!(err.kind(), ErrorKind::AlreadyExists);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_secure_retries_when_temp_path_already_exists_as_file() {
        // `write_secure` opens the temp path with `create_new`, so a
        // stale file from a prior crashed run would block the second
        // call. The `AlreadyExists` arm must remove the stale file and
        // retry; this test pins that retry path.
        let dir = workdir("write-secure-retry");
        let tmp = dir.join("payload.tmp");
        fs::write(&tmp, b"stale").expect("seed stale tmp");

        write_secure(&tmp, b"fresh").expect("retry must succeed");
        assert_eq!(fs::read(&tmp).unwrap(), b"fresh");

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_executable_retries_when_temp_path_already_exists_as_file() {
        // Mirror of the `write_secure` retry test for the 0700 variant
        // used by the Cline adapter's wrapper-script installer.
        let dir = workdir("write-exec-retry");
        let tmp = dir.join("payload.tmp");
        fs::write(&tmp, b"stale").expect("seed stale tmp");

        write_executable(&tmp, b"fresh").expect("retry must succeed");
        assert_eq!(fs::read(&tmp).unwrap(), b"fresh");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn capture_propagates_io_error_when_path_is_a_directory() {
        let dir = workdir("capture-dir-as-file");
        let blocker = dir.join("blocker");
        fs::create_dir_all(&blocker).expect("mkdir blocker");
        let err = capture(&[blocker.as_path()]).expect_err("reading a dir must fail");
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_agents_returns_empty_when_no_paths_exist() {
        let dir = workdir("detect-empty");
        let home = dir.join("home");
        fs::create_dir_all(&home).expect("mkdir home");
        // cwd has no .git → repo discover returns None.
        assert!(detect_agents(Some(dir.as_path()), Some(home.as_path())).is_empty());
        // Also covers the home=None branch.
        assert!(detect_agents(Some(dir.as_path()), None).is_empty());
        // And cwd=None.
        assert!(detect_agents(None, Some(home.as_path())).is_empty());
    }

    #[test]
    fn detect_agents_finds_claude_when_only_home_dotclaude_exists() {
        let dir = workdir("detect-claude");
        let home = dir.join("home");
        fs::create_dir_all(home.join(".claude")).expect("mkdir home/.claude");
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(found, vec![HookAgent::ClaudeCode]);
    }

    #[test]
    fn detect_agents_finds_codex_via_repo_only() {
        let dir = workdir("detect-codex-repo");
        fs::create_dir_all(dir.join(".git")).expect("mkdir .git");
        fs::create_dir_all(dir.join(".codex")).expect("mkdir .codex");
        let home = dir.join("home");
        fs::create_dir_all(&home).expect("mkdir home");
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(found, vec![HookAgent::Codex]);
    }

    #[test]
    fn detect_agents_finds_codex_via_home_only() {
        let dir = workdir("detect-codex-home");
        let home = dir.join("home");
        fs::create_dir_all(home.join(".codex")).expect("mkdir home/.codex");
        // cwd has no .git, no .codex.
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(found, vec![HookAgent::Codex]);
    }

    #[test]
    fn detect_agents_finds_copilot_via_repo_dotgithub() {
        let dir = workdir("detect-copilot");
        fs::create_dir_all(dir.join(".git")).expect("mkdir .git");
        fs::create_dir_all(dir.join(".github")).expect("mkdir .github");
        let home = dir.join("home");
        fs::create_dir_all(&home).expect("mkdir home");
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(found, vec![HookAgent::Copilot]);
    }

    #[test]
    fn detect_agents_finds_kiro_via_repo_only() {
        let dir = workdir("detect-kiro-repo");
        fs::create_dir_all(dir.join(".git")).expect("mkdir .git");
        fs::create_dir_all(dir.join(".kiro")).expect("mkdir .kiro");
        let home = dir.join("home");
        fs::create_dir_all(&home).expect("mkdir home");
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(found, vec![HookAgent::Kiro]);
    }

    #[test]
    fn detect_agents_finds_kiro_via_home_only() {
        let dir = workdir("detect-kiro-home");
        let home = dir.join("home");
        fs::create_dir_all(home.join(".kiro")).expect("mkdir home/.kiro");
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(found, vec![HookAgent::Kiro]);
    }

    #[test]
    fn detect_agents_finds_cline_via_repo_clinerules() {
        let dir = workdir("detect-cline-repo");
        fs::create_dir_all(dir.join(".git")).expect("mkdir .git");
        fs::create_dir_all(dir.join(".clinerules")).expect("mkdir .clinerules");
        let home = dir.join("home");
        fs::create_dir_all(&home).expect("mkdir home");
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(found, vec![HookAgent::Cline]);
    }

    #[test]
    fn detect_agents_finds_cline_via_home_documents_cline() {
        let dir = workdir("detect-cline-home");
        let home = dir.join("home");
        fs::create_dir_all(home.join("Documents/Cline")).expect("mkdir home/Documents/Cline");
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(found, vec![HookAgent::Cline]);
    }

    #[test]
    fn detect_agents_finds_cursor_via_repo_only() {
        let dir = workdir("detect-cursor-repo");
        fs::create_dir_all(dir.join(".git")).expect("mkdir .git");
        fs::create_dir_all(dir.join(".cursor")).expect("mkdir .cursor");
        let home = dir.join("home");
        fs::create_dir_all(&home).expect("mkdir home");
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(found, vec![HookAgent::Cursor]);
    }

    #[test]
    fn detect_agents_finds_cursor_via_home_only() {
        let dir = workdir("detect-cursor-home");
        let home = dir.join("home");
        fs::create_dir_all(home.join(".cursor")).expect("mkdir home/.cursor");
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(found, vec![HookAgent::Cursor]);
    }

    #[test]
    fn detect_agents_returns_all_six_in_stable_order() {
        let dir = workdir("detect-all");
        fs::create_dir_all(dir.join(".git")).expect("mkdir .git");
        fs::create_dir_all(dir.join(".codex")).expect("mkdir .codex");
        fs::create_dir_all(dir.join(".github")).expect("mkdir .github");
        fs::create_dir_all(dir.join(".kiro")).expect("mkdir .kiro");
        fs::create_dir_all(dir.join(".clinerules")).expect("mkdir .clinerules");
        fs::create_dir_all(dir.join(".cursor")).expect("mkdir .cursor");
        let home = dir.join("home");
        fs::create_dir_all(home.join(".claude")).expect("mkdir home/.claude");
        let found = detect_agents(Some(dir.as_path()), Some(home.as_path()));
        assert_eq!(
            found,
            vec![
                HookAgent::ClaudeCode,
                HookAgent::Codex,
                HookAgent::Copilot,
                HookAgent::Kiro,
                HookAgent::Cline,
                HookAgent::Cursor,
            ],
        );
    }
}
