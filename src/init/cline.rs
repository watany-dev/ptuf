//! `ptuf init cline` — install ptuf as a Cline `PreToolUse` file hook.
//!
//! Unlike the other host adapters, Cline file hooks are *executable
//! scripts* rather than command strings registered in a config file.
//! The installer therefore writes a small wrapper script that `exec`s
//! `<ptuf> hook cline`:
//!
//! - repo-local (preferred): `<repo>/.clinerules/hooks/PreToolUse` on
//!   Unix / macOS, `PreToolUse.ps1` on Windows.
//! - global fallback (no repo root): `~/Documents/Cline/Hooks/PreToolUse`.
//!
//! Cline identifies a hook purely by its file name within the hooks
//! directory, so an existing `PreToolUse` that ptuf does not recognise
//! is never silently overwritten — that surfaces as
//! [`InitError::HookFileConflict`]. A wrapper ptuf already manages is
//! re-rendered idempotently so the embedded binary path stays current.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

/// Marker comment embedded in every ptuf-managed Cline wrapper. Its
/// presence is what distinguishes a wrapper ptuf may rewrite from a
/// hand-written hook that must not be clobbered.
const MANAGED_MARKER: &str = "ptuf-managed: cline PreToolUse";

/// Matcher recorded in [`InstallOutcome`] for the rendered summary.
/// Cline file hooks do not use a regex matcher — the hook fires for
/// every `PreToolUse` event — so this is purely descriptive.
pub const DEFAULT_MATCHER: &str = "PreToolUse";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPaths {
    /// Absolute path of the `PreToolUse` wrapper script to install.
    pub hook_path: PathBuf,
    /// `true` when the target is the `~/Documents/Cline/Hooks` global
    /// fallback rather than a repo-local `.clinerules/hooks` directory.
    pub global: bool,
}

/// Try `std::env::current_exe()`. Falls back to the literal `"ptuf"`.
pub fn detect_binary() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| "ptuf".to_string())
}

/// File name of the Cline `PreToolUse` hook for the current platform.
fn cline_hook_file_name() -> &'static str {
    if cfg!(windows) {
        "PreToolUse.ps1"
    } else {
        "PreToolUse"
    }
}

/// Resolve the `PreToolUse` wrapper path Cline should be configured
/// against.
///
/// Prefers the repo-local `<repo>/.clinerules/hooks/PreToolUse` when the
/// caller is inside a git working tree; otherwise falls back to the
/// global `~/Documents/Cline/Hooks/PreToolUse`. Returns
/// [`InitError::HomeNotSet`] when neither a repo root nor `$HOME` is
/// available.
pub fn resolve_paths(start: Option<&Path>) -> Result<TargetPaths, InitError> {
    let file_name = cline_hook_file_name();
    if let Some(root) = start.and_then(crate::config::repo::discover) {
        return Ok(TargetPaths {
            hook_path: root.join(".clinerules/hooks").join(file_name),
            global: false,
        });
    }
    let home = std::env::var_os("HOME").ok_or(InitError::HomeNotSet)?;
    Ok(TargetPaths {
        hook_path: PathBuf::from(home)
            .join("Documents/Cline/Hooks")
            .join(file_name),
        global: true,
    })
}

pub fn install(
    targets: &TargetPaths,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} hook cline");
    let desired = render_wrapper(ptuf_binary);

    let status = match fs::read(&targets.hook_path) {
        Ok(existing) if !is_ptuf_managed(&existing) => {
            return Err(InitError::HookFileConflict {
                path: targets.hook_path.clone(),
            });
        },
        Ok(existing) if existing == desired => InstallStatus::AlreadyPresent,
        Ok(_) => apply(&targets.hook_path, &desired, dry_run)?,
        Err(e) if e.kind() == ErrorKind::NotFound => apply(&targets.hook_path, &desired, dry_run)?,
        Err(e) => {
            return Err(InitError::Io {
                path: targets.hook_path.clone(),
                source: e,
            });
        },
    };

    let label = if targets.global {
        "hook (global)"
    } else {
        "hook"
    };
    Ok(InstallOutcome {
        status,
        agent: "cline",
        paths: vec![InstallPath {
            label,
            path: targets.hook_path.clone(),
        }],
        matcher: DEFAULT_MATCHER.to_string(),
        command,
        kiro_report: None,
    })
}

/// Write `desired` to `path` unless this is a dry run.
fn apply(path: &Path, desired: &[u8], dry_run: bool) -> Result<InstallStatus, InitError> {
    if dry_run {
        return Ok(InstallStatus::WouldInstall);
    }
    write_executable_atomically(path, desired)?;
    Ok(InstallStatus::Installed)
}

/// Render the `PreToolUse` wrapper script for the current platform.
///
/// The Unix wrapper `exec`s ptuf so the hook process is replaced and the
/// exit code passes straight through; the PowerShell wrapper forwards
/// `$LASTEXITCODE` explicitly since `&` does not replace the process.
fn render_wrapper(ptuf_binary: &str) -> Vec<u8> {
    if cfg!(windows) {
        format!(
            "# {MANAGED_MARKER}\n& {} hook cline\nexit $LASTEXITCODE\n",
            quote_powershell(ptuf_binary),
        )
        .into_bytes()
    } else {
        format!(
            "#!/usr/bin/env sh\n# {MANAGED_MARKER}\nexec {} hook cline\n",
            quote_sh(ptuf_binary),
        )
        .into_bytes()
    }
}

/// Single-quote `s` for a POSIX shell: wrap in `'...'` and rewrite every
/// embedded `'` as `'\''`.
fn quote_sh(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Single-quote `s` for PowerShell: wrap in `'...'` and double every
/// embedded `'`.
fn quote_powershell(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A `PreToolUse` file is ptuf's to rewrite when it carries our managed
/// marker, or otherwise visibly invokes `ptuf hook cline`.
fn is_ptuf_managed(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.contains(MANAGED_MARKER) || text.contains("ptuf hook cline")
}

fn write_executable_atomically(path: &Path, bytes: &[u8]) -> Result<(), InitError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| InitError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let tmp = sibling_temp_path(path);
    crate::init::write_executable(&tmp, bytes).map_err(|e| InitError::Io {
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
        || std::ffi::OsString::from("PreToolUse"),
        std::ffi::OsStr::to_os_string,
    );
    name.push(format!(".ptuf.{}.tmp", std::process::id()));
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-init-cline-{}-{}-{}",
            tag,
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    fn repo_targets(dir: &Path) -> TargetPaths {
        TargetPaths {
            hook_path: dir.join(".clinerules/hooks").join(cline_hook_file_name()),
            global: false,
        }
    }

    #[test]
    fn resolve_paths_targets_repo_local_clinerules_hooks() {
        let dir = workdir("resolve-repo");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let targets = resolve_paths(Some(dir.as_path())).unwrap();
        assert!(!targets.global);
        assert!(
            targets.hook_path.ends_with(".clinerules/hooks/PreToolUse")
                || targets
                    .hook_path
                    .ends_with(".clinerules/hooks/PreToolUse.ps1"),
            "got: {:?}",
            targets.hook_path,
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_paths_falls_back_to_global_cline_hooks_dir() {
        // Outside a repo, resolution reads $HOME for the global fallback.
        match resolve_paths(None) {
            Ok(targets) => {
                assert!(targets.global);
                assert!(
                    targets.hook_path.starts_with(
                        PathBuf::from(std::env::var_os("HOME").unwrap())
                            .join("Documents/Cline/Hooks"),
                    ),
                    "got: {:?}",
                    targets.hook_path,
                );
            },
            Err(InitError::HomeNotSet) => {},
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn cline_hook_file_name_matches_platform() {
        let name = cline_hook_file_name();
        if cfg!(windows) {
            assert_eq!(name, "PreToolUse.ps1");
        } else {
            assert_eq!(name, "PreToolUse");
        }
    }

    #[test]
    fn install_writes_wrapper_with_marker_and_hook_command() {
        let dir = workdir("install-marker");
        let targets = repo_targets(&dir);
        let outcome = install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        assert_eq!(outcome.agent, "cline");
        assert_eq!(outcome.matcher, "PreToolUse");
        let body = read(&targets.hook_path);
        assert!(
            body.contains("ptuf-managed: cline PreToolUse"),
            "body: {body}"
        );
        assert!(body.contains("hook cline"), "body: {body}");
        assert!(body.contains("/usr/local/bin/ptuf"), "body: {body}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_marks_wrapper_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workdir("install-exec");
        let targets = repo_targets(&dir);
        install(&targets, "/usr/local/bin/ptuf", false).unwrap();
        let mode = fs::metadata(&targets.hook_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "wrapper must be owner-only executable");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_reports_changes_without_writing() {
        let dir = workdir("dry-run");
        let targets = repo_targets(&dir);
        let outcome = install(&targets, "/usr/local/bin/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!targets.hook_path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_idempotent_when_wrapper_is_byte_identical() {
        let dir = workdir("idempotent");
        let targets = repo_targets(&dir);
        install(&targets, "/x/ptuf", false).unwrap();
        let before = read(&targets.hook_path);
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(before, read(&targets.hook_path));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rewrites_managed_wrapper_when_binary_path_changes() {
        let dir = workdir("update-binary");
        let targets = repo_targets(&dir);
        install(&targets, "/old/ptuf", false).unwrap();
        let outcome = install(&targets, "/new/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = read(&targets.hook_path);
        assert!(body.contains("/new/ptuf"), "body: {body}");
        assert!(!body.contains("/old/ptuf"), "body: {body}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_on_managed_wrapper_change_does_not_write() {
        let dir = workdir("dry-run-update");
        let targets = repo_targets(&dir);
        install(&targets, "/old/ptuf", false).unwrap();
        let before = read(&targets.hook_path);
        let outcome = install(&targets, "/new/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert_eq!(before, read(&targets.hook_path), "dry-run must not rewrite");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_refuses_to_overwrite_unmanaged_hook() {
        let dir = workdir("conflict");
        let targets = repo_targets(&dir);
        fs::create_dir_all(targets.hook_path.parent().unwrap()).unwrap();
        fs::write(&targets.hook_path, "#!/bin/sh\necho hand-written\n").unwrap();
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        match err {
            InitError::HookFileConflict { path } => assert_eq!(path, targets.hook_path),
            other => panic!("expected HookFileConflict, got {other:?}"),
        }
        // The hand-written hook is left exactly as it was.
        assert_eq!(read(&targets.hook_path), "#!/bin/sh\necho hand-written\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_reports_io_error_when_hook_path_is_a_directory() {
        let dir = workdir("hook-is-dir");
        let hook_path = dir.join("PreToolUse");
        fs::create_dir_all(&hook_path).unwrap();
        let targets = TargetPaths {
            hook_path,
            global: false,
        };
        let err = install(&targets, "/x/ptuf", false).unwrap_err();
        assert!(matches!(err, InitError::Io { .. }), "got: {err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_global_outcome_labels_path_as_global() {
        let dir = workdir("global-label");
        let targets = TargetPaths {
            hook_path: dir.join("Documents/Cline/Hooks/PreToolUse"),
            global: true,
        };
        let outcome = install(&targets, "/x/ptuf", false).unwrap();
        assert_eq!(outcome.paths[0].label, "hook (global)");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn quote_sh_escapes_embedded_single_quotes() {
        assert_eq!(quote_sh("/p/ptuf"), "'/p/ptuf'");
        assert_eq!(quote_sh("/a'b/ptuf"), "'/a'\\''b/ptuf'");
    }

    #[test]
    fn quote_powershell_doubles_embedded_single_quotes() {
        assert_eq!(quote_powershell(r"C:\p\ptuf.exe"), r"'C:\p\ptuf.exe'");
        assert_eq!(quote_powershell("a'b"), "'a''b'");
    }

    #[test]
    fn is_ptuf_managed_recognises_marker_and_invocation() {
        assert!(is_ptuf_managed(b"# ptuf-managed: cline PreToolUse\n"));
        assert!(is_ptuf_managed(b"do ptuf hook cline now"));
        assert!(!is_ptuf_managed(b"#!/bin/sh\necho hello\n"));
        assert!(!is_ptuf_managed(&[0xff, 0xfe]));
    }

    #[test]
    fn detect_binary_returns_a_non_empty_string() {
        assert!(!detect_binary().is_empty());
    }

    #[test]
    fn sibling_temp_path_uses_default_filename_when_input_has_none() {
        let tmp = sibling_temp_path(Path::new("/"));
        assert!(
            tmp.to_string_lossy().contains("PreToolUse.ptuf."),
            "got: {tmp:?}",
        );
    }

    #[test]
    fn sibling_temp_path_falls_back_to_bare_filename_when_no_parent() {
        let tmp = sibling_temp_path(Path::new("PreToolUse"));
        assert!(
            tmp.parent()
                .map(Path::as_os_str)
                .unwrap_or_default()
                .is_empty(),
            "no-parent input must yield no-parent temp path: {tmp:?}",
        );
        assert!(tmp.to_string_lossy().contains("PreToolUse.ptuf."));
    }
}
