//! `ptuf init pi` — install ptuf as a Pi Coding Agent TypeScript extension.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

const TEMPLATE: &str = include_str!("templates/pi_extension.ts");

/// Managed-marker lines embedded in every ptuf-generated extension.
pub const MANAGED_MARKER: &str = "Managed by ptuf. Do not edit manually.";
pub const AGENT_MARKER: &str = "ptuf-agent: pi";
pub const BINARY_PLACEHOLDER: &str = "__PTUF_BINARY__";
pub const VERSION_PLACEHOLDER: &str = "__PTUF_VERSION__";

pub const DEFAULT_EXTENSION_NAME: &str = "ptuf.ts";
pub const DEFAULT_MATCHER: &str = "Pi tool_call extension";

/// Which Pi extension directory `ptuf init pi` should write into.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PiScope {
    /// `$HOME/.pi/agent/extensions/ptuf.ts` (default).
    #[default]
    Global,
    /// `<repo>/.pi/extensions/ptuf.ts`.
    Local,
}

/// Pi-specific `ptuf init pi` flags.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PiInitOptions {
    pub scope: PiScope,
    pub root: Option<PathBuf>,
    pub extension: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPaths {
    pub root: PathBuf,
    pub extension_path: PathBuf,
}

/// Try `std::env::current_exe()`. Falls back to the literal `"ptuf"`.
pub fn detect_binary() -> String {
    super::detect_binary_impl()
}

pub fn resolve_paths(
    start: Option<&Path>,
    options: &PiInitOptions,
) -> Result<TargetPaths, InitError> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    resolve_paths_with(start, home.as_deref(), options)
}

fn resolve_paths_with(
    start: Option<&Path>,
    home: Option<&Path>,
    options: &PiInitOptions,
) -> Result<TargetPaths, InitError> {
    if let Some(extension_path) = options.extension.as_ref() {
        let root = extension_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        return Ok(TargetPaths {
            root,
            extension_path: extension_path.clone(),
        });
    }

    match options.scope {
        PiScope::Global => {
            let home = home.ok_or(InitError::HomeNotSet)?;
            let root = home.join(".pi/agent");
            let extension_path = root.join("extensions").join(DEFAULT_EXTENSION_NAME);
            Ok(TargetPaths {
                root,
                extension_path,
            })
        },
        PiScope::Local => {
            let discover_start = options.root.as_deref().or(start);
            let repo = discover_start
                .and_then(crate::config::repo::discover)
                .ok_or(InitError::RepoRootNotFound)?;
            let root = repo.join(".pi");
            let extension_path = root.join("extensions").join(DEFAULT_EXTENSION_NAME);
            Ok(TargetPaths {
                root,
                extension_path,
            })
        },
    }
}

pub fn install(
    targets: &TargetPaths,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} hook pi");
    let desired = render_extension(ptuf_binary, env!("CARGO_PKG_VERSION"));

    let status = match fs::read(&targets.extension_path) {
        Ok(existing) if !is_ptuf_managed(&existing) => {
            return Err(InitError::HookFileConflict {
                path: targets.extension_path.clone(),
            });
        },
        Ok(existing) if existing == desired => InstallStatus::AlreadyPresent,
        Ok(_) => apply(&targets.extension_path, &desired, dry_run)?,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            apply(&targets.extension_path, &desired, dry_run)?
        },
        Err(e) => {
            return Err(InitError::Io {
                path: targets.extension_path.clone(),
                source: e,
            });
        },
    };

    Ok(InstallOutcome {
        status,
        agent: "pi",
        paths: vec![InstallPath {
            label: "extension",
            path: targets.extension_path.clone(),
        }],
        matcher: DEFAULT_MATCHER.to_string(),
        command,
    })
}

fn apply(path: &Path, desired: &[u8], dry_run: bool) -> Result<InstallStatus, InitError> {
    if dry_run {
        return Ok(InstallStatus::WouldInstall);
    }
    write_atomically(path, desired)?;
    Ok(InstallStatus::Installed)
}

/// Render the Pi extension template with the resolved binary path and version.
pub fn render_extension(ptuf_binary: &str, version: &str) -> Vec<u8> {
    let ptuf_binary = serde_json::to_string(ptuf_binary).unwrap_or_else(|_| "\"ptuf\"".into());
    TEMPLATE
        .replace(BINARY_PLACEHOLDER, &ptuf_binary)
        .replace(VERSION_PLACEHOLDER, version)
        .into_bytes()
}

pub(crate) fn is_ptuf_managed(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.contains(MANAGED_MARKER)
        && text.contains(AGENT_MARKER)
        && text.contains("hook")
        && text.contains("pi")
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
    let tmp = super::sibling_install_tmp_path(path, DEFAULT_EXTENSION_NAME);
    super::write_secure(&tmp, bytes).map_err(|e| InitError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| InitError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-init-pi-{}-{}-{}",
            tag,
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn template_contains_managed_marker_and_required_snippets() {
        assert!(TEMPLATE.contains(MANAGED_MARKER));
        assert!(TEMPLATE.contains(AGENT_MARKER));
        assert!(TEMPLATE.contains(BINARY_PLACEHOLDER));
        assert!(TEMPLATE.contains(VERSION_PLACEHOLDER));
        assert!(TEMPLATE.contains(r#"pi.on("tool_call""#));
        assert!(TEMPLATE.contains(r#""hook", "pi""#));
        assert!(TEMPLATE.contains(r#"spawn(PTUF_BINARY, ["hook", "pi"]"#));
        assert!(TEMPLATE.contains("eventInput"));
        assert!(TEMPLATE.contains("event as { input?: unknown; toolInput?: unknown }"));
        assert!(TEMPLATE.contains("ctx.hasUI"));
        assert!(TEMPLATE.contains("ctx.ui.confirm"));
        assert!(TEMPLATE.contains("PTUF_PI_ASK_MODE"));
        assert!(TEMPLATE.contains("decision"));
        assert!(TEMPLATE.contains("block: true"));
        assert!(TEMPLATE.contains("reason: result.reason"));
        assert!(!TEMPLATE.contains("Bun.spawn"));
    }

    #[test]
    fn render_extension_substitutes_binary_and_version() {
        let rendered = String::from_utf8(render_extension("/x/ptuf", "9.9.9")).unwrap();
        assert!(rendered.contains(r#""/x/ptuf""#));
        assert!(rendered.contains("9.9.9"));
        assert!(!rendered.contains(BINARY_PLACEHOLDER));
        assert!(!rendered.contains(VERSION_PLACEHOLDER));
    }

    #[test]
    fn render_extension_json_escapes_binary_literal() {
        let rendered = String::from_utf8(render_extension(
            r#"/tmp/x"; throw new Error("owned") //"#,
            "9.9.9",
        ))
        .unwrap();
        assert!(
            rendered.contains(r#"const PTUF_BINARY = "/tmp/x\"; throw new Error(\"owned\") //";"#),
            "{rendered}"
        );
    }

    #[test]
    fn resolve_paths_global_targets_home_pi_agent_extensions() {
        let home = workdir("global-home");
        let options = PiInitOptions::default();
        let targets = resolve_paths_with(None, Some(home.as_path()), &options).unwrap();
        assert_eq!(
            targets.extension_path,
            home.join(".pi/agent/extensions/ptuf.ts")
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn resolve_paths_local_targets_repo_dot_pi_extensions() {
        let dir = workdir("local-repo");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let options = PiInitOptions {
            scope: PiScope::Local,
            root: None,
            extension: None,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), None, &options).unwrap();
        assert_eq!(targets.extension_path, dir.join(".pi/extensions/ptuf.ts"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_paths_extension_flag_takes_precedence() {
        let dir = workdir("explicit-ext");
        let custom = dir.join("custom/ptuf.ts");
        let options = PiInitOptions {
            scope: PiScope::Global,
            root: None,
            extension: Some(custom.clone()),
        };
        let targets = resolve_paths_with(None, Some(dir.as_path()), &options).unwrap();
        assert_eq!(targets.extension_path, custom);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_does_not_write_extension() {
        let dir = workdir("dry-run");
        let extension = dir.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            extension_path: extension.clone(),
        };
        let outcome = install(&targets, "/bin/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!extension.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_writes_managed_marker_and_binary_path() {
        let dir = workdir("install");
        let extension = dir.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            extension_path: extension.clone(),
        };
        let outcome = install(&targets, "/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = fs::read_to_string(&extension).unwrap();
        assert!(body.contains(MANAGED_MARKER));
        assert!(body.contains("/bin/ptuf"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_refuses_unmanaged_existing_extension() {
        let dir = workdir("conflict");
        let extension = dir.join("ptuf.ts");
        fs::write(&extension, "// user extension\n").unwrap();
        let targets = TargetPaths {
            root: dir.clone(),
            extension_path: extension.clone(),
        };
        let err = install(&targets, "/bin/ptuf", false).expect_err("must conflict");
        assert!(matches!(err, InitError::HookFileConflict { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_marks_extension_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workdir("mode");
        let extension = dir.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            extension_path: extension.clone(),
        };
        install(&targets, "/bin/ptuf", false).unwrap();
        let mode = fs::metadata(&extension).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_paths_global_errors_when_home_unset() {
        let options = PiInitOptions::default();
        let err = resolve_paths_with(None, None, &options).expect_err("needs HOME");
        assert!(matches!(err, InitError::HomeNotSet));
    }

    #[test]
    fn resolve_paths_local_errors_outside_repo() {
        let dir = PathBuf::from("/definitely-no-such-ptuf-pi-repo");
        let options = PiInitOptions {
            scope: PiScope::Local,
            root: None,
            extension: None,
        };
        let err = resolve_paths_with(Some(dir.as_path()), None, &options).expect_err("no repo");
        assert!(matches!(err, InitError::RepoRootNotFound));
    }

    #[test]
    fn install_already_present_when_desired_matches() {
        let dir = workdir("already");
        let extension = dir.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            extension_path: extension.clone(),
        };
        let desired = render_extension("/bin/ptuf", env!("CARGO_PKG_VERSION"));
        fs::write(&extension, &desired).unwrap();
        let outcome = install(&targets, "/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_updates_managed_extension_when_binary_changes() {
        let dir = workdir("update");
        let extension = dir.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            extension_path: extension.clone(),
        };
        fs::write(&extension, render_extension("/old/ptuf", "0.0.0")).unwrap();
        let outcome = install(&targets, "/new/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = fs::read_to_string(&extension).unwrap();
        assert!(body.contains("/new/ptuf"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_ptuf_managed_requires_all_markers() {
        assert!(!is_ptuf_managed(b"// random file\n"));
        assert!(is_ptuf_managed(&render_extension("/bin/ptuf", "1.0.0")));
    }

    #[test]
    fn detect_binary_returns_non_empty_string() {
        assert!(!detect_binary().is_empty());
    }

    #[test]
    fn resolve_paths_reads_home_from_environment() {
        let options = PiInitOptions::default();
        let targets = resolve_paths(None, &options).expect("HOME is set in test env");
        let home = std::env::var_os("HOME").map(PathBuf::from).expect("HOME");
        assert_eq!(
            targets.extension_path,
            home.join(".pi/agent/extensions/ptuf.ts")
        );
    }

    #[test]
    fn install_surfaces_io_error_when_extension_path_is_unreadable() {
        let dir = workdir("io-read");
        let blocker = dir.join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let extension = blocker.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            extension_path: extension,
        };
        let err = install(&targets, "/bin/ptuf", false).expect_err("parent is file");
        assert!(matches!(err, InitError::Io { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_updates_managed_extension_without_writing() {
        let dir = workdir("dry-update");
        let extension = dir.join("ptuf.ts");
        fs::write(&extension, render_extension("/old/ptuf", "0.0.0")).unwrap();
        let targets = TargetPaths {
            root: dir.clone(),
            extension_path: extension.clone(),
        };
        let outcome = install(&targets, "/new/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        let body = fs::read(&extension).unwrap();
        assert!(body.windows(9).any(|w| w == b"/old/ptuf"));
        let _ = fs::remove_dir_all(&dir);
    }
}
