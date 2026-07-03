//! `ptuf init opencode` — install ptuf as an OpenCode TypeScript plugin.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::config::scope::{EnvLookup, SystemEnv};

use super::{InitError, InstallOutcome, InstallPath, InstallStatus};

const TEMPLATE: &str = include_str!("templates/opencode_plugin.ts");

pub const MANAGED_MARKER: &str = "Managed by ptuf. Do not edit manually.";
pub const AGENT_MARKER: &str = "ptuf-agent: opencode";
pub const BINARY_PLACEHOLDER: &str = "__PTUF_BINARY__";
pub const VERSION_PLACEHOLDER: &str = "__PTUF_VERSION__";

pub const DEFAULT_PLUGIN_NAME: &str = "ptuf.ts";
pub const DEFAULT_MATCHER: &str = "OpenCode tool.execute.before plugin";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum OpencodeScope {
    #[default]
    Global,
    Local,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpencodeInitOptions {
    pub scope: OpencodeScope,
    pub root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPaths {
    pub root: PathBuf,
    pub plugin_path: PathBuf,
}

pub fn detect_binary() -> String {
    super::detect_binary_impl()
}

pub fn resolve_paths(
    start: Option<&Path>,
    options: &OpencodeInitOptions,
) -> Result<TargetPaths, InitError> {
    resolve_paths_with(start, &SystemEnv, options)
}

pub fn resolve_paths_with(
    start: Option<&Path>,
    env: &dyn EnvLookup,
    options: &OpencodeInitOptions,
) -> Result<TargetPaths, InitError> {
    match options.scope {
        OpencodeScope::Global => {
            let config_root = opencode_config_dir(env)?;
            let plugin_path = config_root.join("plugin").join(DEFAULT_PLUGIN_NAME);
            Ok(TargetPaths {
                root: config_root,
                plugin_path,
            })
        },
        OpencodeScope::Local => {
            let discover_start = options.root.as_deref().or(start);
            let repo = discover_start
                .and_then(crate::config::repo::discover)
                .ok_or(InitError::RepoRootNotFound)?;
            let root = repo.join(".opencode");
            let plugin_path = root.join("plugin").join(DEFAULT_PLUGIN_NAME);
            Ok(TargetPaths { root, plugin_path })
        },
    }
}

pub fn opencode_config_dir(env: &dyn EnvLookup) -> Result<PathBuf, InitError> {
    if let Some(xdg) = env.var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("opencode"));
    }
    let home = env.var_os("HOME").ok_or(InitError::HomeNotSet)?.to_owned();
    Ok(PathBuf::from(home).join(".config/opencode"))
}

pub fn install(
    targets: &TargetPaths,
    ptuf_binary: &str,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} hook opencode");
    let desired = render_plugin(ptuf_binary, env!("CARGO_PKG_VERSION"));

    let status = match fs::read(&targets.plugin_path) {
        Ok(existing) if !is_ptuf_managed(&existing) => {
            return Err(InitError::HookFileConflict {
                path: targets.plugin_path.clone(),
            });
        },
        Ok(existing) if existing == desired => InstallStatus::AlreadyPresent,
        Ok(_) => apply(&targets.plugin_path, &desired, dry_run)?,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            apply(&targets.plugin_path, &desired, dry_run)?
        },
        Err(e) => {
            return Err(InitError::Io {
                path: targets.plugin_path.clone(),
                source: e,
            });
        },
    };

    Ok(InstallOutcome {
        status,
        agent: "opencode",
        paths: vec![InstallPath {
            label: "plugin",
            path: targets.plugin_path.clone(),
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

pub fn render_plugin(ptuf_binary: &str, version: &str) -> Vec<u8> {
    TEMPLATE
        .replace(BINARY_PLACEHOLDER, ptuf_binary)
        .replace(VERSION_PLACEHOLDER, version)
        .into_bytes()
}

pub(crate) fn is_ptuf_managed(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.contains(MANAGED_MARKER)
        && text.contains(AGENT_MARKER)
        && text.contains("hook")
        && text.contains("opencode")
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
    let tmp = super::sibling_install_tmp_path(path, DEFAULT_PLUGIN_NAME);
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
    use std::collections::HashMap;
    use std::ffi::OsString;

    use super::*;
    use crate::config::scope::EnvLookup;

    struct MapEnv {
        vars: HashMap<String, OsString>,
    }

    impl MapEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            let mut vars = HashMap::new();
            for (k, v) in pairs {
                vars.insert((*k).to_string(), OsString::from(*v));
            }
            Self { vars }
        }
    }

    impl EnvLookup for MapEnv {
        fn var_os(&self, key: &str) -> Option<OsString> {
            self.vars.get(key).cloned()
        }
    }

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-init-opencode-{}-{}-{}",
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
        assert!(TEMPLATE.contains(r#""tool.execute.before""#));
        assert!(TEMPLATE.contains(r#"["hook", "opencode"]"#));
        assert!(TEMPLATE.contains("PTUF_OPENCODE_TIMEOUT_MS"));
        assert!(TEMPLATE.contains("MAX_CAPTURE_BYTES"));
        assert!(TEMPLATE.contains("SIGKILL"));
        assert!(!TEMPLATE.contains("ASK_MODE"));
    }

    #[test]
    fn render_plugin_substitutes_binary_and_version() {
        let rendered = String::from_utf8(render_plugin("/x/ptuf", "9.9.9")).unwrap();
        assert!(rendered.contains("/x/ptuf"));
        assert!(rendered.contains("9.9.9"));
        assert!(!rendered.contains(BINARY_PLACEHOLDER));
        assert!(!rendered.contains(VERSION_PLACEHOLDER));
    }

    #[test]
    fn resolve_paths_global_uses_xdg_config_home() {
        let env = MapEnv::new(&[("XDG_CONFIG_HOME", "/xdg")]);
        let options = OpencodeInitOptions::default();
        let targets = resolve_paths_with(None, &env, &options).unwrap();
        assert_eq!(
            targets.plugin_path,
            PathBuf::from("/xdg/opencode/plugin/ptuf.ts")
        );
    }

    #[test]
    fn resolve_paths_global_falls_back_to_home_dot_config() {
        let home = workdir("home-config");
        let env = MapEnv::new(&[("HOME", home.to_str().unwrap())]);
        let options = OpencodeInitOptions::default();
        let targets = resolve_paths_with(None, &env, &options).unwrap();
        assert_eq!(
            targets.plugin_path,
            home.join(".config/opencode/plugin/ptuf.ts")
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn resolve_paths_local_targets_repo_dot_opencode_plugin() {
        let dir = workdir("local-repo");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let options = OpencodeInitOptions {
            scope: OpencodeScope::Local,
            root: None,
        };
        let targets = resolve_paths_with(Some(dir.as_path()), &MapEnv::new(&[]), &options).unwrap();
        assert_eq!(targets.plugin_path, dir.join(".opencode/plugin/ptuf.ts"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_paths_global_errors_when_home_unset() {
        let options = OpencodeInitOptions::default();
        let err = resolve_paths_with(None, &MapEnv::new(&[]), &options).expect_err("needs HOME");
        assert!(matches!(err, InitError::HomeNotSet));
    }

    #[test]
    fn install_dry_run_does_not_write_plugin() {
        let dir = workdir("dry-run");
        let plugin = dir.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            plugin_path: plugin.clone(),
        };
        let outcome = install(&targets, "/bin/ptuf", true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!plugin.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_writes_managed_marker_and_binary_path() {
        let dir = workdir("install");
        let plugin = dir.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            plugin_path: plugin.clone(),
        };
        let outcome = install(&targets, "/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = fs::read_to_string(&plugin).unwrap();
        assert!(body.contains(MANAGED_MARKER));
        assert!(body.contains("/bin/ptuf"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_refuses_unmanaged_existing_plugin() {
        let dir = workdir("conflict");
        let plugin = dir.join("ptuf.ts");
        fs::write(&plugin, "// user plugin\n").unwrap();
        let targets = TargetPaths {
            root: dir.clone(),
            plugin_path: plugin.clone(),
        };
        let err = install(&targets, "/bin/ptuf", false).expect_err("must conflict");
        assert!(matches!(err, InitError::HookFileConflict { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_already_present_when_desired_matches() {
        let dir = workdir("already");
        let plugin = dir.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            plugin_path: plugin.clone(),
        };
        let desired = render_plugin("/bin/ptuf", env!("CARGO_PKG_VERSION"));
        fs::write(&plugin, &desired).unwrap();
        let outcome = install(&targets, "/bin/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(outcome.agent, "opencode");
        assert_eq!(outcome.matcher, DEFAULT_MATCHER);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_updates_managed_plugin_when_binary_changes() {
        let dir = workdir("update");
        let plugin = dir.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            plugin_path: plugin.clone(),
        };
        fs::write(&plugin, render_plugin("/old/ptuf", "0.0.0")).unwrap();
        let outcome = install(&targets, "/new/ptuf", false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = fs::read_to_string(&plugin).unwrap();
        assert!(body.contains("/new/ptuf"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_ptuf_managed_requires_all_markers() {
        assert!(!is_ptuf_managed(b"// random file\n"));
        assert!(is_ptuf_managed(&render_plugin("/bin/ptuf", "1.0.0")));
    }

    #[test]
    fn detect_binary_returns_non_empty_string() {
        assert!(!detect_binary().is_empty());
    }

    #[test]
    fn resolve_paths_delegates_to_resolve_paths_with() {
        let options = OpencodeInitOptions::default();
        let targets = resolve_paths(None, &options).expect("HOME is set in test env");
        assert!(targets.plugin_path.ends_with("plugin/ptuf.ts"));
    }

    #[test]
    fn resolve_paths_local_errors_outside_repo() {
        let dir = workdir("no-repo");
        let options = OpencodeInitOptions {
            scope: OpencodeScope::Local,
            root: None,
        };
        let err = resolve_paths_with(Some(dir.as_path()), &MapEnv::new(&[]), &options)
            .expect_err("no repo");
        assert!(matches!(err, InitError::RepoRootNotFound));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_paths_local_honours_explicit_root() {
        let dir = workdir("explicit-root");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let nested = dir.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let options = OpencodeInitOptions {
            scope: OpencodeScope::Local,
            root: Some(nested.clone()),
        };
        let targets = resolve_paths_with(None, &MapEnv::new(&[]), &options).unwrap();
        assert_eq!(targets.plugin_path, dir.join(".opencode/plugin/ptuf.ts"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_marks_plugin_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workdir("mode");
        let plugin = dir.join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            plugin_path: plugin.clone(),
        };
        install(&targets, "/bin/ptuf", false).unwrap();
        let mode = fs::metadata(&plugin).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }
}
