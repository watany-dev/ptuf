//! `ptuf init opencode` — install ptuf as an OpenCode TypeScript plugin.
//!
//! Two adapter generations ship side by side:
//!
//! - [`OpencodeGeneration::V1`] targets the OpenCode **v1** plugin API
//!   (`@opencode-ai/plugin` + `tool.execute.before`). It is reachable
//!   only through the pinned `opencode-v1` token.
//! - [`OpencodeGeneration::V2`] targets the OpenCode **v2** plugin API
//!   (`@opencode/plugin` + `Plugin.define({ id, setup })` +
//!   `ctx.tool.hook("execute.before", …)`). It is reachable through the
//!   pinned `opencode-v2` token and the floating `opencode` alias, which
//!   always means the newest adapter this build ships.
//!
//! OpenCode does not run a v1 plugin under v2, so the generation is not a
//! cosmetic choice: it decides which host can load the file. Both
//! generations install to the same managed plugin path (`plugins/ptuf.ts`)
//! — the *content*, never the path, carries the generation, so a host only
//! ever loads a single ptuf plugin.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::config::scope::{EnvLookup, SystemEnv};

use super::{FileMode, InitError, InstallOutcome, InstallPath, InstallStatus};

const TEMPLATE_V1: &str = include_str!("templates/opencode_plugin.ts");
const TEMPLATE_V2: &str = include_str!("templates/opencode_v2_plugin.ts");
const SUBPROCESS_TEMPLATE: &str = include_str!("templates/opencode_subprocess.ts");

pub(crate) const MANAGED_MARKER: &str = "Managed by ptuf. Do not edit manually.";
/// Agent marker written by the OpenCode **v1** plugin. Kept verbatim
/// (without a `-v1` suffix) so installs made before the v2 adapter landed
/// are still recognized as ptuf-managed and can be upgraded in place.
pub(crate) const AGENT_MARKER_V1: &str = "ptuf-agent: opencode";
/// Agent marker written by the OpenCode **v2** plugin. `AGENT_MARKER_V1`
/// is a substring of this constant, so the shared `is_ptuf_managed` check
/// recovers both generations and either `ptuf init opencode-v1` /
/// `opencode-v2` can replace the other's managed file.
pub(crate) const AGENT_MARKER_V2: &str = "ptuf-agent: opencode-v2";
pub(crate) const BINARY_PLACEHOLDER: &str = "__PTUF_BINARY__";
pub(crate) const VERSION_PLACEHOLDER: &str = "__PTUF_VERSION__";

pub(crate) const DEFAULT_PLUGIN_NAME: &str = "ptuf.ts";
const PLUGIN_DIR: &str = "plugins";
const LEGACY_PLUGIN_DIR: &str = "plugin";

/// Which OpenCode plugin API generation a managed plugin targets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum OpencodeGeneration {
    /// OpenCode v1 plugin API (`@opencode-ai/plugin`, `tool.execute.before`).
    V1,
    /// OpenCode v2 plugin API (`@opencode/plugin`, `ctx.tool.hook`). The
    /// newest generation, so it backs the floating `opencode` alias too.
    #[default]
    V2,
}

impl OpencodeGeneration {
    /// Versioned `hook` token the generated plugin spawns, and the token
    /// users pin in `ptuf init` / `ptuf hook`.
    pub(crate) const fn hook_token(self) -> &'static str {
        match self {
            Self::V1 => "opencode-v1",
            Self::V2 => "opencode-v2",
        }
    }

    /// Human-readable matcher surfaced by `ptuf init` output.
    pub(crate) const fn matcher(self) -> &'static str {
        match self {
            Self::V1 => "OpenCode tool.execute.before plugin (v1 API)",
            Self::V2 => "OpenCode ctx.tool.hook execute.before plugin (v2 API)",
        }
    }

    const fn template(self) -> &'static str {
        match self {
            Self::V1 => TEMPLATE_V1,
            Self::V2 => TEMPLATE_V2,
        }
    }
}

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
pub(crate) struct TargetPaths {
    pub root: PathBuf,
    pub plugin_path: PathBuf,
    pub legacy_plugin_path: PathBuf,
}

pub(crate) fn resolve_paths(
    start: Option<&Path>,
    options: &OpencodeInitOptions,
) -> Result<TargetPaths, InitError> {
    resolve_paths_with(start, &SystemEnv, options)
}

pub(crate) fn resolve_paths_with(
    start: Option<&Path>,
    env: &dyn EnvLookup,
    options: &OpencodeInitOptions,
) -> Result<TargetPaths, InitError> {
    match options.scope {
        OpencodeScope::Global => {
            let config_root = opencode_config_dir(env)?;
            let plugin_path = config_root.join(PLUGIN_DIR).join(DEFAULT_PLUGIN_NAME);
            let legacy_plugin_path = config_root
                .join(LEGACY_PLUGIN_DIR)
                .join(DEFAULT_PLUGIN_NAME);
            Ok(TargetPaths {
                root: config_root,
                plugin_path,
                legacy_plugin_path,
            })
        },
        OpencodeScope::Local => {
            let discover_start = options.root.as_deref().or(start);
            let repo = discover_start
                .and_then(crate::config::repo::discover)
                .ok_or(InitError::RepoRootNotFound)?;
            let root = repo.join(".opencode");
            let plugin_path = root.join(PLUGIN_DIR).join(DEFAULT_PLUGIN_NAME);
            let legacy_plugin_path = root.join(LEGACY_PLUGIN_DIR).join(DEFAULT_PLUGIN_NAME);
            Ok(TargetPaths {
                root,
                plugin_path,
                legacy_plugin_path,
            })
        },
    }
}

pub(crate) fn opencode_config_dir(env: &dyn EnvLookup) -> Result<PathBuf, InitError> {
    if let Some(xdg) = env.var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("opencode"));
    }
    let home = env.var_os("HOME").ok_or(InitError::HomeNotSet)?.to_owned();
    Ok(PathBuf::from(home).join(".config/opencode"))
}

/// Auto-detection identifies a host, not its API generation. Only a managed
/// plugin at the actual install target can safely supply the generation.
pub(crate) fn auto_generation(targets: &TargetPaths) -> Result<OpencodeGeneration, InitError> {
    let mut generation = None;
    for path in [&targets.plugin_path, &targets.legacy_plugin_path] {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(InitError::Io {
                    path: path.clone(),
                    source,
                });
            },
        };
        let current = managed_generation(&bytes).ok_or_else(|| generation_required(path))?;
        if generation.is_some_and(|previous| previous != current) {
            return Err(generation_required(path));
        }
        generation = Some(current);
    }
    generation.ok_or_else(|| generation_required(&targets.root))
}

fn generation_required(path: &Path) -> InitError {
    InitError::Schema {
        path: path.to_path_buf(),
        message: "cannot determine OpenCode plugin generation; run ptuf init opencode-v1 or ptuf init opencode-v2 explicitly".into(),
    }
}

fn managed_generation(bytes: &[u8]) -> Option<OpencodeGeneration> {
    if !is_ptuf_managed(bytes) {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut generation = None;
    for line in text.lines() {
        let current = match line.trim().strip_prefix("// ptuf-agent: ") {
            Some("opencode") => OpencodeGeneration::V1,
            Some("opencode-v2") => OpencodeGeneration::V2,
            Some(_) => return None,
            None => continue,
        };
        if generation.is_some_and(|previous| previous != current) {
            return None;
        }
        generation = Some(current);
    }
    generation
}

pub(crate) fn install(
    targets: &TargetPaths,
    ptuf_binary: &str,
    generation: OpencodeGeneration,
    dry_run: bool,
) -> Result<InstallOutcome, InitError> {
    let command = format!("{ptuf_binary} hook {}", generation.hook_token());
    let desired = render_plugin(ptuf_binary, env!("CARGO_PKG_VERSION"), generation);

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
    remove_legacy_managed_plugin(targets, dry_run)?;

    Ok(InstallOutcome {
        status,
        agent: "opencode",
        paths: vec![InstallPath {
            label: "plugin",
            path: targets.plugin_path.clone(),
        }],
        matcher: generation.matcher().to_string(),
        command,
    })
}

fn remove_legacy_managed_plugin(targets: &TargetPaths, dry_run: bool) -> Result<(), InitError> {
    if targets.legacy_plugin_path == targets.plugin_path {
        return Ok(());
    }
    let existing = match fs::read(&targets.legacy_plugin_path) {
        Ok(existing) => existing,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(InitError::Io {
                path: targets.legacy_plugin_path.clone(),
                source: e,
            });
        },
    };
    if !is_ptuf_managed(&existing) || dry_run {
        return Ok(());
    }
    fs::remove_file(&targets.legacy_plugin_path).map_err(|e| InitError::Io {
        path: targets.legacy_plugin_path.clone(),
        source: e,
    })
}

fn apply(path: &Path, desired: &[u8], dry_run: bool) -> Result<InstallStatus, InitError> {
    if dry_run {
        return Ok(InstallStatus::WouldInstall);
    }
    super::write_install_bytes(path, desired, DEFAULT_PLUGIN_NAME, FileMode::Secure)?;
    Ok(InstallStatus::Installed)
}

pub(crate) fn render_plugin(
    ptuf_binary: &str,
    version: &str,
    generation: OpencodeGeneration,
) -> Vec<u8> {
    let ptuf_binary = serde_json::to_string(ptuf_binary).unwrap_or_else(|_| "\"ptuf\"".into());
    generation
        .template()
        .replace("// __PTUF_SUBPROCESS__", SUBPROCESS_TEMPLATE)
        .replace("__PTUF_HOOK_TOKEN__", generation.hook_token())
        .replace(BINARY_PLACEHOLDER, &ptuf_binary)
        .replace(VERSION_PLACEHOLDER, version)
        .into_bytes()
}

/// True when `bytes` is a ptuf-managed OpenCode plugin of either
/// generation.
///
/// Because [`AGENT_MARKER_V1`] is a prefix of [`AGENT_MARKER_V2`], the v1
/// test alone recovers both generations; both are spelled out so the
/// intent is explicit and so a future generation whose marker is *not*
/// prefixed by an older one still passes here.
pub(crate) fn is_ptuf_managed(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let has_agent_marker = text.contains(AGENT_MARKER_V1) || text.contains(AGENT_MARKER_V2);
    has_agent_marker
        && text.contains(MANAGED_MARKER)
        && text.contains("hook")
        && text.contains("opencode")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::scope::MapEnv;

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

    fn test_targets(root: &Path, plugin_path: PathBuf) -> TargetPaths {
        TargetPaths {
            root: root.to_path_buf(),
            legacy_plugin_path: root.join("legacy-plugin").join(DEFAULT_PLUGIN_NAME),
            plugin_path,
        }
    }

    #[test]
    fn v1_template_contains_managed_marker_and_required_snippets() {
        assert!(TEMPLATE_V1.contains(MANAGED_MARKER));
        assert!(TEMPLATE_V1.contains(AGENT_MARKER_V1));
        assert!(!TEMPLATE_V1.contains(AGENT_MARKER_V2));
        assert!(TEMPLATE_V1.contains(BINARY_PLACEHOLDER));
        assert!(TEMPLATE_V1.contains(VERSION_PLACEHOLDER));
        assert!(TEMPLATE_V1.contains(r#""tool.execute.before""#));
        assert!(TEMPLATE_V1.contains("// __PTUF_SUBPROCESS__"));
        assert!(!TEMPLATE_V1.contains("ASK_MODE"));
        // §4.3 fail-closed matrix: allow/monitor must be accompanied by
        // exit 0 — a deny exit paired with an allow body is thrown.
        assert!(SUBPROCESS_TEMPLATE.contains("permitted !== (exitCode === 0)"));
    }

    #[test]
    fn v2_template_targets_v2_api_and_required_snippets() {
        assert!(TEMPLATE_V2.contains(MANAGED_MARKER));
        assert!(TEMPLATE_V2.contains(AGENT_MARKER_V2));
        assert!(TEMPLATE_V2.contains(BINARY_PLACEHOLDER));
        assert!(TEMPLATE_V2.contains(VERSION_PLACEHOLDER));
        // v2 entrypoint + hook registration, not the v1 `tool.execute.before`
        // string-keyed hook object.
        assert!(TEMPLATE_V2.contains(r#"from "@opencode/plugin""#));
        assert!(TEMPLATE_V2.contains("Plugin.define("));
        assert!(TEMPLATE_V2.contains(r#"ctx.tool.hook("execute.before""#));
        assert!(!TEMPLATE_V2.contains("@opencode-ai/plugin"));
        assert!(!TEMPLATE_V2.contains(r#""tool.execute.before""#));
        // The plugin spawns the pinned v2 hook token.
        assert!(TEMPLATE_V2.contains("// __PTUF_SUBPROCESS__"));
        assert!(!TEMPLATE_V2.contains("ASK_MODE"));
        assert!(SUBPROCESS_TEMPLATE.contains("permitted !== (exitCode === 0)"));
    }

    #[test]
    fn render_plugin_substitutes_binary_and_version() {
        for generation in [OpencodeGeneration::V1, OpencodeGeneration::V2] {
            let rendered =
                String::from_utf8(render_plugin("/x/ptuf", "9.9.9", generation)).unwrap();
            assert!(rendered.contains(r#""/x/ptuf""#), "{generation:?}");
            assert!(rendered.contains("9.9.9"), "{generation:?}");
            assert!(!rendered.contains(BINARY_PLACEHOLDER), "{generation:?}");
            assert!(!rendered.contains(VERSION_PLACEHOLDER), "{generation:?}");
        }
    }

    #[test]
    fn render_plugin_json_escapes_binary_literal() {
        let rendered = String::from_utf8(render_plugin(
            r#"/tmp/x"; throw new Error("owned") //"#,
            "9.9.9",
            OpencodeGeneration::V2,
        ))
        .unwrap();
        assert!(
            rendered.contains(r#"const PTUF_BINARY = "/tmp/x\"; throw new Error(\"owned\") //";"#),
            "{rendered}"
        );
    }

    #[test]
    fn generation_tokens_and_matchers_are_distinct_and_pinned() {
        assert_eq!(OpencodeGeneration::V1.hook_token(), "opencode-v1");
        assert_eq!(OpencodeGeneration::V2.hook_token(), "opencode-v2");
        assert_ne!(
            OpencodeGeneration::V1.matcher(),
            OpencodeGeneration::V2.matcher()
        );
        // The floating alias defaults to the newest generation.
        assert_eq!(OpencodeGeneration::default(), OpencodeGeneration::V2);
    }

    #[test]
    fn auto_generation_preserves_current_and_legacy_plugins() {
        for generation in [OpencodeGeneration::V1, OpencodeGeneration::V2] {
            for legacy in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let targets = test_targets(dir.path(), dir.path().join("ptuf.ts"));
                let path = if legacy {
                    &targets.legacy_plugin_path
                } else {
                    &targets.plugin_path
                };
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, render_plugin("/old/ptuf", "0.0.0", generation)).unwrap();
                assert_eq!(auto_generation(&targets).unwrap(), generation);
            }
        }
    }

    #[test]
    fn auto_generation_requires_explicit_selection_when_unknown_or_conflicting() {
        let dir = tempfile::tempdir().unwrap();
        let targets = test_targets(dir.path(), dir.path().join("ptuf.ts"));
        assert!(matches!(
            auto_generation(&targets),
            Err(InitError::Schema { .. })
        ));
        for body in [
            "// user plugin",
            "// Managed by ptuf. Do not edit manually.\n// ptuf-agent: opencode-v3\n// hook opencode",
            "// Managed by ptuf. Do not edit manually.\n// ptuf-agent: opencode\n// ptuf-agent: opencode-v2\n// hook opencode",
        ] {
            fs::write(&targets.plugin_path, body).unwrap();
            assert!(matches!(
                auto_generation(&targets),
                Err(InitError::Schema { .. })
            ));
        }
        fs::write(
            &targets.plugin_path,
            render_plugin("ptuf", "0", OpencodeGeneration::V1),
        )
        .unwrap();
        fs::create_dir_all(targets.legacy_plugin_path.parent().unwrap()).unwrap();
        fs::write(
            &targets.legacy_plugin_path,
            render_plugin("ptuf", "0", OpencodeGeneration::V2),
        )
        .unwrap();
        assert!(matches!(
            auto_generation(&targets),
            Err(InitError::Schema { .. })
        ));
    }

    #[test]
    fn auto_generation_propagates_read_errors() {
        let dir = tempfile::tempdir().unwrap();
        let targets = test_targets(dir.path(), dir.path().join("ptuf.ts"));
        fs::create_dir_all(&targets.plugin_path).unwrap();
        assert!(matches!(
            auto_generation(&targets),
            Err(InitError::Io { .. })
        ));
    }

    #[test]
    fn resolve_paths_global_uses_xdg_config_home() {
        let env = MapEnv::new(&[("XDG_CONFIG_HOME", "/xdg")]);
        let options = OpencodeInitOptions::default();
        let targets = resolve_paths_with(None, &env, &options).unwrap();
        assert_eq!(
            targets.plugin_path,
            PathBuf::from("/xdg/opencode/plugins/ptuf.ts")
        );
        assert_eq!(
            targets.legacy_plugin_path,
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
            home.join(".config/opencode/plugins/ptuf.ts")
        );
        assert_eq!(
            targets.legacy_plugin_path,
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
        assert_eq!(targets.plugin_path, dir.join(".opencode/plugins/ptuf.ts"));
        assert_eq!(
            targets.legacy_plugin_path,
            dir.join(".opencode/plugin/ptuf.ts")
        );
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
        let targets = test_targets(&dir, plugin.clone());
        let outcome = install(&targets, "/bin/ptuf", OpencodeGeneration::V2, true).unwrap();
        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!plugin.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_writes_managed_marker_and_binary_path() {
        let dir = workdir("install");
        let plugin = dir.join("ptuf.ts");
        let targets = test_targets(&dir, plugin.clone());
        let outcome = install(&targets, "/bin/ptuf", OpencodeGeneration::V2, false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = fs::read_to_string(&plugin).unwrap();
        assert!(body.contains(MANAGED_MARKER));
        assert!(body.contains(AGENT_MARKER_V2));
        assert!(body.contains("/bin/ptuf"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_v1_writes_v1_marker_and_pinned_token() {
        let dir = workdir("install-v1");
        let plugin = dir.join("ptuf.ts");
        let targets = test_targets(&dir, plugin.clone());
        let outcome = install(&targets, "/bin/ptuf", OpencodeGeneration::V1, false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = fs::read_to_string(&plugin).unwrap();
        assert!(body.contains(AGENT_MARKER_V1));
        assert!(body.contains(r#"["hook", "opencode-v1"]"#));
        assert!(outcome.command.ends_with("hook opencode-v1"));
        assert!(outcome.matcher.contains("v1 API"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_v2_reports_pinned_command_and_matcher() {
        let dir = workdir("install-v2-report");
        let plugin = dir.join("ptuf.ts");
        let targets = test_targets(&dir, plugin.clone());
        let outcome = install(&targets, "/bin/ptuf", OpencodeGeneration::V2, false).unwrap();
        assert!(outcome.command.ends_with("hook opencode-v2"));
        assert!(outcome.matcher.contains("v2 API"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_v2_upgrades_a_managed_v1_plugin_at_the_same_path() {
        let dir = workdir("upgrade-v1-to-v2");
        let plugin = dir.join("ptuf.ts");
        let targets = test_targets(&dir, plugin.clone());
        fs::write(
            &plugin,
            render_plugin("/old/ptuf", "0.0.0", OpencodeGeneration::V1),
        )
        .unwrap();
        let outcome = install(&targets, "/new/ptuf", OpencodeGeneration::V2, false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = fs::read_to_string(&plugin).unwrap();
        assert!(body.contains(AGENT_MARKER_V2));
        assert!(body.contains(r#"["hook", "opencode-v2"]"#));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_refuses_unmanaged_existing_plugin() {
        let dir = workdir("conflict");
        let plugin = dir.join("ptuf.ts");
        fs::write(&plugin, "// user plugin\n").unwrap();
        let targets = test_targets(&dir, plugin.clone());
        let err = install(&targets, "/bin/ptuf", OpencodeGeneration::V2, false)
            .expect_err("must conflict");
        assert!(matches!(err, InitError::HookFileConflict { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_already_present_when_desired_matches() {
        let dir = workdir("already");
        let plugin = dir.join("ptuf.ts");
        let targets = test_targets(&dir, plugin.clone());
        let desired = render_plugin(
            "/bin/ptuf",
            env!("CARGO_PKG_VERSION"),
            OpencodeGeneration::V2,
        );
        fs::write(&plugin, &desired).unwrap();
        let outcome = install(&targets, "/bin/ptuf", OpencodeGeneration::V2, false).unwrap();
        assert_eq!(outcome.status, InstallStatus::AlreadyPresent);
        assert_eq!(outcome.agent, "opencode");
        assert_eq!(outcome.matcher, OpencodeGeneration::V2.matcher());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_updates_managed_plugin_when_binary_changes() {
        let dir = workdir("update");
        let plugin = dir.join("ptuf.ts");
        let targets = test_targets(&dir, plugin.clone());
        fs::write(
            &plugin,
            render_plugin("/old/ptuf", "0.0.0", OpencodeGeneration::V2),
        )
        .unwrap();
        let outcome = install(&targets, "/new/ptuf", OpencodeGeneration::V2, false).unwrap();
        assert_eq!(outcome.status, InstallStatus::Installed);
        let body = fs::read_to_string(&plugin).unwrap();
        assert!(body.contains("/new/ptuf"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_removes_legacy_managed_plugin_to_avoid_double_loading() {
        let dir = workdir("migrate-legacy");
        let plugin = dir.join("plugins").join("ptuf.ts");
        let legacy = dir.join("plugin").join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            plugin_path: plugin.clone(),
            legacy_plugin_path: legacy.clone(),
        };
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(
            &legacy,
            render_plugin("/old/ptuf", "0.0.0", OpencodeGeneration::V1),
        )
        .unwrap();

        let outcome = install(&targets, "/new/ptuf", OpencodeGeneration::V2, false).unwrap();

        assert_eq!(outcome.status, InstallStatus::Installed);
        assert!(plugin.exists(), "new plural plugin path must be written");
        assert!(
            !legacy.exists(),
            "old managed singular plugin must be removed"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_keeps_unmanaged_legacy_plugin() {
        let dir = workdir("keep-legacy-user");
        let plugin = dir.join("plugins").join("ptuf.ts");
        let legacy = dir.join("plugin").join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            plugin_path: plugin.clone(),
            legacy_plugin_path: legacy.clone(),
        };
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, "// user-owned plugin\n").unwrap();

        let outcome = install(&targets, "/new/ptuf", OpencodeGeneration::V2, false).unwrap();

        assert_eq!(outcome.status, InstallStatus::Installed);
        assert!(plugin.exists(), "new plural plugin path must be written");
        assert!(
            legacy.exists(),
            "user-owned legacy plugin must be left alone"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_dry_run_keeps_legacy_managed_plugin() {
        let dir = workdir("dry-run-legacy");
        let plugin = dir.join("plugins").join("ptuf.ts");
        let legacy = dir.join("plugin").join("ptuf.ts");
        let targets = TargetPaths {
            root: dir.clone(),
            plugin_path: plugin.clone(),
            legacy_plugin_path: legacy.clone(),
        };
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(
            &legacy,
            render_plugin("/old/ptuf", "0.0.0", OpencodeGeneration::V1),
        )
        .unwrap();

        let outcome = install(&targets, "/new/ptuf", OpencodeGeneration::V2, true).unwrap();

        assert_eq!(outcome.status, InstallStatus::WouldInstall);
        assert!(!plugin.exists(), "dry-run must not write plural plugin");
        assert!(legacy.exists(), "dry-run must not remove legacy plugin");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_ptuf_managed_requires_all_markers() {
        assert!(!is_ptuf_managed(b"// random file\n"));
        assert!(is_ptuf_managed(&render_plugin(
            "/bin/ptuf",
            "1.0.0",
            OpencodeGeneration::V1
        )));
        assert!(is_ptuf_managed(&render_plugin(
            "/bin/ptuf",
            "1.0.0",
            OpencodeGeneration::V2
        )));
    }

    #[test]
    fn is_ptuf_managed_recognises_pre_v2_installs() {
        // A file written by a ptuf release before the v2 adapter existed:
        // agent marker without a `-v1` suffix and the floating
        // `hook opencode` command. It must still be recognized so the next
        // `ptuf init` can migrate it in place.
        let legacy = "// Managed by ptuf. Do not edit manually.\n\
            // ptuf-agent: opencode\n\
            // ptuf-binary: \"/bin/ptuf\"\n\
            const args = [\"hook\", \"opencode\"];\n";
        assert!(is_ptuf_managed(legacy.as_bytes()));
    }

    #[test]
    fn resolve_paths_delegates_to_resolve_paths_with() {
        let options = OpencodeInitOptions::default();
        let targets = resolve_paths(None, &options).expect("HOME is set in test env");
        assert!(targets.plugin_path.ends_with("plugins/ptuf.ts"));
    }

    #[test]
    fn resolve_paths_local_errors_outside_repo() {
        let dir = PathBuf::from("/definitely-no-such-ptuf-opencode-repo");
        let options = OpencodeInitOptions {
            scope: OpencodeScope::Local,
            root: None,
        };
        let err = resolve_paths_with(Some(dir.as_path()), &MapEnv::new(&[]), &options)
            .expect_err("no repo");
        assert!(matches!(err, InitError::RepoRootNotFound));
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
        assert_eq!(targets.plugin_path, dir.join(".opencode/plugins/ptuf.ts"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn install_marks_plugin_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workdir("mode");
        let plugin = dir.join("ptuf.ts");
        let targets = test_targets(&dir, plugin.clone());
        install(&targets, "/bin/ptuf", OpencodeGeneration::V2, false).unwrap();
        let mode = fs::metadata(&plugin).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_propagates_read_error_when_plugin_path_is_a_directory() {
        let dir = workdir("install-read-fail");
        let plugin = dir.join("ptuf.ts");
        fs::create_dir_all(&plugin).unwrap();
        let targets = test_targets(&dir, plugin.clone());
        let err = install(&targets, "/bin/ptuf", OpencodeGeneration::V2, false)
            .expect_err("read on dir must fail");
        assert!(matches!(err, InitError::Io { .. }), "got {err:?}");
        let _ = fs::remove_dir_all(&dir);
    }
}
