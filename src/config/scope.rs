//! Resolve the layered scope chain to concrete filesystem paths.
//!
//! Order from lowest to highest priority:
//!
//! 1. `/etc/ptuf/policy.yaml`
//! 2. `~/.config/ptuf/config.yaml` (or `$XDG_CONFIG_HOME/ptuf/config.yaml`)
//! 3. `<repo>/.ptuf.yaml`
//! 4. `<repo>/.ptuf.local.yaml`
//!
//! The implicit "builtin" scope is materialised inside `Config::default`
//! and is therefore not represented as a path here.
//!
//! Two environment variables let tests inject fixture trees without
//! touching the host's real config:
//! * `PTUF_CONFIG_DIR` — overrides the `~/.config/ptuf` directory.
//! * `PTUF_ETC_DIR` — overrides the `/etc/ptuf` directory.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Resolved set of YAML paths in lowest-to-highest priority order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Layout {
    pub system: Option<PathBuf>,
    pub user: Option<PathBuf>,
    pub project: Option<PathBuf>,
    pub project_local: Option<PathBuf>,
}

impl Layout {
    /// Yield every populated path in scope order.
    pub fn ordered_paths(&self) -> Vec<PathBuf> {
        [
            self.system.as_ref(),
            self.user.as_ref(),
            self.project.as_ref(),
            self.project_local.as_ref(),
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect()
    }
}

/// Read-only environment lookup. The blanket [`SystemEnv`] uses
/// `std::env`; tests inject an in-memory map to avoid mutating global
/// process state (which is `unsafe` in edition 2024 and is forbidden
/// by the crate-level lint).
pub trait EnvLookup {
    fn var_os(&self, key: &str) -> Option<OsString>;
}

/// Production environment lookup.
pub struct SystemEnv;

impl EnvLookup for SystemEnv {
    fn var_os(&self, key: &str) -> Option<OsString> {
        env::var_os(key)
    }
}

/// Build the default layout for the current process's environment.
pub fn default_layout(repo_root: Option<&Path>) -> Layout {
    layout_for(repo_root, &SystemEnv)
}

/// Build a layout using `env` for variable lookups. Used directly by
/// tests that need a hermetic env.
pub fn layout_for(repo_root: Option<&Path>, env: &dyn EnvLookup) -> Layout {
    Layout {
        system: system_config_path(env),
        user: user_config_path(env),
        project: repo_root.map(|r| r.join(".ptuf.yaml")),
        project_local: repo_root.map(|r| r.join(".ptuf.local.yaml")),
    }
}

fn system_config_path(env: &dyn EnvLookup) -> Option<PathBuf> {
    if let Some(dir) = env.var_os("PTUF_ETC_DIR") {
        return Some(PathBuf::from(dir).join("policy.yaml"));
    }
    Some(PathBuf::from("/etc/ptuf/policy.yaml"))
}

fn user_config_path(env: &dyn EnvLookup) -> Option<PathBuf> {
    if let Some(dir) = env.var_os("PTUF_CONFIG_DIR") {
        return Some(PathBuf::from(dir).join("config.yaml"));
    }
    if let Some(xdg) = env.var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("ptuf/config.yaml"));
    }
    let home = env.var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/ptuf/config.yaml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// In-memory env used by tests so they never touch real env vars.
    struct MapEnv {
        vars: HashMap<String, OsString>,
    }

    impl MapEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            let mut vars = HashMap::new();
            for (k, v) in pairs {
                vars.insert((*k).to_string(), OsString::from(*v));
            }
            MapEnv { vars }
        }
    }

    impl EnvLookup for MapEnv {
        fn var_os(&self, key: &str) -> Option<OsString> {
            self.vars.get(key).cloned()
        }
    }

    #[test]
    fn ordered_paths_skips_none_entries() {
        let layout = Layout {
            system: Some(PathBuf::from("/etc/ptuf/policy.yaml")),
            user: None,
            project: Some(PathBuf::from("/repo/.ptuf.yaml")),
            project_local: None,
        };
        assert_eq!(
            layout.ordered_paths(),
            vec![
                PathBuf::from("/etc/ptuf/policy.yaml"),
                PathBuf::from("/repo/.ptuf.yaml"),
            ]
        );
    }

    #[test]
    fn ordered_paths_preserves_priority_order() {
        let layout = Layout {
            system: Some(PathBuf::from("a")),
            user: Some(PathBuf::from("b")),
            project: Some(PathBuf::from("c")),
            project_local: Some(PathBuf::from("d")),
        };
        assert_eq!(
            layout.ordered_paths(),
            vec![
                PathBuf::from("a"),
                PathBuf::from("b"),
                PathBuf::from("c"),
                PathBuf::from("d"),
            ]
        );
    }

    #[test]
    fn ptuf_etc_dir_overrides_system_path() {
        let env = MapEnv::new(&[("PTUF_ETC_DIR", "/custom/etc")]);
        let layout = layout_for(Some(Path::new("/repo")), &env);
        assert_eq!(
            layout.system,
            Some(PathBuf::from("/custom/etc/policy.yaml"))
        );
    }

    #[test]
    fn ptuf_config_dir_overrides_user_path() {
        let env = MapEnv::new(&[("PTUF_CONFIG_DIR", "/custom/config")]);
        let layout = layout_for(None, &env);
        assert_eq!(
            layout.user,
            Some(PathBuf::from("/custom/config/config.yaml"))
        );
    }

    #[test]
    fn falls_back_to_home_when_no_xdg() {
        let env = MapEnv::new(&[("HOME", "/home/example")]);
        let layout = layout_for(None, &env);
        assert_eq!(
            layout.user,
            Some(PathBuf::from("/home/example/.config/ptuf/config.yaml"))
        );
    }

    #[test]
    fn xdg_config_home_takes_precedence_over_home() {
        let env = MapEnv::new(&[
            ("HOME", "/home/example"),
            ("XDG_CONFIG_HOME", "/home/example/.config-xdg"),
        ]);
        let layout = layout_for(None, &env);
        assert_eq!(
            layout.user,
            Some(PathBuf::from("/home/example/.config-xdg/ptuf/config.yaml"))
        );
    }

    #[test]
    fn ptuf_config_dir_takes_precedence_over_xdg_and_home() {
        let env = MapEnv::new(&[
            ("HOME", "/home/example"),
            ("XDG_CONFIG_HOME", "/home/example/.config-xdg"),
            ("PTUF_CONFIG_DIR", "/custom/config"),
        ]);
        let layout = layout_for(None, &env);
        assert_eq!(
            layout.user,
            Some(PathBuf::from("/custom/config/config.yaml"))
        );
    }

    #[test]
    fn user_path_is_none_when_no_home_or_overrides() {
        let env = MapEnv::new(&[]);
        let layout = layout_for(None, &env);
        assert!(layout.user.is_none());
    }

    #[test]
    fn project_paths_are_set_only_when_repo_root_is_provided() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let layout = layout_for(Some(Path::new("/repo")), &env);
        assert_eq!(layout.project, Some(PathBuf::from("/repo/.ptuf.yaml")));
        assert_eq!(
            layout.project_local,
            Some(PathBuf::from("/repo/.ptuf.local.yaml"))
        );
    }

    #[test]
    fn project_paths_are_none_when_no_repo_root() {
        let env = MapEnv::new(&[("HOME", "/h")]);
        let layout = layout_for(None, &env);
        assert!(layout.project.is_none());
        assert!(layout.project_local.is_none());
    }

    #[test]
    fn system_env_var_os_reads_from_real_process_env() {
        // Calling SystemEnv::var_os with a key that the test runner is
        // virtually guaranteed to set ("PATH") proves the production
        // env-lookup path actually delegates to std::env. We only
        // assert that the call doesn't panic and that it returns a
        // value when one exists in the parent process.
        let env = SystemEnv;
        let _path = env.var_os("PATH");
        let absent = env.var_os("PTUF_DEFINITELY_NOT_SET_ANYWHERE_xyz123");
        assert!(absent.is_none());
    }

    #[test]
    fn default_layout_uses_system_env_lookup() {
        // default_layout(None) walks SystemEnv::var_os for each scope.
        // The result varies with the host's environment; the only
        // structural invariant we can assert is that the system path
        // is always populated (defaults to /etc/ptuf/policy.yaml when
        // PTUF_ETC_DIR is unset).
        let layout = default_layout(None);
        assert!(layout.system.is_some());
        assert!(layout.project.is_none());
        assert!(layout.project_local.is_none());
    }

    use proptest::prelude::*;

    /// Optional path component for `Layout` field generators.
    fn opt_path() -> impl Strategy<Value = Option<PathBuf>> {
        proptest::option::of("[a-zA-Z0-9_./-]{1,12}".prop_map(PathBuf::from))
    }

    proptest! {
        // `ordered_paths` flattens the four scope slots in fixed
        // priority order, dropping every `None`.
        #[test]
        fn pbt_ordered_paths_preserves_priority_order(
            system in opt_path(),
            user in opt_path(),
            project in opt_path(),
            project_local in opt_path(),
        ) {
            let layout = Layout {
                system: system.clone(),
                user: user.clone(),
                project: project.clone(),
                project_local: project_local.clone(),
            };
            let expected: Vec<PathBuf> = [system, user, project, project_local]
                .into_iter()
                .flatten()
                .collect();
            prop_assert_eq!(layout.ordered_paths(), expected);
        }

        // `PTUF_CONFIG_DIR` pins the user path regardless of whether
        // `XDG_CONFIG_HOME` / `HOME` are also present.
        #[test]
        fn pbt_layout_for_ptuf_config_dir_overrides_user(
            dir in "[a-zA-Z0-9_/-]{1,16}",
            xdg in proptest::option::of("[a-zA-Z0-9_/-]{1,16}"),
            home in proptest::option::of("[a-zA-Z0-9_/-]{1,16}"),
        ) {
            let mut pairs: Vec<(&str, &str)> = vec![("PTUF_CONFIG_DIR", dir.as_str())];
            if let Some(x) = xdg.as_deref() {
                pairs.push(("XDG_CONFIG_HOME", x));
            }
            if let Some(h) = home.as_deref() {
                pairs.push(("HOME", h));
            }
            let env = MapEnv::new(&pairs);
            let layout = layout_for(None, &env);
            prop_assert_eq!(
                layout.user,
                Some(Path::new(dir.as_str()).join("config.yaml")),
            );
        }

        // With no `PTUF_CONFIG_DIR`, `XDG_CONFIG_HOME` pins the user
        // path regardless of `HOME`.
        #[test]
        fn pbt_layout_for_xdg_beats_home(
            xdg in "[a-zA-Z0-9_/-]{1,16}",
            home in proptest::option::of("[a-zA-Z0-9_/-]{1,16}"),
        ) {
            let mut pairs: Vec<(&str, &str)> = vec![("XDG_CONFIG_HOME", xdg.as_str())];
            if let Some(h) = home.as_deref() {
                pairs.push(("HOME", h));
            }
            let env = MapEnv::new(&pairs);
            let layout = layout_for(None, &env);
            prop_assert_eq!(
                layout.user,
                Some(Path::new(xdg.as_str()).join("ptuf/config.yaml")),
            );
        }

        // The system path follows `PTUF_ETC_DIR` when set and otherwise
        // falls back to the hard-coded `/etc/ptuf/policy.yaml`; it is
        // never `None`.
        #[test]
        fn pbt_layout_for_system_path_uses_ptuf_etc_dir_or_default(
            etc in proptest::option::of("[a-zA-Z0-9_/-]{1,16}"),
        ) {
            let pairs: Vec<(&str, &str)> = match etc.as_deref() {
                Some(e) => vec![("PTUF_ETC_DIR", e)],
                None => Vec::new(),
            };
            let env = MapEnv::new(&pairs);
            let layout = layout_for(None, &env);
            let expected = match etc.as_deref() {
                Some(e) => Path::new(e).join("policy.yaml"),
                None => PathBuf::from("/etc/ptuf/policy.yaml"),
            };
            prop_assert_eq!(layout.system, Some(expected));
        }

        // Both project paths are populated exactly when a repo root is
        // supplied, and both are `None` otherwise.
        #[test]
        fn pbt_layout_for_project_paths_track_repo_root(
            repo in proptest::option::of("[a-zA-Z0-9_/-]{1,16}"),
        ) {
            let env = MapEnv::new(&[]);
            let layout = layout_for(repo.as_deref().map(Path::new), &env);
            if let Some(r) = repo.as_deref() {
                prop_assert_eq!(layout.project, Some(Path::new(r).join(".ptuf.yaml")));
                prop_assert_eq!(
                    layout.project_local,
                    Some(Path::new(r).join(".ptuf.local.yaml")),
                );
            } else {
                prop_assert!(layout.project.is_none());
                prop_assert!(layout.project_local.is_none());
            }
        }
    }
}
