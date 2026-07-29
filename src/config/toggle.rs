//! Read-modify-write helpers for the `ptuf readonly on|off` CLI.
//!
//! Writes only the top-level `readonly:` key, preserving every other
//! YAML key via a `serde_yaml_ng::Value` round-trip. Uses tmp+rename so
//! a concurrent hook subprocess never observes a partial file.

use std::fs;
use std::path::{Path, PathBuf};

use serde_yaml_ng::Value;

use super::scope::{self, EnvLookup, SystemEnv};
use super::{ConfigError, repo};

/// Where `ptuf readonly` should write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadonlyTarget {
    pub path: PathBuf,
    /// Human-readable scope label (`project-local` / `user`).
    pub scope: &'static str,
}

/// Resolve the write target: `<repo>/.ptuf.local.yaml` when a repo is
/// found and `--global` is not set; otherwise the user config path.
pub fn resolve_target(global: bool, cwd: &Path, env: &dyn EnvLookup) -> Option<ReadonlyTarget> {
    if !global && let Some(root) = repo::discover(cwd) {
        return Some(ReadonlyTarget {
            path: root.join(".ptuf.local.yaml"),
            scope: "project-local",
        });
    }
    let layout = scope::layout_for(None, env);
    layout.user.map(|path| ReadonlyTarget {
        path,
        scope: "user",
    })
}

/// Resolve using the process environment and current directory.
pub fn resolve_target_default(global: bool) -> Result<ReadonlyTarget, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("cannot determine cwd: {e}"))?;
    resolve_target(global, &cwd, &SystemEnv)
        .ok_or_else(|| "cannot resolve a writable config path (set HOME or PTUF_CONFIG_DIR)".into())
}

/// Set `readonly:` in `path` (creating parent dirs / the file as needed)
/// and atomically replace the file.
pub fn set_readonly(path: &Path, value: bool) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| ConfigError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let existing = if path.is_file() {
        fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?
    } else {
        String::new()
    };
    let mut doc: Value = if existing.trim().is_empty() {
        Value::Mapping(serde_yaml_ng::Mapping::new())
    } else {
        serde_yaml_ng::from_str(&existing).map_err(|e| ConfigError::Yaml {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?
    };
    match &mut doc {
        Value::Mapping(map) => {
            map.insert(Value::String("readonly".into()), Value::Bool(value));
        },
        other => {
            return Err(ConfigError::Yaml {
                path: path.to_path_buf(),
                message: format!("top-level YAML must be a mapping, got {other:?}"),
            });
        },
    }
    let rendered = serde_yaml_ng::to_string(&doc).map_err(|e| ConfigError::Yaml {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    atomic_write(path, &rendered)
}

fn atomic_write(path: &Path, contents: &str) -> Result<(), ConfigError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(".ptuf-readonly-{}.tmp", std::process::id()));
    fs::write(&tmp, contents).map_err(|e| ConfigError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::scope::MapEnv;
    use std::path::PathBuf;

    #[test]
    fn resolve_prefers_project_local_when_repo_present() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-ro-target-{}-{}", std::process::id(), line!()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".git")).expect("mkdir");
        let env = MapEnv::new(&[("HOME", "/home/x")]);
        let t = resolve_target(false, &dir, &env).expect("target");
        assert_eq!(t.path, dir.join(".ptuf.local.yaml"));
        assert_eq!(t.scope, "project-local");
        let t = resolve_target(true, &dir, &env).expect("global");
        assert_eq!(t.path, PathBuf::from("/home/x/.config/ptuf/config.yaml"));
        assert_eq!(t.scope, "user");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_readonly_preserves_other_keys() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-ro-write-{}-{}", std::process::id(), line!()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(".ptuf.local.yaml");
        fs::write(
            &path,
            "mode: monitor\npacks:\n  core.network:\n    enabled: false\n",
        )
        .expect("write");
        set_readonly(&path, true).expect("set");
        let body = fs::read_to_string(&path).expect("read");
        assert!(body.contains("readonly: true"));
        assert!(body.contains("mode: monitor"));
        assert!(body.contains("core.network"));
        set_readonly(&path, false).expect("clear");
        let body = fs::read_to_string(&path).expect("read");
        assert!(body.contains("readonly: false"));
        assert!(body.contains("mode: monitor"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_readonly_creates_missing_file() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-ro-create-{}-{}", std::process::id(), line!()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("nested").join("config.yaml");
        set_readonly(&path, true).expect("create");
        let body = fs::read_to_string(&path).expect("read");
        assert!(body.contains("readonly: true"));
        let _ = fs::remove_dir_all(&dir);
    }
}
