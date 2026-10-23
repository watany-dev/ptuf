//! Configuration model for ptuf.
//!
//! [`Config`] is the resolved view applied at runtime. Each policy
//! scope (`/etc/ptuf`, `~/.config/ptuf`, `<repo>/.ptuf.yaml`,
//! `<repo>/.ptuf.local.yaml`) deserialises into a `schema::RawConfig`
//! whose fields are all optional; `merge::merge` folds those layers
//! (lowest first) into a single [`Config`].
//!
//! `load_for` orchestrates the layered load: it walks the documented
//! scope order, parses each YAML that exists via [`yaml`] and discards
//! missing scopes silently. Errors carry the offending path so that
//! `failClosed` mode can surface them to the user.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::decision::{DecisionKind, Severity};
use crate::plugin::dsl::WhenNode;

pub mod merge;
pub(crate) mod repo;
pub(crate) mod schema;

// `schema` itself is internal; `RawConfig` is re-exported because it
// is the value `yaml::parse_str` hands to `merge::merge`, the pair of
// trust boundaries the `fuzz/` workspace drives.
pub use schema::RawConfig;
pub(crate) mod scope;
pub mod yaml;

/// Operating mode for the engine.
///
/// `Enforce` (default) honours `Decision::Deny` as a blocking deny.
/// `Monitor` demotes denies to `Monitor` so that the hook never blocks
/// the agent but still records the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Enforce,
    Monitor,
}

/// Resolved runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    pub fail_closed: bool,
    /// Per-pack overrides keyed by pack name (`core.network`).
    /// A rule whose id starts with `<pack>.` inherits the pack toggle.
    pub pack_overrides: BTreeMap<String, PackOverride>,
    /// Per-rule overrides keyed by exact rule id. These are applied by
    /// the engine after a rule fires so `hardDeny` / `overridable`
    /// metadata can be enforced against the concrete rule.
    pub rule_overrides: BTreeMap<String, RuleOverride>,
    /// Time-bound exceptions; later commits gate them by `expires_at`.
    pub allowlists: Vec<Allowlist>,
    /// Filesystem paths of `apiVersion: ptuf.dev/v1, kind: Plugin`
    /// YAML files that the engine should load. Lower scopes are
    /// listed first; the engine loads them in order.
    pub plugin_paths: Vec<PathBuf>,
    pub audit: AuditConfig,
    /// Branch names / glob patterns considered "protected" by
    /// `core.project_hygiene`. Default: `main`, `master`, `release/*`.
    /// A higher scope's value replaces lower scopes wholesale rather
    /// than merging, so projects can override the default cleanly.
    pub protected_branches: Vec<String>,
    /// Extra workspace boundaries consumed by
    /// `core.workspace.outside-access`. Stored raw (with `~` un-expanded);
    /// the engine canonicalises them when constructing `Engine.workspaces`.
    /// A higher scope's value replaces lower scopes wholesale.
    pub additional_workspaces: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        let mut pack_overrides: BTreeMap<String, PackOverride> = BTreeMap::new();
        // core.project_hygiene is opt-in: lock-mismatch / protected
        // branch denials would derail dev flows for projects that have
        // not opted into them.
        pack_overrides.insert(
            "core.project_hygiene".to_string(),
            PackOverride {
                enabled: Some(false),
            },
        );
        // core.workspace is opt-in: outside-access also denies Read,
        // which would block reads of external libraries (~/.cargo/...,
        // /usr/include) for projects that have not opted into the boundary.
        pack_overrides.insert(
            "core.workspace".to_string(),
            PackOverride {
                enabled: Some(false),
            },
        );
        Self {
            mode: Mode::default(),
            fail_closed: true,
            pack_overrides,
            rule_overrides: BTreeMap::new(),
            allowlists: Vec::new(),
            plugin_paths: Vec::new(),
            audit: AuditConfig::default(),
            protected_branches: vec!["main".into(), "master".into(), "release/*".into()],
            additional_workspaces: Vec::new(),
        }
    }
}

/// Per-pack overlay applied on top of a pack's static defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackOverride {
    /// `Some(false)` disables every rule in this pack, `Some(true)`
    /// re-enables a pack that an outer scope disabled. `None` leaves
    /// the pack's default in place.
    pub enabled: Option<bool>,
}

/// Per-rule overlay applied after a rule has matched.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleOverride {
    pub enabled: Option<bool>,
    pub decision: Option<DecisionKind>,
    pub severity: Option<Severity>,
}

/// Time-bound exception scoped to one or more rule ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    pub id: String,
    pub rule_ids: Vec<String>,
    pub when: Option<WhenNode>,
    pub expires_at: Option<String>,
    pub reason: Option<String>,
}

/// Audit-sink configuration. Enabled audit with an absent path writes
/// to the documented default path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    pub enabled: bool,
    pub path: Option<PathBuf>,
    /// Record allow decisions. Defaults to `false` to keep the audit
    /// volume manageable.
    pub include_allowed: bool,
    /// Record deny decisions. Defaults to `true`.
    pub include_denied: bool,
    /// Strict redaction is the only supported mode in v0.2; the field
    /// is kept so the schema does not break when a future release
    /// introduces less aggressive policies.
    pub redaction: RedactionMode,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            include_allowed: false,
            include_denied: true,
            redaction: RedactionMode::default(),
        }
    }
}

/// Redaction strength. Only `Strict` is honoured today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedactionMode {
    #[default]
    Strict,
    /// Disabled — the user must opt in explicitly. Audit consumers
    /// should treat this as a self-inflicted risk.
    Off,
}

/// Documented default audit path (`$HOME/.local/share/ptuf/audit.jsonl`).
pub(crate) fn default_audit_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".local/share/ptuf/audit.jsonl"))
}

/// Resolved audit path after applying defaulting and `enabled`.
pub(crate) fn resolved_audit_path(config: &Config) -> Option<PathBuf> {
    if !config.audit.enabled {
        return None;
    }
    config.audit.path.clone().or_else(default_audit_path)
}

/// Errors raised while loading the layered policy.
#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Yaml {
        path: PathBuf,
        message: String,
    },
    Allowlist {
        path: PathBuf,
        id: String,
        message: String,
    },
    Version {
        path: PathBuf,
        found: u32,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read {}: {}", path.display(), source)
            },
            Self::Yaml { path, message } => {
                write!(f, "failed to parse {}: {}", path.display(), message)
            },
            Self::Allowlist { path, id, message } => {
                write!(
                    f,
                    "failed to parse {}: allowlist `{id}`: {message}",
                    path.display()
                )
            },
            Self::Version { path, found } => {
                write!(
                    f,
                    "failed to parse {}: unsupported version {found} (expected 1)",
                    path.display()
                )
            },
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Yaml { .. } | Self::Allowlist { .. } | Self::Version { .. } => None,
        }
    }
}

/// Walk the layered scope chain and merge each existing YAML into a
/// final [`Config`].
///
/// `repo_root` is the discovered project root (typically the closest
/// ancestor containing a `.git` directory or file). When `None`, only
/// the system / user scopes are considered.
///
/// `home_dir` and `etc_dir` overrides exist for testability — production
/// callers pass the real `$HOME` and `/etc/ptuf` paths via
/// [`scope::default_layout`].
pub(crate) fn load_for(repo_root: Option<&Path>) -> Result<Config, ConfigError> {
    load_with_layout(scope::default_layout(repo_root))
}

/// Load configuration given an explicit [`scope::Layout`]. Used by the
/// public [`load_for`] helper as well as by integration tests that
/// inject fixture directories.
pub(crate) fn load_with_layout(layout: scope::Layout) -> Result<Config, ConfigError> {
    let project_layers = [layout.project.as_deref(), layout.project_local.as_deref()];
    let mut layers = Vec::new();
    for path in layout.ordered_paths() {
        if !path.is_file() {
            continue;
        }
        let mut raw = yaml::load_path(&path)?;
        if project_layers.contains(&Some(path.as_path())) {
            confine_project_audit_path(&mut raw, &path);
        }
        layers.push(raw);
    }
    merge::merge(layers)
}

/// A repository's `.ptuf.yaml` / `.ptuf.local.yaml` arrives with the
/// clone and is not trusted to pick where ptuf writes: an `audit.path`
/// outside the repository (e.g. `~/.claude/settings.json` or
/// `~/.bashrc`) would let a cloned repo make every hook call append to
/// an arbitrary file. Keep the value only when it stays lexically inside
/// the directory holding the config file; otherwise drop it so a
/// lower (system / user) layer or the default path applies.
fn confine_project_audit_path(raw: &mut schema::RawConfig, config_path: &Path) {
    let Some(root) = config_path.parent() else {
        raw.audit.path = None;
        return;
    };
    let inside = raw.audit.path.as_deref().is_some_and(|p| {
        // Compare both spellings: the layout's root may already be
        // canonical (macOS `/var` → `/private/var`) while the YAML names
        // the symlinked form, or the other way round.
        let roots = [Some(root.to_path_buf()), std::fs::canonicalize(root).ok()];
        let paths = [Some(p.to_path_buf()), canonical_parent_join(p)];
        roots.iter().flatten().any(|r| {
            paths
                .iter()
                .flatten()
                .any(|candidate| lexically_inside(candidate, r))
        })
    });
    if !inside {
        raw.audit.path = None;
    }
}

fn lexically_inside(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root).is_ok_and(|rest| {
        rest.components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
    })
}

/// `p` with its parent directory canonicalized, when that parent exists.
fn canonical_parent_join(p: &Path) -> Option<PathBuf> {
    let name = p.file_name()?;
    let parent = std::fs::canonicalize(p.parent()?).ok()?;
    Some(parent.join(name))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn config_error_display_io_includes_path_and_source() {
        let err = ConfigError::Io {
            path: PathBuf::from("/etc/ptuf/policy.yaml"),
            source: io::Error::other("nope"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/etc/ptuf/policy.yaml"));
        assert!(msg.contains("nope"));
    }

    #[test]
    fn config_error_display_yaml_includes_path_and_message() {
        let err = ConfigError::Yaml {
            path: PathBuf::from("/repo/.ptuf.yaml"),
            message: "bad indent".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/repo/.ptuf.yaml"));
        assert!(msg.contains("bad indent"));
    }

    #[test]
    fn config_error_source_maps_variants() {
        let io_err = ConfigError::Io {
            path: PathBuf::from("/x"),
            source: io::Error::other("boom"),
        };
        let dyn_io: &dyn std::error::Error = &io_err;
        assert!(dyn_io.source().is_some());

        let yaml_err = ConfigError::Yaml {
            path: PathBuf::from("/x"),
            message: "broken".into(),
        };
        let dyn_yaml: &dyn std::error::Error = &yaml_err;
        assert!(dyn_yaml.source().is_none());

        let allow_err = ConfigError::Allowlist {
            path: PathBuf::from("/x"),
            id: "oops".into(),
            message: "when: unknown key".into(),
        };
        let dyn_allow: &dyn std::error::Error = &allow_err;
        assert!(dyn_allow.source().is_none());
        assert!(format!("{allow_err}").contains("oops"));

        let ver_err = ConfigError::Version {
            path: PathBuf::from("/x"),
            found: 2,
        };
        let dyn_ver: &dyn std::error::Error = &ver_err;
        assert!(dyn_ver.source().is_none());
        assert!(format!("{ver_err}").contains("version 2"));
    }

    #[test]
    fn project_layers_cannot_point_audit_outside_the_repository() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).expect("mkdir");
        let user = dir.path().join("user.yaml");
        std::fs::write(&user, "audit:\n  path: /var/log/ptuf/user.jsonl\n").expect("write");
        let layout = |project: &Path| scope::Layout {
            system: None,
            user: Some(user.clone()),
            project: Some(project.to_path_buf()),
            project_local: None,
        };
        let project = repo.join(".ptuf.yaml");
        for outside in [
            "~/.claude/settings.json",
            "/tmp/elsewhere.jsonl",
            "../sibling/audit.jsonl",
            "logs/../../escape.jsonl",
        ] {
            std::fs::write(&project, format!("audit:\n  path: {outside}\n")).expect("write");
            let cfg = load_with_layout(layout(&project)).expect("load");
            assert_eq!(
                cfg.audit.path,
                Some(PathBuf::from("/var/log/ptuf/user.jsonl")),
                "{outside} must fall back to the user layer"
            );
        }
        std::fs::write(&project, "audit:\n  path: logs/audit.jsonl\n").expect("write");
        let cfg = load_with_layout(layout(&project)).expect("load");
        assert_eq!(cfg.audit.path, Some(repo.join("logs/audit.jsonl")));
    }

    #[cfg(unix)]
    #[test]
    fn project_audit_path_through_a_symlinked_root_stays_inside() {
        // macOS tempdirs live under `/var` → `/private/var`: the layout
        // root and the YAML value can spell the same directory
        // differently.
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let project = real.join(".ptuf.yaml");
        let via_link = link.join("audit.jsonl");
        std::fs::write(
            &project,
            format!("audit:\n  path: {}\n", via_link.display()),
        )
        .expect("write");
        let layout = scope::Layout {
            system: None,
            user: None,
            project: Some(project.clone()),
            project_local: None,
        };
        let cfg = load_with_layout(layout).expect("load");
        assert_eq!(cfg.audit.path, Some(via_link));

        let link_project = link.join(".ptuf.yaml");
        let real_audit = real.join("audit.jsonl");
        std::fs::write(
            &project,
            format!("audit:\n  path: {}\n", real_audit.display()),
        )
        .expect("write");
        let layout = scope::Layout {
            system: None,
            user: None,
            project: Some(link_project),
            project_local: None,
        };
        let cfg = load_with_layout(layout).expect("load");
        assert_eq!(cfg.audit.path, Some(real_audit));
    }

    #[test]
    fn load_with_layout_reads_existing_files_and_merges() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-config-load-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let user = dir.join("user.yaml");
        std::fs::write(&user, "mode: monitor\n").expect("write");

        let layout = scope::Layout {
            system: None,
            user: Some(user.clone()),
            project: None,
            project_local: None,
        };
        let config = load_with_layout(layout).expect("load");
        assert_eq!(config.mode, Mode::Monitor);

        let _ = std::fs::remove_file(&user);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_with_layout_with_no_files_returns_default_config() {
        let layout = scope::Layout {
            system: Some(PathBuf::from("/nonexistent/does-not-exist.yaml")),
            user: None,
            project: None,
            project_local: None,
        };
        let config = load_with_layout(layout).expect("load");
        assert_eq!(config, Config::default());
    }
}
