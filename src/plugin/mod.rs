//! YAML-defined plugins.
//!
//! v0.2 introduces a small but real plugin system: an
//! `apiVersion: ptuf.dev/v1, kind: Plugin` document yields zero or more
//! [`PluginRule`]s the [`crate::Engine`] evaluates alongside the
//! built-ins. Plugins cannot reach raw shell strings; they describe
//! conditions in terms of the facts ptuf already extracts (see
//! [`SUPPORTED_FACTS`]).
//!
//! See `docs/design/config-and-plugins.md:91-214` for the YAML schema
//! and `docs/design/decision-model.md` for how rule outputs aggregate.

pub mod dsl;
pub mod loader;
pub mod rule;
pub mod schema;

use std::path::PathBuf;

pub use loader::{LoadedPlugin, SUPPORTED_FACTS, load_path, load_str};
pub use rule::PluginRule;

/// Errors raised while loading or compiling a plugin.
#[derive(Debug)]
pub enum PluginError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Yaml {
        path: PathBuf,
        message: String,
    },
    ApiVersion {
        path: PathBuf,
        found: String,
    },
    Kind {
        path: PathBuf,
        found: String,
    },
    UnsupportedFact {
        path: PathBuf,
        name: String,
    },
    Compile {
        path: PathBuf,
        rule_id: String,
        message: String,
    },
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginError::Io { path, source } => {
                write!(f, "plugin: read {}: {source}", path.display())
            }
            PluginError::Yaml { path, message } => {
                write!(f, "plugin: parse {}: {message}", path.display())
            }
            PluginError::ApiVersion { path, found } => {
                write!(
                    f,
                    "plugin {}: unsupported apiVersion `{found}` (expected `ptuf.dev/v1`)",
                    path.display()
                )
            }
            PluginError::Kind { path, found } => {
                write!(
                    f,
                    "plugin {}: unsupported kind `{found}` (expected `Plugin`)",
                    path.display()
                )
            }
            PluginError::UnsupportedFact { path, name } => {
                write!(
                    f,
                    "plugin {}: requires fact `{name}` which this version of ptuf does not provide",
                    path.display()
                )
            }
            PluginError::Compile {
                path,
                rule_id,
                message,
            } => {
                write!(f, "plugin {}: rule `{rule_id}`: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for PluginError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PluginError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A bundle of every plugin loaded for one engine run. Holds owned
/// plugin instances and exposes a flat iterator over their rules so
/// the engine treats plugin rules and built-in rules uniformly.
#[derive(Debug, Default)]
pub struct PluginSet {
    pub plugins: Vec<LoadedPlugin>,
}

impl PluginSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, plugin: LoadedPlugin) {
        self.plugins.push(plugin);
    }

    pub fn rule_count(&self) -> usize {
        self.plugins.iter().map(LoadedPlugin::rule_count).sum()
    }

    /// Iterate over every rule contributed by every loaded plugin.
    pub fn rules(&self) -> impl Iterator<Item = &PluginRule> {
        self.plugins.iter().flat_map(|p| p.rules.iter())
    }

    /// Load and append plugins listed in `paths`. Returns the first
    /// error encountered, if any.
    pub fn load_paths(&mut self, paths: &[PathBuf]) -> Result<(), PluginError> {
        for path in paths {
            self.push(load_path(path)?);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::path::Path;

    fn ok_plugin(name: &str) -> LoadedPlugin {
        let yaml = format!(
            r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: {name}
rules:
  - id: {name}.x
    severity: low
    defaultDecision: deny
    when:
      tool: Bash
    reason: r
"#
        );
        load_str(Path::new(&format!("{name}.yaml")), &yaml).expect("load")
    }

    #[test]
    fn empty_plugin_set_iterates_no_rules() {
        let set = PluginSet::new();
        assert_eq!(set.rule_count(), 0);
        assert_eq!(set.rules().count(), 0);
    }

    #[test]
    fn pushed_plugins_contribute_rules() {
        let mut set = PluginSet::new();
        set.push(ok_plugin("a"));
        set.push(ok_plugin("b"));
        assert_eq!(set.rule_count(), 2);
        assert_eq!(set.rules().count(), 2);
    }

    #[test]
    fn plugin_error_io_chain_is_visible_via_source() {
        let err = PluginError::Io {
            path: PathBuf::from("/nope"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "x"),
        };
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_some());
        assert!(format!("{err}").contains("/nope"));
    }

    #[test]
    fn plugin_error_display_covers_every_variant() {
        let p = PathBuf::from("p.yaml");
        let cases = [
            PluginError::Yaml {
                path: p.clone(),
                message: "bad".into(),
            },
            PluginError::ApiVersion {
                path: p.clone(),
                found: "vX".into(),
            },
            PluginError::Kind {
                path: p.clone(),
                found: "Cfg".into(),
            },
            PluginError::UnsupportedFact {
                path: p.clone(),
                name: "url.parse".into(),
            },
            PluginError::Compile {
                path: p.clone(),
                rule_id: "r".into(),
                message: "no".into(),
            },
        ];
        for e in &cases {
            assert!(format!("{e}").contains("p.yaml"));
        }
    }
}
