//! [`EngineBuilder`] — constructs an [`Engine`] with explicit
//! components, always populating self-protection.
//!
//! Embed callers prefer [`Engine::for_cwd`] when configuration discovery
//! is available; the builder is the right shape when callers want to
//! inject a `Config`, [`PluginSet`], or `AuditSink` explicitly without
//! touching the filesystem. Unlike the removed `Engine::default` shim,
//! a builder-built engine always runs
//! [`ProtectedPaths::collect_with_env`] so the binary guardrail is in
//! place even when the caller passes `Config::default()`.

use std::path::PathBuf;
use std::sync::Mutex;

use crate::audit::{AuditSink, NoopSink};
use crate::config::Config;
use crate::facts;
use crate::plugin::PluginSet;
use crate::self_paths::ProtectedPaths;

use super::{Engine, EngineError, compute_plugin_versions, compute_workspaces};

/// Builder for [`Engine`] that always populates self-protection.
#[derive(Default)]
pub struct EngineBuilder {
    config: Option<Config>,
    repo_root: Option<PathBuf>,
    plugins: Option<PluginSet>,
    audit_sink: Option<Box<dyn AuditSink>>,
    agent: Option<&'static str>,
}

impl EngineBuilder {
    /// Use this `Config` instead of [`Config::default`].
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Anchor self-protection and project facts at this repo root.
    pub fn repo_root(mut self, repo_root: impl Into<PathBuf>) -> Self {
        self.repo_root = Some(repo_root.into());
        self
    }

    /// Use a pre-built [`PluginSet`] instead of loading from
    /// `config.plugin_paths`. Useful for tests that want hand-rolled
    /// plugins without disk I/O.
    pub fn plugins(mut self, plugins: PluginSet) -> Self {
        self.plugins = Some(plugins);
        self
    }

    /// Override the audit sink. When unset, [`NoopSink`] is used so the
    /// builder never opens a JSONL file behind the caller's back; route
    /// through [`Engine::with_config`] / [`Engine::for_cwd`] for the
    /// production audit-from-config behaviour.
    pub fn audit_sink(mut self, sink: Box<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Tag the resulting engine with an adapter name.
    pub fn agent(mut self, agent: &'static str) -> Self {
        self.agent = Some(agent);
        self
    }

    /// Finalise the builder.
    ///
    /// When a [`PluginSet`] was injected via [`Self::plugins`] this is
    /// infallible. Otherwise plugin paths in `config.plugin_paths` are
    /// loaded eagerly and the failure surfaces as
    /// [`EngineError::Plugin`].
    pub fn build(self) -> Result<Engine, EngineError> {
        let config = self.config.unwrap_or_default();
        let plugins = if let Some(p) = self.plugins {
            p
        } else {
            let mut set = PluginSet::new();
            set.load_paths(&config.plugin_paths)?;
            set
        };
        let protected = ProtectedPaths::collect(self.repo_root.as_deref(), &config);
        let plugin_versions = compute_plugin_versions(&plugins);
        let project_facts =
            facts::project::collect(self.repo_root.as_deref(), &config.protected_branches);
        let workspaces = compute_workspaces(self.repo_root.as_deref(), &config);
        Ok(Engine {
            config,
            plugins,
            audit_sink: self.audit_sink.unwrap_or_else(|| Box::new(NoopSink)),
            audit_warning: None,
            audit_write_warnings: Mutex::new(Vec::new()),
            repo_root: self.repo_root,
            protected,
            agent: self.agent.unwrap_or("unknown"),
            plugin_versions,
            project_facts,
            workspaces,
        })
    }
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;
    use std::sync::Arc;

    use crate::audit::MemorySink;
    use crate::config::Config;
    use crate::decision::Decision;
    use crate::plugin::PluginSet;

    use super::super::Engine;
    use super::super::test_support::{SharedMemorySink, bash};
    use crate::rules::ConfigRule;

    #[test]
    fn engine_builder_with_default_config_populates_self_protection_binary() {
        // A builder-built engine with `Config::default()` and no
        // repo_root must still expose the running binary as a protected
        // target — otherwise embed callers lose self-protection when
        // configuration discovery fails.
        let engine = Engine::builder()
            .build()
            .expect("default-config builder cannot fail");
        assert!(
            engine.protected_paths().binary.is_some(),
            "builder must populate ProtectedPaths.binary even without a repo_root",
        );
    }

    #[test]
    fn engine_builder_repo_root_is_recorded() {
        let engine = Engine::builder()
            .repo_root(PathBuf::from("/tmp/ptuf-builder-root"))
            .build()
            .expect("builder with repo_root cannot fail");
        assert_eq!(
            engine.protected_paths().repo_root.as_deref(),
            Some(std::path::Path::new("/tmp/ptuf-builder-root")),
        );
    }

    #[test]
    fn engine_plugins_reflects_injected_rules() {
        let yaml = r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
rules:
  - id: pack.demo.no-curl
    severity: medium
    defaultDecision: deny
    when:
      tool: Bash
    reason: nope
"#;
        let plugin =
            crate::plugin::load_str(std::path::Path::new("demo.yaml"), yaml).expect("load plugin");
        let mut set = PluginSet::new();
        set.push(plugin);
        let engine = Engine::builder()
            .plugins(set)
            .build()
            .expect("builder with plugins");
        assert_eq!(engine.plugins().rules().count(), 1);
        assert!(
            engine
                .plugins()
                .rules()
                .any(|r| r.id() == "pack.demo.no-curl")
        );
    }

    #[test]
    fn engine_builder_with_injected_plugins_does_not_load_paths() {
        // Injecting a PluginSet must skip `load_paths`, so a config
        // listing a non-existent plugin path still builds.
        let cfg = Config {
            plugin_paths: vec![PathBuf::from("/does/not/exist.yaml")],
            ..Config::default()
        };
        let engine = Engine::builder()
            .config(cfg)
            .plugins(PluginSet::new())
            .build()
            .expect("injected plugins must skip plugin_paths loading");
        assert_eq!(engine.plugins().rules().count(), 0);
    }

    #[test]
    fn engine_builder_threads_audit_sink_and_agent_into_records() {
        let captured = Arc::new(MemorySink::new());
        let mut cfg = Config::default();
        cfg.audit.include_denied = true;
        let engine = Engine::builder()
            .config(cfg)
            .audit_sink(Box::new(SharedMemorySink(captured.clone())))
            .agent("custom-agent")
            .build()
            .expect("builder build");
        assert!(engine.audit_warning().is_none());
        let _ = engine.decide(&bash("rm -rf /"));
        let records = captured.records();
        assert!(!records.is_empty(), "deny must emit one record");
        assert_eq!(records[0].agent, "custom-agent");
    }

    #[test]
    fn engine_builder_uses_repo_root_for_protected_paths() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-engine-builder-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("workdir");
        let engine = Engine::builder()
            .config(Config::default())
            .repo_root(dir.clone())
            .plugins(PluginSet::new())
            .build()
            .expect("builder build");
        let outcome = engine.decide(&bash("ls"));
        assert_eq!(outcome.decision, Decision::Allow);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
