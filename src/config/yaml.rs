//! Thin wrapper around `serde_yaml_ng` so the rest of the crate stays
//! parser-agnostic. If the YAML backend ever needs to change (e.g.
//! `serde_norway`), only this module updates.

use std::fs;
use std::path::Path;

use super::ConfigError;
use super::schema::RawConfig;
use crate::config::scope::SystemEnv;
use crate::facts::path::resolve_with_env;

/// Parse a YAML string into a [`RawConfig`].
///
/// `path` is supplied only for error context; the parser itself does
/// not touch the filesystem.
pub fn parse_str(path: &Path, source: &str) -> Result<RawConfig, ConfigError> {
    let raw = serde_yaml_ng::from_str::<RawConfig>(source).map_err(|e| ConfigError::Yaml {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    if let Some(version) = raw.version
        && version != 1
    {
        return Err(ConfigError::Version {
            path: path.to_path_buf(),
            found: version,
        });
    }
    for entry in &raw.allowlists {
        if let Some(when) = &entry.when
            && let Err(err) = crate::plugin::dsl::compile(when)
        {
            return Err(ConfigError::Allowlist {
                path: path.to_path_buf(),
                id: entry.id.clone(),
                message: format!("when: {err}"),
            });
        }
        if let Some(expires_at) = &entry.expires_at
            && crate::audit::time::parse_rfc3339_to_secs(expires_at).is_none()
        {
            return Err(ConfigError::Allowlist {
                path: path.to_path_buf(),
                id: entry.id.clone(),
                message: format!("expiresAt: invalid RFC3339 `{expires_at}`"),
            });
        }
    }
    Ok(raw)
}

/// Read the file at `path` and parse it into a [`RawConfig`].
///
/// Plugin and audit paths are home-expanded and, when relative, joined
/// onto the directory that contains `path` so each config layer's
/// references are independent of process cwd.
pub(crate) fn load_path(path: &Path) -> Result<RawConfig, ConfigError> {
    let source = fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut raw = parse_str(path, &source)?;
    resolve_layer_paths(&mut raw, path);
    Ok(raw)
}

fn resolve_layer_paths(raw: &mut RawConfig, config_path: &Path) {
    let config_dir = config_path.parent();
    let env = SystemEnv;
    for plugin in &mut raw.plugins {
        let raw_path = plugin.path.to_string_lossy();
        plugin.path = resolve_with_env(&raw_path, config_dir, &env);
    }
    if let Some(audit_path) = raw.audit.path.take() {
        let raw_path = audit_path.to_string_lossy();
        raw.audit.path = Some(resolve_with_env(&raw_path, config_dir, &env));
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::config::Mode;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("test.yaml")
    }

    #[test]
    fn parses_minimal_config() {
        let yaml = "version: 1\nmode: enforce\nfailClosed: true\n";
        let raw = parse_str(&p(), yaml).expect("parse");
        assert_eq!(raw.version, Some(1));
        assert_eq!(raw.mode, Some(Mode::Enforce));
        assert_eq!(raw.fail_closed, Some(true));
    }

    #[test]
    fn parses_pack_overrides() {
        let yaml = r"
mode: monitor
packs:
  core.network:
    enabled: false
  core.filesystem:
    enabled: true
";
        let raw = parse_str(&p(), yaml).expect("parse");
        assert_eq!(raw.mode, Some(Mode::Monitor));
        let mut expected = BTreeMap::new();
        expected.insert(
            "core.network".to_string(),
            crate::config::schema::RawPack {
                enabled: Some(false),
                protected_branches: None,
                additional_workspaces: None,
            },
        );
        expected.insert(
            "core.filesystem".to_string(),
            crate::config::schema::RawPack {
                enabled: Some(true),
                protected_branches: None,
                additional_workspaces: None,
            },
        );
        assert_eq!(raw.packs, expected);
    }

    #[test]
    fn parses_allowlist_with_rules_and_expires_at() {
        let yaml = r#"
allowlists:
  - id: allow-localhost
    appliesTo:
      rules:
        - core.network.unknown-post
    expiresAt: "2026-06-01T00:00:00Z"
    reason: "local dev"
"#;
        let raw = parse_str(&p(), yaml).expect("parse");
        assert_eq!(raw.allowlists.len(), 1);
        let entry = &raw.allowlists[0];
        assert_eq!(entry.id, "allow-localhost");
        assert_eq!(entry.applies_to.rules, vec!["core.network.unknown-post"]);
        assert_eq!(entry.expires_at.as_deref(), Some("2026-06-01T00:00:00Z"));
        assert_eq!(entry.reason.as_deref(), Some("local dev"));
    }

    #[test]
    fn parses_rule_overrides_and_audit_enabled() {
        let yaml = r#"
rules:
  core.git.reset-hard:
    decision: deny
    severity: critical
audit:
  enabled: false
"#;
        let raw = parse_str(&p(), yaml).expect("parse");
        assert_eq!(raw.audit.enabled, Some(false));
        let overlay = raw.rules.get("core.git.reset-hard").expect("overlay");
        assert_eq!(overlay.decision, Some(crate::decision::DecisionKind::Deny));
        assert_eq!(overlay.severity, Some(crate::decision::Severity::Critical));
    }

    #[test]
    fn rejects_invalid_allowlist_when_expression() {
        let yaml = r#"
allowlists:
  - id: bad
    appliesTo:
      rules: [core.git.reset-hard]
    when:
      shell.argv: 42
"#;
        let err = parse_str(&p(), yaml).expect_err("invalid allowlist when");
        assert!(matches!(err, ConfigError::Allowlist { .. }));
        assert!(format!("{err}").contains("bad"));
    }

    #[test]
    fn parses_audit_path() {
        let yaml = r#"
audit:
  path: /tmp/ptuf/audit.jsonl
"#;
        let raw = parse_str(&p(), yaml).expect("parse");
        assert_eq!(raw.audit.path, Some(PathBuf::from("/tmp/ptuf/audit.jsonl")));
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let yaml = "wat: 1\n";
        let err = parse_str(&p(), yaml).expect_err("should reject");
        match err {
            ConfigError::Yaml { path, message } => {
                assert_eq!(path, PathBuf::from("test.yaml"));
                assert!(
                    message.contains("wat") || message.contains("unknown"),
                    "unexpected message: {message}"
                );
            },
            other => panic!("expected Yaml error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_mode() {
        let yaml = "mode: yolo\n";
        let err = parse_str(&p(), yaml).expect_err("should reject");
        assert!(matches!(err, ConfigError::Yaml { .. }));
    }

    #[test]
    fn empty_yaml_is_a_default_config() {
        let raw = parse_str(&p(), "").expect("parse empty");
        assert_eq!(raw, RawConfig::default());
    }

    #[test]
    fn load_path_reads_a_real_file() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-yaml-load-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("config.yaml");
        std::fs::write(&path, "mode: monitor\n").expect("write");

        let raw = load_path(&path).expect("load");
        assert_eq!(raw.mode, Some(Mode::Monitor));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_path_returns_io_error_for_missing_file() {
        let path = PathBuf::from("/nonexistent/ptuf-load-path-does-not-exist.yaml");
        let err = load_path(&path).expect_err("should fail");
        match err {
            ConfigError::Io { path: returned, .. } => assert_eq!(returned, path),
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn load_path_propagates_yaml_error() {
        let dir =
            std::env::temp_dir().join(format!("ptuf-yaml-bad-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("bad.yaml");
        std::fs::write(&path, "mode: yolo\n").expect("write");

        let err = load_path(&path).expect_err("should fail");
        assert!(matches!(err, ConfigError::Yaml { .. }));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    // Ill-formed YAML at the parser level — the colon-only document is
    // a syntax error before any schema validation can run. Verifies
    // that `path` is round-tripped verbatim into the error.
    #[test]
    fn rejects_syntactically_invalid_yaml() {
        let yaml = ":\n  -";
        let path = PathBuf::from("syntax-broken.yaml");
        let err = parse_str(&path, yaml).expect_err("syntax error expected");
        match err {
            ConfigError::Yaml { path: returned, .. } => assert_eq!(returned, path),
            other => panic!("expected Yaml error, got {other:?}"),
        }
    }

    // Inconsistent indentation surfaces as a YAML parse error, not as
    // a schema deserialization error. Both are mapped to `Yaml`.
    #[test]
    fn rejects_yaml_with_inconsistent_indentation() {
        let yaml = "packs:\n  core.network:\n   enabled: true\n     bad: 1\n";
        let err = parse_str(&p(), yaml).expect_err("indentation error expected");
        assert!(matches!(err, ConfigError::Yaml { .. }));
    }

    // Wrong scalar type for a field that expects a struct or sequence.
    // `audit:` is a struct, not a string.
    #[test]
    fn rejects_yaml_with_wrong_value_type() {
        let yaml = "audit: not-a-struct\n";
        let err = parse_str(&p(), yaml).expect_err("type mismatch expected");
        assert!(matches!(err, ConfigError::Yaml { .. }));
    }

    // The `path` field is preserved verbatim through Yaml errors so
    // that callers can include it in fail-closed audit records.
    #[test]
    fn yaml_error_preserves_caller_supplied_path() {
        let path = PathBuf::from("/some/where/conf.yaml");
        let err = parse_str(&path, "mode: yolo\n").expect_err("invalid mode");
        match err {
            ConfigError::Yaml { path: returned, .. } => assert_eq!(returned, path),
            other => panic!("expected Yaml error, got {other:?}"),
        }
    }

    // Allowlist `when:` clauses are compiled inside `parse_str`.
    // Compile failures from a deeply-nested invalid mapping must
    // surface as `ConfigError::Yaml` with the entry id in the message.
    #[test]
    fn allowlist_when_compile_error_includes_entry_id() {
        let yaml = r"
allowlists:
  - id: my-bad-id
    appliesTo:
      rules: [core.git.reset-hard]
    when:
      all:
        - shell.argv: 42
";
        let err = parse_str(&p(), yaml).expect_err("compile failure expected");
        match err {
            ConfigError::Allowlist { id, message, .. } => {
                assert_eq!(id, "my-bad-id");
                assert!(
                    message.contains("when"),
                    "expected when compile error: {message}"
                );
            },
            other => panic!("expected Allowlist error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_allowlist_expires_at() {
        let yaml = r#"
allowlists:
  - id: stale-shape
    appliesTo:
      rules: [core.git.reset-hard]
    expiresAt: "2026-01-01T00:00:00.000Z"
"#;
        let err = parse_str(&p(), yaml).expect_err("invalid expiresAt");
        assert!(matches!(err, ConfigError::Allowlist { .. }));
        assert!(format!("{err}").contains("stale-shape"));
    }

    #[test]
    fn rejects_unsupported_config_version() {
        let err = parse_str(&p(), "version: 2\n").expect_err("version 2");
        assert!(matches!(err, ConfigError::Version { found: 2, .. }));
    }

    #[test]
    fn accepts_omitted_version() {
        let raw = parse_str(&p(), "mode: enforce\n").expect("parse");
        assert_eq!(raw.version, None);
        assert_eq!(raw.mode, Some(Mode::Enforce));
    }

    #[test]
    fn load_path_resolves_relative_plugin_and_audit_paths() {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-yaml-resolve-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("config.yaml");
        std::fs::write(
            &path,
            "plugins:\n  - path: plugins/team.yaml\naudit:\n  path: logs/audit.jsonl\n",
        )
        .expect("write");

        let raw = load_path(&path).expect("load");
        assert_eq!(raw.plugins[0].path, dir.join("plugins/team.yaml"));
        assert_eq!(
            raw.audit.path.as_deref(),
            Some(dir.join("logs/audit.jsonl").as_path())
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_path_expands_home_in_plugin_and_audit_paths() {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return;
        };
        let dir =
            std::env::temp_dir().join(format!("ptuf-yaml-home-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("config.yaml");
        std::fs::write(
            &path,
            "plugins:\n  - path: ~/team.yaml\naudit:\n  path: $HOME/audit.jsonl\n",
        )
        .expect("write");

        let raw = load_path(&path).expect("load");
        assert_eq!(raw.plugins[0].path, home.join("team.yaml"));
        assert_eq!(
            raw.audit.path.as_deref(),
            Some(home.join("audit.jsonl").as_path())
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    use proptest::prelude::*;

    // Config YAML inputs: mostly arbitrary noise, plus partially-valid
    // documents that drive the scalar / allowlist / pack code paths.
    fn yaml_source() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => crate::testing::proptest::arbitrary_command(),
            1 => "[a-z]{1,10}".prop_map(|mode| format!("mode: {mode}\n")),
            1 => (0u32..3, "[a-z]{0,8}").prop_map(|(version, mode)| format!(
                "version: {version}\nfailClosed: true\nmode: {mode}\n",
            )),
            1 => "[a-z.]{1,16}".prop_map(|rule| format!(
                "allowlists:\n  - id: a\n    appliesTo:\n      rules: [{rule}]\n    \
                 when:\n      tool: Bash\n",
            )),
            1 => ("[a-z.]{1,16}", any::<bool>()).prop_map(|(pack, enabled)| format!(
                "packs:\n  {pack}:\n    enabled: {enabled}\n",
            )),
        ]
    }

    proptest! {
        // `parse_str` is the config trust boundary: arbitrary YAML —
        // junk bytes or partially-valid documents — must yield `Ok` or
        // a `ConfigError`, and never panic.
        #[test]
        fn pbt_parse_str_is_total_on_arbitrary_input(source in yaml_source()) {
            let _ = parse_str(&p(), &source);
        }
    }
}
