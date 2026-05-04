//! Thin wrapper around `serde_yaml_ng` so the rest of the crate stays
//! parser-agnostic. If the YAML backend ever needs to change (e.g.
//! `serde_norway`), only this module updates.

use std::fs;
use std::path::Path;

use super::ConfigError;
use super::schema::RawConfig;

/// Parse a YAML string into a [`RawConfig`].
///
/// `path` is supplied only for error context; the parser itself does
/// not touch the filesystem.
pub fn parse_str(path: &Path, source: &str) -> Result<RawConfig, ConfigError> {
    serde_yaml_ng::from_str::<RawConfig>(source).map_err(|e| ConfigError::Yaml {
        path: path.to_path_buf(),
        message: e.to_string(),
    })
}

/// Read the file at `path` and parse it into a [`RawConfig`].
pub fn load_path(path: &Path) -> Result<RawConfig, ConfigError> {
    let source = fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    parse_str(path, &source)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

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
            },
        );
        expected.insert(
            "core.filesystem".to_string(),
            crate::config::schema::RawPack {
                enabled: Some(true),
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
            }
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
}
