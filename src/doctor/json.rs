//! Stable, machine-readable JSON projection of [`super::Report`].
//!
//! Shadow types live here so `Config`, `PluginError`, and `Layout`
//! don't have to derive `Serialize`. The `to_json` method on `Report`
//! is implemented in this module too, alongside [`render_doctor_json`]
//! which is the production entry point for `ptuf doctor --json`.

use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;

use crate::config::scope::Layout;

use super::{
    ClaudeState, ClaudeStatus, CodexState, CodexStatus, ConfigStatus, DOCTOR_JSON_SCHEMA_VERSION,
    PluginStatus, Report, gather_live_report, mode_label,
};

#[derive(Debug, Serialize)]
pub struct JsonReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub binary: JsonBinary,
    pub project: JsonProject,
    #[serde(rename = "configLayers")]
    pub config_layers: Vec<JsonConfigLayer>,
    pub config: JsonConfig,
    pub plugins: Vec<JsonPlugin>,
    pub claude: JsonClaude,
    pub codex: JsonCodex,
    #[serde(rename = "hasFailure")]
    pub has_failure: bool,
}

#[derive(Debug, Serialize)]
pub struct JsonBinary {
    pub path: Option<String>,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct JsonProject {
    #[serde(rename = "repoRoot")]
    pub repo_root: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JsonConfigLayer {
    pub layer: &'static str,
    pub path: String,
    pub present: bool,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum JsonConfig {
    Loaded {
        loaded: bool, // always true; kept for explicit shape
        mode: &'static str,
        #[serde(rename = "failClosed")]
        fail_closed: bool,
        #[serde(rename = "auditPath")]
        audit_path: Option<String>,
    },
    Failed {
        loaded: bool, // always false
        error: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum JsonPlugin {
    Loaded {
        loaded: bool, // always true
        path: String,
        name: String,
        version: String,
        #[serde(rename = "ruleCount")]
        rule_count: usize,
    },
    Failed {
        loaded: bool, // always false
        path: String,
        error: String,
    },
}

#[derive(Debug, Serialize)]
pub struct JsonClaude {
    #[serde(rename = "settingsPath")]
    pub settings_path: Option<String>,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JsonCodex {
    #[serde(rename = "configPath")]
    pub config_path: Option<String>,
    #[serde(rename = "hooksPath")]
    pub hooks_path: Option<String>,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Report {
    /// Build the JSON projection of this report. Pure transformation;
    /// no I/O, no environment lookups.
    pub fn to_json(&self) -> JsonReport {
        let has_failure = self.has_failure();
        JsonReport {
            schema_version: DOCTOR_JSON_SCHEMA_VERSION,
            binary: JsonBinary {
                path: self.binary.path.as_ref().map(|p| p.display().to_string()),
                version: self.binary.version,
            },
            project: JsonProject {
                repo_root: self
                    .project
                    .repo_root
                    .as_ref()
                    .map(|p| p.display().to_string()),
            },
            config_layers: build_config_layers(&self.layout),
            config: match &self.config {
                ConfigStatus::Loaded(c) => JsonConfig::Loaded {
                    loaded: true,
                    mode: mode_label(c.mode),
                    fail_closed: c.fail_closed,
                    audit_path: crate::config::resolved_audit_path(c)
                        .as_ref()
                        .map(|p| p.display().to_string()),
                },
                ConfigStatus::Failed(err) => JsonConfig::Failed {
                    loaded: false,
                    error: err.to_string(),
                },
            },
            plugins: self
                .plugins
                .iter()
                .map(|p| match p {
                    PluginStatus::Loaded {
                        path,
                        name,
                        version,
                        rule_count,
                    } => JsonPlugin::Loaded {
                        loaded: true,
                        path: path.display().to_string(),
                        name: name.clone(),
                        version: version.clone(),
                        rule_count: *rule_count,
                    },
                    PluginStatus::Failed { path, error } => JsonPlugin::Failed {
                        loaded: false,
                        path: path.display().to_string(),
                        error: error.to_string(),
                    },
                })
                .collect(),
            claude: build_json_claude(&self.claude),
            codex: build_json_codex(&self.codex),
            has_failure,
        }
    }
}

fn build_config_layers(layout: &Layout) -> Vec<JsonConfigLayer> {
    let mut out = Vec::with_capacity(4);
    let entries: [(&'static str, Option<&PathBuf>); 4] = [
        ("system", layout.system.as_ref()),
        ("user", layout.user.as_ref()),
        ("project", layout.project.as_ref()),
        ("projectLocal", layout.project_local.as_ref()),
    ];
    for (layer, path) in entries {
        if let Some(p) = path {
            out.push(JsonConfigLayer {
                layer,
                path: p.display().to_string(),
                present: p.is_file(),
            });
        }
    }
    out
}

fn build_json_claude(status: &ClaudeStatus) -> JsonClaude {
    let settings_path = status
        .settings_path
        .as_ref()
        .map(|p| p.display().to_string());
    let (state, matcher, error) = match &status.state {
        ClaudeState::HomeNotSet => ("homeNotSet", None, None),
        ClaudeState::Missing => ("missing", None, None),
        ClaudeState::HookRegistered { matcher } => ("hookRegistered", matcher.clone(), None),
        ClaudeState::HookMissing => ("hookMissing", None, None),
        ClaudeState::InvalidJson(msg) => ("invalidJson", None, Some(msg.clone())),
        ClaudeState::Io(msg) => ("io", None, Some(msg.clone())),
    };
    JsonClaude {
        settings_path,
        state,
        matcher,
        error,
    }
}

fn build_json_codex(status: &CodexStatus) -> JsonCodex {
    let config_path = status.config_path.as_ref().map(|p| p.display().to_string());
    let hooks_path = status.hooks_path.as_ref().map(|p| p.display().to_string());
    let (state, matcher, error) = match &status.state {
        CodexState::HomeNotSet => ("homeNotSet", None, None),
        CodexState::ConfigMissing => ("configMissing", None, None),
        CodexState::HooksMissing => ("hooksMissing", None, None),
        CodexState::HooksDisabled => ("hooksDisabled", None, None),
        CodexState::HookRegistered { matcher } => ("hookRegistered", matcher.clone(), None),
        CodexState::HookMissing => ("hookMissing", None, None),
        CodexState::InvalidConfig(msg) => ("invalidConfig", None, Some(msg.clone())),
        CodexState::InvalidHooks(msg) => ("invalidHooks", None, Some(msg.clone())),
        CodexState::Io(msg) => ("io", None, Some(msg.clone())),
    };
    JsonCodex {
        config_path,
        hooks_path,
        state,
        matcher,
        error,
    }
}

/// JSON variant of [`super::render_doctor`]. Writes a stable,
/// machine-readable `JsonReport` to `stdout`
/// (`docs/design/cli-and-hooks.md`).
pub fn render_doctor_json<W: Write>(stdout: &mut W) -> std::io::Result<bool> {
    let report = gather_live_report();
    let json = report.to_json();
    serde_json::to_writer_pretty(&mut *stdout, &json).map_err(std::io::Error::other)?;
    writeln!(stdout)?;
    Ok(report.has_failure())
}

#[cfg(test)]
mod tests {

    use std::fs;
    use std::path::PathBuf;

    use crate::config::scope::Layout;

    use super::super::{CodexPaths, Report};
    use super::render_doctor_json;

    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ptuf-doctor-json-{}-{}-{}",
            tag,
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn to_json_value(report: &Report) -> serde_json::Value {
        serde_json::to_value(report.to_json()).unwrap()
    }

    #[test]
    fn json_report_advertises_schema_version_one() {
        let report = Report::gather(None, None, Layout::default(), None);
        let v = to_json_value(&report);
        assert_eq!(v["schemaVersion"], 1);
        assert!(v["codex"]["state"].is_string());
    }

    #[test]
    fn json_report_includes_binary_path_and_version_when_known() {
        let report = Report::gather(
            Some(PathBuf::from("/usr/local/bin/ptuf")),
            None,
            Layout::default(),
            None,
        );
        let v = to_json_value(&report);
        assert_eq!(v["binary"]["path"], "/usr/local/bin/ptuf");
        assert!(v["binary"]["version"].is_string());
    }

    #[test]
    fn json_report_emits_null_binary_path_when_unknown() {
        let report = Report::gather(None, None, Layout::default(), None);
        let v = to_json_value(&report);
        assert!(v["binary"]["path"].is_null());
    }

    #[test]
    fn json_report_drops_unset_layout_entries_but_keeps_set_ones() {
        let dir = workdir("json-layers");
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, "mode: enforce\n").unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj.clone()),
            project_local: Some(dir.join(".ptuf.local.yaml")),
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        let v = to_json_value(&report);
        let layers = v["configLayers"].as_array().unwrap();
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0]["layer"], "project");
        assert_eq!(layers[0]["present"], true);
        assert_eq!(layers[1]["layer"], "projectLocal");
        assert_eq!(layers[1]["present"], false);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_report_serialises_loaded_config_with_mode_and_audit() {
        let dir = workdir("json-cfg");
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, "mode: monitor\nfailClosed: false\n").unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        let v = to_json_value(&report);
        assert_eq!(v["config"]["loaded"], true);
        assert_eq!(v["config"]["mode"], "monitor");
        assert_eq!(v["config"]["failClosed"], false);
        assert_eq!(
            v["config"]["auditPath"],
            crate::config::default_audit_path()
                .map(|p| serde_json::Value::String(p.display().to_string()))
                .unwrap_or(serde_json::Value::Null)
        );
        assert_eq!(v["hasFailure"], false);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_report_serialises_failed_config_with_error_string() {
        let dir = workdir("json-bad-cfg");
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, "mode: enforce\n  bad: : :\n").unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        let v = to_json_value(&report);
        assert_eq!(v["config"]["loaded"], false);
        assert!(v["config"]["error"].is_string());
        assert_eq!(v["hasFailure"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_report_serialises_loaded_plugin_entry() {
        let dir = workdir("json-plugin");
        let plugin = dir.join("ok.yaml");
        fs::write(
            &plugin,
            r#"
apiVersion: ptuf.dev/v1
kind: Plugin
metadata:
  name: pack.demo
  version: 1.0.0
rules:
  - id: pack.demo.rule1
    severity: low
    defaultDecision: deny
    when:
      tool: Bash
    reason: r
"#,
        )
        .unwrap();
        let proj = dir.join(".ptuf.yaml");
        fs::write(&proj, format!("plugins:\n  - path: {}\n", plugin.display())).unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        let v = to_json_value(&report);
        let plugins = v["plugins"].as_array().unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0]["loaded"], true);
        assert_eq!(plugins[0]["name"], "pack.demo");
        assert_eq!(plugins[0]["version"], "1.0.0");
        assert_eq!(plugins[0]["ruleCount"], 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_report_serialises_failed_plugin_entry() {
        let dir = workdir("json-bad-plugin");
        let proj = dir.join(".ptuf.yaml");
        let plugin = dir.join("nope.yaml");
        fs::write(&proj, format!("plugins:\n  - path: {}\n", plugin.display())).unwrap();
        let layout = Layout {
            system: None,
            user: None,
            project: Some(proj),
            project_local: None,
        };
        let report = Report::gather(None, Some(dir.clone()), layout, None);
        let v = to_json_value(&report);
        let plugins = v["plugins"].as_array().unwrap();
        assert_eq!(plugins[0]["loaded"], false);
        assert!(plugins[0]["error"].is_string());
        assert_eq!(v["hasFailure"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_claude_state_home_not_set_omits_optional_fields() {
        let report = Report::gather(None, None, Layout::default(), None);
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "homeNotSet");
        assert!(v["claude"]["settingsPath"].is_null());
        assert!(v["claude"].get("matcher").is_none());
        assert!(v["claude"].get("error").is_none());
    }

    #[test]
    fn json_claude_state_missing_omits_matcher_and_error() {
        let dir = workdir("json-claude-missing");
        let path = dir.join("settings.json");
        let report = Report::gather(None, None, Layout::default(), Some(path.clone()));
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "missing");
        assert_eq!(v["claude"]["settingsPath"], path.display().to_string());
        assert!(v["claude"].get("matcher").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_claude_state_hook_registered_includes_matcher() {
        let dir = workdir("json-claude-good");
        let path = dir.join("settings.json");
        fs::write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|Read|Edit|Write|WebFetch|mcp__.*","hooks":[{"type":"command","command":"ptuf hook claude-code"}]}]}}"#,
        )
        .unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "hookRegistered");
        assert_eq!(
            v["claude"]["matcher"],
            "Bash|Read|Edit|Write|WebFetch|mcp__.*"
        );
        assert!(v["claude"].get("error").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_claude_state_hook_missing_state_string() {
        let dir = workdir("json-claude-no-hook");
        let path = dir.join("settings.json");
        fs::write(&path, r#"{"hooks":{"PreToolUse":[]}}"#).unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "hookMissing");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_claude_state_invalid_json_carries_error() {
        let dir = workdir("json-claude-bad");
        let path = dir.join("settings.json");
        fs::write(&path, "{not json").unwrap();
        let report = Report::gather(None, None, Layout::default(), Some(path));
        let v = to_json_value(&report);
        assert_eq!(v["claude"]["state"], "invalidJson");
        assert!(v["claude"]["error"].is_string());
        assert_eq!(v["hasFailure"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_codex_state_home_not_set_omits_optional_fields() {
        let report = Report::gather(None, None, Layout::default(), None);
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "homeNotSet");
        assert!(v["codex"]["configPath"].is_null());
        assert!(v["codex"]["hooksPath"].is_null());
        assert!(v["codex"].get("matcher").is_none());
        assert!(v["codex"].get("error").is_none());
    }

    #[test]
    fn json_codex_state_hook_registered_includes_matcher() {
        let dir = workdir("json-codex-good");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features]\ncodex_hooks = true\n").unwrap();
        fs::write(
            &hooks_path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash|apply_patch|mcp__.*","hooks":[{"type":"command","command":"ptuf hook codex"}]}]}}"#,
        )
        .unwrap();
        let report = Report::gather_with_codex(
            None,
            None,
            Layout::default(),
            None,
            CodexPaths {
                config_path: Some(config_path.clone()),
                hooks_path: Some(hooks_path.clone()),
            },
        );
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "hookRegistered");
        assert_eq!(v["codex"]["configPath"], config_path.display().to_string());
        assert_eq!(v["codex"]["hooksPath"], hooks_path.display().to_string());
        assert_eq!(v["codex"]["matcher"], "Bash|apply_patch|mcp__.*");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_codex_state_invalid_config_carries_error() {
        let dir = workdir("json-codex-bad");
        let config_path = dir.join("config.toml");
        let hooks_path = dir.join("hooks.json");
        fs::write(&config_path, "[features\ncodex_hooks = true").unwrap();
        let report = Report::gather_with_codex(
            None,
            None,
            Layout::default(),
            None,
            CodexPaths {
                config_path: Some(config_path),
                hooks_path: Some(hooks_path),
            },
        );
        let v = to_json_value(&report);
        assert_eq!(v["codex"]["state"], "invalidConfig");
        assert!(v["codex"]["error"].is_string());
        assert_eq!(v["hasFailure"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_doctor_json_writes_pretty_json_with_trailing_newline() {
        let mut buf = Vec::new();
        let _failure = render_doctor_json(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.ends_with('\n'));
        let value: serde_json::Value =
            serde_json::from_str(s.trim_end()).expect("must be valid JSON");
        assert_eq!(value["schemaVersion"], 1);
    }
}
