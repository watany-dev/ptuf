//! `core.secrets.sensitive-read` — denies `Read`/`Edit` of credentials
//! files.
//!
//! The Bash-only `core.secrets.sensitive-path-to-network` rule already
//! catches commands that *exfiltrate* credentials through a network sink.
//! v0.3 adds this companion rule for the new `Read`/`Edit` tool surface
//! (`docs/design/policy-packs.md:60-66`): even reading a sensitive file is
//! enough exposure that the agent should ask the user to read it
//! themselves.

use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::hook_input::HookInput;
use crate::reason;

use super::ConfigRule;

pub struct SensitiveRead;

const RULE_ID: &str = "core.secrets.sensitive-read";

impl ConfigRule for SensitiveRead {
    fn id(&self) -> &str {
        RULE_ID
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn default_decision(&self) -> DecisionKind {
        DecisionKind::Deny
    }

    fn hard_deny(&self) -> bool {
        true
    }

    fn evaluate(&self, facts: &Facts, input: &HookInput) -> Option<Decision> {
        if !matches!(input.tool_name.as_str(), "Read" | "Edit") {
            return None;
        }
        if facts.sensitive.is_empty() {
            return None;
        }
        let reason = reason::build(
            RULE_ID,
            "The requested file looks like a credentials store (SSH key, AWS / gcloud / kube \
             config, dotenv, npmrc, pypirc, tfstate, or PEM blob). Even reading it through the \
             agent exposes the secret to the model and tool transcript.",
            &[
                "Ask the user to inspect or transform the file themselves.",
                "Operate on a redacted copy with the secret values stripped.",
                "If you only need a structural sample, point the user at a synthetic example.",
            ],
        );
        Some(Decision::Deny {
            rule_id: RULE_ID.into(),
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn read(file_path: &str) -> HookInput {
        HookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({ "file_path": file_path }),
        }
    }

    fn edit(file_path: &str, new_string: &str) -> HookInput {
        HookInput {
            tool_name: "Edit".into(),
            tool_input: serde_json::json!({
                "file_path": file_path,
                "new_string": new_string,
            }),
        }
    }

    #[test]
    fn denies_read_of_ssh_key() {
        let input = read("~/.ssh/id_ed25519");
        let facts = crate::facts::extract(&input);
        let d = SensitiveRead.evaluate(&facts, &input);
        assert!(matches!(
            d,
            Some(Decision::Deny { ref rule_id, .. }) if rule_id == RULE_ID
        ));
    }

    #[test]
    fn denies_edit_of_dotenv() {
        let input = edit("/repo/.env.production", "API_KEY=value");
        let facts = crate::facts::extract(&input);
        let d = SensitiveRead.evaluate(&facts, &input);
        assert!(matches!(d, Some(Decision::Deny { .. })));
    }

    #[test]
    fn denies_read_of_aws_credentials() {
        let input = read("~/.aws/credentials");
        let facts = crate::facts::extract(&input);
        assert!(matches!(
            SensitiveRead.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn allows_read_of_non_sensitive_file() {
        let input = read("/repo/src/main.rs");
        let facts = crate::facts::extract(&input);
        assert!(SensitiveRead.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn does_not_fire_for_bash_invocations_pointing_at_secret_paths() {
        // Bash-with-sensitive-path is handled by sensitive-path-to-network.
        // This rule is Read/Edit-only.
        let input = HookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({ "command": "cat ~/.ssh/id_rsa" }),
        };
        let facts = crate::facts::extract(&input);
        assert!(SensitiveRead.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn does_not_fire_for_write_payloads_alone() {
        // Write of a non-sensitive path with non-sensitive content stays
        // out of this rule entirely.
        let input = HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/src/lib.rs",
                "content": "fn main() {}",
            }),
        };
        let facts = crate::facts::extract(&input);
        assert!(SensitiveRead.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn metadata_matches_design() {
        assert!(SensitiveRead.hard_deny());
        assert_eq!(SensitiveRead.severity(), Severity::High);
        assert_eq!(SensitiveRead.default_decision(), DecisionKind::Deny);
        assert_eq!(SensitiveRead.id(), RULE_ID);
    }
}
