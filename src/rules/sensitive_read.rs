//! `core.secrets.sensitive-read` — denies `Read`/`Edit`/`Write`/`apply_patch`
//! of credentials files (and the MCP equivalents).
//!
//! The Bash-only `core.secrets.sensitive-path-to-network` rule already
//! catches commands that *exfiltrate* credentials through a network sink.
//! This rule covers the file-tool surface: even reading a sensitive file
//! is enough exposure that the agent should ask the user to inspect it
//! themselves. Write-style tools (`Write`, `apply_patch`) are folded in
//! because they can both create and overwrite credentials files —
//! exposing the file via mode change is itself a leak, and writing
//! arbitrary content into `~/.ssh/authorized_keys` or `~/.aws/credentials`
//! is a privilege-escalation primitive
//! (`docs/design/policy-packs.md` `core.secrets`).
//!
//! The written *body* (`Write` content / `Edit` `new_string` / MCP
//! `content`) only counts when it carries secret data itself (PEM
//! blobs, via `facts::sensitive::classify_content_into`); prose that
//! merely mentions credential paths — a setup guide naming
//! `~/.aws/credentials` — does not fire this rule.

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
        let is_file_tool = matches!(
            input.tool_name.as_str(),
            "Read" | "Edit" | "Write" | "apply_patch",
        ) || (input.is_mcp_tool() && !facts.paths.is_empty());
        if !is_file_tool {
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
    fn denies_read_of_absolute_kube_config() {
        let input = read("/home/alice/.kube/config");
        let facts = crate::facts::extract(&input);
        assert!(matches!(
            SensitiveRead.evaluate(&facts, &input),
            Some(Decision::Deny { ref rule_id, .. }) if rule_id == RULE_ID,
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
    fn does_not_fire_for_non_sensitive_write() {
        // Ordinary source-file writes (non-sensitive path, non-sensitive
        // content) must never trigger this rule.
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
    fn denies_write_of_dotenv() {
        let input = HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({
                "file_path": ".env",
                "content": "API_KEY=value",
            }),
        };
        let facts = crate::facts::extract(&input);
        assert!(matches!(
            SensitiveRead.evaluate(&facts, &input),
            Some(Decision::Deny { ref rule_id, .. }) if rule_id == RULE_ID,
        ));
    }

    #[test]
    fn allows_markdown_write_mentioning_secret_paths() {
        // A docs file whose body merely *mentions* credential paths must
        // not trip the content-side classifier — only data-bearing
        // shapes (PEM blobs) count in a written body.
        let input = HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/docs/setup.md",
                "content": "Put creds in ~/.aws/credentials, never commit \
                            arn:aws:s3:::bucket/terraform.tfstate or .env",
            }),
        };
        let facts = crate::facts::extract(&input);
        assert!(SensitiveRead.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn allows_edit_new_string_mentioning_dotenv() {
        let input = edit("/repo/README.md", "copy .env.example to .env");
        let facts = crate::facts::extract(&input);
        assert!(SensitiveRead.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn denies_write_of_pem_content_to_arbitrary_path() {
        // Write of a non-sensitive path BUT with PEM content in the
        // payload trips the content-side classifier.
        let input = HookInput {
            tool_name: "Write".into(),
            tool_input: serde_json::json!({
                "file_path": "/repo/foo.md",
                "content": "-----BEGIN RSA PRIVATE KEY-----\nXYZ\n-----END RSA PRIVATE KEY-----",
            }),
        };
        let facts = crate::facts::extract(&input);
        assert!(matches!(
            SensitiveRead.evaluate(&facts, &input),
            Some(Decision::Deny { .. }),
        ));
    }

    #[test]
    fn denies_apply_patch_adding_dotenv() {
        let input = HookInput {
            tool_name: "apply_patch".into(),
            tool_input: serde_json::json!({
                "command": "*** Begin Patch\n*** Add File: .env\n+API_KEY=value\n*** End Patch\n",
            }),
        };
        let facts = crate::facts::extract(&input);
        assert!(matches!(
            SensitiveRead.evaluate(&facts, &input),
            Some(Decision::Deny { ref rule_id, .. }) if rule_id == RULE_ID,
        ));
    }

    #[test]
    fn does_not_fire_for_non_sensitive_apply_patch() {
        let input = HookInput {
            tool_name: "apply_patch".into(),
            tool_input: serde_json::json!({
                "command": "*** Begin Patch\n*** Add File: src/lib.rs\n+fn main() {}\n\
                            *** End Patch\n",
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

    #[test]
    fn denies_mcp_filesystem_read_of_aws_credentials() {
        let input = HookInput {
            tool_name: "mcp__filesystem__read_file".into(),
            tool_input: serde_json::json!({"path": "~/.aws/credentials"}),
        };
        let facts = crate::facts::extract(&input);
        assert!(matches!(
            SensitiveRead.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn denies_mcp_github_create_or_update_of_pem_path() {
        let input = HookInput {
            tool_name: "mcp__github__create_or_update_file".into(),
            tool_input: serde_json::json!({"path": "~/.ssh/id_rsa", "content": "secret"}),
        };
        let facts = crate::facts::extract(&input);
        assert!(matches!(
            SensitiveRead.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
    }

    #[test]
    fn does_not_fire_for_mcp_tool_without_a_path_field() {
        // An mcp__* tool that exposes only a `url` (e.g. mcp__fetch__fetch)
        // never sets facts.path, so the Read-style rule must not fire.
        let input = HookInput {
            tool_name: "mcp__fetch__fetch".into(),
            tool_input: serde_json::json!({"url": "https://example.com/x"}),
        };
        let facts = crate::facts::extract(&input);
        assert!(SensitiveRead.evaluate(&facts, &input).is_none());
    }

    use crate::testing::proptest::{file_path, richer_hook_input};
    use proptest::prelude::*;

    proptest! {
        // Tools other than Read/Edit/Write/apply_patch/MCP never fire
        // this rule, even with a sensitive path attached. The regex
        // `[A-Z][A-Za-z]{0,8}` only produces uppercase-leading names, so
        // `mcp__*` and `apply_patch` are excluded by construction.
        #[test]
        fn pbt_non_file_tool_yields_none(
            tool in "[A-Z][A-Za-z]{0,8}",
            fp in file_path(),
        ) {
            prop_assume!(!matches!(tool.as_str(), "Read" | "Edit" | "Write"));
            let input = HookInput {
                tool_name: tool,
                tool_input: serde_json::json!({ "file_path": fp }),
            };
            let facts = crate::facts::extract(&input);
            prop_assert!(SensitiveRead.evaluate(&facts, &input).is_none());
        }

        // Empty `facts.sensitive` ⇒ rule never fires, regardless of tool
        // name. We exercise this by handing the rule a hand-built Facts.
        #[test]
        fn pbt_empty_sensitive_yields_none(input in richer_hook_input()) {
            let facts = crate::facts::Facts::default();
            prop_assert!(SensitiveRead.evaluate(&facts, &input).is_none());
        }

        // Adversarial: never panic on any well-formed HookInput.
        #[test]
        fn pbt_evaluate_never_panics(input in richer_hook_input()) {
            let facts = crate::facts::extract(&input);
            let _ = SensitiveRead.evaluate(&facts, &input);
        }

        // When the rule fires, the resulting Decision is always a Deny
        // carrying this rule's id.
        #[test]
        fn pbt_only_emits_deny_with_correct_id(input in richer_hook_input()) {
            let facts = crate::facts::extract(&input);
            if let Some(d) = SensitiveRead.evaluate(&facts, &input) {
                match d {
                    Decision::Deny { rule_id, .. } => prop_assert_eq!(rule_id, RULE_ID),
                    other => prop_assert!(false, "expected Deny, got {other:?}"),
                }
            }
        }

        // Read/Edit/Write on any sensitive path classification fires the
        // rule. Use known-sensitive paths to exercise the positive arm.
        #[test]
        fn pbt_sensitive_read_paths_always_fire(
            tool in proptest::sample::select(&["Read", "Edit", "Write"][..]),
            sensitive_fp in proptest::sample::select(
                &[
                    "~/.ssh/id_rsa",
                    "~/.ssh/id_ed25519",
                    "~/.aws/credentials",
                    "~/.kube/config",
                    "~/.docker/config.json",
                    ".env",
                    ".env.production",
                    "infra/main.tfstate",
                    ".npmrc",
                    ".pypirc",
                ][..],
            ),
        ) {
            let input = HookInput {
                tool_name: tool.to_string(),
                tool_input: serde_json::json!({ "file_path": sensitive_fp }),
            };
            let facts = crate::facts::extract(&input);
            let d = SensitiveRead.evaluate(&facts, &input);
            prop_assert!(
                matches!(d, Some(Decision::Deny { ref rule_id, .. }) if rule_id == RULE_ID),
                "expected Deny for {sensitive_fp:?}, got {d:?}",
            );
        }
    }
}
