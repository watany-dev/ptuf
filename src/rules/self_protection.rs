//! `core.self_protection` pack — refuses any operation that targets ptuf's
//! own binary, configuration, plugins, or the Claude Code hook
//! settings.
//!
//! All five rules are `hard_deny: true` / `Severity::Critical` per
//! `docs/design/policy-packs.md:100-113`. They share the [`SelfRule`]
//! adapter so the [`crate::rules::ConfigRule`] trait is implemented
//! exactly once.

use crate::decision::{Decision, DecisionKind, Severity};
use crate::facts::Facts;
use crate::hook_input::HookInput;
use crate::reason;
use crate::self_paths::ProtectedKind;

use super::ConfigRule;

struct RuleSpec {
    id: &'static str,
    kind: ProtectedKind,
    problem: &'static str,
    alternatives: &'static [&'static str],
}

pub struct SelfRule {
    spec: &'static RuleSpec,
}

impl ConfigRule for SelfRule {
    fn id(&self) -> &str {
        self.spec.id
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn default_decision(&self) -> DecisionKind {
        DecisionKind::Deny
    }

    fn hard_deny(&self) -> bool {
        true
    }

    fn evaluate(&self, facts: &Facts, _input: &HookInput) -> Option<Decision> {
        if !facts.protected.contains(&self.spec.kind) {
            return None;
        }
        let reason = reason::build(self.spec.id, self.spec.problem, self.spec.alternatives);
        Some(Decision::Deny {
            rule_id: self.spec.id.into(),
            reason,
        })
    }
}

const BINARY: RuleSpec = RuleSpec {
    id: "core.self_protection.binary",
    kind: ProtectedKind::Binary,
    problem:
        "The command targets the ptuf binary itself. Removing or replacing it would disable \
         every guardrail in this and future sessions.",
    alternatives: &[
        "Use the package manager / installer that owns the binary.",
        "If you really need to replace ptuf, do it from outside an agent session.",
        "Ask the user to perform the upgrade manually.",
    ],
};

const CONFIG: RuleSpec = RuleSpec {
    id: "core.self_protection.config",
    kind: ProtectedKind::Config,
    problem:
        "The command modifies a ptuf config file. Editing this file from inside the agent \
         could silently widen what the agent itself is allowed to do.",
    alternatives: &[
        "Have the user edit ptuf config in a separate, audited workflow.",
        "Propose the diff in chat instead of writing it.",
        "Restart the policy review process before committing config changes.",
    ],
};

const PLUGIN: RuleSpec = RuleSpec {
    id: "core.self_protection.plugin",
    kind: ProtectedKind::Plugin,
    problem:
        "The command modifies a ptuf plugin file. Plugins extend the rule set, so an in-session \
         edit can grant new capabilities to the same agent that requested the edit.",
    alternatives: &[
        "Ask the user to apply plugin changes themselves.",
        "Submit the plugin update as a normal code change for review.",
        "Disable the plugin by config rather than editing it in place.",
    ],
};

const CLAUDE_SETTINGS: RuleSpec = RuleSpec {
    id: "core.self_protection.claude-settings",
    kind: ProtectedKind::ClaudeSettings,
    problem:
        "The command modifies a Claude Code settings file. The hook registration lives there, \
         so this edit could remove or short-circuit the ptuf hook entirely.",
    alternatives: &[
        "Use `ptuf init claude-code` to manage the hook entry safely.",
        "Have the user edit settings outside an agent session.",
        "If the change is unrelated to hooks, narrow the edit to a non-hook field.",
    ],
};

const HOOK_SCRIPT: RuleSpec = RuleSpec {
    id: "core.self_protection.hook-script",
    kind: ProtectedKind::HookScript,
    problem:
        "The command modifies a script registered as a Claude Code hook. Editing or chmod-ing \
         a hook script can disable ptuf-style enforcement at the next tool use.",
    alternatives: &[
        "Edit the hook script outside an agent session, after review.",
        "Replace the hook entry with a different command via `ptuf init claude-code`.",
        "Verify the script change is not reachable from the registered hook path.",
    ],
};

pub static BINARY_RULE: SelfRule = SelfRule { spec: &BINARY };
pub static CONFIG_RULE: SelfRule = SelfRule { spec: &CONFIG };
pub static PLUGIN_RULE: SelfRule = SelfRule { spec: &PLUGIN };
pub static CLAUDE_SETTINGS_RULE: SelfRule = SelfRule { spec: &CLAUDE_SETTINGS };
pub static HOOK_SCRIPT_RULE: SelfRule = SelfRule { spec: &HOOK_SCRIPT };

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::facts::Facts;
    use crate::hook_input::sample;

    fn facts_with(protected: &[ProtectedKind]) -> Facts {
        Facts {
            protected: protected.to_vec(),
            ..Facts::default()
        }
    }

    #[test]
    fn binary_rule_fires_when_protected_label_present() {
        let facts = facts_with(&[ProtectedKind::Binary]);
        let input = sample("Bash");
        let d = BINARY_RULE.evaluate(&facts, &input);
        assert!(matches!(
            d,
            Some(Decision::Deny { ref rule_id, .. }) if rule_id == "core.self_protection.binary"
        ));
    }

    #[test]
    fn config_rule_fires_only_for_config_label() {
        let facts = facts_with(&[ProtectedKind::Config]);
        let input = sample("Edit");
        assert!(matches!(
            CONFIG_RULE.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
        assert!(BINARY_RULE.evaluate(&facts, &input).is_none());
        assert!(PLUGIN_RULE.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn plugin_rule_fires_only_for_plugin_label() {
        let facts = facts_with(&[ProtectedKind::Plugin]);
        let input = sample("Write");
        assert!(matches!(
            PLUGIN_RULE.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
        assert!(CONFIG_RULE.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn claude_settings_rule_fires_only_for_claude_settings_label() {
        let facts = facts_with(&[ProtectedKind::ClaudeSettings]);
        let input = sample("Edit");
        assert!(matches!(
            CLAUDE_SETTINGS_RULE.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
        assert!(HOOK_SCRIPT_RULE.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn hook_script_rule_fires_only_for_hook_script_label() {
        let facts = facts_with(&[ProtectedKind::HookScript]);
        let input = sample("Bash");
        assert!(matches!(
            HOOK_SCRIPT_RULE.evaluate(&facts, &input),
            Some(Decision::Deny { .. })
        ));
        assert!(CLAUDE_SETTINGS_RULE.evaluate(&facts, &input).is_none());
    }

    #[test]
    fn rules_do_not_fire_for_empty_protected() {
        let facts = facts_with(&[]);
        let input = sample("Bash");
        for rule in [
            &BINARY_RULE,
            &CONFIG_RULE,
            &PLUGIN_RULE,
            &CLAUDE_SETTINGS_RULE,
            &HOOK_SCRIPT_RULE,
        ] {
            assert!(rule.evaluate(&facts, &input).is_none());
        }
    }

    #[test]
    fn rules_carry_hard_deny_critical_metadata() {
        for rule in [
            &BINARY_RULE,
            &CONFIG_RULE,
            &PLUGIN_RULE,
            &CLAUDE_SETTINGS_RULE,
            &HOOK_SCRIPT_RULE,
        ] {
            assert!(rule.hard_deny(), "{} must be hard_deny", rule.id());
            assert_eq!(
                rule.severity(),
                Severity::Critical,
                "{} must be Severity::Critical",
                rule.id()
            );
            assert_eq!(
                rule.default_decision(),
                DecisionKind::Deny,
                "{} must default to Deny",
                rule.id()
            );
        }
    }

    #[test]
    fn reason_includes_rule_id_and_alternatives() {
        let facts = facts_with(&[ProtectedKind::Binary]);
        let input = sample("Bash");
        let d = BINARY_RULE.evaluate(&facts, &input).expect("decision");
        let reason = d.reason().expect("reason for deny");
        assert!(reason.contains("core.self_protection.binary"));
        assert!(reason.contains("Safer alternative"));
    }

    #[test]
    fn rule_ids_are_kebab_case_under_self_protection() {
        for id in [
            BINARY_RULE.id(),
            CONFIG_RULE.id(),
            PLUGIN_RULE.id(),
            CLAUDE_SETTINGS_RULE.id(),
            HOOK_SCRIPT_RULE.id(),
        ] {
            assert!(id.starts_with("core.self_protection."), "id was {id}");
        }
    }
}
