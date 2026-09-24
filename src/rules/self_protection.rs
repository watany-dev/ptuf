//! `core.self_protection` pack — refuses any operation that targets ptuf's
//! own binary, configuration, plugins, coding-agent settings, or hook scripts.
//!
//! All five rules are `hard_deny: true` / `Severity::Critical` per
//! `docs/design/policy-packs.md:100-113`. They share the `SelfRule`
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

pub(crate) struct SelfRule {
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
    problem: "The command targets the ptuf binary itself. Removing or replacing it would disable \
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
    problem: "The command modifies a ptuf config file. Editing this file from inside the agent \
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
    problem: "The command modifies a ptuf plugin file. Plugins extend the rule set, so an in-session \
         edit can grant new capabilities to the same agent that requested the edit.",
    alternatives: &[
        "Ask the user to apply plugin changes themselves.",
        "Submit the plugin update as a normal code change for review.",
        "Disable the plugin by config rather than editing it in place.",
    ],
};

const AGENT_SETTINGS: RuleSpec = RuleSpec {
    id: "core.self_protection.agent-settings",
    kind: ProtectedKind::AgentSettings,
    problem: "The command modifies a coding agent's own config (hook registration, permission \
         allowlist, sandbox / approval policy, or MCP server list) for Claude Code, Codex, \
         Copilot, Cursor, Kiro, Cline, Pi, or OpenCode. Editing it from inside the agent could \
         remove the ptuf hook or let the agent escalate its own privileges.",
    alternatives: &[
        "Use `ptuf init <agent>` to manage the ptuf hook entry safely.",
        "Have the user edit agent settings outside an agent session.",
        "Propose the config change in chat and let the user apply it.",
    ],
};

const HOOK_SCRIPT: RuleSpec = RuleSpec {
    id: "core.self_protection.hook-script",
    kind: ProtectedKind::HookScript,
    problem: "The command modifies a script registered as a Claude Code, Codex, Copilot, Cursor, \
         or Kiro hook. Editing or chmod-ing a hook script can disable ptuf-style enforcement at \
         the next tool use.",
    alternatives: &[
        "Edit the hook script outside an agent session, after review.",
        "Replace the hook entry with `ptuf init <agent>` (claude-code, codex, copilot, cursor, \
         or kiro).",
        "Verify the script change is not reachable from the registered hook path.",
    ],
};

pub(crate) static BINARY_RULE: SelfRule = SelfRule { spec: &BINARY };
pub(crate) static CONFIG_RULE: SelfRule = SelfRule { spec: &CONFIG };
pub(crate) static PLUGIN_RULE: SelfRule = SelfRule { spec: &PLUGIN };
pub(crate) static AGENT_SETTINGS_RULE: SelfRule = SelfRule {
    spec: &AGENT_SETTINGS,
};
pub(crate) static HOOK_SCRIPT_RULE: SelfRule = SelfRule { spec: &HOOK_SCRIPT };

#[cfg(test)]
mod tests {

    use super::*;
    use crate::facts::Facts;
    use crate::hook_input::sample;
    use crate::self_paths::ProtectedKinds;

    fn facts_with(protected: &[ProtectedKind]) -> Facts {
        Facts {
            protected: ProtectedKinds::from(protected),
            ..Facts::default()
        }
    }

    #[test]
    fn rules_do_not_fire_for_empty_protected() {
        let facts = facts_with(&[]);
        let input = sample("Bash");
        for rule in [
            &BINARY_RULE,
            &CONFIG_RULE,
            &PLUGIN_RULE,
            &AGENT_SETTINGS_RULE,
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
            &AGENT_SETTINGS_RULE,
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
        assert_eq!(BINARY_RULE.default_decision(), DecisionKind::Deny);
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
            AGENT_SETTINGS_RULE.id(),
            HOOK_SCRIPT_RULE.id(),
        ] {
            assert!(id.starts_with("core.self_protection."), "id was {id}");
        }
    }

    use crate::testing::proptest::{protected_kind, richer_hook_input};
    use proptest::prelude::*;

    fn all_self_rules() -> [(&'static SelfRule, ProtectedKind); 5] {
        [
            (&BINARY_RULE, ProtectedKind::Binary),
            (&CONFIG_RULE, ProtectedKind::Config),
            (&PLUGIN_RULE, ProtectedKind::Plugin),
            (&AGENT_SETTINGS_RULE, ProtectedKind::AgentSettings),
            (&HOOK_SCRIPT_RULE, ProtectedKind::HookScript),
        ]
    }

    proptest! {
        // Empty `protected` ⇒ no self-protection rule fires, regardless
        // of input shape.
        #[test]
        fn pbt_empty_protected_never_fires(input in richer_hook_input()) {
            let facts = facts_with(&[]);
            for (rule, _) in all_self_rules() {
                prop_assert!(rule.evaluate(&facts, &input).is_none());
            }
        }

        // When a single ProtectedKind label is present, exactly the
        // rule for that kind fires; the other four stay silent.
        #[test]
        fn pbt_single_kind_fires_exactly_its_rule(
            kind in protected_kind(),
            input in richer_hook_input(),
        ) {
            let facts = facts_with(&[kind]);
            for (rule, rule_kind) in all_self_rules() {
                let d = rule.evaluate(&facts, &input);
                if rule_kind == kind {
                    let fired = matches!(
                        &d,
                        Some(Decision::Deny { rule_id, .. }) if rule_id == rule.spec.id,
                    );
                    prop_assert!(fired, "expected {} to fire, got {d:?}", rule.spec.id);
                } else {
                    prop_assert!(d.is_none(), "{} fired unexpectedly", rule.spec.id);
                }
            }
        }

        // Self-protection rules never panic on arbitrary HookInput shapes
        // (the input parameter is unused by `evaluate`, but exercise the
        // facts pipeline anyway).
        #[test]
        fn pbt_evaluate_never_panics(
            kind in protected_kind(),
            input in richer_hook_input(),
        ) {
            let facts = facts_with(&[kind]);
            for (rule, _) in all_self_rules() {
                let _ = rule.evaluate(&facts, &input);
            }
        }
    }
}
