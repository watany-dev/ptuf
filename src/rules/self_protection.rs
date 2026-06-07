//! `core.self_protection` pack — refuses any operation that targets ptuf's
//! own binary, configuration, plugins, or agent hook settings.
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

const CLAUDE_SETTINGS: RuleSpec = RuleSpec {
    id: "core.self_protection.claude-settings",
    kind: ProtectedKind::ClaudeSettings,
    problem: "The command modifies a Claude Code settings file. The hook registration lives there, \
         so this edit could remove or short-circuit the ptuf hook entirely.",
    alternatives: &[
        "Use `ptuf init claude-code` to manage the hook entry safely.",
        "Have the user edit settings outside an agent session.",
        "If the change is unrelated to hooks, narrow the edit to a non-hook field.",
    ],
};

const CODEX_SETTINGS: RuleSpec = RuleSpec {
    id: "core.self_protection.codex-settings",
    kind: ProtectedKind::CodexSettings,
    problem: "The command modifies a Codex hook or config file. The hook registration and \
         feature enablement live there, so this edit could disable or bypass ptuf in Codex.",
    alternatives: &[
        "Use `ptuf init codex` to manage the hook entry safely.",
        "Have the user edit Codex settings outside an agent session.",
        "If the change is unrelated to hooks, narrow the edit to a non-hook file.",
    ],
};

const HOOK_SCRIPT: RuleSpec = RuleSpec {
    id: "core.self_protection.hook-script",
    kind: ProtectedKind::HookScript,
    problem: "The command modifies a script registered as a Claude Code, Codex, Copilot, or Kiro \
         hook. Editing or chmod-ing a hook script can disable ptuf-style enforcement at the next \
         tool use.",
    alternatives: &[
        "Edit the hook script outside an agent session, after review.",
        "Replace the hook entry with `ptuf init claude-code`, `ptuf init codex`, \
         `ptuf init copilot`, or `ptuf init kiro`.",
        "Verify the script change is not reachable from the registered hook path.",
    ],
};

const COPILOT_SETTINGS: RuleSpec = RuleSpec {
    id: "core.self_protection.copilot-settings",
    kind: ProtectedKind::CopilotSettings,
    problem: "The command modifies the GitHub Copilot hook file (.github/hooks/ptuf.json). The \
         hook registration lives there, so this edit could remove or short-circuit the ptuf hook \
         entirely.",
    alternatives: &[
        "Use `ptuf init copilot` to manage the hook entry safely.",
        "Have the user edit the hook file outside an agent session.",
        "If the change is unrelated to hooks, narrow the edit to a non-hook field.",
    ],
};

const KIRO_SETTINGS: RuleSpec = RuleSpec {
    id: "core.self_protection.kiro-settings",
    kind: ProtectedKind::KiroSettings,
    problem: "The command modifies a Kiro CLI agent config file under .kiro/agents/ (workspace or \
         $HOME). The PreToolUse hook registration lives there, so this edit could remove or \
         short-circuit the ptuf hook entirely.",
    alternatives: &[
        "Use `ptuf init kiro` to manage the hook entry safely.",
        "Have the user edit the agent config outside an agent session.",
        "If the change is unrelated to hooks, narrow the edit to a non-hook field.",
    ],
};

pub static BINARY_RULE: SelfRule = SelfRule { spec: &BINARY };
pub static CONFIG_RULE: SelfRule = SelfRule { spec: &CONFIG };
pub static PLUGIN_RULE: SelfRule = SelfRule { spec: &PLUGIN };
pub static CLAUDE_SETTINGS_RULE: SelfRule = SelfRule {
    spec: &CLAUDE_SETTINGS,
};
pub static CODEX_SETTINGS_RULE: SelfRule = SelfRule {
    spec: &CODEX_SETTINGS,
};
pub static HOOK_SCRIPT_RULE: SelfRule = SelfRule { spec: &HOOK_SCRIPT };
pub static COPILOT_SETTINGS_RULE: SelfRule = SelfRule {
    spec: &COPILOT_SETTINGS,
};
pub static KIRO_SETTINGS_RULE: SelfRule = SelfRule {
    spec: &KIRO_SETTINGS,
};

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
            &CLAUDE_SETTINGS_RULE,
            &CODEX_SETTINGS_RULE,
            &HOOK_SCRIPT_RULE,
            &COPILOT_SETTINGS_RULE,
            &KIRO_SETTINGS_RULE,
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
            &CODEX_SETTINGS_RULE,
            &HOOK_SCRIPT_RULE,
            &COPILOT_SETTINGS_RULE,
            &KIRO_SETTINGS_RULE,
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
            CLAUDE_SETTINGS_RULE.id(),
            CODEX_SETTINGS_RULE.id(),
            HOOK_SCRIPT_RULE.id(),
            COPILOT_SETTINGS_RULE.id(),
            KIRO_SETTINGS_RULE.id(),
        ] {
            assert!(id.starts_with("core.self_protection."), "id was {id}");
        }
    }

    use crate::testing::proptest::{protected_kind, richer_hook_input};
    use proptest::prelude::*;

    fn all_self_rules() -> [(&'static SelfRule, ProtectedKind); 8] {
        [
            (&BINARY_RULE, ProtectedKind::Binary),
            (&CONFIG_RULE, ProtectedKind::Config),
            (&PLUGIN_RULE, ProtectedKind::Plugin),
            (&CLAUDE_SETTINGS_RULE, ProtectedKind::ClaudeSettings),
            (&CODEX_SETTINGS_RULE, ProtectedKind::CodexSettings),
            (&HOOK_SCRIPT_RULE, ProtectedKind::HookScript),
            (&COPILOT_SETTINGS_RULE, ProtectedKind::CopilotSettings),
            (&KIRO_SETTINGS_RULE, ProtectedKind::KiroSettings),
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
