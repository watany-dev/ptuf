//! Commit-signing / hook / config / env bypass rules.
//!
//! - `core.git.no-verify` — skips pre-commit / commit-msg / pre-push hooks.
//! - `core.git.no-gpg-sign` — disables required commit/tag signing.
//! - `core.git.config-override-bypass` — `git -c <key>=<value>` that turns
//!   off hooks / signing / fsck for a single invocation.
//! - `core.git.env-bypass` — inline `HUSKY=0` / `LEFTHOOK=0` / `SKIP=` etc.

use crate::decision::{DecisionKind, Severity};
use crate::facts::shell::Argv;

use super::argv::{
    BypassMatch, args_after_subcommand, bypass_value_matches, config_overrides, git_subcommand,
    matches_env_keys,
};
use super::{GitRule, RuleSpec};

const NO_VERIFY_SUBCOMMANDS: &[&str] = &[
    "commit",
    "push",
    "merge",
    "rebase",
    "pull",
    "am",
    "cherry-pick",
    "revert",
    "fetch",
];

const NO_GPG_SIGN_SUBCOMMANDS: &[&str] = &[
    "commit",
    "merge",
    "rebase",
    "cherry-pick",
    "revert",
    "tag",
    "am",
    "pull",
];

const BYPASS_SCOPE_SUBCOMMANDS: &[&str] = &[
    "commit",
    "push",
    "merge",
    "rebase",
    "tag",
    "am",
    "cherry-pick",
    "revert",
    "pull",
];

const CONFIG_BYPASS_KEYS: &[(&str, BypassMatch)] = &[
    ("core.hookspath", BypassMatch::Any),
    ("commit.gpgsign", BypassMatch::Falsy),
    ("tag.gpgsign", BypassMatch::Falsy),
    ("merge.verifysignatures", BypassMatch::Falsy),
    ("transfer.fsckobjects", BypassMatch::Falsy),
    ("receive.fsckobjects", BypassMatch::Falsy),
    ("fetch.fsckobjects", BypassMatch::Falsy),
];

const ENV_BYPASS_KEYS: &[(&str, BypassMatch)] = &[
    ("HUSKY", BypassMatch::Falsy),
    ("LEFTHOOK", BypassMatch::Falsy),
    ("PRE_COMMIT_ALLOW_NO_CONFIG", BypassMatch::Truthy),
    ("SKIP", BypassMatch::Any),
    ("GIT_HOOK_SKIP", BypassMatch::Any),
    ("CORE_HOOKSPATH", BypassMatch::Any),
];

pub(super) fn matches_no_verify(argv: &Argv) -> bool {
    let Some(sub) = git_subcommand(argv) else {
        return false;
    };
    if !NO_VERIFY_SUBCOMMANDS.contains(&sub) {
        return false;
    }
    let rest = args_after_subcommand(argv, sub);
    if rest.contains(&"--no-verify") {
        return true;
    }
    // `-n` only means no-verify on `git commit`. On `push`/`pull`/`merge`/
    // `rebase` it is `--dry-run` or `--no-stat`; on `tag` it sets the
    // displayed line count.
    if sub != "commit" {
        return false;
    }
    rest.iter().any(|a| {
        if !a.starts_with('-') || a.starts_with("--") {
            return false;
        }
        a[1..].contains('n')
    })
}

pub(super) fn matches_no_gpg_sign(argv: &Argv) -> bool {
    let Some(sub) = git_subcommand(argv) else {
        return false;
    };
    if !NO_GPG_SIGN_SUBCOMMANDS.contains(&sub) {
        return false;
    }
    let rest = args_after_subcommand(argv, sub);
    rest.contains(&"--no-gpg-sign")
}

pub(super) fn matches_config_override_bypass(argv: &Argv) -> bool {
    let Some(sub) = git_subcommand(argv) else {
        return false;
    };
    if !BYPASS_SCOPE_SUBCOMMANDS.contains(&sub) {
        return false;
    }
    for raw in config_overrides(argv) {
        let Some(eq) = raw.find('=') else {
            continue;
        };
        let key = raw[..eq].trim();
        let value = &raw[eq + 1..];
        for (target_key, mode) in CONFIG_BYPASS_KEYS {
            if key.eq_ignore_ascii_case(target_key) && bypass_value_matches(*mode, value) {
                return true;
            }
        }
    }
    false
}

pub(super) fn matches_env_bypass(argv: &Argv) -> bool {
    matches_env_keys(argv, Some(BYPASS_SCOPE_SUBCOMMANDS), ENV_BYPASS_KEYS)
}

const NO_VERIFY: RuleSpec = RuleSpec {
    id: "core.git.no-verify",
    severity: Severity::High,
    decision_kind: DecisionKind::Deny,
    hard_deny: false,
    matcher: matches_no_verify,
    problem: "git --no-verify (or `commit -n`) skips pre-commit, commit-msg, pre-push and \
         pre-rebase hooks, which are usually the project's first line of defence against \
         broken or unsigned commits.",
    alternatives: &[
        "Run the hooks once and fix the failures rather than bypassing them.",
        "If a hook is genuinely broken, fix it in the repo so the team benefits.",
        "If a hot-fix truly needs the bypass, allowlist this rule with an explicit expiresAt.",
    ],
};

const NO_GPG_SIGN: RuleSpec = RuleSpec {
    id: "core.git.no-gpg-sign",
    severity: Severity::Medium,
    decision_kind: DecisionKind::Deny,
    hard_deny: false,
    matcher: matches_no_gpg_sign,
    problem: "git --no-gpg-sign overrides a project- or user-level requirement to sign commits \
         and tags, producing artefacts that downstream verification will reject.",
    alternatives: &[
        "Make sure your signing key is configured (gpg.format / user.signingkey) and re-run.",
        "If signing is intentionally optional in this repo, drop commit.gpgsign from config rather than per-call --no-gpg-sign.",
    ],
};

const CONFIG_OVERRIDE_BYPASS: RuleSpec = RuleSpec {
    id: "core.git.config-override-bypass",
    severity: Severity::High,
    decision_kind: DecisionKind::Deny,
    hard_deny: false,
    matcher: matches_config_override_bypass,
    problem: "git -c <key>=<value> can disable hooks (core.hooksPath), turn off commit signing \
         (commit.gpgsign=false), or relax fsck checks for a single invocation, which is \
         almost always a bypass rather than a legitimate one-shot override.",
    alternatives: &[
        "Address the underlying check (fix the hook, install the signing key, etc.) instead.",
        "If the override is genuinely needed, set it in repo config explicitly so it is reviewable.",
        "Allowlist this rule with an expiry rather than embedding -c in scripts.",
    ],
};

const ENV_BYPASS: RuleSpec = RuleSpec {
    id: "core.git.env-bypass",
    severity: Severity::High,
    decision_kind: DecisionKind::Deny,
    hard_deny: false,
    matcher: matches_env_bypass,
    problem: "Inline environment assignments such as HUSKY=0, LEFTHOOK=0, or SKIP=<hook> in \
         front of a git command turn off the project's commit hooks for this single \
         invocation without leaving any trace in repo config.",
    alternatives: &[
        "Run the hooks and resolve the failures.",
        "If a hook is broken on your machine only, fix it locally instead of routinely setting HUSKY=0.",
        "Allowlist this rule with an expiry if a one-off bypass is genuinely warranted.",
    ],
};

pub static NO_VERIFY_RULE: GitRule = GitRule { spec: &NO_VERIFY };
pub static NO_GPG_SIGN_RULE: GitRule = GitRule { spec: &NO_GPG_SIGN };
pub static CONFIG_OVERRIDE_BYPASS_RULE: GitRule = GitRule {
    spec: &CONFIG_OVERRIDE_BYPASS,
};
pub static ENV_BYPASS_RULE: GitRule = GitRule { spec: &ENV_BYPASS };
