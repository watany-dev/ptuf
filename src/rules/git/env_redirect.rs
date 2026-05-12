//! Env-var redirection rules for networked / repository-rooted git ops.
//!
//! - `core.git.env-credential-hijack` — `GIT_SSH_COMMAND` / `GIT_SSH` /
//!   `GIT_ASKPASS` / `SSH_ASKPASS` in front of a networked git command
//!   replaces git's transport or credential prompt.
//! - `core.git.env-path-redirect` — `GIT_DIR` / `GIT_WORK_TREE` /
//!   `GIT_OBJECT_DIRECTORY` / `GIT_INDEX_FILE` / `GIT_CONFIG{,_GLOBAL,_SYSTEM}` /
//!   `GIT_ALTERNATE_OBJECT_DIRECTORIES` re-points git at a different
//!   repository, config, or object store for this one invocation.

use crate::decision::{DecisionKind, Severity};
use crate::facts::shell::Argv;

use super::argv::{BypassMatch, matches_env_keys};
use super::{GitRule, RuleSpec};

const CREDENTIAL_HIJACK_SUBCOMMANDS: &[&str] =
    &["push", "pull", "fetch", "clone", "ls-remote", "remote"];

const CREDENTIAL_HIJACK_KEYS: &[(&str, BypassMatch)] = &[
    ("GIT_SSH_COMMAND", BypassMatch::Any),
    ("GIT_SSH", BypassMatch::Any),
    ("GIT_ASKPASS", BypassMatch::Any),
    ("SSH_ASKPASS", BypassMatch::Any),
];

const PATH_REDIRECT_KEYS: &[(&str, BypassMatch)] = &[
    ("GIT_DIR", BypassMatch::Any),
    ("GIT_WORK_TREE", BypassMatch::Any),
    ("GIT_OBJECT_DIRECTORY", BypassMatch::Any),
    ("GIT_INDEX_FILE", BypassMatch::Any),
    ("GIT_CONFIG", BypassMatch::Any),
    ("GIT_CONFIG_GLOBAL", BypassMatch::Any),
    ("GIT_CONFIG_SYSTEM", BypassMatch::Any),
    ("GIT_ALTERNATE_OBJECT_DIRECTORIES", BypassMatch::Any),
];

pub(super) fn matches_env_credential_hijack(argv: &Argv) -> bool {
    matches_env_keys(
        argv,
        Some(CREDENTIAL_HIJACK_SUBCOMMANDS),
        CREDENTIAL_HIJACK_KEYS,
    )
}

pub(super) fn matches_env_path_redirect(argv: &Argv) -> bool {
    matches_env_keys(argv, None, PATH_REDIRECT_KEYS)
}

const ENV_CREDENTIAL_HIJACK: RuleSpec = RuleSpec {
    id: "core.git.env-credential-hijack",
    severity: Severity::High,
    decision_kind: DecisionKind::Deny,
    hard_deny: false,
    matcher: matches_env_credential_hijack,
    problem: "Inline GIT_SSH_COMMAND / GIT_SSH / GIT_ASKPASS / SSH_ASKPASS in front of a \
         networked git command replaces git's transport or credential-prompt program for \
         this single invocation — a well-known vector for exfiltrating credentials or \
         redirecting traffic.",
    alternatives: &[
        "Configure ssh / askpass once in ~/.ssh/config or git config and re-run.",
        "If the override is genuinely needed, set it in repo config so it is reviewable.",
    ],
};

const ENV_PATH_REDIRECT: RuleSpec = RuleSpec {
    id: "core.git.env-path-redirect",
    severity: Severity::High,
    decision_kind: DecisionKind::Deny,
    hard_deny: false,
    matcher: matches_env_path_redirect,
    problem: "Inline GIT_DIR / GIT_WORK_TREE / GIT_OBJECT_DIRECTORY / GIT_INDEX_FILE / \
         GIT_CONFIG{,_GLOBAL,_SYSTEM} / GIT_ALTERNATE_OBJECT_DIRECTORIES re-points git at a \
         different repository, config, or object store for this one invocation — bypassing \
         every project-local guard, hook, and audit trail.",
    alternatives: &[
        "Run git from inside the intended worktree without redirecting paths.",
        "If you really need an alternate repo, cd into it and run git normally.",
    ],
};

pub static ENV_CREDENTIAL_HIJACK_RULE: GitRule = GitRule {
    spec: &ENV_CREDENTIAL_HIJACK,
};
pub static ENV_PATH_REDIRECT_RULE: GitRule = GitRule {
    spec: &ENV_PATH_REDIRECT,
};
