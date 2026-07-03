//! Regression guard: `rules::iter()` order is part of the determinism
//! contract that the audit pipeline and `engine::aggregate` rely on
//! (`docs/design/audit.md`, `docs/design/decision-model.md`).
//!
//! The order here mirrors the static `RULES` slice in
//! `src/rules/mod.rs`. Any rule reordering — including refactors that
//! split files — must update this fixture consciously, not accidentally.

#[test]
fn rules_iter_order_matches_fixture() {
    let actual: Vec<&str> = ptuf::rules::iter()
        .map(ptuf::rules::ConfigRule::id)
        .collect();
    let expected: &[&str] = &[
        "core.filesystem.destructive-rm",
        "core.network.remote-script-pipe",
        "core.secrets.sensitive-path-to-network",
        "core.secrets.sensitive-bash-read",
        "core.engine.dynamic-eval",
        "core.git.force-push",
        "core.git.force-push-with-lease",
        "core.git.reset-hard",
        "core.git.clean-fdx",
        "core.git.branch-delete-force",
        "core.git.stash-clear",
        "core.git.remote-set-url",
        "core.git.no-verify",
        "core.git.no-gpg-sign",
        "core.git.config-override-bypass",
        "core.git.env-bypass",
        "core.git.push-mirror",
        "core.git.push-delete-remote",
        "core.git.force-if-includes",
        "core.git.update-ref-delete",
        "core.git.reflog-expire",
        "core.git.gc-prune-now",
        "core.git.env-credential-hijack",
        "core.git.env-path-redirect",
        "core.self_protection.binary",
        "core.self_protection.config",
        "core.self_protection.plugin",
        "core.self_protection.claude-settings",
        "core.self_protection.codex-settings",
        "core.self_protection.hook-script",
        "core.self_protection.copilot-settings",
        "core.self_protection.kiro-settings",
        "core.self_protection.pi-settings",
        "core.self_protection.opencode-settings",
        "core.secrets.sensitive-read",
        "core.injection.invisible-chars",
        "core.project_hygiene.lock-mismatch-pnpm",
        "core.project_hygiene.lock-mismatch-uv",
        "core.project_hygiene.protected-branch-destructive-git",
        "core.workspace.outside-access",
    ];
    assert_eq!(actual, expected);
}
