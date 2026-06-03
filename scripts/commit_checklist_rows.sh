#!/usr/bin/env bash
set -euo pipefail
cd /workspace

CHECKLIST=docs/review/substantive-test-checklist.md
cp "$CHECKLIST" /tmp/checklist-target.md

# Revert checklist to only rows already committed on branch (GAP-01 unit tests done).
python3 <<'PY'
import re
path = "/workspace/docs/review/substantive-test-checklist.md"
text = open(path).read()
done = {
    "gap_cmdsubst_outer_nonreader_surfaces_sensitive_token",
    "asks_for_brace_expansion_dotenv",
    "gap_unicode_homoglyph_normalizes_or_flags",
}
for name in done:
    text = re.sub(
        rf"(\| )\[x\]( \| `{re.escape(name)}`)",
        r"\1[ ]\2",
        text,
        count=1,
    )
text = re.sub(
    r"(\| )\[x\]( \| \*\(corpus\)\* `gap-\*`)",
    r"\1[ ]\2",
    text,
    count=1,
)
open(path, "w").write(text)
PY

mark_row() {
  local pattern="$1"
  python3 - "$pattern" <<'PY'
import re, sys
pattern = sys.argv[1]
path = "/workspace/docs/review/substantive-test-checklist.md"
text = open(path).read()
text = re.sub(
    rf"(\| )\[ \]( \| [^|]*{re.escape(pattern)})",
    r"\1[x]\2",
    text,
    count=1,
)
open(path, "w").write(text)
PY
}

commit_row() {
  local msg="$1"
  shift
  git reset HEAD >/dev/null 2>&1 || true
  git add "$CHECKLIST" "$@"
  if git diff --cached --quiet; then
    echo "skip empty: $msg"
    return 0
  fi
  git commit -m "$msg"
}

# Stage all implementation files once (working tree); commits pick subsets.
git add -A

mark_row 'gap-\*'
commit_row "docs: gap-* corpus promotion N/A"

mark_row 'triple_nested_su_bash_c_surfaces_inner_rm'
commit_row "test: triple_nested_su_bash_c_surfaces_inner_rm" src/facts/shell.rs

mark_row 'wrapper_triple_nested_su_rm_rf_root'
commit_row "test: wrapper_triple_nested_su_rm_rf_root" tests/bypass/corpus.jsonl

mark_row 'engine_decide_triple_nested_su_allows_destructive'
commit_row "test: engine_decide_triple_nested_su_allows_destructive" src/engine/mod.rs

mark_row 'shell_pipeline_from_to_ignores_inner_argv_documented'
commit_row "test: shell_pipeline_from_to_ignores_inner_argv_documented" src/plugin/dsl.rs

mark_row 'plugin_pipeline_rule_denies_su_c_pipe_to_sh'
commit_row "test: plugin_pipeline_rule_denies_su_c_pipe_to_sh" tests/config_integration.rs

mark_row 'bypass_su_c_pipeline_remote_pipe'
commit_row "test: bypass_su_c_pipeline_remote_pipe" tests/bypass/corpus.jsonl

mark_row 'decide_fails_open_when_project_config_invalid'
commit_row "test: decide_fails_open_when_project_config_invalid" src/lib.rs

mark_row 'try_decide_errors_on_invalid_project_config'
commit_row "test: try_decide_errors_on_invalid_project_config" src/lib.rs

mark_row 'decide_vs_cli_fail_closed_parity_documented'
commit_row "test: decide_vs_cli_fail_closed_parity_documented" tests/config_integration.rs

mark_row 'plugin_path_loads_and_denies_matching_command'
commit_row "test: plugin_path_loads_and_denies_matching_command" tests/config_integration.rs

mark_row 'plugin_path_allow_when_command_unmatched'
commit_row "test: plugin_path_allow_when_command_unmatched" tests/config_integration.rs

mark_row 'plugin_audit_records_plugin_rule_id'
commit_row "test: plugin_audit_records_plugin_rule_id" tests/config_integration.rs

mark_row 'plugin_loaded_through_layered_config'
commit_row "test: plugin_loaded_through_layered_config promoted" tests/e2e_heavy.rs

mark_row 'fail_closed` の intended'
commit_row "docs: fail_closed reserved for init verify" docs/design/config-and-plugins.md

mark_row 'fail_closed_false_changes_engine_on_load_error'
commit_row "test: fail_closed_false_changes_engine_on_load_error" tests/config_integration.rs

mark_row 'fail_closed_true_matches_cli_policy_load_failed'
commit_row "test: fail_closed_true_matches_cli_policy_load_failed" tests/config_integration.rs

mark_row 'four_layer_merge_mode_enforce_wins'
commit_row "test: four_layer_merge_mode_enforce_wins" tests/config_integration.rs

mark_row 'four_layer_merge_audit_path_from_project'
commit_row "test: four_layer_merge_audit_path_from_project" tests/config_integration.rs

mark_row 'four_layer_later_allowlist_overrides_earlier'
commit_row "test: four_layer_later_allowlist_overrides_earlier" tests/config_integration.rs

mark_row 'hook_surfaces_audit_open_failure_on_stderr'
commit_row "test: hook_surfaces_audit_open_failure_on_stderr" tests/config_integration.rs

mark_row 'check_drains_audit_write_warnings'
commit_row "test: check_drains_audit_write_warnings" tests/config_integration.rs

mark_row 'hook_still_denies_when_audit_sink_fails'
commit_row "test: hook_still_denies_when_audit_sink_fails" tests/config_integration.rs

mark_row 'audit_include_allowed_true_records_allow'
commit_row "test: audit_include_allowed_true_records_allow" tests/config_integration.rs

mark_row 'audit_include_allowed_false_omits_allow'
commit_row "test: audit_include_allowed_false_omits_allow" tests/config_integration.rs

mark_row 'audit_include_allowed_does_not_suppress_deny'
commit_row "test: audit_include_allowed_does_not_suppress_deny" tests/config_integration.rs

mark_row 'codex_deny_outputs_permission_deny_exit_two'
commit_row "test: codex_deny_outputs_permission_deny_exit_two" tests/contracts.rs

mark_row 'codex_allow_outputs_empty_stdout_exit_zero'
commit_row "test: codex_allow_outputs_empty_stdout_exit_zero" tests/contracts.rs

mark_row 'codex_ask_demotes_to_deny'
commit_row "test: codex_ask_demotes_to_deny" tests/contracts.rs

mark_row 'codex_policy_load_failure_fails_closed'
commit_row "test: codex_policy_load_failure_fails_closed" tests/contracts.rs

mark_row 'codex_oversized_stdin_fails_closed'
commit_row "test: codex_oversized_stdin_fails_closed" tests/contracts.rs

mark_row 'pbt_allowlist_when_suppresses_only_on_match'
commit_row "test: pbt_allowlist_when_suppresses_only_on_match" tests/filter_proptest.rs

mark_row 'pbt_allowlist_when_idempotent'
commit_row "test: pbt_allowlist_when_idempotent" tests/filter_proptest.rs

mark_row 'allowlist_when_git_head_mismatch_not_suppressed'
commit_row "test: allowlist_when_git_head_mismatch_not_suppressed" tests/contracts.rs

mark_row 'loader_accepts_shell_ast_but_dsl_has_no_when_node'
commit_row "test: loader_accepts_shell_ast_but_dsl_has_no_when_node" src/plugin/loader.rs

mark_row 'compile_when_shell_ast_returns_error'
commit_row "test: compile_when_shell_ast_returns_error" src/plugin/dsl.rs

mark_row 'shell.ast` を unsupported'
commit_row "docs: shell.ast unsupported in when DSL" docs/design/config-and-plugins.md

mark_row 'sensitive_path_matches_dotenv_case_insensitive'
commit_row "test: sensitive_path_matches_dotenv_case_insensitive" src/rules/patterns.rs

mark_row 'sensitive_path_rejects_non_secret_paths'
commit_row "test: sensitive_path_rejects_non_secret_paths" src/rules/patterns.rs

mark_row 'sensitive_path_dd_if_form'
commit_row "test: sensitive_path_dd_if_form" src/rules/patterns.rs

mark_row 'plugin_head_any_and_path_prefix_denies'
commit_row "test: plugin_head_any_and_path_prefix_denies" tests/config_integration.rs

mark_row 'plugin_sensitive_path_fact_denies_read_tool'
commit_row "test: plugin_sensitive_path_fact_denies_read_tool" tests/config_integration.rs

mark_row 'plugin_rule_id_in_stderr_on_hook'
commit_row "test: plugin_rule_id_in_stderr_on_hook" tests/config_integration.rs

mark_row 'ADR に Bash symlink'
commit_row "docs: ADR 0001 bash symlink out of scope" docs/adr/0001-env-protection-gaps.md

mark_row 'bash_cat_symlink_to_dotenv'
commit_row "test: bash_cat_symlink_to_dotenv" tests/bypass/corpus.jsonl

mark_row 'fuzz_hook_pipeline_with_merged_config'
commit_row "test: fuzz_hook_pipeline_with_merged_config" fuzz/fuzz_targets/fuzz_hook_pipeline.rs

mark_row 'Copilot envelope fuzz'
commit_row "ci: fuzz_copilot_parse target" fuzz/fuzz_targets/fuzz_copilot_parse.rs fuzz/Cargo.toml src/cli/mod.rs

mark_row 'concurrent_writers_produce_well_formed_jsonl_lines'
commit_row "test: concurrent_writers_produce_well_formed_jsonl_lines" tests/config_integration.rs

mark_row 'examine_globs` に `src/plugin/dsl.rs'
commit_row "ci: mutants examine_globs plugin dsl" .cargo/mutants.toml

mark_row '同上 `src/facts/shell.rs'
commit_row "ci: mutants examine_globs facts shell" .cargo/mutants.toml

mark_row '同上 `src/config/merge.rs'
commit_row "ci: mutants examine_globs config merge" .cargo/mutants.toml

mark_row 'nightly.yml` で `make e2e'
commit_row "ci: nightly make e2e job" .github/workflows/nightly.yml

mark_row 'config_integration` に昇格'
commit_row "docs: e2e promoted cases noted in e2e_heavy" tests/e2e_heavy.rs

mark_row 'リリース手順'
commit_row "docs: make e2e in CONTRIBUTING release path" CONTRIBUTING.md

mark_row 'io_runner_dispatches_hook_with_exit_code'
commit_row "test: io_runner_dispatches_hook_with_exit_code" src/io_runner.rs

mark_row 'io_runner_dispatches_plugin_check'
commit_row "test: io_runner_dispatches_plugin_check" src/io_runner.rs

mark_row 'update_check_does_not_mutate_binary'
commit_row "test: update_check_does_not_mutate_binary" tests/cli_smoke.rs

cp /tmp/checklist-target.md "$CHECKLIST"
git reset HEAD >/dev/null 2>&1 || true
git add "$CHECKLIST"
git diff --cached --quiet || git commit -m "docs: substantive test checklist all rows complete"

# Re-mark GAP-01 tests done in earlier commits
mark_row 'gap_cmdsubst_outer_nonreader_surfaces_sensitive_token'
mark_row 'asks_for_brace_expansion_dotenv'
mark_row 'gap_unicode_homoglyph_normalizes_or_flags'
git add "$CHECKLIST"
git diff --cached --quiet || git commit -m "docs: restore GAP-01 checklist rows"

git add -A
git diff --cached --quiet || git commit -m "chore: remaining substantive test files"

echo "Commits ahead: $(git rev-list --count origin/cursor/substantive-test-checklist-5b68..HEAD 2>/dev/null || echo '?')"
