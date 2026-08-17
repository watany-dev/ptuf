# 低価値テスト棚卸しレジスタ

[substantive-test-checklist.md](substantive-test-checklist.md)（守るべき本質的テストの
追加一覧）と **対になる**文書。行カバレッジ 95% 維持のために紛れ込みやすい
「振る舞いを検証していない／重複した低価値テスト」の削減候補を、全テスト精読
（src インライン約 1,576 + tests 51 + PBT 44 + bypass corpus 47 ≒ **実関数 1,700 件超**、
うち本レビューで精読 約 1,400 件）の結果として根拠付きで一覧化する。

- 出典: 全件レビュー（領域 A=rules / B=facts / C=cli+init / D=core / E=tests）
- 判定基準・保持ガードは [testing.md](../design/testing.md) と本書 §判定基準 に従う
- **このレジスタは「削除実行ログ」ではなく「候補レジスタ」**。実削除・統合は別タスクで、
  各行の根拠を再確認し `make check` / `make mutants` を通してから行う
- **判定**: `削除候補` / `統合候補`（N→1 のテーブル化・PBT 吸収）/ `要確認`（判断が割れた）
- security-critical・bypass corpus・代数法則 PBT・total 性/panic 安全 PBT・JSON/schema 契約は
  「薄く見えても**保持**」（§保持ガード）。これらは候補から除外済み

---

## サマリ

| 領域 | 削除候補 | 統合候補 | 要確認 | 精読数 |
| --- | --- | --- | --- | --- |
| A `src/rules/**` | 11 | 16 | 11 | ~205 |
| B `src/facts/**` | 5 | 14 | 11 | ~196 |
| C `src/cli/**` + `src/init/**` | 5 | ~20 本(6 グループ) | 2 | ~290 |
| D core（config/audit/engine/plugin/decision/hook/update ほか） | 4 | 14 | 16 | ~490 |
| E `tests/**` | 0 | 10 | 3 | ~218 |
| **計** | **~25** | **~74 本** | **~43** | **~1,399** |

- **最も確度が高い削除候補**は 2 系統に集約される:
  1. `metadata_matches_design` / `*_accessors` / `*_label_*` 系の**トリビアル定数 getter**
     — `src/rules/mod.rs` の横断 PBT（`pbt_per_rule_decision_kind_matches_default` /
     `pbt_decision_rule_ids_are_known`）や `rule_ids_are_stable_strings` が既に同等契約を担保。
  2. `LazyLock::force` するだけの `all_regexes_compile` / `all_variant_regexes_compile`
     — 実マッチ系テストが間接的に force するため冗長。
- **最も効果が大きい統合候補**は init adapter の**プランビング層**（`write_*_atomically` の
  IO エラー、`sibling_temp_path` default-name、`command_executable`）。各 adapter が
  `init::mod` 共有ヘルパを薄くラップしているだけで、`mod.rs` に等価テストが既存。
- **統合候補の本丸**は「PBT が同一不変条件を直積で網羅済み」の example 群。テーブル駆動 N→1 か
  PBT 吸収で削減可能だが、**削除前に PBT が当該 corner を確実に踏むか個別確認が必須**。

---

## 判定基準（「意味が薄い」の定義）

1. **トリビアル検証** — derive(Debug/Clone/Default/PartialEq) 動作、自明な getter/setter、
   定数をそのまま assert。rustc/serde が保証する範囲。
2. **PBT/example 重複** — 同じ不変条件を PBT と example 両方で検証し example 側が冗長。
3. **同形パラメータ重複** — 入力だけ違う同一ロジックが複数並ぶ。テーブル/ループ 1 本に統合可。
4. **カバレッジ稼ぎ** — 結果を `let _ =` で捨てるだけ、または到達のためだけの薄い assert。
5. **重複アサーション過多** — 1 テストに 5+ assert が混在（削除でなく**分割**提案。別枠）。

---

## A. `src/rules/**`（削除 11 / 統合 16 / 要確認 11）

### 削除候補
| テスト名 | 場所 | カテゴリ | 根拠 |
| --- | --- | --- | --- |
| `metadata_matches_design` | `sensitive_read.rs:220` | 1 | 定数 getter 4 連。`mod.rs` 横断 PBT が default_decision/id を担保 |
| `metadata_matches_design` | `sensitive_bash_read.rs:332` | 1 | 同上（getter 5 連） |
| `metadata_matches_design` | `injection_content.rs:548` | 1 | 同上 |
| `metadata_matches_design_baseline` | `workspace.rs:297` | 1 | 同上 |
| `rule_ids_are_kebab_case_under_self_protection` | `self_protection.rs:344` | 1 | `rule_ids_are_stable_strings` が具体 id を全件 pin 済み |
| `rules_carry_hard_deny_critical_metadata` | `self_protection.rs:306` | 1 | 定数 metadata ループ。横断 PBT と重複 |
| `all_regexes_compile` | `patterns.rs:70` | 4 | `LazyLock::force` のみ。`pbt_*` が実マッチで force |
| `config_rule_defaults_match_documented_baseline` | `rules/mod.rs:258` | 1 | 直下の `_via_dyn_dispatch`(267) と内容同一（経路違い） |
| `protected_git_denies_clean_fdx_*` / `_split_clean_fdx_*` | `project_hygiene.rs:443,453,463` | 3 | `git/mod.rs` の `clean_asks_*`(303-332) が同 matcher を網羅 |

> severity の具体値 pin は横断 PBT に無いため、`metadata_matches_design` 系の削除前に
> severity 契約が別途残るか要確認（下記「要確認」と連動）。

### 統合候補（テーブル化 N→1 / PBT 吸収。security-critical な wrapper 例は残す）
| テスト群 | 場所 | カテゴリ | 吸収先 |
| --- | --- | --- | --- |
| `denies_rm_rf_*`（home/tilde/envvar/root/glob/system）5 本 | `destructive_rm.rs:155-189` | 3 | `pbt_all_destructive_combinations_deny`(388) |
| `denies_alternate_flag_orderings` ほか flag 網羅 4 本 | `destructive_rm.rs:228-255` | 3 | 同上 |
| `asks_on_{node,perl,ruby,python,sh}_dash_*` 6 本 | `dynamic_eval.rs:193-225` | 3 | `DYNAMIC_EVAL_HEADS` テーブル駆動 1 本 |
| `denies_read_of_*` 3 本 | `sensitive_read.rs:95-114` | 2 | `pbt_sensitive_read_paths_always_fire`(318) |
| `asks_for_{cat,source,dot,ssh}_*` 4 本 | `sensitive_bash_read.rs:180-260` | 3 | reader×path テーブル |
| `denies_{id_rsa,dotenv,kube,aws,ssh}_*` 5 本 | `sensitive_net.rs:123-158` | 3 | sink×sensitive テーブル |
| `denies_{curl,fetch,wget}_to_*` 5 本 | `remote_pipe.rs:123-157` | 3 | fetcher×interpreter テーブル |
| `*_rule_fires_*`（ProtectedKind×Rule）7 本 | `self_protection.rs:190-277` | 3 | `pbt_single_kind_fires_exactly_its_rule`(389) |
| `sensitive_path_{case,dd,brace}_form` 3 本 | `patterns.rs:75-99` | 2 | `pbt_brace_dotenv_matches_sensitive_path` ほか |
| `force_push_denies_{long,short}_flag` 2 本 | `git/mod.rs:158,163` | 3 | `pbt_force_push_fires_for_bare_force`(948) |
| `clean_asks_*` flag 形 3 本 | `git/mod.rs:303-321` | 3 | テーブル化 |
| Unicode `asks_for_*`（方向制御/不可視/bidi/tag/C0）8 本 | `injection_content.rs:341-664` | 3 | category×代表 codepoint テーブル |

### 要確認（判断が割れた）
`trait_metadata_is_stable`(destructive_rm.rs:147), `allows_dash_c_without_value`(dynamic_eval.rs:270),
`pbt_outside/inside_path`(workspace.rs:346,367 ↔ example), `config_rule_defaults_*_via_dyn_dispatch`(mod.rs:267, coverage 意図),
`protected_branch_rule_fires_for_git_clean_with_long_force_flag`(project_hygiene.rs:597),
`metadata_matches_design_table`(git/mod.rs:776, 20+ assert だが design 値 pin に固有価値),
`asks_for_new_categories_via_bash_and_mcp`(injection_content.rs:648, 分割可),
`is_content_reader_excludes_hex_dumps`(injection_content.rs:571, helper 単体 vs 挙動) ほか。

---

## B. `src/facts/**`（削除 5 / 統合 14 / 要確認 11）

### 削除候補
| テスト名 | 場所 | カテゴリ | 根拠 |
| --- | --- | --- | --- |
| `all_variant_regexes_compile` | `sensitive.rs:156` | 4 | `LazyLock::force` のみ。build 破損は他全テストが検出 |
| `multiple_kinds_can_match_one_token` | `sensitive.rs:304` | 1/4 | コメント自認「just verify >=1 match」。classify 系と重複 |
| `pbt_unknown_kind_parse_returns_none` | `sensitive.rs:332` | 4 | `prop_assume` で None を仮定し直後に同じ None を assert＝空転 |
| `extract_uses_system_env_lookup` | `path.rs:593` | 4 | コメント「Just exercise the production path」。raw=identity の自明 assert |
| `value_flag_accessors_expose_each_spelling` | `shell.rs:1559` | 1 | `ValueFlag::short()/long()` の自明 getter |

### 統合候補
| テスト群 | 場所 | カテゴリ | 吸収先 |
| --- | --- | --- | --- |
| `parses_url_*`（https/no-path/port/cloud-metadata）4 本 | `url.rs:98-132` | 3 | 表駆動 4→1（metadata は 1 ケース残す） |
| `as_str_round_trips_via_from_str` | `sensitive.rs:277` | 2 | `pbt_kind_round_trips`(327) に完全吸収 |
| `wildcard_match_*` 3 本 | `project.rs:178-191` | 2 | 同名 PBT(231,242) |
| `extracts_{read,edit,write}_*` | `path.rs:469-478` | 3 | tool→PathTool 1 表 |
| `expands_{tilde,lone_tilde,envvar,lone_home}_*` 4 本 | `path.rs:509-531` | 3 | `pbt_tilde_prefix_expands_to_home` ほか |
| redirect op `parses_redirect_{to_file,append,stdin,stderr,merge}` 5 本 | `shell.rs:1393-1437` | 3 | `pbt_redirect_operators_surface_to_pipeline`(1803)。`> ~/.ssh` は個別保持 |
| `double_pipe_is_or_not_pipeline` | `shell.rs:1157` | 2 | `splits_on_and_and_or`(1040) |

### 要確認
`facts_default_is_constructible`(mod.rs:159), `pbt_raw_round_trips`(url.rs:211),
`pbt_no_scheme_separator_fails`(url.rs:258 ↔ example), `collect_returns_default_when_repo_root_is_none`(project.rs:119),
`reads_current_branch`/`on_protected_branch` 系の HEAD 3 分岐(project.rs:148-211),
`match_records_raw_substring`(sensitive.rs:297), `classifies_case_variant_paths`(sensitive.rs:213, 7 assert→分割),
`falls_back_to_raw_when_home_unset`(path.rs:540), `full_path_command_keeps_head_intact`(shell.rs:1151),
`extract_returns_default_facts_for_empty_input`(mod.rs:148, 6 assert) ほか。

---

## C. `src/cli/**` + `src/init/**`（削除 5 / 統合 ~20 本 / 要確認 2）

> **重要**: input parser（cline/copilot/cursor/kiro_input）と output.rs の per-agent 契約は
> 「同形に見えるが JSON 形状・exit code・permissionDecision が**実際に異なる**」ことをコードで
> 確認済み → **全保持**（本領域で最も誤検出が多い箇所）。真の重複は init adapter のプランビング層。

### 削除候補
| テスト名 | 場所 | カテゴリ | 根拠 |
| --- | --- | --- | --- |
| `emit_decision_serialization_failure_returns_one` | `output.rs:617` | 1/4 | 名は「serialize 失敗→1」だが実体は happy-path で code 2 確認。名と内容が乖離 |
| `parse_error_display` | `parse.rs:903` | 1 | Display に固定部分文字列が入るかのトリビアル検証 |
| `cline_hook_file_name_matches_platform` | `cline.rs:263` | 1 | `cfg!(windows)` を再実装して比較するトートロジー |
| `init_error_source_exposes_io_only` | `init/mod.rs:467` | 1 | `Error::source` が Io のみ Some。`display_covers_all_variants` で近接網羅 |

### 統合候補（init mod.rs 共通テストへ集約 / テーブル化）
| テスト群 | 場所 | カテゴリ | 吸収先 |
| --- | --- | --- | --- |
| `write_{,json_}atomically_propagates_*` IO エラー（各 adapter 2-4 本） | claude_code/codex/copilot | 3 | `init/mod.rs:546/620/632`（codex の TOML 版 1 本だけ残す） |
| `sibling_temp_path_uses_default_filename_*`（4 adapter） | claude_code:557, codex:872, copilot:553, cline:416 | 3 | `init/mod.rs:662` ヘルパテスト |
| `command_executable_returns_first_token_or_none`（claude/codex） | claude_code.rs:519, codex.rs:597 | 3 | `init/mod.rs` に 1 本移動 |
| `decision_exit_code_*_matrix`（4 本） | output.rs:228,331,432,518 | 5 | `emit_decision` と重複再 assert → テーブル駆動 1 本 |
| `pbt_parse_is_total_on_arbitrary_utf8`（4 adapter、完全同形） | copilot/cline/cursor/kiro_input | 3 | マクロ/ループで 4→1（別 module 配置のため要確認寄り） |

### 要確認
`entry_commands/hooks_returns_empty_*`（関数別実装のため基本保持。ただし copilot:547 ↔ cursor:754 は完全同形）。

---

## D. core（削除 4 / 統合 14 / 要確認 16）

### 削除候補
| テスト名 | 場所 | カテゴリ | 根拠 |
| --- | --- | --- | --- |
| `rule_id_and_reason_accessors` | `decision.rs:171` | 1 | derive フィールドの単純 getter。挙動ロジックなし |
| `pbt_aggregate_empty_is_allow` | `decision.rs:243` | 2 | `_dummy in 0u8..1` の退化 PBT。example 版(183)と等価で PBT の意味なし |
| `fake_exe_locator_round_trips_inputs` | `update/exe.rs:123` | 1 | テストダブル自身の struct round-trip。プロダクトロジック無し |
| `decision_label_returns_each_label_directly` | `plugin/runner.rs:523` | 1 | enum→定数文字列の match（コメントで coverage 目的と明記） |

### 統合候補
| テスト群 | 場所 | カテゴリ | 吸収先 |
| --- | --- | --- | --- |
| `aggregate_empty_is_allow` | `decision.rs:183` | 2 | （退化 PBT 削除側と対。example を残し PBT を消す） |
| `merge_of_no_layers` / `later_layer_wins_*` | `config/merge.rs` | 2 | `pbt_merge_scalars_are_last_write_wins` |
| `ordered_paths_{preserves_priority,skips_none}` | `config/scope.rs:143` | 2 | 1 つの順序契約に統合 |
| `bash_command_returns_string_*` 等 accessor | `hook_input.rs` | 2 | `pbt_*_round_trips` |
| claude/codex/copilot `ask→deny` example 群 | `hook_output.rs` | 2 | `pbt_*` adapter シリアライズ PBT（代表 1 例残す） |
| dsl compile-error example 群 | `plugin/dsl.rs` | 3 | パラメータ化 |
| yaml/api_version/kind error_path round-trip 群 | `plugin/loader.rs:317-386` | 3 | cross-variant 不変条件 1 本 |
| `{deny,ask,monitor,allow}_rule_emits_*` 4 本 | `plugin/rule.rs:126-180` | 3 | DecisionKind→Decision テーブル（reason 検証のみ deny に残す） |
| `redaction_mode_parses_*` / `mode_parses_each_*` | `config/schema.rs:242-258` | 3 | enum パース table |
| `config_error_source_returns_*` 2 本 | `config/mod.rs:273,283` | 3 | variant 別を table 化 |
| `raw_*_into_*_passes_fields_through` | `config/schema.rs:281,299` | 1 | From 変換のフィールド写像 |
| `full_layout_snapshot` | `reason.rs:43` | 5 | `includes_*`/`enumerates_*` と重複（代表化） |

### 要確認
`severity_enum_orders_*`(decision.rs:189), `placeholder_constant_is_stable`(redaction.rs:330),
`system_env_var_os_reads_*`/`default_layout_uses_system_env_*`(config/scope.rs, seam smoke),
`severity_label_covers_each_variant`(record.rs:333), `noop_sink_accepts_any_record`(audit/mod.rs),
`real_exe_locator_returns_some_path`(exe.rs:116), `strategy_label_*`(update/mod.rs:1170),
`platform_host_picks_a_valid_variant`(update/mod.rs:1232), `protected_kind_round_trip_strings`(self_paths.rs:549),
`supported_facts_includes_expected_v0_3_set`(loader.rs:285), `defaults_overridable_*`(rule.rs:194),
`mode_rejects_removed_observe_variant`(schema.rs:273) ほか。

---

## E. `tests/**`（削除 0 / 統合 10 / 要確認 3）

> 統合テストはプロセス境界（exit code・実バイナリの JSON 形状・fd/tempfile リーク）の価値が
> あるため**削除候補ゼロ**。唯一の実質クラスタは cli_smoke の非 claude-code agent hook smoke。

### 統合候補（`cli_smoke.rs` → `contracts.rs` に集約。同じプロセス境界でより厳密に重複）
| smoke テスト | 場所 | 集約先（contracts.rs） |
| --- | --- | --- |
| `codex_hook_allows_safe_payload_with_empty_streams` | cli_smoke.rs:169 | `codex_allow_outputs_empty_stdout_exit_zero`(731) |
| `codex_hook_maps_ask_to_deny` | cli_smoke.rs:178 | `codex_ask_demotes_to_deny`(739) |
| `cline_hook_denies_destructive_rm_*` | cli_smoke.rs:218 | `cline_deny_outputs_cancel_json_*`(396) |
| `cline_hook_allows_safe_payload_*` | cli_smoke.rs:242 | `cline_allow_outputs_empty_object_*`(417) |
| `cline_hook_invalid_json_fails_closed_*` | cli_smoke.rs:254 | `cline_invalid_payload_outputs_cancel_json_*`(426) |
| `cursor_hook_denies_destructive_rm_*` | cli_smoke.rs:270 | `cursor_deny_outputs_bare_permission_envelope_*`(475) |
| `cursor_hook_preserves_ask_*` | cli_smoke.rs:287 | `cursor_ask_is_preserved_*`(501) |
| `cursor_hook_allows_safe_payload_*` | cli_smoke.rs:306 | `cursor_allow_outputs_explicit_allow_*`(532) |
| `cursor_hook_invalid_json_fails_closed_*` | cli_smoke.rs:318 | `cursor_invalid_payload_fails_closed_*`(547) |

> **保守判断**: Kiro の smoke 2 本（cli_smoke.rs:188,197）は contracts.rs に Kiro 契約セクションが
> 無いため**保持**（誤検出回避）。

### 要確認
`kiro_hook_invalid_json_fails_closed_with_stderr_only`(cli_smoke.rs:206, 非 ignore 唯一の Kiro fail-closed),
`check_denies_*` ルール発火群(cli_smoke.rs, rules unit + corpus と重複だが `check` の exit/表示 end-to-end は smoke のみ。代表数件への削減を要確認)。

---

## 保持ガード（薄く見えても保持＝誤検出として除外したもの）

実削除タスクで**絶対に消してはならない**カテゴリ。本レビューで候補から除外済み。

- **bypass corpus / `known_gap` / `gap_*`**（ADR 0001 契約）: `tests/bypass/corpus.jsonl`,
  `tests/bypass_corpus.rs`, `sensitive_bash_read.rs` の `gap_*`, `triple_nested_su_bash_c`
- **security-critical な example**: wrapper unwrap（`bash -c`/`su -c`/`sudo -u`/`doas`/`pkexec`/
  `find -exec`/full-path）, sensitive path/net co-location, remote pipe, destructive rm,
  force-push/+refspec, redirect→sensitive, command/process substitution の pessimistic flag,
  symlink/`..` traversal containment, workspace 境界 lookalike
- **代数法則 PBT**: `decision::aggregate`（結合/交換/冪等/単位元/上界）, `plugin/dsl` De Morgan,
  `config/merge` 層合成則, `update` version 順序, redaction 正当性/冪等
- **total 性・panic 安全・forward-progress PBT**: `*_never_panics`, `*_is_total_on_arbitrary_*`,
  `read_word_advances_for_every_non_separator_byte`, `lone_ampersand_does_not_loop`
- **JSON round-trip / schema / audit record 契約**: 各 adapter envelope, `contracts.rs`,
  `init_verify_json_schema_contract_is_stable`
- **プロセス境界 E2E**: `e2e_heavy.rs` 全 41 件（fd/tempfile リーク・8 MiB 境界・concurrent JSONL・
  5 adapter parity・病的入力・latency）, init の byte-for-byte idempotency, update の hermetic shell-out
- **config end-to-end**: `config_integration.rs` 全 34 件, `decide_vs_cli_fail_closed_parity_documented`
- **per-agent hook 契約**（C 領域）: input parser・output envelope・install 生成内容は
  JSON 形状/exit code/feature-flag が agent 固有のため統合不可
- **self_paths / self_protection 保護パス契約**, **reason 文契約**（rule_id/alternatives/line 埋め込み）

---

## フォローアップ（実削除タスクの指針）

1. **着手順**（誤検出リスク低→高）:
   - ① C 領域の init プランビング統合（共有ヘルパに既存等価テストあり、最も安全）
   - ② トリビアル削除候補（`metadata_matches_design` 系・`all_regexes_compile` 系・退化 PBT）
   - ③ PBT 吸収系の統合（**削除前に PBT が当該 corner を踏むか個別確認**）
   - ④ E 領域 smoke→contracts 集約（Kiro は保持）
2. **severity 契約の確認**: `metadata_matches_design` 系を消す前に、severity 具体値が横断 PBT か
   別テストで残るかを確認（残らないなら 1 本だけ severity table を新設）。
3. **退行防止**: 各削除・統合 PR では `make check`（fmt/clippy/test/doc/deny）に加え、
   decision コアに触れる場合 `make mutants`（`.cargo/mutants.toml` スコープ）を回し
   **MISSED mutant が増えていない**ことを確認。カバレッジは `make coverage` で 95% 維持を確認。
4. **要確認（~43 件）の裁定**: 判断が割れた行は、削除前に `make mutants` の CAUGHT 差分
   または `make coverage` の行差分で「消しても検出力・カバレッジが落ちない」ことを定量確認する
   （[計画 §Step3]）。落ちるなら保持。
5. corpus に新規 bypass を見つけた場合は本レジスタではなく `tests/bypass/corpus.jsonl` に追記。
