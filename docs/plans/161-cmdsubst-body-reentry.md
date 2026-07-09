# Plan: Command substitution body re-entry — issue #161

## Context

`tests/bypass/corpus.jsonl` の `gap-cmdsubst-outer-nonreader` (ADR 0001 /
ADR 0002 B5) が、外側 head が非 reader の command substitution

```bash
echo $(cat .env)   # 現状 allow — 内側の cat .env が見えない
```

を allow で pin している。`src/facts/shell.rs` は `$(…)` / backtick を
opaque に畳み `has_command_substitution` しか立てない。悲観モードは
flat `commands()` 上の reader × 機密共起を要求するため
`cat $(echo .env)` は捕まえるが、本形は沈黙する。

#163 (homoglyph) / プロセス置換 remote pipe とは独立。後者は本 capture
を前提とするため **本 issue を先に実装する**。

## 現状の穴 (実測)

1. `read_word` は unquoted / double-quoted の `$(` と backtick で
   `saw_subst=true` にするだけで、paren balance 吸収も body capture も
   しない (`<(…)` だけが balance-absorb)。
2. `Argv` に置換本体用フィールドは無く、`collect_commands` は
   `inner_argv` のみ flatten。
3. `sensitive_bash_read::argv_reads_sensitive` は `inner_argv` /
   `inner_redirects` のみ再帰。悲観パスも outer 非 reader では不発。
4. pin: `gap_cmdsubst_outer_nonreader_surfaces_sensitive_token` が
   「token は argv に載るが rule は沈黙」を assert。corpus は
   `known_gap` / allow。

## 設計方針 (ponytail)

| 採る | 採らない |
| --- | --- |
| tokenizer で `$(…)` / backtick を balance-absorb + body capture | 「置換フラグ + 機密 ⇒ 常に ask」(FP) |
| 既存 `parse_inner_shell` / `NESTING_BUDGET` で再パース | 新規クレート・本格 bash AST |
| **`subst_argv: Vec<Argv>`** (inner と分離) | body を `inner_argv` に混在 |
| `commands()` flatten に `subst_argv` を含める | 悲観モード削除 |
| rule / DSL / path walker に 1 行対称の `subst_argv` 再帰 | プロセス置換 re-entry (別 issue) |

### API / データ流

```text
tokenize
  read_word → (word, advanced, saw_subst, bodies: Vec<String>)
  Token::Word { text, subst_bodies }
parse_pipeline / parse_argv
  words + 付随 bodies を argv に束ねる
  nesting_budget > 0 なら各 body を parse_inner_shell → subst_argv
Argv::collect_commands
  self → inner_argv* → subst_argv* (再帰)
```

`read_word` 変更の要点:

1. unquoted `$(` — `<(…)` と同じ paren-depth ループで閉じ `)` まで吸収。
   word には `$(…)` 全文を残し、内側バイト列を `bodies` に push。
2. unquoted / quoted-as-opener backtick — 閉じ `` ` `` まで吸収、内側を
   `bodies` に。未閉じは EOF まで (heredoc degrade と同型)。
3. double-quoted 内 `$(…)` — flag に加え body capture (既存 flag 契約と一致)。
4. single-quoted 内は literal のまま (capture しない)。

`parse_argv` は現状 `Vec<String>` だけ受け取るため、
`Vec<(String, Vec<String>)>` または並列 `subst_bodies: Vec<String>` を
pipeline 側で集約して渡す。集約は「この argv を構成する全 word の
bodies を連結」で足りる (word 単位の帰属は rule に不要)。

budget / 空 body / 再パース結果が空でも `has_command_substitution` は
**下げない**。surface 失敗時の backstop が悲観モード。

### ルール層

`argv_reads_sensitive` 末尾:

```rust
argv.inner_argv.iter().any(argv_reads_sensitive)
    || argv.subst_argv.iter().any(argv_reads_sensitive)
```

`commands()` 利用 rule は flatten 拡張だけで副次カバー
(`echo $(rm -rf /)` → destructive-rm)。明示再帰が必要な walker:

- `plugin/dsl.rs::walk_argv_for_pipeline_from_to`
- `remote_pipe` の `inner_argv` 再帰
- `path::collect_command_redirects` (置換内 `< .env` 等)

`argv_references_sensitive` 自体は flat (head/args/env) のままでよい —
sensitive token は opaque word にも残るし、reader 判定は `subst_argv`
側の head/args で行う。

### FP / 契約

- `echo $(date)` / `VERSION=$(git rev-parse HEAD)` → allow (内側が
  reader×機密でも destructive でもない)。
- `echo "backup of $(date).env-file"` → 置換フラグは立つが、内側に
  reader×機密無し、outer 非 reader → allow (ヒューリスティック不採用の効用)。
- I/O なし。`facts::extract` の純粋性不変。
- latency: body 再パースは budget 有界、呼び出し 1 回。

## 実装段階 (TDD)

### Phase 0 — 失敗テスト先行

1. `src/facts/shell.rs` tests:
   - `parse("echo $(cat .env)")` → outer head `echo`、
     `subst_argv[0].head == "cat"`、args に `.env`。
   - backtick 形 `` echo `cat .env` `` も同様。
   - `parse("echo $(date)")` → `subst_argv` head `date`、
     `has_command_substitution` は true。
   - ネスト `echo $(echo $(cat .env))` は budget 内で内側まで
     surface (または budget で打ち切り + flag 維持を明示)。
2. `sensitive_bash_read`: pin を `assert_ask("echo $(cat .env)")` に反転。
3. まだ実装が無いので red。

### Phase 1 — tokenizer + `subst_argv`

1. `read_word` balance-absorb + bodies。
2. `Token::Word { text, subst_bodies }`、`parse_pipeline` /
   `parse_argv` 配線、`Argv.subst_argv`、全構造体リテラル更新
   (`unwrap_prefix_wrapper` 生成、`argv()` ヘルパ、git テスト)。
3. `collect_commands` に `subst_argv` flatten。
4. Phase 0 パーサテスト green。

### Phase 2 — rules / walkers / corpus

1. `argv_reads_sensitive` + DSL / remote_pipe / path walker。
2. corpus: `gap-cmdsubst-outer-nonreader` を
   `must_catch` / `ask` に反転 (**コードと同 PR 必須** —
   known_gap は意図しない修正でも fail する設計)。
3. 副次: `echo $(rm -rf /)` の unit または corpus 1 件 (destructive-rm
   deny) を推奨。
4. 負例 unit: `echo $(date)` / `VERSION=$(git rev-parse HEAD)` が
   sensitive-bash-read で沈黙。

### Phase 3 — PBT / fuzz / docs

1. `docs/design/testing.md` の `facts::shell::parse` 不変条件に
   「`$(…)` / backtick body は `subst_argv` に bounded re-parse」を追記。
2. `src/testing/proptest.rs`: 置換内 reader × 機密 token 戦略。
3. `sensitive_bash_read` PBT:
   「その戦略のコマンドは必ず Ask」。
4. `fuzz/corpus/fuzz_shell_parse/` に
   `seed-cmdsubst-nested` (`echo $(cat .env)`, ネスト `$(`, backtick)。
5. ADR / 設計書更新 (下記)。

### Phase 4 — ゲート

`make check`。corpus 反転と pin 書き換えは同一コミット群で落とさない。

## 変更ファイル

| ファイル | 変更 |
| --- | --- |
| `src/facts/shell.rs` | capture + 再パース + `subst_argv` + flatten + unit |
| `src/rules/sensitive_bash_read.rs` | 再帰 + pin 反転 + 負例 + PBT |
| `src/plugin/dsl.rs` | `subst_argv` walk |
| `src/rules/remote_pipe.rs` | `subst_argv` 再帰 |
| `src/facts/path.rs` | `subst_argv` redirect 収集 |
| `src/rules/git/mod.rs` 等 | `Argv { … subst_argv: vec![] }` リテラル |
| `tests/bypass/corpus.jsonl` | gap → must_catch |
| `src/testing/proptest.rs` | cmdsubst reader×sensitive strategy |
| `fuzz/corpus/fuzz_shell_parse/` | ネスト seed |
| `docs/adr/0008-…md` | 新規 (本プランと同時) |
| `docs/adr/0001` / `0002` / `0003` | B5 / opacity を Resolved by ADR 0008 |
| `docs/design/{architecture,testing,policy-packs}.md` | subst_argv / 限界解消 |
| `docs/review/substantive-test-checklist.md` | GAP-01 cmdsubst 行更新 |

触らない: プロセス置換 re-entry、悲観モード削除、新規依存、
`NESTING_BUDGET` 値変更 (3 のまま共有)。

## リスクと緩和

| リスク | 緩和 |
| --- | --- |
| body を `inner_argv` に混ぜて DSL 意味が壊れる | 別フィールドを ADR / 型で強制 |
| corpus だけ先に反転 → CI 赤 | コードと同 PR・同コミット群 |
| budget 超過で再び沈黙 | 悲観モード維持 + flag 非クリア |
| `Token::Word` 変更の広範コンパイルエラー | リテラル箇所は grep で列挙済み (少数) |
| double-quote 内 capture 漏れ | Phase 0 に `"$(cat .env)"` ケース追加 |
| FP 増 | ヒューリスティック不採用を負例テストで pin |

## 検証サマリ (update-plan)

| カテゴリ | 点数 | 所見 |
| --- | --- | --- |
| モジュール / 構造体設計 | 19 / 20 | `subst_argv` を `inner_argv` と分離。再パースは既存 `parse_inner_shell` 再利用。公開 API は `facts::shell` 内 |
| フック契約 | 20 / 20 | PreToolUse I/O・`Decision` スキーマ不変。発火が allow→ask/deny に厳格化されるだけ |
| 判定ルール / ポリシー | 19 / 20 | パーサ層解決。ルールは再帰 1 行。悲観 backstop 維持。FP ヒューリスティック不採用 |
| エラーハンドリング | 20 / 20 | 純粋・budget 打ち切りは capture 破棄 + flag 維持。`unwrap` なし |
| テスト容易性 | 19 / 20 | TDD 段階明示、corpus 同一 PR、PBT・fuzz seed・副次 destructive-rm |
| **合計** | **97 / 100** | 実装 ready (≥ 90) |

### 整合性

- 参照シンボル (`read_word`, `parse_inner_shell`, `NESTING_BUDGET`,
  `collect_commands`, `argv_reads_sensitive`,
  `gap_cmdsubst_outer_nonreader_surfaces_sensitive_token`,
  corpus id `gap-cmdsubst-outer-nonreader`) は現行 `src/` / `tests/` に実在。
- ADR 採番: 既存最大は **0007** (unicode homoglyph) → 本変更は **0008**
  (issue 文面の「0007」は採番衝突のためプラン側で訂正)。
- 段階順: 失敗テスト → tokenizer/AST → rules/corpus → PBT/fuzz/docs →
  `make check`。依存前後に問題なし。
- プロセス置換 (ADR 0003 C) は本プラン範囲外だが、capture 機構の後続と明記。

### 改善反映済み (プラン作成時)

- P0: issue の「ADR 0007」を **0008** に訂正 (0007 は homoglyph で使用済)。
- P0: `commands()` flatten だけでなく DSL / remote_pipe / path walker の
  対称走査を必須化 (B4 型取り逃し防止)。
- P1: double-quoted `$(…)` capture と backtick を Phase 0 に明示。
- P1: 悲観モード削除禁止を Decision とリスク表の両方に固定。
