# ADR 0008 — Command substitution body re-entry (2026-07)

## Status

Accepted (2026-07-09). Implemented with issue #161.

## Context

ADR 0001 / ADR 0002 B5 は、shell パーサが `` `…` `` / `$(…)` を opaque
word に畳み `Bash::has_command_substitution` フラグだけを立てる制約を
既知限界として固定した。悲観モード
(`sensitive-bash-read` / `sensitive-path-to-network`) はフラットな
`commands()` 上で reader/sink × 機密 token の共起を要求するため、

| shape | 結果 |
| --- | --- |
| `cat $(echo .env)` | outer reader + 漏洩 token → **ask** (cover) |
| `echo $(cat .env)` | outer が非 reader、内側 `cat` が不可視 → **allow** (gap) |

`tests/bypass/corpus.jsonl` の `gap-cmdsubst-outer-nonreader` と
`gap_cmdsubst_outer_nonreader_surfaces_sensitive_token` がこの allow を
pin している。

ルール層ヒューリスティック（「置換フラグ + 機密 token で常に ask」）は
`echo "backup of $(date).env-file"` 型の false positive を出すため採らない。
パーサ層で置換本体を再パースし、既存の `inner_argv` 再帰と同じく
inspectable な argv として surface する。

プロセス置換 `<(…)` 版 remote pipe (issue #162 / ADR 0003 C) は、本 ADR の
capture 機構を前提とし、後続で同じ `subst_argv` 経路に載せた。

## Decision

### 1. tokenizer: `$(…)` / backtick の balance-absorb + body capture

`read_word` に、既存 `<(…)` / `>(…)` 吸収と同じ paren-depth 追跡を
`$(…)` へ追加する。backtick は対応する閉じ `` ` `` までを 1 span として
吸収する (ネスト backtick は POSIX 上稀で、未閉じは入力末まで消費 —
heredoc と同様の degrade)。

- word 文字列は従来どおり opaque なまま保持する (既存スナップショット /
  悲観モードの token 漏洩契約を壊さない)。
- 置換本体のバイト列 (外側の `$(` / `` ` `` と閉じを除く) を
  `Vec<String>` として capture し、呼び出し元へ返す。
- single-quoted span 内の `$(` / `` ` `` は従来どおり literal (capture しない)。
- double-quoted span 内の `$(…)` は capture する (既存 flag 契約と一致)。

`read_word` の戻り値は `(String /*word*/, usize /*advanced*/, bool /*saw_subst*/, Vec<String> /*bodies*/)`
に拡張する。`Token::Word` は本体リストを運ぶ:

```rust
enum Token {
    Word { text: String, subst_bodies: Vec<String> },
    // …
}
```

### 2. `Argv.subst_argv` — `inner_argv` とは別フィールド

```rust
pub struct Argv {
    // …既存…
    pub inner_argv: Vec<Self>,
    pub inner_code: Vec<String>,
    pub inner_redirects: Vec<Redirect>,
    /// Substitution bodies (`$(…)` / backticks / `<(…)` / `>(…)`)
    /// re-parsed with the same bounded-depth engine as `bash -c`. Not
    /// mixed into `inner_argv` (ADR 0008 / #162).
    pub subst_argv: Vec<Self>,
}
```

`parse_argv` 後、その argv の head/args 由来 word が運んだ
`subst_bodies` を、`NESTING_BUDGET` 残量で `parse_inner_shell` 相当
(既存 `merge_inner_shell` と同じ flatten: segment 内 pipeline 順を保った
`Vec<Argv>`) に再パースし `subst_argv` へ格納する。

- budget 残 0 / 空 body → capture を捨て、`has_command_substitution` は
  立てたまま (悲観モード backstop)。
- `inner_argv` / `inner_code` / `inner_redirects` には混ぜない。
- `Argv::collect_commands` (ひいては `Bash::commands()`) は
  `inner_argv` に加え **`subst_argv` も再帰 flatten** する。

### 3. fail-closed 境界 — 悲観モードは削除しない

パース不能・budget 超過・未閉じ置換で body を surface できない場合でも
`has_command_substitution = true` を維持し、既存の command-wide
co-occurrence 悲観モードを backstop として残す。成功時もフラグは下げない
(部分成功やネスト残りを楽観視しない)。

### 4. ルール層

- `sensitive_bash_read::argv_reads_sensitive` の再帰に `subst_argv` 走査を
  追加する (`inner_argv` と並列)。悲観パスは `commands()` flatten 経由でも
  内側 reader を見るようになるが、非悲観パスと単一 argv 判定の対称性のため
  明示再帰を残す。
- `commands()` 経由の rule (`destructive-rm`, `dynamic-eval`,
  `sensitive-net` 悲観, git, …) は flatten 拡張だけで
  `echo $(rm -rf /)` 等が surface される (意図した副次効果)。
- plugin DSL `walk_argv_for_pipeline_from_to` と legacy `remote_pipe` の
  `inner_argv` 再帰、および `path::collect_command_redirects` も
  `subst_argv` を同じ深さで辿る (1 行対称。B4 と同型の取り逃しを防ぐ)。

### 採らないもの

| 採らない | 理由 |
| --- | --- |
| 「置換フラグ + 機密 token ⇒ 常に ask」 | `$(date).env-file` 型 FP |
| body を `inner_argv` に混在 | `bash -c` と意味が異なる |
| ~~プロセス置換 `<(…)` の re-entry~~ | Resolved by issue #162 (本 capture を再利用) |
| 新規クレート / 本格 bash AST | Minimal Dependencies・既存 tokenizer 拡張で足りる |

## Consequences

### Positive

- `echo $(cat .env)` / backtick 形が `sensitive-bash-read` で
  **ask** になる (GAP B5 解消)。
- `echo $(rm -rf /)` が `destructive-rm` で deny になる等、既存
  `commands()` 消費 rule が置換内側を自然に見る。
- FP は増えない: 内側 argv は通常の rule 判定を受けるだけ。
  `echo $(date)` / `VERSION=$(git rev-parse HEAD)` は allow のまま。
- I/O なし・純粋性契約不変。パースは呼び出しあたり budget 有界。

### Negative

- `Argv` にフィールド追加 (構造体リテラル更新が数箇所)。
- `Token::Word` 形変更で tokenize → parse_argv の受け渡しが少し太る。
- 深ネスト置換は `NESTING_BUDGET` で打ち切られ、打ち切り分は悲観
  backstop に依存する (既存 wrapper ネストと同じ契約)。

### Known limitations (継続)

- ~~プロセス置換 `bash <(curl …)` — ADR 0003 C~~ — Resolved by issue #162
- B2 Bash token symlink、C2 変数 head (`$CMD .env`)
- 未閉じ / 病的ネスト backtick の完全な bash 互換は目指さない

## Implementation map

| 項目 | ファイル | 主要変更 |
| --- | --- | --- |
| tokenizer | `src/facts/shell.rs` | `$(…)` / backtick balance-absorb + body capture、`Token::Word` 拡張 |
| AST | `src/facts/shell.rs` | `Argv.subst_argv`、`collect_commands` flatten、`parse_argv` 再パース |
| rules | `src/rules/sensitive_bash_read.rs` | `subst_argv` 再帰、pin テストを ask 期待へ |
| walkers | `src/plugin/dsl.rs`, `src/rules/remote_pipe.rs`, `src/facts/path.rs` | `subst_argv` 対称走査 |
| corpus | `tests/bypass/corpus.jsonl` | `gap-cmdsubst-outer-nonreader` → `must_catch` / ask |
| PBT | `src/testing/proptest.rs`, `docs/design/testing.md` | 置換内 reader × 機密 ⇒ ask 以上 |
| fuzz | `fuzz/corpus/fuzz_shell_parse/` | `$(` ネスト seed 追加 |
| docs | 本 ADR、`0001`/`0002`/`0003` Known limitations、`architecture.md` / `policy-packs.md` / `testing.md` / checklist | B5 解消追記 |

## References

- Issue #161
- ADR 0001 (A1 pessimistic + known gap)、ADR 0002 B5、ADR 0003 C
- `docs/plans/161-cmdsubst-body-reentry.md`
