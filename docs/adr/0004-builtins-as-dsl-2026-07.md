# ADR 0004 — builtin rule の DSL 一本化 (2026-07)

## Status

Accepted (2026-07-03). スライス 1 実装済み。

## Context

`docs/review/open-issues.md` §1.1/§1.2 が指摘する技術負債: builtin rule は
手書き Rust (`src/rules/**`)、plugin rule は YAML + DSL コンパイラ
(`src/plugin/dsl.rs`) と、同じ「条件 → Decision」を 2 系統で実装しており、

- 条件表現のドリフト (ADR 0003 の分類器不整合と同型の問題) が builtin ↔ DSL
  間でも起こりうる
- DSL の表現力改善 (privilege wrapper unwrap / `inner_argv` 再帰など) が
  builtin に還元されない
- rule 追加のたびに Rust boilerplate (struct + trait impl + テスト) が必要

という費用を払い続けていた。実際、DSL の `shell.pipeline` walk
(`walk_argv_for_pipeline_from_to`) は fetch 側でも privilege wrapper を
unwrap し `inner_argv` に再帰するため、旧 Rust 版 remote-script-pipe が
見逃す `sudo curl … | sh` / `bash -c 'curl …' | sh` を捕捉できる —
つまり DSL の方が既に**強い**。

一方で全面移行には表現力の壁がある: 正規表現ベースの分類器
(sensitive path / invisible chars)、ファイルシステム参照 (workspace の
canonicalize / lock-mismatch の mtime 比較)、動的 reason 生成などは現行
DSL に leaf が無い。

## Decision

builtin rule を **DSL で表現できるものから段階的に** YAML
(`src/rules/builtins.yaml`, `include_str!` で埋め込み) へ移し、Rust 実装は
削除せずパリティ oracle として残す。アーキテクチャは次で固定する:

### 供給経路 — `rules::iter()` の chain

`rules::builtin_dsl` に `LazyLock<Vec<PluginRule>>` を置き、
`rules::iter()` が静的 `RULES` slice の後ろへ DSL builtin を chain する。
Engine (`decide` ループ / `severity_for` / mode demotion の
`is_hard_deny_rule_id`) は `rules::iter()` しか見ないため **engine 側の
変更はゼロ**。pack 無効化・rule override・allowlist・`hardDeny` 不可侵は
両種の rule に同一機構で作用する。

### fail-closed sentinel

`builtins.yaml` は `include_str!` + 決定的コンパイルなので load 失敗は
構造的に到達不能 (テストで pin)。それでも失敗した場合は
`core.engine.builtin-load-failed` (空 `all:` = 全マッチ、Critical / Deny /
hardDeny / overridable: false) 1 件へ縮退し、ガードレール喪失を
**deny-everything** で顕在化させる。silent allow への縮退は決定モデルの
fail-closed 原則 (`docs/design/decision-model.md`) に反するため採らない。

### `core.` id 予約

builtin が YAML 化されると、外部 plugin が `core.*` id を名乗って builtin に
なりすます (mode demotion の hardDeny 判定や audit 帰属を混乱させる) 経路が
現実味を持つ。loader は外部 plugin (`load_str`) の `core` / `core.*` id を
`PluginError::ReservedRuleId` で reject し、embedded 経路
(`load_builtin_str`, `pub(crate)`) のみ許可する。同一 plugin 内の id 重複も
両経路で `PluginError::DuplicateRuleId` で reject する。

### wire 互換

移行する rule は id / severity / defaultDecision / hardDeny / reason /
remediation を旧実装と byte-identical に保つ (`Decision` の `assert_eq` で
pin)。hook 応答・audit record の shape は変わらない。

### パリティ検証

旧 Rust 実装は `pub` のまま残し (semver 非破壊)、PBT で
「旧実装が fire ⇒ DSL が同一 payload で fire」の**片方向包含**を縛る。
逆方向は成立しない (DSL が強い) ため、強化差分は明示テストと
`tests/bypass/corpus.jsonl` の must_catch で pin する。

### スライス 1 の範囲

`core.network.remote-script-pipe` 1 件。`shell.pipeline` leaf で完全表現
でき、かつ強化差分が明確なため最初の移行対象とした。

## Consequences

### Positive

- remote-script-pipe が fetch 側 wrapper 越し (`sudo curl … | sh`,
  `bash -c 'curl …' | sh`) でも Deny になる (Security 強化)。
- builtin と plugin の条件評価が単一実装 (`plugin/dsl.rs`) に収斂し始め、
  DSL の改善が builtin に自動で波及する。
- 以降のスライスは YAML 追記 + テストのみで rule を移せる。

### Negative

- `PluginError` variant 追加は breaking change (0.5.0 bump)。
- rule 定義が Rust と YAML の 2 箇所に分かれる過渡期が生じる (パリティ
  oracle の削除は全スライス完了後)。
- DSL 化された rule は compile を経るぶん、初回評価に LazyLock の
  one-shot コストが乗る (以降は静的 rule と同等)。

### 移行できない/しないもの (現時点)

- 正規表現分類器依存: `sensitive-*` / `invisible-chars` /
  `destructive-rm` (パス shape 判定) — DSL に regex leaf を足すか否かは
  将来スライスで判断
- ファイルシステム参照: `workspace.outside-access` (canonicalize) /
  `lock-mismatch-*` (mtime) — facts 化の設計が先
- 動的 reason: `workspace` / `sensitive-read` の実パス埋め込み — DSL の
  reason はテンプレートを持たない

## Implementation map (スライス 1)

| 項目 | ファイル | 主要変更 |
| --- | --- | --- |
| YAML | `src/rules/builtins.yaml` | remote-script-pipe の DSL 定義 (埋め込み) |
| 供給 | `src/rules/builtin_dsl.rs` | LazyLock + fail-closed sentinel + `iter()` |
| chain | `src/rules/mod.rs` | `iter()` が RULES + DSL builtin を chain |
| 予約 id | `src/plugin/loader.rs`, `src/plugin/mod.rs` | `ReservedRuleId` / `DuplicateRuleId` |
| oracle | `src/rules/remote_pipe.rs` | RULES から外し legacy oracle として残置 |
| Tests | `src/rules/builtin_dsl.rs`, `tests/rules_iter_order.rs`, `tests/bypass/corpus.jsonl` | 片方向パリティ PBT / wire 同一 pin / 強化差分 must_catch 2 件 |
| Doc | `docs/design/config-and-plugins.md`, `docs/design/policy-packs.md`, `docs/review/open-issues.md`, `docs/design/roadmap.md`, 本 ADR | 設計追従 |
