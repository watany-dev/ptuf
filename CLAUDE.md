# CLAUDE.md

このファイルは Claude Code がこのリポジトリで作業する際の指針です。
プロジェクト概要・品質方針・モジュール詳細は以下を参照する。

- ユーザ向け概要 / CLI 使用例 / 開発ゲートの一覧 → `README.md`
- 設計・モジュール構成・エラーハンドリング方針・言語規約
  → `docs/design/overview.md` (そこから architecture / decision-model
  / policy-packs / config-and-plugins / cli-and-hooks / audit / testing
  / roadmap にリンクあり)

## 必須チェック (commit / push 前)

`make check` を必ずローカルで通すこと。これは CI と同じ 5 ステップ
(fmt-check / clippy / test / `cargo doc` / cargo-deny) を実行する。手順の
詳細は README "Develop" と `Makefile` を参照。

初回クローン後に `make install-hooks` を実行すれば、`scripts/hooks/pre-push`
が `git push` 時に自動で `make check` を走らせ、CI ゲートが落ちる差分の
push を物理的にブロックする。

PBT は 3 段の予算で同じ proptest ブロックを繰り返し打つ:

- `make pbt-quick` (`PROPTEST_CASES=1024`) — PR CI ゲート相当、ローカル最短ループ
- `make pbt` (`PROPTEST_CASES=10000`) — main push 時の `pbt-deep` job 相当、夜間 / リリース前に手動
- `make pbt-deep` (`PROPTEST_CASES=100000`) — リリース前ソーク。CI には載せない

`make e2e` (`tests/e2e_heavy.rs`, `--test-threads=1`) は実 `ptuf` を subprocess で連続 spawn し、
fd / tempfile リーク・8 MiB stdin 境界・並列 hook と shared audit JSONL・4 層 config フル統合・
5 adapter parity・病的入力 (クラッシュ / ハング検出)・per-call latency 予算・subcommand 連続実行の
8 軸 40 ケースを `#[ignore]` で実行する重 E2E。spawn ハーネスはタイムアウト付きで、ハングは
失敗化し signal kill (クラッシュ) も検出する。`make check` には含めず、nightly / リリース直前に手動実行する。

`make check` 非対象の追加 QA 層 (`.github/workflows/nightly.yml` で夜間実行):

- `make fuzz` / `make fuzz-soak` — `cargo fuzz` による信頼境界 4 種 (shell parser /
  hook pipeline / config merge / plugin DSL) の coverage-guided fuzzing に加え、
  `arbitrary` で valid な入力を直接組み立て判定コアを毎回叩く構造化ターゲット
  (`fuzz_engine_structured`)。`fuzz/` は独立 workspace で nightly toolchain を
  要する。クラッシュ種は `fuzz/artifacts/` に commit。
- `make mutants` — `cargo-mutants` による decision コア (`src/decision.rs` / `src/rules/**` /
  `src/engine/**`、スコープは `.cargo/mutants.toml`) の mutation testing。
- `make semver` — `cargo-semver-checks` で公開 API の SemVer 破壊を検知 (PR CI でも実行)。

敵対的 bypass の回帰は `tests/bypass/corpus.jsonl` (版管理) に集約し、`make check` の
`test` ステップで `tests/bypass_corpus.rs` が検証する。fuzz / 監査で新規 bypass を
発見したら corpus に追記する。

## アーキテクチャ規約

- 設計詳細は `docs/design/overview.md` から辿る
- 新規ロジックは必ず `src/lib.rs` 配下に置く
- `src/main.rs` は CLI shim のため coverage 集計から除外する

## 技術原則

- **Minimal Dependencies** — 追加クレートは必要性を吟味する
- **Safety-First** — `unsafe_code = "forbid"` (`Cargo.toml [lints.rust]`) でゼロ unsafe を強制。
  `clippy::pedantic` / `nursery` / `cargo` を group warn、`unwrap_used` / `expect_used` /
  `panic` / `todo` / `unimplemented` / `dbg_macro` / `print_stdout` / `print_stderr` /
  `exit` 等の restriction を deny。production で局所的に許可する場合は
  `#[expect(... reason = "...")]` を使い、テストでは `clippy.toml` の
  `allow-{unwrap,expect,panic,print,dbg}-in-tests = true` が有効。
- **Test Coverage** — `cargo-tarpaulin` で 95% 以上を維持
- **Supply Chain** — `cargo-deny` で advisories / licenses / bans / sources を監査

詳細は `docs/design/architecture.md` を参照。

## 開発手法

- **TDD** — failing test → 実装 → リファクタ
- **Tidy First** (Kent Beck) — 機能変更前に、ガード節・デッドコード削除・対称性整え・ヘルパ抽出・コメント明確化で読みやすさを上げられないか検討する
