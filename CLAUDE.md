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

`make pbt` (`PROPTEST_CASES=10000 cargo test --features testing`) はリリース直前の深掘り PBT 用。

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
