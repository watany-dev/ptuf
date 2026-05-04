# CLAUDE.md

このファイルは Claude Code がこのリポジトリで作業する際の指針です。

## プロジェクト概要

**ptuf (PreToolUseFilter)** はコーディングエージェント向けの汎用ガードレール層を目指す OSS。
Claude Code 等の `PreToolUse` フックから呼び出され、stdin で受け取った hook payload を評価し、
Allow / Deny を exit code と stderr メッセージで返す CLI バイナリ + 組み込み用ライブラリ。

## 必須チェック (commit / push 前)

`make check` を必ずローカルで通すこと。これは CI と同じ 5 ステップを実行する。

1. `cargo fmt -- --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`
4. `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`
5. `cargo deny check advisories licenses bans sources`

加えて以下も提供。

- `make build` — release ビルド
- `make coverage` — `cargo tarpaulin --fail-under 95 --exclude-files "src/main.rs"`
- `make fmt` — 自動フォーマット

## アーキテクチャ

- `src/lib.rs` — 判定コア。`Decision`, `HookInput`, `decide()` を公開
- `src/main.rs` — CLI エントリ。stdin JSON → `decide` → exit code
- `docs/design/` — 日本語の設計書群

`src/main.rs` は coverage 集計から除外する (CLI shim のため)。新規ロジックは必ず `src/lib.rs` 配下に置く。

## 技術原則

- **Minimal Dependencies** — 追加クレートは必要性を吟味する
- **Safety-First** — `#![forbid(unsafe_code)]`、`unwrap()` / `expect()` 禁止 (テスト除く)
- **Test Coverage** — `cargo-tarpaulin` で 95% 以上を維持
- **Supply Chain** — `cargo-deny` で advisories / licenses / bans / sources を監査

## 開発手法

- **TDD** — failing test → 実装 → リファクタ
- **Tidy First** (Kent Beck) — 機能変更前に、ガード節・デッドコード削除・対称性整え・ヘルパ抽出・コメント明確化で読みやすさを上げられないか検討する

## 言語規約

- README.md は英語
- 設計書 (`docs/design/`) と CLAUDE.md は日本語
- コード識別子は Rust 標準 (PascalCase 型 / snake_case 関数)
