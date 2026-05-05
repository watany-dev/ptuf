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
- `make pbt` — `PROPTEST_CASES=10000 cargo test` (デフォルト 10000 ケース、
  `PBT_CASES=N` で上書き)。リリース直前の深掘り PBT 用

## アーキテクチャ

- `src/lib.rs` — 判定コアの再エクスポート層。`Decision`, `HookInput`, `decide()`,
  `aggregate` を公開し、内部モジュールへ委譲する
- `src/decision.rs` — `Decision` (4 variants) と `severity` / `aggregate`
- `src/hook_input.rs` — `HookInput` と `bash_command()` / `file_path()` /
  `web_fetch_url()` / `write_payload()` accessor。`mcp__<server>__<tool>`
  形式の MCP tool は `path` / `url` / `content` の汎用キーを認識する
- `src/hook_output.rs` — Claude Code `hookSpecificOutput` envelope
- `src/reason.rs` — `reason::build` (deny / ask の Rule Feedback 整形)
- `src/rules/` — `ConfigRule` trait、組み込み rule (filesystem / network /
  secrets / git / self_protection / sensitive_read / project_hygiene)、
  共有 `LazyLock<Regex>` 群。built-in rule は計 23 個
- `src/facts/` — fact extraction (`shell` / `path` / `url` / `sensitive` /
  `project`)。`protected` と `project` は `Engine::decide` 時に注入。
  `project_facts` は engine 構築時に 1 回 collect し、per-decide では I/O しない
- `src/self_paths.rs` — `ProtectedPaths` (binary / configs / plugins /
  claude_settings / hook_scripts) の収集と分類
- `src/engine.rs` — config / plugin / audit / `ProtectedPaths` を抱える Engine。
  `for_cwd` / `for_path_opt` / `with_config` / `with_components` / `with_agent`
- `src/audit/` — JSONL 永続化。`AuditRecord` は `schemaVersion: 1` を含み、
  `agent` (`claude-code` / `cli`) と `pluginVersions`
  (`name@version` 配列) と `allowlistId` (allow に至った allowlist の id) を伝える
- `src/init/` — `ptuf init <agent>`。v0.4 では `claude_code` adapter のみ
- `src/doctor.rs` — `ptuf doctor` 診断レポート (`Report::gather` + `render`)
- `src/cli.rs` — 引数 parse とサブコマンド実行 (`Hook` /
  `Eval` / `PluginTest` / `Init` / `Doctor` /
  `Help` / `Version`)。fail-closed は `build_engine_or_fail_closed`
- `src/io_runner.rs` — stdin → `decide` → stdout / stderr / `ExitCode`
- `src/main.rs` — argv / 各 stream を `io_runner::run` に渡す数行の shim
- `src/testing/` — `#[cfg(test)] pub(crate) mod testing` で公開する PBT 戦略
  (`Decision` / `Severity` / `HookInput` / `bash_command`)。`tests/engine_proptest.rs`
  は integration crate のため共通戦略を独立に複製
- `proptest-regressions/` — proptest がシュリンクで見つけた最小反例の永続化先。
  全環境で同シードで再現させるため git 管理する
- `docs/design/` — 日本語の設計書群。エントリポイントは `docs/design/overview.md` で、
  そこから architecture / decision-model / policy-packs / config-and-plugins /
  cli-and-hooks / audit / testing / roadmap にリンクが張られている

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
