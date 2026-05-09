# ptuf 設計概要

本書は ptuf (PreToolUseFilter) の設計書群の入口である。一次情報は `src/`
配下の実装であり、本書群はその契約と意図を整理する。

## 現在の実装スコープ

ptuf は `v0.0.1` (内部マイルストーン M1〜M4 を統合) で次を実装済み:

- `PreToolUse` 向け CLI とライブラリ
- Claude Code / Codex / GitHub Copilot adapter (frozen)
- Kiro CLI adapter (`hook` / `init` / `doctor` 連携を実装済み)
- built-in pack:
  `core.filesystem` / `core.network` / `core.secrets` / `core.git` /
  `core.self_protection` / `core.engine` /
  `core.project_hygiene` (opt-in)
- facts 抽出:
  `shell.*`, `path`, `url`, `sensitive_path`, `protected`, `project`
- `bash -c`, `sh -c`, `eval`, `xargs`, `find -exec` に対する bounded wrapper
  inspection と、wrapped redirect を含む self-protection
- layered YAML config, YAML plugin, allowlist, audit JSONL
- `ptuf init <agent>`, `ptuf doctor [--json]`, `ptuf plugin test <path>`
- `tests/contracts.rs` による hook / audit / `doctor --json` 契約の固定

## ビルド前提と依存

- Rust edition は `2024`
- MSRV は `1.93.0`
- 実行時依存は `serde`, `serde_json`, `serde_yaml_ng`, `regex`, `time`,
  `toml_edit`
- `time` は audit timestamp と allowlist `expiresAt` の RFC3339
  formatting / parsing に使う
- dev 依存は `proptest` と `tempfile`

## 公開 API

`src/lib.rs` は以下を公開する。

- `Decision`
- `aggregate`
- `Engine`
- `EngineError`
- `Outcome`
- `Facts`
- `HookInput`
- `decide`
- `try_decide`

`decide(&HookInput) -> Decision` は後方互換用の薄い API であり、まず
`Engine::for_cwd()` を試し、設定や plugin の読み込みに失敗した場合は
`Engine::builder().agent("embed-fallback").build()` にフォールバックする。
builder は `ProtectedPaths::collect_with_env` を必ず通すため、fallback 経路
でも binary / Claude / Codex settings の self-protection は populate される。
CLI 経路はこれと異なり fail-closed で動作する。

`try_decide(&HookInput) -> Result<Decision, EngineError>` は失敗を握り潰さ
ない並立 API。embed 利用側で CLI と同じ fail-closed 契約が欲しい場合に使う。

## CLI の現在形

実装済みサブコマンドは次のとおり。

- `ptuf hook claude-code`
- `ptuf hook codex`
- `ptuf hook copilot`
- `ptuf hook kiro`
- `ptuf eval --tool <name> <command>`
- `ptuf plugin test <path>`
- `ptuf init claude-code [--dry-run] [--settings <PATH>] [--verify [--json]]`
- `ptuf init codex [--dry-run] [--root <PATH>] [--hooks <PATH>] [--config <PATH>] [--verify [--json]]`
- `ptuf init copilot [--dry-run] [--root <PATH>] [--hooks <PATH>] [--profile local] [--verify [--json]]`
- `ptuf init kiro [--dry-run] [--root <PATH>] [--agent <NAME>] [--agent-config <PATH>] [--scope local|global] [--verify [--json]]`
- `ptuf doctor [--json]`
- `ptuf --help`
- `ptuf --version`

## 目的

コーディングエージェントが外部ツールを呼ぶ直前に介在し、危険な操作や
プロジェクト規約違反を deterministic に止める。

## Goals

- 破壊的操作、remote script pipe、機密ファイルの読取・外部送信を既定で防ぐ
- 生の文字列ではなく facts に正規化して判定する
- YAML plugin で project-specific / team-specific rule を追加できる
- agent に理由と代替手順を返す

## Non-goals

- すべてのコマンドを完全に安全化すること
- LLM 判定を default にすること
- 任意実行形式の plugin を default 許可すること

## 関連文書

| ファイル | 内容 |
| --- | --- |
| [`architecture.md`](architecture.md) | 実行パイプライン、facts、I/O 契約 |
| [`decision-model.md`](decision-model.md) | `Decision` の意味、集約順序、mode、fail-closed |
| [`policy-packs.md`](policy-packs.md) | 実装済み built-in pack と rule 一覧 |
| [`config-and-plugins.md`](config-and-plugins.md) | config schema、plugin schema、allowlist |
| [`cli-and-hooks.md`](cli-and-hooks.md) | `init` / `hook` / `doctor` と agent 統合 |
| [`kiro-cli.md`](kiro-cli.md) | Kiro CLI adapter の正規化・fail-closed・doctor 統合 |
| [`audit.md`](audit.md) | audit JSONL schema と redaction |
| [`testing.md`](testing.md) | example-based test と PBT の役割分担 |
| [`roadmap.md`](roadmap.md) | M1〜M4 の到達点と今後の候補 |

## 言語規約

- `README.md` は英語
- `docs/install.md` / `docs/agents.md` などの user-facing how-to は
  README からのリンク先として英語で揃える
- `docs/design/` と `CLAUDE.md` は日本語
- rule id、型名、CLI 名などの安定識別子は実装と同名を保つ
