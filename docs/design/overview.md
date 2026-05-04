# ptuf 設計概要

本書は ptuf (PreToolUseFilter) のドキュメント群のエントリポイント。
個別の関心事は本書からリンクされる各文書にまとめる。
詳細仕様の一次情報は `src/lib.rs` および `src/main.rs` のコードであり、
本書群は意図と契約を記述する。

## 現状と本書群の射程

ptuf は現状 bootstrap フェーズにあり、`decide()` は常に `Decision::Allow` を返す。
本書群は MVP v0.1 以降で到達すべき設計を含み、現実装と将来像が混在する。
各章は「今あるもの」と「これから入るもの」を可能な限り区別して記述する。
roadmap は [`roadmap.md`](roadmap.md) を参照。

## 目的

コーディングエージェント (Claude Code 等) が外部ツールを呼び出す直前に介在し、
危険な CLI 操作・情報漏洩・プロジェクト規約違反を deterministic に判定する
汎用ガードレール層を提供する。最初の主対象は Claude Code の `PreToolUse` hook
とし、将来は Codex / Cursor / Gemini CLI / MCP tools にも adapter で対応できる
構造を取る。

## Goals

- `curl | bash`、`wget | sh`、秘密情報の外部送信、破壊的 filesystem / git 操作を
  default で防ぐ
- Bash 文字列の単純 grep ではなく、shell AST・argv・pipeline・redirect・path・
  URL・dataflow facts に変換して判定する
- ユーザ管理の YAML plugin で project-specific / team-specific guardrail を
  追加できる
- agent に対して「なぜ止めたか」「どう直すべきか」を返し、再試行可能な安全経路
  に誘導する
- default は強いが開発体験を壊さない。危険度に応じて
  `allow / monitor / ask / deny` を使い分ける

## Non-goals

- すべての shell command を完全に安全化すること
- LLM による曖昧な安全判定を default にすること
- 任意 executable plugin を default 許可すること
- 企業向け DLP 製品の完全代替になること

## 全体像

```
+----------------------+        stdin (JSON)         +-----------+
|  Coding agent        |  ─────────────────────────▶ |  ptuf CLI |
|  (PreToolUse hook)   |                              |  src/main |
+----------------------+ ◀───── exit code 0 / 2 ──── +-----------+
                                  + stderr reason            │
                                                             ▼
                                              +-----------------------------+
                                              | adapter → fact extraction → |
                                              | policy merge → rule eval →  |
                                              | decision aggregation        |
                                              | (src/lib.rs)                |
                                              +-----------------------------+
```

詳細パイプラインは [`architecture.md`](architecture.md) を参照。

## 関連文書

| ファイル | 内容 |
| --- | --- |
| [`architecture.md`](architecture.md) | adapter → fact extraction → policy merge → rule evaluation → decision aggregation のパイプラインと I/O 契約 |
| [`decision-model.md`](decision-model.md) | 4 種類 (allow / monitor / ask / deny) の semantics、優先順位、`hardDeny` / `overridable` |
| [`policy-packs.md`](policy-packs.md) | built-in 6 packs (network / secrets / filesystem / git / self_protection / project_hygiene) |
| [`config-and-plugins.md`](config-and-plugins.md) | 設定スコープのマージ、YAML plugin 形式、plugin tests、allowlists |
| [`cli-and-hooks.md`](cli-and-hooks.md) | `ptuf` サブコマンド一覧、Claude Code 統合、将来の adapter 戦略 |
| [`audit.md`](audit.md) | JSONL 監査ログのスキーマと redaction 規約 |
| [`roadmap.md`](roadmap.md) | MVP v0.1〜v0.4 のスコープと設計原則 |

## 言語・運用規約

- 本書群はすべて日本語、`README.md` のみ英語
- コード識別子は Rust 標準 (PascalCase 型 / snake_case 関数)
- 設計上の安定 ID (rule id `core.network.remote-script-pipe` 等、severity
  `critical` 等) は実装で同名を維持し、本書群でも変更しない
