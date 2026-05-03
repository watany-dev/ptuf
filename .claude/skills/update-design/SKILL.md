---
name: update-design
description: ptuf の `docs/design/` 配下の設計書を評価・改善するスキル。フィルタ判定ロジックや PreToolUse フック契約の整合性を `src/` と突き合わせて検証する。
---

# update-design スキル

ptuf (PreToolUseFilter) の設計書を **収集 → 評価 → 整合確認 → 改善提案** の 4 フェーズで点検する。

## Phase 1: コンテキスト収集

- `docs/design/` 配下の Markdown ファイルをすべて読む
- `src/lib.rs` / `src/main.rs` の公開 API（`Decision`, `HookInput`, `decide`）を読み、設計書との対応を把握する
- `Cargo.toml` の依存と `deny.toml` の制約から、設計上利用可能なクレートの範囲を確認する

## Phase 2: 設計書品質評価 (100 点満点 / 5 カテゴリ)

各 20 点で採点し、合計 90 点以上で実装 ready とみなす。50 点未満は再設計を要求する。

| カテゴリ | 観点 |
| --- | --- |
| モジュール / 構造体設計 | クレート分割、`pub` 境界、責務分離、Rust 命名規約 (PascalCase / snake_case) |
| フック契約 (PreToolUse JSON I/O) | Claude Code の hook payload との互換、`tool_name` / `tool_input` のフィールド網羅、`Decision` 出力の JSON スキーマ |
| 判定ルール / ポリシー設計 | ルールの記述方式、優先順位、拒否理由 (`Decision::Deny.reason`) のテンプレート、デフォルト挙動 |
| エラーハンドリング | `Result` 伝搬、`#![forbid(unsafe_code)]` 遵守、`unwrap`/`expect` 不使用、stdin / JSON parse 失敗時の終了コード |
| テスト容易性 | 関数の純粋性、I/O の境界化、フィクスチャ駆動テストの設計、95% coverage 維持戦略 |

## Phase 3: 整合性チェック

- 設計書 ↔ `src/` の双方向比較（設計済みだが未実装、実装済みだが未設計の箇所を列挙）
- 設計書 ↔ `README.md` / `CLAUDE.md` のコマンド・I/O 例の突合
- 設計書間の用語・データ型・終了コードの不整合検出

## Phase 4: 改善提案

- P0 (実装ブロッカー) / P1 (品質低下) / P2 (Nice to have) で優先度分類
- 各指摘は「対象ファイル:行 → 問題 → 推奨修正」の形式で記述
- 具体的な Rust コード断片を添える（PascalCase / snake_case 準拠）

## 出力テンプレート

```markdown
## 評価サマリ
| カテゴリ | 点数 |
| --- | --- |
| モジュール / 構造体設計 | xx / 20 |
| フック契約 | xx / 20 |
| 判定ルール / ポリシー | xx / 20 |
| エラーハンドリング | xx / 20 |
| テスト容易性 | xx / 20 |
| **合計** | **xx / 100** |

## 主要所見
...

## 設計書 ↔ ソース整合性
...

## 改善提案
- P0: ...
- P1: ...
- P2: ...
```
