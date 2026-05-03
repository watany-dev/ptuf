---
name: update-docs
description: ptuf のドキュメント (README.md, docs/design/, CLAUDE.md) を最新の `src/` に追従させる更新スキル。
---

# update-docs スキル

ptuf のソースとドキュメントの乖離を解消する 5 フェーズスキル。

## Phase 1: ソース構造の把握

- `src/lib.rs` の公開項目（`Decision`, `HookInput`, `decide`, モジュール構成）を抽出
- `src/main.rs` の CLI I/O（stdin payload, exit code 0/2, stderr メッセージ）を抽出
- `Cargo.toml` の依存・MSRV (`rust-version`)・edition の現状値を取得

## Phase 2: 設計ドキュメント反映

- `docs/design/` 配下の各 Markdown を、Phase 1 の事実と突き合わせて更新
- 削除された API・改名されたフィールドの追従、追加されたモジュールの章追加
- 設計書のステータス（実装済み / 進行中 / 計画中）を実装に揃える

## Phase 3: README 反映

- `README.md` には次を必ず含める
  - 1 段落のプロジェクト概要（PreToolUse フィルタである旨）
  - インストール / ビルド (`cargo install`, `make build`)
  - Claude Code `settings.json` への組み込み例（`hooks.PreToolUse` を `ptuf` で配線）
  - 終了コード仕様（`0` = Allow, `2` = Deny + stderr）
  - `make check` / `make coverage` の説明

## Phase 4: 横断整合性チェック

- 全 Markdown 間で、コマンド名 / ファイルパス / Cargo クレート名 / 終了コード / 用語が一致しているか確認
- README は英語、`docs/design/` と `CLAUDE.md` は日本語、という言語規約に従う

## Phase 5: 報告

- 更新ファイル一覧
- 新規追加すべきドキュメント候補
- 解消できなかった不整合（要設計判断のもの）
