# ptuf 設計概要

本書は ptuf (PreToolUseFilter) の最小設計書。
詳細仕様は `src/lib.rs` および `src/main.rs` を一次情報とし、本書は意図と契約を記す。

## 目的

コーディングエージェント (Claude Code 等) が外部ツールを呼び出す前に介在し、
組織ポリシー・セキュリティ要件・運用上の制約に基づいて Allow / Deny を返すガードレール層を提供する。

## アーキテクチャ

```
+----------------------+        stdin (JSON)         +-----------+
|  Coding agent        |  ─────────────────────────▶ |  ptuf CLI |
|  (PreToolUse hook)   |                              |  src/main |
+----------------------+ ◀───── exit code 0 / 2 ──── +-----------+
                                  + stderr reason            │
                                                             ▼
                                                     +-----------------+
                                                     | ptuf::decide    |
                                                     | (src/lib.rs)    |
                                                     +-----------------+
```

- **CLI shim** (`src/main.rs`) は I/O とプロセス終了コードのみを担当する
- **判定コア** (`src/lib.rs`) は純粋関数として実装し、ライブラリ利用者にも公開する

## フック契約 (PreToolUse JSON I/O)

### 入力 (`HookInput`)

```json
{
  "tool_name": "Bash",
  "tool_input": { "command": "ls" }
}
```

| フィールド | 型 | 必須 | 説明 |
| --- | --- | --- | --- |
| `tool_name` | string | yes | エージェントが呼ぼうとしているツール名 |
| `tool_input` | object (任意) | no | ツール固有の引数 (省略時は `null` を許容) |

不正 JSON や stdin 読み取り失敗は exit code `1` (内部エラー)。

### 出力

| Decision | exit code | stderr |
| --- | --- | --- |
| `Allow` | `0` | (空) |
| `Deny { reason }` | `2` | `reason` の文字列 |

`Decision` は serde で以下の JSON にもシリアライズ可能 (組み込み利用時)。

```json
{ "decision": "allow" }
{ "decision": "deny", "reason": "blocked by policy" }
```

## 判定ルール / ポリシー (現状)

`decide()` は常に `Decision::Allow` を返す。
将来は `tool_name` ベースのマッチングと `tool_input` パターン (regex / prefix 等) を加え、
ルールセットは設定ファイルから読み込めるようにする (未確定)。

## エラーハンドリング方針

- `#![forbid(unsafe_code)]` を全クレートで強制
- 本体コードでは `unwrap()` / `expect()` 禁止 (clippy で warn)
- テスト内のみ `#![allow(clippy::expect_used, clippy::unwrap_used)]` を許容
- I/O 失敗は exit code `1`、ポリシー違反は exit code `2`、正常通過は exit code `0`

## テスト戦略

- 判定コアは純粋関数なのでユニットテストで網羅する
- `src/main.rs` は薄い shim のため coverage 集計から除外 (`--exclude-files "src/main.rs"`)
- `cargo-tarpaulin` で 95% 以上を維持 (CI でゲート)

## 開発・依存方針

- MSRV: `1.93.0` (`Cargo.toml` の `rust-version` に記載)
- edition: `2024`
- 依存追加時は `deny.toml` の `licenses.allow` 範囲で済むこと、`bans.wildcards = "deny"` を満たすことを必須とする
