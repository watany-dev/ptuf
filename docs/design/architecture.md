# アーキテクチャ

ptuf はコーディングエージェントの `PreToolUse` 相当の hook から呼び出される
CLI バイナリと、判定コアを公開するライブラリの 2 面構成を持つ。
本書はパイプライン全体と、現状の I/O 契約を記述する。

## 二層構成

- **CLI shim** (`src/main.rs`) — stdin / stdout / stderr / プロセス終了コードのみ
  を担当する薄い層。coverage 集計から除外する (`--exclude-files "src/main.rs"`)。
- **判定コア** (`src/lib.rs`) — 純粋関数として実装し、ライブラリ利用者にも
  公開する。新規ロジックは必ずこちらに置く。

## 評価パイプライン

将来到達形のパイプラインは以下の 6 段で構成する。

```
stdin JSON
  ↓
adapter
  - claude-code         (v0.1)
  - codex               (v0.4 以降)
  - cursor              (v0.4 以降)
  - gemini              (v0.4 以降)
  ↓
normalized event
  ↓
fact extraction
  - shell AST / argv / pipeline / redirect
  - path normalization
  - URL classification
  - sensitive path classification
  - project facts
  - git facts
  ↓
policy merge
  - builtin packs
  - org config
  - user config
  - project config
  - local config
  ↓
rule evaluation
  ↓
decision aggregation
  ↓
hook response + audit log
```

### adapter

エージェントごとの hook ペイロード形状の差異を吸収し、内部の normalized event
に変換する。最初は Claude Code の `PreToolUse` のみ対応 (`HookInput` 構造体)。
他エージェントは [`roadmap.md`](roadmap.md) の v0.4 で追加する。

### fact extraction

raw な Bash 文字列を直接 regex で判定するのではなく、構造化された facts に
落とし込む。これにより plugin rule が安定的に書ける。

- shell AST: 単純な lexer / parser で argv・pipeline・redirect を抽出
- path normalization: `~` 展開、相対 → 絶対化、シンボリックリンク解決
- URL classification: scheme / host / port / path、cloud metadata endpoint 判別
- sensitive path classification: `~/.ssh/**` 等、[`policy-packs.md`](policy-packs.md)
  の `core.secrets` 一覧に基づく分類
- project facts: lockfile 種別、protected branch、generated file 規約
- git facts: working tree 状態、現在の branch、remote URL

| fact | 実装ステータス |
| --- | --- |
| `shell.argv` / `shell.pipeline` / `shell.env_assignments` | v0.2 で実装済み |
| `path` (`~` 展開・絶対化) | v0.3 で実装済み |
| `url` (scheme / host / port / path) | v0.3 で実装済み |
| `sensitive_path` (`SshDir` / `AwsDir` / `GcloudDir` / `KubeDir` / `DockerDir` / `PrivateKey` / `Dotenv` / `Npmrc` / `Pypirc` / `Tfstate` / `PemBlob`) | v0.3 で実装済み |
| `protected` (Engine が決定する self_protection マッチ) | v0.3 で実装済み |
| MCP fact 抽出 (`mcp__*` の汎用 `path` / `url` / `content` キー) | v0.4 で実装済み ([`cli-and-hooks.md`](cli-and-hooks.md#mcp-fact-抽出-v04)) |
| `dataflow.basic` (sensitive → network、同一コマンド co-occur を超えた追跡) | v0.4 以降 |
| project facts (lockfile 種別 / 現在 branch / protected branch flag) | v0.4 で実装済み (engine 構築時に 1 回 collect、per-decide で参照) |
| git facts (working tree / remote URL) | v0.4 以降 |

組み込み rule のうち以下は facts ベース:

- v0.2 から: `core.filesystem.destructive-rm` /
  `core.network.remote-script-pipe` /
  `core.secrets.sensitive-path-to-network`
- v0.3 で追加: `core.secrets.sensitive-read` / `core.git.*` / `core.self_protection.*`
- v0.4 で追加: `core.project_hygiene.*` (lock-mismatch-pnpm /
  lock-mismatch-uv / protected-branch-destructive-git)

YAML plugin の `when:` DSL も同じ facts に対して書ける。raw shell regex への
直接アクセスは plugin 側からは不可視。

### policy merge

`builtin → org → user → project → local` の順で設定を重ねる。
詳細は [`config-and-plugins.md`](config-and-plugins.md) を参照。

### rule evaluation

各 rule は facts に対する条件と decision を返す。
複数 rule が一致する場合の集約規則は [`decision-model.md`](decision-model.md)
を参照。

### hook response + audit log

stdout は hook protocol 専用に保つ。debug / audit は stderr または
JSONL audit log に出す ([`audit.md`](audit.md))。

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

`ptuf` の起動形態は 3 つあり、それぞれ stdout / stderr / exit code の組み合わせが
異なる。判定そのもの (exit code 0/2) と内部エラー (exit code 1) を厳密に区別する。

| 起動形態 | 例 | stdout | stderr | exit code |
| --- | --- | --- | --- | --- |
| 互換モード (引数なし) | `ptuf` | (空) | deny 時のみ reason | 0 / 2 |
| `hook` サブコマンド | `ptuf hook claude-code pre-tool-use` | deny / ask 時に `hookSpecificOutput` JSON | reason | 0 / 2 |
| `eval` サブコマンド | `ptuf eval --tool Bash 'rm -rf /'` | 人間可読な判定結果 | deny 時のみ reason | 0 / 2 |

| 内部エラー | stderr | exit code |
| --- | --- | --- |
| stdin 読み取り失敗 | `ptuf: failed to read stdin` | 1 |
| JSON parse 失敗 | `ptuf: invalid hook payload: <err>` | 1 |
| 不明なサブコマンド / 引数不足 | usage メッセージ | 1 |

`Decision` は serde で以下の JSON にもシリアライズ可能 (組み込み利用時)。

```json
{ "decision": "allow" }
{ "decision": "monitor", "rule_id": "core.filesystem.destructive-rm" }
{ "decision": "ask",     "rule_id": "core.network.remote-script-pipe", "reason": "..." }
{ "decision": "deny",    "rule_id": "core.filesystem.destructive-rm",  "reason": "..." }
```

Claude Code 専用 `hookSpecificOutput` envelope のフィールド一覧は
[`cli-and-hooks.md`](cli-and-hooks.md) を参照。

## エラーハンドリング方針

- `#![forbid(unsafe_code)]` を全クレートで強制
- 本体コードでは `unwrap()` / `expect()` 禁止 (clippy で warn)
- テスト内のみ `#![allow(clippy::expect_used, clippy::unwrap_used)]` を許容
- I/O 失敗は exit code `1`、ポリシー違反は exit code `2`、正常通過は exit code `0`
- `enforce` モードで policy が読み込めない場合は fail-closed (deny)

## テスト戦略

- 判定コアは純粋関数なのでユニットテストで網羅する
- `src/main.rs` は薄い shim のため coverage 集計から除外
- `cargo-tarpaulin` で 95% 以上を維持 (CI でゲート)
- example-based テストに加え `proptest` を併用し、`aggregate` の代数法則 /
  `engine::demote_for_mode` / `facts::shell::parse` / 組み込み rule の全域性
  (panic 安全) / `audit::redact_strict` の冪等性などコア不変条件を Property-Based
  Testing で検証する。共通戦略は `src/testing/proptest.rs`、統合層 PBT は
  `tests/engine_proptest.rs`、深掘りは `make pbt` (デフォルト 10000 ケース)。
  詳細は [`testing.md`](testing.md)
- plugin rule は `tests:` セクションで deny / allow ケースを宣言的に書き、
  `ptuf plugin test <path>` で検証する (v0.2 で実装済み、
  [`config-and-plugins.md`](config-and-plugins.md))

## 開発・依存方針

- MSRV: `1.93.0` (`Cargo.toml` の `rust-version` に記載)
- edition: `2024`
- 依存追加時は `deny.toml` の `licenses.allow` 範囲で済むこと、
  `bans.wildcards = "deny"` を満たすことを必須とする
