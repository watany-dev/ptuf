# Kiro CLI adapter

Kiro CLI の `preToolUse` hook を ptuf に橋渡しする adapter (M6) の設計
書。本書は Kiro 固有の payload 正規化・出力規約・fail-closed 経路・
`init` / `doctor` 統合をまとめる。一般的な hook protocol と Decision
モデルは [`cli-and-hooks.md`](cli-and-hooks.md) と
[`decision-model.md`](decision-model.md) を参照。

## 全体像

| サブコマンド | 役割 |
| --- | --- |
| `ptuf hook kiro` | stdin の Kiro `preToolUse` payload を canonical `HookInput` に正規化し、engine 判定結果を stderr + exit code で返す |
| `ptuf init kiro` | `<repo>/.kiro/agents/<name>.json` (local) / `~/.kiro/agents/<name>.json` (global) に hook entry を idempotent に書き込む |
| `ptuf doctor` | 上記の agent 設定ファイルを走査し、`hooks.preToolUse[].command` の末尾が `["hook", "kiro"]` のものを「ptuf hook 登録済み」として報告 |

中核 engine と他 3 adapter (Claude Code / Codex / Copilot) は不変。Kiro
固有の揺れは `src/cli/kiro_input.rs`, `src/cli/output.rs::adapt_hook_decision`,
`src/init/kiro.rs`, `src/doctor/mod.rs::build_kiro_status` に閉じ込めて
ある。

## 入力 payload の正規化

Kiro `preToolUse` payload の例:

```json
{
  "hook_event_name": "preToolUse",
  "cwd": "/repo",
  "session_id": "...",
  "tool_name": "shell",
  "tool_input": { "command": "rm -rf /" }
}
```

`hook_event_name` は省略可。`preToolUse` 以外が来た場合は
`core.engine.invalid-payload` で fail-closed する。

`tool_name` は canonical 名 (`Bash` / `Read` / `Write` / `WebFetch` /
`mcp__server__tool`) に書き換える:

| Kiro での名前 | canonical |
| --- | --- |
| `shell`, `execute_bash`, `execute_cmd` | `Bash` |
| `read`, `fs_read`, `fsRead` | `Read` |
| `write`, `fs_write`, `fsWrite` | `Write` |
| `web_fetch`, `webFetch` | `WebFetch` |
| `@<server>/<tool>[/<rest>]` | `mcp__<server>__<tool>` (`<rest>` 内の `/` は `_` に変換、空 segment は raw 維持) |
| その他 | そのまま (engine の generic 抽出に任せる) |

`tool_input` の正規化は canonical 名ごとに以下の優先順で alias を統合
する。

- `Bash`: `command` 不在なら `cmd` → `script` を `command` にコピー
- `Read` / `Write`: 単一 path 候補を `file_path` に複製 (優先順:
  `file_path` → `path` → `paths[0]` → `operations[0].path` →
  `files[0].path` → `items[0].path`)。`paths[]` / `operations[]` は
  原位置に残す (core `collect_event_paths` が拡張済みの Read/Edit/Write
  arm で重複排除しつつ拾い上げる)
- `Write`: `content` 不在なら `text` → `new_content` をコピー
- `WebFetch` / MCP: 既存 generic 抽出に任せる (変換しない)

Ask demotion 文言:

> Kiro CLI PreToolUse hooks do not define an interactive ask channel;
> ptuf is blocking this request instead.

## 出力規約と exit code

Kiro hook は JSON envelope を持たない。よって stdout は常に空、reason は
stderr のみで通知する。

| Decision | stdout | stderr | exit |
| --- | --- | --- | --- |
| Allow / Monitor | (empty) | (empty) | `0` |
| Ask | — | adapt 後 `Deny` として扱う | `2` |
| Deny | (empty) | reason | `2` |
| invalid payload / policy load failure | (empty) | `core.engine.*` reason | `2` |

stdin が読めない、JSON parse 失敗、`hook_event_name != preToolUse` の
すべては fail-closed: `core.engine.invalid-payload` で deny し exit `2`。

## `ptuf init kiro`

`.kiro/agents/<name>.json` の `hooks.preToolUse` 配列に entry を append
する。既に末尾 token が `["hook", "kiro"]` の `command` を持つ entry
があれば `AlreadyPresent` で no-op。

CLI フラグ:

| フラグ | 用途 |
| --- | --- |
| `--root <PATH>` | 明示 repo root (省略時は cwd から `.git` を辿る) |
| `--agent <NAME>` | 既定 `ptuf-guarded`。agent file の `name` と stem に使う |
| `--agent-config <PATH>` | scope/root を無視して指定 path に直接書き込む |
| `--scope local\|global` | local 既定。global は `$HOME/.kiro/agents/<name>.json` |
| `--dry-run` | 書き込まずに `WouldInstall` を報告 |
| `--verify [--json]` | install 後に synthetic deny + fail-closed の 2 case を実行。失敗時は capture/restore で rollback |

書き込みは temp file + `rename(2)` の atomic write、JSON は
`serde_json::to_string_pretty` + 末尾改行 1 つ。`hooks.preToolUse` 以外
のキー (`name`, `description`, `tools`, `model`, `temperature`, ...) は
`serde_json::Value` のまま保持し mutate しない。

新規作成時の default skeleton:

```json
{
  "name": "ptuf-guarded",
  "description": "Kiro CLI agent guarded by ptuf PreToolUse policy.",
  "tools": ["*"],
  "includeMcpJson": true,
  "hooks": {
    "preToolUse": [
      {
        "matcher": "*",
        "command": "<absolute ptuf path> hook kiro",
        "timeout_ms": 10000,
        "cache_ttl_seconds": 0
      }
    ]
  }
}
```

`<absolute ptuf path>` は `std::env::current_exe()` から導出する。
得られない場合は literal `"ptuf"` にフォールバック (他 adapter と同様)。

## `ptuf doctor` 統合

`Kiro CLI integration` section が次を出力する:

- `local agents dir`: `<repo>/.kiro/agents`
- `global agents dir`: `$HOME/.kiro/agents`
- 状態:
  - `noTargets` — repo root も `$HOME` も解決できず走査対象なし (warning)
  - `missing` — どちらの directory にも `.json` agent file が無い (warning)
  - `hookRegistered` — agent file の中に末尾 token が `["hook", "kiro"]`
    の `command` が見つかった。`scope` (`local` / `global`) と任意の
    `matcher` を併記
  - `hookMissing` — agent file はあるが ptuf hook が無い (warning)
  - `invalidJson` — どれかの agent file が JSON parse 失敗 (failure)
  - `io` — directory / agent file の I/O error (failure)

最初に `hookRegistered` を返した entry の path を採用する (local を
global より優先する)。

`doctor --json` 側は `kiro` ブロックとして同等情報を返す:

```json
{
  "schemaVersion": 1,
  "kiro": {
    "localAgentsDir": "/repo/.kiro/agents",
    "globalAgentsDir": "/home/me/.kiro/agents",
    "state": "hookRegistered",
    "configPath": "/repo/.kiro/agents/ptuf-guarded.json",
    "scope": "local",
    "matcher": "*"
  }
}
```

`scope` / `matcher` / `configPath` / `error` は state に応じて省略
される (`#[serde(skip_serializing_if = "Option::is_none")]`)。

## audit log との関係

Kiro 経由の hook 呼び出しは audit JSONL に `agent: "kiro"` として
記録される。schema は不変 (`audit.md` 参照)。

## 関連ファイル

実装の主な参照点:

- `src/cli/kiro_input.rs` — payload 正規化と alias テーブル
- `src/cli/output.rs::{adapt_hook_decision, decision_exit_code}` — Ask
  demotion / stderr-only 出力 / exit code matrix
- `src/hook_output.rs::kiro::deny_reason_for_ask` — Ask 拒否文言
- `src/init/kiro.rs` — `resolve_paths` / `install` / `entry_commands` /
  `command_invokes_ptuf_hook`
- `src/doctor/mod.rs::{KiroStatus, KiroState, build_kiro_status,
  KiroPaths}` と `src/doctor/json.rs::JsonKiro` — doctor 統合
- `tests/cli_smoke.rs::kiro_hook_*` — subprocess 境界の smoke test
