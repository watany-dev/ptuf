# Kiro CLI adapter

Kiro CLI の `preToolUse` hook を ptuf に橋渡しする adapter (M6) の設計
書。本書は Kiro 固有の payload 正規化・出力規約・fail-closed 経路・
`init` 統合をまとめる。一般的な hook protocol と Decision
モデルは [`cli-and-hooks.md`](cli-and-hooks.md) と
[`decision-model.md`](decision-model.md) を参照。

## 全体像

| サブコマンド | 役割 |
| --- | --- |
| `ptuf hook kiro` | stdin の Kiro `preToolUse` payload を canonical `HookInput` に正規化し、engine 判定結果を stderr + exit code で返す |
| `ptuf init kiro` | `<repo>/.kiro/agents/*.json` と `<global_root>/agents/*.json` を列挙して各 agent に `matcher: "*"` の `preToolUse` hook を append し、`chat.defaultAgent` 経由の effective default agent が実際に protect されているか検証する |

中核 engine と他 3 adapter (Claude Code / Codex / Copilot) は不変。Kiro
固有の揺れは `src/cli/kiro_input.rs`, `src/cli/output.rs::adapt_hook_decision`,
`src/init/kiro.rs` に閉じ込めてある。

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

成功条件は「Kiro CLI が実際に起動する agent (= effective default agent)
が ptuf hook で守られている」こと。単に `ptuf-guarded.json` を生成するだけ
では built-in `kiro_default` (patch 不能) や既存 custom agent を素通しに
してしまうため、列挙 + patch + default 検証の 3 段で構成する。

### 探索パス

| scope | path | 取得元 |
| --- | --- | --- |
| Workspace agents dir | `<repo>/.kiro/agents/` | `cwd` から repo root を解決 |
| Global agents dir | `<global_root>/agents/` | `KIRO_HOME` があればそれ、無ければ `$HOME/.kiro` |
| Global settings file | `<global_root>/settings/cli.json` | 同上 |
| Workspace settings (diagnostic) | `<repo>/.kiro/settings/cli.json` | authoritative ではない、warning 用 |

各ディレクトリ内の `*.json` を全て enumerate する。`.md` などの非 JSON
は `skippedNonJsonAgents` として report に残す。

### Effective default agent の解決

`<global_root>/settings/cli.json` の `chat.defaultAgent` を authoritative
として読む:

- `chat.defaultAgent` 未設定 → Kiro CLI は built-in `kiro_default` を使う。
  これは file が存在しないため patch 不能で、`BuiltinDefaultUncovered`
  failure。
- `chat.defaultAgent: "kiro_default"` → 同上 (`BuiltinDefaultUncovered`)。
- `chat.defaultAgent: "<name>"` → workspace → global の順で
  `<name>.json` を検索。両方に存在する場合は workspace precedence、
  global は warning として記録する。

`--set-default <name>` が指定されたら、設定ファイル経由の値を上書きして
init 中に `chat.defaultAgent` を `<name>` に書き換える。
`--set-default default` の特殊ケースとして `default.json` が存在しなければ
fallback skeleton (下記) を `<global_root>/agents/default.json` (無ければ
workspace) に生成する。

### Coverage tri-state

各 agent JSON 内の `hooks.preToolUse[]` を以下に分類する:

- **FullCoverage** — `matcher` が `"*"` あるいは省略 (Kiro CLI の wildcard 解釈)
  かつ `command` の末尾 token が `["hook", "kiro"]`。
- **NarrowCoverage** — `command` 末尾は ptuf だが `matcher` が
  特定 tool (`fs_write` 等)。元 entry は触らず、兄弟として `matcher: "*"`
  の新 entry を append する。
- **Present** (= ptuf hook が無い) — `matcher: "*"` の FullCoverage を append。

既に FullCoverage を含む agent は `AlreadyFullCoverage` で no-op
(install status は他に変更が無ければ `AlreadyPresent`)。

### CLI flags

| フラグ | 用途 |
| --- | --- |
| `--no-verify` | install 後の synthetic deny / fail-closed verify を skip |
| `--dry-run` | 書き込まずに `WouldInstall` を報告 (verify は自動的に off) |
| `--new-agent` | レガシー互換: `ptuf-guarded.json` 単一ファイルを workspace か global に生成し、default-agent coverage 検証を skip する |
| `--set-default <name>` | init 終了時に `<global_root>/settings/cli.json` の `chat.defaultAgent` を `<name>` に固定する。`<name>` の agent JSON が無く `default` が指定された場合のみ skeleton を生成する |
| `--workspace-only` | global agents / global settings を一切触らない |
| `--global` | workspace agents を skip し、global のみ操作する (`--workspace-only` と排他) |

### Hook entry の書式

```json
{
  "matcher": "*",
  "command": "'/abs/path/to/ptuf' hook kiro",
  "timeout_ms": 10000,
  "cache_ttl_seconds": 0
}
```

`command` は POSIX shell 単一引用符でクォートした絶対パス
(`'/abs/path/ptuf'` 内の `'` は `'\''` で escape)
+ ` hook kiro`。`std::env::current_exe()` から導出し、得られない場合は
literal `"ptuf"` にフォールバック (他 adapter と同様)。

書き込みは temp file + `rename(2)` の atomic write、JSON は
`serde_json::to_string_pretty` + 末尾改行 1 つ、mode 0600。`hooks.preToolUse`
以外のキー (`name`, `description`, `tools`, `model`, `temperature`, ...)
は `serde_json::Value` のまま保持し mutate しない。

### Fallback skeleton

`--set-default default` で `default.json` が存在しないとき、または
`--new-agent` モードで `ptuf-guarded.json` を新規作成するときの shape:

```json
{
  "name": "<default|ptuf-guarded>",
  "description": "Kiro CLI agent guarded by ptuf PreToolUse policy.",
  "tools": ["*"],
  "includeMcpJson": true,
  "hooks": {
    "preToolUse": [
      {
        "matcher": "*",
        "command": "'<absolute ptuf path>' hook kiro",
        "timeout_ms": 10000,
        "cache_ttl_seconds": 0
      }
    ]
  }
}
```

### 失敗条件

以下のいずれかで `overall_failure = true` → exit 1:

- `BuiltinDefaultUncovered` — `chat.defaultAgent` 未設定 or `kiro_default`
- `DefaultAgentJsonNotFound` — `chat.defaultAgent: "<name>"` だが `<name>.json` 不在
- `InvalidDefaultAgentJson` / `UnsupportedDefaultAgentJsonShape` — default agent の JSON が壊れている
- `PatchFailed` — default agent への書き込み失敗
- `NoAgentsAndNoSetDefault` — `--new-agent` 未指定で agents が 0、`--set-default` も無し

非 default agent の patch 失敗は warning のみで init 自体は通る。

## audit log との関係

Kiro 経由の hook 呼び出しは audit JSONL に `agent: "kiro"` として
記録される。schema は不変 (`audit.md` 参照)。

## 関連ファイル

実装の主な参照点:

- `src/cli/kiro_input.rs` — payload 正規化と alias テーブル
- `src/cli/output.rs::{adapt_hook_decision, decision_exit_code}` — Ask
  demotion / stderr-only 出力 / exit code matrix
- `src/hook_output.rs::kiro::deny_reason_for_ask` — Ask 拒否文言
- `src/init/kiro.rs` — `plan` / `install` / coverage 分類 /
  `command_invokes_ptuf_hook` / fallback skeleton 生成
- `tests/cli_smoke.rs::kiro_hook_*` — subprocess 境界の smoke test
