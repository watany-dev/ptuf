# Kiro CLI adapter (v2)

Kiro CLI の `preToolUse` hook を ptuf に橋渡しする adapter (M6) の設計
書。本書は Kiro 固有の payload 正規化・出力規約・fail-closed 経路・
`init` 統合をまとめる。一般的な hook protocol と Decision
モデルは [`cli-and-hooks.md`](cli-and-hooks.md) と
[`decision-model.md`](decision-model.md) を参照。

## 全体像

| サブコマンド | 役割 |
| --- | --- |
| `ptuf hook kiro-v2` | stdin の Kiro `preToolUse` payload を canonical `HookInput` に正規化し、engine 判定結果を stderr + exit code で返す |
| `ptuf init kiro-v2` | `<repo>/.kiro/agents/*.json` と `~/.kiro/agents/*.json` の **既存 agent JSON すべて** に hook entry を idempotent に注入する (`--new-agent` で legacy single-file 動作) |

## agent token のバージョニング

Kiro CLI の hook 仕様は v3 で変更される予定のため、adapter 世代ごとに
**versioned token** を持たせる。現行の `.kiro/agents/*.json` +
`hooks.preToolUse` 契約を対象とする本 adapter は `kiro-v2`。v3 が来た際は
別 `HookAgent` variant + `kiro-v3` token として追加し、本 adapter は据え置く。

無印の `kiro` は **floating alias** = 「その ptuf build における最新の Kiro
adapter」を指す。`cli::parse` の 2 つの const がその意味論を担う:

| const | 役割 |
|---|---|
| `KIRO_LATEST_ALIAS = "kiro"` | 無印 token の綴り |
| `KIRO_LATEST_AGENT = HookAgent::Kiro` | alias の解決先。**v3 追加時はここだけ差し替える** |

`kiro-v2` 等の versioned token は自分の世代に固定され、alias には追従しない。
`kiro-v3` は該当 adapter が入るまで未知 agent として reject する。

### 書き込む command は versioned に pin する

alias が最新に追従する以上、agent JSON に `ptuf hook kiro` と書いてしまうと
**ptuf を upgrade した瞬間に既存インストールの hook 行が v3 へ黙って切り替わる**。
これを避けるため、書き込む command は常に versioned 形:

- `COMMAND_TAIL = ["hook", "kiro-v2"]` — 書き込む形かつ冪等検出のマーカー
- `LEGACY_COMMAND_TAIL = ["hook", "kiro"]` — 旧 ptuf が書いた無印形。
  検出のみ行い、次回 `ptuf init` で **その場で versioned 形に書き換える**
  (`rewrite_legacy_hooks`)。entry を重複 append しないので冪等性は保たれ、
  同時に旧インストールを floating alias から降ろせる。書き換えが走った
  ファイルは `AlreadyPresent` ではなく `Installed` として報告される。

一方 `HookAgent::Kiro.audit_name()` → `"kiro"` は **変更しない**。監査レコードは
adapter 世代をまたいで比較可能であるべきなので、世代情報は audit name には
載せない。

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

default 動作は **既存 agent JSON への一括 patch**: 列挙対象の各 scope に
ある `*.json` をすべて読み込み、`hooks.preToolUse` 配列に ptuf entry を
append する。既に末尾 token が `["hook", "kiro-v2"]` の `command` を持つ entry
があれば `AlreadyPresent` で no-op (冪等)。末尾が旧形の `["hook", "kiro"]` の
entry はその場で versioned 形へ書き換える (上記「書き込む command は
versioned に pin する」を参照)。

scope:

- repo-local: `<repo>/.kiro/agents/*.json`
- global: `$HOME/.kiro/agents/*.json`

両 scope は独立に列挙され、各 scope の `settings/cli.json` から
`chat.defaultAgent` (flat dotted-key) を読んで、参照先の agent JSON が
同じ scope に存在するか検証する。**`chat.defaultAgent` が指定されている
が対応する `agents/<name>.json` が無い場合は `InitError::Schema` で
fail-closed する** (新規 init は失敗、verify は出力しない)。

`.md` agent ファイルは触らず、verify report の `skipped_non_json_agents`
に列挙する。

両 scope を合わせて agent JSON が 1 つも見つからない場合のみ、最優先
scope (workspace > home) に `agents/default.json` を新規作成し skeleton +
hook を書き込む。

| フラグ | 用途 |
| --- | --- |
| `--no-verify` | install 後の synthetic deny / fail-closed verify を skip |
| `--dry-run` | 書き込まずに `WouldInstall` を報告 (verify は自動的に off) |
| `--new-agent` | legacy 動作: `<scope>/.kiro/agents/ptuf-guarded.json` を 1 ファイル作成。既存 agent JSON は触らない |
| `--workspace-only` | repo-local scope のみ列挙 (`$HOME` は触らない)。`--new-agent` と併用すると parse error |
| `--global` | `$HOME` scope のみ列挙。`--new-agent` と併用すると `$HOME/.kiro/agents/ptuf-guarded.json` を作る |

`--workspace-only` と `--global` は排他。Kiro-only フラグを他 adapter や
auto-detect 経路に渡すと parse error (`ParseError::ConflictingFlags`)。

書き込みは temp file + `rename(2)` の atomic write、JSON は
`serde_json::to_string_pretty` + 末尾改行 1 つ。`hooks.preToolUse` 以外
のキー (`name`, `description`, `tools`, `model`, `temperature`, ...) は
`serde_json::Value` のまま保持し mutate しない。

新規作成 (`--new-agent` または空ディレクトリ fallback) 時の default
skeleton:

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
        "command": "<absolute ptuf path> hook kiro-v2",
        "timeout_ms": 10000,
        "cache_ttl_seconds": 0
      }
    ]
  }
}
```

空ディレクトリ fallback のファイル名は `default.json` (legacy
`ptuf-guarded.json` ではない)。

`<absolute ptuf path>` は `std::env::current_exe()` から導出する。
得られない場合は literal `"ptuf"` にフォールバック (他 adapter と同様)。

### Partial-write window

複数ファイル install で `--no-verify` 指定時は capture/restore が回らない
ため、ループ途中で write が失敗すると先行ファイルだけ patch 済の状態が
残る。各 file の write は temp+rename で atomic なので個別ファイルが torn
にはならないが、ファイル間整合性は保証されない。`--no-verify` を使う
ユーザーは部分適用を許容すること。デフォルト (`--no-verify` 未指定) では
verify 経路の snapshot capture により mid-loop crash でも自動巻き戻し。

## self-protection との関係

`ProtectedPaths::collect` は起動時に `<repo>/.kiro/agents/*.json` と
`$HOME/.kiro/agents/*.json` に実在する `*.json` をすべて列挙し
`ProtectedKind::KiroSettings` の対象に積む。`ptuf init kiro` の default
mode で patch される全 agent JSON が `core.self_protection.kiro-settings`
の保護下に入るため、hook 直後に同じ session が当該 JSON を書き換えて
hook を消すことを deny する。`.md` agent や `.kiro/agents/` 自体が存在
しないリポジトリでは `kiro_settings` は空のまま (protected list は graceful
degrade)。

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
- `tests/cli_smoke.rs::kiro_hook_*` — subprocess 境界の smoke test
