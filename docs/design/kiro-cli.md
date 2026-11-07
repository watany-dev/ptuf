# Kiro CLI adapter (v2 / v3)

Kiro CLI の `PreToolUse` / `preToolUse` hook を ptuf に橋渡しする adapter (M6) の設計
書。v3 (既定) は [後半の節](#kiro-cli-adapter-v3) を参照。本書は Kiro 固有の payload 正規化・出力規約・fail-closed 経路・
`init` 統合をまとめる。一般的な hook protocol と Decision
モデルは [`cli-and-hooks.md`](cli-and-hooks.md) と
[`decision-model.md`](decision-model.md) を参照。

## 全体像

| サブコマンド | 役割 |
| --- | --- |
| `ptuf hook kiro-v2` | stdin の Kiro `preToolUse` payload を canonical `HookInput` に正規化し、engine 判定結果を stderr + exit code で返す |
| `ptuf init kiro-v2` | `<repo>/.kiro/agents/*.json` と `~/.kiro/agents/*.json` の **既存 agent JSON すべて** に hook entry を idempotent に注入する (`--new-agent` で legacy single-file 動作) |
| `ptuf hook kiro-v3` (= `kiro`) | stdin の V3 engine `PreToolUse` payload を正規化。`Ask` は native の `permissionDecision: "ask"` envelope で返す |
| `ptuf init kiro-v3` (= `kiro`) | standalone hook 文書 `.kiro/hooks/ptuf.json` (既定 global) を idempotent に作成・更新する |

## agent token のバージョニング

Kiro CLI の hook 仕様は v3 で変わったため、adapter 世代ごとに
**versioned token** を持たせる。`.kiro/agents/*.json` +
`hooks.preToolUse` 契約を対象とする adapter は `kiro-v2` (`HookAgent::KiroV2`)、
standalone `.kiro/hooks/*.json` + `PreToolUse` 契約を対象とする adapter は
`kiro-v3` (`HookAgent::KiroV3`)。

無印の `kiro` は **floating alias** = 「その ptuf build における最新の Kiro
adapter」を指す。`cli::parse` の 2 つの const がその意味論を担う:

| const | 役割 |
|---|---|
| `KIRO_LATEST_ALIAS = "kiro"` | 無印 token の綴り |
| `KIRO_LATEST_AGENT = HookAgent::KiroV3` | alias の解決先。次世代追加時はここだけ差し替える |

`kiro-v2` / `kiro-v3` の versioned token は自分の世代に固定され、alias には追従しない。
`kiro-v4` 等の未実装世代は未知 agent として reject する。

### 書き込む command は versioned に pin する

alias が最新に追従する以上、agent JSON に `ptuf hook kiro` と書いてしまうと
**ptuf を upgrade した瞬間に既存インストールの hook 行が次世代へ黙って切り替わる**。
これを避けるため、書き込む command は常に versioned 形:

- `COMMAND_TAIL = ["hook", "kiro-v2"]` — 書き込む形かつ冪等検出のマーカー
- `LEGACY_COMMAND_TAIL = ["hook", "kiro"]` — 旧 ptuf が書いた無印形。
  検出のみ行い、次回 `ptuf init` で **その場で versioned 形に書き換える**
  (`rewrite_legacy_hooks`)。entry を重複 append しないので冪等性は保たれ、
  同時に旧インストールを floating alias から降ろせる。書き換えが走った
  ファイルは `AlreadyPresent` ではなく `Installed` として報告される。

一方 `HookAgent::KiroV2` / `KiroV3` の `audit_name()` → `"kiro"` は **共通**。監査レコードは
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

## Kiro CLI adapter (v3)

### 仕様の出典

- V3 hooks 移行ガイド: <https://kiro.dev/docs/cli/v3/hooks-migration/>
- hook の種類 / action / 共通仕様: <https://kiro.dev/docs/hooks/>,
  <https://kiro.dev/docs/hooks/types/>, <https://kiro.dev/docs/hooks/actions/>
- V3 tool ID 一覧: <https://kiro.dev/docs/tools/>
- V3 概要 / 移行ガイド: <https://kiro.dev/docs/cli/v3/>,
  <https://kiro.dev/docs/cli/v3/migration-guide/>
- agent 設定リファレンス (inline `hooks` 配列): <https://kiro.dev/docs/custom-agents/configuration-reference/>
- changelog: <https://kiro.dev/changelog/cli/2-8/> (V3 early access),
  <https://kiro.dev/changelog/cli/2-28/> (category matcher)
- 上記に加え kiro-cli 2.33.0 に同梱された V3 engine (`@kiro/agent` 0.66.48) の
  静的解析で payload / 出力 / alias / timeout の実挙動を確認した。

### hook 文書

V3 の hook は agent profile から独立した `.kiro/hooks/*.json` (workspace) と
`~/.kiro/hooks/*.json` (global) に置かれ、両方が全 agent に並行適用される。
`ptuf init kiro-v3` は ptuf 管理の `ptuf.json` 1 ファイルだけを扱う:

```json
{
  "version": "v1",
  "hooks": [
    {
      "name": "ptuf",
      "description": "ptuf PreToolUse guardrail (managed by `ptuf init kiro-v3`).",
      "trigger": "PreToolUse",
      "matcher": "*",
      "action": { "type": "command", "command": "<absolute ptuf path> hook kiro-v3" },
      "timeout": 30,
      "enabled": true
    }
  ]
}
```

- 既定 scope は global (`~/.kiro/hooks/ptuf.json`)。`--workspace-only` / `--scope local`
  は `<repo>/.kiro/hooks/ptuf.json`、`--root` で repo を明示できる。
  workspace と global を両方書くと同じ tool call を 2 回判定するため、`Both` は global 1 箇所に寄せる。
- 冪等: `action.command` 末尾が `hook kiro-v3` (または旧無印 `hook kiro`) の entry を
  正規形に置換し、なければ append。他の entry と未知フィールドは保持する。
  `version` が `v1` 以外、`hooks` が配列でない文書は schema error で触らない。
- `matcher: "*"` は matcher 省略時の警告を避けつつ全 tool を対象にする。
- `timeout` は秒。Kiro 側既定は 60 秒だが、判定は数 ms なので 30 秒に詰める。

### 入力 payload

```json
{
  "session_id": "...",
  "hook_event_name": "PreToolUse",
  "cwd": "/repo",
  "tool_name": "execute_bash",
  "tool_input": { "command": "rm -rf /", "description": "...", "cwd": "/repo" }
}
```

`kiro_input` は `hook_event_name` の綴りで語彙を選ぶ (`PreToolUse` → v3 表、
`preToolUse` → v2 表)。field が無い場合だけ adapter 世代を fallback に使う。
V3 engine は legacy agent JSON の `preToolUse` hook (= `ptuf hook kiro-v2`) にも
V3 payload を送るため、`kiro-v2` 登録のまま engine を V3 に切り替えても
fail-closed で全拒否にならない。それ以外の event は fail-closed で reject。

| V3 tool ID | canonical | input の整形 |
|---|---|---|
| `execute_bash` / `execute_pwsh` | `Bash` | `command` |
| `read_file` | `Read` | `path` → `file_path` |
| `fs_write` / `fs_append` | `Write` | `path` → `file_path`, `text` → `content` |
| `str_replace` | `Edit` | `path` / `oldStr` / `newStr` → `file_path` / `old_string` / `new_string` |
| `delete_file` | `Write` | `targetFile` → `file_path` (削除は書き込みと同じ保護に乗せる) |
| `web_fetch` | `WebFetch` | `url` |
| `list_directory` / `file_search` / `grep_search` | `mcp__kiro__<id>` | そのまま (path 系規則は `path` を見る) |
| `mcp_<server>_<tool>` | `mcp__<server>__<tool>` | 最初の `_` で server と tool を分割 |
| その他 | そのまま | — |

### 出力

| Decision | exit | stdout | stderr |
|---|---|---|---|
| `Allow` / `Monitor` | `0` | 空 | 空 |
| `Ask` | `0` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"..."}}` | 空 |
| `Deny` | `2` | 空 | reason |

V3 engine は exit `2` で tool をブロックし stderr を agent に渡す。`ask` は
利用者に確認を求め、確認手段がない (非対話) セッションでは deny 扱いになる。
v2 と違い `Ask` を `Deny` へ demote しない。

### 既知の制約

- **untrusted workspace では hook が全停止**する (global hook を含む)。Kiro 側の仕様で ptuf からは回避できない。
- Kiro は exit `2` 以外の non-zero・crash・timeout で **fail-open** する。
  ptuf 内部エラーは exit `2` で返すが、ptuf プロセス自体の起動失敗は防げない。
- MCP tool ID は Kiro 側で `mcp_` + 小文字化・記号除去・64 文字切り詰めで作られる
  非可逆な名前のため、server / tool の境界は推定 (最初の `_`) になる。
  `_` を含む server 名の MCP 規則は意図通りに当たらない可能性がある。
- 自己保護は `.kiro/hooks/ptuf.json` と起動時に実在する `.kiro/hooks/*.json` を対象にする。
  session 中に新規作成された別名の hook 文書は対象外。
- kiro-cli 2.x では V2 engine がまだ既定 (`--v3` / `chat.agentEngine v3` で opt-in)。
  V2 engine は `.kiro/hooks` を読まないため、V2 engine 利用者は `ptuf init kiro-v2` を使う。
  両方入れても engine ごとにどちらか一方しか発火しない。
