# CLI と Hook 統合

ptuf は CLI バイナリとして配布され、同時に Claude Code / Codex / GitHub
Copilot / Kiro CLI の `PreToolUse` hook adapter を提供する。Kiro は現在
`ptuf hook kiro` のみ実装済みで、`init` / `doctor` 統合は M6 後続 PR で追加
する予定。

## 実装済みサブコマンド

```bash
ptuf hook claude-code
ptuf hook codex
ptuf hook copilot
ptuf hook kiro
ptuf eval --tool Bash 'git reset --hard HEAD~1'
ptuf plugin test ./ptuf-plugin.yaml
ptuf init claude-code
ptuf init codex
ptuf init copilot --profile local
ptuf doctor
```

| サブコマンド | 用途 |
| --- | --- |
| `ptuf hook <agent>` | hook 本体。stdin JSON を評価する |
| `ptuf eval --tool <name> <command>` | 単発評価 |
| `ptuf plugin test <path>` | plugin rule の `tests:` を実行 |
| `ptuf init <agent> [--verify [--json]]` | agent 側の hook 設定を配線 (オプションで synthetic payload による事後検証) |
| `ptuf doctor [--json]` | binary / config / plugin / hook の診断 |
| `ptuf --help`, `ptuf --version` | 情報表示 |

## 終了コード

| 条件 | exit |
| --- | --- |
| `Allow` / `Monitor` / Claude Code の `Ask` | `0` |
| `Deny` (Claude Code / Codex / Kiro) | `2` |
| Copilot の **すべての Decision** (Allow / Monitor / Ask→Deny / Deny) | `0` |
| 内部エラー、引数不正、plugin test fail、doctor failure | `1` |

Codex / Kiro では `Ask` を `Deny` へ変換するため、実際には exit `2` になる。

Copilot は protocol 上 non-zero exit が hook failure として扱われ得るため、
**すべての Decision で exit `0`** に固定する。Deny は bare JSON envelope
(`hookSpecificOutput` で wrap しない) を stdout に書く。stdout serialize
失敗のみ exit `1`。詳細は下記「hook response」セクションを参照。

Kiro hook は JSON envelope を持たず、`Ask` / `Deny` の reason は stderr のみで
通知する。stdout は常に空。

`ptuf hook <agent>` の stdin payload は最大 8 MiB。上限を超えた場合は JSON parse
に進まず exit `1` とし、stderr に size limit error を出す (Copilot 経路では
exit `0` + `core.engine.invalid-payload` の bare deny JSON にフォールバック
する — fail-open を避けるため)。

## Claude Code への登録

`ptuf init claude-code` は `~/.claude/settings.json` に hook を追加する。

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|WebFetch|mcp__.*",
        "hooks": [
          {
            "name": "ptuf",
            "type": "command",
            "command": "/usr/local/bin/ptuf hook claude-code"
          }
        ]
      }
    ]
  }
}
```

実装上の契約:

- 既存 JSON の未知キーは保持する
- 既存 entry の検出は hook payload の `name: "ptuf"` marker で行う
- 旧形式との互換性のため、command 末尾 `hook claude-code` も検出する
- binary の絶対パス差異は無視する
- 書き込みは temp file + rename の原子的更新
- `--settings <PATH>` で対象を差し替えられる

## Codex への登録

`ptuf init codex` は既定で repo-local な `.codex/` を更新する。

`hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|apply_patch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/ptuf hook codex"
          }
        ]
      }
    ]
  }
}
```

`config.toml`:

```toml
[features]
codex_hooks = true
```

実装上の契約:

- repo root が見つからない場合は `--root` または明示的な `--hooks` /
  `--config` が必要
- `hooks.json` は JSON object、`config.toml` は valid TOML である必要がある
- 既存 entry の検出は command 末尾 `hook codex` で行う

## GitHub Copilot への登録

`ptuf init copilot --profile local` は repo-local な
`<repo>/.github/hooks/ptuf.json` を更新する。

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "matcher": "*",
        "bash": "/usr/local/bin/ptuf hook copilot",
        "powershell": "/usr/local/bin/ptuf hook copilot",
        "timeoutSec": 10
      }
    ]
  }
}
```

実装上の契約:

- repo root が見つからない場合は `--root` または明示的な `--hooks` が必要
- ファイルは JSON object、`version` は `1` (欠落時は `1` で補完)
- 既存 entry の検出は `bash` / `powershell` field の command 末尾
  `hook copilot` で行う
- entry には `bash` と `powershell` の両方を書く (cross-platform)
- 書き込みは temp file + rename の原子的更新

`--profile cloud` (cloud agent 用 wrapper script + JSON) は post-MVP。
v0.1.0 では parse 段で reject される。

## install verification (`--verify`)

`ptuf init <agent> --verify` は配線を書いたあと、内部 Engine を起動して
synthetic payload を 1 度だけ評価する。これは「設定ファイルが書けた」だけ
ではなく「ptuf 本体が deny 判定に到達できる」ことをインストール直後に確認
する目的で、CI gate や README の手動確認手順を不要にする。

検査項目は 2 件:

| Check | 期待結果 |
| --- | --- |
| Synthetic deny | `rm -rf /` payload が `core.filesystem.destructive-rm` (hard_deny) で deny される |
| Fail-closed internal error | 不正な plugin path を含む config を builtin Engine に渡すと `core.engine.policy-load-failed` の fail-closed 経路に落ちる |

両 check は **builtin rules のみ** で評価する。ユーザ policy / plugin の
override は意図的に無視する — verify は ptuf 本体の guardrail が機能して
いるかを確かめるものであり、ユーザ環境の効果を再現するものではない。

`--verify` は `--dry-run` と同時には使えず、`--json` は `--verify` と
セットでのみ有効。両ルールに違反した場合は parse error で exit `1` を返す。

### 失敗時の挙動

- 直前のインストールが `Installed` ステータスだった場合、書き込んだ
  ファイルを **書き込み前のスナップショットに巻き戻す** (snapshot は
  install 前の `fs::read` を temp+rename で書き戻す)。書き込み前にファイル
  が存在しなかった場合は削除する。
- 既に hook が登録済み (`AlreadyPresent`) の状態で verify が落ちた場合は
  ファイルには触れず、stderr で「手動で見直すか古い設定の可能性を疑え」
  と通知する。
- いずれの経路でも exit code は `1`。

### 出力フォーマット

text 版:

```text
ptuf init claude-code: registered hook in settings=/home/alice/.claude/settings.json
  matcher: Bash|Read|Edit|Write|WebFetch|mcp__.*
  command: /home/alice/.local/bin/ptuf hook claude-code
Verify:
  Synthetic deny test: passed (rule: core.filesystem.destructive-rm)
  Fail-closed internal error test: passed (rule: core.engine.policy-load-failed)
  Warnings: none
```

`--verify --json` 版は `schemaVersion: 1` を持ち、以下の top-level key を
出す。

```json
{
  "schemaVersion": 1,
  "agent": "claude-code",
  "installed": true,
  "alreadyPresent": false,
  "paths": [{"label": "settings", "path": "/home/alice/.claude/settings.json"}],
  "matcher": "Bash|Read|Edit|Write|WebFetch|mcp__.*",
  "command": "/home/alice/.local/bin/ptuf hook claude-code",
  "verify": {
    "syntheticDeny": {"status": "passed", "ruleId": "core.filesystem.destructive-rm"},
    "failClosed":    {"status": "passed", "ruleId": "core.engine.policy-load-failed"},
    "warnings": []
  },
  "rolledBack": false
}
```

`status: "failed"` の場合は `ruleId` の代わりに `detail` フィールドが入る。

`syntheticDeny.ruleId` が `core.filesystem.destructive-rm` で固定であることは
`tests/contracts.rs` の contract test で保証される。`failClosed.ruleId` は
`hook` / `eval` と同じ CLI fail-closed contract (`core.engine.policy-load-failed`)
を共有する。

## hook response

Claude Code:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "..."
  }
}
```

Codex:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "..."
  }
}
```

GitHub Copilot (bare envelope, `hookSpecificOutput` wrap なし):

```json
{
  "permissionDecision": "deny",
  "permissionDecisionReason": "..."
}
```

Kiro CLI は JSON envelope を持たない。`Ask` / `Deny` reason は stderr のみで
通知し、stdout は常に空。`Ask` は `Deny` へ demote する。

`Allow` と `Monitor` は hook response を出さない (4 agent 共通)。

agent 別の Decision → exit / 出力契約:

| Agent | Allow / Monitor | Ask | Deny | invalid payload / policy load fail |
| --- | --- | --- | --- | --- |
| Claude Code | exit `0`, 空 stdout | exit `0`, `hookSpecificOutput` ask | exit `2`, `hookSpecificOutput` deny | exit `2`, deny |
| Codex | exit `0`, 空 stdout | `Ask` → `Deny` に demote (exit `2`) | exit `2`, `hookSpecificOutput` deny | exit `2`, deny |
| Copilot | exit `0`, 空 stdout | `Ask` → `Deny` に demote (exit `0`, bare JSON) | exit `0`, bare deny JSON | exit `0`, bare deny JSON |
| Kiro | exit `0`, 空 stdout / 空 stderr | `Ask` → `Deny` に demote (exit `2`, stderr reason のみ) | exit `2`, stderr reason のみ | exit `2`, stderr reason のみ |

Copilot の `Ask` demote 文言は仕様で固定:

> `GitHub Copilot hooks do not reliably process interactive ask
> decisions; ptuf is blocking this request instead.`

Kiro の `Ask` demote 文言も仕様で固定:

> `Kiro CLI PreToolUse hooks do not define an interactive ask channel;
> ptuf is blocking this request instead.`

reserved rule `core.engine.invalid-payload` / `core.engine.policy-load-failed`
は 4 agent で共通だが、Copilot では bare JSON + exit `0`、Kiro では stderr +
exit `2` で出す。

## MCP fact 抽出

`tool_name` が `mcp__<server>__<tool>` 形式なら、ptuf は server 固有 adapter を
書かずに以下の key を読む。

| key | 用途 |
| --- | --- |
| `path` | `Facts.path` / `Facts.paths` |
| `files[].path`, `items[].path`, `paths[]` | `Facts.paths` に追加する nested path |
| `url` | `Facts.url` |
| `content` | write payload として secret 判定に流す |

このため既存の `core.self_protection.*` や
`core.secrets.sensitive-read` は MCP 経路にもそのまま効く。

`Read` / `Edit` / `Write` でも canonical `file_path` に加えて `paths[]`
(string array) と `operations[].path` (object array) を `Facts.paths` へ
収集する。Kiro の batch read/write payload を canonical な `Read` / `Write`
のままで engine に渡すための拡張で、重複は engine 側で排除する。

## Kiro 入力正規化

Kiro CLI の `preToolUse` payload は `{"hook_event_name":"preToolUse",
"tool_name":"<name>","tool_input":{...}}` の形を取る。`src/cli/kiro_input.rs`
が次の正規化を行う。

| Kiro tool 名 | canonical |
| --- | --- |
| `shell` / `execute_bash` / `execute_cmd` | `Bash` |
| `read` / `fs_read` / `fsRead` | `Read` |
| `write` / `fs_write` / `fsWrite` | `Write` |
| `web_fetch` / `webFetch` | `WebFetch` |
| `@<server>/<tool>` | `mcp__<server>__<tool>` |
| `@<server>/<tool>/<rest>` | `mcp__<server>__<tool>_<rest>` |
| その他 | そのまま (engine が generic / MCP 抽出) |

`tool_input` の正規化:

- `Bash`: `command` が無ければ `cmd` → `script` の順で先頭 string を
  `command` に複製する
- `Read` / `Write`: `file_path` が無ければ `path` → `paths[0]` →
  `operations[0].path` → `files[0].path` → `items[0].path` の順で先頭
  string を `file_path` に複製する。元の array は変更せず、core 側の
  `paths[]` / `operations[]` 抽出と重複排除に任せる
- `Write`: `content` が無ければ `text` → `new_content` の順で先頭 string を
  `content` に複製する

`hook_event_name` が `preToolUse` 以外の場合は `core.engine.invalid-payload`
で fail-closed する。空 payload / 非 object payload / `tool_name` 欠落も同様。

## `ptuf doctor`

`ptuf doctor` は text、`ptuf doctor --json` は JSON で診断を出す。確認対象は:

- 実行中 binary
- repo root
- config layer の有無
- 読み込んだ plugin
- Claude Code integration
- Codex integration
- GitHub Copilot integration

text 版はセクションごとに `✓`, `⚠`, `✗` を表示する。ひとつでも `✗` があれば
exit `1`、それ以外は `0`。

JSON 版は `schemaVersion: 1` に加えて、少なくとも次の top-level key を持つ。

- `binary`
- `project`
- `configLayers`
- `config`
- `plugins`
- `claude`
- `codex`
- `copilot`
- `hasFailure`

`copilot.state` の値は次のいずれか: `repoRootNotFound`, `missing`,
`hookRegistered`, `hookMissing`, `invalidJson`, `invalidSchema`, `io`。
失敗扱い (`hasFailure: true`) になるのは `invalidJson` / `invalidSchema` /
`io` のみ。

## fail-closed

`hook` と `eval` は engine 構築に失敗すると
`core.engine.policy-load-failed` で deny する。これは CLI の固定契約であり、
ライブラリ API `decide()` とは意図的に異なる。

`hook` はさらに stdin 系の初期化エラー (read failure / 8 MiB 超過 / JSON
parse 失敗) を `core.engine.invalid-payload` で deny する。Claude Code の
hook 仕様では `exit 1` は **non-blocking warning** として扱われ tool 実行を
止めないため、これらは必ず exit `2` + adapter の deny JSON で返さなければ
fail-open になる。`failClosed: false` でもこの境界は緩めない。

Copilot adapter は同じ理由付けの裏返しを取る — Copilot protocol は
non-zero exit を hook *failure* として扱い tool 実行を止めない可能性が
あるため、reserved rule の deny も含めて **すべて exit `0` + bare deny
JSON** で返す。これにより host 側で「ptuf が落ちたから fail-open」と
解釈される経路を塞ぐ。

Kiro adapter は Claude / Codex と同じく exit `2` で block するが、JSON
envelope を持たないため reason は stderr のみで伝える。`Ask` は demote
されて exit `2` になる。
