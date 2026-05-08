# CLI と Hook 統合

ptuf は CLI バイナリとして配布され、同時に Claude Code / Codex の
`PreToolUse` hook adapter を提供する。

## 実装済みサブコマンド

```bash
ptuf hook claude-code
ptuf hook codex
ptuf eval --tool Bash 'git reset --hard HEAD~1'
ptuf plugin test ./ptuf-plugin.yaml
ptuf init claude-code
ptuf init codex
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
| `Deny` | `2` |
| 内部エラー、引数不正、plugin test fail、doctor failure | `1` |

Codex では `Ask` を `Deny` へ変換するため、実際には exit `2` になる。

`ptuf hook <agent>` の stdin payload は最大 8 MiB。上限を超えた場合は JSON parse
に進まず exit `1` とし、stderr に size limit error を出す。

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

`Allow` と `Monitor` は hook response を出さない。

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

## `ptuf doctor`

`ptuf doctor` は text、`ptuf doctor --json` は JSON で診断を出す。確認対象は:

- 実行中 binary
- repo root
- config layer の有無
- 読み込んだ plugin
- Claude Code integration
- Codex integration

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
- `hasFailure`

## fail-closed

`hook` と `eval` は engine 構築に失敗すると
`core.engine.policy-load-failed` で deny する。これは CLI の固定契約であり、
ライブラリ API `decide()` とは意図的に異なる。

`hook` はさらに stdin 系の初期化エラー (read failure / 8 MiB 超過 / JSON
parse 失敗) を `core.engine.invalid-payload` で deny する。Claude Code の
hook 仕様では `exit 1` は **non-blocking warning** として扱われ tool 実行を
止めないため、これらは必ず exit `2` + adapter の deny JSON で返さなければ
fail-open になる。`failClosed: false` でもこの境界は緩めない。
