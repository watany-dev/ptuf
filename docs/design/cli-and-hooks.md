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
| `ptuf init <agent>` | agent 側の hook 設定を配線 |
| `ptuf doctor [--json]` | binary / config / plugin / hook の診断 |
| `ptuf --help`, `ptuf --version` | 情報表示 |

## 終了コード

| 条件 | exit |
| --- | --- |
| `Allow` / `Monitor` / Claude Code の `Ask` | `0` |
| `Deny` | `2` |
| 内部エラー、引数不正、plugin test fail、doctor failure | `1` |

Codex では `Ask` を `Deny` へ変換するため、実際には exit `2` になる。

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
- 既存 entry の検出は command 末尾 `hook claude-code` で行う
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
書かずに以下の top-level key を読む。

| key | 用途 |
| --- | --- |
| `path` | `Facts.path` / `Facts.paths` |
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

## fail-closed

`hook` と `eval` は engine 構築に失敗すると
`core.engine.policy-load-failed` で deny する。これは CLI の固定契約であり、
ライブラリ API `decide()` とは意図的に異なる。
