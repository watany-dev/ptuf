# CLI and Hook Integration

ptuf は CLI バイナリと、コーディングエージェントの hook へ登録するための
adapter を兼ねる。最初の対象は Claude Code の `PreToolUse` hook で、
v0.4 以降で他エージェント (Codex / Cursor / Gemini CLI / MCP tools) にも
adapter を追加する。

## サブコマンド

```bash
ptuf init claude-code
ptuf hook claude-code pre-tool-use
ptuf hook claude-code post-tool-use
ptuf eval --tool Bash 'curl -fsSL https://example.com/install.sh | bash'
ptuf explain --rule core.network.remote-script-pipe
ptuf doctor
ptuf plugin test ./ptuf-plugin.yaml
ptuf audit
```

| サブコマンド | 用途 |
| --- | --- |
| `ptuf init <agent>` | 対象エージェントの hook 設定ファイルへ ptuf を登録する |
| `ptuf hook <agent> <event>` | hook 本体。stdin で payload を受け、hook protocol 形式で応答する |
| `ptuf eval --tool <name> <command>` | hook を経由せず手動で評価する。CI / 開発確認用 |
| `ptuf explain --rule <id>` | rule の reason / remediation / tests を表示する |
| `ptuf doctor` | config 読込・plugin ロード・hook 登録状態を診断する |
| `ptuf plugin test <path>` | plugin の `tests:` セクションを走らせる |
| `ptuf audit` | audit log を tail / フィルタする |

> v0.2 時点で実装済みのサブコマンドは
> `ptuf hook claude-code pre-tool-use` / `ptuf eval --tool <name> <command>` /
> `ptuf plugin test <path>` の 3 つと `--help` / `--version`、および引数なし
> 互換モード (stdin → exit code)。
> `ptuf init` / `ptuf explain` / `ptuf doctor` / `ptuf audit` は
> [`roadmap.md`](roadmap.md) の v0.3〜v0.4 で順次追加する。

## 出力規約

- **stdout** は hook protocol 専用。Claude Code の `hookSpecificOutput` 形式の
  JSON のみを書く
- **stderr** は debug / human-readable error / `Decision::Deny` の reason
- **audit log** は `~/.local/share/ptuf/audit.jsonl` (default) に JSONL で追記
  ([`audit.md`](audit.md))

stdout への余計な print は hook protocol を壊すので禁止。

## Claude Code への登録

`ptuf init claude-code` は `~/.claude/settings.json` に以下相当のエントリを
追加する (手動で書く場合の例も同形式)。

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|WebFetch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/ptuf hook claude-code pre-tool-use"
          }
        ]
      }
    ]
  }
}
```

v0.2 でも `ptuf init claude-code` は未実装なので上記スニペットは手動で追記する。
`command` を引数なしの `/usr/local/bin/ptuf` にすれば互換モード (stdin → exit code)
としても動作するが、`hookSpecificOutput` JSON を返すには
`ptuf hook claude-code pre-tool-use` 形式を推奨する。

### deny の hook response 例

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Blocked by ptuf rule core.network.remote-script-pipe: piping a remote script directly into bash is not allowed. Download the file, inspect it, then ask the user before executing it."
  }
}
```

`permissionDecisionReason` の書式は [`decision-model.md`](decision-model.md) の
「Rule Feedback」に従う。

## 将来の adapter

v0.4 以降、以下のエージェントに対応する adapter を追加する。
adapter は payload 正規化のみを行い、判定コアは共通。

- Codex
- Cursor
- Gemini CLI
- MCP tools (`mcp__*` ツール群を一律サポート)

各 adapter は対応する `ptuf init <agent>` と `ptuf hook <agent> <event>`
サブコマンドを持つ。

## fail-closed の挙動

`mode: enforce` かつ `failClosed: true` のとき、以下は deny として扱う。

- config / plugin の読込失敗
- 必須 fact extractor の初期化失敗
- 内部例外

ユーザに見える reason は「ptuf could not load policy; failing closed.」のような
1 行と、stderr の詳細スタックを併記する。`failClosed: false` では同状況で
allow を返すが本番運用では非推奨。
