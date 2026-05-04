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

> v0.3 時点で実装済みのサブコマンドは
> `ptuf hook claude-code pre-tool-use` / `ptuf eval --tool <name> <command>` /
> `ptuf plugin test <path>` / `ptuf init claude-code [--dry-run] [--settings <PATH>]` /
> `ptuf doctor [--json]` と `--help` / `--version`、および引数なし
> 互換モード (stdin → exit code)。
> `ptuf explain` / `ptuf audit` は v0.4 以降で実装する。
>
> `ptuf doctor --json` は `Report` を構造化 JSON として stdout に書き、
> exit code は text 版と同じ semantics (failure → 1, success → 0)。
> スキーマ (`schemaVersion: 1`) は CI / 監査ツール向けの安定 contract:
>
> ```json
> {
>   "schemaVersion": 1,
>   "binary":   { "path": "/usr/local/bin/ptuf", "version": "0.3.0" },
>   "project":  { "repoRoot": "/home/user/proj" },
>   "configLayers": [
>     { "layer": "system",       "path": "...", "present": false },
>     { "layer": "user",         "path": "...", "present": false },
>     { "layer": "project",      "path": "...", "present": true  },
>     { "layer": "projectLocal", "path": "...", "present": false }
>   ],
>   "config":   { "loaded": true, "mode": "enforce", "failClosed": true,
>                 "auditPath": null },
>   "plugins":  [],
>   "claude":   { "settingsPath": "...", "state": "hookRegistered",
>                 "matcher": "Bash|Read|Edit|Write|WebFetch|mcp__.*" },
>   "hasFailure": false
> }
> ```
>
> `state` は `homeNotSet` / `missing` / `hookRegistered` / `hookMissing` /
> `invalidJson` / `io` のいずれか。`matcher` は `hookRegistered` の場合のみ、
> `error` は `invalidJson` / `io` の場合のみ出力される。

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

v0.3 で `ptuf init claude-code` が冪等 install を提供する。既存
`hooks.PreToolUse[].hooks[].command` の末尾 3 トークンが
`hook claude-code pre-tool-use` であれば既設定とみなして再書き込みは行わない
(binary path の差異は無視する)。`--dry-run` で書き込まずに計画を表示でき、
`--settings <PATH>` で対象ファイルを差し替えられる。
`command` を引数なしの `/usr/local/bin/ptuf` にすれば互換モード (stdin → exit code)
としても動作するが、`hookSpecificOutput` JSON を返すには
`ptuf hook claude-code pre-tool-use` 形式を推奨する。

### `ptuf doctor` の出力例

```text
ptuf doctor

Binary
  ✓ /usr/local/bin/ptuf  (version 0.3.0)

Project
  ✓ repository root: /home/user/proj
  ✓ config layers loaded (4 scopes considered, 1 file present)
       /etc/ptuf/policy.yaml                                       (not found)
       /home/user/.config/ptuf/config.yaml                         (not found)
       /home/user/proj/.ptuf.yaml                                  (loaded)
       /home/user/proj/.ptuf.local.yaml                            (not found)

Effective config
  mode:        enforce
  failClosed:  true
  audit.path:  /home/user/.local/share/ptuf/audit.jsonl

Plugins (1)
  ✓ /home/user/proj/.ptuf-plugins/team.yaml  (acme.security 0.1.0, 3 rules)

Claude Code integration
  ✓ /home/user/.claude/settings.json present
  ✓ ptuf hook registered (matcher: "Bash|Read|Edit|Write|WebFetch|mcp__.*")
```

セクションが ✗ を出した場合は exit code 1。⚠ のみで ✗ がない場合は 0。

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
- MCP tools (`mcp__*` ツール群を一律サポート — fact 層は v0.4 で対応済み、
  個別 adapter を追加する場合の `tool_name` 整形のみ未対応)

各 adapter は対応する `ptuf init <agent>` と `ptuf hook <agent> <event>`
サブコマンドを持つ。

### MCP fact 抽出 (v0.4)

Claude Code の MCP プロトコルでは tool 名が `mcp__<server>__<tool>` 形式で
入ってくる (例: `mcp__github__create_or_update_file`,
`mcp__filesystem__read_file`, `mcp__fetch__fetch`)。MCP server ごとに
payload の shape が異なるため、ptuf は個別 server に依存しない汎用的な
キー抽出戦略を採る:

| `tool_input` の top-level キー | 振る舞い |
| --- | --- |
| `path` (string) | `Facts.path` に正規化。`~` / `$HOME` 展開も既存と同じ |
| `url` (string) | `Facts.url` に正規化 (WebFetch 経由と同じパース) |
| `content` (string) | `Facts.write_payload` 経由で `sensitive` 検出に流す |

これにより以下の既存 rule が MCP 経路でも自動で効く:

- `core.self_protection.*` — ptuf 自身の binary / config / plugin /
  Claude settings / hook script の MCP 経由の改変を deny
- `core.secrets.sensitive-read` — MCP tool が sensitive な path を
  参照する場合 (例: `mcp__filesystem__read_file` で
  `~/.aws/credentials`) を deny

複数 path を持つ MCP tool (`mcp__github__push_files.files[].path` 等) は
v1 では先頭要素のみ `Facts.path` に詰める。残りは v2 で
`Facts.extra_paths` を導入して全件保護する想定。

非 string な値 (例: `path: 123`, `url: false`) は `as_str()` で `None` に
落として無視する — MCP server の payload 仕様変動に対する防御策。

## fail-closed の挙動

CLI 経路 (`ptuf` 引数なし互換モード / `ptuf hook ...` / `ptuf eval`) では、
Engine 構築失敗時 (config / plugin 読込失敗) を **常に** deny で扱う。
予約 rule_id `core.engine.policy-load-failed` を返し、reason は
「ptuf could not load policy; failing closed.」、stderr に詳細を付ける。
`failClosed: false` の opt-out は、設定ファイル自体が読めない時点では
評価できないので CLI では無効。

ライブラリ呼び出し (`crate::decide`) は組込み第三者の驚き最小化のため
`Engine::for_cwd()` 失敗時に `Engine::default()` へ寛容にフォールバックする
(CLI と意図的に挙動を分けている)。

`mode: enforce` で deny 以外の理由 (必須 fact extractor 失敗、内部例外) も
v0.4 以降は同様に fail-closed する予定。
