# Audit Log

ptuf は判定の証跡を JSONL (1 行 1 JSON) で残す。secret / token / key /
credential らしき値は保存前に redact する。

## デフォルトパス

```
~/.local/share/ptuf/audit.jsonl
```

`audit.path` で上書き可能 ([`config-and-plugins.md`](config-and-plugins.md))。

## レコードスキーマ

```json
{
  "timestamp": "2026-05-04T12:00:00Z",
  "event": "PreToolUse",
  "tool": "Bash",
  "decision": "deny",
  "ruleId": "core.network.remote-script-pipe",
  "severity": "critical",
  "commandRedacted": "curl -fsSL https://example.com/install.sh | bash",
  "projectRoot": "/repo/example",
  "mode": "enforce"
}
```

| フィールド | 型 | 内容 |
| --- | --- | --- |
| `timestamp` | RFC3339 string | UTC で記録 |
| `event` | string | `PreToolUse` / `PostToolUse` 等 |
| `tool` | string | `tool_name` |
| `decision` | string | `allow` / `monitor` / `ask` / `deny` |
| `ruleId` | string \| null | 一致した rule。`allow` decision では省略 |
| `severity` | string \| null | `info` / `low` / `medium` / `high` / `critical` |
| `commandRedacted` | string | redaction 後の command 文字列 |
| `projectRoot` | string \| null | 検出された repo root |
| `mode` | string | その時点の `enforce` / `monitor` / `observe` |
| `modeDemoted` | bool | `true` のとき `mode: monitor` / `observe` で `deny` が `monitor` に降格された (フィールドは `false` のとき省略) |

将来追加し得るフィールド (v0.3 以降):

- `allowlistId` — allowlist 経由で allow になった場合の id
- `agent` — `claude-code` / `codex` 等の adapter 名
- `pluginVersions` — ロード済み plugin の `name@version` 配列

## 記録対象の制御

```yaml
audit:
  includeAllowed: false
  includeDenied: true
  redaction: strict
```

| キー | 既定 | 意味 |
| --- | --- | --- |
| `includeAllowed` | `false` | `allow` decision を記録するか |
| `includeDenied` | `true` | `deny` decision を記録するか |
| `redaction` | `strict` | redaction の積極度 |

`monitor` / `ask` は常に記録される。

## Redaction

`redaction: strict` (default) では以下を `***` 等に置換する。

- 環境変数代入のうち、key 名に `TOKEN` / `KEY` / `SECRET` / `PASSWORD` /
  `CREDENTIAL` / `PRIVATE` を含むものの value
- 一般的な token 形式 (例: `ghp_...`, `sk-...`, AWS access key の `AKIA...`、
  JWT の 3 セグメント)
- HTTP basic auth 形式 (`https://user:pass@host/...` の `pass` 部分)
- PEM ヘッダ (`-----BEGIN ... PRIVATE KEY-----`) を含む blob

`redaction: off` は明示的に選んだ場合のみ動作する。本番運用では使わない。

## ローテーション

ファイルサイズや日付ベースのローテーションは ptuf 自体では行わず、OS の
`logrotate` 等の外部ツールに任せる。stdout / stderr ではなくファイル書き込み
なので tee やパイプを挟む必要は無い。

## 閲覧

`ptuf audit` で audit log を tail し、`--rule`, `--decision`, `--since` 等で
フィルタする ([`cli-and-hooks.md`](cli-and-hooks.md))。
