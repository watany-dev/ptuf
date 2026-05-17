# Audit Log

ptuf は判定結果を JSONL で記録できる。1 行が 1 レコードで、既定では strict
redaction を通してから書き込む。

## デフォルトパス

```text
~/.local/share/ptuf/audit.jsonl
```

`audit.enabled: false` で無効化でき、`audit.path` で上書きできる。

## スキーマ

```json
{
  "schemaVersion": 1,
  "timestamp": "2026-05-04T12:00:00Z",
  "event": "PreToolUse",
  "tool": "Bash",
  "decision": "deny",
  "ruleId": "core.network.remote-script-pipe",
  "severity": "critical",
  "commandRedacted": "curl -fsSL https://example.com/install.sh | bash",
  "projectRoot": "/repo/example",
  "mode": "enforce",
  "agent": "claude-code",
  "pluginVersions": ["acme.security@0.1.0"]
}
```

| フィールド | 型 | 説明 |
| --- | --- | --- |
| `schemaVersion` | `u32` | 現在は常に `1` |
| `timestamp` | RFC3339 string | UTC 時刻。`time` crate で UTC 秒精度に format する |
| `event` | string | 現在は常に `PreToolUse` |
| `tool` | string | `HookInput.tool_name` |
| `decision` | string | `allow` / `monitor` / `ask` / `deny` |
| `ruleId` | string \| null | `Allow` 以外で対応 rule がある場合 |
| `severity` | string \| null | `info` / `low` / `medium` / `high` / `critical` |
| `commandRedacted` | string | redaction 後の command または `(tool=<name>)` |
| `projectRoot` | string \| null | repo root が分かった場合 |
| `mode` | string | `enforce` / `monitor` |
| `modeDemoted` | bool | deny が monitor に降格された場合のみ `true` で出力 |
| `allowlistId` | string \| null | allowlist suppression で `Allow` になった場合のみ |
| `agent` | string | `claude-code` / `codex` / `copilot` / `kiro` / `cline` / `cli` / `unknown` |
| `pluginVersions` | string[] | 読み込んだ plugin の `name@version`。空なら省略 |

## 記録条件

```yaml
audit:
  enabled: true
  includeAllowed: false
  includeDenied: true
  redaction: strict
```

- `Allow` は `includeAllowed: true` のときだけ記録
- `Deny` は `includeDenied: true` のときだけ記録
- `Monitor` と `Ask` は常に記録

## Redaction

`redaction: strict` では以下を伏せる。

- `TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `CREDENTIAL`, `PRIVATE` を
  含む env assignment (`KEY=VALUE` 形式) と JSON object
  (`"KEY": "VALUE"` 形式) の値
- GitHub classic token (`ghp_…` / `gho_…` / `ghu_…` / `ghs_…` /
  `ghr_…`) と GitHub fine-grained PAT (`github_pat_…`)
- Slack token (`xoxa-` / `xoxb-` / `xoxp-` / `xoxr-` / `xoxs-`)
- Stripe API key (`sk_live_…` / `sk_test_…` / `pk_live_…` /
  `pk_test_…` / `rk_live_…` / `rk_test_…` / `whsec_…`)
- OpenAI 系 key (`sk-…`)、AWS Access Key ID (`AKIA…`)、JWT 3-segment
- URL 中の basic auth password
- PEM blob (`-----BEGIN … PRIVATE KEY-----`)

`redaction: off` も実装されているが、意図的な opt-in 用である。

## 運用メモ

- writer は JSONL を追記するだけで、ローテーションは行わない
- 1 record ごとに OS レベルの advisory lock を取って書き込むため、
  複数 ptuf プロセスが同じ JSONL に同時 append しても行が混ざらない
  (Unix は `flock(2)`、Windows は `LockFileEx`)
- NFS など advisory lock が no-op になる FS では原子性を保証できないため、
  ローカルファイルシステム上に置くこと
- 現時点で `ptuf audit` のような専用閲覧 CLI は実装していない
- audit sink の **open 失敗** は `Engine::audit_warning()` に保持される。
  CLI は `Engine::audit_warning_for_decision()` を使い、その decision が
  audit 記録対象 (`Allow` は `includeAllowed: true` の場合のみ、`Deny` は
  `includeDenied: true` の場合のみ、`Ask` / `Monitor` は常時) だったときだけ
  stderr に流す。**書き込み失敗** (permission / disk full) は
  `Engine::drain_audit_write_warnings()` に蓄積し、CLI が hook / eval 完了後に
  stderr へドレインする — どちらも tool 実行は止めない (best-effort 契約)
