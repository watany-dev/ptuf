# `audit.jsonl` と `ptuf doctor --json` でガードを「運用」に乗せた話

## 入れた後の話

`ptuf init claude-code` でガードが効くようになって一安心、と言いたいところですが、実際には入れたあとに「どれくらい止まっているか」「設定はちゃんと読まれているか」を継続的に見たくなりました。これを片付けてくれたのが `audit.jsonl` と `ptuf doctor --json` の 2 つです。

## audit.jsonl の有効化

`~/.config/ptuf/config.yaml` に audit セクションを足します。

```yaml
audit:
  enabled: true
  path: ~/.local/share/ptuf/audit.jsonl
  includeAllowed: false
  includeDenied: true
  redaction: strict
```

`Allow` と `Deny` の記録は opt-in、`Monitor` と `Ask` は **常に記録** されます (`docs/design/audit.md`)。ノイズが多くなりやすい `Allow` を切って、`Deny` だけ残すのが運用しやすかったです。

## 1 行の中身

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

運用してみて重宝したフィールドは:

- `ruleId` × `decision` で「最近どの rule が一番引っかかっているか」をすぐ集計できる
- `agent` で Claude Code / Codex / `cli` / `unknown` を分けて見られる
- `pluginVersions` で「どの版のプラグインが効いていたか」が事後に分かる
- `allowlistId` は allowlist で suppression された Allow のときだけ出るので、例外運用の追跡に使える
- `modeDemoted` は `Deny` が `Monitor` に降格されたときだけ出る (mode を `monitor` に倒した移行期に重要)

## redaction の安心感

`redaction: strict` は env assignment の `TOKEN`/`KEY`/`SECRET`/`PASSWORD` の値、`ghp_...` / `sk-...` / `AKIA...` / JWT、URL の basic auth、PEM blob を伏せて記録します。`commandRedacted` の中身を社内のセキュリティチームに見せても二次インシデントになりにくい、というのが導入理由のひとつでした。

## ローテーションは別途

writer は単純に追記するだけで、ローテーションは行いません (POSIX `O_APPEND` 相当で書く)。私のところは `logrotate` の copytruncate で日次ローテにしました。Windows の場合は best-effort の追記なので、別途運用配慮が必要です。

## 集計の例

`jq` で「直近で deny が多かった rule」を雑に出すなら:

```bash
jq -r 'select(.decision=="deny") | .ruleId' ~/.local/share/ptuf/audit.jsonl \
  | sort | uniq -c | sort -nr | head
```

これで「みんな `core.network.remote-script-pipe` でよく止まってる」とか「`core.git.no-verify` が思ったより出てる」みたいな傾向が見えます。

## ptuf doctor で土台を確認

audit を見る前に、そもそも設定が読まれているかを確認したいことが多いです。

```bash
ptuf doctor
ptuf doctor --json
```

`doctor` は次を診断します (`docs/design/cli-and-hooks.md`):

- 実行中 binary
- repo root
- config layer の有無
- 読み込んだ plugin
- Claude Code integration
- Codex integration

text 版はセクションごとに `✓`, `⚠`, `✗` を出して、`✗` がひとつでもあれば exit `1`。`--json` 版はそのまま CI に食わせる用途です。私のところでは社内の health check スクリプトから `ptuf doctor --json` を叩いて、`✗` を検知したら Slack 通知、というのを入れています。

## 運用してみての所感

- `audit.jsonl` が JSONL なので、好きな集計手段に流せる (Splunk でも Loki でも `jq` でも)
- `pluginVersions` のおかげで、社内プラグインを更新したときに「実際にどの版が走ったか」を後から追える
- `doctor` は新人セットアップ後の確認にも刺さる。「`Claude Code integration: ✓`」が出ているかを最初に見てもらうだけで、サポート工数がだいぶ減った

`ptuf` は入れて終わりではなく、`audit` で振り返り、`doctor` で土台を確認する、という運用ループに乗せると価値が安定します。

## 関連

- [`docs/design/audit.md`](../../design/audit.md) — JSONL の schema 全項目
- [`docs/design/cli-and-hooks.md`](../../design/cli-and-hooks.md) — `ptuf doctor` の確認対象
- [`docs/design/decision-model.md`](../../design/decision-model.md) — `mode` と `modeDemoted`
