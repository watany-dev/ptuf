# Decision Model

ptuf の判定結果は 4 種類。複数 rule が同じ event に一致した場合は、もっとも
制限的な decision を採用する。security rule は user / local config から弱め
られないようロックできる。

## 4 種類の Decision

| Decision | 意味 |
| --- | --- |
| `allow` | 実行許可。何も追加しない |
| `monitor` | 実行許可するが audit log に記録する |
| `ask` | エージェントを止め、ユーザの確認に昇格する |
| `deny` | 実行拒否。理由を返す |

CLI の exit code との対応は次の通り。

| Decision | exit code | stderr | 補足 |
| --- | --- | --- | --- |
| `allow` | `0` | (空) | |
| `monitor` | `0` | (空) | audit log にのみ記録 |
| `ask` | `0` | reason | hook response 経由でユーザ確認に昇格 |
| `deny` | `2` | reason | |

> v0.1 時点で `Decision` は 4 variants (`Allow`, `Monitor { rule_id }`,
> `Ask { rule_id, reason }`, `Deny { rule_id, reason }`) を実装済み。
> ただし組み込み 3 rule (`core.filesystem.destructive-rm` /
> `core.network.remote-script-pipe` /
> `core.secrets.sensitive-path-to-network`) はすべて `deny` を返すため、
> `monitor` / `ask` は実利用としては v0.2 (config scope と plugin pack 導入)
> 以降に登場する ([`roadmap.md`](roadmap.md))。

## 集約規則

複数 rule が一致した場合の優先順位:

```
deny > ask > monitor > allow
```

つまり、いずれかの rule が `deny` を返したら他の `allow` は無視され、
`deny` が無く `ask` があれば `ask`、それも無ければ `monitor`、と段階的に下る。

## hardDeny / overridable

security pack の rule は user / local config による弱化を防げるよう、
2 種類のロック手段を持つ。

- `hardDeny: true` — 上位 scope で deny を宣言した場合、下位 scope の allowlist
  / 個別 rule disable で覆せない
- `overridable: false` — その rule の `defaultDecision` を下位 scope から
  変更できない

両者は `core.network.remote-script-pipe` のような重要 rule に default 適用する。
通常の project hygiene rule など、上書きを許す rule は `overridable: true`
(default) のままにする。

scope の順序とマージ規則は [`config-and-plugins.md`](config-and-plugins.md) を
参照。

> v0.1 時点では config merge 機構が未実装のため、`Rule` trait に
> `overridable()` / `hard_deny()` 属性は持たせていない。組み込み 3 rule は
> 実質 `hardDeny: true` 相当 (無条件 deny) として動く。これらの属性は
> v0.2 で config scope の実装と同時に導入する。

## モード

`mode` で全体の振る舞いを切り替える。

| mode | 振る舞い |
| --- | --- |
| `enforce` | rule が `deny` ならツール実行を止める。`failClosed: true` で policy 読込失敗時も deny |
| `monitor` | すべての `deny` を `monitor` に降格して記録だけ取る。導入直後の dry-run 用途 |

`failClosed` を `false` にすると `enforce` モードでも policy 読込失敗時に
`allow` を返すが、本番では推奨しない。

## Rule Feedback (deny 理由の規約)

`deny` / `ask` の reason は、エージェントが次に何をすべきか分かる形式に揃える。
最低限以下を含める。

1. **どの rule が止めたか** — `Blocked by ptuf rule <id>.`
2. **何が問題か** — 1〜2 文で具体的に
3. **どう直すべきか** — 箇条書きで実行可能な代替案

例:

```
Blocked by ptuf rule core.network.remote-script-pipe.

The command downloads a remote script and pipes it directly into bash.
This is not allowed because the script would execute before it can be inspected.

Safer alternative:
1. Download the script to a temporary file.
2. Show the URL and file summary.
3. Ask the user before executing it.
```

エージェントへの返却 JSON では `permissionDecision` と
`permissionDecisionReason` に分けて返す。詳細フォーマットは
[`cli-and-hooks.md`](cli-and-hooks.md) を参照。
