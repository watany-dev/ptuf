# Decision Model

ptuf の判定結果は `Decision` で表現する。複数 rule が一致した場合は、より制限的な
ものを採用する。

## Decision 種別

| Decision | 意味 |
| --- | --- |
| `allow` | 実行許可 |
| `monitor` | 実行許可しつつ audit に残す |
| `ask` | ユーザ確認へ昇格させる |
| `deny` | 実行拒否する |

Rust の公開 enum:

- `Decision::Allow`
- `Decision::Monitor { rule_id }`
- `Decision::Ask { rule_id, reason }`
- `Decision::Deny { rule_id, reason }`

## 集約規則

優先順位は固定で:

```text
deny > ask > monitor > allow
```

`aggregate([])` は `Allow`。

## CLI / hook との対応

| 条件 | Claude Code | Codex |
| --- | --- | --- |
| `Allow` | exit `0` | exit `0` |
| `Monitor` | exit `0` | exit `0` |
| `Ask` | exit `0` + hook response `ask` | adapter で `Deny` に変換され exit `2` |
| `Deny` | exit `2` | exit `2` |

`Ask` / `Deny` は reason を stderr にも書く。

## mode

| mode | 挙動 |
| --- | --- |
| `enforce` | `Deny` をそのまま block する |
| `monitor` | `Deny` を `Monitor` に降格する |
| `observe` | 現状は `monitor` と同じく `Deny` を `Monitor` に降格する |

降格前の結果が `Deny` で、mode によって `Monitor` へ変わった場合は
`Outcome.mode_demoted = true` となり、audit の `modeDemoted` にも反映される。

## fail-closed の境界

- CLI (`hook`, `eval`) は policy load に失敗すると
  `core.engine.policy-load-failed` で deny する
- これは `failClosed: false` でも変わらない
- ライブラリ API `decide()` は後方互換のため default engine にフォールバックする

`failClosed` は runtime 中の policy 評価の意図を表す設定であり、CLI 初期化の
成否までは緩めない。

## hardDeny / overridable

各 rule は 2 種類のロック属性を持てる。

- `hardDeny: true`
  - allowlist で suppression できない
  - 個別 disable による弱化も許さない
- `overridable: false`
  - 下位 scope から `decision` / `severity` を変えられない

具体的な対象は [`policy-packs.md`](policy-packs.md) の各表に従う。

## reason の規約

`Ask` / `Deny` の reason は、次を含む実行可能な文章に揃える。

1. どの rule が止めたか
2. 何が問題か
3. どう直すか

実装では `reason::build()` がこの書式を組み立てる。
