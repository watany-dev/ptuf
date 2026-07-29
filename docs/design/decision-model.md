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

| 条件 | Claude Code | Codex | GitHub Copilot | Kiro | Cline | Cursor | Pi |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Allow` | exit `0` | exit `0` | exit `0`、stdout 空 | exit `0` | exit `0`、stdout `{}` | exit `0`、bare `permission:allow` JSON | exit `0`、bare `decision:allow` JSON |
| `Monitor` | exit `0` | exit `0` | exit `0`、stdout 空 | exit `0` | exit `0`、stdout `{}` | exit `0`、bare `permission:allow` JSON | exit `0`、bare `decision:monitor` JSON |
| `Ask` | exit `0` + hook response `ask` | adapter で `Deny` に変換され exit `2` | adapter で `Deny` に変換、bare JSON envelope を stdout、exit `0` | adapter で `Deny` に変換され exit `2` (stderr のみ) | adapter で `Deny` に変換、cancel JSON を stdout、exit `0` | exit `0`、bare `permission:ask` JSON (**降格しない**) | exit `0`、bare `decision:ask` JSON (**降格しない**) |
| `Deny` | exit `2` | exit `2` | bare JSON envelope を stdout、exit `0` | exit `2` (stderr のみ) | cancel JSON を stdout、exit `0` | exit `2`、bare `permission:deny` JSON | exit `2`、bare `decision:deny` JSON |

`Ask` / `Deny` は reason を stderr にも書く。GitHub Copilot は preToolUse
hook の非ゼロ exit を hook 失敗として扱うため、`Deny` / `Ask` でも exit
code は `0` のままで、判定は stdout の bare JSON envelope
(`hookSpecificOutput` ラッパなし) で伝える。fail-closed 経路
(`core.engine.invalid-payload` / `core.engine.policy-load-failed`) も同じ
contract に従う。Kiro は JSON envelope を持たないため stderr のみで通知する。
Cline も file hook の非ゼロ exit を hook 失敗扱いにするため、`Deny` / `Ask`
でも exit code は `0` のままで、判定は stdout の cancel JSON envelope
(`{"cancel":true,"errorMessage":"…"}`) で伝える。`Allow` / `Monitor` でも
stdout に `{}` を出し、`shouldContinue` は一切出さない。

## mode

| mode | 挙動 |
| --- | --- |
| `enforce` | `Deny` をそのまま block する |
| `monitor` | `hardDeny` 以外の `Deny` を `Monitor` に降格する |

`hardDeny: true` の rule が `Deny` を返した場合は mode に関わらず `Deny` のまま
block する。repository 側の `.ptuf.yaml` で `mode: monitor` を指定しても、
`destructive-rm` や `remote-script-pipe` などの critical rule は弱化できない。

降格前の結果が `Deny` で、mode によって `Monitor` へ変わった場合は
`Outcome.mode_demoted = true` となり、audit の `modeDemoted` にも反映される。

## readonly ゲート

`Config.readonly: bool` は `mode` と直交する強制読み取り専用軸
([ADR 0009](../adr/0009-readonly-mode-2026-07.md))。

- `demote_for_mode` の**後**に合成する。既存の具体 `Deny` があればその
  rule id を優先し、そうでなければ `core.readonly.{file,bash,mcp}-write`
  が Deny を返す
- pack disable / rule override / allowlist は rule ループ外のため到達不能
- `mode: monitor` でも readonly Deny は降格しない (`core.readonly.` は
  hardDeny 相当)
- `Outcome.readonly` / audit の `readonly` に実効値を載せる

## fail-closed の境界

- CLI (`hook`, `eval`) は policy load に失敗すると
  `core.engine.policy-load-failed` で deny する
- `hook` は stdin 読み取り失敗 / 8 MiB 超過 / JSON parse 失敗を
  `core.engine.invalid-payload` で deny する (Claude Code は exit 1 を
  non-blocking warning と解釈するため deny + exit 2 が必須。GitHub Copilot
  と Cline は逆に非ゼロ exit を hook 失敗扱いにするため deny + exit `0` +
  stdout に JSON envelope (Copilot は bare、Cline は cancel) で伝える)
- これらは `failClosed: false` でも変わらない
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
