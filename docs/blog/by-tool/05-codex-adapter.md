# Codex の `Ask` は `Deny` に化けるので、設計を読んでから配線した話

## なぜハマったか

Claude Code に慣れた状態で Codex を試したとき、最初に困惑したのが「**ユーザに聞かれずに deny される**」ことでした。Claude Code なら `Ask` で「これ実行していいですか?」と確認が出るような操作が、Codex だと問答無用で止まります。

これは ptuf の挙動でも、Codex の挙動でもなく、両者の **契約の差** が露出したものでした。原因と対処をまとめます。

## 何が起きているか

`docs/design/decision-model.md` の表が答えです。

| 条件 | Claude Code | Codex |
| --- | --- | --- |
| `Allow` | exit `0` | exit `0` |
| `Monitor` | exit `0` | exit `0` |
| `Ask` | exit `0` + hook response `ask` | adapter で `Deny` に変換され exit `2` |
| `Deny` | exit `2` | exit `2` |

Codex は `PreToolUse` の段階で **対話的に確認できない** ため、ptuf の Codex アダプタは `Ask` を一律 `Deny` に倒します。これは設計上の固定契約です。

## 影響を受けやすい rule

`core.git` の Ask 系がそのまま当たります (これも `docs/design/policy-packs.md` に列挙):

- `core.git.force-push-with-lease` (ask / high)
- `core.git.reset-hard` (ask / high)
- `core.git.clean-fdx` (ask / high)
- `core.git.branch-delete-force` (ask / high)
- `core.git.stash-clear` (ask / medium)
- `core.git.remote-set-url` (ask / medium)

Claude Code なら確認ダイアログ、Codex なら `Deny`。同じリポジトリで両方のエージェントを併用すると体感が違うので、把握しておかないと混乱します。

## 配線

```bash
ptuf init codex
```

これで repo 直下に:

- `<repo>/.codex/hooks.json` (matcher: `Bash|apply_patch|mcp__.*`、command: `ptuf hook codex`)
- `<repo>/.codex/config.toml` (`features.codex_hooks = true`)

が生成されます。Claude Code (`~/.claude/settings.json`) と違って **repo-local が既定** という点が最初の混乱ポイントなので、グローバル展開したい場合は `--root` や `--config` / `--hooks` で明示する必要があります。

## どう運用するか

私のチームで落ち着いた運用は:

1. Codex を使う repo では、`reset --hard` 系は `Deny` 前提で運用すると割り切る
2. どうしても許したいときは `git switch -c <branch>` してからやる、というワークフローに揃える
3. `ptuf eval --tool Bash 'git reset --hard HEAD~1'` で stderr の reason を読む癖をつける (`Ask` の reason はそのまま `Deny` reason として表示されます)

## つまずいたところ

`ptuf init codex` を `~/projects` のような上位で叩いて、Codex 側が拾わないところに `.codex/` ができていたことがありました。`init codex` は repo root の検出に失敗すると `--root` を要求するので、エラーが出たら横着せずに repo root を渡すのが結局はやい、という結論です。

## 関連

- [`docs/design/decision-model.md`](../../design/decision-model.md) — `Ask` 集約と Codex の `Ask→Deny`
- [`docs/design/cli-and-hooks.md`](../../design/cli-and-hooks.md) — Codex への登録契約
- [`docs/design/policy-packs.md`](../../design/policy-packs.md) — `core.git` の Ask 系 rule
