# チームリードとして、Codex 導入前夜に protected branch を固めた話

## 状況

うちのチームでは Claude Code に加えて Codex も並行で試すことになりました。エージェントが多様化するのは歓迎なのですが、リードとして気になっていたのは「`main` で `git reset --hard` をされてしまったら、PR 駆動の運用が一発で破綻する」点です。

そこで Codex を配る前に、`ptuf` の `core.project_hygiene` パックで保護ブランチ用の deny を効かせてからにしました。

## やったこと

リポジトリのルートで:

```bash
ptuf init codex
```

これで `<repo>/.codex/hooks.json` と `<repo>/.codex/config.toml` が生成されます。`hooks.json` の matcher は `Bash|apply_patch|mcp__.*`、コマンドは `ptuf hook codex` です。

次に同じリポジトリの `.ptuf.yaml` で `core.project_hygiene` を有効化します。

```yaml
version: 1

packs:
  core.project_hygiene:
    enabled: true
    protectedBranches:
      - main
      - master
      - release/*
```

`core.project_hygiene` は default で **無効** なので、明示的に `enabled: true` が要ります。ここを忘れると保護ブランチの追加 deny は効きません。

## 何が変わったか

`main` ブランチに居る状態で Codex に「失敗したコミットを巻き戻して」と頼むと、内部的にエージェントが叩こうとした `git reset --hard HEAD~1` は `core.project_hygiene.protected-branch-destructive-git` に止められます。

ここがポイントで、同じコマンドは built-in の `core.git.reset-hard` だと **`Ask`** 扱いです。Claude Code ならユーザに確認を求めるところですが、Codex は `PreToolUse` で対話できないため、アダプタ層で `Ask` を一律 `Deny` に変換します。さらに今回は `protected-branch-destructive-git` (default `Deny`) が aggregate の優先順位で上書きするので、結果として stderr に「保護ブランチ上での破壊的 git 操作なので拒否、ブランチを切り直して下さい」という主旨の reason が出て、exit `2` で止まります。

```text
deny > ask > monitor > allow
```

この aggregate ルールは `docs/design/decision-model.md` に書かれていますが、実物で挙動を確認すると安心感が違いました。

## つまずいたところ

最初に `ptuf init codex` を repo の外で叩いてしまい、`--root` も無いのでエラーになりました。Codex のインストール先は **repo-local が既定** なので、`<repo>` か `--root <PATH>` を必ず合わせる必要があります。逆に Claude Code 側 (`~/.claude/settings.json`) はユーザグローバルなので、ここの設計差は最初に頭に入れておくと迷いません。

## 結論

`core.project_hygiene` を有効にしてから配ると、Codex 経由のエージェントが保護ブランチを傷付ける経路がほぼ閉じます。`pnpm-lock.yaml` がある repo で `npm install` を叩く問題 (`lock-mismatch-pnpm`) もこの pack の中で塞げるので、フロントエンド寄りのリポジトリには特に効くと思います。

## 関連

- [`docs/design/policy-packs.md`](../../design/policy-packs.md) — `core.project_hygiene` の rule 表
- [`docs/design/decision-model.md`](../../design/decision-model.md) — `Ask` の集約と Codex の `Ask→Deny` 変換
- [`docs/design/cli-and-hooks.md`](../../design/cli-and-hooks.md) — `init codex` の生成物
