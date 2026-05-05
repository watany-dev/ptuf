# `git reset --hard origin/main` で泣いた朝、ptuf を入れ直した話

## 何が起きたか

ある朝、エージェントに「コンフリクトを解消して」とだけ指示を投げて席を立ってしまいました。戻ってきたら `feature/x` ブランチで作業中の自分のローカルコミット 6 件が消えていて、状態を見たら `git reset --hard origin/main` が走っていました。エージェント的には「リモートと揃えれば conflict は解消する」という、間違ってはいないけれど人間が選ばない解だった訳です。

`git reflog` で泣きながら救い出したあと、その日のうちに `ptuf` を入れ直しました。

## 何を入れたか

```bash
ptuf init claude-code
```

これで built-in pack のうち `core.git` が default で効きます。実装済みは 11 rule、私が今回助けて欲しかったのはこのあたりです (`docs/design/policy-packs.md`)。

| rule | decision | severity |
| --- | --- | --- |
| `core.git.force-push` | deny / hardDeny | critical |
| `core.git.force-push-with-lease` | ask | high |
| `core.git.reset-hard` | ask | high |
| `core.git.clean-fdx` | ask | high |
| `core.git.no-verify` | deny | high |
| `core.git.no-gpg-sign` | deny | medium |
| `core.git.config-override-bypass` | deny | high |
| `core.git.env-bypass` | deny | high |

`reset --hard` は default `Ask` なので、Claude Code なら「実行していいか」聞かれて、私が「ダメ」と言えていれば防げた話でした。

## bypass 系は容赦しない

地味に効いたのは末尾 4 つの bypass 系です。たとえばエージェントが「pre-commit を回避するために `--no-verify` 付ければいいだろう」と判断する展開はあり得ますが、`core.git.no-verify` は default `Deny`。同様に `--no-gpg-sign` や `-c hooks.bypass=...`、`GIT_*` 系の bypass env を使った迂回も止まります。

「ガードレールを回避する方向に考えが流れたコマンド」にちゃんとツッコミが入る、というのが導入してみての一番の安心材料でした。

## protected branch ならさらに固められる

`main` 上での `git reset --hard` は、`core.project_hygiene` を有効にすると `Ask` から `Deny` に上書きされます。aggregate 規則 `deny > ask > monitor > allow` で、protected pack の方が勝つ仕組みです。

```yaml
packs:
  core.project_hygiene:
    enabled: true
    protectedBranches:
      - main
      - master
      - release/*
```

今回の事故は feature ブランチ上だったので protected pack では救えませんでしたが、`main` で同じ事故を起こすルートはこれで塞がります。

## fail-closed の話

`ptuf` の CLI は、policy load に失敗したらそれだけで `core.engine.policy-load-failed` で deny します。これは `failClosed: false` でも変わりません (`docs/design/decision-model.md`)。「設定ファイルが壊れてるからフィルタ無し」みたいな静かな fail-open は起きないので、運用的にも信用しやすかったです。

## 教訓

- 失敗しないと真面目に入れない、というアンチパターンを地で行ってしまった
- `core.git` だけでもエージェントの危なっかしい判断のかなりを抑止できる
- bypass 系まで先回りして塞がっているのが、思っていたより助かった

## 関連

- [`docs/design/policy-packs.md`](../../design/policy-packs.md) — `core.git` の rule 一覧
- [`docs/design/decision-model.md`](../../design/decision-model.md) — `failClosed` と CLI の挙動差
