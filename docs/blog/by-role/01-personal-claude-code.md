# Claude Code に ptuf を入れてみたら、うっかり `rm -rf` から救われた話

## どんな状況だったか

ひとり開発で Claude Code を回しています。普段はエージェントが書いたコマンドをそれなりに目視確認しているのですが、夜中に `make clean` 周りの整理を任せていたら、ふと「これ、もし変なパスに `rm -rf` を投げられたら気付ける自信ないな」と急に怖くなりました。

そこで `ptuf` を入れてみることにしました。`PreToolUse` フックでエージェントの実行を deterministic に止めてくれる Rust 製のガードレールツールです。

## 入れたコマンド

リポジトリをクローンして、いつもの `cargo install`。

```bash
cargo install --path .
ptuf init claude-code --dry-run
```

`--dry-run` で `~/.claude/settings.json` に書き込まれる差分を眺めて、問題なさそうだったので本番。

```bash
ptuf init claude-code
```

これだけで `~/.claude/settings.json` の `PreToolUse` に matcher `Bash|Read|Edit|Write|WebFetch|mcp__.*` のエントリが追加されます。既存設定はちゃんと残してくれるので、二回叩いても重複しません (idempotent) 。

## 実際に防がれたところ

そのまま `ptuf eval` でわざと危険なやつを投げて挙動確認。

```bash
ptuf eval --tool Bash 'rm -rf /'
```

stderr に「`core.filesystem.destructive-rm` が止めた」「rm の対象が `/` なので拒否」「対象パスを限定してから再試行してください」という主旨の理由が出て、exit code は `2`。Claude Code のフック契約だと、これで `permissionDecision: "deny"` が返り、エージェントは実行できずに別の手を考えるようになります。

`rm -rf ~` も同じ rule で止まるはず、と思って試したらやはり deny。これは `core.filesystem.destructive-rm` が `hardDeny: true` / severity `critical` なので、allowlist でも例外を作れない硬めの rule になっています。

## つまずいたところ

最初、シェルから `ptuf eval` を叩いたら何も止まらなくて「効いてない?」と焦ったのですが、よく見たら `rm -rf ./build` のような限定された削除でした。`core.filesystem.destructive-rm` が見ているのは `/`、`~`、リポジトリルート級の危険な再帰削除だけで、ローカル成果物の `rm` までは騒がない設計でした。`docs/design/policy-packs.md` に明記されています。

## 結論

ひとり開発でも、夜中に Claude Code に作業を投げて寝るような運用をしているなら、これは入れておいて損が無いと思いました。`ptuf init claude-code` の一発で済むので、導入コストは事実上ゼロでした。

## 関連

- [`docs/design/policy-packs.md`](../../design/policy-packs.md) — 既定で動く pack の一覧
- [`docs/design/cli-and-hooks.md`](../../design/cli-and-hooks.md) — `init` と hook の挙動
