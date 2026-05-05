# `ptuf init` を全社に配布した話 (Claude Code の hook をどう周知したか)

## 配布の前提

社内には Claude Code 利用者と Codex 利用者が混在していて、`ptuf` をどう配るのが楽かを 2 週間ほど試しました。要件はざっくり:

- ユーザは「コマンドを 1 行叩くだけ」で済ませたい
- 既存の `~/.claude/settings.json` を **絶対に壊さない**
- 二回叩いても安全 (idempotent)
- repo ごとの設定は repo 側で完結する

ptuf の `init` はこの要件にだいぶフィットしてくれました。

## Claude Code 側 — グローバル

`~/.claude/settings.json` はユーザグローバルなので、配布スクリプトはユーザに 1 回叩いてもらうだけです。

```bash
ptuf init claude-code
```

実装上の契約 (`docs/design/cli-and-hooks.md`):

- 既存 JSON の **未知キーは保持** する
- 既存 entry の検出は command 末尾 `hook claude-code` で行う
- binary の絶対パス差異は無視する
- 書き込みは temp file + rename の **原子的更新**

社内には `~/.claude/settings.json` を自前のフックで埋めている人が居たのですが、ptuf 側がコマンド末尾でエントリ同一判定をしてくれるので、binary を `/usr/local/bin/ptuf` から `~/.cargo/bin/ptuf` に変えても重複登録にはなりませんでした。

検証は `--dry-run` で。

```bash
ptuf init claude-code --dry-run
```

書き込み先を変えたい人 (個人で settings を分けている) には:

```bash
ptuf init claude-code --settings ~/.claude/settings.work.json
```

を案内しました。

## Codex 側 — repo-local

Codex は **repo-local が既定** という違いがあります。

```bash
ptuf init codex
```

これで `<repo>/.codex/hooks.json` と `<repo>/.codex/config.toml` が作られます。matcher は `Bash|apply_patch|mcp__.*`、`features.codex_hooks = true` も同時にセットされます。

社内の標準テンプレ repo に `.codex/` 込みでコミットしておけば、新規プロジェクトを作った人は意識せずに hook 配線が済みます。

`init codex` は repo root を見つけられないと `--root` か `--hooks` / `--config` を要求するので、CI からの非対話実行で repo root が曖昧なときは `--root` を渡すのが安全でした。

## 周知のしかた

社内 wiki に貼ったのは下の 4 行だけです。

```bash
cargo install --path .
ptuf init claude-code
# Codex を使う repo では各 repo で:
ptuf init codex
```

「壊れたら `--dry-run` で内容を見る」「二回叩いても安全」「対象パスを変えたければ `--settings` / `--root`」という説明を 1 段書いておけば、サポートに来る質問はだいぶ減りました。

## 配布後に効いたこと

- 新人さんが `Claude Code` を初日に触ったら、`rm -rf ~` で止まって「これ何ですか?」と聞きに来た。`stderr` の reason が読めるので、何が止めたかは説明しやすい
- 既存メンバーが個別に書いていた `pre-tool` 系の手書きフックと共存できた (未知キー保持のおかげ)
- Codex を使い始めた repo で `git reset --hard` が `Deny` されて驚かれた → これは Codex の `Ask→Deny` 仕様、と説明すれば納得

## つまずいたところ

- 一部メンバーが `~/.claude/settings.json` ではなく `~/.claude/settings.local.json` で運用していて、最初の `init` が空振り。`--settings` で対象を切り替えてもらいました
- Linux ビルドは `lld` が前提で、入っていないマシンで `cargo build` が落ちた。配布前に `make build` まで通る環境かを確認してもらうチェックリストを作りました

## 関連

- [`docs/design/cli-and-hooks.md`](../../design/cli-and-hooks.md) — Claude Code / Codex の登録契約
- [`README.md`](../../../README.md) — install と CLI の概要
