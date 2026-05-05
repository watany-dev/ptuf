# ptuf ユーザー目線の体験記事

`ptuf` を実際に使ってみた人の視点で書いた、Zenn / Qiita 風の体験記事を集めたディレクトリです。仕様の正典は `docs/design/` 以下、CLI の総覧は `README.md` を参照してください。ここではあくまで「使ってみてどうだったか」を、3 つの軸から計 9 本でまとめます。

## 軸別の目次

### 役割別 (`by-role/`)

- [01 個人開発者がうっかり `rm -rf` から救われた話](by-role/01-personal-claude-code.md)
- [02 チームリードとして Codex 導入前夜に protected branch を固めた話](by-role/02-team-lead-codex.md)
- [03 セキュリティエンジニアとして `.env` と `~/.aws/` の流出経路を塞いだ話](by-role/03-security-engineer.md)

### ツール別 (`by-tool/`)

- [04 `ptuf init claude-code --dry-run` から始める安心ハンズオン](by-tool/04-claude-code-deepdive.md)
- [05 Codex の `Ask` は `Deny` に化けるので、設計を読んでから配線した話](by-tool/05-codex-adapter.md)
- [06 社内固有ルールを YAML プラグインに切り出した話](by-tool/06-plugin-author.md)

### フェーズ別 (`by-phase/`)

- [07 `git reset --hard origin/main` で泣いた朝、ptuf を入れ直した話](by-phase/07-rm-rf-failure.md)
- [08 `ptuf init` を全社に配布した話](by-phase/08-rollout.md)
- [09 `audit.jsonl` と `ptuf doctor --json` でガードを「運用」に乗せた話](by-phase/09-operations-audit.md)

## どこから読むか

- まず雰囲気を掴みたい → 01
- チーム導入を検討中 → 02 / 08
- セキュリティ観点を確認したい → 03 / 09
- 実装契約を抑えたい → 04 / 05
- 自分でルールを書きたい → 06
- 失敗例から入りたい → 07
