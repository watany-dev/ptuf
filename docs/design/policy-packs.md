# Policy Packs

ptuf は built-in pack を持つ。pack は config の `packs.<name>.enabled` で
まとめて ON/OFF できる。

| Pack | 既定 | 内容 |
| --- | --- | --- |
| `core.filesystem` | enabled | 破壊的 `rm` |
| `core.network` | enabled | remote script pipe |
| `core.secrets` | enabled | 機密 path の読取 / 外部送信 |
| `core.git` | enabled | 危険な git 操作と bypass |
| `core.self_protection` | enabled | ptuf 自身と hook 設定の保護 |
| `core.engine` | enabled | 動的コード評価 (`bash -c` / `eval` 等) の確認 |
| `core.injection` | enabled | 読み込むファイル中身の不可視文字インジェクション検査 |
| `core.project_hygiene` | disabled | lockfile / protected branch 規約 |
| `core.workspace` | disabled | workspace 外への Read/Write/redirect/MCP path |

## `core.filesystem`

| Rule id | Decision | hardDeny | severity |
| --- | --- | --- | --- |
| `core.filesystem.destructive-rm` | deny | true | critical |

現在は `rm -rf /`, `rm -rf ~`, repo root や親 directory への危険な再帰削除を
主対象にする。

## `core.network`

| Rule id | Decision | hardDeny | severity |
| --- | --- | --- | --- |
| `core.network.remote-script-pipe` | deny | true | critical |

現在の対象は remote script pipe に限定される。例:

- `curl ... | bash`
- `wget -qO- ... | sh`

## `core.secrets`

| Rule id | Decision | hardDeny | severity | 対象 |
| --- | --- | --- | --- | --- |
| `core.secrets.sensitive-path-to-network` | deny | true | critical | 同一 pipeline (segment) 上で機密 path 参照と network sink (`curl`/`wget`/`scp`/`rsync`/`nc` 等) が共存。pipeline の redirect 先が機密 path の場合も対象 |
| `core.secrets.sensitive-read` | deny | true | high | `Read` / `Edit` / `Write` / `apply_patch`、または path を持つ MCP tool で機密 path を直接対象にする |
| `core.secrets.sensitive-bash-read` | ask | false | high | Bash の reader head (`cat`/`head`/`tail`/`source`/`.`/`grep`/`awk`/`sed`/`dd` 等) または `<` redirect が機密 path を読む |

機密分類は `~/.ssh/**`, `~/.aws/**`, `~/.config/gcloud/**`, `~/.kube/config`,
`~/.docker/config.json`, `.env*`, `.npmrc`, `.pypirc`, `*.tfstate`, PEM blob など。
判定は case-insensitive で行うため `.ENV` / `.Ssh` / `.AWS` 等の大文字混じり
でも一致する (case-insensitive FS 上の bypass 対策)。`.env` 系の anchor には
`/`・空白に加えて glob meta (`*`, `?`, `[`, `]`) と `=` も含まれ、`cat *.env`、
`cp ?.env`、`dd if=.env`、`--env-file=.env` 等の literal token も検出する。

`sensitive-path-to-network` は segment (`;` / `&&` / `||` 区切り) ごとに判定する
ため `ls ~/.ssh; curl https://example.com` のように無関係な segment を並べた
shape では発火しない。一方 pipeline 内の redirect (`curl https://x > ~/.ssh/foo`
など) は同一 pipeline として扱う。`$(...)` を含む command は parser から body
が見えないため、従来どおり command-wide co-occurrence で pessimistic に判定
する (false positive を選ぶ既存方針)。`sensitive-bash-read` も同じ
pessimistic 戦略 + Ask 設計を採用するため、reader head が外側の argv に
出る限り (`cat $(echo .env)`) は捕捉し、外側が非 reader で内側に reader が
隠れる shape (`echo $(cat .env)`) は parser 制約により取り逃す既知の限界が
ある (ADR 0001)。`apply_patch` の patch body 内 PEM/credentials の内容
スキャンも本イテレーション範囲外。

`sensitive-bash-read` の reader head allowlist には `cat`/`head`/`tail`/
`less`/`more`/`view`/`bat`/`xxd`/`od`/`hexdump`/`strings`/`base64`/`base32`/
`grep`/`egrep`/`fgrep`/`awk`/`gawk`/`mawk`/`sed`/`cut`/`tr`/`sort`/`uniq`/
`wc`/`nl`/`tac`/`rev`/`column`/`file`/`dd`/`source`/`.` が含まれる。
`tee` は writer なので除外 (`cat foo | tee .env` の判定は前段の `cat` 側で
完結する)。書き込み系 redirect (`>`, `>>`, `2>`, `&>`) は `sensitive-read`
(Write tool 経由) の責務として本ルール対象外。Ask を採用しているため
`cat .env.example` 等の正当な使用も発火するが、`.ptuf.yaml` の
`overrides.allow` で project-local に suppress 可能 (Copilot adapter では
Ask が Deny に demote される既存挙動が適用される)。

## `core.git`

実装済み rule は 19 個。

| Rule id | Decision | hardDeny | severity |
| --- | --- | --- | --- |
| `core.git.force-push` | deny | true | critical |
| `core.git.force-push-with-lease` | ask | false | high |
| `core.git.reset-hard` | ask | false | high |
| `core.git.clean-fdx` | ask | false | high |
| `core.git.branch-delete-force` | ask | false | high |
| `core.git.stash-clear` | ask | false | medium |
| `core.git.remote-set-url` | ask | false | medium |
| `core.git.no-verify` | deny | false | high |
| `core.git.no-gpg-sign` | deny | false | medium |
| `core.git.config-override-bypass` | deny | false | high |
| `core.git.env-bypass` | deny | false | high |
| `core.git.push-mirror` | ask | false | high |
| `core.git.push-delete-remote` | ask | false | high |
| `core.git.force-if-includes` | ask | false | high |
| `core.git.update-ref-delete` | ask | false | high |
| `core.git.reflog-expire` | ask | false | high |
| `core.git.gc-prune-now` | ask | false | medium |
| `core.git.env-credential-hijack` | deny | false | high |
| `core.git.env-path-redirect` | deny | false | high |

hook / signing / fsck bypass を block する rule (`core.git.no-verify` /
`core.git.no-gpg-sign` / `core.git.config-override-bypass` /
`core.git.env-bypass`) と、credential / path redirection 系
(`core.git.env-credential-hijack` / `core.git.env-path-redirect`)
が 6 件。`sudo` 経由の git 実行も同じ matcher に通す。
`sudo -u root git ...` や `sudo --user=root git ...` のような
value-taking sudo option は、option 値を command head と誤認しないように
unwrap してから評価する。
`core.git.clean-fdx` は `git clean -fdx` だけでなく、`git clean -f -d -x` や
`git clean --force -d -x` のように分割された flag も検出する。`-n` dry-run は
発火しない。

`core.git.force-push` は `--force` / `-f` / `--force=*` に加えて、
`git push origin +main:main` のような `+refspec` 表記 (force push と
意味的に同一) も Critical / hardDeny で捕捉する。
`core.git.push-mirror` は `git push --mirror` を Ask する (全 ref を上書きする
ため事実上のリポジトリ全力 force push)。
`core.git.push-delete-remote` は `--delete` / `-d` フラグおよび
`git push origin :foo` 形式の colon-prefix 削除 refspec を Ask する。
`core.git.force-if-includes` は `--force-with-lease` と並ぶ新フラグで、
同等の force-push リスクを持つため Ask とする。
`core.git.update-ref-delete` は `git update-ref -d` / `--delete` で
低レベル ref 削除を Ask する。`--stdin` 経由のバッチ削除は本イテレーション
範囲外 (既知の取り逃し)。
`core.git.reflog-expire` は `git reflog delete <ref>` および
`git reflog expire` の `--expire=now` / `--expire=0` /
`--expire-unreachable=now` を Ask する。`git reflog show --all` 等の
read-only 操作は対象外。
`core.git.gc-prune-now` は `git gc --prune=now` / `--prune=all` を Ask する。
既定の `--prune=2.weeks.ago` 等の dated value は安全 (reflog grace window 内)
なので発火しない。
`core.git.env-credential-hijack` は `GIT_SSH_COMMAND` / `GIT_SSH` /
`GIT_ASKPASS` / `SSH_ASKPASS` を `push` / `pull` / `fetch` / `clone` /
`ls-remote` / `remote` の前に inline assign したケースを Deny する
(資格情報や transport を 1 回限り差し替える典型的な乗っ取りパス)。
`core.git.env-path-redirect` は `GIT_DIR` / `GIT_WORK_TREE` /
`GIT_OBJECT_DIRECTORY` / `GIT_INDEX_FILE` / `GIT_CONFIG{,_GLOBAL,_SYSTEM}` /
`GIT_ALTERNATE_OBJECT_DIRECTORIES` を任意の git subcommand 前に inline
assign したケースを Deny する (リポジトリ自体を別の場所に向け、project-local
guard / hook / 監査を 1 発で迂回する)。

## `core.self_protection`

実装済み rule は 8 個で、すべて `deny`, `hardDeny: true`, `severity: critical`。

| Rule id | 対象 |
| --- | --- |
| `core.self_protection.binary` | ptuf 実行ファイル |
| `core.self_protection.config` | config layer (`/etc`, `~/.config`, repo local) |
| `core.self_protection.plugin` | config で参照された plugin YAML |
| `core.self_protection.claude-settings` | `.claude/settings*.json` |
| `core.self_protection.codex-settings` | `.codex/config.toml`, `.codex/hooks.json` |
| `core.self_protection.copilot-settings` | `.github/hooks/ptuf.json` |
| `core.self_protection.kiro-settings` | `.kiro/agents/ptuf-guarded.json` |
| `core.self_protection.hook-script` | Claude / Codex / Copilot / Kiro / Cline の hook command が参照する実行ファイル |

## `core.engine`

| Rule id | Decision | hardDeny | severity | 対象 |
| --- | --- | --- | --- | --- |
| `core.engine.dynamic-eval` | ask | false | medium | `bash -c …` / `sh -c` / `python -c` / `node -e` / `perl -e` / `ruby -c\|-e` / `eval …` 等の 2 段階実行 |

shell wrapper (`bash -c`, `sh -c`, `eval`, `xargs`, `find -exec`) については、
bounded depth の再 parse により inner command と redirect が既存 rule
(`destructive-rm`, self-protection など) にも流れる。一方で `python -c`,
`node -e`, `perl -e`, `ruby -e` のような interpreter 組み込みコードは依然
opaque なので、`core.engine.dynamic-eval` が `Ask` を返してユーザに inner code
確認を求める。`sudo bash -c …` のような sudo 経由も unwrap して評価する。
`bash --login` や `python file.py` のような通常起動は発火しない。allowlist
(`overrides.allow` の glob) や `rule_overrides.disable` で project-local に
抑制できる。

## `core.injection`

| Rule id | Decision | hardDeny | severity | 対象 |
| --- | --- | --- | --- | --- |
| `core.injection.invisible-chars` | ask | false | high | `Read` / `Edit` / path を持つ MCP tool / Bash の reader head が読み込むファイルの中身に、人間のレビュアーには見えない文字が含まれる |

ptuf の他 rule は tool 入力 (path 文字列・コマンド文字列) を判定するが、
本 rule は唯一「対象ファイルを開いて中身を検査する」rule。レビュアーには
無害に見えるファイルに不可視文字を仕込み、agent の context にだけ隠れた
指示を流し込む間接プロンプトインジェクション (Trojan Source / ASCII
smuggling) を検出する。検出カテゴリは 5 種:

- **zero-width / 不可視 Unicode** — ZWSP (U+200B), ZWNJ, ZWJ, WORD
  JOINER, 不可視数学演算子 (U+2061–2064), SOFT HYPHEN, COMBINING
  GRAPHEME JOINER (U+034F), HANGUL filler 等。先頭の U+FEFF は正規の
  BOM として除外する
- **BiDi 制御文字** — U+202A–202E / U+2066–2069 の override / isolate と
  方向マーク LRM / RLM / ALM (U+200E / U+200F / U+061C) (Trojan Source)
- **Unicode Tag 文字** — U+E0000–E007F (ASCII smuggling)
- **variation selector** — Variation Selectors Supplement
  (U+E0100–E01EF) (data smuggling)。標準の U+FE00–FE0F は絵文字異体字で
  多用されるため意図的に検出対象外
- **C0/C1 制御文字** — TAB / LF / CR と NUL を除く制御バイト

I/O は best-effort で fail-open する。ファイル欠如・権限エラー・非通常
ファイル (ディレクトリ / FIFO / デバイス)・バイナリ (NUL バイトまたは
denylist 拡張子)・非 UTF-8 はすべて `None` (素通り) になる。巨大ファイルは
先頭 1 MiB のみ scan する。`Write` / `apply_patch` は agent 自身が書く
内容のため対象外。Bash は reader head (`cat` / `head` 等) の positional
引数のみを対象とする。allowlist は `sensitive-bash-read` と共通だが、
hex ダンプ系 (`xxd` / `od` / `hexdump`) は隠し文字を可視化するため対象から
除外する。`< file` redirect 経由は本イテレーション範囲外。

Ask 採用のため soft hyphen 等を含む正当なファイルでも発火しうるが、
`.ptuf.yaml` の `overrides.allow` で project-local に suppress できる。

## `core.project_hygiene`

この pack は default で無効。`packs.core.project_hygiene.enabled: true` で有効化する。

| Rule id | Decision | hardDeny | severity | 対象 |
| --- | --- | --- | --- | --- |
| `core.project_hygiene.lock-mismatch-pnpm` | deny | false | high | `pnpm-lock.yaml` がある repo で `npm` / `yarn` install 系 |
| `core.project_hygiene.lock-mismatch-uv` | deny | false | high | `uv.lock` がある repo で素の `pip install` |
| `core.project_hygiene.protected-branch-destructive-git` | deny | false | high | protected branch 上で `git reset --hard`, `git clean -fdx` / `git clean -f -d -x`, `git branch -D`, `git stash clear` |

`protected-branch-destructive-git` は aggregate の優先順位により、同操作に対する
`core.git.*` の `Ask` を `Deny` で上書きする。

protected branch の既定値は:

```yaml
packs:
  core.project_hygiene:
    protectedBranches:
      - main
      - master
      - release/*
```

## `core.workspace`

この pack は default で無効。`packs.core.workspace.enabled: true` で有効化する。
Read も対象になるため、有効化すると外部 lib (`~/.cargo/registry/...`,
`/usr/include/...` など) の参照が default で deny される点に注意する。

| Rule id | Decision | hardDeny | severity | 対象 |
| --- | --- | --- | --- | --- |
| `core.workspace.outside-access` | deny | false | medium | tool 入力 (`Read`/`Edit`/`Write`/`apply_patch`/MCP `path`) と Bash redirect target が workspace 境界の外を指す場合 |

境界は engine の `repo_root` (`.git` 探索結果) と
`packs.core.workspace.additionalWorkspaces` の和集合。両方とも未設定なら
ルールはスキップ (`None` を返す)。境界・候補とも `canonicalize` で
symlink を解決してから component 単位で `starts_with` 判定するため、
`/work-evil` のような lookalike prefix では誤マッチしない。存在しない
descendant については祖先まで遡って canonicalize し、`..` を自前で
解決した正規化形を判定対象とする。

```yaml
packs:
  core.workspace:
    enabled: true
    additionalWorkspaces:
      - ~/work/notes
      - /opt/shared/scratch
```

UX 上の摩擦を緩和したい場合は `allowlists` で対象パスを限定的に許可
できる:

```yaml
allowlists:
  - id: tmp-build-ok
    appliesTo:
      rules: [core.workspace.outside-access]
    when:
      path.absolute:
        startsWith: /tmp/build-
    reason: ビルドキャッシュは workspace 外 OK
```
