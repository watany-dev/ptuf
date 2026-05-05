# Policy Packs

ptuf は default で 6 つの built-in pack を提供する。各 pack は独立に
有効化/無効化でき、user / project config から個別 rule の severity や
decision を上書きできる (rule が `overridable: false` でない限り)。
有効化方法は [`config-and-plugins.md`](config-and-plugins.md) を参照。

| Pack | default | 守備範囲 |
| --- | --- | --- |
| `core.network` | enabled | 外部送信・remote script・cloud metadata |
| `core.secrets` | enabled | 認証情報ファイルの読取と外部送信 |
| `core.filesystem` | enabled | 破壊的 fs 操作 |
| `core.git` | enabled | 危険な git 操作 |
| `core.self_protection` | enabled | ptuf 自身と hook 設定の保護 |
| `core.project_hygiene` | optional | プロジェクト規約違反 |

## `core.network`

Network 経路の情報漏洩と remote code execution を防ぐ。

**止めるもの:**

- `curl https://... | bash`
- `wget -qO- https://... | sh`
- remote script を interpreter (sh / bash / zsh / fish / python / ruby / node 等)
  に直接流す command
- sensitive file から network sink (`curl`, `wget`, `nc`, `scp`, `rsync` 等)
  への dataflow
- cloud metadata endpoint (`169.254.169.254`, `metadata.google.internal` 等)
  へのアクセス
- unknown domain への POST / upload

**許すもの:**

- public docs / API への read-only GET
- `localhost` / `127.0.0.1` / `::1` への dev 用アクセス
- 公式パッケージマネージャや CLI の通常通信 (allowlist で host を限定)

## `core.secrets`

認証情報・秘密鍵を保護する。

**保護対象パス:**

```
~/.ssh/**
~/.aws/**
~/.config/gcloud/**
~/.kube/config
~/.docker/config.json
**/.env
**/.env.*
**/.npmrc
**/.pypirc
**/*.tfstate
private key らしきファイル (PEM ヘッダ等で判別)
```

**止めるもの:**

- `Read` tool による sensitive file の直接読取
- `cat ~/.aws/credentials` のような shell 経由の閲覧
- `tar czf secrets.tgz ~/.ssh` のようなアーカイブ化
- `base64 ~/.ssh/id_ed25519` のようなエンコード経由読取
- sensitive file を `curl`, `wget`, `nc`, `scp`, `rsync` 等の network sink へ
  流す操作 (dataflow facts で検出)

## `core.filesystem`

不可逆な破壊的操作を防ぐ。

**止めるもの:**

- `rm -rf /`
- `rm -rf ~`
- repo root での `rm -rf .`
- repo root / parent directory の再帰削除
- system path (`/etc`, `/usr`, `/var` 等) への destructive write
- system / home / repo root 配下への再帰 `chmod` / `chown`
- block device への `dd`
- `mkfs`、partition 操作

## `core.git`

危険な git 操作の default decision を以下に固定する (v0.3 で 7 rule、追加 4 rule で計 11 rule)。

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

protected branch (`main`, `master`, `release/*` 等、project facts で定義) では
v0.4 で `core.project_hygiene.protected-branch-destructive-git` がこれらの
`ask` を `deny` に昇格させる (本書下部の `core.project_hygiene` を参照)。

末尾 4 rule は「git の品質ゲートを意図的に skip する操作」を `deny` する
(`hardDeny: false`, `overridable: true`)。CI hot-fix など正当な必要性がある場合は
project / user の `allowlists` で expiry 付きに通す。`git status -c
core.hooksPath=/dev/null` のように副作用ない呼び出しは誤検出回避で見逃す。
scope は rule ごとに副作用 subcommand に絞っている:

- `no-verify`: `commit / push / merge / rebase / pull / am / cherry-pick / revert / fetch`
- `no-gpg-sign`: `commit / merge / rebase / cherry-pick / revert / tag / am / pull`
- `config-override-bypass` / `env-bypass`: `commit / push / merge / rebase / tag /
  am / cherry-pick / revert / pull`

`-n` の解釈は subcommand 依存 — `git push -n` (= `--dry-run`) や `git tag -n`
(= 行数指定) は無害なので発火しない。bash パーサが command substitution / 変数展開
を解釈しない (`docs/design/architecture.md` §fact extraction 準拠) ため、
`` git -c `echo core.hooksPath=/dev/null` commit `` のような文字列構築での隠蔽、
および `export HUSKY=0; git commit` のような別 segment での env 立ては MVP では
検出不能 (既知の限界)。

## `core.self_protection`

prompt injection 等で agent が guardrail 自体を無効化することを防ぐ
(v0.3 で 5 rule とも実装済み、すべて `hardDeny: true` / `severity: critical`)。

| Rule id | 止めるもの |
| --- | --- |
| `core.self_protection.binary` | ptuf 実行ファイルの改変 (`current_exe()` で判定) |
| `core.self_protection.config` | `.ptuf.yaml` / `.ptuf.local.yaml` / `~/.config/ptuf/config.yaml` / `/etc/ptuf/policy.yaml` |
| `core.self_protection.plugin` | config で参照されている plugin YAML |
| `core.self_protection.claude-settings` | `.claude/settings.json` / `.claude/settings.local.json` / `~/.claude/settings.json` |
| `core.self_protection.hook-script` | `~/.claude/settings.json` の `command` で参照される実行可能ファイル |

これらの rule は `hardDeny: true` のため下位 scope の allowlist で解除できない
([`decision-model.md`](decision-model.md))。

## `core.secrets`

| Rule id | Decision | hardDeny | severity | 止めるもの |
| --- | --- | --- | --- | --- |
| `core.secrets.sensitive-path-to-network` | deny | true | critical | Bash で sensitive path と network sink が同一コマンド上に co-occur |
| `core.secrets.sensitive-read` | deny | true | high | `Read` / `Edit` で sensitive path を直接対象にした |

## `core.project_hygiene`

プロジェクト規約と整合しない操作を止める。default は **disabled**。
opt-in するには `packs.core.project_hygiene.enabled: true` を設定する
([`config-and-plugins.md`](config-and-plugins.md))。

### v1 実装済み rule (v0.4)

| Rule id | Decision | hardDeny | severity | 止めるもの |
| --- | --- | --- | --- | --- |
| `core.project_hygiene.lock-mismatch-pnpm` | deny | false | high | `pnpm-lock.yaml` がある repo で `npm install` / `npm ci` / `yarn install` / `yarn add` |
| `core.project_hygiene.lock-mismatch-uv` | deny | false | high | `uv.lock` がある repo で `pip install` (素の `pip`、`uv pip install` は対象外) |
| `core.project_hygiene.protected-branch-destructive-git` | deny | false | high | protected branch (`main` / `master` / `release/*` 既定) 上で `git reset --hard` / `git clean -fdx` / `git branch -D` / `git stash clear`。`core.git` が ask する操作を deny に昇格 |

`protected-branch-destructive-git` は `aggregate` の
`deny > ask > monitor > allow` 規則により、protected branch で同じ操作に
対する `core.git.reset-hard` 等の ask を上書きして deny を返す。
非 protected branch では `core.git` の ask が通常通り出る。

protected branch 一覧は `packs.core.project_hygiene.protectedBranches` で
project / user 単位に上書きできる。default は `["main", "master", "release/*"]`。
パターンは末尾 `*` のみ glob として扱われる minimal matcher。

### v1 で扱わないもの (v2 以降)

- generated file の直接編集を止める (project facts で `generated: true` のもの)
- project-specific forbidden command を止める (config で列挙)
