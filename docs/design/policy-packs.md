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

危険な git 操作の default decision を以下に固定する。

| Command | Decision |
| --- | --- |
| `git push --force` | `deny` |
| `git push --force-with-lease` | `ask` |
| `git reset --hard` | `ask` |
| `git clean -fdx` | `ask` (strict profile では `deny`) |
| `git branch -D` | `ask` |
| `git stash clear` | `ask` |
| `git remote set-url` | `ask` |

protected branch (`main`, `master`, `release/*` 等、project facts で定義) では
これらをさらに 1 段強める運用を推奨。

## `core.self_protection`

prompt injection 等で agent が guardrail 自体を無効化することを防ぐ。

**止めるもの:**

- ptuf binary / config / plugin ファイルの改変
- `.claude/settings.json`
- `.claude/settings.local.json`
- `~/.claude/settings.json`
- hook script / hook registration の削除や改変

これらの rule は default で `hardDeny: true` 相当の扱いとし、下位 scope から
解除できない ([`decision-model.md`](decision-model.md))。

## `core.project_hygiene`

プロジェクト規約と整合しない操作を止める。default は optional。

**例:**

- `pnpm-lock.yaml` がある repo で `npm install` / `yarn install` を止める
- `uv.lock` がある repo で直接 `pip install` を止める
- generated file の直接編集を止める (project facts で `generated: true` のもの)
- protected branch で destructive git 操作を止める
- project-specific forbidden command を止める (config で列挙)
