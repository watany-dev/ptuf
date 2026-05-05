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
| `core.project_hygiene` | disabled | lockfile / protected branch 規約 |

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
| `core.secrets.sensitive-path-to-network` | deny | true | critical | Bash で機密 path と network sink が同一 command に共存 |
| `core.secrets.sensitive-read` | deny | true | high | `Read` / `Edit`、または path を持つ MCP tool で機密 path を直接対象にする |

機密分類は `~/.ssh/**`, `~/.aws/**`, `~/.config/gcloud/**`, `~/.kube/config`,
`~/.docker/config.json`, `.env*`, `.npmrc`, `.pypirc`, `*.tfstate`, PEM blob など。

## `core.git`

実装済み rule は 11 個。

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

末尾 4 rule は hook / signing / fsck bypass を block するためのもの。

## `core.self_protection`

実装済み rule は 6 個で、すべて `deny`, `hardDeny: true`, `severity: critical`。

| Rule id | 対象 |
| --- | --- |
| `core.self_protection.binary` | ptuf 実行ファイル |
| `core.self_protection.config` | config layer (`/etc`, `~/.config`, repo local) |
| `core.self_protection.plugin` | config で参照された plugin YAML |
| `core.self_protection.claude-settings` | `.claude/settings*.json` |
| `core.self_protection.codex-settings` | `.codex/config.toml`, `.codex/hooks.json` |
| `core.self_protection.hook-script` | Claude / Codex の hook command が参照する実行ファイル |

## `core.project_hygiene`

この pack は default で無効。`packs.core.project_hygiene.enabled: true` で有効化する。

| Rule id | Decision | hardDeny | severity | 対象 |
| --- | --- | --- | --- | --- |
| `core.project_hygiene.lock-mismatch-pnpm` | deny | false | high | `pnpm-lock.yaml` がある repo で `npm` / `yarn` install 系 |
| `core.project_hygiene.lock-mismatch-uv` | deny | false | high | `uv.lock` がある repo で素の `pip install` |
| `core.project_hygiene.protected-branch-destructive-git` | deny | false | high | protected branch 上で `git reset --hard`, `git clean -fdx`, `git branch -D`, `git stash clear` |

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
