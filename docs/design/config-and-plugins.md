# Config と Plugin

ptuf の runtime 設定は複数 scope の YAML を merge して決まる。plugin は
`apiVersion: ptuf.dev/v1` の YAML rule 集である。

## Config スコープ

優先順位は下ほど高い。

1. builtin defaults
2. `/etc/ptuf/policy.yaml`
3. `~/.config/ptuf/config.yaml`
4. `<repo>/.ptuf.yaml`
5. `<repo>/.ptuf.local.yaml`

存在しないファイルは無視する。

`readonly: true` は書き込みを一律拒否する強制ゲート (`mode` と直交)。
環境変数 `PTUF_READONLY=1|true|on` は合成レイヤーとして `readonly: true`
を最上段に積む (falsy 値はレイヤーを作らない = 強化のみ可能)。
`core.readonly.*` は engine ゲートであり pack ではない
([ADR 0009](../adr/0009-readonly-mode-2026-07.md))。

## Config schema

```yaml
version: 1

mode: enforce
failClosed: true
readonly: false

packs:
  core.project_hygiene:
    enabled: true
    protectedBranches:
      - main
      - master
      - release/*

rules:
  core.git.reset-hard:
    enabled: true
    decision: ask
    severity: high

plugins:
  - path: ~/.config/ptuf/plugins/team.yaml
    enabled: true

allowlists:
  - id: allow-local-dev-server
    appliesTo:
      rules:
        - acme.dev.local-post
    when:
      url.hostAny:
        - localhost
        - 127.0.0.1
    expiresAt: "2026-06-01T00:00:00Z"
    reason: Local development callback.

audit:
  enabled: true
  path: ~/.local/share/ptuf/audit.jsonl
  includeAllowed: false
  includeDenied: true
  redaction: strict
```

### top-level key

| key | 型 | 説明 |
| --- | --- | --- |
| `version` | `u32` | 現在は `1` |
| `mode` | `enforce` / `monitor` | 実行 mode |
| `failClosed` | `bool` | **予約フィールド** — `ptuf init --verify` の fail-closed チェックとスキーマ互換用。ランタイムの `Engine::for_cwd` / CLI hook は常に policy load 失敗で `core.engine.policy-load-failed` として fail-closed し、このフラグは読まれない |
| `packs` | map | pack ごとの設定 |
| `rules` | map | rule id 単位の override |
| `plugins` | list | plugin file 参照 |
| `allowlists` | list | 時限付き例外 |
| `audit` | map | audit 出力設定 |

### `packs`

現在の `RawPack` は共通 shape で、実装上の認識キーは次のみ。

| key | 型 | 説明 |
| --- | --- | --- |
| `enabled` | `bool` | pack 全体の有効 / 無効 |
| `protectedBranches` | `string[]` | `core.project_hygiene` のみ使用 |
| `additionalWorkspaces` | `string[]` | `core.workspace` のみ使用。`~` / `$HOME` を展開し、engine が canonical 化して `repo_root` と合わせて境界集合を作る |

`core.project_hygiene` と `core.workspace` は default で `enabled: false`。
`core.workspace.outside-access` は Read も対象にするため、有効化すると
外部 lib (`~/.cargo/registry/...`, `/usr/include/...` など) の参照が
deny される。詳細は `policy-packs.md#core-workspace` を参照。

### `rules`

正確な rule id をキーにして override する。

| key | 型 | 説明 |
| --- | --- | --- |
| `enabled` | `bool` | 個別 rule の ON/OFF |
| `decision` | `allow` / `monitor` / `ask` / `deny` | default decision の上書き |
| `severity` | `info` / `low` / `medium` / `high` / `critical` | severity の上書き |

`hardDeny` や `overridable: false` の rule は下位 scope から弱められない。

### `plugins`

| key | 型 | 説明 |
| --- | --- | --- |
| `path` | path | plugin YAML |
| `enabled` | `bool` | `false` なら参照だけ残して load しない |

### `allowlists`

| key | 型 | 説明 |
| --- | --- | --- |
| `id` | string | audit に出る識別子 |
| `appliesTo.rules` | string[] | 適用対象 rule id |
| `when` | mapping | plugin DSL と同じ条件式 |
| `expiresAt` | RFC3339 string | 期限。過ぎると無効 |
| `reason` | string | 人間向けメモ |

allowlist は suppression できた場合だけ `allowlistId` として audit に残る。
`hardDeny` rule には効かない。

### `audit`

| key | 型 | 説明 |
| --- | --- | --- |
| `enabled` | `bool` | 書き込みを有効化。閲覧 CLI (`ptuf audit`) は既存ファイルを読める。`--path` 未指定時は warning を出して表示する (issue #189) |
| `path` | path | 出力先。省略時は既定パス |
| `includeAllowed` | `bool` | `Allow` を記録するか |
| `includeDenied` | `bool` | `Deny` を記録するか |
| `redaction` | `strict` / `off` | redaction mode |

## Plugin schema

```yaml
apiVersion: ptuf.dev/v1
kind: Plugin

metadata:
  name: acme.security
  version: 0.1.0
  description: Team-specific rules

capabilities:
  events: [PreToolUse]
  tools: [Bash]
  requires: [tool, event, shell.argv]

rules:
  - id: acme.security.no-curl
    title: Block raw curl
    severity: high
    defaultDecision: deny
    when:
      all:
        - event: PreToolUse
        - tool: Bash
        - shell.argv:
            headAny: [curl]
    reason: Avoid raw curl in this repository.
    remediation:
      - Use the project fetch helper instead.
    tests:
      deny:
        - input:
            tool_name: Bash
            tool_input:
              command: "curl https://example.com"
      allow:
        - input:
            tool_name: Bash
            tool_input:
              command: "ls"
```

### `metadata`

| key | 型 |
| --- | --- |
| `name` | string |
| `version` | string |
| `description` | string |

### `capabilities`

`requires` は loader が検証する。現在受け付ける値:

- `shell.ast`
- `shell.argv`
- `shell.pipeline`
- `tool`
- `event`
- `path`
- `url`
- `sensitive_path`

### `rules[*]`

| key | 型 | 説明 |
| --- | --- | --- |
| `id` | string | 安定 rule id |
| `title` | string | 1 行要約 |
| `severity` | enum | 必須 |
| `defaultDecision` | enum | 必須 |
| `overridable` | `bool` | 省略時 `true` |
| `hardDeny` | `bool` | 省略時 `false` |
| `when` | mapping | 条件式 |
| `reason` | string | deny / ask 理由 |
| `remediation` | string[] | 代替手順 |
| `tests` | object | `deny` / `allow` ケース |

`id` は loader が検証する:

- `core` および `core.` prefix の id は ptuf 組み込み rule 用に**予約**
  されており、外部 plugin が使うと `ReservedRuleId` エラーで load が
  失敗する (builtin なりすましの防止 — mode demotion の hardDeny 判定や
  audit 帰属が id で行われるため)。
- 同一 plugin 内で id が重複すると `DuplicateRuleId` エラーで load が
  失敗する。

## `when:` DSL

サポートしている leaf は次のとおり。

| key | shape | 説明 |
| --- | --- | --- |
| `event` | `string` | 現在は `PreToolUse` と比較 |
| `tool` | `string` | `tool_name` と一致 |
| `toolAny` | `string[]` | `tool_name` がいずれかに一致 |
| `shell.argv` | `{ headAny: [string] }` | command head がいずれかに一致。`bash -c`, `eval`, `xargs`, `find -exec` のような wrapper で surfaced した nested command も含む |
| `shell.pipeline` | `{ from: { commandAny: [...] }, to: { commandAny: [...] } }` | pipeline に from→to の流れがある |
| `shell.ast` | — | **未サポート** — `capabilities.requires` では宣言できるが `when:` leaf には使えない |
| `path.filePathPrefixAny` | `string[]` | 抽出 path が prefix に一致 |
| `url.schemeAny` | `string[]` | URL scheme が一致 |
| `url.hostAny` | `string[]` | URL host が一致 |
| `sensitive.pathKindAny` | `string[]` | 機密分類が一致 |
| `all` / `any` / `not` | nested | 論理結合 |

## Plugin check

`ptuf plugin check <path>` は plugin の `tests.deny` / `tests.allow` を、その rule
単体に対して実行する。built-in rule や engine の aggregate までは通さない。

## 組み込み rule の DSL 化 (`src/rules/builtins.yaml`)

ptuf 自身の組み込み rule も、DSL で表現できるものから順に同じ plugin
スキーマの YAML (`src/rules/builtins.yaml`, バイナリに埋め込み) へ移して
いる (ADR 0004)。`rules::iter()` が静的 Rust rule の後ろへ DSL 組み込みを
chain するため、pack 無効化・rule override・allowlist・`hardDeny` は両者に
同一機構で作用する。外部 plugin との違いは 2 点のみ:

- 埋め込み経路 (`load_builtin_str`) だけが `core.*` id を使える
- 埋め込み YAML のコンパイル失敗 (構造的に到達不能、テストで pin) 時は
  deny-everything の fail-closed sentinel
  (`core.engine.builtin-load-failed`) に縮退する

現在 DSL 化済み: `core.network.remote-script-pipe`。
