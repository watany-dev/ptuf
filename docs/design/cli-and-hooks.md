# CLI と Hook 統合

ptuf は CLI バイナリとして配布され、同時に Claude Code / Codex / GitHub
Copilot / Kiro CLI / Cline / Cursor / Pi Coding Agent / OpenCode の hook adapter を提供する。
Kiro 固有の正規化や fail-closed 経路の詳細は [`kiro-cli.md`](kiro-cli.md) を参照。

## 実装済みサブコマンド

```bash
ptuf hook claude-code
ptuf hook codex
ptuf hook copilot
ptuf hook kiro
ptuf hook cline
ptuf hook cursor
ptuf hook pi
ptuf hook opencode
ptuf [--json] check --tool Bash 'git reset --hard HEAD~1'
ptuf [--json] plugin check ./ptuf-plugin.yaml
ptuf [--json] init                       # auto-detect every agent
ptuf [--json] init claude-code           # pin to one adapter
ptuf [--json] init claude-code --no-verify
ptuf [--json] init claude-code --dry-run
ptuf update [--check] [--version <TAG>] [--force]
```

| サブコマンド | 用途 |
| --- | --- |
| `ptuf hook <agent>` | hook 本体。stdin JSON を評価する |
| `ptuf check --tool <name> <command>` | 単発評価 |
| `ptuf plugin check <path>` | plugin rule の `tests:` を実行 |
| `ptuf init [<agent>] [--no-verify] [--dry-run]` | agent 側の hook 設定を配線 (verify は既定 ON、`--dry-run` 時は自動 OFF) |
| `ptuf update [--check] [--version <TAG>] [--force]` | GitHub Releases から最新 tag を取得し、`cargo install --force` または cargo-dist 製 installer を auto-detect で起動して binary を差し替える |
| `ptuf --help`, `ptuf --version` | 情報表示 |

計画中 (issue #189 / [`audit.md`](audit.md)):

```bash
ptuf [--json] audit [--path <FILE>] [--decision <deny|ask|monitor|allow>]
                    [--rule <ID>] [--tool <NAME>]
                    [--since <CANONICAL_RFC3339|<N>m|<N>h|<N>d>]
                    [--limit <N>] [--stats]
```

| サブコマンド | 用途 |
| --- | --- |
| `ptuf [--json] audit` | 監査 JSONL の閲覧。書き込み経路には触れない |

`--json` はトップレベルの global flag で、サブコマンド **の前** にのみ
書ける (`ptuf --json init ...`)。`hook <agent>` は host 側の出力形が
固定なので `--json` を parse 段で reject する。

`ptuf init` は引数なしで auto-detect を行う:

| Agent | 検出条件 | install 先 |
|---|---|---|
| ClaudeCode | `$HOME/.claude/` | `$HOME/.claude/settings.json` |
| Codex | `<repo>/.codex/` または `$HOME/.codex/` | repo 配下の `.codex/` |
| Copilot | `<repo>/.github/` | `<repo>/.github/hooks/ptuf.json` |
| Kiro | `<repo>/.kiro/` または `$HOME/.kiro/` | 両 scope の `.kiro/agents/*.json` を一括 patch (空 scope は `agents/default.json` で fallback) |
| Cline | `<repo>/.clinerules/` `.cline/`、または `$HOME/Documents/Cline/` `.cline/` | repo 配下 `.clinerules/hooks/PreToolUse` または `$HOME/Documents/Cline/Hooks/PreToolUse` |
| Cursor | `<repo>/.cursor/` または `$HOME/.cursor/` | `<repo>/.cursor/hooks.json` (`--scope global` で `$HOME/.cursor/hooks.json`) |
| Pi | `<repo>/.pi/` または `$HOME/.pi/agent/` | `$HOME/.pi/agent/extensions/ptuf.ts` (default global) または `<repo>/.pi/extensions/ptuf.ts` (local) |
| OpenCode | `<repo>/.opencode/` または `<repo>/opencode.json` | `$XDG_CONFIG_HOME/opencode/plugins/ptuf.ts` (default global) または `<repo>/.opencode/plugins/ptuf.ts` (local) |

検出 0 件 → exit `1` + `no agent detected` を stderr に出す。1 件以上
→ 全部 install + verify。verify がいずれかで失敗すれば exit `1`。
`--dry-run` は計画のみ (verify off)、`--no-verify` は書き込むが verify
を走らせない。`<agent>` を明示すれば auto-detect を bypass し単独
install になる。

## 終了コード

| 条件 | exit |
| --- | --- |
| `Allow` / `Monitor` / Claude Code・Cursor・Pi の `Ask` | `0` |
| `Deny` (Claude Code / Codex / Kiro / Cursor / Pi) | `2` |
| Copilot / Cline の **すべての Decision** (Allow / Monitor / Ask→Deny / Deny) | `0` |
| 内部エラー、引数不正、plugin check fail、init verify fail、update 失敗 (curl 不在 / updater 非ゼロ)、`audit` の I/O エラー / 引数不正 / default path 解決不能 | `1` |

Codex / Kiro では `Ask` を `Deny` へ変換するため、実際には exit `2` になる。
Cursor は Claude Code と同じく `Ask` channel を持つため `Ask` を降格せず、
`{"permission":"ask",…}` を exit `0` で返す (下記「Cursor への登録」参照)。


Pi Coding Agent extension は TypeScript bridge 経由で `ptuf hook pi` を
spawn する。すべての Decision で bare JSON envelope
(`{"decision":"allow"|"monitor"|"ask"|"deny",…}`) を stdout に書き、
`Allow` / `Monitor` / `Ask` は exit `0`、`Deny` と reserved rule は exit `2`
とする。Cursor と同じく `Ask` を降格しない。extension 側は exit `0` と
`2` のみを有効とみなし、exit `1` や空 stdout は fail-closed deny として
扱う。

Copilot は protocol 上 non-zero exit が hook failure として扱われ得るため、
**すべての Decision で exit `0`** に固定する。Deny は bare JSON envelope
(`hookSpecificOutput` で wrap しない) を stdout に書く。stdout serialize
失敗のみ exit `1`。詳細は下記「hook response」セクションを参照。

Kiro hook は JSON envelope を持たず、`Ask` / `Deny` の reason は stderr のみで
通知する。stdout は常に空。

Cline file hook はプロセス失敗が経路によって fail-open になり得るため、
Copilot と同じく **すべての Decision で exit `0`** に固定し、block は stdout
の `{"cancel":true,…}` JSON で表現する。Allow / Monitor でも空 object `{}` を
stdout に書く。

`ptuf hook <agent>` の stdin payload は最大 8 MiB。上限を超えた場合は JSON parse
に進まず exit `1` とし、stderr に size limit error を出す (Copilot / Cline 経路
では exit `0` + `core.engine.invalid-payload` の deny JSON にフォールバック
する — fail-open を避けるため)。

## Claude Code への登録

`ptuf init claude-code` は `~/.claude/settings.json` に hook を追加する。

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|WebFetch|mcp__.*",
        "hooks": [
          {
            "name": "@watany-dev/ptuf",
            "type": "command",
            "command": "/usr/local/bin/ptuf hook claude-code"
          }
        ]
      }
    ]
  }
}
```

実装上の契約:

- 既存 JSON の未知キーは保持する
- 既存 entry の検出は hook payload の `name: "ptuf"` marker で行う
- 旧形式との互換性のため、command 末尾 `hook claude-code` も検出する
- binary の絶対パス差異は無視する
- 書き込みは temp file + rename の原子的更新
- 対象 path は固定で `$HOME/.claude/settings.json` (HOME unset → `InitError::HomeNotSet`)

## Codex への登録

`ptuf init codex` は既定で repo-local な `.codex/` を更新する。

`hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|apply_patch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/ptuf hook codex"
          }
        ]
      }
    ]
  }
}
```

`config.toml`:

```toml
[features]
hooks = true
```

実装上の契約:

- repo root が見つからない場合は `InitError::RepoRootNotFound` を返す
  (auto-detect では `.codex/` 検出が repo root を要求しないため、`$HOME/.codex/`
  fallback でも install を試みる)
- `hooks.json` は JSON object、`config.toml` は valid TOML である必要がある
- 既存 entry の検出は command 末尾 `hook codex` で行う

## GitHub Copilot への登録

`ptuf init copilot` は repo-local な
`<repo>/.github/hooks/ptuf.json` を更新する。

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "matcher": "*",
        "bash": "/usr/local/bin/ptuf hook copilot",
        "powershell": "/usr/local/bin/ptuf hook copilot",
        "timeoutSec": 10
      }
    ]
  }
}
```

実装上の契約:

- repo root が見つからない場合は `InitError::RepoRootNotFound` を返す
- ファイルは JSON object、`version` は `1` (欠落時は `1` で補完)
- 既存 entry の検出は `bash` / `powershell` field の command 末尾
  `hook copilot` で行う
- entry には `bash` と `powershell` の両方を書く (cross-platform)
- 書き込みは temp file + rename の原子的更新

## Kiro CLI への登録

`ptuf init kiro` の default 動作は **既存 agent JSON への一括 patch**:
列挙対象の各 scope (workspace + home) にある `*.json` をすべて読み込み、
`hooks.preToolUse` 配列に ptuf entry を append する。

scope:

- repo-local: `<repo>/.kiro/agents/*.json`
- global: `$HOME/.kiro/agents/*.json`

```json
{
  "name": "<既存 agent 名>",
  "description": "<既存 description>",
  "tools": ["*"],
  "hooks": {
    "preToolUse": [
      {
        "matcher": "*",
        "command": "/usr/local/bin/ptuf hook kiro",
        "timeout_ms": 10000,
        "cache_ttl_seconds": 0
      }
    ]
  }
}
```

CLI フラグ:

| フラグ | scope | 動作 |
| --- | --- | --- |
| (なし) | workspace + home | 全 agent JSON を patch |
| `--workspace-only` | repo-local のみ | `$HOME` は触らない |
| `--global` | `$HOME` のみ | repo-local は触らない |
| `--new-agent` | (組合せ可能) | legacy 動作: `<scope>/.kiro/agents/ptuf-guarded.json` を単一ファイルとして作成 |

`--workspace-only` + `--global` は parse error。`--new-agent` +
`--workspace-only` も parse error。`--new-agent` + `--global` は許可。
Kiro-only フラグを他 adapter / auto-detect に渡しても parse error。

実装上の契約:

- scope filter の解決:
  - `WorkspaceOnly`: repo root 未発見なら `InitError::RepoRootNotFound`
  - `GlobalOnly`: `$HOME` 未設定なら `InitError::HomeNotSet`
  - `Both`: repo / home 両方とも解決できない場合は `InitError::RepoRootNotFound`
- 各 scope について `settings/cli.json` を読み、flat dotted-key
  `"chat.defaultAgent"` を取得する。指定された名前に対応する
  `agents/<name>.json` が同じ scope に存在しない場合は
  **`InitError::Schema` で fail-closed** (新規 init は失敗、verify は出力
  しない)
- `.md` agent ファイル (`.kiro/agents/*.md`) は触らず、verify report の
  `skipped_non_json_agents` に列挙
- 両 scope 合わせて agent JSON が 1 つも見つからない場合のみ、最優先
  scope (workspace > home) に `agents/default.json` を新規作成し
  skeleton + hook を書く (legacy `ptuf-guarded.json` は使わない)
- `--new-agent` 経路では legacy 動作: scope filter が `WorkspaceOnly`
  なら repo 内、`GlobalOnly` なら HOME 内、`Both` なら repo 優先・HOME
  fallback の単一 path `agents/ptuf-guarded.json` を返す
- ファイルは JSON object、新規生成時は default skeleton (`name`,
  `description`, `tools`, `includeMcpJson`, `hooks.preToolUse`) を書く
- 既存 entry の検出は `hooks.preToolUse[].command` 末尾 `hook kiro` で行う
- 既存ファイル中の未知 key (`model` / `temperature` / `prompt` /
  `allowedTools` / `resources` 等) は `serde_json::Value` のまま保持される
- 書き込みは temp file + rename の原子的更新
- Unix では temp file を `OpenOptions::create_new(true).mode(0o600)` で
  生成し、rename 先のホスト設定ファイル (settings.json / hooks.json /
  config.toml / agent.json) も owner-only (`0o600`) になる。process
  umask に依存しないため、共有ホスト上で hook 設定が world-readable に
  なる経路を塞ぐ。Windows では NTFS ACL を親ディレクトリから継承する
  既存挙動をそのまま採用する
- 複数ファイル install で `--no-verify` 指定時は capture/restore が回らず、
  ループ途中で write が失敗すると先行ファイルだけ patch 済の状態が残る
  (個別 file の write は atomic だが、ファイル間整合性は保証なし)。
  default の verify 経路では snapshot capture が走り mid-loop crash でも
  自動巻き戻し

## Cline への登録

`ptuf init cline` は他の 4 adapter と異なり、設定ファイルへ command 文字列を
登録するのではなく **実行可能な wrapper script** を書く。Cline の file hook は
スクリプトそのものを実行する仕組みのため。

- repo root が見つかった場合: `<repo>/.clinerules/hooks/PreToolUse`
  (Windows は `PreToolUse.ps1`)
- repo root が無い場合: `$HOME/Documents/Cline/Hooks/PreToolUse[.ps1]` へ
  fallback する。`$HOME` も解決できない場合は `InitError::HomeNotSet`

Unix の wrapper:

```sh
#!/usr/bin/env sh
# ptuf-managed: cline PreToolUse
exec '/usr/local/bin/ptuf' hook cline
```

Windows の wrapper (`PreToolUse.ps1`):

```powershell
# ptuf-managed: cline PreToolUse
& '/usr/local/bin/ptuf' hook cline
exit $LASTEXITCODE
```

実装上の契約:

- Unix では wrapper をモード `0700` で書く (owner のみ実行可)。temp file +
  rename の原子的更新
- 既存 entry の検出は `ptuf-managed: cline PreToolUse` marker で行う。marker
  を持つ既存ファイルは binary path 差異があれば再生成、内容一致なら
  `AlreadyPresent`
- marker を持たない既存 `PreToolUse` は上書きせず `InitError::HookFileConflict`
  を返す
- binary path の quoting は sh では single-quote (`'` → `'\''`)、PowerShell
  では single-quote (`'` → `''`) で行う

## Cursor への登録

`ptuf init cursor` は `<repo>/.cursor/hooks.json` (`--scope global` で
`$HOME/.cursor/hooks.json`) に `version: 1` の `hooks.preToolUse` entry を
追加する。Copilot と同じ JSON-config 系 installer だが、scope/path 解決の
柔軟性が異なる。

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "command": "/usr/local/bin/ptuf hook cursor",
        "matcher": "Shell|Bash|Read|ReadFile|Write|Edit|MCP|WebFetch|Fetch|mcp__.*",
        "timeout": 10,
        "failClosed": true
      }
    ]
  }
}
```

path 解決の優先順位 (`init::cursor::resolve_paths`):

- `--hooks <path>` が最優先。指定ファイルをそのまま対象にする (root は
  parent ディレクトリ、無ければ `.`)
- `--scope global`: `$HOME/.cursor/hooks.json`。`$HOME` 不在は
  `InitError::HomeNotSet`
- `--scope local` (default): `--root <path>` を起点 (無ければ cwd) に
  `config::repo::discover` で repo root を探し、`<repo>/.cursor/hooks.json`。
  repo root 不在は `InitError::RepoRootNotFound`

merge 契約 (Copilot と同型):

- `version` 欠如 → `1` を付与。`hooks` / `hooks.preToolUse` を object /
  array として補完
- idempotent 判定は command tail `["hook","cursor"]`。既存 ptuf entry が
  あれば推奨値へ揃え、無ければ追加。他の hook entry は保持
- temp file + rename の原子的更新、mode `0600`
- object であるべき箇所が他の型なら非破壊で `InitError`

`--scope` / `--root` は Cursor と Pi で共有する。`--hooks` は Cursor 専用、
`--extension` は Pi 専用。他 adapter や auto-detect へ渡すと parse error
(`ConflictingFlags`)。Kiro の `--global` との取り違えを避けるため Cursor /
Pi は `--scope global` を採用している。


## Pi Coding Agent への登録

`ptuf init pi` は managed TypeScript extension (`extensions/ptuf.ts`) を
書き込む。デフォルト scope は **global** (`$HOME/.pi/agent/extensions/ptuf.ts`)。

path 解決の優先順位 (`init::pi::resolve_paths`):

- `--extension <path>` が最優先。指定ファイルをそのまま対象にする
- `--scope global` (default): `$HOME/.pi/agent/extensions/ptuf.ts`。
  `$HOME` 不在は `InitError::HomeNotSet`
- `--scope local`: `--root <path>` を起点 (無ければ cwd) に
  `config::repo::discover` で repo root を探し、
  `<repo>/.pi/extensions/ptuf.ts`。repo root 不在は `InitError::RepoRootNotFound`

extension は `pi.on("tool_call", …)` で raw event を `ptuf hook pi` に渡す。
正規化 (`bash`→`Bash`, `grep`→`mcp__pi__grep`, unknown→`mcp__pi__*`) は
Rust (`src/cli/pi_input.rs`) で行う。managed marker (`Managed by ptuf…`,
`ptuf-agent: pi`) を持たない既存ファイルは `InitError::HookFileConflict`。
temp file + rename の原子的更新、Unix では mode `0600`。

`--scope` / `--root` は Cursor と Pi で共有する。`--extension` は Pi 専用。
`--hooks` は Cursor 専用。他 adapter や auto-detect へ渡すと
`ParseError::ConflictingFlags`。



### OpenCode 入力正規化 (`src/cli/opencode_input.rs`)

| OpenCode tool | Canonical `tool_name` | 備考 |
| --- | --- | --- |
| bash | Bash | |
| read / write / edit | Read / Write / Edit | camelCase `filePath` → `file_path` |
| patch | apply_patch | patch 本文を `command` に複製 |
| webfetch | WebFetch | |
| grep / glob / list | `mcp__opencode__grep` 等 | 既存 MCP 汎用 path 抽出 |
| todowrite / todoread / task | `mcp__opencode__<name>` | |
| 未知 | `mcp__opencode__<sanitized>` | |

OpenCode の stdout は Pi と同型の bare envelope (`decision` / `rule_id` /
`reason`)。**Ask は Rust 側で Deny に降格**（OpenCode の `permission.ask`
hook は既知の不発火があり、`tool.execute.before` から対話確認を開始できないため）。

### Pi 入力正規化 (`src/cli/pi_input.rs`)

| Pi tool | Canonical `tool_name` | 備考 |
| --- | --- | --- |
| `bash` | `Bash` | `tool_input.command` をそのまま渡す |
| `read` / `write` | `Read` / `Write` | `path` → `file_path` |
| `edit` | `Edit` | `path` → `file_path`; `edits[].newText` / `new_text` → `new_string` |
| `grep` / `find` / `ls` | `mcp__pi__grep` / `mcp__pi__find` / `mcp__pi__ls` | args を object のまま渡す |
| `fetch` / `web_fetch` | `WebFetch` | |
| その他 | `mcp__pi__<sanitized>` | 非英数字 → `_` |

`tool_name` / `toolName` / `name`、`tool_input` / `toolInput` の alias を受け付ける。
`tool_input` は object / JSON 文字列 / scalar / null。空 payload / 非 object /
tool name 欠如は `core.engine.invalid-payload` で fail-closed。

## install verification

`ptuf init <agent>` は配線を書いたあと、内部 Engine を起動して
synthetic payload を 1 度だけ評価する。これは「設定ファイルが書けた」だけ
ではなく「ptuf 本体が deny 判定に到達できる」ことをインストール直後に確認
する目的で、CI gate や README の手動確認手順を不要にする。

verify は既定で実行される。`--no-verify` で skip、`--dry-run` 指定時は
書き込み自体を行わないため verify も自動的に off になる。

検査項目は 2 件:

| Check | 期待結果 |
| --- | --- |
| Synthetic deny | `rm -rf /` payload が `core.filesystem.destructive-rm` (hard_deny) で deny される |
| Fail-closed internal error | 不正な plugin path を含む config を builtin Engine に渡すと `core.engine.policy-load-failed` の fail-closed 経路に落ちる |

両 check は **builtin rules のみ** で評価する。ユーザ policy / plugin の
override は意図的に無視する — verify は ptuf 本体の guardrail が機能して
いるかを確かめるものであり、ユーザ環境の効果を再現するものではない。

`--json` は global flag のため `ptuf --json init ...` の形でのみ受け付ける。
`ptuf init --json` のように subcommand 後置の場合は `UnexpectedArgument` で
exit `1` を返す。

### 失敗時の挙動

- 直前のインストールが `Installed` ステータスだった場合、書き込んだ
  ファイルを **書き込み前のスナップショットに巻き戻す** (snapshot は
  install 前の `fs::read` を temp+rename で書き戻す)。書き込み前にファイル
  が存在しなかった場合は削除する。
- 既に hook が登録済み (`AlreadyPresent`) の状態で verify が落ちた場合は
  ファイルには触れず、stderr で「手動で見直すか古い設定の可能性を疑え」
  と通知する。
- いずれの経路でも exit code は `1`。

### 出力フォーマット

text 版:

```text
ptuf init claude-code: registered hook in settings=/home/alice/.claude/settings.json
  matcher: Bash|Read|Edit|Write|WebFetch|mcp__.*
  command: /home/alice/.local/bin/ptuf hook claude-code
Verify:
  Synthetic deny test: passed (rule: core.filesystem.destructive-rm)
  Fail-closed internal error test: passed (rule: core.engine.policy-load-failed)
  Warnings: none
```

`--json` 版は `schemaVersion: 1` を持ち、以下の top-level key を出す。

```json
{
  "schemaVersion": 1,
  "agent": "claude-code",
  "installed": true,
  "alreadyPresent": false,
  "paths": [{"label": "settings", "path": "/home/alice/.claude/settings.json"}],
  "matcher": "Bash|Read|Edit|Write|WebFetch|mcp__.*",
  "command": "/home/alice/.local/bin/ptuf hook claude-code",
  "verify": {
    "syntheticDeny": {"status": "passed", "ruleId": "core.filesystem.destructive-rm"},
    "failClosed":    {"status": "passed", "ruleId": "core.engine.policy-load-failed"},
    "warnings": []
  },
  "rolledBack": false
}
```

`status: "failed"` の場合は `ruleId` の代わりに `detail` フィールドが入る。

`syntheticDeny.ruleId` が `core.filesystem.destructive-rm` で固定であることは
`tests/contracts.rs` の contract test で保証される。`failClosed.ruleId` は
`hook` / `check` と同じ CLI fail-closed contract (`core.engine.policy-load-failed`)
を共有する。

## hook response

Claude Code:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "..."
  }
}
```

Codex:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "..."
  }
}
```

GitHub Copilot (bare envelope, `hookSpecificOutput` wrap なし):

```json
{
  "permissionDecision": "deny",
  "permissionDecisionReason": "..."
}
```

Kiro CLI は JSON envelope を持たない。`Ask` / `Deny` reason は stderr のみで
通知し、stdout は常に空。`Ask` は `Deny` へ demote する。

Cline (`hookSpecificOutput` wrap なし、`shouldContinue` / `review` /
`overrideInput` は出さない):

```json
{
  "cancel": true,
  "errorMessage": "...",
  "context": "...",
  "contextModification": "..."
}
```

Cursor (bare envelope, `hookSpecificOutput` wrap なし。`permission` は
`ask` / `deny` のみ。Claude Code と同じく `Ask` を保持し降格しない):

```json
{
  "permission": "deny",
  "user_message": "...",
  "agent_message": "..."
}
```

Pi Coding Agent (bare envelope, `hookSpecificOutput` wrap なし。`decision` は
`allow` / `monitor` / `ask` / `deny`。Cursor と同じく `Ask` を保持し降格しない):

```json
{
  "decision": "deny",
  "rule_id": "core.filesystem.destructive-rm",
  "reason": "..."
}
```

`Allow` と `Monitor` は hook response を出さない (Claude Code / Codex /
Copilot / Kiro)。Cline は Allow / Monitor でも空 object `{}` を stdout に
書き、Cursor は `failClosed` hook の空 stdout が invalid 扱いになるため
`{"permission":"allow"}` を明示する。Pi はすべての Decision で bare
`decision` JSON を stdout に書く。block 時のみ Cline は
`cancel: true` envelope を出す。`Ask` は Claude Code / Cursor / Pi では保持、
それ以外では `Deny` へ demote する。

agent 別の Decision → exit / 出力契約:

| Agent | Allow / Monitor | Ask | Deny | invalid payload / policy load fail |
| --- | --- | --- | --- | --- |
| Claude Code | exit `0`, 空 stdout | exit `0`, `hookSpecificOutput` ask | exit `2`, `hookSpecificOutput` deny | exit `2`, deny |
| Codex | exit `0`, 空 stdout | `Ask` → `Deny` に demote (exit `2`) | exit `2`, `hookSpecificOutput` deny | exit `2`, deny |
| Copilot | exit `0`, 空 stdout | `Ask` → `Deny` に demote (exit `0`, bare JSON) | exit `0`, bare deny JSON | exit `0`, bare deny JSON |
| Kiro | exit `0`, 空 stdout / 空 stderr | `Ask` → `Deny` に demote (exit `2`, stderr reason のみ) | exit `2`, stderr reason のみ | exit `2`, stderr reason のみ |
| Cline | exit `0`, stdout `{}` | `Ask` → `Deny` に demote (exit `0`, cancel JSON) | exit `0`, cancel JSON | exit `0`, cancel JSON |
| Cursor | exit `0`, bare `permission:allow` JSON | exit `0`, bare `permission:ask` JSON (**降格しない**) | exit `2`, bare `permission:deny` JSON | exit `2`, deny |
| Pi | exit `0`, bare `decision:allow` / `monitor` JSON | exit `0`, bare `decision:ask` JSON (**降格しない**) | exit `2`, bare `decision:deny` JSON | exit `2`, deny JSON |

Copilot の `Ask` demote 文言は仕様で固定:

> `GitHub Copilot hooks do not reliably process interactive ask
> decisions; ptuf is blocking this request instead.`

Kiro の `Ask` demote 文言も仕様で固定:

> `Kiro CLI PreToolUse hooks do not define an interactive ask channel;
> ptuf is blocking this request instead.`

Cline の `Ask` demote 文言も仕様で固定:

> `Cline PreToolUse file hooks do not currently provide a uniformly
> reliable interactive review channel; ptuf is blocking this request
> instead.`

reserved rule `core.engine.invalid-payload` / `core.engine.policy-load-failed`
は 7 agent で共通だが、Copilot では bare JSON + exit `0`、Kiro では stderr +
exit `2`、Cline では cancel JSON + exit `0`、Cursor では bare
`permission:deny` JSON + exit `2` で出す。

## MCP fact 抽出

`tool_name` が `mcp__<server>__<tool>` 形式なら、ptuf は server 固有 adapter を
書かずに以下の key を読む。

| key | 用途 |
| --- | --- |
| `path` | `Facts.path` / `Facts.paths` |
| `files[].path`, `items[].path`, `paths[]` | `Facts.paths` に追加する nested path |
| `url` | `Facts.url` |
| `content` | write payload として secret 判定に流す |

このため既存の `core.self_protection.*` や
`core.secrets.sensitive-read` は MCP 経路にもそのまま効く。

`Read` / `Edit` / `Write` でも canonical `file_path` に加えて `paths[]`
(string array) と `operations[].path` (object array) を `Facts.paths` へ
収集する。Kiro の batch read/write payload を canonical な `Read` / `Write`
のままで engine に渡すための拡張で、重複は engine 側で排除する。

## Kiro 入力正規化

Kiro CLI の `preToolUse` payload は `{"hook_event_name":"preToolUse",
"tool_name":"<name>","tool_input":{...}}` の形を取る。`src/cli/kiro_input.rs`
が次の正規化を行う。

| Kiro tool 名 | canonical |
| --- | --- |
| `shell` / `execute_bash` / `execute_cmd` | `Bash` |
| `read` / `fs_read` / `fsRead` | `Read` |
| `write` / `fs_write` / `fsWrite` | `Write` |
| `web_fetch` / `webFetch` | `WebFetch` |
| `@<server>/<tool>` | `mcp__<server>__<tool>` |
| `@<server>/<tool>/<rest>` | `mcp__<server>__<tool>_<rest>` |
| その他 | そのまま (engine が generic / MCP 抽出) |

`tool_input` の正規化:

- `Bash`: `command` が無ければ `cmd` → `script` の順で先頭 string を
  `command` に複製する
- `Read` / `Write`: `file_path` が無ければ `path` → `paths[0]` →
  `operations[0].path` → `files[0].path` → `items[0].path` の順で先頭
  string を `file_path` に複製する。元の array は変更せず、core 側の
  `paths[]` / `operations[]` 抽出と重複排除に任せる
- `Write`: `content` が無ければ `text` → `new_content` の順で先頭 string を
  `content` に複製する

`hook_event_name` が `preToolUse` 以外の場合は `core.engine.invalid-payload`
で fail-closed する。空 payload / 非 object payload / `tool_name` 欠落も同様。

## Cline 入力正規化

Cline の file hook payload は `hookName` envelope に包まれており、2 つの形を
取る。`src/cli/cline_input.rs` が両方を受け、canonical shape に正規化する。

- SDK / CLI file-hook 形: `{"hookName":"tool_call","tool_call":{"id","name",
  "input"}}`
- legacy extension 形: `{"hookName":"PreToolUse","preToolUse":{"toolName",
  "parameters"}}`

`tool_call` と `preToolUse` が両方あれば `tool_call` を常に優先する。

| Cline tool 名 | canonical |
| --- | --- |
| `execute_command` / `run_command` / `run_commands` / `bash` | `Bash` |
| `read_file` / `read_files` | `Read` |
| `editor` / `replace_in_file` / `edit_file` | `Edit` |
| `write_file` | `Write` |
| `apply_patch` | `apply_patch` |
| `fetch_web` / `fetch_web_content` / `web_fetch` | `WebFetch` |
| `use_mcp_tool` | `mcp__<server>__<tool>` |
| `access_mcp_resource` | `mcp__<server>__access_resource` |
| その他 | input field から推測 (`command` 系 → `Bash`、`url` 系 → `WebFetch`、`content`+path → `Write`)、推測不能ならそのまま |

`input` / `parameters` の正規化:

- `Bash`: `command` が無ければ `cmd` → `shellCommand` の順、さらに無ければ
  `commands[]` を改行連結して `command` に複製する
- `Read` / `Edit` / `Write`: `file_path` が無ければ `filePath` → `path` →
  `absolutePath` → `relativePath` の順で `file_path` に複製する
- `WebFetch`: `url` が無ければ `uri` → `href` の順で `url` に複製する
- `use_mcp_tool` / `access_mcp_resource`: `arguments` (object もしくは
  JSON 文字列) を tool input へ flatten する。元の alias key は保持する

正規化後、`_cline_tool_name` に元の tool 名を、SDK 形なら `_cline_tool_call_id`
に `tool_call.id` を付与する。非 JSON / 非対応 `hookName` / `tool_call` も
`preToolUse` も無い / tool 名が空 のいずれも `core.engine.invalid-payload`
で fail-closed する。

## Cursor 入力正規化

Cursor の hook payload は `hook_event_name` (camelCase `hookEventName` 互換)
で event を区別する。`src/cli/cursor_input.rs` が enforce 対象 event を
canonical shape に正規化する。

| Cursor event | canonical tool |
| --- | --- |
| `preToolUse` | `tool_name` を正規化 (下表)。`tool_name` 欠落は fail-closed |
| `beforeShellExecution` | `Bash` |
| `beforeReadFile` | `Read` |
| `beforeMCPExecution` | `mcp__<server>__<tool>` |
| その他 (`postToolUse` / `afterFileEdit` / `sessionStart` / `stop` 等) | `core.engine.invalid-payload` で fail-closed (MVP では observe-only 化しない) |

`preToolUse` の `tool_name` 正規化:

| Cursor tool 名 | canonical |
| --- | --- |
| `Shell` / `Bash` | `Bash` |
| `Read` / `ReadFile` | `Read` |
| `Write` | `Write` |
| `Edit` | `Edit` |
| `WebFetch` / `Fetch` | `WebFetch` |
| `MCP` / `mcp__*` | `mcp__<server>__<tool>` |
| その他 | そのまま (engine が generic / MCP 抽出) |

field fallback (`tool_input` / camelCase `toolInput` / root いずれからも読む):

- `Bash`: `command` → `cmd` → `script` → root `command` の順で先頭 string を
  `command` に複製
- `Read` / `Write` / `Edit`: `file_path` → `path` → root `path` → `paths[0]`
  → `files[0].path` の順で `file_path` に複製
- `Write`: `content` → `text` → `new_content`
- `Edit`: `old_string` → `oldText` → `old`、`new_string` → `newText` → `new`
- `beforeMCPExecution`: `metadata.server` / `metadata.tool_name` (または
  `tool_input.*` / root) から `mcp__<server>__<tool>` を組み立てる。空白 /
  `/` / `.` 等は `_` へ正規化する (`kiro_input::normalize_at_mcp` と同型)

`tool_input` が JSON 文字列の場合は parse し、失敗時は `{"text":"<raw>"}` で
保持する (`copilot_input::decode_args` と同型)。空 payload / 非 object payload
も `core.engine.invalid-payload` で fail-closed する。

## fail-closed

`hook` と `check` は engine 構築に失敗すると
`core.engine.policy-load-failed` で deny する。これは CLI の固定契約であり、
ライブラリ API `decide()` とは意図的に異なる。

`hook` はさらに stdin 系の初期化エラー (read failure / 8 MiB 超過 / JSON
parse 失敗) を `core.engine.invalid-payload` で deny する。Claude Code の
hook 仕様では `exit 1` は **non-blocking warning** として扱われ tool 実行を
止めないため、これらは必ず exit `2` + adapter の deny JSON で返さなければ
fail-open になる。`failClosed: false` でもこの境界は緩めない。

Copilot adapter は同じ理由付けの裏返しを取る — Copilot protocol は
non-zero exit を hook *failure* として扱い tool 実行を止めない可能性が
あるため、reserved rule の deny も含めて **すべて exit `0` + bare deny
JSON** で返す。これにより host 側で「ptuf が落ちたから fail-open」と
解釈される経路を塞ぐ。

Kiro adapter は Claude / Codex と同じく exit `2` で block するが、JSON
envelope を持たないため reason は stderr のみで伝える。`Ask` は demote
されて exit `2` になる。

Cline adapter は Copilot と同じ理由付けを取る — Cline の file hook は経路に
よってプロセス失敗が fail-open になり得るため、reserved rule の deny も
含めて **すべて exit `0` + `cancel: true` JSON** で返す。`Ask` は demote
されて cancel JSON になる。`shouldContinue` は一切出さない。

## Update の境界

`ptuf update` は Decision エンジンを **経由しない**。`HookInput` を構築
することなく `std::process::Command` で `curl` / `cargo` / `gh` / `sh` /
`powershell` を spawn するだけの薄い shell-out で、policy / plugin /
audit 経路には一切触れない。fail-closed 契約 (`policy-load-failed`,
`invalid-payload`) も適用されない — update の失敗はネットワーク不通や
updater 非ゼロ exit などインフラ層の問題で、Decision 層の問題ではない。

ただし prebuilt installer 経路に限り **download → attestation verify →
execute** の 3 段階が走る: ptuf は `curl` (Unix) / `iwr` (Windows) で
installer script をプロセス専用 tmp に落とし、`gh attestation verify
<tmp> --repo watany-dev/ptuf` で artifact attestation を検証してから
ようやく `sh` / `powershell` で実行する。`gh` が PATH に無い場合は exit
`1` で download 済みファイルを残置し、ユーザが GitHub CLI を入れて手動
verify できるようにする。`--skip-attestation` (もしくは
`PTUF_UPDATE_SKIP_ATTESTATION=1`) はこの check を skip し、stderr に
`WARNING` を 1 行出して未検証 install であることを監査可能にする。
cargo install 経路は `--locked` で transitive deps を pin する以外
追加検証を持たない (cargo 自身が `.crate` の hash を検証するため)。

`self_paths::ProtectedPaths` の自己保護ルール (別の ptuf hook 経由で
`~/.cargo/bin/ptuf` 等が書換対象となった場合に deny する) と `ptuf
update` の binary 差し替えは互いに干渉しない: 前者は **他プロセス** の
tool call を hook して block する経路で、後者は ptuf 自身が子プロセスを
起動して updater に差し替えを委譲する経路だからである。同一バイナリを
別ホスト経由で書こうとすれば self-protection が依然 deny する。

## `ptuf audit` (計画中, issue #189)

`ptuf audit` も Decision エンジンを **経由しない**。stdin は読まず、
既存 JSONL を read-only で開く。`hook` / `check` の fail-closed 契約
(`policy-load-failed`, `invalid-payload`) は適用しない。exit `2` は
deny 専用なので使わない。

```text
ptuf [--json] audit [--path <FILE>] [--decision <deny|ask|monitor|allow>]
                    [--rule <ID>] [--tool <NAME>]
                    [--since <CANONICAL_RFC3339|<N>m|<N>h|<N>d>]
                    [--limit <N>] [--stats]
```

parse (`src/cli/parse.rs` の `parse_audit`):

- `--flag value` / `--flag=value` は既存 `parse_check` / `parse_update` と同型
- `--decision` は `allow` / `monitor` / `ask` / `deny` 以外を
  `ParseError::UnexpectedArgument` で reject (新 variant は足さない)
- `--limit` は十進 `usize`。非数値は `UnexpectedArgument`
- 明示 `--limit` と `--stats` は `ParseError::ConflictingFlags`
- `limit: Option<usize>`。未指定は `None` (一覧モードで 20、`--stats` では使わない)
- `--limit 0` は `Some(0)` (全件)
- `--since` は `parse_since(value, SystemTime::now())`。grammar / overflow
  失敗は `UnexpectedArgument`
- `--json` は既存どおり subcommand **の前** のみ (`ptuf --json audit`)

`Command::Audit(AuditOptions)` の追加は公開 enum の網羅 match を壊す
breaking change。`AuditOptions` も公開になるが、`src/audit/read.rs` は
`pub(crate)` のまま。

run (`src/cli/run.rs` の `run_audit`):

| 条件 | exit | stdout | stderr |
| --- | --- | --- | --- |
| 成功 (テキスト) | `0` | レコード行 or stats 行 | summary。`--json` では出さない |
| 成功 (JSON) | `0` | pretty JSON (`init` と同型 `to_string_pretty`) | 成功 summary なし |
| ファイル不在 | `0` | 空 / ゼロ件数 JSON | テキストなら summary のみ |
| `audit.enabled: false` (`--path` なし) | `0` | 既存レコード (無ければ空) | `audit is currently disabled; showing existing records` |
| 引数不正 | `1` | 空 | `ptuf: …` (`io_runner` の parse エラー経路) |
| HOME unset で default path 不能 (`--path` なし) | `1` | 空 | `audit disabled` とは書かない |
| `--path` なしで config load 失敗 | `1` | 空 | 既存 `ConfigError` |
| I/O error (permission / 途中 Read 失敗 / ディレクトリを開いた) | `1` | 空 | エラー |

`--path` があるときは config / `audit.enabled` / `$HOME` を見ない。
reader 契約・JSON schema・control character escape は
[`audit.md`](audit.md) を正本とする。

