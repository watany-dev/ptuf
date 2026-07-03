# アーキテクチャ

ptuf は CLI shim と判定コアを分けた構成を取る。`src/main.rs` は I/O のみを扱い、
実質的なロジックは `src/lib.rs` 配下に置く。

## 層構造

- **CLI shim** (`src/main.rs`, `src/io_runner.rs`, `src/cli/`)
  - argv を parse する
  - stdin / stdout / stderr を配線する
  - 終了コードを返す
- **判定コア** (`src/engine/` ほか)
  - config をロードする
  - facts を抽出する
  - built-in rule と plugin rule を評価する
  - `Decision` を集約し audit を記録する

`src/main.rs` は coverage 集計から除外する。新規ロジックは `src/lib.rs` 配下へ
置く。

## 実行パイプライン

```text
hook stdin JSON / eval argv
  ↓
CLI parse / dispatch
  ↓
Engine::for_cwd()
  ↓
facts::extract()
  ↓
built-in rules + plugin rules
  ↓
aggregate(deny > ask > monitor > allow)
  ↓
mode に応じて demote
  ↓
hook response / eval text / audit JSONL
```

`crate::decide()` だけは例外で、`Engine::for_cwd()` 失敗時に
`Engine::builder().agent("embed-fallback").build()` へフォールバックする。
builder は `ProtectedPaths::collect_with_env` を必ず通すため、`current_exe()`
由来の binary や HOME-rooted Claude/Codex settings といった self-protection
ターゲットは fallback 経路でも populate される (旧 `Engine::default()` シムは
P1 として削除)。embed 利用者は `Engine::builder()` 直接利用も可能。

## Facts

`facts::extract()` が構築する主な shape:

| fact | 内容 |
| --- | --- |
| `bash` | `Bash` tool の `command` を parse した command / segment / pipeline。`Pipeline.redirects` で `>` / `>>` / `<` / `2>` / `&>` / heredoc の operator と target を保持する。`Bash::has_command_substitution` / `has_redirect` / `has_heredoc` / `has_process_substitution` で `` ` … ` `` / `$(…)` / リダイレクト / heredoc / `<(…)` `>(…)` の存在を surface する。`Argv.inner_argv` / `inner_code` / `inner_redirects` は `bash -c`, `su -c`, `eval`, `xargs`, `find -exec` の内側 command と redirect を bounded depth で再 parse し、既存 rule と self-protection が inspectable な形に連結する |
| `path` | 先頭の file path (`Read` / `Edit` / `Write` / MCP の top-level `path`)。`PathFact` として `raw` / `expanded` / `absolute` / `canonical_or_raw` / `origin` を保持する |
| `paths` | tool 入力 (`Read` / `Edit` / `Write` / `apply_patch` / MCP) 由来の全 `PathFact`。`Read` / `Edit` / `Write` の `paths[]` (string array) と `operations[].path` (object array) も canonical な `file_path` と並んで重複排除しつつ収集する (Kiro batch read/write 経路用)。Bash redirect target はここには含まれない (engine が self-protection 用に別 slice として供給する) |
| `url` | `WebFetch` または MCP の top-level `url` |
| `sensitive` | path / URL / write payload などから検出した機密分類 |
| `protected` | self-protection 対象との一致。engine 側で `Facts.paths` と Bash redirect target (`Pipeline.redirects[].target` に加え wrapper 由来の `Argv.inner_redirects[].target`) を `ProtectedPaths::classify_input_with_paths_pair` に二本のスライスとして渡して補完する。戻り値は固定長の `ProtectedKinds` (`[ProtectedKind; 9] + len`) で、中間 path clone や `ProtectedKind` 用 heap allocation は発生させない |
| `project` | lock file、現在 branch、protected branch 判定。engine 側で補完 |

`PathFact.origin` は `ToolInputDirect` (top-level `file_path` / MCP `path`) /
`ToolInputNested` (`files[].path` / `paths[]` / `items[].path`) /
`ApplyPatch` (`*** Add/Update/Delete/Move` 行) / `BashRedirect` (`>` / `>>` /
`<` / `2>` / `&>` の operand。`1>` 等の数値 fd 形も同じ shape に collapse
されて含まれる。engine のみが emit する) の 4 種で、書込み先かど
うかの判定や cross-tool 一貫性の根拠に使う。`canonical_or_raw` は構築時に 1
回だけ `canonicalize()` を試み、I/O 失敗時は `absolute` に fallback する
(symlink loop / permission denied / 未存在 path で panic しない不変条件)。

plugin `requires:` と `when:` DSL から参照できる fact 名は現在次に限る:

- `shell.ast`
- `shell.argv`
- `shell.pipeline`
- `tool`
- `event`
- `path`
- `url`
- `sensitive_path`

## Agent adapter

現在の adapter は 7 つ。

- `claude-code`
- `codex`
- `copilot` (GitHub Copilot)
- `kiro` (Kiro CLI)
- `cline` (Cline)
- `cursor` (Cursor)
- `pi` (Pi Coding Agent)
- `opencode` (OpenCode)

adapter は stdin payload をまず `RawHookInput` として受け、内部では
normalized `Event { agent, event, tool, inputs, paths, urls, content }`
ビューへ変換して fact 抽出に渡す。公開 API は後方互換のため `HookInput` を維持
する。hook response の扱いは agent ごとに次の差分を持つ。

- Claude Code: `Ask` はそのまま `permissionDecision = "ask"`、`Deny` は exit `2`
- Codex: `Ask` は `Deny` へ変換して block (exit `2`)
- Copilot: `Ask` は `Deny` へ demote。すべての Decision で exit `0` を返し、
  `Deny` は `hookSpecificOutput` で wrap せず *bare* JSON envelope
  (`{"permissionDecision":"deny","permissionDecisionReason":"…"}`) を stdout
  に書く。Copilot protocol が non-zero exit を hook *failure* として扱い得る
  ため、reserved rule (`core.engine.invalid-payload` /
  `core.engine.policy-load-failed`) も exit `0` + bare deny JSON で fail-closed
  する。
- Kiro: hook protocol が JSON envelope を持たないため、stdout は常に空。
  `Ask` / `Deny` の reason は stderr に書き、`Deny` (および demote された
  `Ask`) は exit `2`。reserved rule の fail-closed も同経路で扱う。
- Cline: `Ask` は `Deny` へ demote。すべての Decision で exit `0` を返す。
  `Allow` / `Monitor` は stdout に `{}`、`Deny` (および demote された
  `Ask`) は `{"cancel":true,"errorMessage":"…"}` JSON を stdout に書く。
  Cline の file hook が non-zero exit を hook *failure* として扱い得るため、
  reserved rule (`core.engine.invalid-payload` /
  `core.engine.policy-load-failed`) も exit `0` + cancel JSON で fail-closed
  する。`shouldContinue` は一切出さない。
- Cursor: Claude Code と同じく独自の `Ask` channel を持つため `Ask` を
  降格せず保持する。`Allow` / `Monitor` は stdout 空 + exit `0`、`Ask` は
  bare `{"permission":"ask","user_message":"…","agent_message":"…"}` + exit `0`、
  `Deny` は `permission` を `deny` にして exit `2`。reserved rule も bare
  `permission:deny` JSON + exit `2` で fail-closed する。Cursor の全機能ではなく
  hook 駆動の agent tool execution のみが対象 (Tab 補完・手動編集・手動
  ターミナルは hook を経由しないため対象外)。
- Pi: TypeScript extension が raw tool event を `ptuf hook pi` に渡す。
  すべての Decision で bare `{"decision":"…"}` JSON を stdout に書き、
  `Ask` を降格せず保持する (Cursor と同型)。`Allow` / `Monitor` / `Ask` は
  exit `0`、`Deny` と reserved rule は exit `2`。正規化は
  `src/cli/pi_input.rs` で行う。

Copilot 入力は CLI 層の `src/cli/copilot_input.rs` で snake (`tool_name` /
`tool_input`) と camel (`toolName` / `toolArgs`) の両形を正規化し、tool 名
mapping (`bash`→`Bash`, `view`→`Read`, `edit`→`Edit`, `create`→`Write`,
`web_fetch`→`WebFetch`, `powershell`→`Bash`) を適用する。

Kiro 入力は CLI 層の `src/cli/kiro_input.rs` で `hook_event_name == "preToolUse"`
を検証したうえで tool 名を canonical 形へ正規化する
(`shell` / `execute_bash` / `execute_cmd`→`Bash`、`read` / `fs_read` / `fsRead`
→`Read`、`write` / `fs_write` / `fsWrite`→`Write`、`web_fetch` / `webFetch`
→`WebFetch`、`@server/tool`→`mcp__server__tool`)。`tool_input` も
`command` (`cmd` / `script` をフォールバック)、`file_path` (`path` / `paths[0]`
/ `operations[0].path` 等をフォールバック)、`content` (`text` / `new_content`
をフォールバック) のキーに正規化する。

Cline 入力は CLI 層の `src/cli/cline_input.rs` で SDK 形 (`tool_call`) と
legacy 形 (`preToolUse`) の両 envelope を正規化する。`tool_call` がある場合は
`hookName == "tool_call"` を要求して優先採用し、無ければ `preToolUse` を
`hookName ∈ {"PreToolUse","tool_call"}` で採用する。tool 名 mapping
(`run_commands` / `execute_command` / `bash`→`Bash`、`read_files`→`Read`、
`write_file`→`Write`、`use_mcp_tool`→`mcp__server__tool` 等) を適用し、
alias キー (`command` / `file_path` / `content` 等) を非破壊的に正規化する。
canonical 化した tool 名と `tool_call` の id は `_cline_tool_name` /
`_cline_tool_call_id` として `tool_input` に保持する。

Pi 入力は CLI 層の `src/cli/pi_input.rs` で Pi native tool 名を canonical
形へ正規化する (`bash`→`Bash`, `grep`→`mcp__pi__grep`, unknown→`mcp__pi__*`,
`path`→`file_path` など)。

Cursor 入力は CLI 層の `src/cli/cursor_input.rs` で `hook_event_name`
(camelCase `hookEventName` 互換) を event dispatcher として正規化する。
enforce 対象は `preToolUse` (tool 名を canonical 形へ正規化) /
`beforeShellExecution`→`Bash` / `beforeReadFile`→`Read` /
`beforeMCPExecution`→`mcp__server__tool` で、それ以外の event は MVP では
`core.engine.invalid-payload` で fail-closed する。tool 名 mapping
(`Shell` / `Bash`→`Bash`、`Read` / `ReadFile`→`Read`、`Write`→`Write`、
`Edit`→`Edit`、`Fetch`→`WebFetch`、`MCP` / `mcp__*`→`mcp__server__tool`) を
適用し、`tool_input` (camelCase `toolInput` / root も読む) の `command` /
`file_path` / `content` / `old_string` / `new_string` を alias から非破壊的に
複製する。`tool_input` が JSON 文字列なら parse し、失敗時は `{"text":…}` で
保持する。

判定 engine 自体は agent 非依存で、adapter 拡張は CLI 層に閉じている。

## I/O 契約

### hook

入力:

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "ls"
  }
}
```

stdin payload は最大 8 MiB。上限超過時は JSON parse に進まず exit `1`。

出力:

| コマンド | stdout | stderr | exit |
| --- | --- | --- | --- |
| `ptuf hook claude-code` | `Ask` / `Deny` のときだけ `hookSpecificOutput` JSON | `Ask` / `Deny` reason | `0` or `2` |
| `ptuf hook codex` | `Deny` のときだけ `hookSpecificOutput` JSON | deny reason | `0` or `2` |
| `ptuf hook copilot` | `Deny` のときだけ bare JSON envelope (no `hookSpecificOutput`) | deny reason | 常に `0` (stdout serialize 失敗のみ `1`) |
| `ptuf hook kiro` | 常に空 (Kiro hook には JSON envelope が無い) | `Ask` / `Deny` reason | `0` or `2` |
| `ptuf hook cline` | `Allow` / `Monitor` は `{}`、`Deny` は cancel JSON envelope | deny reason | 常に `0` (stdout serialize 失敗のみ `1`) |
| `ptuf hook cursor` | `Allow` / `Monitor` は bare `permission:allow` JSON、`Ask` / `Deny` は bare JSON | `Ask` / `Deny` reason | `0` or `2` |
| `ptuf hook pi` | すべての Decision で bare `decision` JSON | `Ask` / `Deny` reason | `0` or `2` |

### check

`ptuf check --tool <name> <command>` は stdout に人間可読な判定結果を書き、reason が
ある場合だけ stderr に出す。

| Decision | exit |
| --- | --- |
| `Allow` / `Monitor` / `Ask` | `0` |
| `Deny` | `2` |

### 内部エラー

以下は exit `1`:

- argv parse 失敗
- `plugin check` の内部エラー
- `init` の書き込み失敗 / verify 失敗

`hook` サブコマンドは Claude Code の hook 仕様 (exit 1 は non-blocking warning) に
追従するため、stdin 系の初期化エラーは exit `1` ではなく exit `2` + deny で扱う。
詳細は次節を参照。

## fail-closed

CLI 経路 (`hook`, `eval`) は config / plugin のロードに失敗すると
`core.engine.policy-load-failed` を返して fail-closed する。これは
`failClosed: false` でも変わらない。設定ファイル自体が読めない状況では、その設定を
信用できないためである。

`hook` はさらに stdin 読み取り失敗 / 8 MiB 上限超過 / JSON parse 失敗を
`core.engine.invalid-payload` で deny する (exit `2` + adapter の deny JSON)。
Claude Code の hook 仕様では exit `1` が non-blocking warning として扱われ
tool 実行を止めないため、これらの初期化エラーを exit `1` のまま放置すると
fail-open する。`failClosed: false` でもこの境界は緩めない。

一方、ライブラリ API `decide()` は組み込み呼び出しの後方互換性を優先し、
default engine にフォールバックする。`try_decide()` は CLI と同じ
fail-closed 契約を embed 利用側に提供する並立 API である。

## audit

判定後、設定に応じて audit JSONL を追記する。詳細は [`audit.md`](audit.md) を
参照。

timestamp と allowlist expiry の RFC3339 処理は `time` crate に委譲する。
自前の年月日計算は持たない。
