# アーキテクチャ

ptuf は CLI shim と判定コアを分けた構成を取る。`src/main.rs` は I/O のみを扱い、
実質的なロジックは `src/lib.rs` 配下に置く。

## 層構造

- **CLI shim** (`src/main.rs`, `src/io_runner.rs`, `src/cli.rs`)
  - argv を parse する
  - stdin / stdout / stderr を配線する
  - 終了コードを返す
- **判定コア** (`src/engine.rs` ほか)
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
| `bash` | `Bash` tool の `command` を parse した command / segment / pipeline。`Pipeline.redirects` で `>` / `>>` / `<` / `2>` / `&>` / heredoc の operator と target を保持する。`Bash::has_command_substitution` / `has_redirect` / `has_heredoc` / `has_process_substitution` で `` ` … ` `` / `$(…)` / リダイレクト / heredoc / `<(…)` `>(…)` の存在を surface する。`Argv.inner_argv` / `inner_code` / `inner_redirects` は `bash -c`, `eval`, `xargs`, `find -exec` の内側 command と redirect を bounded depth で再 parse し、既存 rule と self-protection が inspectable な形に連結する |
| `path` | 先頭の file path (`Read` / `Edit` / `Write` / MCP の top-level `path`)。`PathFact` として `raw` / `expanded` / `absolute` / `canonical_or_raw` / `origin` を保持する |
| `paths` | tool 入力 (`Read` / `Edit` / `Write` / `apply_patch` / MCP) 由来の全 `PathFact`。Bash redirect target はここには含まれない (engine が self-protection 用に別 slice として供給する) |
| `url` | `WebFetch` または MCP の top-level `url` |
| `sensitive` | path / URL / write payload などから検出した機密分類 |
| `protected` | self-protection 対象との一致。engine 側で `Facts.paths` と Bash redirect target (`Pipeline.redirects[].target` に加え wrapper 由来の `Argv.inner_redirects[].target`) を `ProtectedPaths::classify_input_with_paths_pair` に二本のスライスとして渡して補完する (中間 `Vec` の clone は発生させない) |
| `project` | lock file、現在 branch、protected branch 判定。engine 側で補完 |

`PathFact.origin` は `ToolInputDirect` (top-level `file_path` / MCP `path`) /
`ToolInputNested` (`files[].path` / `paths[]` / `items[].path`) /
`ApplyPatch` (`*** Add/Update/Delete/Move` 行) / `BashRedirect` (`>` / `>>` /
`<` / `2>` / `&>` の operand。engine のみが emit する) の 4 種で、書込み先かど
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

現在の adapter は 2 つ。

- `claude-code`
- `codex`

adapter は stdin payload をまず `RawHookInput` として受け、内部では
normalized `Event { agent, event, tool, inputs, paths, urls, content }`
ビューへ変換して fact 抽出に渡す。公開 API は後方互換のため `HookInput` を維持
する。hook response の扱いは agent ごとに次の差分を持つ。

- Claude Code: `Ask` はそのまま `permissionDecision = "ask"`
- Codex: `Ask` は `Deny` へ変換して block する

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

### eval

`ptuf eval --tool <name> <command>` は stdout に人間可読な判定結果を書き、reason が
ある場合だけ stderr に出す。

| Decision | exit |
| --- | --- |
| `Allow` / `Monitor` / `Ask` | `0` |
| `Deny` | `2` |

### 内部エラー

以下は exit `1`:

- argv parse 失敗
- stdin 読み取り失敗
- stdin payload 上限超過
- JSON parse 失敗
- policy / plugin load 失敗時の hook response 生成失敗
- `doctor` / `plugin test` の内部エラー

## fail-closed

CLI 経路 (`hook`, `eval`) は config / plugin のロードに失敗すると
`core.engine.policy-load-failed` を返して fail-closed する。これは
`failClosed: false` でも変わらない。設定ファイル自体が読めない状況では、その設定を
信用できないためである。

一方、ライブラリ API `decide()` は組み込み呼び出しの後方互換性を優先し、
default engine にフォールバックする。`try_decide()` は CLI と同じ
fail-closed 契約を embed 利用側に提供する並立 API である。

## audit

判定後、設定に応じて audit JSONL を追記する。詳細は [`audit.md`](audit.md) を
参照。
