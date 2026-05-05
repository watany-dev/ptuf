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
`Engine::default()` へフォールバックする。

## Facts

`facts::extract()` が構築する主な shape:

| fact | 内容 |
| --- | --- |
| `bash` | `Bash` tool の `command` を parse した command / segment / pipeline |
| `path` | 先頭の file path (`Read` / `Edit` / `Write` / MCP の top-level `path`) |
| `paths` | 抽出された全 path |
| `url` | `WebFetch` または MCP の top-level `url` |
| `sensitive` | path / URL / write payload などから検出した機密分類 |
| `protected` | self-protection 対象との一致。engine 側で補完 |
| `project` | lock file、現在 branch、protected branch 判定。engine 側で補完 |

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

どちらも stdin の JSON payload を `HookInput` として評価するが、hook response の
扱いが異なる。

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
- JSON parse 失敗
- policy / plugin load 失敗時の hook response 生成失敗
- `doctor` / `plugin test` の内部エラー

## fail-closed

CLI 経路 (`hook`, `eval`) は config / plugin のロードに失敗すると
`core.engine.policy-load-failed` を返して fail-closed する。これは
`failClosed: false` でも変わらない。設定ファイル自体が読めない状況では、その設定を
信用できないためである。

一方、ライブラリ API `decide()` は組み込み呼び出しの後方互換性を優先し、
default engine にフォールバックする。

## audit

判定後、設定に応じて audit JSONL を追記する。詳細は [`audit.md`](audit.md) を
参照。
