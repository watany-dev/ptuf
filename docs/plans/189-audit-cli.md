# Plan: `ptuf audit` 閲覧 CLI — issue #189

Issue: https://github.com/watany-dev/ptuf/issues/189
Comment (設計レビュー): https://github.com/watany-dev/ptuf/issues/189#issuecomment-5301065892

本プランは **設計と実装手順** を固定する。書き込み経路 (engine / sink /
redaction / `AuditRecord` schema) は変更しない。

## Context

ptuf は deny / ask / monitor を既定で
`~/.local/share/ptuf/audit.jsonl` へ記録している
(`AuditConfig::default()` が `enabled: true` / `include_denied: true`)。
「何がブロックされたか」のデータは既にあるが、読む手段が `jq` 手書きしかない。
`docs/design/audit.md` も「専用閲覧 CLI は実装していない」と明記している。

本 issue は **閲覧手段の欠落だけ** を対象にする。レコードの情報量を増やす話
(`reason` / `session_id` / `cwd`) はスキーマ変更を伴うため別 issue。

## 現状 (HEAD 実測)

| 箇所 | 事実 |
| --- | --- |
| `src/audit/record.rs` | `AuditRecord` は `Serialize` のみ。`event` / `decision` / `mode` / `agent` が `&'static str` のため `Deserialize` 不可 |
| `src/audit/writer.rs` | JSON + `\n` を 1 回の `write_all` で append。呼び出し側が exclusive `File::lock` |
| `src/audit/mod.rs` `JsonlSink::record` | Unix `flock(2)` / Windows `LockFileEx` の exclusive lock。reader は未参加 |
| `src/audit/time.rs` `parse_rfc3339_to_secs` | canonical RFC3339 (`YYYY-MM-DDTHH:MM:SSZ` または `±HH:MM`)、秒精度。分数秒・lowercase `t` は reject |
| `src/config/mod.rs` `resolved_audit_path` | `enabled == false` と HOME 未設定をどちらも `None` に畳む。閲覧 CLI では使えない |
| `src/cli/mod.rs` `Command` | 公開 enum、`#[non_exhaustive]` ではない。variant 追加は SemVer breaking |
| `src/cli/parse.rs` | `--flag value` / `--flag=value` 両対応。不正値は既存 `ParseError` で reject |
| `src/cli/run.rs` | `run_with` ハーネスで JSON / text / エラー分岐を直接叩ける |
| `src/cli/run.rs` `MAX_HOOK_STDIN_BYTES` | 8 MiB。audit 1 行の上限とは別定数にする |
| MSRV | `1.93.0`。`std::fs::File::lock_shared` が使える |

追える / 追えない情報 (issue 整理、本プランでは変えない):

| 追える | 追えない |
| --- | --- |
| 発動時刻 / decision / ruleId / severity | deny の `reason` 文字列 |
| redaction 後のコマンド文字列 | Bash 以外の tool の対象パス (`(tool=Write)` のみ) |
| projectRoot / mode / modeDemoted / allowlistId | session_id / cwd |
| agent / pluginVersions | — |

## スコープ

read-only の `ptuf audit` を追加する。

```text
ptuf [--json] audit [--path <FILE>] [--decision <deny|ask|monitor|allow>]
                    [--rule <ID>] [--tool <NAME>]
                    [--since <CANONICAL_RFC3339|<N>m|<N>h|<N>d>]
                    [--limit <N>] [--stats]
```

実装の置き場所:

```text
src/audit/read.rs     pub(crate) JSONL reader (parse / validate / filter / tail / stats)
src/cli/parse.rs      parse_audit
src/cli/run.rs        run_audit (path 解決 / snapshot open / exit / render)
src/cli/mod.rs        Command::Audit(AuditOptions) + HELP
```

設計の正本は次のドキュメント (本プランと同時に更新する):

- [`docs/design/audit.md`](../design/audit.md) — reader 契約
- [`docs/design/cli-and-hooks.md`](../design/cli-and-hooks.md) — CLI 面
- [`docs/design/testing.md`](../design/testing.md) — テスト配置

## 非スコープ (別 issue)

- `AuditRecord` へのフィールド追加 (`reason` / `session_id` / `cwd`)
- JSONL ローテーション / サイズ上限 (ファイル全体)
- `--follow` (tail -f)
- `fuzz/` への reader ターゲット追加
- `resolved_audit_path` の意味変更 (書き込み経路を壊す)
- 新規クレート (`clap` 等)
- 新規 `ParseError` variant (既存 `UnexpectedArgument` / `ConflictingFlags` / `MissingValue` で足りる)

## 公開 API

`cli::Command` は公開かつ exhaustive。`Command::Audit(AuditOptions)` 追加は
**breaking change**。CHANGELOG は Added と Changed (BREAKING) の両方に書く。

`src/audit/read.rs` は `pub(crate) mod read`。reader 型を crates.io 公開 API
に載せない。

## 設計方針 (ponytail)

| 採る | 採らない |
| --- | --- |
| 既存 `parse_rfc3339_to_secs` を `--since` に再利用 | 新規日付パーサ |
| byte 行読み + `serde_json::from_slice` | `BufRead::lines()` (不正 UTF-8 で失敗する) |
| raw parse と validation の二段 | 全フィールド `Option` のまま表示する |
| 元 JSON object を `--json` 出力に保持 | typed view を再 serialize (未知フィールドが消える) |
| shared advisory lock で length snapshot | 読み取り中ずっと lock を握る |
| 既存 `ParseError` variant | `InvalidValue` 新設 |
| `run_audit` を `src/cli/run.rs` に追加 | `src/cli/audit.rs` 新ファイル |
| 1 行上限 `MAX_AUDIT_RECORD_BYTES` (1 MiB) | hook の 8 MiB 定数を流用して混同する |
