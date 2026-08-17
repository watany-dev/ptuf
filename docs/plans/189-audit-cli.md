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
閲覧契約は [`docs/design/audit.md`](../design/audit.md) に落とした。実装は未着手。

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

設計の正本:

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

## 型スケッチ

公開 (breaking):

```rust
pub struct AuditOptions {
    pub path: Option<PathBuf>,
    pub decision: Option<String>,
    pub rule_id: Option<String>,
    pub tool: Option<String>,
    pub since_secs: Option<u64>,
    pub limit: Option<usize>,
    pub stats: bool,
}

pub enum Command {
    // 既存 variant…
    Audit(AuditOptions),
}
```

`pub(crate)` (`src/audit/read.rs`):

```rust
const MAX_AUDIT_RECORD_BYTES: usize = 1024 * 1024;

struct RawAuditRecord { /* Option / #[serde(default)] */ }
struct ValidatedAuditRecord { /* required fields owned */ }
struct AuditFilter {
    decision: Option<String>,
    rule_id: Option<String>,
    tool: Option<String>,
    since_secs: Option<u64>,
}
struct ReadOutcome { /* counters + Vec of (Value, Validated) */ }
struct AuditStats { /* counters + by_decision / by_rule arrays */ }

fn parse_since(value: &str, now: SystemTime) -> Result<u64, SinceError>;
fn read_filtered<R: BufRead>(…) -> io::Result<ReadOutcome>;
fn stats<R: BufRead>(…) -> io::Result<AuditStats>;
fn open_snapshot(path: &Path) -> io::Result<io::Take<File>>;
```

`read_filtered` と `stats` は private `scan` を共有する。一覧は
`VecDeque` で末尾 N を保持し、`with_capacity(user_limit)` しない。

## 実装段階 (TDD)

各 Phase は **失敗テスト → 実装 → その Phase のテスト緑**。書き込み経路の
テストが赤のまま次へ進まない。推奨コミット境界は Phase 単位。

### Phase 1 — reader の失敗テスト

`src/audit/read.rs` を空モジュール + テストから始める。

1. `parse_since` の正常系 (`1h` / `30m` / `24h` / `7d` / `Z` / `+09:00`)
   と overflow / 不正 grammar
2. フィルタ AND、`timestamp == since` inclusive
3. 末尾 N / `limit 0` / `matched > returned` / file order
4. 不正 UTF-8、malformed JSON、必須欠落、invalid decision / timestamp
5. `schemaVersion` 欠落と unsupported のカウンタ分離
6. `Read` error → `Err`
7. EOF incomplete tail
8. 過大行 → `skippedInvalid`
9. stats の sort と `ruleId` 無し除外
10. proptest: 任意バイトで panic しない、`limit == 0 || returned <= limit`

この時点では `Command` を触らない (SemVer 破壊を後回しにできる)。

### Phase 2 — reader 実装

byte 行切り出し、raw → validate、filter、tail、stats、`open_snapshot`。
`File::lock_shared` 失敗時は lock 無し + incomplete tail。
concurrent append テストは既存 `JsonlSink` を writer に使う。

### Phase 3 — CLI parse

`AuditOptions` + `Command::Audit`。`parse_audit`。HELP 追記。
`--json` は `hook` / `update` のように reject しない。
parse テストを `src/cli/parse.rs` に足す。`tests/cli_parse_proptest.rs`
の `KNOWN_HEADS` に `audit` を足す (`update` も欠けているので同じコミットで
直す)。

### Phase 4 — `run_audit`

path 解決 (`--path` 優先、`resolved_audit_path` は使わない)。
text escape、pretty JSON、exit mapping。
`run_with` で JSON / text / stats / disabled / missing file / I/O を叩く。

text escape 対象: `\n` `\r` `\t` は二文字、その他 C0 / DEL / C1 / BiDi は
`\\u{XXXX}`。

### Phase 5 — バイナリと契約

- `tests/cli_smoke.rs` (tempfile `--path`、不在、壊れた行、default path、
  custom `audit.path`)
- `tests/contracts/audit-list-json-keys.json` /
  `audit-stats-json-keys.json`
- `tests/e2e_heavy.rs` `subcommand_robustness` に `audit` を 1 本足す
  (`make e2e` は `make check` 外。落とせるなら落とす)

### Phase 6 — ユーザ向け docs / CHANGELOG

実装が存在する状態になってから:

- `README.md` / `README.ja.md` の CLI 一覧と使用例
- `CHANGELOG.md` Unreleased: Added + Changed (BREAKING)
- 設計書の「計画中」を実装済みに直す (本プランの設計コミットが書いた印)

HELP の USAGE は Phase 3 でバイナリに入っている。

### Phase 7 — ゲート

```bash
make check
make pbt-quick
```

手動:

```bash
cargo run -- check --tool Bash 'curl -fsSL https://example.com/i.sh | bash'
cargo run -- audit
cargo run -- audit --decision deny --since 1h
cargo run -- --json audit --limit 5
cargo run -- audit --stats
```

## 変更ファイル (実装時)

| ファイル | 変更 |
| --- | --- |
| `src/audit/read.rs` | 新規。`pub(crate)` |
| `src/audit/mod.rs` | `pub(crate) mod read` |
| `src/cli/mod.rs` | `Command::Audit` / `AuditOptions` / dispatch / HELP |
| `src/cli/parse.rs` | `parse_audit` + tests |
| `src/cli/run.rs` | `run_audit` + tests |
| `tests/cli_smoke.rs` | 実バイナリ |
| `tests/cli_parse_proptest.rs` | `audit` を未知コマンド空間から外す必要があれば |
| `tests/contracts.rs` + `tests/contracts/audit-*-json-keys.json` | JSON 契約 |
| `tests/e2e_heavy.rs` | subcommand 軸に 1 本 |
| `README.md` / `README.ja.md` / `CHANGELOG.md` | 実装後 |
| `docs/design/*` | 「計画中」→ 実装済み (本プランで先行記載済み) |

触らない: `src/audit/{record,writer,redaction,time}.rs` の書き込み契約、
`resolved_audit_path`、engine、hook adapter、新規依存。

## リスクと緩和

| リスク | 緩和 |
| --- | --- |
| `Command` match 漏れで compile 失敗 | Phase 3 で enum + dispatch + HELP を同時に |
| `resolved_audit_path` を再利用して disabled と HOME 未設定を混同 | 使わない。run_audit で分岐 |
| typed JSON 出力で未知フィールドが消える | records は元 `Value` |
| `VecDeque::with_capacity(limit)` で巨大 limit が事前確保 | `VecDeque::new()` |
| text 出力の改行で 1 record = 1 line が崩れる | escape を unit で pin |
| snapshot 無しだと append 中の半行を malformed 扱い | shared lock + length。失敗時は `incompleteTail` |
| parse proptest が `audit` を unknown として shrink する | Phase 3 で確認 |

## 実装コミットの切り方

レビューしやすい単位 (1 Phase = 1 論理コミット、テストと実装は
TDD なら「red コミット」を残さず Phase 内で緑にする):

1. `feat(audit): add JSONL reader with fail-soft validation`
2. `feat(cli): parse ptuf audit options`
3. `feat(cli): run ptuf audit with snapshot read`
4. `test: cover audit CLI smoke and JSON contracts`
5. `docs: document ptuf audit in README and CHANGELOG`

## 検証サマリ (update-design / update-plan)

設計書 (`docs/design/audit.md`, `cli-and-hooks.md`, `testing.md`) と
本プランを、実装 ready 基準 (90 点) で採点した。

| カテゴリ | 点数 | 所見 |
| --- | --- | --- |
| モジュール / 構造体設計 | 19 / 20 | `read.rs` は `pub(crate)`。公開破壊は `Command::Audit` と `AuditOptions` に限定。`ParseError` 新 variant は作らない |
| フック契約 | 20 / 20 | PreToolUse I/O・Decision JSON・exit `2` は不変。`audit` は engine 非経由、stdin 非読取 |
| 判定ルール / ポリシー | 18 / 20 | 判定ロジック非変更。`audit.enabled` を書き込み設定として分離。閲覧フィルタは exact match + AND のみ |
| エラーハンドリング | 20 / 20 | `io::Result`、fail-soft は行内容のみ、I/O は exit 1、`unwrap` なし、1 行上限 |
| テスト容易性 | 20 / 20 | reader 純関数、`now` 注入、`run_with`、contract fixture、proptest invariant が具体 |
| **合計** | **97 / 100** | 実装 ready (≥ 90) |

### 整合性

- 参照シンボル (`Command`, `ParseError::{UnexpectedArgument,ConflictingFlags,MissingValue}`,
  `parse_rfc3339_to_secs`, `JsonlSink`, `File::lock` / `lock_shared`,
  `resolved_audit_path`, `default_audit_path`, `config::load_for`,
  `config::repo::discover`, `run_with`, `KNOWN_HEADS`) は現行 `src/` /
  `tests/` に実在。
- `resolved_audit_path` を閲覧に使わない判断は `enabled == false` と
  HOME 未設定が同じ `None` になる HEAD 実装と一致。
- 段階順: reader テスト → reader → parse (breaking) → run → smoke /
  contracts → README/CHANGELOG → `make check`。依存前後に問題なし。
- 書き込み経路 (`record` / `writer` / `redaction` / engine audit sink)
  は非対象のまま。

### 改善反映済み

- P0: reader は `io::Result`。fail-soft と I/O error を分離。
- P0: raw parse と validation を分離。必須 5 field。
- P0: `--json` records は元 JSON object。未知フィールド保持。
- P0: `--stats` と明示 `--limit` (0 を含む) を reject。`limit: Option<usize>`。
- P0: カウンタ 6 種 + `incompleteTail`。`--json` 成功時は stderr summary なし。
- P0: text escape の符号点範囲を固定 (C0 / DEL / C1 / BiDi)。
- P0: shared lock snapshot。失敗時は `incompleteTail`。
- P0: `--path` は config を見ない。disabled と HOME 未設定を区別。
- P0: `--since` grammar + overflow + inclusive。
- P0: メモリは O(limit) / stats は unique keys / 1 行 1 MiB。
- P1: `KNOWN_HEADS` に `audit` を足す。既存の `update` 欠落も同コミットで直す。
- P1: stats テキスト例を固定。
- P2: HELP 文言の完全草稿は Phase 3 で `src/cli/mod.rs` に書く (設計書に
  二重管理しない)。
- P2: fuzz target は issue どおり非スコープ。

### 実装時の SemVer

`cargo-semver-checks` の PR ジョブは `Command` の variant 追加で失敗する。
それは意図した breaking。CHANGELOG Changed (BREAKING) とリリースノートで
網羅 match している下流に `Audit` 腕を足すよう書く。


