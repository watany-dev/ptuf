# Audit Log

ptuf は判定結果を JSONL で記録できる。1 行が 1 レコードで、既定では strict
redaction を通してから書き込む。

## デフォルトパス

```text
~/.local/share/ptuf/audit.jsonl
```

`audit.enabled: false` で無効化でき、`audit.path` で上書きできる。

## スキーマ

```json
{
  "schemaVersion": 1,
  "timestamp": "2026-05-04T12:00:00Z",
  "event": "PreToolUse",
  "tool": "Bash",
  "decision": "deny",
  "ruleId": "core.network.remote-script-pipe",
  "severity": "critical",
  "commandRedacted": "curl -fsSL https://example.com/install.sh | bash",
  "projectRoot": "/repo/example",
  "mode": "enforce",
  "agent": "claude-code",
  "pluginVersions": ["acme.security@0.1.0"]
}
```

| フィールド | 型 | 説明 |
| --- | --- | --- |
| `schemaVersion` | `u32` | 現在は常に `1` |
| `timestamp` | RFC3339 string | UTC 時刻。`time` crate で UTC 秒精度に format する |
| `event` | string | 現在は常に `PreToolUse` |
| `tool` | string | `HookInput.tool_name` |
| `decision` | string | `allow` / `monitor` / `ask` / `deny` |
| `ruleId` | string \| null | `Allow` 以外で対応 rule がある場合 |
| `severity` | string \| null | `info` / `low` / `medium` / `high` / `critical` |
| `commandRedacted` | string | redaction 後の command または `(tool=<name>)` |
| `projectRoot` | string \| null | repo root が分かった場合 |
| `mode` | string | `enforce` / `monitor` |
| `modeDemoted` | bool | deny が monitor に降格された場合のみ `true` で出力 |
| `allowlistId` | string \| null | allowlist suppression で `Allow` になった場合のみ |
| `agent` | string | `claude-code` / `codex` / `copilot` / `kiro` / `cline` / `cli` / `unknown` |
| `pluginVersions` | string[] | 読み込んだ plugin の `name@version`。空なら省略 |

## 記録条件

```yaml
audit:
  enabled: true
  includeAllowed: false
  includeDenied: true
  redaction: strict
```

- `Allow` は `includeAllowed: true` のときだけ記録
- `Deny` は `includeDenied: true` のときだけ記録
- `Monitor` と `Ask` は常に記録

## Redaction

`redaction: strict` では以下を伏せる。

- `TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `CREDENTIAL`, `PRIVATE` を
  含む env assignment (`KEY=VALUE` 形式) と JSON object
  (`"KEY": "VALUE"` 形式) の値
- GitHub classic token (`ghp_…` / `gho_…` / `ghu_…` / `ghs_…` /
  `ghr_…`) と GitHub fine-grained PAT (`github_pat_…`)
- Slack token (`xoxa-` / `xoxb-` / `xoxp-` / `xoxr-` / `xoxs-`)
- Stripe API key (`sk_live_…` / `sk_test_…` / `pk_live_…` /
  `pk_test_…` / `rk_live_…` / `rk_test_…` / `whsec_…`)
- OpenAI 系 key (`sk-…`)、AWS Access Key ID (`AKIA…`)、JWT 3-segment
- URL 中の basic auth password
- PEM blob (`-----BEGIN … PRIVATE KEY-----`)

`redaction: off` も実装されているが、意図的な opt-in 用である。

## 運用メモ

- writer は JSONL を追記するだけで、ローテーションは行わない
- 1 record ごとに OS レベルの advisory lock を取って書き込むため、
  複数 ptuf プロセスが同じ JSONL に同時 append しても行が混ざらない
  (Unix は `flock(2)`、Windows は `LockFileEx`)
- NFS など advisory lock が no-op になる FS では原子性を保証できないため、
  ローカルファイルシステム上に置くこと
- 閲覧 CLI (`ptuf audit`) の契約は次節。実装は issue #189
  ([プラン](../plans/189-audit-cli.md))
- audit sink の **open 失敗** は `Engine::audit_warning()` に保持される。
  CLI は `Engine::audit_warning_for_decision()` を使い、その decision が
  audit 記録対象 (`Allow` は `includeAllowed: true` の場合のみ、`Deny` は
  `includeDenied: true` の場合のみ、`Ask` / `Monitor` は常時) だったときだけ
  stderr に流す。**書き込み失敗** (permission / disk full) は
  `Engine::drain_audit_write_warnings()` に蓄積し、CLI が hook / eval 完了後に
  stderr へドレインする — どちらも tool 実行は止めない (best-effort 契約)

## 閲覧 CLI (`ptuf audit`) — 計画中 (issue #189)

書き込み経路は変更しない。本節は read-only の閲覧契約である。

### 責務分離

```text
src/audit/read.rs   pub(crate)
  byte-oriented JSONL reader
  ├─ raw parse
  ├─ schema validation
  ├─ filter
  ├─ bounded tail collection
  └─ stats

src/cli/parse.rs    parse_audit
src/cli/run.rs      run_audit (path 解決 / snapshot / exit / render)
```

`AuditRecord` (`src/audit/record.rs`) は `&'static str` を持つ Serialize
専用型のままにする。reader は別型を新設する。

### パースと validation

```text
JSON bytes
  ├─ serde_json::Value          → `--json` の records にそのまま出す
  └─ RawAuditRecord             → Option / #[serde(default)]
       ↓ validate
     ValidatedAuditRecord       → filter / stats / text render
```

`BufRead::lines()` は使わない。byte 単位で行を切り、
`serde_json::from_slice` に渡す (不正 UTF-8 を malformed として扱える)。

必須フィールド (欠落・不正値は `skippedInvalid`):

- `schemaVersion`
- `timestamp` (canonical RFC3339。`parse_rfc3339_to_secs` が `Some`)
- `decision` (`allow` / `monitor` / `ask` / `deny`)
- `tool`
- `commandRedacted`

`schemaVersion` があり、かつ `1` 以外 → `skippedUnsupportedSchema`
(JSON 破損とは別カウンタ)。`schemaVersion` 欠落は `skippedInvalid`。

後から schema v1 に足された additive field は optional のまま。未知
フィールドは deserialize 時に許容し、`--json` 出力では消さない。

### fail-soft と I/O エラー

reader API は `io::Result` を返す。fail-soft は「読めた行の内容が壊れて
いる」場合に限定する。

```rust
fn read_filtered<R: BufRead>(
    reader: R,
    filter: &AuditFilter,
    limit: usize,
) -> io::Result<ReadOutcome>;

fn stats<R: BufRead>(
    reader: R,
    filter: &AuditFilter,
) -> io::Result<AuditStats>;
```

| ケース | 扱い | exit |
| --- | --- | --- |
| malformed JSON / 必須 field 不正 / 不正 UTF-8 | skip + `skippedInvalid` | 0 |
| 空白のみの行 | `linesRead` に含め、skip。`skippedInvalid` にはしない | 0 |
| unsupported `schemaVersion` | skip + `skippedUnsupportedSchema` | 0 |
| EOF の newline 未終端行 | `incompleteTail: true`。`skippedInvalid` にはしない | 0 |
| 1 行が `MAX_AUDIT_RECORD_BYTES` (1 MiB) を超える | 次の `\n` または snapshot 末端まで破棄 + `skippedInvalid` | 0 |
| 実際の I/O error (途中の `Read` 失敗を含む) | `Err` | 1 |
| ファイル不在 | reader を呼ばず空結果 | 0 |

### フィルタ

AND 結合。未指定のキーは制限しない。

| フラグ | 一致条件 |
| --- | --- |
| `--decision` | `ValidatedAuditRecord.decision` の exact match |
| `--rule` | `ruleId` の exact match。`ruleId` 欠落レコードは不一致 |
| `--tool` | `tool` の exact match |
| `--since` | `timestamp` の epoch 秒 `>= since` (inclusive) |

### `--since` grammar

```text
--since <CANONICAL_RFC3339|<N>m|<N>h|<N>d>
```

- 相対: 1 個以上の ASCII 数字 `N` + `m` / `h` / `d` (`30m`, `1h`, `24h`,
  `7d`)。符号・小数点・空白は reject。`0m` は受理 (`since = now`)
- 絶対: 既存 `audit::time::parse_rfc3339_to_secs` の canonical form
  (`2026-08-15T09:00:00Z` / `2026-08-15T18:00:00+09:00`)。分数秒・
  lowercase `t`・colon 無し offset は reject
- 相対計算は `checked_mul` / `checked_sub`。overflow は reject
  (`now` が epoch 近くで `N` が大きい場合を含む)
- `now` は引数注入 (`parse_since(value, now) -> Result<u64, SinceError>`)

help 文言は「RFC3339」ではなく canonical form / 秒精度を書く。

### 末尾 N 件とメモリ

「最新 N 件」は timestamp sort ではなく JSONL の append / file order の
末尾 N 件。出力順も file order (古い → 新しい)。

- 一覧モードで `limit > 0`: 保持レコード数を O(limit) に抑える
  (`VecDeque`。`with_capacity(limit)` で user input を事前確保しない)
- `limit = 0`: 全 matched records を保持する
- stats: O(unique decision + unique ruleId)
- 1 行の読み込みは `MAX_AUDIT_RECORD_BYTES` で別途上限

proptest の返却件数: `limit == 0 || returned <= limit`。

### snapshot read

writer は exclusive lock で 1 record を serialize する。reader は
lock protocol に参加する:

1. audit file を open
2. writer と互換の **shared** advisory lock (`File::lock_shared`)
3. file length を取得
4. lock を解放
5. 取得した length までを snapshot として読む

読み取り本体のあいだ writer を block しない。shared lock が失敗したら
lock 無しで読み、EOF の incomplete tail を通常の malformed と区別する。

### カウンタ

```json
{
  "path": "/path/to/audit.jsonl",
  "linesRead": 812,
  "validRecords": 810,
  "matched": 100,
  "returned": 20,
  "skippedInvalid": 1,
  "skippedUnsupportedSchema": 1,
  "incompleteTail": false,
  "records": []
}
```

| キー | 意味 |
| --- | --- |
| `linesRead` | 読み取った物理行数 (空白行を含む) |
| `validRecords` | schema validation を通過した数 |
| `matched` | limit 適用前の filter 一致総数 |
| `returned` | 実際に返却したレコード数 |
| `skippedInvalid` | JSON / 必須 field / field value / 過大行が不正 |
| `skippedUnsupportedSchema` | 正常 JSON だが未対応 `schemaVersion` |
| `incompleteTail` | snapshot 末端が newline 未終端 |

`--json` 成功時は stderr に summary を重複出力しない。テキストモードの
summary は stderr:

```text
scanned 812 lines, 810 valid, 100 matched, 20 returned, 1 invalid, 1 unsupported schema
```

`incompleteTail` が true のときは同じ行に `incomplete tail` を足す。

### `--stats`

filter 後の全レコードを集計する。明示 `--limit` との併用は parse で
reject (`ParseError::ConflictingFlags`、exit 1)。`--limit 0 --stats` も
同じ (0 は「未指定」ではない)。既定 limit 20 と衝突しないよう、parse
時の `limit` は `Option<usize>`。一覧モードに入った時点で `None → 20`
を適用する。

`ruleId` の無いレコードは `byRule` から除外する (decision 集計には含める)。

決定的順序は JSON object ではなく array。双方とも
`count desc → id asc`:

```json
{
  "path": "/path/to/audit.jsonl",
  "linesRead": 812,
  "validRecords": 810,
  "matched": 24,
  "skippedInvalid": 1,
  "skippedUnsupportedSchema": 0,
  "incompleteTail": false,
  "byDecision": [
    {"decision": "deny", "count": 20},
    {"decision": "ask", "count": 4}
  ],
  "byRule": [
    {"ruleId": "core.example.a", "count": 12},
    {"ruleId": "core.example.b", "count": 12}
  ]
}
```

count 0 の decision / rule は出さない。通常 JSON / stats JSON の
トップレベル key 集合は contract fixture で固定する。

### テキスト出力

1 record = 1 line。外部由来 string (`commandRedacted` / `tool` /
`ruleId` / その他表示するフィールド) の control character を escape する。

```text
\n → \\n
\r → \\r
\t → \\t
その他 C0 (U+0000..=U+001F) / DEL (U+007F) / C1 (U+0080..=U+009F)
  / BiDi (U+061C, U+200E, U+200F, U+202A..=U+202E, U+2066..=U+2069)
  → \\u{XXXX}
```

`severity` / `ruleId` が無いときは `-`。列は空白区切り、整列しない:

```text
2026-08-15T09:12:03Z deny critical core.network.remote-script-pipe Bash curl -fsSL https://example.com/i.sh | bash
2026-08-15T09:20:44Z ask medium core.git.reset-hard Bash git reset --hard HEAD~1
```

stats のテキストは `byDecision` を先に、続けて `byRule`。同じ sort。
整列しない:

```text
deny 20
ask 4
core.example.a 12
core.example.b 12
```

### パス解決

`--path` 指定あり:

- 指定 path を直接読む
- repo discovery / config load / `audit.enabled` を見ない
- 壊れた project config や `$HOME` 未設定でも診断できる

`--path` 指定なし:

```text
cwd → config::repo::discover → config::load_for
  → config.audit.path / default_audit_path()
```

`resolved_audit_path()` は使わない (`enabled == false` と HOME 未設定が
同じ `None` になるため)。CLI 側で区別する:

| 状況 | 動作 |
| --- | --- |
| `audit.enabled: false` かつ既存ファイル | exit 0。stderr に `audit is currently disabled; showing existing records`。既存レコードを表示 |
| `audit.enabled: false` かつファイル不在 | 同じ warning + 空結果、exit 0 |
| HOME unset で default path を解決不能 | exit 1。`audit disabled` とは書かない |
| `--path` 未指定で config load 失敗 | exit 1 (既存 `ConfigError`) |

`audit.enabled` は **書き込み設定** であり、既存ログの閲覧可否とは分離する。
