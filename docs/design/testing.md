# テスト戦略 (example-based + PBT)

ptuf のテスト層は **二段構成** で運用する。判定の正しさは個別ケースで担保し、
コアのアルゴリズム性質は Property-Based Testing (PBT) で網羅する。両者は補完
関係であり、片方が他方を置き換えることはない。

## 役割分担

| 観点 | example-based | Property-Based |
| --- | --- | --- |
| 入力 | 手書きの代表ケース | proptest 戦略から無作為生成 |
| 検証対象 | "ある入力 X で結果が Y であること" | "全入力空間で性質 P が成立すること" |
| 主用途 | 既知の Allow/Deny ケース、CLI smoke、JSON shape | 代数法則・冪等性・全域性 (panic 安全)・モルフィズム |
| 失敗時 | 最小再現はそのまま | proptest が自動シュリンク → 最小反例を保存 |

example-based テストは `src/<module>.rs` の `#[cfg(test)] mod tests` と
`tests/cli_smoke.rs` に存在し続ける。PBT は **同じテストモジュール内** に
`proptest!` ブロックとして追記する形を取り、各モジュールが自分の不変条件を
所有する Tidy First 方針に従う。複数モジュールにまたがる統合層の PBT のみ
`tests/` 配下に独立して置く: engine end-to-end は `tests/engine_proptest.rs`、
全 rule にまたがる否定空間は `tests/rules_proptest.rs`、CLI argv 解析は
`tests/cli_parse_proptest.rs`、`engine::filter` の合成則
(`hard_deny` × `allowlist` × `rule_override` × `pack_override` × Mode demote)
は `tests/filter_proptest.rs`。

## 主要な不変条件

### `decision::aggregate` (代数構造)

- `aggregate([])` == `Allow` (単位元)
- `aggregate([d, d, …])` == `d` (冪等律)
- `aggregate(xs ++ ys)` == `aggregate([aggregate(xs), aggregate(ys)])` (結合律)
- 並べ替えに対し `severity` が不変 (交換律)
- 任意の `x ∈ xs` について `aggregate(xs).rank() >= x.rank()` (上界)

### `engine::demote_for_mode`

- `Mode::Enforce` ⇒ 入力をそのまま返す (恒等)
- `Mode::Monitor` で `Allow / Ask / Monitor` ⇒ 不変
- `Mode::Monitor` で `Deny { rule_id, .. }` ⇒
  `Monitor { rule_id }` (rule_id を保存)
- demote は severity を増加させない

### `facts::shell::parse`

- 任意の UTF-8 入力で panic しない
- 空白のみ ⇒ `segments.is_empty()`
- セパレータをシングルクォートで囲んだ文字列は単一 segment になる
- `flags()` と `positional()` は `args` の互いに素な分割
- redirect operator (`>` / `>>` / `<` / `2>` / `&>`) は `Pipeline.redirects`
  に保存され、続く word が target になる
- heredoc (`<<TAG` / `<<-TAG`) の body は terminator までを 1 word として
  `Redirect.target` に保持し、`Bash::has_heredoc` を true にする
- process substitution (`<(...)` / `>(...)`) は paren-balance で 1 word として
  吸収され `Bash::has_process_substitution` を true にする
- `bash -lc`, `sh -ec` のような combined short option でも `-c` / `-e` を認識する
- `Argv.inner_argv` / `inner_redirects` は wrapper (`bash -c`, `eval`, `xargs`,
  `find -exec`) の内側 command / redirect を bounded depth で surface する
- tokenizer は 1 byte 以上前進する (forward-progress;
  `debug_assert!(advanced > 0)`)

### 組み込み rule (全件)

`src/rules/mod.rs` の `RULES` slice に登録された全 rule に対して、以下の
不変条件を proptest で検証する。

- 自分の対象でない tool (例: Bash 系 rule に Read tool) ⇒ `evaluate()` は `None`
- 任意のコマンド文字列 / 引数で panic しない
- `Some(d)` を返す場合、`d.rule_id() == self.id()` かつ
  `d` の variant は `default_decision()` と整合
- 否定空間 (該当パターンを含まない入力) は `None` を返す

最後の 2 件 (`rule_id == self.id`, `kind == default_decision`) は
`src/rules/mod.rs` の `proptest!` 内で `for rule in RULES` の **横断版**
として再表現する (`pbt_per_rule_decision_rule_id_matches_self_id`,
`pbt_per_rule_decision_kind_matches_default`)。これにより将来 `RULES`
slice に built-in rule が追加された際の自動カバーとして機能する。

### Adapter 入口の fail-closed (全 agent)

ClaudeCode / Copilot / Kiro の各 adapter parser と CLI hook entry point
は、外部 agent との信頼境界として以下の不変を持つ。

- `arbitrary_utf8_bytes()` から生成した任意のバイト列を `run` 関数に
  ClaudeCode adapter として流すと、必ず exit `0`/`1`/`2` のいずれかを
  返し panic しない。exit `2` の場合は stdout に
  `"permissionDecision":"deny"` を含む (`src/cli/run.rs` の
  `pbt_run_hook_fails_closed_for_arbitrary_stdin`)
- `copilot_input::parse` / `kiro_input::parse` は任意の `&str` に対し
  `Ok` / `Err(ParseProblem | KiroInputError)` を返し panic しない
  (`pbt_parse_is_total_on_arbitrary_utf8`)
- 非 object / `toolName`/`tool_name` 欠落 / Kiro の場合は
  `hook_event_name != "preToolUse"` の各異常 envelope は対応する
  parser error variant を返す (`pbt_invalid_envelope_returns_err`)
- 例外として、Copilot の 8 MiB 超 stdin は adapter 経由でも exit `0` +
  裸 envelope (no `hookSpecificOutput`) で fail-closed deny になり、
  Kiro の空 stdin は exit `2` + stdout 空 + stderr に
  `INVALID_PAYLOAD_RULE` で fail-closed deny になる
  (`src/cli/run.rs` の `run_hook_copilot_adapter_rejects_oversize_stdin_payload`,
  `run_hook_kiro_adapter_rejects_empty_stdin_payload`; CLI 全体を通した
  end-to-end の example として、上記 PBT を補完する)

### `audit::redact_strict`

- 冪等律: `redact_strict(redact_strict(s))` == `redact_strict(s)`
- 既知の機密シェイプ (`ghp_…` / `sk-…` / `AKIA…` / `KEY=value` 等) は必ず `***`
- 機密キーを含まない安全文字列は変化しない

### JSON ラウンドトリップ

- `Decision`, `Severity`, `DecisionKind` は `to_string` → `from_str` で同値

## ランタイム / CI 構成

PBT は 3 段の予算で同じ `proptest!` ブロックを繰り返し打つ。case 数の
階層は `Makefile` の `pbt-quick` / `pbt` / `pbt-deep` ターゲットおよび
`.github/workflows/ci.yml` の `test` / `pbt-deep` job に対応する。

- **PR ゲート (`pbt-quick`)**: PR 用 CI (`test` job) は
  `PROPTEST_CASES=1024` を明示し、proptest デフォルトの 256 ケースより
  4 倍深く property を回す。`make pbt-quick` がローカル等価コマンド。
  失敗ケースは `proptest-regressions/` に固定化される。
- **`make check` (ローカル)**: `cargo test --features testing` は
  proptest をデフォルト 256 ケースで実行。Tidy First の最短ループ用。
- **深掘り (`pbt`)**: `make pbt` (デフォルト 10000 ケース、`PBT_CASES=N` で
  上書き可) をローカル / 夜間 / リリース直前に手動実行。同じ 10000 ケース
  予算の `pbt-deep` job が main push 時に CI で走る。
- **ソーク (`pbt-deep`)**: `make pbt-deep` (デフォルト 100000 ケース、
  `PBT_DEEP_CASES=N` で上書き可) はリリース前 / 個別調査向け。CI では
  動かさず、ローカル実行のみ。
- **重 E2E**: `make e2e` (`tests/e2e_heavy.rs`, `--test-threads=1`) は
  実 `ptuf` バイナリを subprocess で連続 spawn し、fd / tempfile リーク
  検出 (200 回 spawn 前後の `/proc/self/fd` 差分)、8 MiB stdin 境界、
  10 worker × 100 並列 hook + 単一 audit JSONL の flock 整合性、
  `/etc/ptuf` から project local まで 4 層 + plugin + audit を tempdir に
  組み上げた end-to-end の計 15 ケースを `#[ignore]` で隔離する。
  `make check` には含めず、nightly / リリース直前に手動実行する。
- **再現性**: `proptest-regressions/` は git 管理。シュリンクで見つかった反例は
  全員のローカルと CI で同じシードで再現される。
- **依存方針**: テスト用クレート (`proptest`, `tempfile`) は
  `[dev-dependencies]` のみ。出荷バイナリ (`cargo build --release`) には
  含まれず、配布物の依存ツリーは無変更。CLAUDE.md の "Minimal
  Dependencies" 原則を満たす。

## 戦略 (Strategy) の置き場所

`src/testing/proptest.rs` に共通戦略 (Decision / Severity / HookInput /
bash_command / bash_with_quoting / bash_redirects / bash_heredoc /
bash_process_subst / combined_short_opts / bash_wrapper_nested /
mcp_nested_input / arbitrary_utf8_bytes / safe_command_string /
safe_heads / pack_override / rule_override / allowlist_entry /
config_with_filters) を集約し、
`#[cfg(any(test, feature = "testing"))] pub mod testing` で各モジュールの
テストブロックと `tests/` 配下の統合 PBT (`engine_proptest.rs` /
`rules_proptest.rs` / `cli_parse_proptest.rs` / `filter_proptest.rs`) の
両方から参照する。`testing` feature は optional `proptest` 依存だけを
有効化し、通常の `cargo build --release` では出荷バイナリに含まれない。

`arbitrary_command()` は ASCII printable / Unicode (`\PC`) / 制御文字
(NUL 含む) / `String::from_utf8_lossy` 経由の lossy ASCII の 4 領域を
混ぜて返す。`file_path()` は `safe_paths` / `sensitive_paths` /
`traversal_paths` (`..`, `../../etc/passwd`, `..\\..\\windows\\system32`,
`///etc/passwd` 等 12 件) / 任意文字列の 4 領域から重み付きで選ぶ。
`tool_name()` / `hook_input()` は Bash / 構造化 tool / 任意文字列を
`2:2:1` で混ぜ、Bash 偏重を緩和して Read / Write / WebFetch 系の
fact カバレッジを確保する。

## 契約テスト

`tests/contracts.rs` と `tests/contracts/*.json` は公開契約を固定する層である。
ここでは example-based / PBT とは別に、次を regression として保持する。

- hook deny 時の `hookSpecificOutput` JSON shape
- `init --json` の verify report top-level schema
- audit JSONL の field contract (`schemaVersion`, `agent`, `allowlistId` など)
- plugin loader error の fail-closed 契約
- hook stdin の fail-closed 契約 (`core.engine.invalid-payload` での deny)
- allowlist `when` の suppression 契約
- MCP nested path と hook script self-protection の end-to-end 契約
- GitHub Copilot adapter の bare JSON envelope / `Ask` → `Deny` demote /
  全 Decision exit `0` / fail-closed (`core.engine.invalid-payload` /
  `core.engine.policy-load-failed`) を 9 ケースで固定
  (`tests/contracts.rs` の `copilot_*` 群)
- `rules::iter()` の出力順 (38 件) は `tests/rules_iter_order.rs` で fixture
  固定する。audit のルール表示順、`severity_for` 検索順、`engine::aggregate`
  の決定取捨選択が暗黙に順序に依存しているため、`src/rules/mod.rs::RULES`
  並び替えやモジュール分割の回帰検出ネットとして機能する。
