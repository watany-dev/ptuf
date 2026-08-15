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

### `Config.readonly` ゲート

- pack disable / allowlist / `mode: monitor` 下でも Write / 非 read bash は Deny
- `rank(readonly) >= rank(baseline)` の単調強化 PBT
- bypass corpus の `readonly: true` ケース (ADR 0009)


- `Mode::Enforce` ⇒ 入力をそのまま返す (恒等)
- `Mode::Monitor` で `Allow / Ask / Monitor` ⇒ 不変
- `Mode::Monitor` で `Deny { rule_id, .. }` かつ rule が `hard_deny` ⇒ 不変
- `Mode::Monitor` で `Deny { rule_id, .. }` かつ rule が non-`hard_deny` ⇒
  `Monitor { rule_id }` (rule_id を保存)
- demote は severity を増加させない

### `facts::shell::parse`

- 任意の UTF-8 入力で panic しない
- 空白のみ ⇒ `segments.is_empty()`
- セパレータをシングルクォートで囲んだ文字列は単一 segment になる
- `flags()` と `positional()` は `args` の互いに素な分割
- redirect operator (`>` / `>>` / `<` / `2>` / `&>`) は `Pipeline.redirects`
  に保存され、続く word が target になる。`1>` / `0<` / `3>` / `10>` などの
  数値 fd 形も、fd 2 のみ `Stderr` に、それ以外は演算子ごとに `Stdout` /
  `StdoutAppend` / `Stdin` に collapse されて同様に保存される (`n<<` の
  数値 fd heredoc は対象外でフォールスルーする)
- heredoc (`<<TAG` / `<<-TAG`) の body は terminator までを 1 word として
  `Redirect.target` に保持し、`Bash::has_heredoc` を true にする
- process substitution (`<(...)` / `>(...)`) は paren-balance で 1 word として
  吸収され `Bash::has_process_substitution` を true にし、本体は
  `Argv.subst_argv` へ再 parse される (ADR 0003 C / 0008)
- `bash -lc`, `sh -ec` のような combined short option でも `-c` / `-e` を認識する
- `Argv.inner_argv` / `inner_redirects` は wrapper (`bash -c`, `eval`, `xargs`,
  `find -exec`) の内側 command / redirect を bounded depth で surface する
- `` `…` `` / `$(…)` / `<(…)` / `>(…)` 本体は opaque word を保ったまま
  `Argv.subst_argv` へ同じ `NESTING_BUDGET` で再 parse され、`commands()` は
  `inner_argv` と `subst_argv` を flatten する (ADR 0008)。budget 超過・空
  body では capture を捨てるが flag は true のまま。置換内 reader × 機密
  (`echo $(cat .env)`) は `sensitive-bash-read` が Ask 以上 (PBT で固定)。
  interpreter × subst fetcher (`bash <(curl …)`) は remote-script-pipe が
  Deny (subst 再帰は fresh `seen_from`)
- `Argv.head` は最初のトークンを正規化せず保持する (生値契約;
  `full_path_command_keeps_head_intact` が保証)。`Argv::head_basename()` は
  `head.rsplit('/').next()` で比較用の basename を導出する委譲メソッドで、
  ルール側の head 判定はこれ経由に統一されている (ADR 0005)
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

ClaudeCode / Copilot / Kiro / Cline の各 adapter parser と CLI hook entry
point は、外部 agent との信頼境界として以下の不変を持つ。

- `arbitrary_utf8_bytes()` から生成した任意のバイト列を `run` 関数に
  各 adapter として流すと panic しない。Claude Code / Cursor は exit
  `0`/`1`/`2` のいずれかで、invalid payload 時は exit `2` + deny
  envelope。Copilot は常に exit `0`/`1`（invalid payload も exit `0` +
  bare deny）。Kiro は exit `0`/`1`/`2`（invalid payload 時は exit `2` +
  stdout 空 + stderr reason）。対応 PBT:
  `pbt_run_hook_fails_closed_for_arbitrary_stdin` (Claude Code),
  `pbt_cursor_run_hook_fails_closed_for_arbitrary_stdin`,
  `pbt_copilot_run_hook_fails_closed_for_arbitrary_stdin`,
  `pbt_kiro_run_hook_fails_closed_for_arbitrary_stdin` (`src/cli/run.rs`)
- `copilot_input::parse` / `kiro_input::parse` / `cline_input::parse` /
  `cursor_input::parse` はいずれも任意の `&str` に対し `Ok` / 構造化
  `Err(...)` を返し panic しない。trust boundary ごとに
  `pbt_parse_is_total_on_arbitrary_utf8` を各 adapter module が保持する
  （dedupe しない）
- 非 object / `toolName`/`tool_name` 欠落 / Kiro の `hook_event_name !=
  "preToolUse"` / Cline の `tool_call`・`preToolUse` 双方欠落や非対応
  `hookName` といった各異常 envelope は対応する parser error variant を
  返す (`pbt_invalid_envelope_returns_err`)
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

### `audit::read` (計画中, issue #189)

閲覧 CLI の reader は書き込み経路と独立した信頼境界 (JSONL は同 uid から
改竄され得る)。テストは `src/audit/read.rs` の unit / proptest を主にし、
CLI 配線は `parse.rs` / `run.rs` / `tests/cli_smoke.rs` で足す。

example-based (`src/audit/read.rs`):

- 各フィルタと AND 合成
- file order の末尾 N 件 (timestamp sort しない) / `limit 0` 全件 /
  `matched > returned`
- 空白行 skip (`skippedInvalid` にしない)
- 不正 UTF-8 / malformed JSON / 必須 field 欠落 / invalid decision /
  invalid timestamp → `skippedInvalid`、panic しない
- `schemaVersion` 欠落は `skippedInvalid`、非 `1` は
  `skippedUnsupportedSchema` (混同しない)
- 途中で `Read` error を返す reader は `Err`
- EOF の incomplete tail (`incompleteTail: true`)
- concurrent append 中の snapshot read (writer の exclusive lock と
  共存し、途中行を返さない)
- `parse_since`: `1h` / `30m` / `24h` / `7d` 受理、canonical RFC3339 の
  timezone offset、overflow reject、`timestamp == since` は含む
- stats: `count desc → id asc`、`ruleId` 無しは `byRule` から除外
- 1 行が `MAX_AUDIT_RECORD_BYTES` を超えると `skippedInvalid`

proptest (`src/audit/read.rs` 内):

- 任意バイト列を食わせても panic しない
- `limit == 0 || returned <= limit`

CLI parse (`src/cli/parse.rs`):

- 全フラグ、`--flag=value` 形式
- 不正 `--decision` / 非数値 `--limit` は `UnexpectedArgument`
- `--stats --limit N` は `ConflictingFlags`

CLI run (`src/cli/run.rs` の `run_with`):

- JSON / text / stats / エラー分岐 (coverage 95%)
- `--path` が audit disabled / home 未設定 / 壊れた project config を迂回
- audit disabled と default path resolution failure を区別
- text renderer が newline / CR / tab / ESC / BiDi を escape

バイナリ (`tests/cli_smoke.rs`):

- tempfile JSONL に対する `--path` / `--json` / `--decision deny`
- ファイル不在 (exit 0 空)
- 壊れた行混入
- default audit path (home を temp に向ける)
- project config の custom `audit.path`

契約 fixture (`tests/contracts/`):

- `audit-list-json-keys.json` — 通常 JSON のトップレベル key
- `audit-stats-json-keys.json` — stats JSON のトップレベル key
  (`byDecision` / `byRule` は array)

重 E2E (`tests/e2e_heavy.rs` `subcommand_robustness`): `audit` を
既存 subcommand 連続実行に足す。fuzz ターゲット追加は本 issue の非スコープ。

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
  実 `ptuf` バイナリを subprocess で連続 spawn し、8 軸 40 ケースを
  `#[ignore]` で隔離する。前半 4 軸は fd / tempfile リーク検出
  (200 回 spawn 前後の `/proc/self/fd` 差分)、8 MiB stdin 境界、
  10 worker × 100 並列 hook + 単一 audit JSONL の flock 整合性、
  `/etc/ptuf` から project local まで 4 層 + plugin + audit を tempdir に
  組み上げた end-to-end。後半 4 軸はクラッシュ / ハング / 遅延を回帰検出
  する: 8 adapter (claude-code / codex / copilot / kiro / cline / cursor / pi /
  opencode) の出力契約 parity、病的入力 (非 UTF-8 / NUL / 深いネスト JSON・bash /
  envelope / 巨大 secret 列) を fail-closed で弾くか、per-call latency 予算、
  `check` / `plugin check` / `init` / `update` / (計画) `audit` subcommand の連続 / 敵対的
  実行。spawn ハーネスはタイムアウト付きで、`Child::try_wait()` ポーリング
  により無期限ハングを「タイムアウト失敗」へ変換し、signal kill された子
  (クラッシュ) も `SpawnOutcome::signal` で検出する — `assert_clean_exit`
  が両者をまとめてアサートする。`make check` には含めず、nightly /
  リリース直前に手動実行する。
- **Fuzzing (nightly / on demand)**: `make fuzz` は `cargo-fuzz`
  (coverage-guided, nightly toolchain 必須) で 6 つの信頼境界を打つ
  — `fuzz_shell_parse` (shell tokenizer), `fuzz_hook_pipeline`
  (hook stdin JSON → `decide`), `fuzz_config_merge` (4 層 YAML config
  パース + merge), `fuzz_plugin_dsl` (plugin DSL コンパイラ),
  `fuzz_copilot_parse` (Copilot stdin normaliser),
  `fuzz_opencode_parse` (OpenCode stdin normaliser)。
  `fuzz/` は独立 workspace のため `make check` / `cargo clippy
  --all-targets` / `cargo-deny` / crates.io パッケージに干渉しない。
  PBT が proptest 戦略から「構造化された」入力を生成するのに対し、
  fuzzing は任意バイト列を coverage-guided で当て続け panic 安全 /
  forward-progress / hang 無しを検証する。`make fuzz-soak
  FUZZ_TARGET=<name>` で単一ターゲットを長時間走らせる。クラッシュ
  再現入力は `fuzz/artifacts/` に最小化のうえ git 管理し、
  `proptest-regressions/` と同様に恒久回帰種とする。CI では
  `.github/workflows/nightly.yml` の `fuzz` job が各ターゲットを
  300 秒ずつ実行する。
- **Mutation testing (nightly / on demand)**: `make mutants` は
  `cargo-mutants` でソースを機械的に変異させ、テストがその変異を
  捕捉できる (= 振る舞いを検証している) かを測る。95% カバレッジは
  「行が実行された」を測るが「テストが振る舞いを検証しているか」は
  測らない。スコープは `.cargo/mutants.toml` の `examine_globs` で
  セキュリティ中核 (`src/decision.rs` / `src/rules/**` /
  `src/engine/**`) に限定する。生き残った (`MISSED`) ミュータントは
  テストが見逃す実バイパスに直結するため、example-based テストで
  潰す。`nightly.yml` の `mutants` job が full スコープで実行し
  mutation report を artifact 出力する。
- **Bypass 回帰コーパス (`make check` 内)**: `tests/bypass/corpus.jsonl`
  は版管理された敵対的入力の負テストスイートで、`tests/bypass_corpus.rs`
  が通常の `cargo test` (= `make check` の `test` step) で実行する。
  各ケースは `must_catch` (指定 rank 以上で必ず捕捉) か `known_gap`
  (ADR (0001, 0004, 0005 等) に記録した既知限界 — 現状の振る舞いを固定し、
  改善・退行の双方を test 失敗として可視化) の期待値を持つ。fuzzing や
  監査で新規バイパスを発見するたび corpus に追記する。
- **新ツールの tier**: `cargo-fuzz` / `cargo-mutants` /
  `cargo-semver-checks` は `make tools` で版固定インストールする
  (`Makefile` の `CARGO_*_VERSION`)。`cargo-semver-checks` は高速な
  ため `ci.yml` の PR ゲート (`semver` job) に載せ、公開 API
  (`decide` / `try_decide` / `Engine` / `Decision` 等) の SemVer
  破壊を検知する。`cargo-fuzz` / `cargo-mutants` は重いため
  `make check` に含めず nightly に隔離する (`make e2e` / `pbt-deep`
  と同じ予算階層)。
- **再現性**: `proptest-regressions/` は git 管理。シュリンクで見つかった反例は
  全員のローカルと CI で同じシードで再現される。
- **依存方針**: テスト用クレート (`proptest`, `tempfile`) は
  `[dev-dependencies]` のみ。出荷バイナリ (`cargo build --release`) には
  含まれず、配布物の依存ツリーは無変更。CLAUDE.md の "Minimal
  Dependencies" 原則を満たす。

## 戦略 (Strategy) の置き場所

`src/testing/proptest.rs` に共通戦略 (Decision / Severity / HookInput /
bash_command / bash_with_quoting / bash_redirects / bash_heredoc /
bash_process_subst / bash_process_subst_remote_pipe / combined_short_opts / bash_wrapper_nested /
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

## 本質的テストのギャップチェックリスト

行カバレッジでは測れない「契約・統合・既知バイパス」の追加タスクは
[substantive-test-checklist.md](../review/substantive-test-checklist.md)
にテスト名と期待 assert 付きで整理している。新規 bypass や adapter 契約を
足す前に該当行を確認する。

## 契約テスト

`tests/contracts.rs` と `tests/contracts/*.json` は公開契約を固定する層である。
ここでは example-based / PBT とは別に、次を regression として保持する。

- hook deny 時の `hookSpecificOutput` JSON shape
- `init --json` の verify report top-level schema
- audit JSONL の field contract (`schemaVersion`, `agent`, `allowlistId` など)
- `ptuf --json audit` / `ptuf --json audit --stats` のトップレベル key
  集合 (issue #189。実装後に `tests/contracts/audit-list-json-keys.json`
  と `audit-stats-json-keys.json` で固定)
- plugin loader error の fail-closed 契約
- hook stdin の fail-closed 契約 (`core.engine.invalid-payload` での deny)
- allowlist `when` の suppression 契約
- MCP nested path と hook script self-protection の end-to-end 契約
- GitHub Copilot adapter の bare JSON envelope / `Ask` → `Deny` demote /
  全 Decision exit `0` / fail-closed (`core.engine.invalid-payload` /
  `core.engine.policy-load-failed`) を 9 ケースで固定
  (`tests/contracts.rs` の `copilot_*` 群)
- Cline adapter の cancel JSON envelope / `Allow` での `{}` 出力 /
  `Ask` → `Deny` demote / invalid payload を含む全経路で exit `0` /
  `shouldContinue` 非出力を `tests/contracts.rs` の `cline_*` 群で固定
- `rules::iter()` の出力順 (38 件) は `tests/rules_iter_order.rs` で fixture
  固定する。audit のルール表示順、`severity_for` 検索順、`engine::aggregate`
  の決定取捨選択が暗黙に順序に依存しているため、`src/rules/mod.rs::RULES`
  並び替えやモジュール分割の回帰検出ネットとして機能する。
