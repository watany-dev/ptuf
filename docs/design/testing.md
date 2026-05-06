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
所有する Tidy First 方針に従う。統合層 (engine end-to-end) のみ
`tests/engine_proptest.rs` に独立して置く。

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

### `audit::redact_strict`

- 冪等律: `redact_strict(redact_strict(s))` == `redact_strict(s)`
- 既知の機密シェイプ (`ghp_…` / `sk-…` / `AKIA…` / `KEY=value` 等) は必ず `***`
- 機密キーを含まない安全文字列は変化しない

### JSON ラウンドトリップ

- `Decision`, `Severity`, `DecisionKind` は `to_string` → `from_str` で同値

## ランタイム / CI 構成

- **デフォルト**: `cargo test --features testing` (`make check`, CI) は
  proptest をデフォルト 256 ケースで実行。失敗ケースは
  `proptest-regressions/` に固定化される。
- **深掘り**: `make pbt` (デフォルト 10000 ケース、`PBT_CASES=N` で上書き可)
  をローカル / 夜間 / リリース直前に手動実行。
- **再現性**: `proptest-regressions/` は git 管理。シュリンクで見つかった反例は
  全員のローカルと CI で同じシードで再現される。
- **依存方針**: テスト用クレート (`proptest`, `tempfile`) は
  `[dev-dependencies]` のみ。出荷バイナリ (`cargo build --release`) には
  含まれず、配布物の依存ツリーは無変更。CLAUDE.md の "Minimal
  Dependencies" 原則を満たす。

## 戦略 (Strategy) の置き場所

`src/testing/proptest.rs` に共通戦略 (Decision / Severity / HookInput /
bash_command) を集約し、`#[cfg(any(test, feature = "testing"))] pub mod
testing` で各モジュールのテストブロックと `tests/engine_proptest.rs` の両方
から参照する。`testing` feature は optional `proptest` 依存だけを有効化し、
通常の `cargo build --release` では出荷バイナリに含まれない。

## 契約テスト

`tests/contracts.rs` と `tests/contracts/*.json` は公開契約を固定する層である。
ここでは example-based / PBT とは別に、次を regression として保持する。

- hook deny 時の `hookSpecificOutput` JSON shape
- `doctor --json` の top-level schema
- audit JSONL の field contract (`schemaVersion`, `agent`, `allowlistId` など)
- plugin loader error の fail-closed 契約
- hook stdin の fail-closed 契約 (`core.engine.invalid-payload` での deny)
- allowlist `when` の suppression 契約
- MCP nested path と hook script self-protection の end-to-end 契約
