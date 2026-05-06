# Open Issues

`docs/review/archive/2026-05-05/{redesign,design-debt}.md` のレビューから、
**現時点 (`v0.0.1` HEAD) でも未解決の指摘のみ** を抜粋して整理する。
解決済みは [archive/2026-05-05/README.md](archive/2026-05-05/README.md)
を参照 (D1 / D2 / D3 / D6 / D7 / D8 / §3.1 / §3.2 / §3.3 / §3.5 / §1.6 /
§1.7 / §5.3 / §5.5 / D9 / D5 / §2-conservative / §4.2 / §6.3 / §1.4 /
§1.5 / §5.6 / §2 / D4 / D10 / D12 を解消)。

現行 parser は redirect / heredoc / process substitution 検出に加え、
`bash -c` / `eval` / `xargs` / `find -exec` の bounded inner parse と
`inner_code` / `inner_redirects` 抽出を実装済み。残る parser リスクは
完全な shell 解釈ではなく、command substitution / process substitution の中身を
opaque な flag surface として扱う点に限定される。

各項目には次を付ける:

- **出典**: 元レビューでの節番号 (`§3.1`, `D5` のような形式)
- **コード参照**: 現状の `src/` 内の根拠 (ファイル:行)
- **優先度**: P0 (バグ・要修正) / P1 (設計契約に直接影響) / P2 (改善余地)

## Status Snapshot

| 状態 | 項目 |
| --- | --- |
| Resolved in current HEAD | §2 / D4 parser wrapper・redirect 系、D10 adapter 分離、D12 contract test 拡充 |
| Still open | §1.3 / §4.1 / §4.3 / §4.4 / §4.5 data model・alloc、§5.1 / §5.4 CLI・I/O、§1.1 / §1.2 / D11 engine 構造、§6.1 test strategy 重複 |
| Deferred design choice | §6.2 coverage 95% 方針転換候補 |

## 1. Concrete bugs (P0)

(該当なし — §3.3 / §3.5 は解消済み。`Bash::has_command_substitution`
で command substitution を pessimistic 扱いに surface できるようになった。
`tokenize` の `read_word` 呼び出しに `debug_assert!(advanced > 0)` を
追加して forward-progress 不変条件を明示。)

## 2. Parser / fact extraction (P1)

(該当なし — §2 / D4 と D10 は解消済み。`Argv.inner_argv` /
`inner_code` / `inner_redirects` により `bash -c`, `eval`, `xargs`,
`find -exec` の内側 command / redirect を bounded depth で再 parse し、
`Bash::commands()` から `destructive-rm` / `core.git.*` など既存 rule が
inspect できるようになった。adapter 層は `RawHookInput` と normalized
`Event` を分離し、facts 抽出は `Event` ビュー経由で行う。設計上の contract は
`docs/design/architecture.md` の Facts / Agent adapter 節にも反映済み。)

## 3. Data model & performance (P2)

ホットパスでの alloc を減らす余地。いずれも CLI 1 起動 1 回しか走らない
現状では実害が小さいが、daemon 化や WASM plugin 評価では効く。

- **§1.3** `HookInput.tool_input: serde_json::Value` で都度 string 抽出。
  `#[serde(tag = "tool_name", content = "tool_input")] enum ToolCall`
  形式への移行候補。コード: `src/hook_input.rs:10-14`
- **§4.1** `Argv.head: String`, `args: Vec<String>` が all-owned。
  `parse<'a>(&'a str) -> Bash<'a>` で借用可。コード:
  `src/facts/shell.rs:90-109`
- **§4.3** `Decision::Deny.reason: String` を `reason::build()` で毎回
  構築。`Cow<'static, str>` か lazy formatter で Allow ホットパスから
  外す。コード: `src/decision.rs:5-9`, `src/reason.rs:3-12`
- **§4.4** plugin loader の AST 共有なし。Engine ごとにファイル読み込み +
  コンパイル。daemon 化時は `Arc<LoadedPlugin>` キャッシュが必要。
  コード: `src/plugin/loader.rs:53-64`
- **§4.5** `Engine::decide` の `facts.protected = self.protected
  .classify_input_with_paths_pair(input, &facts.paths, &redirect_facts)` で
  `ProtectedKind` 用の小さな `Vec` を毎回作る。中間の path clone は
  解消済みだが、戻り値は `SmallVec<[_; 4]>` で十分。コード:
  `src/engine.rs:290-294`, `src/self_paths.rs:198-204`

## 4. CLI / I/O

| 出典 | 内容 | コード参照 | 優先度 |
| --- | --- | --- | --- |
| §5.1 | 自前 CLI parser が 1394 行に成長 (レビュー時 1141 行)。`doctor --json` は実装済みなので未実装フラグ例から外す。残課題は parser が大きく、clap derive 等へ移行する余地がある点 | `src/cli.rs:1-1394` | P2 |
| §5.4 | `init/claude_code.rs` の hook 重複検出が tail token 一致依存。将来フラグ追加で重複登録の懸念。`name: "ptuf"` 等 stable marker を payload 側に持たせる | `src/init/claude_code.rs:24-28`, `src/init/claude_code.rs:114-120` | P2 |

## 5. Engine 構造 / 安全性

- **§1.1** builtin rule (`src/rules/`) と plugin DSL
  (`src/plugin/dsl.rs`) の二重実装。builtin を YAML 1 本
  (`include_str!("builtins.yaml")`) で配布し、起動時に DSL コンパイラを
  通す案。Rust 専用にすべきは self_protection の `ProtectedPaths` 突合
  のように DSL では書けないものだけ。優先度: P2 (大改修)
- **§1.2** `dyn ConfigRule` static slice + `pub static` 16 個
  (`src/rules/git.rs` 等)。`enum Rule { Filesystem(...), Git(GitRuleId),
  SelfProtection(ProtectedKind), Plugin(PluginRule), … }` で動的
  ディスパッチを消す。優先度: P2
- **D11** 大型ファイル: `src/engine.rs` 2065 行 / `src/cli.rs` 1394 行 /
  `src/doctor.rs` 1710 行 / `src/plugin/dsl.rs` 1066 行。レビュー時
  (engine 1362, cli 1158, doctor 1073, dsl 1056) より増加している。
  `engine/{evaluator,allowlist,audit}.rs`, `cli/{parse,commands}.rs`,
  `doctor/json.rs` への分割案。優先度: P2

## 6. テスト基盤

- **§6.1** proptest 戦略が `src/testing/proptest.rs` と
  `tests/engine_proptest.rs` で二重定義されている。`pub(crate)` 公開が
  原因。`testing-strategies` を別 crate (`ptuf-testing`) に切るか、
  `#[cfg(any(test, feature = "testing"))]` で feature gate する。
  CLAUDE.md でも明記済の既知課題。優先度: P2
- **§6.2** 95% coverage 強制が `_via_dyn_dispatch` (`src/rules/mod.rs`
  周辺) のような「coverage を埋めるためだけ」のテストを誘発する。
  ただし CLAUDE.md / Makefile は現在も 95% 以上を要求しているため、
  未解決 bug ではなく branch coverage 指標への置換や coverage 数値の扱いを
  見直す方針転換候補。優先度: P2
- (該当なし — D12 は解消済み。`tests/contracts.rs` と
  `tests/contracts/*.json` が hook response、`doctor --json`、audit schema、
  plugin loader error、allowlist condition、MCP nested path、hook script
  self-protection の end-to-end 契約を固定する。)
