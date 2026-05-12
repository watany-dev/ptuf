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
| Resolved in current HEAD | §2 / D4 parser wrapper・redirect 系、D10 adapter 分離、D12 contract test 拡充、§5.4 Claude Code hook stable marker、§6.1 proptest strategy feature gate、§4.3 reason temporary allocation、§4.5 self-protection label allocation、D11 大型ファイル分割 (engine / cli / doctor) |
| Deferred architecture backlog | §1.3 / §4.1 data model・borrowed shell AST、§4.4 plugin cache、§5.1 CLI parser、§1.1 / §1.2 builtin rule / DSL 統合 |
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
- **§4.3** 解消済み。`reason::build()` は rule trigger 後にのみ呼ばれ、
  Allow ホットパスでは構築されない。alternatives 生成も `format!`
  temporary を避け、`write!` / `writeln!` ベースに変更済み。
  `Decision::{Ask,Deny}.reason: String` は JSON wire shape と public API churn
  を避けるため維持。コード: `src/decision.rs:5-9`, `src/reason.rs:3-15`
- **§4.4** plugin loader の AST 共有なし。Engine ごとにファイル読み込み +
  コンパイル。CLI 1 起動 1 回の現状では実害が小さいため、daemon 化時の
  `Arc<LoadedPlugin>` キャッシュ候補として deferred。
  コード: `src/plugin/loader.rs:53-64`
- **§4.5** 解消済み。`ProtectedKind` 用の小さな `Vec` は
  allocation-free な `ProtectedKinds` (`[ProtectedKind; 6] + len`) に置換済み。
  `smallvec` などの新規 dependency は追加していない。コード:
  `src/engine/mod.rs:300-310`, `src/self_paths.rs:46-108`, `src/self_paths.rs:260-283`

## 4. CLI / I/O

| 出典 | 内容 | コード参照 | 優先度 |
| --- | --- | --- | --- |
| §5.1 | deferred。自前 CLI parser は `src/cli/parse.rs` に分離済みだが、自前実装が残る点は変わらず。`doctor --json` は実装済みなので未実装フラグ例から外す。残課題は parser が依然として自前実装で、clap derive 等へ移行する余地がある点 | `src/cli/parse.rs` | P2 |

§5.4 は解消済み。`ptuf init claude-code` が hook payload に
`name: "ptuf"` stable marker を書き込み、既存 entry 検出も marker を優先する。
旧形式の command tail (`hook claude-code`) 検出は互換性のため残している。
コード: `src/init/claude_code.rs`

## 5. Engine 構造 / 安全性

- **§1.1** deferred。builtin rule (`src/rules/`) と plugin DSL
  (`src/plugin/dsl.rs`) の二重実装。builtin を YAML 1 本
  (`include_str!("builtins.yaml")`) で配布し、起動時に DSL コンパイラを
  通す案。Rust 専用にすべきは self_protection の `ProtectedPaths` 突合
  のように DSL では書けないものだけ。優先度: P2 (大改修)
- **§1.2** deferred。`dyn ConfigRule` static slice + `pub static` 19 個
  (`src/rules/git/` 等)。`enum Rule { Filesystem(...), Git(GitRuleId),
  SelfProtection(ProtectedKind), Plugin(PluginRule), … }` で動的
  ディスパッチを消す。優先度: P2
- **D11** 解消済み。`src/engine.rs` を `src/engine/{mod,builder,filter}.rs` に、
  `src/cli.rs` を `src/cli/{mod,parse,run,output,test_support}.rs` に、
  `src/doctor.rs` を `src/doctor/{mod,json}.rs` に、`src/rules/git.rs` (2077 行)
  を `src/rules/git/{mod,argv,branch,bypass,clean,env_redirect,history,push,remote,reset,stash}.rs`
  に分割し、責務単位でファイルを縮小した。残る `src/plugin/dsl.rs` 1066 行は次回以降の候補。

## 6. テスト基盤

- **§6.1** 解消済み。共通 proptest 戦略は
  `#[cfg(any(test, feature = "testing"))] pub mod testing` で公開し、
  `tests/engine_proptest.rs` も `ptuf::testing::proptest::*` を参照する。
  `testing` feature は optional `proptest` 依存のみを有効化し、通常 build
  には入らない。
- **§6.2** 95% coverage 強制が `_via_dyn_dispatch` (`src/rules/mod.rs`
  周辺) のような「coverage を埋めるためだけ」のテストを誘発する。
  ただし CLAUDE.md / Makefile は現在も 95% 以上を要求しているため、
  未解決 bug ではなく branch coverage 指標への置換や coverage 数値の扱いを
  見直す方針転換候補。優先度: P2
- (該当なし — D12 は解消済み。`tests/contracts.rs` と
  `tests/contracts/*.json` が hook response、`doctor --json`、audit schema、
  plugin loader error、allowlist condition、MCP nested path、hook script
  self-protection の end-to-end 契約を固定する。)
