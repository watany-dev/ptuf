# Open Issues

`docs/review/archive/2026-05-05/{redesign,design-debt}.md` のレビューから、
**現時点 (`v0.0.1` HEAD) でも未解決の指摘のみ** を抜粋して整理する。
解決済みは [archive/2026-05-05/README.md](archive/2026-05-05/README.md)
を参照 (D1 / D2 / D3 / D6 / D7 / D8 / §3.1 / §3.2 / §3.3 / §3.5 / §1.6 /
§1.7 / §5.3 / §5.5 / D9 / D5 / §2-conservative / §4.2 / §6.3 を解消。
§2 / D4 は parser の redirect / heredoc / process substitution 部分のみ
解消済で、`xargs` / `find -exec` / inner_code 抽出は未対応で残置)。

各項目には次を付ける:

- **出典**: 元レビューでの節番号 (`§3.1`, `D5` のような形式)
- **コード参照**: 現状の `src/` 内の根拠 (ファイル:行)
- **優先度**: P0 (バグ・要修正) / P1 (設計契約に直接影響) / P2 (改善余地)

## 1. Concrete bugs (P0)

(該当なし — §3.3 / §3.5 は解消済み。`Bash::has_command_substitution`
で command substitution を pessimistic 扱いに surface できるようになった。
`tokenize` の `read_word` 呼び出しに `debug_assert!(advanced > 0)` を
追加して forward-progress 不変条件を明示。)

## 2. Parser / fact extraction (P1)

shell parser と fact 抽出の到達範囲が、設計書 (`docs/design/architecture.md`)
の理想形と乖離している。

- **§2 / D4: shell parser の残盲点 (部分解消)**
  - 解消済 (PR-A 2026-05-06): redirect (`>` / `>>` / `<` / `2>` / `&>`),
    heredoc (`<<TAG` / `<<-TAG`), process substitution (`<(…)` / `>(…)`),
    command substitution (`` ` … ` `` / `$(…)`) の存在検出。
    `Pipeline.redirects: Vec<Redirect>` と `Bash::has_redirect /
    has_heredoc / has_process_substitution / has_command_substitution`
    で surface 済 (`src/facts/shell.rs`)。
  - 解消済 (PR-B 2026-05-06): `bash -c` / `python -c` / `node -e` /
    `perl -e` / `ruby -c|-e` / `eval …` は新 rule
    `core.engine.dynamic-eval` (Ask) で確認させる
    (`src/rules/dynamic_eval.rs`)。
  - **残課題**: `xargs <cmd>` / `find -exec <cmd> {} ;` の inner argv
    再 parse、`bash -c` の inner code を再 parse して既存 rule
    (`destructive-rm` 等) に流す `Argv.inner_code` / `inner_argv` 連結。
    現状は head 検出 + Ask で止まっているため、内側の特定動作は
    inspectable でない。
- **D10: adapter 層の型が無い**。`HookInput` が Claude Code / Codex /
  内部 normalized event を兼ねているため、新 adapter 追加で条件分岐が
  増える。`RawHookInput` と `Event { agent, event, tool, inputs, paths,
  urls, content }` への分離が必要。コード: `src/hook_input.rs`

## 3. Data model & performance (P2)

ホットパスでの alloc を減らす余地。いずれも CLI 1 起動 1 回しか走らない
現状では実害が小さいが、daemon 化や WASM plugin 評価では効く。

- **§1.3** `HookInput.tool_input: serde_json::Value` で都度 string 抽出。
  `#[serde(tag = "tool_name", content = "tool_input")] enum ToolCall`
  形式への移行候補。コード: `src/hook_input.rs:7`
- **§4.1** `Argv.head: String`, `args: Vec<String>` が all-owned。
  `parse<'a>(&'a str) -> Bash<'a>` で借用可。コード:
  `src/facts/shell.rs:28-35`
- **§4.3** `Decision::Deny.reason: String` を `reason::build()` で毎回
  構築。`Cow<'static, str>` か lazy formatter で Allow ホットパスから
  外す。コード: `src/reason.rs`, `src/decision.rs`
- **§4.4** plugin loader の AST 共有なし。Engine ごとにファイル読み込み +
  コンパイル。daemon 化時は `Arc<LoadedPlugin>` キャッシュが必要。
  コード: `src/plugin/loader.rs`
- **§4.5** `Engine::decide` の `facts.protected = self.protected
  .classify_input(input)` で毎回 `Vec<ProtectedKind>` を作る。
  `SmallVec<[_; 4]>` で十分。コード: `src/engine.rs`

## 4. CLI / I/O

| 出典 | 内容 | コード参照 | 優先度 |
| --- | --- | --- | --- |
| §5.1 | 自前 CLI parser が 1352 行に成長 (レビュー時 1141 行)。clap derive で 1/3〜1/4 に減る。`--json` のような中途半端な未実装フラグを `#[arg(skip)]` で明示できる | `src/cli.rs` | P2 |
| §5.4 | `init/claude_code.rs` の hook 重複検出が tail token 一致依存。将来フラグ追加で重複登録の懸念。`name: "ptuf"` 等 stable marker を payload 側に持たせる | `src/init/claude_code.rs` | P2 |
| §5.6 | `audit/time.rs` の RFC3339 自前実装。月日計算は典型的なバグ温床。`time` クレートを 1 つ入れる方がメンテ性が高い (Minimal Dependencies 方針とのトレードオフ) | `src/audit/time.rs` | P2 |

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
- **§1.4** `Decision::severity() -> u8` 手書き比較。`Decision` の variant
  順序を Allow → Monitor → Ask → Deny に揃えれば
  `#[derive(PartialOrd, Ord)]` で自動導出可、`aggregate` も
  `decisions.into_iter().max()` で済む。コード: `src/decision.rs:39-46`。
  優先度: P2
- **§1.5** `Mode::Observe` がデッドバリアント。`engine.rs` の
  `demote_for_mode` では `Monitor | Observe` を同一扱い。
  `docs/design/roadmap.md:49` でも「現状は monitor と同じ」と明記。
  意味を分けるか削除する。優先度: P2
- **D11** 大型ファイル: `src/engine.rs` 1812 行 / `src/cli.rs` 1352 行 /
  `src/doctor.rs` 1712 行 / `src/plugin/dsl.rs` 1067 行。レビュー時
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
  branch coverage 指標への置換、または coverage 数値を捨てる方針転換。
  優先度: P2
- **D12** 契約 fixture (`tests/contracts/*`) が無い。`coverage 95%` を
  満たしても、設計書が「実装済み」と書く契約の未実装が検出されない。
  CLI exit code、stdout/stderr、audit schema、doctor JSON、plugin
  loader error、allowlist condition、MCP nested paths、hook script
  self-protection、`~`/`$HOME`/relative path の self-protection など。
  優先度: P1
