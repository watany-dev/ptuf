# ptuf — Pi Coding Agent 対応 イテレーティブ TDD 実装計画

## Context（なぜこの変更をするか）

ptuf は AI コーディングエージェントの tool call を実行前に評価して
deny/ask/monitor/allow を判定する Rust 製ガードレール。現在 Claude Code /
Codex / Copilot / Kiro / Cline / Cursor の 6 host adapter を持つ。本変更は
7 つ目の host として **Pi Coding Agent**（`earendil-works/pi`）対応を追加する。

Pi は外部 hook 設定ファイル方式ではなく、TypeScript extension の `tool_call`
イベントで実行前にブロックする構造。そのため ptuf 側は二層で対応する:
(1) `ptuf hook pi` adapter を追加、(2) `ptuf init pi` が Pi extension を生成し、
その extension が tool call ごとに `ptuf hook pi` を spawn する。policy engine /
builtin rules / plugin DSL / audit は fork しない。Pi 固有差分は
adapter / init / self-protection / 正規化に閉じる。

### 確定した設計判断（設計書からの精緻化）

ユーザ確認済みの2点。設計書の素直な実装から以下を変更する:

1. **正規化は Rust `src/cli/pi_input.rs` に集約**（設計書 §6 の TS 正規化ではなく）。
   理由: ptuf は純 Rust リポジトリで JS ツール基盤を持たず、host ごとの入力正規化は
   既に `cursor_input.rs` / `cline_input.rs` 等の **per-agent Rust parser** に集約され、
   `src/cli/run.rs::parse_hook_input_for_agent` で分岐している。セキュリティ上重要な
   tool 名・キー正規化（`bash`→`Bash`、`path`→`file_path`、`edits[].newText`→`new_string`、
   `grep`→`mcp__pi__grep`、未知→`mcp__pi__*`）を Rust 単体テスト + bypass corpus + PBT で
   完全に担保する。設計書 §15「Rust 側でも canonical input を受ける」とも整合。
   → 設計書 §5.6/§5.7 の `HookInput` 共有改変は不要。正規化を `pi_input.rs` 内で完結させる。
   → TS extension は Pi の生イベント（`{tool_name: rawName, tool_input, pi:{...}}`）を
     薄く転送するブリッジに留め、decision→block/confirm/notify と Ask mode・fail-closed
     のみ担当する。

2. **TS template の検証は Rust テスト + 手動スモーク**（JS テスト基盤は追加しない）。
   `include_str!` した template に対し managed marker / binary path 埋め込み / 必須スニペット
   存在を Rust テストで検証。実 Pi 連携は docs 化した手動スモーク（設計書 §11.6）に委ねる。

## 進め方（イテレーティブ TDD + commit/push 規律）

- 開発ブランチ: `claude/iterative-tdd-plan-qpojt3`（なければ作成）。push は常に
  `git push -u origin claude/iterative-tdd-plan-qpojt3`、network 失敗時のみ指数バックオフで最大4回。
- 各マイルストーン（M）は **TDD**: failing test を先に書く → 実装 → リファクタ（Tidy First）。
- 各 M の完了条件: **`make check` がローカルで green**（fmt-check / clippy / test / cargo doc /
  cargo-deny の5ステップ）→ commit → push。M をまたぐ大きな塊にせず、M 単位で commit/push する。
- policy/正規化に触れる M（M3 / M9 / M10）は完了時に `make pbt-quick`（1024 cases）も通す。
- 全 M 完了後に `make e2e`（重 E2E、`#[ignore]`、`--test-threads=1`）を一度通す。
- PR は**ユーザが明示要求するまで作らない**。

各 commit メッセージ末尾に Co-Authored-By / Claude-Session トレーラを付す（モデル ID は記載しない）。

---

## マイルストーン

### M0. ベースライン確認
- ブランチを作成/チェックアウトし、`make check` が現状 green であることを確認（差分のベースライン）。
- 何も変更しない。失敗するなら原因を切り分けてから着手。

### M1. `HookAgent::Pi` 追加（enum / parser / help / audit）
TDD: 先に parser/audit テストを追加 → 実装。
- `src/cli/mod.rs`: `HookAgent` enum に `Pi` 追加、`audit_name()` に `Self::Pi => "pi"`、
  HELP 文字列の agent list に `| pi` 追記。
- `src/cli/parse.rs`: `parse_agent()` に `"pi" => Ok(HookAgent::Pi)`、`parse_init()` の
  agent token match に `| "pi"` 追記。テストテーブルに `("pi", HookAgent::Pi)` 追加。
- `src/cli/run.rs`: unknown-agent エラーメッセージの agent list に `pi` 追記。
- この時点では `emit_decision` / `parse_hook_input_for_agent` / `AgentPlan::resolve` の
  非網羅 match がコンパイルエラーになる → 後続 M で埋める。M1 内で最小スタブ
  （`HookAgent::Pi`分岐に `todo!` ではなく暫定の安全な fail-closed 実装）を入れて
  コンパイルを通すか、M2 と束ねて1 commit にする。**推奨: M1+M2 を1 commit**（コンパイル単位）。

### M2. `hook_output::pi` + 出力契約
TDD: `src/cli/output.rs` の `#[cfg(test)]` に Pi 用 emit テストを追加（既存 cursor テスト準拠）。
- `src/hook_output.rs`: `pub mod pi` を追加。`PiHookResponse { decision, rule_id?, reason? }` と
  `from_decision()`（設計書 §5.5 の通り。allow/monitor/ask/deny を素直にシリアライズ）。
- `src/cli/output.rs`:
  - `emit_decision` に `HookAgent::Pi => Some(serde_json::to_string(&hook_output::pi::from_decision(&adapted)))`。
  - `adapt_hook_decision`: Pi は **Ask を demote しない**（`_ => decision.clone()` のまま、明示分岐不要）。
  - `decision_exit_code`: Pi は Deny=2, Ask/Allow/Monitor=0（Cursor と同じ。既存
    `(_, Decision::Deny) => 2` と `_ => 0` でカバーされるため明示分岐不要だが、テストで固定）。
  - `render_hook_response`: `HookAgent::Pi => None`（bare envelope のため）。
- テスト（設計書 §11.2）: Pi は `hookSpecificOutput` を持たない / 常に JSON 出力 /
  Allow は `{"decision":"allow"}` / Ask は保持され demote されない / Deny は rule_id と reason を含む。
- 完了: `make check` → commit（M1 と束ねる）→ push。

### M3. `src/cli/pi_input.rs` — Pi ネイティブ正規化 parser（★セキュリティ中核）
TDD: 正規化テストを先に列挙（設計書 §11.3 を Rust テスト化）。
- 新規 `src/cli/pi_input.rs`（`cursor_input.rs` を雛形に）。`parse(body) -> Result<HookInput, PiInputError>`:
  - `bash` → `Bash`（`{command, timeout}` 保持）
  - `read`/`write`/`edit` → `Read`/`Write`/`Edit`。`path` を `file_path` に複製（既存両方保持）。
  - `edit` の `edits: [{oldText,newText}]` → `new_string`（newText を `\n` join、空は除外。設計書 §5.7 ロジック）。
  - `grep`→`mcp__pi__grep`、`find`→`mcp__pi__find`、`ls`→`mcp__pi__ls`、`fetch`/`web_fetch`→`WebFetch`。
  - 未知 tool → `mcp__pi__<sanitized>`（`[^A-Za-z0-9_]+`→`_`、前後 `_` 除去、空は `unknown`。
    設計書 §6 `sanitizeToolName` と一致させる）。input は保持。
  - 空 body / 非 object / JSON エラーは `PiInputError`（fail-closed は呼び出し側で deny 化）。
  - `tool_name` のキーは Pi 生イベント互換に `toolName`/`tool_name`/`name` を許容。
- `src/cli/run.rs::parse_hook_input_for_agent` に `HookAgent::Pi => pi_input::parse(body)` 追加、
  `src/cli/mod.rs` に `mod pi_input;` 追加。
- テスト: §11.3 全項目 + 不正 stdin → fail-closed deny。`mcp__pi__grep` が `path` を
  `is_mcp_tool()` 経由で sensitive 判定に乗ることを engine 統合テストで確認。
- bypass corpus（`tests/bypass/corpus.jsonl`）に Pi 正規化由来ケースを追記（grep .env / unknown tool with path 等）。
- 完了: `make check` + `make pbt-quick` → commit → push。

### M4. TS extension template + 埋め込み + Rust 検証テスト
- 新規 template ファイル（例: `src/init/templates/pi_extension.ts`）を作成し `include_str!` で埋め込む。
  内容は設計書 §6.2 を**薄いブリッジ化**: 正規化を最小化し Pi 生イベントを `{tool_name, tool_input, pi}`
  として `ptuf hook pi` に渡す。decision 解釈（allow/monitor/notify/ask confirm/deny block）、
  `PTUF_PI_ASK_MODE`（default `confirm-if-ui-else-deny`）、timeout、fail-closed block は維持。
  先頭に managed marker（`// Managed by ptuf. Do not edit manually.` / `// ptuf-agent: pi` /
  `// ptuf-binary: __PTUF_BINARY__` / `// ptuf-version: __PTUF_VERSION__`）。
- render 関数で `__PTUF_BINARY__` / `__PTUF_VERSION__` を置換。
- Rust テスト: template が managed marker・必須スニペット（`pi.on("tool_call"`、`hook`,`pi` spawn 引数、
  ask mode 分岐、fail-closed block）を含むこと、render 後に binary path/version が埋まることを検証。
- 完了: `make check` → commit → push。

### M5. `src/init/pi.rs` + `ptuf init pi`
TDD: path 解決・idempotency・dry-run のテストを先に（`cursor.rs` の test 群準拠）。
- 新規 `src/init/pi.rs`（設計書 §7）:
  - `PiScope { Global, Local }`、`PiInitOptions { scope, root, extension }`、`TargetPaths { root, extension_path }`。
  - path 解決優先順位: `--extension` > `--scope global`（`$HOME/.pi/agent/extensions/ptuf.ts`）>
    `--scope local`（`<repo>/.pi/extensions/ptuf.ts`）。default は global。
  - idempotency（managed marker 判定）: なし→作成 / marker一致→`AlreadyPresent` /
    marker有り binary・version 差分→更新 / marker無し既存→`HookFileConflict`。
  - 書き込み: 既存 `init::write_secure`（Unix 0600）+ temp file + `rename`、parent 作成、dry-run は書かない。
  - `detect_binary()` は `super::detect_binary_impl()` に委譲。
- `src/init/mod.rs`: `pub mod pi;` 追加。
- `src/cli/parse.rs::parse_init`: `--scope <global|local>` / `--root <PATH>` は現状 **cursor 専用に
  検証**され（`parse_init_rejects_cursor_flag_without_cursor_agent` が非 cursor agent で reject）、
  `value_flag` + `parse_cursor_scope` で処理される。Pi では (a) `--scope`/`--root` の許可 agent に
  `Pi` を追加、(b) 新規 `--extension <PATH>` フラグを `value_flag` で追加し pi 専用に検証。
  scope パーサは `CursorScope` 流用ではなく `PiScope` を別途用意（または共通 `Scope` に統一を検討）。
  `PiInitOptions` を `InitOptions` に載せる（`InitOptions` に `pi: PiInitOptions` フィールド追加。
  CHANGELOG 既出の「`InitOptions` に `cursor: CursorInitOptions` field を追加」と同じ前例に倣う）。
  既存 `parse_init` の全テスト分岐（`kiro: ..., cursor: ...` を埋めている箇所）に
  `pi: PiInitOptions::default()` を追加する必要がある点に注意。
- `src/cli/run.rs::AgentPlan::resolve`: `HookAgent::Pi` 分岐で `init::pi::resolve_paths` +
  `init::pi::install`、snapshot_paths に extension_path。
- HELP に `ptuf init pi [--scope ...] [--root ...] [--extension ...]` を反映。
- テスト（設計書 §11.4）: global/local path 解決 / dry-run 無書き込み / managed marker 存在 /
  unmanaged 既存は上書きしない / Unix mode 0600。
- 完了: `make check` → commit → push。

### M6. init verify（Pi）+ snapshot rollback
- `src/init/verify.rs`: Pi 用 verify（設計書 §7.5）。Pi process は起動せず ptuf 単体で:
  extension 存在 / managed marker / 現 binary path 埋め込み / `ptuf hook pi` に synthetic
  **deny**（`rm -rf /`）→`decision=deny` / synthetic **allow**（`ls`）→`decision=allow`。
- 既存 `init::capture` / `init::restore`（snapshot rollback）に extension_path を載せ、verify 失敗時
  rollback（既存 `install_one` フロー流用）。
- テスト: verify pass/fail、verify 失敗で新規書き込みが rollback されること（§11.4）。
- 完了: `make check` → commit → push。

### M7. auto-detect に Pi 追加
- `src/init/mod.rs::detect_agents`: `<home>/.pi/agent/` or `<repo>/.pi/` 存在で `HookAgent::Pi` を push。
  explicit `ptuf init pi` は既存 dir なしでも global extension dir を作成可能（M5 の resolve で担保）。
- テスト: `~/.pi/agent` 検出 / `<repo>/.pi` 検出（§11.4）。detect 順序の決定性を既存テスト規約に合わせる。
- 完了: `make check` → commit → push。

### M8. self-protection に Pi paths 追加
TDD: 「Pi が ptuf extension/settings を改変→block」テストを先に。
- `src/self_paths.rs`:
  - `ProtectedKind` に `PiSettings`（または `PiExtension`）追加、`as_str()` に `"pi_settings"`。
  - `ProtectedPaths` に `pi_settings: Vec<PathBuf>` 追加。`collect`（env 経由）で設計書 §8 の6パスを収集:
    `~/.pi/agent/settings.json` / `~/.pi/agent/extensions/ptuf.ts` / `~/.pi/agent/extensions/ptuf/index.ts` /
    `<repo>/.pi/settings.json` / `<repo>/.pi/extensions/ptuf.ts` / `<repo>/.pi/extensions/ptuf/index.ts`。
  - `match_path` に pi_settings 突合追加。
- 既存 `core.self_protection.*` rules（`src/rules/self_protection`）が `Write`/`Edit`/`Read`/`Bash` redirect・
  `rm`/`mv`/`sed -i` 等・`mcp__pi__*` path-bearing を対象に block することを確認/拡張。
- bypass corpus に §11.5 の self-protection ケース追記（write/edit/rm/sed-i ptuf.ts、`.pi/settings.json`、
  custom tool `{path:".pi/settings.json"}`）。
- テスト: 設計書 §8 の block 例すべて。
- 完了: `make check` → commit → push。

### M9. Pi native `grep`/`find`/`ls` policy
TDD: bypass corpus に先に追加してから rule 実装（red→green）。
- builtin policy は `builtins.yaml`（DSL コンパイル配布）が主。`mcp__pi__grep`/`mcp__pi__find`/
  `mcp__pi__ls` に対し設計書 §9 の判定を追加:
  - `grep`: `path` が sensitive / `glob` が `.env*`,`*.pem`,`*.tfstate`,credentials / self-protection target。
    `.env` 系は Deny 寄り。
  - `find`/`ls`: sensitive path / self-protection path。self-protection target は Deny、
    secret directory listing は Ask（MVP）。
  - DSL で表現できない突合（self-protection）は既存 Rust 経路を使う。
- bypass corpus に Pi grep/find/ls ケース（§11.5: `grep .env`→deny/ask 等）。
- テスト: §11.5 セキュリティ回帰一式。
- 完了: `make check` + `make pbt-quick` → commit → push。

### M10. docs 更新
- 更新対象（設計書 §14）: `README.md` / `README.ja.md` / `docs/agents.md` /
  `docs/design/cli-and-hooks.md` / `docs/design/architecture.md` / `docs/design/policy-packs.md` /
  `docs/design/testing.md` / `CHANGELOG.md`。
- README supported hosts に `Pi Coding Agent` 追加。`docs/agents.md` に Pi セクション
  （`ptuf init pi` / scope / env vars `PTUF_PI_ASK_MODE`・`PTUF_PI_TIMEOUT_MS`・
  `PTUF_PI_GUARD_USER_BASH`(将来) / limitations: project-local trust ゆえ global 推奨、
  spawn-per-call、Ask 非対話 deny）。
- `cli-and-hooks.md` の host 別 exit/output 契約表に Pi 追加。
- ドキュメントは `/update-docs` skill で `src/` 追従を検証。
- 完了: `make check` → commit → push。

### M11. 重 E2E + 最終ゲート + 手動スモーク手順
- `tests/e2e_heavy.rs` に Pi adapter の parity ケース（5→6 adapter parity を Pi 含め拡張、
  実 `ptuf hook pi` subprocess の deny/allow/ask、fail-closed）。
- 最終: `make check` + `make pbt-quick` を通し、`make e2e`（`--ignored --test-threads=1`）を一度実行。
- 手動スモーク手順（設計書 §11.6）を docs に記載（`ptuf init pi --scope global` → `pi` →
  `run rm -rf /` が実行前 block）。本計画では手順記載まで（実機 Pi は CI 外）。
- 完了: `make check` → commit → push。

---

## 主要参照（既存資産の再利用）
- 出力契約の雛形: `src/hook_output.rs`（cursor mod）、`src/cli/output.rs`（emit_decision / decision_exit_code）。
- 入力正規化の雛形: `src/cli/cursor_input.rs`、分岐点 `src/cli/run.rs::parse_hook_input_for_agent`。
- init の雛形: `src/init/cursor.rs`（scope/resolve/install/idempotency）、`src/init/cline.rs`（managed marker）、
  `src/init/mod.rs`（`write_secure` / `capture` / `restore` / `detect_agents`）、`src/init/verify.rs`。
- self-protection: `src/self_paths.rs`（`ProtectedKind` / `ProtectedPaths::collect` / `match_path`）、
  `src/rules/self_protection`。
- sensitive 判定: `src/facts/sensitive.rs`、`src/rules/sensitive_read.rs`、`is_mcp_tool()`。
- テスト規約: inline `#[cfg(test)]` + `tests/bypass/corpus.jsonl`（`tests/bypass_corpus.rs` harness）+
  PBT（`src/testing/proptest.rs`, `tests/*_proptest.rs`）。builtin は `builtins.yaml`。

## 受け入れ基準（設計書 §13 = 完了判定）
1. `ptuf init pi` 後、Pi `bash` の `rm -rf /` が実行前 block（deny, exit 2）。
2. `read {path:".env"}` が既存 secrets policy で block。
3. `write`/`edit` による Pi extension/settings 改変が block。
4. `Ask` は interactive Pi で confirm、非対話で deny（TS `ASK_MODE`）。Rust 側は Ask を保持し demote しない。
5. ptuf 不在 / policy load 失敗 / adapter JSON parse 失敗がすべて fail-closed。
6. 既存6 adapter の output/exit 契約を壊さない（既存テスト全 green）。
7. `ptuf init` auto-detect に Pi 追加。
8. docs に `ptuf init pi` / scope / env vars / limitations 記載。

## 検証方法（エンドツーエンド）
- 各 M: `make check`（5ゲート）。policy/正規化 M: + `make pbt-quick`。
- 正規化: `echo '{"tool_name":"bash","tool_input":{"command":"rm -rf /"}}' | cargo run -- hook pi`
  → `{"decision":"deny",...}` + exit 2 を確認。`ls` → `{"decision":"allow"}` + exit 0。
- init: 一時 HOME で `cargo run -- init pi --scope global --dry-run`（無書き込み）/ 実書き込み →
  `~/.pi/agent/extensions/ptuf.ts` に managed marker・0600・binary path 埋め込みを確認 → verify pass。
- 全 M 後: `make e2e` を一度通し、docs 記載の手動スモーク手順を残す。

## スコープ外（設計書 §16 / MVP 除外）
npm package 化 / daemon mode / `user_bash` default guard（env opt-in の土台のみ docs 言及）/
full custom tool policy / project-local install の default 化 / advanced Pi MCP integration。

---

## 検証サマリ（update-plan）

`src/` 実在シンボルとの突合済み。参照はすべて確認できた:
`HookAgent` enum / `audit_name` (src/cli/mod.rs)、`parse_agent`・`parse_init`・`value_flag`・
`parse_cursor_scope` (src/cli/parse.rs)、`emit_decision`・`adapt_hook_decision`・`decision_exit_code`・
`render_hook_response` (src/cli/output.rs)、`parse_hook_input_for_agent` (src/cli/run.rs, `Result<HookInput,String>`)、
`hook_output::cursor` mod (src/hook_output.rs)、`InitOptions{kiro,cursor}` (src/cli/mod.rs)、
`detect_agents`・`write_secure`・`capture`・`restore`・`InitError`・`AdapterRunReport` (src/init/mod.rs)、
`init::verify` (src/init/verify.rs)、`ProtectedKind`・`ProtectedPaths{copilot_settings,kiro_settings}`・
`match_path` (src/self_paths.rs)、`builtins.yaml`、`tests/bypass/corpus.jsonl` + `tests/bypass_corpus.rs`。

| カテゴリ | 点 | 主要所見 |
| --- | --- | --- |
| モジュール/構造体設計 | 19/20 | `pi_input.rs` / `init/pi.rs` / `hook_output::pi` の境界は既存 adapter と対称。`PiScope` を `CursorScope` 流用せず独立させる方針を明記済み。 |
| フック契約 | 19/20 | Pi=bare envelope・Ask 非 demote・Deny=2 を Cursor 契約に揃え、既存6 adapter の出力/exit 契約不変（受け入れ §6）。stdin/stdout 契約を §5.3/§5.4 で固定。 |
| 判定ルール/ポリシー | 18/20 | 正規化を Rust 集約しセキュリティ中核を Rust テスト+corpus+PBT で担保。grep/find/ls は builtins.yaml + self-protection Rust 経路の二系統を明記。`.env` glob は Deny 寄りデフォルト。 |
| エラーハンドリング | 18/20 | `PiInputError` は `Result<_,String>` 経路に整合。fail-closed（spawn/timeout/JSON 破損/policy load 失敗）を TS+Rust 双方で deny 化。verify 失敗で snapshot rollback。`unwrap`/`expect` は production 禁止規約順守。 |
| テスト容易性 | 18/20 | 各 M で failing test 先行、`make check` ゲート、policy M で `pbt-quick`、最後に `e2e`。TS は include_str! + Rust 検証 + 手動スモークで 95% coverage を Rust 側で維持。 |
| **合計** | **92/100** | 合格ライン 90 超。 |

反映した改善:
- **P1**: `--scope`/`--root` が現状 cursor 専用検証である点を発見し、M5 に「許可 agent に Pi 追加 +
  `--extension` 新設 + 既存 parse_init テスト分岐に `pi: PiInitOptions::default()` 追加」を明記。
- **P1**: 設計書 §5.6/§5.7 の共有 `HookInput` 改変を、正規化 Rust 集約方針に合わせ `pi_input.rs` 内
  完結へ変更（共有型を汚さない）。
- **P2**: M1+M2 を非網羅 match のコンパイル単位として 1 commit に束ねる判断を明記。

残存リスク（実装時に解消）: builtins.yaml DSL で self-protection 突合が表現可能な範囲の見極めは
M9 着手時に `docs/design/config-and-plugins.md` と実 DSL で再確認する。
