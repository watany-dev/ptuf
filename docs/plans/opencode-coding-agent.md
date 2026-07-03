# ptuf — OpenCode 対応 設計仕様(レビュー反映版)

## Context(なぜこの変更をするか)

ptuf は AI コーディングエージェントの tool call を実行前に評価して
deny/ask/monitor/allow を判定する Rust 製ガードレール。現在 Claude Code /
Codex / Copilot / Kiro / Cline / Cursor / Pi の 7 host adapter を持つ。
本変更は 8 つ目の host として **OpenCode**(`anomalyco/opencode`)対応を追加する。

OpenCode は外部 hook 設定ファイル方式ではなく、Bun ランタイムで実行される
plugin の `tool.execute.before` hook でツール実行直前に介入する構造。そのため
ptuf 側は Pi と同じ二層で対応する: (1) `ptuf hook opencode` adapter を追加、
(2) `ptuf init opencode` が OpenCode plugin(TypeScript)を生成し、その plugin
が tool call ごとに `ptuf hook opencode` を spawn する。policy engine /
builtin rules / plugin DSL / audit は fork しない。OpenCode 固有差分は
adapter / init / self-protection / 正規化に閉じる。

本書は初版仕様案のレビュー(OpenCode 実仕様との突合 + ptuf 既存実装との突合)
を反映した改訂版である。主な変更点:

1. **プラグインディレクトリを単数形 `plugin/` に修正**(OpenCode の実仕様。
   初版の `plugins/` では一切ロードされない)。
2. **ツール正規化表を OpenCode の実在ツールで再作成**(`patch` / `list` を追加、
   実在しない `shell` / `apply_patch` / `fetch` / `search` / `websearch` を削除)。
3. **ask→deny 降格の理由付けを修正**。OpenCode には `permission.ask` hook が
   実在する(`output.status = "ask"|"deny"|"allow"`)が、既知の不発火バグ
   (anomalyco/opencode #7006, #19927)があり、かつ `tool.execute.before` から
   対話確認を開始する API ではないため、MVP では降格する。Phase 3 の実装
   候補は `permission.ask` hook 連携。
4. **正規化モデルを既存 adapter 流儀に統一**。初版の
   `{"kind": ..., "facts": ...}` 形式は廃止し、`src/cli/opencode_input.rs` が
   `HookInput { tool_name, tool_input }` へ reshape する(Copilot/Cursor/Pi 前例)。
   facts は engine 側の `facts::extract` が抽出する。
5. **GenericTool / content_snippets の新設を廃止**。未知 tool は Pi 前例の
   `mcp__opencode__<sanitized>` 写像に置き換え、既存の `is_mcp_tool()` +
   `MCP_DIRECT_PATH_KEYS` 汎用抽出で保護する。
6. **監査ログ拡張(session_id / call_id / original_tool_name 等)を MVP から
   除外**。`AuditRecord`(schema v1)のスキーマ変更と 7 既存 adapter との
   parity 議論が必要なため、別マイルストーンに分離する。
7. **生成物は JS ではなく TS**。OpenCode plugin は Bun が TS を直接実行する
   ため build step は不要であり、Pi の TS テンプレート前例に揃える。

---

## 1. 基本方針

OpenCode 対応は custom tool 上書き方式ではなく、plugin hook 方式で実装する。

- `tool.execute.before` で組み込み tool / custom tool / MCP tool を同じ入口で
  観測できる。
- 既存設計「agent 別 hook stdin JSON → Rust 正規化 → rule engine → agent 別
  レスポンス」を崩さない。正規化は Rust(`opencode_input.rs`)に集約し、
  TS plugin は薄いブリッジに留める(Pi の確定判断 1 と同一)。
- OpenCode の permission UX(`--auto` 等)に依存せず、上位の fail-closed
  guardrail として動く。
- MVP では ptuf の `ask` 判定は `deny` に降格する(§9)。

## 2. 追加 CLI

```bash
ptuf hook opencode
ptuf init opencode [--scope global|local] [--dry-run] [--no-verify]
```

- `--json` はトップレベル global flag(既存規約)。`hook` サブコマンドは
  出力形状が host プロトコルで固定のため `--json` を拒否する(既存規約)。
- `--scope` の許可 agent は現在 cursor / pi のみ(`parse_shared_scope`)。
  **opencode を許可リストに追加する parse 変更が必要**(Pi plan M5 と同じ
  落とし穴)。既存 `parse_init` テスト分岐への `InitOptions` フィールド追加
  も同様。
- デフォルト scope は **global**(Pi 前例)。project-local ファイルはリポジトリ
  側の信頼に依存するため、全プロジェクトを覆う global を既定とし、repo 単位
  導入は `--scope local` で行う。

## 3. OpenCode 検出

`ptuf init` の auto-detect(`src/init/mod.rs::detect_agents`)に追加する。
既存 agent と同様、repo 側と home 側の両方を見る:

- repo 側: `<repo>/.opencode/` ディレクトリ、または `<repo>/opencode.json`
  (`opencode.jsonc` のサポート有無は実装前検証項目 §17)
- home 側: `$XDG_CONFIG_HOME/opencode/`(未設定時 `~/.config/opencode/`)

返却順は enum 定義順で固定(既存テスト規約
`detect_agents_returns_all_*_in_stable_order` に追従)。

## 4. 生成する OpenCode plugin

### 4.1 生成先

```text
global: $XDG_CONFIG_HOME/opencode/plugin/ptuf.ts
        (XDG_CONFIG_HOME 未設定時: ~/.config/opencode/plugin/ptuf.ts)
local:  <repo>/.opencode/plugin/ptuf.ts
```

**ディレクトリ名は単数形 `plugin/`**。OpenCode は
`.opencode/plugin/` と `~/.config/opencode/plugin/` からロードする。

既存 init adapter は `HOME` 直叩きで XDG 解決の前例が無いため、
`src/config/scope.rs::user_config_path` の `EnvLookup` パターン
(`XDG_CONFIG_HOME` → `HOME/.config` フォールバック、テスト注入可能)を
init 側へ持ち込む。`HOME` 未設定は `InitError::HomeNotSet`。

### 4.2 テンプレート

`src/init/templates/opencode_plugin.ts` を新設し `include_str!` で埋め込む
(Pi の `pi_extension.ts` 前例)。先頭に管理マーカー 4 行:

```ts
// Managed by ptuf. Do not edit manually.
// ptuf-agent: opencode
// ptuf-binary: __PTUF_BINARY__
// ptuf-version: __PTUF_VERSION__
```

- `__PTUF_BINARY__` / `__PTUF_VERSION__` は `render` 時に置換(Pi 前例)。
  **素の `spawn("ptuf")` は使わない**(PATH 依存を避け絶対パスを埋め込む)。
- `is_ptuf_managed()` 判定 + 非管理既存ファイルは `InitError::HookFileConflict`
  で上書き拒否(Pi/Cline 前例の 3 点セット)。
- 書き込みは `init::write_secure`(0600, temp+rename atomic)。

### 4.3 plugin の概念コード

```ts
import { spawn } from "node:child_process"
import type { Plugin } from "@opencode-ai/plugin"

const PTUF_BINARY = "__PTUF_BINARY__"
const TIMEOUT_MS = Number(process.env.PTUF_OPENCODE_TIMEOUT_MS ?? "10000")
const MAX_CAPTURE_BYTES = 65536

export const Ptuf: Plugin = async ({ directory, worktree }) => {
  return {
    "tool.execute.before": async (input, output) => {
      const payload = {
        tool_name: input.tool,
        tool_input: output.args ?? {},
        opencode: {
          cwd: directory,
          worktree,
          sessionId: input.sessionID,
          callId: input.callID,
        },
      }

      const result = await runPtufHook(payload) // 失敗はすべて throw (fail-closed)

      if (result.decision === "allow" || result.decision === "monitor") {
        return
      }
      throw new Error(result.reason ?? "blocked by ptuf")
    },
  }
}
```

`runPtufHook` は Pi テンプレートの実装パターンを踏襲する:

- `AbortController` + `setTimeout` で timeout(二重 reject 問題を構造的に回避)。
  SIGTERM が無視された場合に備え、abort 後一定時間で `SIGKILL` フォールバック。
- stdout / stderr は `MAX_CAPTURE_BYTES`(64 KiB)で打ち切り。
- exit code `0` / `2` 以外、stdout JSON parse 失敗、spawn ENOENT、timeout は
  すべて throw(= block)。Pi と異なり OpenCode には ask UI 連携が無いため、
  plugin 側に ASK_MODE 分岐は持たない(降格は Rust 側 §9)。

fail-closed マトリクス:

```text
exit 0 + valid JSON allow/monitor -> return (実行許可)
exit 2 + valid JSON deny          -> throw Error(reason)
exit その他 / JSON parse 失敗      -> throw Error("ptuf failed closed: ...")
spawn ENOENT / timeout            -> throw Error("ptuf failed closed: ...")
```

環境変数: `PTUF_OPENCODE_TIMEOUT_MS`(既定 10000。Pi の
`PTUF_PI_TIMEOUT_MS` と同じ既定値)。

## 5. hook 入力スキーマ

plugin が `ptuf hook opencode` の stdin に渡す payload(Pi 前例の最小形):

```json
{
  "tool_name": "bash",
  "tool_input": { "command": "rm -rf /" },
  "opencode": {
    "cwd": "/repo",
    "worktree": "/repo",
    "sessionId": "ses_xxx",
    "callId": "call_xxx"
  }
}
```

- 初版仕様の `schema_version` / `host` / `hook_event_name` トップレベル
  フィールドは採用しない。既存 7 adapter はいずれも持たず(`hook_event_name`
  を読むのは Cursor のみ)、plugin と parser の両方を ptuf 自身が生成・配布
  するためバージョン整合はテンプレートの `ptuf-version` マーカーと init の
  更新フローで担保できる。
- `opencode.*` メタデータは MVP では読み捨て(Kiro の `session_id` と同じ
  扱い)。監査転記は Phase 2(§13)。
- 制約: `tool_name` は空文字不可、`tool_input` は object のみ。stdin は既存の
  `MAX_HOOK_STDIN_BYTES`(8 MiB)がそのまま適用される。
- 不正 payload は既存規約どおり `core.engine.invalid-payload` の deny
  (exit 2)。policy load 失敗は `core.engine.policy-load-failed` の deny。

## 6. ツール正規化(`src/cli/opencode_input.rs`)

OpenCode の組み込みツールは
`bash / edit / write / read / grep / glob / list / patch / todowrite /
todoread / webfetch / task`。正規化先は ptuf の正規語彙(Claude Code の
tool 名文字列。`apply_patch` は小文字が正規名 — Cline 前例、Codex 既定
matcher `"Bash|apply_patch|mcp__.*"`)とする:

```text
bash      -> Bash
read      -> Read
edit      -> Edit
write     -> Write
patch     -> apply_patch
webfetch  -> WebFetch
grep      -> mcp__opencode__grep
glob      -> mcp__opencode__glob
list      -> mcp__opencode__list
todowrite / todoread / task -> mcp__opencode__<name>
MCP / custom tool -> mcp__<server>__<tool>(形式が判別可能な場合。§17)
未知 tool -> mcp__opencode__<sanitized>
```

- 初版仕様の `GenericTool` 種別は新設しない。未知 tool を
  `mcp__opencode__<sanitized>` に写像することで、既存の `is_mcp_tool()` +
  `MCP_DIRECT_PATH_KEYS`(path/filePath/files[].path 等 15 synonym + nested)
  による汎用 path 抽出と sensitive 判定にそのまま乗る(Pi M3 と同一の手法)。
- sanitize 規則は Pi と同一: `[^A-Za-z0-9_]+` → `_`、前後 `_` 除去、空は
  `unknown`。元 input は保持する。
- 大文字小文字は受理側で寛容に(`Bash`/`bash` 等)、出力は正規名に固定。

## 7. 引数正規化

camelCase → snake_case の reshape は Copilot(`reshape_path` /
`reshape_edit` / `reshape_create`)と Cursor の前例に倣い、
`input_helpers::take_first_string` を用いて `opencode_input.rs` 内で行う。
正規化キーへ複製し、元キーも保持する(既存流儀)。

```text
read:  filePath -> file_path
edit:  filePath -> file_path, oldString -> old_string,
       newString -> new_string, replaceAll -> replace_all
write: filePath -> file_path (content はそのまま)
bash:  command / workdir / timeout はそのまま保持(改名しない)
webfetch: url はそのまま保持
```

初版仕様の `timeout -> timeout_ms` 改名、`kind` フィールド付与、`tool_input`
内への `facts` 埋め込みはすべて廃止する。facts(paths / urls / bash command
解析 / sensitive)は engine 側の `facts::extract` が既存ロジックで抽出する。

### `patch`(apply_patch 形式)

patch 本文からの path 抽出(`*** Add File:` / `*** Update File:` /
`*** Delete File:` / `*** Move to:`)は **既存の
`collect_apply_patch_paths`(`src/facts/path.rs`)を再利用する**。同関数は
`tool_input.command` を読むため、adapter で patch 本文フィールドを
`command` キーへ複製する reshape を行う(新パーサは書かない)。

- OpenCode `patch` ツールの実引数名(`patchText` か否か)と patch 形式
  (apply_patch 形式か unified diff か)は実装前検証項目(§17)。形式が
  異なる場合は M3 で抽出ロジックの追加を判断する。

## 8. MCP / custom tool の保護

MVP では §6 の `mcp__opencode__<sanitized>` 写像 + 既存 MCP 汎用抽出で
path / url を検出し、sensitive path・self-protection 判定に流す。
初版仕様の「再帰的 fact 抽出 + content_snippets」は新設サブシステムになる
ため採用しない(書き込み内容の機密走査は既存の `event.content` 経路 =
`HookInput::write_payload` + `collect_sensitive` に乗せる)。

OpenCode 側で MCP server/tool の metadata が安定取得できる場合のみ、
Phase 2 で `mcp__<server>__<tool>` への identity 復元を追加する。

## 9. 判定結果と ask 降格

stdout JSON は **Pi と同型の bare envelope**:

```json
{ "decision": "deny", "rule_id": "core.filesystem.destructive-rm", "reason": "..." }
```

- 初版仕様の `schema_version` / `message` / `demoted_from` / `audit_id`
  フィールドは採用しない(既存 adapter に前例なし)。
- **ask 降格は Rust 側**(`src/cli/output.rs::adapt_hook_decision`)で行う。
  Codex / Copilot / Kiro / Cline と同型: `deny_reason_for_ask` +
  `append_demote_note`(`ASK_UNAVAILABLE_NOTE`)で reason に降格注記を付す。
  したがって opencode の stdout に `ask` は現れない。
- 降格理由(docs にもこの表現で記載する): OpenCode には `permission.ask`
  plugin hook が存在するが、不発火の既知バグ(anomalyco/opencode #7006,
  #19927)があり、また `tool.execute.before` から対話確認を開始する API は
  無い。安全側に倒し MVP では deny に降格する。
- exit code(`decision_exit_code`): Deny(降格含む)= 2、Allow/Monitor = 0。
  invalid payload / policy load 失敗も 2(fail-closed)。plugin 側(§4.3)は
  0/2 以外を throw するため、host 側 fail-open の懸念(Copilot/Cline が
  常時 exit 0 を選んだ理由)は生じない。

## 10. OpenCode permission との関係

ptuf は OpenCode permission の代替ではなく上位の fail-closed guardrail。
`ptuf init opencode` は `opencode.json` を変更しない(ユーザーの permission
運用を壊さない)。docs には併用例として permission(`bash` / `edit` /
`webfetch` を `ask`)を載せるが、キー名は実装前に実仕様で検証する(§17)。

## 11. init 詳細

`AgentPlan::resolve`(`src/cli/run.rs`)に opencode 分岐を追加し、既存の
`install_one` フロー(snapshot → install → verify → 失敗時 rollback)に乗せる。

```text
1. scope 解決(global: XDG / local: repo root = config::repo::discover)
2. plugin ディレクトリ作成 + ptuf.ts を write_secure で生成
3. 既存ファイル: managed marker 一致 -> AlreadyPresent /
   marker 有り差分 -> 更新 / marker 無し -> HookFileConflict
4. verify(--no-verify で skip、--dry-run は verify 自動 off + 無書き込み)
5. verify 失敗かつ Installed のとき snapshot rollback(init::capture/restore)
```

verify(`src/init/verify.rs`、Pi M6 前例)は OpenCode process を起動せず
ptuf 単体で行う:

- 生成ファイルの managed marker と binary path 埋め込みを確認
- `ptuf hook opencode` に synthetic deny(`bash: rm -rf /` →
  `core.filesystem.destructive-rm`)と synthetic allow(`ls`)を流して確認
- fail-closed 経路(`core.engine.policy-load-failed`)の確認は既存 verify を流用

`--json` 出力は既存 `render_install_json` / `verify::render_json` に従う
(初版仕様の独自 JSON 形状は採用しない)。

## 12. self-protection

`src/self_paths.rs` に OpenCode パスを追加する(Pi plan M8 相当。初版仕様
から漏れていた必須項目)。agent が ptuf 生成 plugin 自体を改変・削除して
ガードレールを外す攻撃への防御:

```text
<repo>/.opencode/plugin/ptuf.ts
$XDG_CONFIG_HOME/opencode/plugin/ptuf.ts (未設定時 ~/.config/opencode/plugin/ptuf.ts)
```

`ProtectedKind` に variant 追加、`ProtectedPaths::collect` / `match_path` に
突合を追加し、既存 `core.self_protection.*` rules で Write/Edit/Bash
(rm / mv / sed -i / redirect)/`mcp__opencode__*` path-bearing を block する。
`opencode.json` 経由で directory plugin を無効化できる場合は config ファイル
も保護対象に加える(§17 の検証結果で確定)。

## 13. 監査ログ

MVP では既存 `AuditRecord`(schema v1)のまま、`HookAgent::audit_name()` に
`"opencode"` を追加するのみ。`tool` には正規化後名が入る(既存 7 adapter と
同一の挙動)。

初版仕様にあった `session_id` / `call_id` / `original_tool_name` /
`normalized_tool` / `cwd` / `worktree` / `facts` の監査転記は、
`AUDIT_SCHEMA_VERSION` の改版と全 adapter parity(他 host でも同等情報を
残すか)の設計判断を伴うため、**MVP から除外し独立マイルストーンとする**。

## 14. テスト

既存規約(inline `#[cfg(test)]` + bypass corpus + PBT + 重 E2E + fuzz)に
沿って以下を揃える:

- **unit**: tool/引数正規化テーブル全行、`patch` → `command` 複製と
  `collect_apply_patch_paths` 到達、未知 tool の `mcp__opencode__*` sanitize、
  不正 payload → fail-closed deny、ask 降格(reason に降格注記、exit 2)、
  init の path 解決(XDG / HOME fallback)・idempotency・conflict 拒否・
  dry-run 無書き込み・verify rollback、テンプレートの managed marker /
  binary 埋め込み検証(Pi M4 前例)。
- **proptest**: `opencode_input::parse` never panics / 半端な `HookInput` を
  返さない(Copilot/Cursor 前例)。`make pbt-quick` を正規化 M の完了条件に含む。
- **bypass corpus**(`tests/bypass/corpus.jsonl`): `bash rm -rf /`、
  curl|sh、`read {filePath: ".env"}`、patch で `.env` 更新、
  未知 tool `{path: ".opencode/plugin/ptuf.ts"}`、self-protection 一式。
- **e2e**(`tests/e2e_heavy.rs`): adapter parity を 7 → 8 に拡張。
- **fuzz**(`fuzz/`): `opencode_parse` target を追加(copilot parse 前例)。
- **mutants**: `.cargo/mutants.toml` のスコープは decision コア中心で adapter
  を含まないため変更不要(方針変更するなら別途)。

## 15. 実装順(イテレーティブ TDD)

`docs/plans/pi-coding-agent.md` の M0〜M11 をひな型に、各 M で
failing test → 実装 → `make check` green → commit/push:

- **M0**: ベースライン確認(`make check` green)
- **M1+M2**: `HookAgent::Opencode`(enum / `parse_agent` / `audit_name` /
  help)+ `hook_output::opencode`(bare envelope)+ `adapt_hook_decision`
  の ask 降格 + `decision_exit_code`(非網羅 match のため 1 commit)
- **M3**: `src/cli/opencode_input.rs`(★セキュリティ中核。§6〜§8)+
  bypass corpus + `make pbt-quick`
- **M4**: TS テンプレート + `include_str!` + Rust 検証テスト
- **M5**: `src/init/opencode.rs` + `--scope` 許可リスト変更 + XDG 解決
- **M6**: init verify + snapshot rollback
- **M7**: auto-detect 追加
- **M8**: self-protection パス追加 + corpus 追記
- **M9**: (Pi の native tool policy 相当)`mcp__opencode__grep/glob/list` の
  sensitive / self-protection 判定が既存 rule で足りるか確認し、不足分のみ
  `builtins.yaml` に追加
- **M10**: docs 更新(README / README.ja / docs/agents.md /
  docs/design/cli-and-hooks.md / architecture.md / testing.md / CHANGELOG)
- **M11**: e2e parity 拡張 + `make e2e` + 手動スモーク手順の記載

### Phase 2(別 PR)
- MCP server/tool identity 復元(`mcp__<server>__<tool>`)
- 監査 metadata 拡張(§13。audit schema 改版とセット)

### Phase 3(別 PR)
- `permission.ask` hook 連携による ask 保持(OpenCode 側バグ #7006 /
  #19927 の解消と挙動安定を確認できた場合のみ)

## 16. ドキュメント記載事項

- OpenCode 対応は `ptuf init opencode` が `.opencode/plugin/ptuf.ts`
  (global は `~/.config/opencode/plugin/ptuf.ts`)を生成して行う。
- ptuf の Ask 判定は Deny に降格される。理由: OpenCode の `permission.ask`
  hook は現状不発火の既知バグがあり、`tool.execute.before` から対話確認を
  開始する API も無いため(将来 Phase 3 で ask 保持を検討)。
- ptuf は fail-closed guardrail として動作し、OpenCode の permission 設定や
  `--auto` にバイパスされない。`opencode.json` は変更しない。
- MCP / custom tool は MVP では `mcp__opencode__*` として扱い、汎用 path
  抽出により保護される。
- 環境変数: `PTUF_OPENCODE_TIMEOUT_MS`(既定 10000)。

## 17. 実装前検証項目(M3 着手前に実機 / ソースで確認)

初版レビューで確証が取れなかった点。仕様の該当箇所は検証結果で確定する:

1. `patch` ツールの引数名(`patchText`?)と patch 本文の形式
   (apply_patch 形式 / unified diff)→ §7 の reshape 先
2. OpenCode における MCP tool の `input.tool` 命名形式
   (`<server>_<tool>` 等)→ §6 の identity 判別可否
3. `opencode.jsonc` のサポート有無 → §3 の検出マーカー
4. `opencode.json` から directory plugin を無効化できるか
   → §12 の保護対象に config を含めるか
5. permission 設定のキー名(初版例の `external_directory` の実在確認)
   → §10 の docs 併用例
6. `tool.execute.before` で throw した Error message がモデル / ユーザーに
   どう表示されるか → reason 文言の設計

## 18. 受け入れ基準

1. `ptuf init opencode` 後、OpenCode `bash` の `rm -rf /` が実行前に
   block される(deny, exit 2, throw)。
2. `read {filePath: ".env"}` が既存 secrets policy で block。
3. `patch` による `.env` 更新が `collect_apply_patch_paths` 経由で block。
4. plugin / 設定への自己改変(write / edit / rm / sed -i)が
   self-protection で block。
5. ptuf 不在 / timeout / policy load 失敗 / JSON 破損がすべて fail-closed。
6. 既存 7 adapter の output / exit 契約を壊さない(既存テスト全 green)。
7. auto-detect に opencode が含まれる。
8. docs に導入手順 / ask 降格理由 / env vars / limitations を記載。

## スコープ外(MVP 除外)

npm package plugin 化 / OpenCode interactive ask(Phase 3)/
MCP identity 復元(Phase 2)/ 監査 metadata 拡張(Phase 2)/
`opencode.json` permission の自動編集。
