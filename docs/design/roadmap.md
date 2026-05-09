# Roadmap と設計原則

本書は、どこまで実装済みで、どこから先が将来候補かを簡潔に整理する。

## マイルストーン整理

公開バージョン `v0.0.1` にこれら M1〜M4 をまとめて含めた。M1〜M4 は
リリースタグではなく、実装の段階を区切るための内部マイルストーン名である。

### M1 — 最小ガードレール (実装済み)

- `Decision` と `aggregate`
- `ptuf hook claude-code`
- `ptuf eval --tool <name> <command>`
- `core.filesystem.destructive-rm`
- `core.network.remote-script-pipe`
- `core.secrets.sensitive-path-to-network`

### M2 — Config / Plugin / Audit (実装済み)

- layered YAML config
- YAML plugin loader
- `ptuf plugin test <path>`
- audit JSONL
- `mode`, `failClosed`, allowlist

### M3 — ツール面の拡張 (実装済み)

- `Read` / `Edit` / `Write` / `WebFetch`
- `core.secrets.sensitive-read`
- `core.git` 11 rule
- `core.self_protection` 6 rule
- `ptuf init claude-code`
- `ptuf doctor`

### M4 — adapter / project facts / MCP (実装済み)

- `ptuf hook codex`
- `ptuf init codex`
- MCP top-level `path` / `url` / `content` fact 抽出
- `project` facts (lock file, branch, protected branch)
- `core.project_hygiene` v1
- audit schema v1 拡張 (`agent`, `pluginVersions`, `allowlistId`)

### M5 — GitHub Copilot adapter (実装済み, `v0.1.0` 予定)

- `ptuf hook copilot` (snake/camel 入力正規化、bare JSON envelope、
  すべての Decision で exit `0`、`Ask` → `Deny` demote)
- `ptuf init copilot --profile local` (`<repo>/.github/hooks/ptuf.json` を
  idempotent / atomic に書き込む)
- `ptuf doctor` の `GitHub Copilot integration` section と
  `doctor --json` の `copilot` field
- `core.engine.invalid-payload` / `core.engine.policy-load-failed` を
  bare JSON + exit `0` で流用する fail-closed 経路
- audit `agent: "copilot"` を許容

### M6 — Kiro CLI adapter (実装中, `v0.1.0` 予定)

- `ptuf hook kiro` (Kiro `preToolUse` payload 正規化、tool 名 alias と
  `@server/tool` MCP 化、`Ask` → `Deny` demote、JSON envelope を持たず
  stderr + exit `2` で deny を返す fail-closed 経路、`core.engine.*`
  reserved rule の流用) — Phase 1 PR で実装済み
- `ptuf init kiro` (`.kiro/agents/<name>.json` への idempotent 書き込み、
  `--scope local|global`、`--agent-config`、`--verify [--json]`) — Phase 2
  PR で実装済み
- `ptuf doctor` の `Kiro CLI integration` section と `doctor --json` の
  `kiro` field — Phase 3 後続 PR
- `Read` / `Edit` / `Write` の `paths[]` / `operations[].path` を core
  `collect_event_paths` で重複排除しつつ収集する additive 拡張 — Phase 1
  PR で実装済み
- audit `agent: "kiro"` を許容 — Phase 1 PR で実装済み

## 今後の候補

現時点でコードに入っていない候補:

- Cursor / Gemini など追加 adapter
- `ptuf init copilot --profile cloud` (cloud agent 用 wrapper script
  + JSON。network egress / firewall / installer 取得経路の整理が必要)
- `dataflow.basic` の強化
- signed / pinned plugin 配布
- generated file など、project_hygiene の追加 rule
- optional WASM plugin runtime
- CLI parser の分割または `clap` derive 等への移行
- `engine/{evaluator,allowlist,audit}.rs` などへの Engine 分割
- builtin rule と plugin DSL の統合 (`builtins.yaml` + DSL compiler など)
- daemon 化時の plugin loader cache (`Arc<LoadedPlugin>` など)
- `parse<'a>(&'a str) -> Bash<'a>` 形式の borrowed shell AST

## 設計原則

- **deterministic first**  
  文字列や facts に基づく決定的な判定を優先する
- **default strong, override explicit**  
  既定は強く、緩和は config / allowlist に明示させる
- **stdout is protocol-only**  
  hook response 以外を stdout に混ぜない
- **fail closed in CLI paths**  
  policy を読めなければ `hook` / `eval` は deny する
- **self-protection is mandatory**  
  guardrail 自体の無効化を block する
- **plugin rules must be testable**  
  `tests:` と `ptuf plugin test` を前提にする
