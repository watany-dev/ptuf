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

## 今後の候補

現時点でコードに入っていない候補:

- Cursor / Gemini など追加 adapter
- `dataflow.basic` の強化
- signed / pinned plugin 配布
- generated file など、project_hygiene の追加 rule
- optional WASM plugin runtime

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
