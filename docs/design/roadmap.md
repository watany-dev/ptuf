# Roadmap and Design Principles

本書は ptuf の MVP マイルストーンと、全体を貫く設計原則をまとめる。
個別仕様は他章を参照。

## MVP スコープ

### v0.1 — 最小ガードレール

判定コアの拡張と、最も重要な 3 rule + `eval` 動作確認 CLI を提供する。

- `ptuf hook claude-code pre-tool-use` (現状の引数なし起動も互換維持)
- Bash command の AST / argv / pipeline 抽出
- structured JSON response (Claude Code 形式の `hookSpecificOutput`)
- `core.network.remote-script-pipe`
- `core.filesystem.destructive-rm`
- `core.secrets.sensitive-path-to-network`
- `ptuf eval --tool Bash '<cmd>'`

### v0.2 — Plugin と Audit

- YAML plugin loader
- plugin 内 `tests:` の実行 (`ptuf plugin test`)
- config scope merge (`builtin → org → user → project → local`)
- audit JSONL 出力
- redaction (strict)

### v0.3 — Tool 拡張と self-protection

- `Read / Edit / Write / WebFetch` tool 対応
- `core.self_protection` (ptuf binary / config / `.claude/settings*.json`)
- `core.git` 全 rule
- `ptuf init claude-code`
- `ptuf doctor`

### v0.4 — 多 adapter と運用

- `core.project_hygiene`
- MCP tool 対応
- org policy 配布 (`/etc/ptuf/policy.yaml`)
- 署名 / pin 付き plugin
- optional WASM plugin runtime
- Codex / Cursor / Gemini CLI adapter

各 milestone の rule と CLI が揃った時点でリリースタグを切る。

## 設計原則

- **deterministic first** — LLM による曖昧判定を default にしない。決定性のある
  facts ベースで判断する
- **default strong, override explicit** — 強い default を提供し、緩めるには
  明示的な allowlist / config を要求する
- **deny reasons must be actionable** — 止めた理由と直し方を必ず返す
  ([`decision-model.md`](decision-model.md) の Rule Feedback)
- **plugin rules must be testable** — plugin に `tests:` セクションを必須化し、
  `ptuf plugin test` で検証可能にする
- **no arbitrary executable plugins by default** — 任意 executable の plugin は
  default で許可しない。WASM 等は v0.4 以降の opt-in
- **stdout must remain hook-protocol clean** — debug は stderr / audit log。
  stdout は hook protocol 専用
- **fail closed when policy cannot be loaded in enforce mode** — `enforce` +
  `failClosed: true` が標準
- **ptuf must protect its own config and hook registration** — prompt injection
  で guardrail 自体を無効化されないようにする
  ([`policy-packs.md`](policy-packs.md) の `core.self_protection`)
