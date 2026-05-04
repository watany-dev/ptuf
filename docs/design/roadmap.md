# Roadmap and Design Principles

本書は ptuf の MVP マイルストーンと、全体を貫く設計原則をまとめる。
個別仕様は他章を参照。

## MVP スコープ

### v0.1 — 最小ガードレール (実装済み)

判定コアの拡張と、最も重要な 3 rule + `eval` 動作確認 CLI を提供する。

- `ptuf hook claude-code pre-tool-use` (引数なし互換モードも維持)
- `ptuf eval --tool Bash '<cmd>'`、`--help` / `--version`
- structured JSON response (Claude Code 形式の `hookSpecificOutput`)
- `Decision` 4 variants (`allow` / `monitor` / `ask` / `deny`) と
  `aggregate` (`deny > ask > monitor > allow`)
- `core.filesystem.destructive-rm`
- `core.network.remote-script-pipe`
- `core.secrets.sensitive-path-to-network`

### v0.2 — Plugin と Audit (実装済み)

- fact extraction 層 (`shell.argv` / `shell.pipeline`)。組み込み 3 rule も
  すべて facts ベースに書き換え済み
- YAML plugin loader (`apiVersion: ptuf.dev/v1, kind: Plugin`、`when:` DSL、
  `requires:` 検証)
- plugin 内 `tests:` の実行 (`ptuf plugin test <path>`)
- config scope merge (`builtin → /etc/ptuf → ~/.config/ptuf → <repo>/.ptuf.yaml
  → <repo>/.ptuf.local.yaml`)、`mode` / `failClosed` / `packs.*.enabled` /
  `plugins` / `allowlists` / `audit.*` を扱う
- audit JSONL 出力 (`AuditSink` trait、`NoopSink` / `MemorySink` / `JsonlSink`)
- redaction (strict): env token 代入、GH / OpenAI / AWS / JWT トークン、
  HTTP basic auth、PEM blob を `***` 置換
- `hardDeny: true` rule は下位 scope の allowlist で覆せない。
  `expiresAt` を過ぎた allowlist は自動失効

### v0.3 — Tool 拡張と self-protection (実装済み)

- `Read / Edit / Write / WebFetch` tool 対応 (HookInput accessor + tool 別
  fact extraction `path` / `url` / `sensitive_path`)
- `core.secrets.sensitive-read` (Read/Edit 経由の credential 読取を deny)
- `core.self_protection` 5 rule (ptuf binary / config / plugins /
  `.claude/settings*.json` / hook script)
- `core.git` 7 rule (force-push / force-push-with-lease / reset --hard /
  clean -fdx / branch -D / stash clear / remote set-url)
- `ptuf init claude-code` (`~/.claude/settings.json` 冪等 install、
  `--dry-run` / `--settings <PATH>` flag)
- `ptuf doctor` (Binary / Project / Effective config / Plugins /
  Claude integration の診断レポート、`--json` は v0.4)
- CLI 経路の fail-closed (`core.engine.policy-load-failed`)
- plugin DSL 4 leaf 追加: `path.filePathPrefixAny` / `url.schemeAny` /
  `url.hostAny` / `sensitive.pathKindAny`

### v0.4 — 多 adapter と運用

- `core.project_hygiene`
- `dataflow.basic` facts (同一 transcript 内の co-occur を超えた追跡)
- MCP tool 対応
- org policy 配布 (`/etc/ptuf/policy.yaml`)
- 署名 / pin 付き plugin
- optional WASM plugin runtime
- Codex / Cursor / Gemini CLI adapter
- `ptuf doctor --json` 出力

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
