# Roadmap と設計原則

本書は、どこまで実装済みで、どこから先が将来候補かを簡潔に整理する。

## マイルストーン整理

公開バージョン `v0.0.1` にこれら M1〜M4 をまとめて含めた。M1〜M4 は
リリースタグではなく、実装の段階を区切るための内部マイルストーン名である。

### M1 — 最小ガードレール (実装済み)

- `Decision` と `aggregate`
- `ptuf hook claude-code`
- `ptuf check --tool <name> <command>`
- `core.filesystem.destructive-rm`
- `core.network.remote-script-pipe`
- `core.secrets.sensitive-path-to-network`

### M2 — Config / Plugin / Audit (実装済み)

- layered YAML config
- YAML plugin loader
- `ptuf plugin check <path>`
- audit JSONL
- `mode`, `failClosed`, allowlist

### M3 — ツール面の拡張 (実装済み)

- `Read` / `Edit` / `Write` / `WebFetch`
- `core.secrets.sensitive-read`
- `core.git` 11 rule
- `core.self_protection` 6 rule
- `ptuf init claude-code`

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
- `ptuf init copilot` (`<repo>/.github/hooks/ptuf.json` を
  idempotent / atomic に書き込む)
- `core.engine.invalid-payload` / `core.engine.policy-load-failed` を
  bare JSON + exit `0` で流用する fail-closed 経路
- audit `agent: "copilot"` を許容

### M6 — Kiro CLI adapter (実装済み, `v0.1.0` 予定)

- `ptuf hook kiro` (Kiro `preToolUse` payload 正規化、tool 名 alias と
  `@server/tool` MCP 化、`Ask` → `Deny` demote、JSON envelope を持たず
  stderr + exit `2` で deny を返す fail-closed 経路、`core.engine.*`
  reserved rule の流用)
- `ptuf init kiro` (`<repo>/.kiro/agents/*.json` と `$HOME/.kiro/agents/*.json`
  の **全 JSON** への idempotent な hook 注入。空 scope は
  `agents/default.json` で fallback。`--new-agent` で legacy 単独ファイル動作)
- `Read` / `Edit` / `Write` の `paths[]` / `operations[].path` を core
  `collect_event_paths` で重複排除しつつ収集する additive 拡張
- audit `agent: "kiro"` を許容

### M7 — Cline adapter (実装済み, post-`v0.1.0`)

- `ptuf hook cline` (Cline SDK `tool_call` / legacy `preToolUse` payload
  正規化、tool 名 alias と `use_mcp_tool` の MCP 化、`Ask` → `Deny` demote、
  `Allow` / `Monitor` は `{}` / `Deny` は cancel JSON envelope を stdout に
  書きすべての Decision で exit `0`、`shouldContinue` 非出力、`core.engine.*`
  reserved rule を流用する fail-closed 経路)
- `ptuf init cline` (`<repo>/.clinerules/hooks/PreToolUse` への `0700`
  wrapper script を idempotent / atomic に書き込む。repo root が無ければ
  `~/Documents/Cline/Hooks/` へ fallback、Windows は `PreToolUse.ps1`、
  非 ptuf hook は `HookFileConflict` で保護)
- `ptuf init` auto-detect が Cline を検出
- audit `agent: "cline"` を許容

### M8 — `.env` 保護穴塞ぎ (実装済み, post-`v0.1.0`)

詳細は `docs/adr/0001-env-protection-gaps.md`。

- `core.secrets.sensitive-bash-read` (Ask / High / overridable) 追加。
  Bash の reader head allowlist + `<` redirect で機密 path の単独読みを
  捕捉する
- `core.secrets.sensitive-read` の matcher を `Read` / `Edit` /
  `Write` / `apply_patch` + path 持ち MCP に拡張
- 機密 path 正規表現を case-insensitive 化 (PEM_BLOB のみ
  `(?-i:...)` で RFC 7468 準拠を維持)、dotenv anchor を glob meta /
  `=` に拡張
- `facts.path.collect_mcp_paths` に同義キー (`file_path`, `target`,
  `dest`, `source`, `from`, `to`, ...) を追加
- `facts.collect_sensitive` で `expanded` / `canonical_or_raw` も
  classify (symlink bypass を塞ぐ)

### M9 — ファイル中身のインジェクション検査 (実装済み, `v0.1.1`)

- `core.injection.invisible-chars` (Ask / High / overridable) 追加。
  ptuf で初めて評価中に対象ファイルを開き、中身をバイト単位で静的検査
  する rule。レビュアーには無害に見えるファイルに不可視文字を仕込む
  間接プロンプトインジェクションを検出する
- 検出カテゴリは 5 種: zero-width / 不可視 Unicode (不可視数学演算子
  U+2061–2064 を含む)、BiDi 制御文字と方向マーク LRM/RLM/ALM
  (Trojan Source)、Unicode Tag 文字 (ASCII smuggling)、variation
  selector supplement U+E0100–E01EF (data smuggling)、C0/C1 制御文字
- 対象は `Read` / `Edit` / path 持ち MCP tool / Bash の reader head。
  allowlist は `sensitive-bash-read` と共通だが、hex ダンプ系
  (`xxd` / `od` / `hexdump`) は隠し文字を可視化するため対象外。
  `Write` / `apply_patch` は agent 自身が書く内容のため対象外
- 新 pack `core.injection` を既定 enabled で追加
- I/O は best-effort fail-open。ファイル欠如・非通常ファイル・バイナリ
  (NUL バイト / denylist 拡張子)・非 UTF-8 はすべて素通り、scan は
  先頭 1 MiB のみ

### M7 — CLI ゼロベース簡素化 (実装済み, `v0.1.0` 予定 / breaking)

- `ptuf init` を引数なしで auto-detect (cwd の repo root と `$HOME` から
  agent 候補を検出して全部 install)
- per-subcommand `--json` を廃止しトップレベル global flag `--json` へ
  統合
- `ptuf init` の path-override flag (`--root` / `--hooks` / `--config` /
  `--settings` / `--agent` / `--agent-config` / `--scope` / `--profile`)
  を撤去
- verify を既定で実行、`--no-verify` で opt-out。`--dry-run` 指定時は
  verify も自動的に off
- `ptuf eval` → `ptuf check`、`ptuf plugin test` → `ptuf plugin check`
  にリネーム
- `ptuf doctor` を完全に廃止 (代替は `ptuf init --dry-run [--no-verify]`)

## 今後の候補

現時点でコードに入っていない候補:

- Cursor / Gemini など追加 adapter
- cloud Copilot agent 向け wrapper script + JSON (network egress /
  firewall / installer 取得経路の整理が必要)
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
  policy を読めなければ `hook` / `check` は deny する
- **self-protection is mandatory**  
  guardrail 自体の無効化を block する
- **plugin rules must be testable**  
  `tests:` と `ptuf plugin check` を前提にする
