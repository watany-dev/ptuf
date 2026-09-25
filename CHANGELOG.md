# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- `core.self_protection.cursor-settings` / `core.self_protection.cline-settings`
  を追加。対応 8 host のうち Cursor と Cline だけ hook 登録が自己保護の対象外で、
  guarded session が `.cursor/hooks.json` の削除・書き換えや Cline の
  `PreToolUse` wrapper (`.clinerules/hooks/` / `~/Documents/Cline/Hooks/`) の
  上書きで ptuf hook を外せていた。あわせて `.cursor/hooks.json` の
  `preToolUse` command が参照する実行ファイルを `core.self_protection.hook-script`
  の対象に加えた。

### Changed (BREAKING)
- `rules::remote_pipe`(`RemoteScriptPipe`)を削除。`static RULES` に載らない
  テスト専用 oracle で、本番の判定は DSL 版 `core.network.remote-script-pipe`
  (`src/rules/builtins.yaml`)が行っていた。パリティ PBT は DSL への直接
  アサーションに置き換え、回帰は `tests/bypass/corpus.jsonl` が守る。公開 API の
  削除にあたるため 0.9.0 へ bump。(#209)

### Fixed
- ラベル無しの PKCS#8 PEM ヘッダ `-----BEGIN PRIVATE KEY-----` が機密分類器を
  すり抜けていた問題を修正。audit redactor 側 (ラベル任意) と分類器側
  (ラベル必須) でパターンが食い違っていたのが原因で、分類器統合に伴い
  `PEM_PRIVATE_KEY_{BEGIN,END}` の単一定義へ収斂させた。(#210)

### Changed (BREAKING)
- 機密 path 分類器を `facts::sensitive` の `PROBES` 1 系統に統合。
  `rules::patterns` の `SENSITIVE_PATH` / `SENSITIVE_NEEDLES` を削除し、
  `matches_sensitive_path` は新設の短絡版 `sensitive::matches` へ委譲する
  薄い adapter になった。2 実装の等価性を縛っていた PBT 群は、実装が 1 つに
  なったため削除 (engine レベルの surface 間パリティ検証は継続)。公開 static の
  削除にあたるため 0.10.0 へ bump。(#210)

### Changed
- テスト用の環境変数ダブルを `config::scope::MapEnv`
  (`#[cfg(test)] pub(crate)`) 1 個に集約。`facts::path` / `self_paths` /
  `config::scope` / `update::exe` / `init::opencode` に散っていた同型の
  `MapEnv` 5 定義と、`init` の `EmptyEnv` / `XdgEnv` を削除した。公開 API に
  影響はない。(#212)

### Removed (BREAKING)
- `ProtectedPaths::classify_input_with_paths` /
  `ProtectedPaths::classify_input_with_paths_pair` — 4 段あった
  `classify_input` の wrapper 連鎖を、facts 抽出を自前で行う
  `classify_input` と engine 向けの `classify_input_prepared` の 2 本に
  集約した。中間 2 本はどこからも呼ばれていなかった。(#216)
- `self_paths::discover_repo` — `config::repo::discover` の 1 行 wrapper。
  本番の呼び出し元は全て `config::repo::discover` を直接使っている。(#216)
- 上記の公開 API 削除にあたるため 0.11.0 へ bump。

### Changed
- 6 つの agent adapter (`copilot` / `kiro` / `cline` / `cursor` / `pi` /
  `opencode`) の入力正規化を `src/cli/input_helpers.rs` に集約。個別の
  `*InputError` enum 6 種を単一の `InputError` に統合し、`sanitize_tool_name` /
  `normalize_at_mcp` / `decode_args` / `first_string` の重複実装を共有化した
  (crate 内部のみ、公開 API 変更なし)。空 tool name のメッセージは
  `hook payload tool_name must not be empty` に統一。cline / kiro の
  `tool_input` も共有 `decode_args` 経由となり、JSON 文字列として渡された
  object を展開するようになった (従来は `raw` キーに素通し)。(#222)

### Changed
- init adapter 9 種に複製されていた atomic write ヘルパ (`mkdir -p` →
  temp file → `rename`) を `init::write_atomically_at` 1 箇所に集約。
  各 adapter の `write_atomically` / `write_json_atomically` /
  `write_toml_atomically` / `write_executable_atomically` と
  `sibling_temp_path` ラッパを削除し、`write_install_bytes` /
  `write_install_json` を直接呼ぶ。
- 権限ビットだけが違った `write_secure` (0600) / `write_executable` (0700)
  を `FileMode` を取る単一の writer に統合。書き込まれるモードは従来と同一。(#218)

### Changed (BREAKING)
- 各 adapter の `pub fn detect_binary()` (8 個) を削除し、共有実装を
  `init::detect_binary()` として公開。`init::claude_code::detect_binary()` 等を
  呼んでいる下流は `init::detect_binary()` に置き換える必要がある。公開 API の
  削除にあたるため 0.12.0 へ bump。(#219)

### Changed
- init adapter 間でコピーされていた JSON hook 操作ヘルパを
  `src/init/json.rs` に集約。`read_hooks` / `read_settings` /
  `read_agent_config` の共通部分は `json::read_or_default` /
  `json::read_object` に、`ensure_object` / `ensure_array` /
  `ensure_version` は 1 実装に、5 箇所の `append_hook` に共通していた
  `hooks.<event>` 配列の掘り下げは `json::hook_array` になった。
  生成される JSON とエラーメッセージは従来と同一。(#219)

### Removed (BREAKING)
- `init::kiro::install` — CLI は `install_with_report` のみを使っており、
  kiro 固有の報告 (`KiroInstallExtras`) を捨てるだけの wrapper だった。
- `init::codex::default_home_hooks_path` / `default_home_config_path` —
  クレート内外から未参照。
- `init::kiro::DEFAULT_CACHE_TTL_SECONDS` を非公開化 (agent skeleton の
  生成内部でのみ使用)。
- 上記の公開 API 削除にあたるため 0.13.0 へ bump。(#221)

### Changed
- 内部の `AdapterRunReport` を struct から enum (`Simple` / `Kiro`) に変更。
  kiro 専用フィールドを共通型から外し、`src/cli/run.rs` の `kiro: None` ×11 を
  解消した。
- `init::claude_code::install` が同一の `InstallOutcome` literal を 3 回
  構築していたのを 1 箇所に集約。(#221)

### Removed (BREAKING)
- feature `testing` と公開モジュール `ptuf::testing` を削除。proptest の
  strategy 群 (`src/testing/proptest.rs`) は `#[cfg(test)]` の crate 内
  モジュールになり、公開 API からも出荷バイナリからも消えた。
- `proptest` は optional dependency をやめ dev-dependency のみになった。
- 未参照の strategy `bash_with_quoting` を削除。
- 上記の公開 API 削除にあたるため 0.14.0 へ bump。(#215)

### Changed
- `tests/{engine,rules,cli_parse,filter}_proptest.rs` を
  `src/testing/{engine,rules,cli_parse,filter}_pbt.rs` に移動し unit test 化。
  `[[test]] required-features = ["testing"]` の付け忘れでテストが黙って
  skip される状態を解消した。Makefile / CI / docs の `--features testing`
  指定 (10 箇所) も削除。(#215)
- lib テストの CWD 競合を解消: プロセス CWD を読むテストも `CwdGuard` と
  同じ `CWD_LOCK` を取るようにした (PBT が同一バイナリに移り並列度が
  上がったことで顕在化した flake)。(#215)

### Removed (BREAKING)
- crate 外から参照されていない非テスト `pub` 項目を一掃した。`src/` 配下
  (`src/main.rs` と `src/testing/**` を除き、末尾の `#[cfg(test)] mod tests` を
  切り落として数えた `pub fn|struct|enum|trait|type|const|static|mod|use` 宣言)
  は 482 → 158 件になり、`cargo-semver-checks` が守る公開 API は
  `src/lib.rs` の re-export (`Decision` / `aggregate` / `Engine` /
  `EngineError` / `Outcome` / `Facts` / `HookInput` / `decide` /
  `try_decide`)、`fuzz/` が叩く信頼境界 (`config::yaml::parse_str` /
  `config::merge::merge` / `plugin::load_str` / `facts::shell::parse` /
  `cli::fuzz_copilot_parse` / `cli::fuzz_opencode_parse`)、および
  `tests/` / `benches/` が使う範囲に縮小した。
- `AuditRecord::build` — 0.6.0 から deprecated だった builder shim。
  `AuditRecord::builder` を使う。
- `InitError::UnknownAgent` — 構築箇所が無い variant。agent 名の検証は
  `cli::ParseError::UnknownAgent` が担う。
- `facts::path::extract` の production 版 — 単一パス形は test だけが使うため
  `#[cfg(test)]` に落とした。production は `extract_all` を通る。
- `LoadedPlugin::rule_count` / `PluginSet::rule_count` — `rules.len()` /
  `rules().count()` と同値の重複アクセサ。呼び出し側をそちらに寄せて削除した。
- `facts::sensitive::classify` を `#[cfg(test)]` に落とした。buffer を取る
  `classify_into` の `Vec` 版で、production からは呼ばれていない。
- `hook_output::opencode::OpencodeHookResponse` — `PiHookResponse` の未使用 alias。
- 上記の公開 API 削除にあたるため 0.15.0 へ bump。(#217)

### Changed
- `unreachable_pub = "deny"` を有効化 (`Cargo.toml [lints.rust]`)。内部項目に
  付いた inert な `pub` が再び増えるのを止める。この lint は *モジュール鎖が
  crate 内に閉じている* 項目しか見ないため、公開 API に属さない module 宣言は
  `pub(crate) mod` に落とし、lint が実際に効く状態にした。`unreachable_pub` と
  方向が衝突する `clippy::redundant_pub_crate` (nursery) は `allow` にした。
- 内部専用だった module 宣言を `pub(crate) mod` に降格した
  (`hook_input` / `init` / `reason` / `self_paths` / `update`、および
  `audit` / `config` / `facts` / `plugin` / `rules` / `hook_output` 配下の
  子モジュール)。`pub` のまま残したのは `src/lib.rs` の re-export 経路と
  `fuzz/` / `tests/` / `benches/` が名指しする
  `audit::record` / `facts::shell` / `plugin::dsl` / `config::yaml` /
  `config::merge` のみ。
- `plugin::runner::run_str` を `#[cfg(test)]` に移し、独自の YAML パースを
  やめて production と同じ `plugin::load_str` 経由に統一した。test fixture も
  `apiVersion` / `kind` / 予約 id の検証を通る。`run` と `run_str` は
  `run_loaded` で本体を共有する。(#217)

## [0.8.0] - 2026-09-17

### Added
- audit record に `allowlistIds` (`string[]`) を追加。allowlist が rule を
  抑止した全件を最終 decision に関わらず残す。`allowlistId` は後方互換のため
  `Allow` 時の先頭 1 件のまま。
- `ConfigError::Allowlist` / `ConfigError::Version`。allowlist `when` /
  `expiresAt` と未対応 `version` の load 時検証失敗を表す。
- `PluginSet::try_push` — rule id を builtin / 既存 plugin と照合してから追加。

### Changed (BREAKING)
- `config::merge::merge` が `Result<Config, ConfigError>` を返す。
  allowlist / version の検証失敗を伝播する。
- `AuditRecord` と `engine::Outcome` に `allowlist_ids: Vec<String>` フィールドを追加。
  構造体リテラルを書いている下流は更新が必要。
- `ConfigError` に `Allowlist` / `Version` variant を追加。網羅 `match` している
  下流は更新が必要。

### Fixed
- allowlist `when` の DSL コンパイル失敗が無条件 allowlist に化ける fail-open
  を解消。不正 `when` / 不正 `expiresAt` / `version != 1` は policy-load-failed
  (issues #202)。
- `path.filePathPrefixAny` が未正規化文字列 prefix 比較だったため `..` /
  symlink / 部分一致で allowlist を広げられた問題を、path と prefix の両方を
  正規化 + `Path::starts_with` に変更して修正 (issue #203)。prefix の
  祖先 alias (`/tmp` → `/private/tmp`) は辿るが、最終成分の張り替え
  symlink は辿らず allowlist 拡大を防ぐ。
- plugin 間 / plugin と builtin の rule id 衝突を load 時に reject。
  `is_hard_deny_rule_id` は同 id のどれかが `hardDeny` なら true にし、
  monitor 降格の first-wins 抜けを塞ぐ (issue #204)。
- config の `plugins[].path` / `audit.path` が home 展開も config ファイル基準の
  相対解決もしなかった問題を修正 (issue #205)。
- `overridable: false` の rule が `packs.<prefix>.enabled: false` で消えていた
  非対称を、rule override と同じ `is_overridable` 判定に揃えて修正 (issue #206)。
  allowlist ヒットは `includeAllowed: false` でも audit に残る。

## [0.7.0] - 2026-08-16

### Added
- CI に [`zghalint`](https://github.com/watany-dev/zghalint) v0.0.1 を追加
  (workflow linter)。cargo-dist 生成の `release.yml` は設定ファイルで
  ignore（npm 復旧の `workflow_dispatch` tag checkout が SEC021）。
- **`kiro-v2` agent token** — Kiro CLI の hook 仕様が v3 で変わるため、
  adapter 世代ごとに versioned token を持たせた。現行 adapter は
  `ptuf init kiro-v2` / `ptuf hook kiro-v2`。無印の `kiro` は
  **最新 Kiro adapter を指す floating alias** で、v3 adapter が入れば
  `ptuf init kiro` はそちらへ追従する (今日の契約に固定したい場合は
  `kiro-v2` を明示する)。未知の `kiro-v3` は該当 adapter が入るまで reject する。
  監査名は世代をまたいで `"kiro"` のまま。
- **`ptuf audit`** — 監査 JSONL の read-only 閲覧 CLI (`--path` /
  `--decision` / `--rule` / `--tool` / `--since` / `--limit` / `--stats`)。
  書き込み経路は変更しない。`--json` の `records` は元 JSON object を保持し、
  text 出力は C0 / DEL / C1 / BiDi を escape する。
- `apply_patch` の added 行 (`+` prefix) を content lane で PEM スキャン
  (`facts::patch::added_content`)。非機密 path 宛 patch への PEM 埋め込み bypass
  (ADR 0001 known limitation) を解消。
- Cline adapter が `patch` / `patchText` / `content` を `command` へ正規化
  (OpenCode `reshape_patch` と同等)。Cline 経由 apply_patch の path / content
  空振りを修正。

### Fixed
- Nested prefix wrappers (`sudo env …`) are unwrapped for every rule and
  the plugin DSL, not only `core.git` / `destructive_rm`.
- `core.project_hygiene` reuses `core.git` matchers, so
  `git -c key=val reset --hard` is denied on a protected branch.
- Pi hook template now caps captured output, SIGKILLs a hung hook, and
  rejects decision/exit-code inconsistency (parity with OpenCode).
- CI `msrv` job installs Rust 1.93.0 instead of rebuilding stable.

### Changed
- RFC3339 formatting/parsing no longer depends on the `time` crate.
- `make check` installs only `cargo-deny`; tarpaulin / fuzz / mutants /
  semver-checks stay on their own targets.
- Unused `benches/perf.rs` + `divan` removed.
- **Kiro agent JSON に書き込む hook command が `ptuf hook kiro-v2` になった。**
  無印 `kiro` が最新版 alias になったため、`ptuf hook kiro` と書かれた既存の
  hook 行は ptuf を upgrade した時点で v3 adapter へ黙って切り替わってしまう。
  これを防ぐため書き込む形を versioned に pin し、旧 ptuf が書いた
  `ptuf hook kiro` entry は次回 `ptuf init` で **その場で書き換える**
  (重複 append はしない)。書き換えが走ったファイルは `AlreadyPresent` ではなく
  `Installed` として報告される。

### Changed (BREAKING)
- `cli::Command` に `Audit(AuditOptions)` variant を追加。
  `Command` は `#[non_exhaustive]` ではないため、この enum を網羅 `match`
  している下流ライブラリ利用者は更新が必要。

## [0.6.0] - 2026-08-12

### Changed (BREAKING)
- `facts::shell::Argv` に公開フィールド `subst_argv: Vec<Argv>` を追加
  (ADR 0008)。既存の `Argv { … }` 構造体リテラルは更新が必要。
- `PluginError` に `ReservedRuleId` / `DuplicateRuleId` variant を追加。
  `PluginError` は `#[non_exhaustive]` ではないため、この enum を網羅 `match`
  している下流ライブラリ利用者は更新が必要。

### Changed
- builtin rule の DSL 統合スライス 1 (ADR 0004): `core.network.remote-script-pipe`
  を `src/rules/builtins.yaml` (plugin DSL) から提供するように変更。reason /
  remediation / rule id / hardDeny / severity は旧 Rust 実装と wire 互換。旧
  実装 (`rules::remote_pipe::RemoteScriptPipe`) はパリティ oracle として残置。

### Fixed
- `core.secrets.sensitive-read` の書き込み本文スキャンを data-bearing shape
  (PEM blob) のみに限定 (`classify_content_into`)。手順書等のドキュメントが
  `~/.aws/credentials` や `*.tfstate` を含む ARN に言及しただけで Write が
  hard-deny される false positive を解消。書き込み**先** path・Bash・URL の
  分類は従来どおり全 shape を対象とする。

### Added
- STRIDE 脅威モデル (`docs/design/threat-model.md`) と `SECURITY.md` の
  No Telemetry / Threat Model 節。
- CI MSRV job を `cargo check` から release build + test harness compile +
  `cargo doc` に拡張 (公開 MSRV ピンが実ビルド可能であることを保証)。
- Process substitution (`<(…)` / `>(…)`) 本体を `Argv.subst_argv` へ
  re-parse (ADR 0003 C / issue #162)。`bash <(curl …)` と
  `bash -c "$(curl …)"` を `remote-script-pipe` が Deny。subst 再帰は
  fresh `seen_from` で `echo <(curl) | bash` の漏洩 FP を防ぐ。
- Command substitution (`$(…)` / backticks) 本体の bounded re-parse。
  `echo $(cat .env)` を `sensitive-bash-read` が Ask する (issue #161)。
  `Bash::commands()` は `subst_argv` も flatten する。悲観モードは
  budget 超過時の backstop として維持。
- 外部 plugin の rule id 検証: `core.` prefix の予約 (`ReservedRuleId`) と
  同一 plugin 内の id 重複 (`DuplicateRuleId`) を load 時に reject。
- `builtins.yaml` のコンパイル失敗 (構造的に到達不能、テストで pin) 時は
  deny-everything の fail-closed sentinel (`core.engine.builtin-load-failed`)
  に縮退。

### Security
- DSL 版 remote-script-pipe は fetch 側でも権限 wrapper の unwrap と
  `inner_argv` 再帰を行うため、旧実装が見逃していた
  `sudo curl … | sh` / `bash -c 'curl …' | sh` を新たに deny
  (`tests/bypass/corpus.jsonl` に must_catch として追加)。

## [0.5.0] - 2026-07-03

### Changed (BREAKING)
- `HookAgent` に `Opencode` variant を追加。
- `InitOptions` に `opencode: OpencodeInitOptions` field を追加。
- `ProtectedKind` に `OpencodeSettings` variant を追加。
- `ProtectedPaths` に `opencode_settings` field を追加。

### Added
- **OpenCode adapter** — `ptuf hook opencode` and `ptuf init opencode` install a
  managed TypeScript plugin under `plugins/ptuf.ts` (global XDG config or local
  `.opencode/`). Native tool names are normalised in `src/cli/opencode_input.rs`;
  Ask decisions demote to Deny because OpenCode cannot reliably prompt from
  `tool.execute.before`.
- **npm distribution** — `@watany-dev/ptuf` ships a zero-install-script JavaScript
  shim plus optional native platform packages for npm / npx users.

## [0.4.1] - 2026-06-29

### Fixed
- Pi Coding Agent extension template now targets the current package/API,
  uses Node child process spawning instead of Bun-only APIs, reads the current
  event input shape, and returns Pi's expected block reason fields.
- Sensitive-path network exfiltration checks now deny `/dev/tcp` and
  `/dev/udp` redirections without panicking.
- Self-protection path extraction now treats `sed` as a writer command.

## [0.4.0] - 2026-06-29

### Changed (BREAKING)
- `HookAgent` に `Pi` variant を追加。
- `InitOptions` に `pi: PiInitOptions` field を追加。
- `ProtectedKind` に `PiSettings` variant を追加。
- `ProtectedPaths` に `pi_settings` field を追加。

### Added
- **Pi Coding Agent** host adapter: `ptuf hook pi`, `ptuf init pi`, Rust
  input normalisation (`pi_input.rs`), TypeScript extension template,
  self-protection for `.pi/` paths, and auto-detect via `~/.pi/agent/` or
  `<repo>/.pi/`.

## [0.3.0] - 2026-05-31

### Changed (BREAKING)
- `HookAgent` に `Cursor` variant を追加。
- `InitOptions` に `cursor: CursorInitOptions` field を追加。

### Added
- Cursor hook runtime adapter (`ptuf hook cursor`) と `ptuf init cursor`
  (repo-local / global `.cursor/hooks.json`、`--scope` / `--root` /
  `--hooks` flag)。

## [0.2.0] - 2026-05-28

### Changed (BREAKING)
- `ptuf init kiro` の default 動作を変更: `<repo>/.kiro/agents/*.json`
  と `$HOME/.kiro/agents/*.json` の **すべて** に PreToolUse hook を
  注入する方式に切り替えた。これまでの「専用 `ptuf-guarded.json` を
  一つ作るだけ」の挙動は、`chat.defaultAgent` 等で別 agent を選ぶ
  ユーザーをサイレントに bypass していたため。legacy の単独作成は
  `--new-agent` flag で残置。scope 制限用に `--workspace-only` /
  `--global` を追加。`<scope>/.kiro/settings/cli.json` の
  `chat.defaultAgent` が同 scope に存在しない agent JSON を指している
  場合は `InitError::Schema` で fail-closed。`.kiro/agents/*.md` は
  patch 対象から除外。
- `init::kiro::TargetPaths` の構造変更:
  `{ agent_config_path: PathBuf }` → `{ agent_config_paths:
  Vec<ResolvedAgent>, skipped_non_json: Vec<PathBuf>,
  default_agent_names: Vec<KiroDefaultAgentReport> }`。
- `init::kiro::resolve_paths` に必須引数 `&KiroInitOptions` を追加。
- `init::kiro::install` の `&TargetPaths` 意味論を単一 path から多 path
  に変更 (signature 同型のまま受け取る struct shape が変わる)。
- `init::kiro::TargetPaths` の field を `pub(crate)` に降格 (struct
  自体は `pub` 維持の opaque handle)。embedded user は `resolve_paths`
  の戻り値を `install` にそのまま渡せれば足りるので、内部 field を
  直接読む API contract は外す。
- `core.self_protection.kiro-settings` の対象を `.kiro/agents/ptuf-
  guarded.json` 単独から `<repo>/.kiro/agents/*.json` + `$HOME/.kiro/
  agents/*.json` (起動時に列挙された実在 `*.json`) に拡張。`ptuf init
  kiro` の default mode で patch される全 agent JSON が self-protection
  の対象になる。空ディレクトリでは `kiro_settings` は空のまま (rule は
  発火しない)。

### Added
- `init::kiro` の新規 pub items: `KiroMode`, `ScopeFilter`,
  `KiroInitOptions`, `FALLBACK_AGENT_NAME`。kiro 固有の reporting 型
  (`Scope` / `ResolvedAgent` / `KiroDefaultAgentReport` /
  `KiroInstallExtras`) は CLI 内部 (`pub(crate)`) に閉じ込め、
  `pub fn install` の戻り値は pre-kiro と同じ素の `InstallOutcome`。
  CLI dispatcher は `pub(crate) fn install_with_report` 経由で extras
  を受領する。
- `ptuf init` の Kiro 専用 flag: `--new-agent` (legacy 単独 agent 作成)、
  `--workspace-only` (`<repo>/.kiro/agents/` のみ patch)、`--global`
  (`$HOME/.kiro/agents/` のみ patch)。

## [0.1.1] - 2026-05-18

### Added
- New rule `core.injection.invisible-chars` (pack `core.injection`,
  default-enabled). Statically inspects the *contents* of files an agent
  is about to read — `Read`/`Edit`, path-bearing MCP tools, and Bash
  reader heads (`cat`, `head`, …) — and returns `Ask` when it finds
  characters invisible to a human reviewer: zero-width/invisible
  Unicode, BiDi controls (Trojan Source), Unicode Tag chars (ASCII
  smuggling), and C0/C1 control bytes. This is the first ptuf rule that
  opens the target file during evaluation; I/O is best-effort and
  fail-open (missing/binary/non-UTF-8/oversize files pass through),
  scanning at most the first 1 MiB. `Write`/`apply_patch` are out of
  scope. See `docs/design/policy-packs.md` "core.injection".
- Homebrew tap distribution wired into `dist-workspace.toml` and
  `.github/workflows/release.yml` via the new `publish-homebrew-formula`
  job. `brew install watany-dev/tap/ptuf` becomes available on the next
  tagged release once the maintainer creates `watany-dev/homebrew-tap`
  and adds the `HOMEBREW_TAP_TOKEN` Actions secret. See
  `docs/RELEASING.md` "One-time setup" for the runbook.
- `homepage` added to `Cargo.toml` (required by cargo-dist for Homebrew
  formula generation).
- README and `docs/install.md` now document mise (`ubi` backend) and aqua
  (`github_release`) as no-curl install paths consuming the existing
  release archives.

## [0.1.0] - 2026-05-13

### BREAKING
- **CLI surface — zero-base simplification.** `v0.1.0` rewires the
  command grammar around auto-detect and a global `--json` flag.
  Migration guide:
  - `ptuf eval --tool <name> <command>` → `ptuf check --tool <name> <command>`.
    Verb is unified across check / plugin check.
  - `ptuf plugin test <path>` → `ptuf plugin check <path>`. (`test` clashed
    with the plugin DSL's per-rule `tests:` block.)
  - `ptuf doctor [--json]` is **removed**. `ptuf init --dry-run` (with
    optional `--no-verify`) reports the same agent / file state without
    writing or running the synthetic deny check. The
    `tests/contracts/doctor-schema-keys.json` fixture is deleted; the
    `init --json` verify report (`tests/contracts/init-verify-schema-keys.json`)
    is the supported observability surface going forward.
  - `--json` moves from per-subcommand to a **global pre-subcommand flag**:
    `ptuf --json init …` / `ptuf --json check …` / `ptuf --json plugin check …`.
    Subcommand-position `--json` (e.g. `ptuf init --json`) is rejected as
    `UnexpectedArgument`. `ptuf hook <agent>` rejects `--json` at parse
    time because the host's hook envelope is fixed.
  - `ptuf init` runs **auto-detect by default**. Without an agent argument
    it scans `$HOME/.claude/`, `<repo>/.codex/` / `$HOME/.codex/`,
    `<repo>/.github/`, and `<repo>/.kiro/` / `$HOME/.kiro/`, and installs
    every detected agent. Detection of zero agents exits `1` with
    `no agent detected`. `ptuf init <agent>` still pins to a single
    adapter.
  - **Verify is the new default.** `--verify` is removed; install
    automatically runs the synthetic deny + fail-closed checks. `--no-verify`
    opts out, and `--dry-run` (which writes nothing) implicitly disables
    verify.
  - All `init` path-override flags are removed: `--root`, `--hooks`,
    `--config`, `--settings`, `--agent`, `--agent-config`, `--scope`,
    `--profile`. Adapters now derive their write targets from the same
    cwd / `$HOME` lookup the auto-detect uses; `init kiro` falls back to
    `$HOME/.kiro/` when no repo root is found, and `init copilot` requires
    a repo root (returns `RepoRootNotFound`).
  - `InitError::HomeNotSet` and `InitError::RepoRootNotFound` Display
    strings updated to drop references to the removed flags.

### Added
- **GitHub Copilot adapter (`v0.1.0` target).** First-class `copilot`
  agent across hook / init:
  - `ptuf hook copilot` — accepts both snake (`tool_name` / `tool_input`)
    and camel (`toolName` / `toolArgs`) input shapes, applies tool name
    mapping (`bash`→`Bash`, `view`→`Read`, `edit`→`Edit`, `create`→`Write`,
    `web_fetch`→`WebFetch`, `powershell`→`Bash`), and writes a *bare* JSON
    envelope (`{"permissionDecision":"deny","permissionDecisionReason":"…"}`)
    on `Deny`. Because Copilot's hook protocol treats non-zero exit as a
    hook *failure* and may let the call through, every Decision — including
    the reserved `core.engine.invalid-payload` and
    `core.engine.policy-load-failed` rules — exits `0` to stay
    fail-closed. `Ask` is demoted to `Deny`.
  - `ptuf init copilot` — atomically writes
    `<repo>/.github/hooks/ptuf.json` with both `bash` and `powershell`
    command strings on the `preToolUse` array. Idempotent (detects
    existing entries via the `hook copilot` command tail).
  - `audit.agent` now accepts `"copilot"` alongside `claude-code` and
    `codex`.
- `ptuf init <agent>` install verification — after writing the hook
  configuration, runs a builtin-only Engine against a synthetic
  `rm -rf /` payload to confirm `core.filesystem.destructive-rm` fires,
  then forces a plugin-load failure to confirm the
  `core.engine.policy-load-failed` fail-closed path. If either check
  fails the install is rolled back to its pre-write state and the
  command exits `1`. `ptuf --json init` emits a `schemaVersion: 1`
  machine-readable report. `--no-verify` skips the checks; `--dry-run`
  implicitly disables them.
- `try_decide(&HookInput) -> Result<Decision, EngineError>` — fallible
  variant of `decide()` that surfaces config / plugin load errors instead
  of falling back to a default-configured engine. Embedded callers that
  want the same fail-closed contract as the CLI now have a direct API
  (review §1.6).
- `Bash::has_command_substitution: bool` — the shell parser now flags
  whether the command string contained a `` ` … ` `` or `$(…)` opening
  (including `$(…)` inside double-quoted spans). The substitution body
  is still folded into the surrounding word as opaque text; rules that
  need pessimistic handling can opt in by reading this flag (review §3.3).
- `Engine::drain_audit_write_warnings()` — accumulates per-record audit
  write failures (permission denied, disk full, …). The CLI hook and
  check entry points now drain these to stderr after each decision so
  silent audit loss is observable. Open failures continue to surface
  through `Engine::audit_warning()` (review D9).
- `core.engine.dynamic-eval` rule (Ask / Medium / overridable) — flags
  two-stage execution shapes such as `bash -c …`, `sh -c …`,
  `python -c …`, `node -e …`, `perl -e …`, `ruby -c|-e …`, and
  `eval …`. The inner code is opaque to the parser, so other rules
  cannot inspect what will actually run; the new rule asks the user to
  confirm. `sudo` wrappers are unwrapped before matching. Default-enabled
  via the new `core.engine` policy pack (review §2 / D4).
- `Pipeline.redirects: Vec<Redirect>` and `Bash::has_redirect` /
  `has_heredoc` / `has_process_substitution` parser surfaces. The
  tokenizer now recognises `>` / `>>` / `<` / `2>` / `&>` redirect
  operators with their target words, captures heredoc bodies up to the
  terminator (`<<TAG` / `<<-TAG`), and absorbs process substitution
  (`<(…)` / `>(…)`) into a single paren-balanced word. These let rules
  judge per-pipeline shapes that previously fell through the parser
  (review §2 / D4).
- `Engine::builder()` — canonical entry point for embed callers that
  want to inject a `Config`, `PluginSet`, `AuditSink`, or `repo_root`
  without going through `Engine::for_cwd`. Every builder-built engine
  runs `ProtectedPaths::collect_with_env`, so `binary` / claude / codex
  settings are populated even with `Config::default()`. Closes the
  embed-fallback gap left by the removed `Engine::default` shim
  (review §1.7).
- `Engine::protected_paths()` — read-only accessor for the engine's
  resolved self-protection target set. Useful for embed callers and
  tests that want to assert the binary / settings guardrail was wired.
- `PathFact { tool, raw, expanded, absolute, canonical_or_raw, origin }`
  expanded out of the previous `FilePath` shape. `expanded` carries the
  `~` / `$HOME`-resolved form, `absolute` adds the `base_dir` join when
  the input was relative, and `canonical_or_raw` falls back to
  `absolute` for any I/O failure (missing file, permission denied,
  symlink loop). `pub type FilePath = PathFact;` keeps the historical
  name compiling. `PathOrigin` distinguishes `ToolInputDirect`
  (`file_path`, MCP `path`) / `ToolInputNested` (`files[].path`,
  `paths[]`, `items[].path`) / `ApplyPatch` / `BashRedirect` (engine
  emits these from `Pipeline.redirects` so self-protection sees the
  same view as file-tool inputs) (review D8).
- `facts::path::from_bash_redirects(bash, repo_root) -> Vec<PathFact>`
  — public helper that walks a parsed `Bash`'s `Pipeline.redirects` and
  returns one `PathFact { origin: BashRedirect, tool: Write }` per
  non-heredoc target. The engine uses it to feed self-protection;
  embed callers can reuse it without reimplementing the walk.
- `ProtectedPaths::classify_input_with_paths_pair(input, paths, extra)`
  — sibling of `classify_input_with_paths` that classifies the union
  of two `PathFact` slices (tool-input-derived and engine-supplied)
  without forcing the caller to allocate a merged `Vec`.
- Verified release artifacts with `SHA256SUMS`, GitHub artifact attestations,
  and SPDX JSON SBOM publication.
- `x86_64-unknown-linux-musl` release target for portable Linux installs.

### Changed
- `tokenize` in `src/facts/shell.rs` now asserts forward progress on
  every `read_word` call (`debug_assert!(advanced > 0)`), and
  `read_word` documents the contract that callers strip whitespace and
  separator bytes before invocation (review §3.5).
- `core.secrets.sensitive-path-to-network` is now judged per pipeline
  (segment) instead of command-wide. Unrelated segments such as
  `ls ~/.ssh; curl https://example.com` no longer fire the rule, while
  pipelines that redirect into a sensitive path
  (`curl https://x > ~/.ssh/foo`) still deny via the new
  `Pipeline.redirects` surface. When `Bash::has_command_substitution`
  is set the rule falls back to the previous command-wide co-occurrence
  to preserve the safety-first false-positive bias (review D5).
- `crate::decide` (and the engine's per-decide path) now classifies
  Bash redirect operands (`> file`, `>> file`, `< file`, `2> file`,
  `&> file`) against `ProtectedPaths`. Previously only positional
  arguments to known writer heads (`rm`, `cp`, `mv`, …) were inspected,
  so `echo y > ~/.claude/settings.json` slipped past
  `core.self_protection.claude-settings`. Scripts that intentionally
  redirect into a self-protection target may now produce new Deny
  decisions; this is a bug-fix-class behaviour change (review D8).
- `crate::decide`'s embed fallback (when `Engine::for_cwd` cannot
  discover a config) now goes through `Engine::builder().agent(
  "embed-fallback").build()`. The fallback engine therefore populates
  `ProtectedPaths` with the running binary and HOME-rooted claude /
  codex settings, where the previous `Engine::default()` fallback left
  those slots empty. Embedded callers that depended on the empty
  fallback to bypass self-protection will see new Deny decisions for
  binary / settings edits (review §1.7).
- `ProtectedPaths::collect_with_env` now pre-canonicalises every
  target path (binary, configs, plugins, claude / codex settings, hook
  scripts) at collect time. `path_matches` only canonicalises the
  candidate side at match time. Net effect is a single `canonicalize()`
  per target instead of per match; behaviour is unchanged for files
  whose canonical form is stable across decides (review D8).
- Unix release archives are published as `.tar.gz` and Windows archives as
  `.zip`.
- Installation docs now prefer pinned archive downloads with checksum and
  attestation verification over installer scripts.

### BREAKING
- `Bash` (in `ptuf::facts::shell`) gained a public field
  `has_command_substitution`. Pattern-matching `Bash { segments }`
  exhaustively now requires `..`. The struct is constructed only by
  `parse()` so this matters for downstream consumers that destructure it.
- `Bash` further gained `has_redirect`, `has_heredoc`, and
  `has_process_substitution` public fields, and `Pipeline` gained
  `redirects: Vec<Redirect>` (with companion `Redirect` / `RedirectOp`
  types). Exhaustive destructuring of `Bash` / `Pipeline` requires `..`.
  Both types are constructed only by `parse()`.
- `impl Default for Engine` was removed. Callers that relied on
  `Engine::default()` should switch to `Engine::builder().build()` (or
  `Engine::for_cwd()` when project policy is desired). The builder
  populates `ProtectedPaths` whereas the deleted `Default` shim left
  it empty, so the new construction path is *not* a drop-in
  replacement when the caller expected self-protection to be a noop
  (review §1.7).
- `FilePath` is now a type alias for `PathFact`. Existing field
  accesses (`fp.tool` / `fp.raw` / `fp.absolute`) keep compiling, but
  exhaustive struct destructuring (`FilePath { tool, raw, absolute }`)
  now requires `..` because the underlying `PathFact` adds `expanded`,
  `canonical_or_raw`, and `origin` (review D8).

### Security
- `ptuf update` now passes `--locked` to `cargo install` so the
  transitive dependency graph is pinned to the published `Cargo.lock`
  rather than re-resolved at install time.
- `ptuf update --version <older-tag>` is rejected unless `--force` is
  also given, preventing accidental rollbacks to known-vulnerable
  releases. Pre-release tags emit an advisory line and skip the guard
  because they cannot be safely ordered against bare semver.
- `ptuf init` now writes host configuration files
  (`~/.claude/settings.json`, `<repo>/.codex/hooks.json`,
  `<repo>/.codex/config.toml`, `<repo>/.github/hooks/ptuf.json`,
  `<repo>/.kiro/agent.json`) with mode `0600` on Unix instead of relying
  on the process umask. Prevents world-readable hook configurations on
  shared hosts. Behaviour on Windows is unchanged (NTFS ACLs are
  inherited from the parent directory).
- `ptuf update` now downloads the prebuilt installer to a tmp file and
  runs `gh attestation verify <file> --repo watany-dev/ptuf` before
  executing it, replacing the previous `curl … | sh` pipeline that
  trusted the network response. Pass `--skip-attestation` (or set
  `PTUF_UPDATE_SKIP_ATTESTATION=1`) to bypass the check on hosts without
  GitHub CLI; the bypass emits a `WARNING` line to stderr so the
  unverified install is auditable. When `gh` is missing without the
  bypass flag, ptuf exits `1` and leaves the downloaded script on disk
  for manual inspection. Cargo-managed installs are unaffected.

## [0.0.1] - 2026-05-05

Initial public release.

### Added
- `ptuf hook <agent>` adapter for Claude Code and Codex `PreToolUse` hooks
- `ptuf eval` one-shot evaluator for shell use and debugging
- `ptuf init claude-code` / `ptuf init codex` idempotent installers
- `ptuf doctor [--json]` diagnostics for binary, config, plugins, and hook wiring
- `ptuf plugin test <path>` for rule-local `tests.deny` / `tests.allow`
- Built-in policy packs: filesystem, network, secrets, git, self-protection, and
  opt-in project hygiene
- Tool-aware fact extraction for `Bash`, `Read`, `Edit`, `Write`, `WebFetch`,
  and generic `mcp__<server>__<tool>` payloads
- Layered YAML config (`/etc/ptuf/policy.yaml`, `~/.config/ptuf/config.yaml`,
  `<repo>/.ptuf.yaml`, `<repo>/.ptuf.local.yaml`) with YAML plugins
- Audit JSONL with `schemaVersion: 1`, `agent`, `pluginVersions`, and
  `allowlistId`
- Pre-built binaries for `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`,
  and `x86_64-pc-windows-msvc`
- `curl | sh` and PowerShell installers via cargo-dist
- crates.io publication

[Unreleased]: https://github.com/watany-dev/ptuf/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/watany-dev/ptuf/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/watany-dev/ptuf/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/watany-dev/ptuf/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/watany-dev/ptuf/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/watany-dev/ptuf/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/watany-dev/ptuf/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/watany-dev/ptuf/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/watany-dev/ptuf/releases/tag/v0.1.0
[0.0.1]: https://github.com/watany-dev/ptuf/releases/tag/v0.0.1
