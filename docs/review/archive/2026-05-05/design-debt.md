# ptuf 設計負債独立レビュー

作成日: 2026-05-05

このレビューは `docs/review` 配下の既存レビューを参照せず、コード、`docs/design`、`README.md`、CI、Makefile を一次情報として作成した。

## Executive Summary

ptuf は「hook I/O を薄く保ち、判定コアを facts ベースで決定的に評価する」という骨格は成立している。一方で、設計文書が「実装済み」と書く契約の一部が、実装では未到達または簡略化されたまま公開契約化している。全面再構築は必須ではないが、現在のまま v0.4 契約として広げると、allowlist、audit、self-protection、MCP 経路の安全性に対する利用者の期待を満たせない。

最重要負債は次の 8 件。

| 優先 | severity | 負債 | 判断 |
| --- | --- | --- | --- |
| 1 | critical | allowlist が `when` 条件を持たず、対象 rule を評価前に丸ごと抑制する | 短期修正必須 |
| 2 | critical | `core.self_protection.hook-script` は実質未実装で、登録済み hook script を収集していない | 短期修正必須 |
| 3 | high | audit は README / design が示す default JSONL と異なり、既定では無効 | 契約決定が必要 |
| 4 | high | shell / fact 抽出の到達範囲が設計契約より狭く、redirect / heredoc / substitution / dataflow がない | 段階的内部再設計 |
| 5 | high | MCP fact 抽出は top-level `path` / `url` / `content` だけで、複数 path payload を保護できない | 段階的内部再設計 |
| 6 | high | config schema は pack enable と allowlist だけで、設計が述べる rule-level decision / severity override を表現できない | 設計契約の整理 |
| 7 | medium | `engine.rs` / `cli.rs` / `doctor.rs` / `plugin/dsl.rs` が大型化し、境界が「型」より「関数群」に寄っている | 小分けリファクタ |
| 8 | medium | test は広いが、契約テストが代表ケース中心で、設計ドリフトを止める schema / fixture が不足 | テスト追加 |

推奨は「全面再構築」ではなく、公開契約を固定し直した上での内部再設計。特に allowlist と self-protection は互換性を壊さず修正できるため先に切り出す。shell / MCP / config override は新しい中間表現と schema を導入する必要があるため、PR を分けて移行する。

## Contract Map

### CLI

維持すべき契約:

- `ptuf` 引数なし互換モード: stdin JSON、stdout 空、deny 時 stderr reason、exit code `0 / 2 / 1`。
- `ptuf hook claude-code pre-tool-use`: deny / ask 時に stdout へ `hookSpecificOutput` JSON、stderr に reason、exit code は deny のみ `2`。
- `ptuf eval --tool <name> <command>`: 人間向け stdout、reason は stderr。
- `ptuf plugin test <path>`、`ptuf init claude-code`、`ptuf doctor [--json]`。

根拠: README の run 契約、`src/cli.rs:232-355`、`tests/cli_smoke.rs:33-95`。

破壊候補:

- `docs/design/cli-and-hooks.md:10-18` は `post-tool-use` / `explain` / `audit` を一覧に含むが、同文書 `31-36` では未実装と明記している。CLI help には未実装コマンドを載せない現在の実装を正とするべき。

### Library API

維持すべき契約:

- `ptuf::{Decision, HookInput, Facts, Engine, Outcome, decide}` の re-export。
- `decide(&HookInput) -> Decision` は embedded caller 向けに `Engine::for_cwd()` 失敗時 `Engine::default()` へフォールバックする。
- CLI は `build_engine_or_fail_closed` で policy load failure を `core.engine.policy-load-failed` deny として扱う。

根拠: `src/lib.rs:20-36`、`src/cli.rs:13-36`、`docs/design/cli-and-hooks.md:197-208`。

### Config / Plugin YAML

維持すべき契約:

- config scope: `/etc/ptuf/policy.yaml` → `~/.config/ptuf/config.yaml` → `<repo>/.ptuf.yaml` → `<repo>/.ptuf.local.yaml`。
- YAML plugin: `apiVersion: ptuf.dev/v1`, `kind: Plugin`, `metadata`, `capabilities.requires`, `rules[*].when`, `tests`。
- plugin DSL leaves: `tool`, `toolAny`, `event`, `shell.argv`, `shell.pipeline`, `path.filePathPrefixAny`, `url.schemeAny`, `url.hostAny`, `sensitive.pathKindAny`。

根拠: `src/config/schema.rs:20-145`、`src/plugin/schema.rs:18-70`、`src/plugin/dsl.rs:18-30`、`src/plugin/loader.rs:25-34`。

破壊候補:

- 設計文書の allowlist `when` と rule-level override は未実装なので、互換性を壊さず追加するか、v1 schema から明示的に外す必要がある。

### Audit JSONL

維持すべき契約:

- `schemaVersion: 1`、`agent`、`pluginVersions`、`allowlistId`、`modeDemoted`。
- strict redaction。
- `includeAllowed: false`、`includeDenied: true`、ask / monitor は記録対象。

根拠: `src/audit/record.rs:29-67`、`src/engine.rs:286-345`。

未確定契約:

- `docs/design/audit.md:6-12` と `README.md:88-94` は default path を示すが、実装は `Config::default()` で `audit.path = None`、つまり既定 audit 無効 (`src/config/mod.rs:120-127`)。

### `doctor --json`

維持すべき契約:

- `schemaVersion: 1` envelope。
- `binary`、`project`、`configLayers`、`config`、`plugins`、`claude`、`hasFailure`。
- text / json とも failure section があれば exit `1`。

根拠: `docs/design/cli-and-hooks.md:38-64`、`src/doctor.rs:93-150`。

### `hookSpecificOutput`

維持すべき契約:

- `hookEventName: "PreToolUse"`。
- `permissionDecision: "ask" | "deny"`。
- `permissionDecisionReason` は `Decision` の reason をそのまま載せる。
- allow / monitor は stdout 空。

根拠: `src/hook_output.rs:24-39`、`tests/engine_proptest.rs:100-125`。

## Debt Inventory

### D1. allowlist が条件付き例外ではなく rule 単位の無条件 suppression になっている

- severity: critical
- 根拠: 設計は `allowlists[*].when` を rule の `when` と同形式で扱うと書く (`docs/design/config-and-plugins.md:58-94`)。実装の `RawAllowlist` は `id` / `appliesTo.rules` / `expiresAt` / `reason` だけで `when` を持たない (`src/config/schema.rs:111-140`)。`Engine::decide` は rule evaluation 前に `allowlist_hit_for` を呼び、hit した rule は評価せず `continue` する (`src/engine.rs:226-249`, `src/engine.rs:370-384`)。
- 影響範囲: allowlist を使う全 policy。plugin rule と non-hardDeny builtin rule。
- 破綻シナリオ: `core.git.reset-hard` を一時許可したいだけの allowlist が、その rule の全入力を期限内に無条件許可する。さらに対象 command が rule に一致していなくても `allowlistId` が allow audit に付く可能性があり、監査意味論も濁る。
- 推奨対応: `Allowlist` に compiled `WhenNode` を持たせる。評価順は「rule.evaluate が decision を返した後、その decision に対して allowlist 条件を評価」。`allowlistId` は suppression が実際に起きた時だけ設定する。

### D2. `core.self_protection.hook-script` が実質未接続

- severity: critical
- 根拠: policy pack は `~/.claude/settings.json` の `command` で参照される hook script を止める契約 (`docs/design/policy-packs.md:101-115`)。しかし `ProtectedPaths::collect_with_env` は `hook_scripts: Vec::new()` 固定 (`src/self_paths.rs:79-85`) で、`hook_scripts` は他に投入されていない。
- 影響範囲: self-protection。Claude Code hook chain。
- 破綻シナリオ: settings 自体は保護されるが、settings から呼ばれる shell wrapper や hook script を agent が編集して ptuf を迂回できる。
- 推奨対応: `~/.claude/settings.json` と repo `.claude/settings*.json` を読み、`hooks.PreToolUse[].hooks[].command` の先頭 executable path を抽出して `hook_scripts` に追加する。shell tokenization の仕様は `init` の token-based detection と合わせる。

### D3. audit の default 契約が README / design と実装で割れている

- severity: high
- 根拠: README は「every decision is recorded to `~/.local/share/ptuf/audit.jsonl`」と書く (`README.md:88-94`)。design も default path を明記する (`docs/design/audit.md:6-12`)。一方 `Config::default()` は `audit.path = None` で (`src/config/mod.rs:120-127`)、`audit_sink_from_config` は path がなければ `NoopSink` (`src/engine.rs:330-337`)。
- 影響範囲: 監査、導入時の期待値、incident response。
- 破綻シナリオ: 利用者は監査ログが残ると思って運用するが、config に audit.path を明示しない限り何も残らない。
- 推奨対応: どちらを正にするか決める。安全製品としては default path を実装し、opt-out を `audit.enabled: false` のように明示する方が契約と一致する。互換性重視なら README / design を「audit.path 設定時のみ」に直す。

### D4. shell / facts の抽出範囲が設計契約より狭い

- severity: high
- 根拠: architecture は shell AST / argv / pipeline / redirect、path normalization、dataflow を fact extraction の目標に含む (`docs/design/architecture.md:57-80`)。実装は `facts::shell` の冒頭で redirects / heredocs / command substitution / process substitution を対象外と明記している (`src/facts/shell.rs:1-11`)。
- 影響範囲: `core.network`、`core.secrets`、plugin DSL、将来 dataflow。
- 破綻シナリオ: `bash <(curl ...)`、redirect 経由の secret upload、`sh -c "$(curl ...)"` などが facts に現れず、ルールが「安全」と誤判定する。plugin author は design の事実モデルを信じて rule を書くが、実装上は検出不能な入力が残る。
- 推奨対応: shell parsing を独立 crate / module boundary に分離し、最低限 `redirect`, `substitution`, `heredoc`, `process_substitution`, `background` を facts として表現する。完全 shell parser を目指さず、危険構文を lossless token として残す方が現実的。

### D5. sensitive-path-to-network は structured facts ではなく局所 regex と command-wide co-occurrence に依存している

- severity: high
- 根拠: `facts::extract` は `Facts.sensitive` を集める (`src/facts/mod.rs:56-105`) が、`core.secrets.sensitive-path-to-network` は `patterns::SENSITIVE_PATH` と network sink head の存在だけを別実装で見ている (`src/rules/sensitive_net.rs`)。policy pack は「同一コマンド上に co-occur」と書く (`docs/design/policy-packs.md:119-122`) が、実装は Bash 全体の commands で `has_sink` と `has_sensitive` を別々に見ている。
- 影響範囲: secret exfiltration 判定、false positive / false negative、plugin DSL との一貫性。
- 破綻シナリオ: unrelated segment の `ls ~/.ssh; curl https://example.com` が同一 payload 内 co-occurrence として deny される一方、redirect / substitution 経由の流れは見えない。
- 推奨対応: `Facts` に command segment id / pipeline edge / source-sink relation を持たせる。短期的には `Facts.sensitive` を rule に利用して分類ロジックを一元化し、segment 単位に判定を狭める。

### D6. MCP fact 抽出は top-level だけで、複数 path / nested payload を保護できない

- severity: high
- 根拠: `HookInput::file_path` は MCP の top-level `path` だけを見る (`src/hook_input.rs:19-28`)。design も `mcp__github__push_files.files[].path` は v2 で `Facts.extra_paths` と認めている (`docs/design/cli-and-hooks.md:168-195`)。
- 影響範囲: MCP GitHub / filesystem / multi-file tools、self-protection、sensitive-read。
- 破綻シナリオ: MCP tool が `files: [{ path: "~/.claude/settings.json", content: ... }]` の形を使う場合、self-protection が働かない。README は MCP fact extraction を v0.4 feature として打ち出しているため、利用者は保護済みと誤認しやすい。
- 推奨対応: `Facts.path: Option<FilePath>` を `paths: Vec<FilePath>` に拡張し、top-level と known nested arrays を全件抽出する。互換性のため当面 `path` accessor は first path view として残す。

### D7. config schema が設計上の rule-level override を表現できない

- severity: high
- 根拠: design は severity / decision / overridable を下位 scope から扱えると説明する (`docs/design/decision-model.md`, `docs/design/policy-packs.md`)。実装の `RawPack` は `enabled` と `protectedBranches` だけ (`src/config/schema.rs:72-84`)、`PackOverride` も `enabled` だけ (`src/config/mod.rs:87-94`)。`ConfigRule::overridable()` は trait にあるが engine で override 判定に使われていない。
- 影響範囲: project policy、組織 policy、設計文書との整合。
- 破綻シナリオ: `core.git.reset-hard` を deny に強める、特定 plugin rule を monitor に落とす、といった文書上可能に見える運用が schema で書けない。
- 推奨対応: v1 config で「pack enable だけが実装済み」と契約を絞るか、`rules.<id>.decision/severity/enabled` を導入する。`overridable` は override 適用時に検証する。

### D8. path normalization は「絶対化 / symlink 解決済み」という設計より浅い

- severity: medium
- 根拠: architecture は path normalization を「`~` 展開、相対 → 絶対化、シンボリックリンク解決」と書く (`docs/design/architecture.md:62-64`)。`facts::path::expand_home` は `~` / `$HOME` の展開はするが、相対 path の repo/current-dir 絶対化は行わない。self-protection の Bash path 候補は `PathBuf::from(a)` のままで、`~` 展開もない (`src/self_paths.rs:142-170`)。
- 影響範囲: self-protection、plugin path prefix、sensitive-read。
- 破綻シナリオ: `rm -f ~/.claude/settings.json` の Bash 経路は shell 実行時には HOME に展開されるが、self-protection の候補比較では raw `~` のままになり、target と一致しない可能性がある。
- 推奨対応: `PathFact` を `raw`, `expanded`, `absolute`, `canonical_or_raw`, `origin` に分け、Bash / MCP / file tools すべて同じ正規化関数を使う。

### D9. audit sink open / write failure が完全に best-effort で、利用者に見えない

- severity: medium
- 根拠: `audit_sink_from_config` は open failure を `NoopSink` に落とすだけ (`src/engine.rs:330-337`)。`record_audit` は `let _ = self.audit_sink.record(&record);` で write error を捨てる (`src/engine.rs:302-315`)。audit module のコメントは engine が警告する余地を示すが、実装は無音。
- 影響範囲: 監査可観測性、運用。
- 破綻シナリオ: audit path の permission error や disk full でログが消えるが、CLI / doctor / stderr に出ない。
- 推奨対応: Engine constructor で audit status を保持し、CLI 経路では stderr warning、doctor では warning/failure として出す。policy enforcement 自体は止めない現在方針でよい。

### D10. adapter 層が型として存在せず、`HookInput` が Claude Code と内部 normalized event を兼ねている

- severity: medium
- 根拠: architecture は adapter → normalized event を分ける (`docs/design/architecture.md:51-55`) が、実装は `HookInput` の accessor が Claude Code / MCP top-level 形状を直接判定する (`src/hook_input.rs:12-52`)。
- 影響範囲: Codex / Cursor / Gemini adapter、MCP shape 拡張、hook output。
- 破綻シナリオ: 新 adapter を入れるたびに `HookInput` と facts extractor に条件分岐が増え、どの payload shape が公開契約なのか曖昧になる。
- 推奨対応: `RawHookInput` と `Event` を分け、adapter は `Event { agent, event, tool, inputs, paths, urls, content }` へ正規化する。公開 `HookInput` は互換型として残せる。

### D11. 大型ファイルが境界を曖昧にしている

- severity: medium
- 根拠: `src/engine.rs` 1362 行、`src/cli.rs` 1158 行、`src/doctor.rs` 1073 行、`src/plugin/dsl.rs` 1056 行。`engine` は config load、plugin load、fact augmentation、rule evaluation、allowlist、audit を同居させている。
- 影響範囲: 保守性、レビュー容易性、テストの焦点。
- 破綻シナリオ: allowlist 修正が audit / plugin / mode demotion と同じ関数を触るため、局所変更の影響範囲が読みにくい。
- 推奨対応: `engine/evaluator.rs`, `engine/allowlist.rs`, `engine/audit.rs`, `cli/parse.rs`, `cli/commands.rs`, `doctor/json.rs` へ分割する。公開 API は `pub use` で維持する。

### D12. CI は強いが契約 fixture が不足している

- severity: medium
- 根拠: CI は fmt / clippy / doc / test / coverage 95% / MSRV / actionlint / cargo-deny を持つ (`.github/workflows/ci.yml:17-104`)。Makefile も `make check`, `make pbt`, `coverage` を提供する (`Makefile:1-40`)。PBT は totality / panic safety を厚く見る (`tests/engine_proptest.rs:82-145`)。一方、allowlist `when`、nested MCP paths、audit default path、hook script self-protection の契約 fixture は見当たらない。
- 影響範囲: 設計ドリフト検出。
- 破綻シナリオ: coverage 95% を満たしても、文書が実装済みと主張する契約の未実装が検出されない。
- 推奨対応: `tests/contracts/*.rs` または JSON/YAML fixtures を追加し、CLI exit code、stdout/stderr、audit schema、doctor JSON、plugin loader error、allowlist condition、MCP nested paths を固定する。

## Module Boundary Notes

| module | 現在の責務 | 境界上の負債 | 再設計時に残すもの |
| --- | --- | --- | --- |
| `cli` / `io_runner` | argv parse、stdin/stdout/stderr、exit code、subcommand dispatch | parse / command execution / rendering が `cli.rs` に集中し、hook / eval / init / doctor の failure policy が同居 | exit code、stdout/stderr 契約、`core.engine.policy-load-failed` |
| `engine` | config load、plugin load、facts 補完、rule evaluation、allowlist、mode demotion、audit | allowlist と audit が evaluator 内に密結合。policy merge failure と runtime decision の扱いが同じ層にある | `Engine::decide`、`Outcome`、mode demotion semantics |
| `facts` | Bash parse、path / url / sensitive / project facts | `Facts.path` が単数、Bash path normalization が file tool と別、dataflow がない | facts-first の rule API |
| `rules` | built-in rule の static list と `ConfigRule` trait | rule-level override の trait メソッドが config から使われていない。git / project_hygiene に重複 matcher がある | stable rule ids、`Decision` reason contract |
| `config` | scope discovery、YAML parse、merge、runtime `Config` | allowlist `when`、rule override、audit default の契約が不足 | scope order、`failClosed`、pack enable、plugin refs |
| `plugin` | plugin schema、`requires` validation、DSL compile/evaluate、plugin tests | DSL が fact model の制限を直接露出する。`dataflow.basic` 等の将来 fact と schema の対応が未整理 | `apiVersion: ptuf.dev/v1`、declarative tests |
| `audit` | JSONL record、redaction、sink | default path と failure visibility が契約と割れている | schemaVersion 1、redaction、agent / pluginVersions / allowlistId |
| `doctor` | binary / project / config / plugins / Claude status の report | hook script self-protection と同じ settings parser を共有していない | `doctor --json` schemaVersion 1 |
| `init` | Claude settings への idempotent hook install | token-based command detection はあるが self-protection の hook script 抽出と共有されていない | `ptuf init claude-code` の idempotency と dry-run |

## Rebuild Options

| 案 | 内容 | 互換性 | 工数 | リスク | 評価 |
| --- | --- | --- | --- | --- | --- |
| A. 小分けリファクタ | allowlist、audit default、hook script 収集、大型ファイル分割を現行型のまま直す | 高い | 低-中 | shell / MCP の根本は残る | 短期必須 |
| B. 内部再設計 | `HookInput` と normalized `Event` を分離し、`Facts` を multi-path / shell edge / allowlist condition 対応に拡張 | 高い。旧 API は wrapper で残せる | 中-高 | 移行中の二重モデル | 推奨 |
| C. 全面再構築 | CLI 契約以外を作り直し、parser / policy / audit を再定義 | 低-中 | 高 | 既存テスト資産を捨てがち | 現時点では過剰 |

推奨は B。ただし B の前に A の critical 2 件を先行修正する。全面再構築を選ぶ場合でも、以下の契約は残すべき。

- CLI exit code `0 / 1 / 2`。
- `hookSpecificOutput` JSON shape。
- rule id 文字列。
- config scope order。
- plugin YAML `apiVersion: ptuf.dev/v1` の基本形。
- audit `schemaVersion: 1` の既存フィールド。
- `ptuf::decide` の存在。ただし挙動は migration note 付きで見直し可。

## Migration Plan

1. Contract fixture PR
   - `tests/contracts` を追加。
   - allowlist condition、audit default、hook script、MCP nested path の「期待値」を先に明文化する。
   - ここで設計を正にするか、現実装を正にするかを PR description に明記する。

2. Critical fix PR: allowlist
   - `RawAllowlist.when: Option<Value>` を追加。
   - loader / merge で compiled condition を保持。
   - `Engine::decide` の順序を「rule evaluate → allowlist suppress」に変更。
   - 既存 allowlist は `when` 省略時に全条件 match として互換維持。

3. Critical fix PR: self-protection hook scripts
   - Claude settings parser を `init` / `doctor` / `self_paths` で共有。
   - registered command の executable を `ProtectedPaths.hook_scripts` に追加。
   - `~`, `$HOME`, relative path を同じ path normalizer に通す。

4. Audit contract PR
   - default path を実装するか、docs を修正して audit opt-in とする。
   - open/write failure を doctor と stderr warning に出す。
   - audit schema snapshot test を追加。

5. Fact model PR
   - `Facts.path` を `paths` へ拡張し、旧 accessor は first item 互換にする。
   - MCP nested path extractor を導入。
   - Bash path normalization を file-tool path normalization と共有。

6. Shell / dataflow PR
   - shell parser を `facts/shell` 内で段階拡張。
   - redirect / heredoc / command substitution / process substitution を facts として失わない。
   - `sensitive-path-to-network` を segment / pipeline relation で判定する。

7. Config override PR
   - rule-level override を v1 に追加するか、v2 schema として切るかを決定。
   - `overridable` / `hardDeny` を engine の override 適用に接続。

8. Module split PR
   - behavior change なしで `engine`, `cli`, `doctor`, `plugin/dsl` を分割。
   - coverage と public API diff を確認。

## Validation

この環境では `cargo` と `rustc` が見つからないため、Rust 1.93.0+ の環境で以下を実行すること。

通常検証:

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

深掘り検証:

```bash
make pbt
cargo tarpaulin --fail-under 95
cargo deny check advisories licenses bans sources
```

契約検証として追加すべき代表ケース:

- CLI exit code と stdout/stderr 分離。
- deny / ask の `hookSpecificOutput` JSON。
- audit `schemaVersion: 1` と default path の有無。
- `doctor --json` の `schemaVersion: 1`。
- plugin loader の unsupported `requires` と unknown `when`。
- allowlist `expiresAt` 期限切れと `when` 条件不一致。
- MCP top-level path と nested `files[].path`。
- hook script self-protection。
- `~`, `$HOME`, relative path の self-protection。

## Final Recommendation

全面再構築ではなく、公開契約を守りながら内部を再設計する。最初に直すべきは allowlist と self-protection hook script で、これはセキュリティ境界に直結する。次に audit default と MCP/path model を整理し、その後 shell/dataflow を拡張する。現在のテスト資産と CI は残す価値が高いので、再構築する場合でも「契約 fixture を増やしてから内部を差し替える」順序を崩さない。
