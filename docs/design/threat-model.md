# ptuf 脅威モデル

本書は ptuf が前提とする攻撃者・信頼境界・想定脅威・緩和策を整理する。
`SECURITY.md` の reporting と scope を補完する一次設計書である。

実装の正本は `src/` 配下であり、本書と乖離した場合は実装を優先する。
緩和策に対応するコードパスを各項目末尾で `file:line` 形式で参照する。

## 攻撃者モデル

ptuf は **AI agent (Claude Code / Codex / Copilot / Kiro CLI / Cline /
Cursor / Pi / OpenCode) の tool hook として呼ばれる Rust CLI** である。
次の 3 種類の攻撃者を想定する:

1. **悪意ある LLM 出力 (Adversarial agent)** — agent が `tool_input`
   に injection / wrapper / 機密読み出しを仕込んで stdin から渡す。
   ptuf の信頼境界の主要な対象であり、もっとも頻度が高い。
2. **悪意ある plugin 著者 (Untrusted plugin)** — `~/.config/ptuf/plugins/`
   や repo 内 `.ptuf/plugins/` に置かれた plugin YAML が ReDoS / 巨大
   rule / unsupported fact 経由で engine を破壊しようとする。
3. **同一ホスト上の別ローカルプロセス (Co-located process)** — 同じ
   uid で動く別プロセスが audit log を改竄したり、config を競合書き
   換え (TOCTOU) しようとする。uid 越境攻撃と root 攻撃は **scope 外**。

権限昇格を伴う攻撃者 (kernel exploit、別 uid からの侵入、物理アクセス)
は scope 外。OS の uid 隔離と filesystem ACL を前提に置く。

## 信頼境界

```
┌──────────────────────────────────────────────────────────────┐
│  agent process (Claude Code / Codex / Copilot / Kiro / …)   │
│                                                              │
│   tool_input  ──[stdin, ≤ 8 MiB]──▶  ptuf hook adapter      │
│                                                              │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
        ┌──────────── trust boundary A ────────────┐
        │                                          │
        │  ptuf CLI (this crate)                   │
        │  - fail-closed on parse error            │
        │  - bounded payload size                  │
        │  - redaction before audit                │
        │                                          │
        │  trust boundary B ─▶ plugin YAML (user)  │
        │                                          │
        └──────────────────────────────────────────┘
                           │
                           ▼
              filesystem (config / audit log)
              ── trust boundary C ──
              (other local processes, same uid)
```

- 境界 A: hook 入力 (`tool_input`) は **untrusted**。agent ごとの parser
  で `HookInput` に正規化し、8 MiB 上限で DOS を抑制
  (`src/cli/run.rs`)。
- 境界 B: plugin YAML は **半信頼**。schema (`apiVersion: ptuf.dev/v1`,
  `kind: Plugin`) と SUPPORTED_FACTS で表現力を絞り、生シェル文字列
  へのアクセスを禁止 (`src/plugin/loader.rs:25-34`)。
- 境界 C: audit log と config は **同 uid 攻撃者からは半信頼**。
  OS-level advisory lock 付き append で interleave を防ぐ
  (`src/audit/mod.rs`, `src/audit/writer.rs`)。事後改竄の検知は未実装。

## STRIDE 分析

### Spoofing — agent adapter なりすまし

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| S-1 | 攻撃者が agent 名 (`claude-code` 等) を偽装し、本来適用される rule を回避 | medium | adapter 名は subcommand 名 (`hook claude-code`) で binding。CLI argv は OS が認証境界として管理。audit record の `agent` field で証跡固定 (`src/audit/record.rs`) |
| S-2 | agent stdin から偽装 `tool_input` を流し込み、別 tool 名で許可済み rule を踏む | high | `tool_name` は serde で必須 field 化。rule 側は `tool: Bash` で明示マッチ。`*` ワイルドカード除外 |

### Tampering — 出力・状態の改竄

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| T-1 | 同 uid プロセスが audit JSONL を append 中に書き込み割込ませて record を破壊 | medium | flock(2) advisory lock で 1 record 単位 atomic append (`src/audit/writer.rs`) |
| T-2 | 同 uid プロセスが事後に audit JSONL を直接編集して record を削除 / 改竄 | **high** | **現状未対応 (residual risk)**。現在の advisory lock は並行 append の interleave のみを防ぐ |
| T-3 | redaction 漏れによる機密情報の audit log 流出 | high | `src/audit/redaction.rs` の strict mode (token / API key / PEM / JWT / credential) を proptest で網羅、PBT 3 段で 100k cases ソーク |
| T-4 | plugin YAML を engine 起動中に書き換え、TOCTOU で異なる rule を適用 | low | plugin は engine 起動時に 1 度だけ読み込み、メモリ上で固定。途中書き換えは無視 |
| T-5 | 4 層 config (`/etc` → `~/.config` → repo → local) の優先順位悪用で禁止 rule を上書き許可 | medium | merge は `src/config/merge.rs` で deterministic、`hardDeny` rule は allowlist / pack disable / weakening override を無視する (`src/engine/filter.rs`) |

### Repudiation — 否認

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| R-1 | 利用者 / agent が deny 決定を踏んだ事実を否認 | low | audit JSONL は構造化 (`schemaVersion`, `timestamp`, `ruleId`, `agent`) で機械可読、運用側で集中管理推奨 |
| R-2 | audit log が消されると否認可能 | medium | T-2 と同根。現状は改竄検知を提供しないため、必要な運用では audit log を別システムへ退避する |

### Information disclosure — 情報漏洩

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| I-1 | redaction が外れ、API キーや個人情報が audit log に書かれる | high | `src/audit/redaction.rs` の token / API key / PEM / JWT / credential 5 系統、PBT で 100k cases、`docs/design/audit.md` に schema 固定 |
| I-2 | エラーメッセージに plugin 内部の secret が逆流 | medium | plugin error は path / rule id / parser・compile message に限定する (`src/plugin/mod.rs`) |
| I-3 | telemetry / 外部送信による意図せぬデータ流出 | **scope-blocking** | **ptuf は telemetry を一切持たない。`SECURITY.md` に "No Telemetry" を明示**。hook / check / config / plugin / audit 経路は network I/O を行わず、明示的な `ptuf update` だけが GitHub Releases にアクセスする |

### Denial of service — リソース枯渇

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| D-1 | 巨大 stdin (TB 級) で OOM | medium | 8 MiB cap (`src/cli/run.rs`)、超過時 fail-closed deny |
| D-2 | malicious plugin の `(a+)+$` 等 ReDoS pattern で engine が無限ループ | low (no current attack surface) | plugin DSL (`src/plugin/dsl.rs` の `WhenNode`) は **user 由来 regex を一切受け付けない**。比較は exact match (`Tool`, `Event`)、list membership (`ToolAny`, `ShellArgvHeadAny`)、prefix (`PathFilePathPrefixAny`)、scheme (`UrlSchemeAny`) のみ。本体内 regex はすべて static `LazyLock<Regex>` (`src/audit/redaction.rs`, `src/facts/sensitive.rs`, `src/rules/patterns.rs`) で、`regex` crate が線形時間を保証。**将来 DSL が regex leaf を採用する場合は本項を再評価し、`RegexBuilder::size_limit` 等を導入する** |
| D-3 | malicious plugin の大量 rule で memory 枯渇 / engine 起動失敗 | high | **現状未対応 (residual risk)**。plugin rule 数・総数の上限導入を要検討 |
| D-4 | panic で agent 全体が止まる | medium | `unsafe_code = "forbid"` + clippy `unwrap_used` / `expect_used` / `panic` deny で明示的な panic 経路を抑制し、`Result` 伝播と敵対的入力テストで fail-closed を検証 |

### Elevation of privilege — 権限昇格

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| E-1 | plugin DSL が任意 shell コマンドを実行できる | high | DSL は fact 参照と表明評価のみ (`src/plugin/dsl.rs`)。`exec:` 構文は **存在しない**。`apiVersion: ptuf.dev/v1` schema で書ける表現を制限 |
| E-2 | hook 入力経由で host OS の任意ファイル読取 | high | hook / check の facts (`path`, `url`, `sensitive_path`) は静的解析し、入力が指すファイルを読み取らない。config / plugin / audit と明示的な `init` / `update` の I/O は別契約 |
| E-3 | self-protection 回避で ptuf 自身の設定が変更される | high | `core.self_protection` pack で ptuf binary / config / plugin と各 agent の hook 設定を hardDeny。wrapper (`bash -c`, `xargs`, `find -exec`) と redirect も bounded で検査 |
| E-4 | 公開 MSRV ピンと実ビルド成果物の乖離 (supply chain) | medium | CI の MSRV job は `cargo build` / `cargo test --no-run` / `cargo doc` で codegen と linker を通す (`.github/workflows/ci.yml` `msrv` job)。`package.rust-version` 変更は同一 PR で toolchain pin と CHANGELOG を更新 |

## Residual risk (現状の既知の弱点)

セキュリティクリティカル水準を目指す上で、以下は **本書執筆時点で
未解消** であり、`docs/design/roadmap.md` 経由で順次対処する:

| 項目 | 状態 |
|---|---|
| T-2 audit log の事後改竄検知なし | 未対応 |
| D-3 plugin rule 数 / コンパイル時間の上限なし | 未対応 |
| `serde_yaml_ng` のメンテ状況未評価 | 未対応 |
| `cargo-vet` による transitive dep 監査未導入 | 未対応 |

## 非対象 (Out of scope)

以下は脅威モデル外であり、ptuf は防御を提供しない:

- root 攻撃者・ kernel exploit・同一ホスト別 uid からの攻撃
- 物理アクセス・サイドチャネル (timing / power analysis)
- 攻撃者が agent (Claude Code 等) に root 相当の権限を与えた状態での誤用
- 攻撃者が ptuf binary そのものをすり替えた状態 (バイナリ署名検証は
  `docs/install.md` の `cosign verify-attestation` で別途確保)
- 攻撃者が ptuf より上位の hook (例えば `PreToolUse` の前段) を制御
  しているケース

## 検証

脅威モデルの緩和策は以下のテストで検証する:

- `make pbt-deep` (`PROPTEST_CASES=100000`) — redaction / decision / rule
  matching の境界条件をソーク
- `make e2e` — fd リーク / 8 MiB stdin / 並列 hook / 4 層 config フル統合
- `make mutants` (nightly) — engine と plugin loader の mutation testing
- `make fuzz` / `make fuzz-soak` (nightly) — YAML / DSL / JSON payload の
  coverage-guided fuzzing

## 変更時の手続

本書を更新する場合:

1. 該当 STRIDE 項目に行を追加 / 修正
2. 緩和策コードパスを `file:line` で参照
3. `SECURITY.md` の scope に矛盾しないか確認
4. 変更が重大 (新規攻撃者を scope に入れる等) の場合は CHANGELOG に記載
