# ptuf 脅威モデル

本書は ptuf が前提とする攻撃者・信頼境界・想定脅威・緩和策を整理する。
`SECURITY.md` の reporting と scope を補完する一次設計書である。

実装の正本は `src/` 配下であり、本書と乖離した場合は実装を優先する。
緩和策に対応するコードパスを各項目末尾で `file:line` 形式で参照する。

## 攻撃者モデル

ptuf は **AI agent (Claude Code / Codex / Copilot / Kiro CLI)
の `PreToolUse` hook として呼ばれる Rust CLI** である。次の 3 種類の
攻撃者を想定する:

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
│  agent process (Claude Code / Codex / Copilot / Kiro CLI)   │
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

- 境界 A: hook 入力 (`tool_input`) は **untrusted**。`HookInput` は
  serde で構造を固定し、未知 field は無視。8 MiB 上限で DOS を抑制
  (`src/cli/run.rs:27`)。
- 境界 B: plugin YAML は **半信頼**。schema (`apiVersion: ptuf.dev/v1`,
  `kind: Plugin`) と SUPPORTED_FACTS で表現力を絞り、生シェル文字列
  へのアクセスを禁止 (`src/plugin/loader.rs:25-34`)。
- 境界 C: audit log と config は **同 uid 攻撃者からは半信頼**。
  flock atomic append で interleave を防ぐ (`src/audit/writer.rs:46-53`)。
  改竄検知は P1-5 (HMAC chain) で別途実装予定 (現状は flock のみ)。

## STRIDE 分析

### Spoofing — agent adapter なりすまし

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| S-1 | 攻撃者が agent 名 (`claude-code` 等) を偽装し、本来適用される rule を回避 | medium | adapter 名は subcommand 名 (`hook claude-code`) で binding。CLI argv は OS が認証境界として管理。audit record の `agent` field で証跡固定 (`src/audit/record.rs:55-58`) |
| S-2 | agent stdin から偽装 `tool_input` を流し込み、別 tool 名で許可済み rule を踏む | high | `tool_name` は serde で必須 field 化。rule 側は `tool: Bash` で明示マッチ。`*` ワイルドカード除外 |

### Tampering — 出力・状態の改竄

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| T-1 | 同 uid プロセスが audit JSONL を append 中に書き込み割込ませて record を破壊 | medium | flock(2) advisory lock で 1 record 単位 atomic append (`src/audit/writer.rs`) |
| T-2 | 同 uid プロセスが事後に audit JSONL を直接編集して record を削除 / 改竄 | **high** | **現状未対応 (residual risk)**。P1-5 (HMAC chain + `ptuf audit verify`) で対処予定。鍵は `~/.config/ptuf/audit.key` mode 0600 想定 |
| T-3 | redaction 漏れによる機密情報の audit log 流出 | high | `src/audit/redaction.rs` の strict mode (token / API key / PEM / JWT / credential) を proptest で網羅、PBT 3 段で 100k cases ソーク |
| T-4 | plugin YAML を engine 起動中に書き換え、TOCTOU で異なる rule を適用 | low | plugin は engine 起動時に 1 度だけ読み込み、メモリ上で固定。途中書き換えは無視 |
| T-5 | 4 層 config (`/etc` → `~/.config` → repo → local) の優先順位悪用で禁止 rule を上書き許可 | medium | merge は `src/config/merge.rs` で deterministic、`hardDeny` rule は overridable=false を強制 (`src/plugin/rule.rs`)。`SECURITY.md` で禁止 rule を hardDeny にする運用を推奨 |

### Repudiation — 否認

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| R-1 | 利用者 / agent が deny 決定を踏んだ事実を否認 | low | audit JSONL は構造化 (`schemaVersion`, `timestamp`, `ruleId`, `agent`) で機械可読、運用側で集中管理推奨 |
| R-2 | audit log が消されると否認可能 | medium | T-2 と同根。P1-5 HMAC chain + 外部 syslog 連携でカバー予定 |

### Information disclosure — 情報漏洩

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| I-1 | redaction が外れ、API キーや個人情報が audit log に書かれる | high | `src/audit/redaction.rs` の token / API key / PEM / JWT / credential 5 系統、PBT で 100k cases、`docs/design/audit.md` に schema 固定 |
| I-2 | エラーメッセージに plugin 内部の secret が逆流 | medium | エラーは `PluginError::Compile` 等で `message` に変換、原値は出さない。`docs/design/errors.md` (P2-9) で error code 体系化予定 |
| I-3 | telemetry / 外部送信による意図せぬデータ流出 | **scope-blocking** | **ptuf は telemetry を一切持たない。`SECURITY.md` に "No telemetry" を明示**。network IO は user-defined plugin が起こす操作のみ |

### Denial of service — リソース枯渇

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| D-1 | 巨大 stdin (TB 級) で OOM | medium | 8 MiB cap (`src/cli/run.rs:27`)、超過時 fail-closed deny |
| D-2 | malicious plugin の `(a+)+$` 等 ReDoS pattern で engine が無限ループ | low (no current attack surface) | plugin DSL (`src/plugin/dsl.rs` の `WhenNode`) は **user 由来 regex を一切受け付けない**。比較は exact match (`Tool`, `Event`)、list membership (`ToolAny`, `ShellArgvHeadAny`)、prefix (`PathFilePathPrefixAny`)、scheme (`UrlSchemeAny`) のみ。本体内 regex はすべて static `LazyLock<Regex>` (`src/audit/redaction.rs`, `src/facts/sensitive.rs`, `src/rules/patterns.rs`) で、`regex` crate が線形時間を保証。**将来 DSL が regex leaf を採用する場合は本項を再評価し、`RegexBuilder::size_limit` 等を導入する** |
| D-3 | malicious plugin の 100 万 rule で memory 枯渇 / engine 起動失敗 | high | **P1-6 で対処**: `max_rules_per_plugin` (default 1024) + `max_total_rules` + `compile_timeout_ms` (5000 ms)、超過時 `PluginError::ResourceExceeded` |
| D-4 | panic で agent 全体が止まる | medium | `unsafe_code = "forbid"` + clippy `unwrap_used` / `panic` deny で panic 経路を型レベルで排除。`Result` 伝播で fail-closed |

### Elevation of privilege — 権限昇格

| ID | 脅威 | 影響 | 緩和策 |
|---|---|---|---|
| E-1 | plugin DSL が任意 shell コマンドを実行できる | high | DSL は fact 参照と表明評価のみ (`src/plugin/dsl.rs`)。`exec:` 構文は **存在しない**。`apiVersion: ptuf.dev/v1` schema で書ける表現を制限 |
| E-2 | hook 入力経由で host OS の任意ファイル読取 | high | facts (`path`, `url`, `sensitive_path`) は静的解析。ptuf 自体は file system に副作用を持たず、判断結果を agent に返すのみ |
| E-3 | self-protection 回避で ptuf 自身の設定が変更される | high | `core.self_protection` pack で `~/.config/claude/` / `~/.codex/` / `~/.ptuf/` を hardDeny。wrapper (`bash -c`, `xargs`, `find -exec`) と redirect も bounded で検査 |
| E-4 | malicious plugin が ptuf binary の自己更新を起こす | medium | `update` モジュール (`src/update/`) は user-initiated subcommand のみ起動、plugin から呼べない |

## Residual risk (現状の既知の弱点)

セキュリティクリティカル水準を目指す上で、以下は **本セッション時点で
未解消** であり、`docs/design/roadmap.md` 経由で順次対処する:

| 項目 | 対応する punch list |
|---|---|
| T-2 audit log の事後改竄検知なし | P1-5 HMAC chain |
| D-3 plugin rule 数 / コンパイル時間の上限なし | P1-6 |
| `serde_yaml_ng` のメンテ状況未評価 | P2-4 |
| `cargo-vet` による transitive dep 監査未導入 | P2-1 |

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
- `make mutants` (P1-1) — engine と plugin loader の test 殺害率 80% 以上
- `make fuzz-1h` (P1-2、別 PR) — YAML / DSL / JSON payload を 1 時間ソーク
- `make sanitize` (P1-3) — asan / leak で UB / リーク検知
- `make verify-reproducible` (P1-10) — 2 連続ビルドの SHA256 一致

## 変更時の手続

本書を更新する場合:

1. 該当 STRIDE 項目に行を追加 / 修正
2. 緩和策コードパスを `file:line` で参照
3. `SECURITY.md` の scope に矛盾しないか確認
4. 変更が重大 (新規攻撃者を scope に入れる等) の場合は CHANGELOG に記載
