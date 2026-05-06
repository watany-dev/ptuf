# 2026-05-05 レビュー アーカイブ

このディレクトリは、`v0.0.1` 公開直前 (2026-05-05) に実施した 2 本の
レビューの **当時のスナップショット原文** を保存するためのもの。

| ファイル | 元のパス | 内容 |
| --- | --- | --- |
| `redesign.md` | `docs/review/redesign-2026-05.md` | 「1 から作り直す前提で実装の課題と非効率を洗い出す」 (`src/` 約 14,890 行 + `docs/design/` を一次情報とする) |
| `design-debt.md` | `docs/review/design-debt-independent-review.md` | 既存レビューを参照せず独立に行った負債レビュー (D1〜D12) |

## 取り扱い

- 原文は無加工で保存する。リンクや章番号もそのまま。
- **現状の残課題は本ディレクトリではなく
  [`../../open-issues.md`](../../open-issues.md) を参照すること**。
  原文と現状の差分を毎回読み合わせるのは負担なので、未解決のものだけを
  抜き出して整理してある。

## 解決済みの指摘 (本リポジトリで対応済)

下表は `design-debt.md` 側の負債番号で並べる。`redesign.md` の
「すぐ修正できる low-hanging bug 一覧」のうち未解決のものは
`open-issues.md` 側に転記してある。

| 元番号 | 内容 | 現実装の根拠 |
| --- | --- | --- |
| D1 | allowlist が `when` を持たず無条件 suppression になっている | `RawAllowlist.when: Option<Value>` を持ち、`Allowlist.when: Option<WhenNode>` に compile される。Engine は rule evaluate 後に suppression 判定する (`src/config/schema.rs:142-176`, `src/config/mod.rs:113-120`) |
| D2 | `core.self_protection.hook-script` が hook script を収集していない | `ProtectedPaths::collect_with_env` が Claude settings を読み、`hooks.PreToolUse[].hooks[].command` の executable を `hook_scripts` に追加する (`src/self_paths.rs:98-120`) |
| D3 | audit の default 契約が README / design と実装で割れている | `AuditConfig::default()` は `enabled: true` で、`default_audit_path()` が `~/.local/share/ptuf/audit.jsonl` を返す。`audit.enabled: false` で opt-out できる (`src/config/mod.rs:139-174`) |
| D6 | MCP fact 抽出が top-level だけで `files[].path` を保護できない | `Facts.paths: Vec<FilePath>` と `path::extract_all` が `path` / `paths[]` / `files[].path` の nested 抽出に対応 (`src/facts/path.rs:53-107`, テスト `src/facts/path.rs:315-378`) |
| D7 | config schema が rule-level decision / severity override を表現できない | `RawRuleOverride { enabled, decision, severity }` を実装し、`RuleOverride` として merge される (`src/config/schema.rs:91-111`, `src/config/mod.rs:104-110`) |
| §3.2 | `sudo -u <user>` の値を git command head と誤認して git rule をバイパスできる | sudo unwrap を `facts::shell::unwrap_sudo` に共通化し、value-taking sudo option (`-u root`, `-uroot`, `--user root`, `--user=root` など) を skip してから `core.git` / `core.project_hygiene` に評価させる (`src/facts/shell.rs:72-125`, `src/rules/git.rs`, `src/rules/project_hygiene.rs`) |
| §3.1 | `git clean -f -d -x` の空白区切り短フラグを見逃す | `core.git` と `core.project_hygiene` の `git clean` 判定が short flags を引数横断で集計し、`--force -d -x` も検出する。dry-run `-n` は引き続き許可する (`src/rules/git.rs`, `src/rules/project_hygiene.rs`) |
| §3.3 | `read_word` の backtick 意味論が ad hoc | `Bash::has_command_substitution` を追加し、`` ` … ` `` および `$(…)` (single-quote span 内を除く) を検出して flag として surface する。rule 側がまだ消費していない点は別 issue に分離 (`src/facts/shell.rs:13-22, 217-279`) |
| §3.5 | `read_word` が必ず最低 1 byte 進む不変条件が未明示 | `tokenize` の呼び出し直後に `debug_assert!(advanced > 0, ...)` を追加し、`read_word` の docstring で前進性契約を明文化。新規テスト `read_word_advances_for_every_non_separator_byte` で全 printable ASCII を回す (`src/facts/shell.rs:194-206, 627-642`) |
| §1.6 | `crate::decide()` が config / plugin load error を握り潰す | 並立する `try_decide(&HookInput) -> Result<Decision, EngineError>` を追加。CLI と同じ fail-closed 契約を embed 利用側にも提供 (`src/lib.rs:35-58`) |
| D9 | audit write failure が `let _ = ...` で握り潰されている | `Engine::audit_write_warnings: Mutex<Vec<String>>` に蓄積し、`drain_audit_write_warnings()` で取得。CLI hook / eval が完了後に stderr へドレインする (`src/engine.rs:30-44, 230-243, 312-358`, `src/cli.rs:371-400`) |
| §5.3 | audit JSONL の `write_all` ループで PIPE_BUF 超え行が分割書き込みになり複数 process 同時 audit で行が混ざる | `JsonlSink::record` が record 毎に `std::fs::File::lock`/`unlock` で OS-level advisory lock (Unix `flock(2)` / Windows `LockFileEx`) を取り、独立 OFD でも行が混ざらないことを cross-OFD 並列テストで検証 (`src/audit/mod.rs::JsonlSink::record`, `src/audit/writer.rs`) |
| §4.2 | `parse_argv` が `Vec::remove(0)` で head と env assignment を剥がすため argv 長 N に対し O(N²) | `parse_argv` 内で `Vec` を `VecDeque` に変換し `pop_front` で剥がすよう変更 (`src/facts/shell.rs::parse_argv`) |
| §6.3 | テスト群が `std::env::temp_dir().join(format!(pid, line!))` を手書きし、panic 時に scratch dir が残る・cleanup boilerplate が散在する | `tempfile = "3"` を `[dev-dependencies]` に追加し、`src/audit/writer.rs` 2 件・`src/engine.rs` 1 件・`tests/cli_smoke.rs` 9 件を `tempfile::TempDir::new()` の RAII Drop に置換 |

その他の項目 (parser 限界、redaction 網羅性、CLI parser
サイズ、モジュール肥大化、契約 fixture 不在など) は
`../../open-issues.md` で現状コード参照付きに整理した。

## 元 commit / 環境

- 作成日: 2026-05-05
- レビュー実施: Claude (Opus 4.7、Explore subagent 2 並列)
- 対象 commit: `claude/code-review-redesign-VwMEJ` HEAD
  (`redesign.md` 末尾参照)
