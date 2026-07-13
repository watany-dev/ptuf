# ADR 0001 — `.env` 保護ルールの穴を塞ぐ

## Status

Accepted (2026-05-11).

## Context

実装監査の結果、`core.secrets.sensitive-read` (Read/Edit/MCP 対象、hardDeny)
と `core.secrets.sensitive-path-to-network` (Bash で機密 path + network sink
共存、hardDeny) の 2 ルールで機密ファイル保護を行っていた既存スタックに、
以下 7 個の穴を確認した。

1. **A1** — Bash で network sink を伴わない単独読み出し (`cat .env`,
   `source .env`, `< .env`) が allow される。読み出し時点で secret が agent
   transcript に流入する。
2. **A2** — `Write` ツールで `.env` を上書き / 新規作成できる。matcher が
   `Read | Edit | MCP` のみで `Write` を含んでいなかった。
3. **A3** — `apply_patch` で `.env` を作成 / 更新できる。同上。
4. **A4** — Read/Edit で symlink (`/tmp/x.txt → .env`) 経由で読める。
   `canonical_or_raw` は計算済みだが `collect_sensitive` で参照していなかった。
5. **B1** — case-insensitive FS (macOS APFS, Windows NTFS) で `.ENV` `.SSH`
   `.AWS` 等が bypass。
6. **B2** — literal glob token (`*.env`, `?.env`, `[abc].env`, `dd if=.env`)
   が anchor 非マッチ。
7. **B3** — 非標準 MCP key 名 (`file_path`, `target`, `dest`, `source`,
   `from`, `to`, `location` 等) で path 抽出漏れ。

脅威モデルは「内容暴露防止 + 流出防止の両立、内容暴露を優先」を採用した。

## Decision

各穴に対し以下を実施する。

- **A1**: 新規ルール `core.secrets.sensitive-bash-read` を追加。
  - Decision = Ask, hardDeny = false, overridable = true, Severity = High。
  - 対象は `facts.bash` が `Some` の入力のみ。
  - READER_HEADS allowlist (`cat`/`head`/`tail`/`less`/`more`/`view`/`bat`/
    `xxd`/`od`/`hexdump`/`strings`/`base64`/`base32`/`grep`/`egrep`/`fgrep`/
    `awk`/`gawk`/`mawk`/`sed`/`cut`/`tr`/`sort`/`uniq`/`wc`/`nl`/`tac`/`rev`/
    `column`/`file`/`dd`/`source`/`.`) のいずれかが head で、かつ
    argv.args いずれかが `SENSITIVE_PATH` にマッチ、もしくは pipeline 内
    Stdin redirect (`<`) の target が機密 path にマッチした場合に発火。
  - `sudo` / `doas` / `pkexec` / `run0` などの権限昇格ラッパーおよび
    `env` / `command` などの POSIX コマンドラッパーは
    `unwrap_prefix_wrapper` で剥がしてから再判定。`su -c '...'`,
    `bash -c '...'`, `xargs`, `find -exec`, `eval` の `inner_argv` も再帰走査。
  - `$(...)` を含む場合は pessimistic mode (`bash.commands()` フラット列で
    reader argv と sensitive argv の coexistence を要求) を backstop として
    維持する。外側が非 reader で内側に reader が隠れる shape
    (`echo $(cat .env)`) は ADR 0008 の `subst_argv` re-entry で捕捉する。
  - `tee` は READER_HEADS から除外 (writer なので前段のリーダー判定で
    cover)。書き込み系 redirect (`>`, `>>`, `2>`, `&>`) も対象外で、
    `sensitive-read` (Write tool 経由) の責務とする。
- **A2, A3**: `core.secrets.sensitive-read` の matcher に `Write` と
  `apply_patch` を追加。hardDeny + High は据え置き。Write の content
  payload は既存 `event.content` 経由で PEM blob も classify される。
- **A4**: `facts/mod.rs::collect_sensitive` で `p.raw` のみだった分類対象を
  `p.raw` + `p.expanded` + `p.canonical_or_raw` の 3 つに拡張。
  `canonical_or_raw` は `absolute.canonicalize()` の失敗時に `absolute` に
  フォールバックする infallible 計算なので I/O エラーは伝搬しない。Bash
  token の symlink 解決 (`cat /tmp/link.env` 経由) は I/O コスト懸念で本
  イテレーション範囲外。
- **B1**: PEM_BLOB を除く 10 個の機密 path 正規表現に `(?i)` フラグを付与
  し、`rules::patterns::SENSITIVE_PATH` 全体にも `(?ix)` を付ける。
  PEM_BLOB は RFC 7468 uppercase 規定のため `(?-i:...)` で個別に
  case-sensitive に戻す。
- **B2**: DOTENV と SENSITIVE_PATH 内 dotenv branch の開始 anchor を
  `(?:^|/|\s|[*?\[\]={},])` に拡張。`*`/`?`/`[`/`]` は glob meta、`{`/`}`/`,` は
  brace expansion (`{a,b}.env`)、`=` は `dd if=.env` や `--env-file=.env` のような flag value 形を catch する。
  Unicode homoglyph (`.еnv` キリル e 等) は当時範囲外 → ADR 0007 で解消。
- **B3**: `facts::path::collect_mcp_paths` に同義キー名
  (`file_path`, `filename`, `file`, `filepath`, `target`, `target_file`,
  `dest`, `destination`, `src`, `source`, `from`, `to`, `location`, `uri`)
  を追加。`url` は URL 専用のキーとして区別し、意図的に含めない
  (`mcp__fetch__fetch` の `url` を path として誤抽出すると、URL 内の
  `.env` 文字列が false positive を生むため)。

## Consequences

### Positive

- `.env` を含む機密ファイルの「読み」が `cat`/`source`/`<` 経由でも Ask に
  なり、内容が transcript に流入する確率が大きく下がる。
- Write / apply_patch / MCP 非標準キー / symlink / case-variant / glob /
  flag-value 形 (`if=.env`) の各迂回が塞がれる。
- 設計と実装のギャップ (`canonical_or_raw` が計算済みなのに classify に
  使われていない) が解消される。

### Negative

- `sensitive-bash-read` の Ask は false positive を生む場面が増える
  (例: `cat .env.example`, `source ./hack/setup.sh`)。`overrides.allow`
  で project-local に suppress する運用が必要。
- case-insensitive 化で誤マッチ確率が微増するが、anchor 条件と word
  boundary で抑えられる範囲。
- Copilot 環境では Ask が Deny に demote される (既存挙動) ため、対話なし
  に Bash 単独読みがすべてブロックされる。これは contributor の dev フロー
  に摩擦を生む可能性 → `overrides.allow` で個別緩和。
- DOTENV anchor に `=` を追加したことで `KEY=.env` 形 (env assignment の
  value, 滅多に書かれない) も match するようになるが、Ask レベル / Deny
  も含めて誤発火許容範囲。

### Known limitations (本イテレーション外)

- ~~`apply_patch` の patch body 内 PEM/credentials の内容スキャン~~ —
  Resolved by issue #175 (`facts::patch::added_content` scans `+` lines via
  `classify_content_into`; deletion/context lines are excluded).
- `fold_char` が大文字 Cyrillic を小文字 ASCII に fold しないため、
  case-sensitive PEM probe と uppercase homoglyph が噛み合わない gap が
  Write / apply_patch 両経路に残る (本 issue scope 外)。
- `python -c "open('.env').read()"`, `node -e "..."` などの dynamic-eval
  内部での `.env` 参照は `core.engine.dynamic-eval` の Ask に依存。
- Bash arg の symlink 解決 (`cat /tmp/link.env` の link が `.env` を指す
  ケース) は I/O コストのため対応しない。
- ~~Unicode homoglyph (`.еnv` キリル e 等)~~ — Resolved by ADR 0007
  (bounded lookalike fold; full confusables still deferred).
- ~~`echo $(cat .env)` のように、外側 argv head が非 reader で内側に
  reader が隠れる command-substitution shape~~ — Resolved by ADR 0008
  (`Argv.subst_argv` re-entry).
- 権限昇格ラッパーは `nesting_budget = 3` まで展開する (ADR 0002 B3)。
  4 段を超えるネストは最深層を取り逃す (`tests/bypass/corpus.jsonl` で固定)。
- plugin DSL の `shell.pipeline` (`ShellPipelineFromTo`) は `pipe.commands`
  を直走査するため `inner_argv` が見えず、`su -c '... | sink'` 経由の
  pipeline は捕捉できない。prefix ラッパー (`sudo` / `env` / `command` 等) は
  `unwrap_prefix_wrapper` で対応済み。

## Implementation map

| 修正項目 | ファイル | 主要変更 |
|---|---|---|
| A1 | `src/rules/sensitive_bash_read.rs` (新規) | `SensitiveBashRead` 実装、READER_HEADS allowlist、Stdin redirect 判定、sudo unwrap、inner_argv 再帰、pessimistic mode |
| A1 | `src/rules/mod.rs` | `pub mod sensitive_bash_read;` 追加、`RULES` slice 登録、`rule_ids_are_stable_strings` テスト更新、`BASH_ONLY_RULE_IDS` 追加 |
| A2/A3 | `src/rules/sensitive_read.rs` | matcher に `Write` / `apply_patch` 追加、PBT `pbt_non_read_edit_yields_none` → `pbt_non_file_tool_yields_none` rename と `prop_assume` 拡張 |
| A4 | `src/facts/mod.rs` | `collect_sensitive` で `p.expanded` と `p.canonical_or_raw` も classify、symlink integration test 追加 |
| B1 | `src/facts/sensitive.rs` / `src/rules/patterns.rs` | 機密 path 正規表現 10 件に `(?i)` 付与、PEM_BLOB は `(?-i:...)` で case-sensitive 維持 |
| B2 | `src/facts/sensitive.rs` / `src/rules/patterns.rs` | DOTENV anchor に `[*?\[\]=]` 追加 |
| B3 | `src/facts/path.rs` | `collect_mcp_paths` に同義 top-level キー (`file_path`, `filename`, ... `uri`) を追加 |
| Doc | `docs/design/policy-packs.md` | `sensitive-bash-read` 表追加、`sensitive-read` 対象 tool に Write/apply_patch、case-insensitive / glob anchor / `=` anchor の説明、pessimistic mode 限界記載 |
