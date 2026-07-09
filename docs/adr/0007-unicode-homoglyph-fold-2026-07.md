# ADR 0007 — Unicode homoglyph fold for credential needles (2026-07)

## Status

Accepted (2026-07-09).

## Context

ADR 0001 / 0002 B1 deferred Unicode homoglyph bypass (`cat .еnv` with Cyrillic
`е` U+0435) because a general NFKC + confusables table would add a large
dependency, conflicting with Minimal Dependencies.

The bypass remained pinned as `known_gap` in `tests/bypass/corpus.jsonl`
(`gap-unicode-homoglyph`) and ADR 0001 Known limitations.

Credential needles are a **bounded alphabet** (≈20 lowercase ASCII letters
across `.env`, `.ssh`, `.aws`, `id_rsa`, `.npmrc`, etc.), so a hand-written
lookalike table is sufficient without a confusables crate.

Additionally, the shell parser decodes non-ASCII bytes as Latin-1
(`push_latin1` in `src/facts/shell.rs`). UTF-8 Cyrillic in argv tokens
therefore arrives as mojibake (e.g. `.еnv` → `.Ðµnv`) before classification.

## Decision

Add `normalize_for_sensitive_match` in `src/facts/sensitive.rs`:

1. **ASCII fast path** — return the token borrowed unchanged (zero cost).
2. **Mojibake recovery** — when every char is U+00FF or below, re-encode as
   bytes and attempt UTF-8 decode before folding.
3. **Bounded homoglyph fold** — map Cyrillic/Greek lookalikes for needle
   letters to ASCII via a ~30-entry `match` table; unknown non-ASCII scalars
   pass through unchanged.

Apply normalization at the entry of **both** classifiers:

- `facts::sensitive::classify_into` (file-tool / facts path)
- `rules::patterns::matches_sensitive_path` (Bash rules path)

**Fail-closed boundary:** tokens that cannot be recovered or folded stay as-is;
legitimate non-ASCII filenames (CJK, etc.) are not promoted to secrets.

Do **not** change the shell parser or the `SENSITIVE_PATH` regex literals.

## Consequences

### Positive

- `cat .еnv` → `sensitive-bash-read` Ask; `scp .еnv host:` →
  `sensitive-path-to-network` Deny.
- Classifier parity preserved via a single shared normalizer.
- Zero new dependencies; ASCII-only tokens pay no allocation.

### Negative

- The fold table must stay in sync with needle letters; PBT +
  `homoglyph_substituted_needle` strategy guard drift.

### Known limitations (still out of scope)

- General Unicode confusables / NFKC normalization.
- Homoglyphs outside the bounded table (rare scripts, fullwidth, etc.).

## Implementation map

| Item | File | Change |
| --- | --- | --- |
| Normalizer | `src/facts/sensitive.rs` | fold table, mojibake recovery, `classify_into` hook |
| Bash parity | `src/rules/patterns.rs` | `matches_sensitive_path` hook |
| Unit tests | `src/rules/sensitive_bash_read.rs`, `sensitive_net.rs` | Ask / Deny pins |
| Corpus | `tests/bypass/corpus.jsonl` | `gap-unicode-homoglyph` → `must_catch`; scp exfil |
| PBT | `src/testing/proptest.rs`, `sensitive.rs`, `patterns.rs` | homoglyph properties |
| Doc | `docs/design/policy-packs.md`, ADR 0001/0002 | known-gap removal |
