//! Fold a curated set of Unicode confusables (homoglyphs) down to their
//! ASCII look-alikes before a token is matched against the sensitive-path
//! classifiers.
//!
//! The sensitive-path detectors — [`crate::rules::patterns::SENSITIVE_PATH`]
//! and [`crate::facts::sensitive::classify`] — fold only ASCII case
//! (`(?i-u:…)`), so a token like `.еnv` written with a Cyrillic `е`
//! (U+0435) slips past every credentials check even though it renders
//! identically to the ASCII `.env`. NFKC normalisation does **not** close
//! this: compatibility decomposition keeps cross-script letters distinct
//! (Cyrillic `е` ≠ Latin `e`). The correct technique is Unicode TR39
//! confusables mapping. To honour the project's Minimal-Dependencies rule
//! we ship a small hand-curated table rather than pulling in a
//! `unicode-security`-class crate: only the confusables that can spell the
//! credential shapes in `docs/design/policy-packs.md` §`core.secrets`
//! (Cyrillic, Greek, and the fullwidth Latin block) are mapped. This is a
//! deliberately narrow attack surface, not the full TR39 set — codepoints
//! outside the table pass through unchanged and stay a documented
//! `known_gap` (`tests/bypass/corpus.jsonl`, ADR 0007).

use std::borrow::Cow;

/// Fold curated confusable codepoints in `token` to their ASCII
/// look-alikes so homoglyph spellings of sensitive paths classify
/// identically to their ASCII form.
///
/// Returns `Cow::Borrowed` unchanged whenever `token` is pure ASCII — the
/// overwhelmingly common case for shell tokens and file paths — so the
/// hot path allocates nothing and its behaviour is bit-for-bit identical
/// to before this module existed. Only a token carrying at least one
/// non-ASCII byte is scanned and rewritten.
///
/// Non-ASCII characters outside the curated table pass through unchanged,
/// so folding never *drops* information. When folding does occur the
/// returned string — and hence any [`crate::facts::sensitive::SensitivePath`]
/// `raw` derived from it — is the folded form, not the original bytes;
/// `raw` is informational only (rules decide on `kind`/non-emptiness), so
/// this is harmless. Total over all input: never panics.
pub(crate) fn fold_confusables(token: &str) -> Cow<'_, str> {
    if token.is_ascii() {
        return Cow::Borrowed(token);
    }
    let mut folded = String::with_capacity(token.len());
    for ch in token.chars() {
        folded.push(fold_char(ch).unwrap_or(ch));
    }
    Cow::Owned(folded)
}

/// Map a single confusable codepoint to its ASCII look-alike, or `None`
/// if it is not a curated confusable. ASCII characters return `None`
/// (they are already canonical and pass through unchanged).
fn fold_char(ch: char) -> Option<char> {
    // The fullwidth ASCII-variants block (U+FF01..=U+FF5E) maps onto
    // printable ASCII (0x21..=0x7E) by a fixed 0xFEE0 offset, covering
    // fullwidth letters, digits, and punctuation in one arithmetic step.
    if ('\u{FF01}'..='\u{FF5E}').contains(&ch) {
        return char::from_u32(ch as u32 - 0xFEE0);
    }
    Some(match ch {
        // --- Cyrillic lowercase → Latin ---
        '\u{0430}' => 'a', // а
        '\u{0435}' => 'e', // е
        '\u{043E}' => 'o', // о
        '\u{0440}' => 'p', // р
        '\u{0441}' => 'c', // с
        '\u{0443}' => 'y', // у
        '\u{0445}' => 'x', // х
        '\u{043A}' => 'k', // к
        '\u{0455}' => 's', // ѕ
        '\u{0456}' => 'i', // і
        '\u{0458}' => 'j', // ј
        '\u{04BB}' => 'h', // һ
        '\u{051B}' => 'q', // ԛ
        '\u{051D}' => 'w', // ԝ
        '\u{0501}' => 'd', // ԁ
        // --- Cyrillic uppercase → Latin ---
        '\u{0410}' => 'A', // А
        '\u{0412}' => 'B', // В
        '\u{0415}' => 'E', // Е
        '\u{041A}' => 'K', // К
        '\u{041C}' => 'M', // М
        '\u{041D}' => 'H', // Н
        '\u{041E}' => 'O', // О
        '\u{0420}' => 'P', // Р
        '\u{0421}' => 'C', // С
        '\u{0422}' => 'T', // Т
        '\u{0423}' => 'Y', // У
        '\u{0425}' => 'X', // Х
        // --- Greek lowercase → Latin ---
        '\u{03B1}' => 'a', // α
        '\u{03B5}' => 'e', // ε
        '\u{03B9}' => 'i', // ι
        '\u{03BA}' => 'k', // κ
        '\u{03BD}' => 'v', // ν
        '\u{03BF}' => 'o', // ο
        '\u{03C1}' => 'p', // ρ
        '\u{03C4}' => 't', // τ
        '\u{03C5}' => 'u', // υ
        '\u{03C7}' => 'x', // χ
        // --- Greek uppercase → Latin ---
        '\u{0391}' => 'A', // Α
        '\u{0392}' => 'B', // Β
        '\u{0395}' => 'E', // Ε
        '\u{0396}' => 'Z', // Ζ
        '\u{0397}' => 'H', // Η
        '\u{0399}' => 'I', // Ι
        '\u{039A}' => 'K', // Κ
        '\u{039C}' => 'M', // Μ
        '\u{039D}' => 'N', // Ν
        '\u{039F}' => 'O', // Ο
        '\u{03A1}' => 'P', // Ρ
        '\u{03A4}' => 'T', // Τ
        '\u{03A5}' => 'Y', // Υ
        '\u{03A7}' => 'X', // Χ
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_borrowed_unchanged() {
        // Pure-ASCII tokens must round-trip byte-for-byte and never
        // allocate (the hot path).
        for token in ["", ".env", "cat /home/user/.ssh/id_rsa", "README.md"] {
            match fold_confusables(token) {
                Cow::Borrowed(s) => assert_eq!(s, token),
                Cow::Owned(_) => panic!("ASCII token {token:?} was needlessly owned"),
            }
        }
    }

    #[test]
    fn folds_cyrillic_e_dotenv() {
        // The canonical GAP-01 payload: Cyrillic е (U+0435) in `.еnv`.
        assert_eq!(fold_confusables(".\u{0435}nv").as_ref(), ".env");
    }

    #[test]
    fn folds_mixed_script_ssh_path() {
        // Cyrillic ѕ/с blended into an `.ssh` path still resolves.
        assert_eq!(
            fold_confusables("~/.\u{0455}\u{0455}h/id_r\u{0455}a").as_ref(),
            "~/.ssh/id_rsa"
        );
    }

    #[test]
    fn folds_fullwidth_latin() {
        // Fullwidth `．ｅｎｖ` → `.env` via the arithmetic branch.
        assert_eq!(
            fold_confusables("\u{FF0E}\u{FF45}\u{FF4E}\u{FF56}").as_ref(),
            ".env"
        );
    }

    #[test]
    fn folds_greek_confusables() {
        // Greek ο/ν used to spell `.env` (ε is folded to e as well).
        assert_eq!(fold_confusables(".\u{03B5}n\u{03BD}").as_ref(), ".env");
    }

    #[test]
    fn passes_through_uncurated_codepoints() {
        // Non-ASCII outside the table stays put (documented gap boundary):
        // Mathematical Sans-Serif Small E (U+1D5BE) is deliberately not
        // mapped. A legitimate accented filename must also survive intact.
        assert_eq!(fold_confusables(".\u{1D5BE}nv").as_ref(), ".\u{1D5BE}nv");
        assert_eq!(
            fold_confusables("caf\u{00E9}.txt").as_ref(),
            "caf\u{00E9}.txt"
        );
    }

    use proptest::prelude::*;

    proptest! {
        // Total over arbitrary Unicode: folding never panics.
        #[test]
        fn pbt_fold_never_panics(s in "\\PC{0,80}") {
            let _ = fold_confusables(&s);
        }

        // Pure-ASCII input is always returned borrowed and identical.
        #[test]
        fn pbt_ascii_is_identity(s in "[ -~]{0,80}") {
            let folded = fold_confusables(&s);
            prop_assert_eq!(folded.as_ref(), s.as_str());
            prop_assert!(matches!(folded, Cow::Borrowed(_)));
        }

        // The output never grows the char count: each char maps to at
        // most one char (or passes through). Guards against a table entry
        // that accidentally expands.
        #[test]
        fn pbt_fold_preserves_char_count(s in "\\PC{0,80}") {
            let folded = fold_confusables(&s);
            prop_assert_eq!(folded.chars().count(), s.chars().count());
        }
    }
}
